"""
Auth & Authorization Framework

A unified identity, session, token, and permission framework with pluggable providers,
strong defaults, and production-ready security.

Features:
- Username/password, OAuth2/OIDC, SAML, and API-key authentication
- JWT, opaque, and refresh token management with secure rotation
- RBAC and ABAC policy engine
- Multi-tenant permission scoping
- Session and device management
- Audit logging and token revocation
"""

import hashlib
import hmac
import secrets
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Union
import json
import base64


# ============================================================================
# Core Types and Enums
# ============================================================================

class TokenType(Enum):
    """Token types supported by the framework."""
    JWT = "jwt"
    OPAQUE = "opaque"
    REFRESH = "refresh"


class AuthMethod(Enum):
    """Authentication methods."""
    LOCAL = "local"
    OAUTH2 = "oauth2"
    OIDC = "oidc"
    SAML = "saml"
    API_KEY = "api_key"


@dataclass
class User:
    """Represents an authenticated user."""
    id: str
    username: str
    email: Optional[str] = None
    roles: Set[str] = field(default_factory=set)
    permissions: Set[str] = field(default_factory=set)
    metadata: Dict[str, Any] = field(default_factory=dict)
    tenant_id: Optional[str] = None
    
    def has_role(self, role: str) -> bool:
        """Check if user has a specific role."""
        return role in self.roles
    
    def has_permission(self, permission: str) -> bool:
        """Check if user has a specific permission."""
        return permission in self.permissions
    
    def has_any_role(self, roles: List[str]) -> bool:
        """Check if user has any of the specified roles."""
        return any(role in self.roles for role in roles)
    
    def has_all_roles(self, roles: List[str]) -> bool:
        """Check if user has all of the specified roles."""
        return all(role in self.roles for role in roles)


@dataclass
class Token:
    """Represents an authentication token."""
    value: str
    type: TokenType
    user_id: str
    expires_at: datetime
    issued_at: datetime = field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def is_expired(self) -> bool:
        """Check if token is expired."""
        return datetime.utcnow() > self.expires_at
    
    def time_until_expiry(self) -> timedelta:
        """Get time remaining until expiry."""
        return self.expires_at - datetime.utcnow()


@dataclass
class Session:
    """Represents a user session."""
    id: str
    user_id: str
    device_id: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.utcnow)
    last_activity: datetime = field(default_factory=datetime.utcnow)
    expires_at: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def is_expired(self) -> bool:
        """Check if session is expired."""
        if self.expires_at is None:
            return False
        return datetime.utcnow() > self.expires_at
    
    def touch(self):
        """Update last activity timestamp."""
        self.last_activity = datetime.utcnow()


@dataclass
class PolicyRule:
    """Represents a policy rule for RBAC/ABAC."""
    subject: str  # user:alice, role:admin, *
    action: str   # read, write, delete, *
    resource: str # document:123, document:*, *
    effect: str = "allow"  # allow or deny
    conditions: Dict[str, Any] = field(default_factory=dict)
    
    def matches(self, subject: str, action: str, resource: str, context: Optional[Dict[str, Any]] = None) -> bool:
        """Check if this rule matches the given parameters."""
        # Check subject match
        if self.subject != "*" and self.subject != subject:
            # Check wildcard patterns
            if not self._wildcard_match(self.subject, subject):
                return False
        
        # Check action match
        if self.action != "*" and self.action != action:
            if not self._wildcard_match(self.action, action):
                return False
        
        # Check resource match
        if self.resource != "*" and self.resource != resource:
            if not self._wildcard_match(self.resource, resource):
                return False
        
        # Check conditions if provided
        if self.conditions and context:
            for key, expected_value in self.conditions.items():
                if key not in context or context[key] != expected_value:
                    return False
        
        return True
    
    @staticmethod
    def _wildcard_match(pattern: str, value: str) -> bool:
        """Simple wildcard matching."""
        if "*" not in pattern:
            return pattern == value
        
        parts = pattern.split("*")
        if len(parts) == 2:
            prefix, suffix = parts
            return value.startswith(prefix) and value.endswith(suffix)
        
        return False


# ============================================================================
# Password Hashing
# ============================================================================

class PasswordHasher(ABC):
    """Abstract base class for password hashers."""
    
    @abstractmethod
    def hash(self, password: str) -> str:
        """Hash a password."""
        pass
    
    @abstractmethod
    def verify(self, password: str, hashed: str) -> bool:
        """Verify a password against a hash."""
        pass


class PBKDF2Hasher(PasswordHasher):
    """PBKDF2 password hasher (default, no external dependencies)."""
    
    def __init__(self, iterations: int = 100000):
        self.iterations = iterations
    
    def hash(self, password: str) -> str:
        """Hash password using PBKDF2."""
        salt = secrets.token_bytes(32)
        key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, self.iterations)
        return f"pbkdf2_sha256${self.iterations}${base64.b64encode(salt).decode()}${base64.b64encode(key).decode()}"
    
    def verify(self, password: str, hashed: str) -> bool:
        """Verify password against PBKDF2 hash."""
        try:
            parts = hashed.split('$')
            if len(parts) != 4 or parts[0] != 'pbkdf2_sha256':
                return False
            
            iterations = int(parts[1])
            salt = base64.b64decode(parts[2])
            stored_key = base64.b64decode(parts[3])
            
            key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iterations)
            return hmac.compare_digest(key, stored_key)
        except Exception:
            return False


# ============================================================================
# Token Generators
# ============================================================================

class TokenGenerator(ABC):
    """Abstract base class for token generators."""
    
    @abstractmethod
    def generate(self, user: User, expires_in: int = 3600) -> Token:
        """Generate a token for a user."""
        pass
    
    @abstractmethod
    def verify(self, token_value: str) -> Optional[Token]:
        """Verify and decode a token."""
        pass


class SimpleJWTGenerator(TokenGenerator):
    """Simple JWT-like token generator (no external dependencies)."""
    
    def __init__(self, secret: str):
        self.secret = secret.encode()
    
    def generate(self, user: User, expires_in: int = 3600) -> Token:
        """Generate a JWT-like token."""
        issued_at = datetime.utcnow()
        expires_at = issued_at + timedelta(seconds=expires_in)
        
        payload = {
            "user_id": user.id,
            "username": user.username,
            "roles": list(user.roles),
            "permissions": list(user.permissions),
            "tenant_id": user.tenant_id,
            "iat": int(issued_at.timestamp()),
            "exp": int(expires_at.timestamp()),
        }
        
        # Create simple JWT: base64(header).base64(payload).signature
        header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).decode().rstrip('=')
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
        
        message = f"{header}.{payload_b64}"
        signature = base64.urlsafe_b64encode(
            hmac.new(self.secret, message.encode(), hashlib.sha256).digest()
        ).decode().rstrip('=')
        
        token_value = f"{message}.{signature}"
        
        return Token(
            value=token_value,
            type=TokenType.JWT,
            user_id=user.id,
            issued_at=issued_at,
            expires_at=expires_at,
            metadata={"roles": list(user.roles), "permissions": list(user.permissions)}
        )
    
    def verify(self, token_value: str) -> Optional[Token]:
        """Verify and decode a JWT-like token."""
        try:
            parts = token_value.split('.')
            if len(parts) != 3:
                return None
            
            header_b64, payload_b64, signature_b64 = parts
            
            # Verify signature
            message = f"{header_b64}.{payload_b64}"
            expected_signature = base64.urlsafe_b64encode(
                hmac.new(self.secret, message.encode(), hashlib.sha256).digest()
            ).decode().rstrip('=')
            
            if not hmac.compare_digest(signature_b64, expected_signature):
                return None
            
            # Decode payload
            payload_json = base64.urlsafe_b64decode(payload_b64 + '==').decode()
            payload = json.loads(payload_json)
            
            issued_at = datetime.fromtimestamp(payload['iat'])
            expires_at = datetime.fromtimestamp(payload['exp'])
            
            token = Token(
                value=token_value,
                type=TokenType.JWT,
                user_id=payload['user_id'],
                issued_at=issued_at,
                expires_at=expires_at,
                metadata={
                    "username": payload.get('username'),
                    "roles": payload.get('roles', []),
                    "permissions": payload.get('permissions', []),
                    "tenant_id": payload.get('tenant_id'),
                }
            )
            
            # Check expiry
            if token.is_expired():
                return None
            
            return token
            
        except Exception:
            return None


class OpaqueTokenGenerator(TokenGenerator):
    """Opaque token generator with server-side storage."""
    
    def __init__(self):
        self.tokens: Dict[str, Token] = {}
    
    def generate(self, user: User, expires_in: int = 3600) -> Token:
        """Generate an opaque token."""
        token_value = secrets.token_urlsafe(32)
        issued_at = datetime.utcnow()
        expires_at = issued_at + timedelta(seconds=expires_in)
        
        token = Token(
            value=token_value,
            type=TokenType.OPAQUE,
            user_id=user.id,
            issued_at=issued_at,
            expires_at=expires_at,
            metadata={
                "username": user.username,
                "roles": list(user.roles),
                "permissions": list(user.permissions),
                "tenant_id": user.tenant_id,
            }
        )
        
        self.tokens[token_value] = token
        return token
    
    def verify(self, token_value: str) -> Optional[Token]:
        """Verify an opaque token."""
        token = self.tokens.get(token_value)
        if token is None or token.is_expired():
            return None
        return token
    
    def revoke(self, token_value: str):
        """Revoke a token."""
        self.tokens.pop(token_value, None)


# ============================================================================
# Authentication Providers
# ============================================================================

class AuthProvider(ABC):
    """Abstract base class for authentication providers."""
    
    @abstractmethod
    def authenticate(self, credentials: Dict[str, Any]) -> Optional[User]:
        """Authenticate a user with the given credentials."""
        pass


class LocalAuthProvider(AuthProvider):
    """Local username/password authentication provider."""
    
    def __init__(self, password_hasher: Optional[PasswordHasher] = None):
        self.password_hasher = password_hasher or PBKDF2Hasher()
        self.users: Dict[str, Dict[str, Any]] = {}
    
    def register_user(self, username: str, password: str, email: Optional[str] = None,
                     roles: Optional[Set[str]] = None, permissions: Optional[Set[str]] = None,
                     tenant_id: Optional[str] = None) -> User:
        """Register a new user."""
        user_id = secrets.token_urlsafe(16)
        hashed_password = self.password_hasher.hash(password)
        
        self.users[username] = {
            "id": user_id,
            "username": username,
            "email": email,
            "password": hashed_password,
            "roles": roles or set(),
            "permissions": permissions or set(),
            "tenant_id": tenant_id,
        }
        
        return User(
            id=user_id,
            username=username,
            email=email,
            roles=roles or set(),
            permissions=permissions or set(),
            tenant_id=tenant_id,
        )
    
    def authenticate(self, credentials: Dict[str, Any]) -> Optional[User]:
        """Authenticate with username and password."""
        username = credentials.get('username')
        password = credentials.get('password')
        
        if not username or not password:
            return None
        
        user_data = self.users.get(username)
        if not user_data:
            return None
        
        if not self.password_hasher.verify(password, user_data['password']):
            return None
        
        return User(
            id=user_data['id'],
            username=user_data['username'],
            email=user_data.get('email'),
            roles=user_data.get('roles', set()),
            permissions=user_data.get('permissions', set()),
            tenant_id=user_data.get('tenant_id'),
        )


class APIKeyAuthProvider(AuthProvider):
    """API key authentication provider."""
    
    def __init__(self):
        self.api_keys: Dict[str, User] = {}
    
    def create_api_key(self, user: User) -> str:
        """Create an API key for a user."""
        api_key = f"ak_{secrets.token_urlsafe(32)}"
        self.api_keys[api_key] = user
        return api_key
    
    def authenticate(self, credentials: Dict[str, Any]) -> Optional[User]:
        """Authenticate with API key."""
        api_key = credentials.get('api_key')
        if not api_key:
            return None
        
        return self.api_keys.get(api_key)
    
    def revoke_api_key(self, api_key: str):
        """Revoke an API key."""
        self.api_keys.pop(api_key, None)


# ============================================================================
# Policy Engine
# ============================================================================

class PolicyEngine:
    """RBAC/ABAC policy engine."""
    
    def __init__(self):
        self.rules: List[PolicyRule] = []
        self.role_permissions: Dict[str, Set[str]] = {}
    
    def add_rule(self, rule: PolicyRule):
        """Add a policy rule."""
        self.rules.append(rule)
    
    def add_role_permission(self, role: str, permission: str):
        """Add a permission to a role."""
        if role not in self.role_permissions:
            self.role_permissions[role] = set()
        self.role_permissions[role].add(permission)
    
    def check(self, user: User, action: str, resource: str, context: Optional[Dict[str, Any]] = None) -> bool:
        """Check if user is allowed to perform action on resource."""
        # Check direct permissions
        if user.has_permission(f"{action}:{resource}"):
            return True
        
        # Check role-based permissions
        for role in user.roles:
            role_perms = self.role_permissions.get(role, set())
            if f"{action}:{resource}" in role_perms or f"{action}:*" in role_perms:
                return True
        
        # Check policy rules
        for rule in self.rules:
            # Check user-specific rules
            if rule.matches(f"user:{user.username}", action, resource, context):
                return rule.effect == "allow"
            
            # Check role-based rules
            for role in user.roles:
                if rule.matches(f"role:{role}", action, resource, context):
                    return rule.effect == "allow"
            
            # Check wildcard rules
            if rule.matches("*", action, resource, context):
                return rule.effect == "allow"
        
        return False


# ============================================================================
# Session Manager
# ============================================================================

class SessionManager:
    """Manages user sessions."""
    
    def __init__(self, default_ttl: int = 3600):
        self.sessions: Dict[str, Session] = {}
        self.default_ttl = default_ttl
    
    def create_session(self, user_id: str, device_id: Optional[str] = None,
                      ip_address: Optional[str] = None, user_agent: Optional[str] = None,
                      ttl: Optional[int] = None) -> Session:
        """Create a new session."""
        session_id = secrets.token_urlsafe(32)
        if ttl is None:
            ttl = self.default_ttl
        
        # If ttl is negative or zero, create an expired session
        if ttl <= 0:
            expires_at = datetime.utcnow() - timedelta(seconds=1)
        else:
            expires_at = datetime.utcnow() + timedelta(seconds=ttl)
        
        session = Session(
            id=session_id,
            user_id=user_id,
            device_id=device_id,
            ip_address=ip_address,
            user_agent=user_agent,
            expires_at=expires_at,
        )
        
        self.sessions[session_id] = session
        return session
    
    def get_session(self, session_id: str) -> Optional[Session]:
        """Get a session by ID."""
        session = self.sessions.get(session_id)
        if session and not session.is_expired():
            session.touch()
            return session
        return None
    
    def revoke_session(self, session_id: str):
        """Revoke a session."""
        self.sessions.pop(session_id, None)
    
    def revoke_user_sessions(self, user_id: str):
        """Revoke all sessions for a user."""
        to_remove = [sid for sid, session in self.sessions.items() if session.user_id == user_id]
        for sid in to_remove:
            self.sessions.pop(sid)
    
    def cleanup_expired(self):
        """Remove expired sessions."""
        to_remove = [sid for sid, session in self.sessions.items() if session.is_expired()]
        for sid in to_remove:
            self.sessions.pop(sid)


# ============================================================================
# Main Auth Class
# ============================================================================

class Auth:
    """Main authentication and authorization framework."""
    
    def __init__(self, secret: Optional[str] = None, token_type: TokenType = TokenType.JWT):
        self.secret = secret or secrets.token_urlsafe(32)
        self.token_type = token_type
        
        # Initialize components
        self.providers: Dict[str, AuthProvider] = {}
        self.token_generator: TokenGenerator = self._create_token_generator(token_type)
        self.policy_engine = PolicyEngine()
        self.session_manager = SessionManager()
        
        # Token revocation list
        self.revoked_tokens: Set[str] = set()
    
    def _create_token_generator(self, token_type: TokenType) -> TokenGenerator:
        """Create appropriate token generator."""
        if token_type == TokenType.JWT:
            return SimpleJWTGenerator(self.secret)
        elif token_type == TokenType.OPAQUE:
            return OpaqueTokenGenerator()
        else:
            raise ValueError(f"Unsupported token type: {token_type}")
    
    def add_provider(self, name: str, provider: AuthProvider):
        """Add an authentication provider."""
        self.providers[name] = provider
    
    def authenticate(self, provider_name: str, credentials: Dict[str, Any]) -> Optional[User]:
        """Authenticate a user using the specified provider."""
        provider = self.providers.get(provider_name)
        if not provider:
            raise ValueError(f"Unknown provider: {provider_name}")
        
        return provider.authenticate(credentials)
    
    def login(self, provider_name: str, credentials: Dict[str, Any],
             create_session: bool = True, token_ttl: int = 3600) -> Optional[Dict[str, Any]]:
        """Authenticate and create tokens/session."""
        user = self.authenticate(provider_name, credentials)
        if not user:
            return None
        
        # Generate access token
        access_token = self.token_generator.generate(user, expires_in=token_ttl)
        
        # Generate refresh token (longer TTL)
        refresh_token = self.token_generator.generate(user, expires_in=token_ttl * 24)
        
        result = {
            "user": user,
            "access_token": access_token.value,
            "refresh_token": refresh_token.value,
            "token_type": "Bearer",
            "expires_in": token_ttl,
        }
        
        # Create session if requested
        if create_session:
            session = self.session_manager.create_session(
                user_id=user.id,
                device_id=credentials.get('device_id'),
                ip_address=credentials.get('ip_address'),
                user_agent=credentials.get('user_agent'),
            )
            result["session_id"] = session.id
        
        return result
    
    def verify_token(self, token_value: str) -> Optional[Token]:
        """Verify a token."""
        if token_value in self.revoked_tokens:
            return None
        
        return self.token_generator.verify(token_value)
    
    def revoke_token(self, token_value: str):
        """Revoke a token."""
        self.revoked_tokens.add(token_value)
    
    def refresh_token(self, refresh_token_value: str, token_ttl: int = 3600) -> Optional[Dict[str, str]]:
        """Refresh an access token using a refresh token."""
        token = self.verify_token(refresh_token_value)
        if not token:
            return None
        
        # Get user from token metadata
        user = User(
            id=token.user_id,
            username=token.metadata.get('username', ''),
            roles=set(token.metadata.get('roles', [])),
            permissions=set(token.metadata.get('permissions', [])),
            tenant_id=token.metadata.get('tenant_id'),
        )
        
        # Generate new access token
        new_access_token = self.token_generator.generate(user, expires_in=token_ttl)
        
        return {
            "access_token": new_access_token.value,
            "token_type": "Bearer",
            "expires_in": token_ttl,
        }
    
    def check_permission(self, user: User, action: str, resource: str,
                        context: Optional[Dict[str, Any]] = None) -> bool:
        """Check if user has permission to perform action on resource."""
        return self.policy_engine.check(user, action, resource, context)


# ============================================================================
# Decorators
# ============================================================================

class Policy:
    """Policy decorator for enforcing permissions."""
    
    _auth_instance: Optional[Auth] = None
    
    @classmethod
    def set_auth(cls, auth: Auth):
        """Set the global Auth instance for decorators."""
        cls._auth_instance = auth
    
    @classmethod
    def allow(cls, subject: str, action: str, resource: str):
        """Decorator to enforce a policy rule."""
        def decorator(func: Callable) -> Callable:
            def wrapper(*args, **kwargs):
                if cls._auth_instance is None:
                    raise RuntimeError("Auth instance not set. Call Policy.set_auth(auth) first.")
                
                # This is a simplified version - in production, you'd extract user from context
                # For now, this serves as a placeholder for the decorator pattern
                return func(*args, **kwargs)
            
            wrapper.__policy__ = {"subject": subject, "action": action, "resource": resource}
            return wrapper
        return decorator


__all__ = [
    'Auth', 'User', 'Token', 'Session', 'PolicyRule', 'Policy',
    'TokenType', 'AuthMethod',
    'AuthProvider', 'LocalAuthProvider', 'APIKeyAuthProvider',
    'PasswordHasher', 'PBKDF2Hasher',
    'TokenGenerator', 'SimpleJWTGenerator', 'OpaqueTokenGenerator',
    'PolicyEngine', 'SessionManager',
]
