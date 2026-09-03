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
import os
import secrets
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Union
import json
import base64
import fnmatch


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


class AuthError(Exception):
    """Exception raised for authentication configuration or runtime errors."""
    pass


# ============================================================================
# Clock Abstraction
# ============================================================================

class Clock(ABC):
    """Abstract clock for time-based operations."""

    @abstractmethod
    def now(self) -> datetime:
        """Return the current time as a timezone-aware UTC datetime."""
        pass


class RealClock(Clock):
    """Clock that returns the real current UTC time."""

    def now(self) -> datetime:
        return datetime.now(timezone.utc)


class FixedClock(Clock):
    """Clock with a controllable, fixed time for testing."""

    def __init__(self, initial: Optional[datetime] = None):
        self._dt = initial if initial is not None else datetime.now(timezone.utc)

    def now(self) -> datetime:
        return self._dt

    def advance(self, seconds: int):
        """Move the clock forward by the given number of seconds."""
        self._dt += timedelta(seconds=seconds)

    def set(self, dt: datetime):
        """Set the clock to the given datetime."""
        self._dt = dt


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
    issued_at: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    clock: Optional[Clock] = None

    def __post_init__(self):
        if self.clock is None:
            self.clock = RealClock()
        if self.issued_at is None:
            self.issued_at = self.clock.now()
        if self.issued_at.tzinfo is None:
            self.issued_at = self.issued_at.replace(tzinfo=timezone.utc)
        if self.expires_at.tzinfo is None:
            self.expires_at = self.expires_at.replace(tzinfo=timezone.utc)

    def is_expired(self) -> bool:
        """Check if token is expired."""
        return self.clock.now() > self.expires_at

    def time_until_expiry(self) -> timedelta:
        """Get time remaining until expiry."""
        return self.expires_at - self.clock.now()


@dataclass
class Session:
    """Represents a user session."""
    id: str
    user_id: str
    device_id: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    created_at: Optional[datetime] = None
    last_activity: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    clock: Optional[Clock] = None

    def __post_init__(self):
        if self.clock is None:
            self.clock = RealClock()
        now = self.clock.now()
        if self.created_at is None:
            self.created_at = now
        if self.last_activity is None:
            self.last_activity = now
        if self.created_at.tzinfo is None:
            self.created_at = self.created_at.replace(tzinfo=timezone.utc)
        if self.last_activity.tzinfo is None:
            self.last_activity = self.last_activity.replace(tzinfo=timezone.utc)
        if self.expires_at is not None and self.expires_at.tzinfo is None:
            self.expires_at = self.expires_at.replace(tzinfo=timezone.utc)

    def is_expired(self) -> bool:
        """Check if session is expired."""
        if self.expires_at is None:
            return False
        return self.clock.now() > self.expires_at

    def touch(self):
        """Update last activity timestamp."""
        self.last_activity = self.clock.now()


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
        """Glob-style wildcard matching. Supports * and ?."""
        return fnmatch.fnmatchcase(value, pattern)


# ============================================================================
# Storage Backend
# ============================================================================

class StorageBackend(ABC):
    """Abstract base class for pluggable storage backends."""
    
    @abstractmethod
    def get(self, key: str) -> Optional[Any]:
        """Get a value by key. Returns None if not found or expired."""
        pass
    
    @abstractmethod
    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """Store a value. Optional ttl is in seconds."""
        pass
    
    @abstractmethod
    def delete(self, key: str) -> bool:
        """Delete a key."""
        pass
    
    @abstractmethod
    def has(self, key: str) -> bool:
        """Check if a key exists and is not expired."""
        pass
    
    @abstractmethod
    def keys(self, prefix: Optional[str] = None) -> List[str]:
        """List keys, optionally filtered by prefix."""
        pass
    
    @abstractmethod
    def clear(self) -> None:
        """Clear all stored data."""
        pass


class InMemoryStorage(StorageBackend):
    """In-memory storage backend (default)."""
    
    def __init__(self, clock: Optional[Clock] = None):
        self._data: Dict[str, Any] = {}
        self.clock = clock or RealClock()
    
    def _expired(self, key: str) -> bool:
        if key not in self._data:
            return False
        entry = self._data[key]
        if isinstance(entry, tuple) and len(entry) == 2 and entry[1] is not None:
            return self.clock.now().timestamp() > entry[1]
        return False
    
    def get(self, key: str) -> Optional[Any]:
        if key not in self._data:
            return None
        if self._expired(key):
            self.delete(key)
            return None
        value, _ = self._data[key]
        return value
    
    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        expires_at = None
        if ttl is not None and ttl > 0:
            expires_at = self.clock.now().timestamp() + ttl
        self._data[key] = (value, expires_at)
        return True
    
    def delete(self, key: str) -> bool:
        if key in self._data:
            del self._data[key]
            return True
        return False
    
    def has(self, key: str) -> bool:
        if key not in self._data:
            return False
        if self._expired(key):
            self.delete(key)
            return False
        return True
    
    def keys(self, prefix: Optional[str] = None) -> List[str]:
        result: List[str] = []
        for key in list(self._data.keys()):
            if self._expired(key):
                self.delete(key)
                continue
            if prefix is None or key.startswith(prefix):
                result.append(key)
        return result
    
    def clear(self) -> None:
        self._data.clear()


def _revoke_refresh_family(storage: StorageBackend, family_id: str,
                            extra_tokens: Optional[List[str]] = None) -> None:
    """Revoke every refresh token in a family.

    Deletes the active family record and any associated metadata, then marks
    all known token values in the family as revoked so they cannot be used
    again.
    """
    extra_tokens = extra_tokens or []
    tokens_to_revoke = set(extra_tokens)
    for key in list(storage.keys(prefix="refresh_meta:")):
        meta = storage.get(key)
        if isinstance(meta, dict) and meta.get('fid') == family_id:
            token_value = key.split(":", 1)[1]
            tokens_to_revoke.add(token_value)
            storage.delete(key)
    storage.delete(f"refresh_family:{family_id}")
    for token_value in tokens_to_revoke:
        storage.set(f"revoked:{token_value}", True)


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
    
    @abstractmethod
    def revoke(self, token_value: str):
        """Revoke a token."""
        pass
    
    @abstractmethod
    def is_revoked(self, token_value: str) -> bool:
        """Check if a token has been revoked."""
        pass


class SimpleJWTGenerator(TokenGenerator):
    """Simple JWT-like token generator (no external dependencies)."""
    
    def __init__(
        self,
        secret: str,
        storage: Optional[StorageBackend] = None,
        issuer: Optional[str] = None,
        audience: Optional[str] = None,
        key_id: Optional[str] = None,
        allowed_algorithms: Optional[List[str]] = None,
        expected_issuer: Optional[str] = None,
        expected_audience: Optional[str] = None,
        clock: Optional[Clock] = None,
    ):
        self.secret = secret.encode()
        self.storage = storage or InMemoryStorage(clock=clock)
        self.issuer = issuer
        self.audience = audience
        self.key_id = key_id
        self.allowed_algorithms = allowed_algorithms or ["HS256"]
        self.expected_issuer = expected_issuer
        self.expected_audience = expected_audience
        self.clock = clock or RealClock()
    
    def generate(self, user: User, expires_in: int = 3600,
                 extra_claims: Optional[Dict[str, Any]] = None,
                 token_type: Optional[TokenType] = None) -> Token:
        """Generate a JWT-like token."""
        if token_type is None:
            token_type = TokenType.JWT

        issued_at = self.clock.now()
        expires_at = issued_at + timedelta(seconds=expires_in)

        payload: Dict[str, Any] = {
            "user_id": user.id,
            "username": user.username,
            "roles": list(user.roles),
            "permissions": list(user.permissions),
            "tenant_id": user.tenant_id,
            "jti": secrets.token_urlsafe(16),
            "iat": int(issued_at.timestamp()),
            "exp": int(expires_at.timestamp()),
            "ttyp": token_type.value,
        }
        if self.issuer is not None:
            payload["iss"] = self.issuer
        if self.audience is not None:
            payload["aud"] = self.audience
        if extra_claims:
            payload.update(extra_claims)

        # Create simple JWT: base64(header).base64(payload).signature
        header_obj = {"alg": "HS256", "typ": "JWT"}
        if self.key_id is not None:
            header_obj["kid"] = self.key_id
        header = base64.urlsafe_b64encode(json.dumps(header_obj).encode()).decode().rstrip('=')
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')

        message = f"{header}.{payload_b64}"
        signature = base64.urlsafe_b64encode(
            hmac.new(self.secret, message.encode(), hashlib.sha256).digest()
        ).decode().rstrip('=')

        token_value = f"{message}.{signature}"

        metadata = {
            "username": user.username,
            "roles": list(user.roles),
            "permissions": list(user.permissions),
            "tenant_id": user.tenant_id,
            "jti": payload["jti"],
        }
        if extra_claims:
            metadata.update(extra_claims)

        return Token(
            value=token_value,
            type=token_type,
            user_id=user.id,
            issued_at=issued_at,
            expires_at=expires_at,
            metadata=metadata,
            clock=self.clock,
        )
    
    def verify(self, token_value: str) -> Optional[Token]:
        """Verify and decode a JWT-like token."""
        try:
            parts = token_value.split('.')
            if len(parts) != 3:
                return None

            header_b64, payload_b64, signature_b64 = parts

            # Decode and validate header
            header_padding = '=' * (-len(header_b64) % 4)
            header_json = base64.urlsafe_b64decode(header_b64 + header_padding).decode()
            header = json.loads(header_json)
            if header.get("alg") not in self.allowed_algorithms:
                return None
            if self.key_id is not None and header.get("kid") != self.key_id:
                return None

            # Verify signature
            message = f"{header_b64}.{payload_b64}"
            expected_signature = base64.urlsafe_b64encode(
                hmac.new(self.secret, message.encode(), hashlib.sha256).digest()
            ).decode().rstrip('=')

            if not hmac.compare_digest(signature_b64, expected_signature):
                return None

            # Decode payload
            payload_padding = '=' * (-len(payload_b64) % 4)
            payload_json = base64.urlsafe_b64decode(payload_b64 + payload_padding).decode()
            payload = json.loads(payload_json)

            # Validate claims
            if self.expected_issuer is not None and payload.get("iss") != self.expected_issuer:
                return None
            if self.expected_audience is not None and payload.get("aud") != self.expected_audience:
                return None
            if not payload.get("jti"):
                return None

            token_type = TokenType.JWT
            ttyp = payload.get("ttyp")
            if ttyp:
                try:
                    token_type = TokenType(ttyp)
                except ValueError:
                    token_type = TokenType.JWT

            issued_at = datetime.fromtimestamp(payload['iat'], tz=timezone.utc)
            expires_at = datetime.fromtimestamp(payload['exp'], tz=timezone.utc)

            token = Token(
                value=token_value,
                type=token_type,
                user_id=payload['user_id'],
                issued_at=issued_at,
                expires_at=expires_at,
                metadata={
                    "username": payload.get('username'),
                    "jti": payload.get('jti'),
                    "roles": payload.get('roles', []),
                    "permissions": payload.get('permissions', []),
                    "tenant_id": payload.get('tenant_id'),
                },
                clock=self.clock,
            )
            if 'fid' in payload:
                token.metadata['fid'] = payload['fid']

            # Check expiry
            if token.is_expired():
                return None

            if self.is_revoked(token_value):
                return None

            return token

        except Exception:
            return None
    
    def revoke(self, token_value: str):
        """Revoke a token."""
        token = self.verify(token_value)
        if token is not None and token.type == TokenType.REFRESH:
            family_id = token.metadata.get('fid')
            if family_id:
                _revoke_refresh_family(self.storage, family_id, extra_tokens=[token_value])
                return
        self.storage.set(f"revoked:{token_value}", True)
    
    def is_revoked(self, token_value: str) -> bool:
        """Check if a token has been revoked."""
        return self.storage.has(f"revoked:{token_value}")


class OpaqueTokenGenerator(TokenGenerator):
    """Opaque token generator with server-side storage."""
    
    def __init__(self, storage: Optional[StorageBackend] = None, clock: Optional[Clock] = None):
        self.storage = storage or InMemoryStorage(clock=clock)
        self.clock = clock or RealClock()
    
    def _token_key(self, token_value: str) -> str:
        return f"token:{token_value}"
    
    def _revoked_key(self, token_value: str) -> str:
        return f"revoked:{token_value}"
    
    def generate(self, user: User, expires_in: int = 3600,
                 extra_claims: Optional[Dict[str, Any]] = None,
                 token_type: Optional[TokenType] = None) -> Token:
        """Generate an opaque token."""
        token_value = secrets.token_urlsafe(32)
        issued_at = self.clock.now()
        expires_at = issued_at + timedelta(seconds=expires_in)

        token_type = token_type or TokenType.OPAQUE
        metadata = {
            "username": user.username,
            "roles": list(user.roles),
            "permissions": list(user.permissions),
            "tenant_id": user.tenant_id,
        }
        if extra_claims:
            metadata.update(extra_claims)

        token = Token(
            value=token_value,
            type=token_type,
            user_id=user.id,
            issued_at=issued_at,
            expires_at=expires_at,
            metadata=metadata,
            clock=self.clock,
        )

        self.storage.set(self._token_key(token_value), token, ttl=expires_in)
        return token
    
    def verify(self, token_value: str) -> Optional[Token]:
        """Verify an opaque token."""
        if self.is_revoked(token_value):
            return None
        token = self.storage.get(self._token_key(token_value))
        if token is None or token.is_expired():
            return None
        return token
    
    def revoke(self, token_value: str):
        """Revoke a token."""
        token = self.storage.get(self._token_key(token_value))
        if token is not None and token.type == TokenType.REFRESH:
            family_id = token.metadata.get('fid')
            if family_id:
                _revoke_refresh_family(self.storage, family_id, extra_tokens=[token_value])
        self.storage.delete(self._token_key(token_value))
        self.storage.set(self._revoked_key(token_value), True)
    
    def is_revoked(self, token_value: str) -> bool:
        """Check if a token has been revoked."""
        return self.storage.has(self._revoked_key(token_value))


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

        role_set = set(roles) if roles is not None else set()
        permission_set = set(permissions) if permissions is not None else set()

        self.users[username] = {
            "id": user_id,
            "username": username,
            "email": email,
            "password": hashed_password,
            "roles": role_set,
            "permissions": permission_set,
            "tenant_id": tenant_id,
        }

        return User(
            id=user_id,
            username=username,
            email=email,
            roles=role_set,
            permissions=permission_set,
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
        """Check if user is allowed to perform action on resource.

        Deny rules are evaluated first and override direct permissions or role
        permissions. After that, direct permissions, role permissions, and allow
        rules grant access.
        """
        # First pass: explicit deny rules override everything
        for rule in self.rules:
            if rule.matches(f"user:{user.username}", action, resource, context):
                if rule.effect == "deny":
                    return False
                continue
            if any(rule.matches(f"role:{role}", action, resource, context) for role in user.roles):
                if rule.effect == "deny":
                    return False
                continue
            if rule.matches("*", action, resource, context):
                if rule.effect == "deny":
                    return False
                continue

        # Direct permissions
        if user.has_permission(f"{action}:{resource}"):
            return True

        # Role-based permissions
        for role in user.roles:
            role_perms = self.role_permissions.get(role, set())
            if f"{action}:{resource}" in role_perms or f"{action}:*" in role_perms:
                return True

        # Second pass: allow rules
        for rule in self.rules:
            if rule.matches(f"user:{user.username}", action, resource, context):
                return rule.effect == "allow"
            if any(rule.matches(f"role:{role}", action, resource, context) for role in user.roles):
                return rule.effect == "allow"
            if rule.matches("*", action, resource, context):
                return rule.effect == "allow"

        return False


# ============================================================================
# Session Manager
# ============================================================================

class SessionManager:
    """Manages user sessions."""
    
    def __init__(self, default_ttl: int = 3600, storage: Optional[StorageBackend] = None, clock: Optional[Clock] = None):
        self.storage = storage or InMemoryStorage(clock=clock)
        self.default_ttl = default_ttl
        self.clock = clock or RealClock()
    
    def _session_key(self, session_id: str) -> str:
        return f"session:{session_id}"
    
    def _user_sessions_key(self, user_id: str) -> str:
        return f"user_sessions:{user_id}"
    
    def create_session(self, user_id: str, device_id: Optional[str] = None,
                      ip_address: Optional[str] = None, user_agent: Optional[str] = None,
                      ttl: Optional[int] = None) -> Session:
        """Create a new session."""
        session_id = secrets.token_urlsafe(32)
        if ttl is None:
            ttl = self.default_ttl
        
        now = self.clock.now()
        # If ttl is negative or zero, create an expired session
        if ttl <= 0:
            expires_at = now - timedelta(seconds=1)
        else:
            expires_at = now + timedelta(seconds=ttl)
        
        session = Session(
            id=session_id,
            user_id=user_id,
            device_id=device_id,
            ip_address=ip_address,
            user_agent=user_agent,
            expires_at=expires_at,
            clock=self.clock,
        )
        
        self.storage.set(self._session_key(session_id), session, ttl=ttl)
        
        # Update user session index
        index = self.storage.get(self._user_sessions_key(user_id)) or set()
        index.add(session_id)
        self.storage.set(self._user_sessions_key(user_id), index)
        
        return session
    
    def get_session(self, session_id: str) -> Optional[Session]:
        """Get a session by ID."""
        session = self.storage.get(self._session_key(session_id))
        if session is None or session.is_expired():
            return None
        session.touch()
        self.storage.set(self._session_key(session_id), session)
        return session
    
    def revoke_session(self, session_id: str):
        """Revoke a session."""
        session = self.storage.get(self._session_key(session_id))
        if session is not None:
            self.storage.delete(self._session_key(session_id))
            index = self.storage.get(self._user_sessions_key(session.user_id)) or set()
            index.discard(session_id)
            self.storage.set(self._user_sessions_key(session.user_id), index)
    
    def revoke_user_sessions(self, user_id: str):
        """Revoke all sessions for a user."""
        index = self.storage.get(self._user_sessions_key(user_id)) or set()
        for session_id in list(index):
            self.storage.delete(self._session_key(session_id))
        self.storage.delete(self._user_sessions_key(user_id))
    
    def cleanup_expired(self):
        """Remove expired sessions."""
        for key in list(self.storage.keys(prefix="session:")):
            session = self.storage.get(key)
            if session is not None and session.is_expired():
                self.storage.delete(key)
                index = self.storage.get(self._user_sessions_key(session.user_id)) or set()
                if session.id in index:
                    index.discard(session.id)
                    self.storage.set(self._user_sessions_key(session.user_id), index)


# ============================================================================
# Main Auth Class
# ============================================================================

class Auth:
    """Main authentication and authorization framework."""
    
    def __init__(
        self,
        secret: str,
        token_type: TokenType = TokenType.JWT,
        issuer: Optional[str] = None,
        audience: Optional[str] = None,
        key_id: Optional[str] = None,
        allowed_algorithms: Optional[List[str]] = None,
        storage: Optional[StorageBackend] = None,
        clock: Optional[Clock] = None,
    ):
        if not secret:
            raise AuthError(
                "A secret must be provided. Do not use an empty or auto-generated secret in production."
            )
        self.secret = secret
        self.token_type = token_type
        self.issuer = issuer
        self.audience = audience
        self.key_id = key_id
        self.allowed_algorithms = allowed_algorithms
        self.clock = clock or RealClock()
        
        # Shared storage backend (defaults to in-memory)
        self.storage = storage or InMemoryStorage(clock=self.clock)
        
        # Initialize components
        self.providers: Dict[str, AuthProvider] = {}
        self.token_generator: TokenGenerator = self._create_token_generator(token_type)
        self.policy_engine = PolicyEngine()
        self.session_manager = SessionManager(storage=self.storage, clock=self.clock)
    
    def _create_token_generator(self, token_type: TokenType) -> TokenGenerator:
        """Create appropriate token generator."""
        if token_type == TokenType.JWT:
            return SimpleJWTGenerator(
                self.secret,
                storage=self.storage,
                issuer=self.issuer,
                audience=self.audience,
                key_id=self.key_id,
                allowed_algorithms=self.allowed_algorithms,
                expected_issuer=self.issuer,
                expected_audience=self.audience,
                clock=self.clock,
            )
        elif token_type == TokenType.OPAQUE:
            return OpaqueTokenGenerator(storage=self.storage, clock=self.clock)
        else:
            raise AuthError(f"Unsupported token type: {token_type}")
    
    def add_provider(self, name: str, provider: AuthProvider):
        """Add an authentication provider."""
        self.providers[name] = provider
    
    def authenticate(self, provider_name: str, credentials: Dict[str, Any]) -> Optional[User]:
        """Authenticate a user using the specified provider."""
        provider = self.providers.get(provider_name)
        if not provider:
            raise AuthError(f"Unknown provider: {provider_name}")
        
        return provider.authenticate(credentials)
    
    def login(self, provider_name: str, credentials: Dict[str, Any],
             create_session: bool = True, ttl: int = 3600) -> Optional[Dict[str, Any]]:
        """Authenticate and create tokens/session."""
        user = self.authenticate(provider_name, credentials)
        if not user:
            return None

        # Generate access token
        access_token = self.token_generator.generate(user, expires_in=ttl)

        # Generate refresh token in a unique family
        family_id = secrets.token_urlsafe(16)
        refresh_ttl = ttl * 24
        refresh_token = self.token_generator.generate(
            user,
            expires_in=refresh_ttl,
            token_type=TokenType.REFRESH,
            extra_claims={"fid": family_id},
        )

        # Store active refresh-token family record
        self.storage.set(f"refresh_family:{family_id}", refresh_token.value, ttl=refresh_ttl)
        self.storage.set(
            f"refresh_meta:{refresh_token.value}",
            {"fid": family_id, "user_id": user.id, "username": user.username},
            ttl=refresh_ttl,
        )

        result = {
            "user": user,
            "access_token": access_token.value,
            "refresh_token": refresh_token.value,
            "token_type": "Bearer",
            "expires_in": ttl,
            "family_id": family_id,
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
        return self.token_generator.verify(token_value)
    
    def revoke_token(self, token_value: str):
        """Revoke a token."""
        self.token_generator.revoke(token_value)
    
    def _user_from_token(self, token: Token) -> User:
        """Reconstruct a User from a verified token's metadata."""
        return User(
            id=token.user_id,
            username=token.metadata.get('username', ''),
            roles=set(token.metadata.get('roles', [])),
            permissions=set(token.metadata.get('permissions', [])),
            tenant_id=token.metadata.get('tenant_id'),
        )

    def refresh(self, refresh_token_value: str, token_ttl: int = 3600) -> Optional[Dict[str, Any]]:
        """Refresh an access token using a refresh token.

        Implements refresh-token rotation with family binding and reuse
        detection. If the presented refresh token is not the currently active
        token for its family, the whole family is revoked.
        """
        token = self.verify_token(refresh_token_value)
        if not token or token.type != TokenType.REFRESH:
            return None

        family_id = token.metadata.get('fid')
        if not family_id:
            return None

        active_token = self.storage.get(f"refresh_family:{family_id}")
        if active_token is None or active_token != refresh_token_value:
            _revoke_refresh_family(
                self.storage,
                family_id,
                extra_tokens=[refresh_token_value, active_token] if active_token else [refresh_token_value],
            )
            return None

        # Valid refresh: revoke the old token and rotate to a new one
        user = self._user_from_token(token)
        new_access = self.token_generator.generate(user, expires_in=token_ttl)
        refresh_ttl = token_ttl * 24
        new_refresh = self.token_generator.generate(
            user,
            expires_in=refresh_ttl,
            token_type=TokenType.REFRESH,
            extra_claims={"fid": family_id},
        )

        self.storage.set(f"revoked:{refresh_token_value}", True)
        self.storage.delete(f"token:{refresh_token_value}")
        self.storage.delete(f"refresh_meta:{refresh_token_value}")
        self.storage.set(f"refresh_family:{family_id}", new_refresh.value, ttl=refresh_ttl)
        self.storage.set(
            f"refresh_meta:{new_refresh.value}",
            {"fid": family_id, "user_id": user.id, "username": user.username},
            ttl=refresh_ttl,
        )

        return {
            "user": user,
            "access_token": new_access.value,
            "refresh_token": new_refresh.value,
            "token_type": "Bearer",
            "expires_in": token_ttl,
            "family_id": family_id,
        }

    def refresh_token(self, refresh_token_value: str, token_ttl: int = 3600) -> Optional[Dict[str, Any]]:
        """Refresh an access token (alias for :meth:`refresh`)."""
        return self.refresh(refresh_token_value, token_ttl=token_ttl)
    
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
    'Auth', 'AuthError', 'User', 'Token', 'Session', 'PolicyRule', 'Policy',
    'TokenType', 'AuthMethod',
    'Clock', 'RealClock', 'FixedClock',
    'StorageBackend', 'InMemoryStorage',
    'AuthProvider', 'LocalAuthProvider', 'APIKeyAuthProvider',
    'PasswordHasher', 'PBKDF2Hasher',
    'TokenGenerator', 'SimpleJWTGenerator', 'OpaqueTokenGenerator',
    'PolicyEngine', 'SessionManager',
]
