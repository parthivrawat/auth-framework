"""
Comprehensive tests for Auth & Authorization Framework
"""

import pytest
from datetime import datetime, timedelta
from auth_framework import (
    Auth, User, Token, Session, PolicyRule, Policy,
    TokenType, AuthMethod,
    LocalAuthProvider, APIKeyAuthProvider,
    PBKDF2Hasher, SimpleJWTGenerator, OpaqueTokenGenerator,
    PolicyEngine, SessionManager,
)


# ============================================================================
# User Tests
# ============================================================================

def test_user_creation():
    """Test user creation and basic properties."""
    user = User(
        id="user123",
        username="alice",
        email="alice@example.com",
        roles={"admin", "user"},
        permissions={"read:documents", "write:documents"},
        tenant_id="tenant1"
    )
    
    assert user.id == "user123"
    assert user.username == "alice"
    assert user.email == "alice@example.com"
    assert user.has_role("admin")
    assert user.has_permission("read:documents")
    assert user.tenant_id == "tenant1"


def test_user_role_checks():
    """Test user role checking methods."""
    user = User(
        id="user123",
        username="alice",
        roles={"admin", "editor"}
    )
    
    assert user.has_role("admin")
    assert not user.has_role("viewer")
    assert user.has_any_role(["admin", "viewer"])
    assert user.has_all_roles(["admin", "editor"])
    assert not user.has_all_roles(["admin", "viewer"])


def test_user_permission_checks():
    """Test user permission checking."""
    user = User(
        id="user123",
        username="alice",
        permissions={"read:documents", "write:documents"}
    )
    
    assert user.has_permission("read:documents")
    assert not user.has_permission("delete:documents")


# ============================================================================
# Token Tests
# ============================================================================

def test_token_expiry():
    """Test token expiry checking."""
    expired_token = Token(
        value="token123",
        type=TokenType.JWT,
        user_id="user123",
        expires_at=datetime.utcnow() - timedelta(hours=1)
    )
    
    valid_token = Token(
        value="token456",
        type=TokenType.JWT,
        user_id="user123",
        expires_at=datetime.utcnow() + timedelta(hours=1)
    )
    
    assert expired_token.is_expired()
    assert not valid_token.is_expired()


def test_token_time_until_expiry():
    """Test time until expiry calculation."""
    token = Token(
        value="token123",
        type=TokenType.JWT,
        user_id="user123",
        expires_at=datetime.utcnow() + timedelta(hours=1)
    )
    
    time_left = token.time_until_expiry()
    assert time_left.total_seconds() > 3500  # ~1 hour minus a bit


# ============================================================================
# Session Tests
# ============================================================================

def test_session_creation():
    """Test session creation."""
    session = Session(
        id="session123",
        user_id="user123",
        device_id="device1",
        ip_address="192.168.1.1",
        user_agent="Mozilla/5.0"
    )
    
    assert session.id == "session123"
    assert session.user_id == "user123"
    assert session.device_id == "device1"
    assert not session.is_expired()


def test_session_expiry():
    """Test session expiry."""
    expired_session = Session(
        id="session123",
        user_id="user123",
        expires_at=datetime.utcnow() - timedelta(hours=1)
    )
    
    valid_session = Session(
        id="session456",
        user_id="user123",
        expires_at=datetime.utcnow() + timedelta(hours=1)
    )
    
    assert expired_session.is_expired()
    assert not valid_session.is_expired()


def test_session_touch():
    """Test session last activity update."""
    session = Session(id="session123", user_id="user123")
    original_time = session.last_activity
    
    import time
    time.sleep(0.01)  # Small delay
    session.touch()
    
    assert session.last_activity > original_time


# ============================================================================
# Policy Rule Tests
# ============================================================================

def test_policy_rule_exact_match():
    """Test exact policy rule matching."""
    rule = PolicyRule(
        subject="user:alice",
        action="read",
        resource="document:123"
    )
    
    assert rule.matches("user:alice", "read", "document:123")
    assert not rule.matches("user:bob", "read", "document:123")
    assert not rule.matches("user:alice", "write", "document:123")


def test_policy_rule_wildcard_match():
    """Test wildcard policy rule matching."""
    rule = PolicyRule(
        subject="role:admin",
        action="*",
        resource="document:*"
    )
    
    assert rule.matches("role:admin", "read", "document:123")
    assert rule.matches("role:admin", "write", "document:456")
    assert not rule.matches("role:user", "read", "document:123")


def test_policy_rule_with_conditions():
    """Test policy rule with conditions."""
    rule = PolicyRule(
        subject="user:alice",
        action="read",
        resource="document:*",
        conditions={"tenant": "tenant1"}
    )
    
    assert rule.matches("user:alice", "read", "document:123", {"tenant": "tenant1"})
    assert not rule.matches("user:alice", "read", "document:123", {"tenant": "tenant2"})


# ============================================================================
# Password Hasher Tests
# ============================================================================

def test_pbkdf2_hasher():
    """Test PBKDF2 password hashing."""
    hasher = PBKDF2Hasher()
    password = "secure_password_123"
    
    hashed = hasher.hash(password)
    assert hashed.startswith("pbkdf2_sha256$")
    assert hasher.verify(password, hashed)
    assert not hasher.verify("wrong_password", hashed)


def test_pbkdf2_hasher_different_hashes():
    """Test that same password produces different hashes (due to salt)."""
    hasher = PBKDF2Hasher()
    password = "secure_password_123"
    
    hash1 = hasher.hash(password)
    hash2 = hasher.hash(password)
    
    assert hash1 != hash2
    assert hasher.verify(password, hash1)
    assert hasher.verify(password, hash2)


# ============================================================================
# Token Generator Tests
# ============================================================================

def test_simple_jwt_generator():
    """Test Simple JWT token generation and verification."""
    generator = SimpleJWTGenerator(secret="test_secret_key")
    
    user = User(
        id="user123",
        username="alice",
        roles={"admin"},
        permissions={"read:all"}
    )
    
    token = generator.generate(user, expires_in=3600)
    
    assert token.type == TokenType.JWT
    assert token.user_id == "user123"
    assert not token.is_expired()
    
    # Verify token
    verified = generator.verify(token.value)
    assert verified is not None
    assert verified.user_id == "user123"
    assert verified.metadata["username"] == "alice"


def test_jwt_generator_invalid_token():
    """Test JWT verification with invalid token."""
    generator = SimpleJWTGenerator(secret="test_secret_key")
    
    verified = generator.verify("invalid.token.here")
    assert verified is None


def test_jwt_generator_expired_token():
    """Test JWT verification with expired token."""
    generator = SimpleJWTGenerator(secret="test_secret_key")
    
    user = User(id="user123", username="alice")
    token = generator.generate(user, expires_in=-1)  # Already expired
    
    verified = generator.verify(token.value)
    assert verified is None


def test_opaque_token_generator():
    """Test opaque token generation and verification."""
    generator = OpaqueTokenGenerator()
    
    user = User(id="user123", username="alice")
    token = generator.generate(user, expires_in=3600)
    
    assert token.type == TokenType.OPAQUE
    assert token.user_id == "user123"
    
    # Verify token
    verified = generator.verify(token.value)
    assert verified is not None
    assert verified.user_id == "user123"


def test_opaque_token_revocation():
    """Test opaque token revocation."""
    generator = OpaqueTokenGenerator()
    
    user = User(id="user123", username="alice")
    token = generator.generate(user, expires_in=3600)
    
    # Token should be valid
    assert generator.verify(token.value) is not None
    
    # Revoke token
    generator.revoke(token.value)
    
    # Token should now be invalid
    assert generator.verify(token.value) is None


# ============================================================================
# Local Auth Provider Tests
# ============================================================================

def test_local_auth_provider_registration():
    """Test user registration with local provider."""
    provider = LocalAuthProvider()
    
    user = provider.register_user(
        username="alice",
        password="secure_password",
        email="alice@example.com",
        roles={"admin"},
        permissions={"read:all"}
    )
    
    assert user.username == "alice"
    assert user.email == "alice@example.com"
    assert user.has_role("admin")


def test_local_auth_provider_authentication():
    """Test authentication with local provider."""
    provider = LocalAuthProvider()
    
    provider.register_user(username="alice", password="secure_password")
    
    # Valid credentials
    user = provider.authenticate({"username": "alice", "password": "secure_password"})
    assert user is not None
    assert user.username == "alice"
    
    # Invalid password
    user = provider.authenticate({"username": "alice", "password": "wrong_password"})
    assert user is None
    
    # Non-existent user
    user = provider.authenticate({"username": "bob", "password": "password"})
    assert user is None


# ============================================================================
# API Key Auth Provider Tests
# ============================================================================

def test_api_key_provider_creation():
    """Test API key creation."""
    provider = APIKeyAuthProvider()
    
    user = User(id="user123", username="alice")
    api_key = provider.create_api_key(user)
    
    assert api_key.startswith("ak_")
    
    # Authenticate with API key
    authenticated_user = provider.authenticate({"api_key": api_key})
    assert authenticated_user is not None
    assert authenticated_user.id == "user123"


def test_api_key_revocation():
    """Test API key revocation."""
    provider = APIKeyAuthProvider()
    
    user = User(id="user123", username="alice")
    api_key = provider.create_api_key(user)
    
    # Key should work
    assert provider.authenticate({"api_key": api_key}) is not None
    
    # Revoke key
    provider.revoke_api_key(api_key)
    
    # Key should no longer work
    assert provider.authenticate({"api_key": api_key}) is None


# ============================================================================
# Policy Engine Tests
# ============================================================================

def test_policy_engine_direct_permission():
    """Test policy engine with direct permissions."""
    engine = PolicyEngine()
    
    user = User(
        id="user123",
        username="alice",
        permissions={"read:document:123"}
    )
    
    assert engine.check(user, "read", "document:123")
    assert not engine.check(user, "write", "document:123")


def test_policy_engine_role_permissions():
    """Test policy engine with role-based permissions."""
    engine = PolicyEngine()
    
    engine.add_role_permission("admin", "read:*")
    engine.add_role_permission("admin", "write:*")
    
    user = User(
        id="user123",
        username="alice",
        roles={"admin"}
    )
    
    assert engine.check(user, "read", "document:123")
    assert engine.check(user, "write", "document:123")


def test_policy_engine_rules():
    """Test policy engine with custom rules."""
    engine = PolicyEngine()
    
    engine.add_rule(PolicyRule(
        subject="user:alice",
        action="read",
        resource="document:*",
        effect="allow"
    ))
    
    user = User(id="user123", username="alice")
    
    assert engine.check(user, "read", "document:123")
    assert not engine.check(user, "write", "document:123")


def test_policy_engine_deny_rule():
    """Test policy engine with deny rules."""
    engine = PolicyEngine()
    
    engine.add_rule(PolicyRule(
        subject="user:alice",
        action="delete",
        resource="document:*",
        effect="deny"
    ))
    
    user = User(id="user123", username="alice")
    
    assert not engine.check(user, "delete", "document:123")


# ============================================================================
# Session Manager Tests
# ============================================================================

def test_session_manager_creation():
    """Test session creation."""
    manager = SessionManager()
    
    session = manager.create_session(
        user_id="user123",
        device_id="device1",
        ip_address="192.168.1.1"
    )
    
    assert session.user_id == "user123"
    assert session.device_id == "device1"


def test_session_manager_retrieval():
    """Test session retrieval."""
    manager = SessionManager()
    
    session = manager.create_session(user_id="user123")
    
    retrieved = manager.get_session(session.id)
    assert retrieved is not None
    assert retrieved.id == session.id


def test_session_manager_revocation():
    """Test session revocation."""
    manager = SessionManager()
    
    session = manager.create_session(user_id="user123")
    
    # Session should exist
    assert manager.get_session(session.id) is not None
    
    # Revoke session
    manager.revoke_session(session.id)
    
    # Session should no longer exist
    assert manager.get_session(session.id) is None


def test_session_manager_revoke_user_sessions():
    """Test revoking all sessions for a user."""
    manager = SessionManager()
    
    session1 = manager.create_session(user_id="user123")
    session2 = manager.create_session(user_id="user123")
    session3 = manager.create_session(user_id="user456")
    
    # Revoke all sessions for user123
    manager.revoke_user_sessions("user123")
    
    # user123 sessions should be gone
    assert manager.get_session(session1.id) is None
    assert manager.get_session(session2.id) is None
    
    # user456 session should still exist
    assert manager.get_session(session3.id) is not None


def test_session_manager_cleanup_expired():
    """Test cleanup of expired sessions."""
    manager = SessionManager()
    
    # Create expired session
    session1 = manager.create_session(user_id="user123", ttl=-1)
    
    # Create valid session
    session2 = manager.create_session(user_id="user456", ttl=3600)
    
    # Cleanup expired
    manager.cleanup_expired()
    
    # Expired session should be gone
    assert manager.get_session(session1.id) is None
    
    # Valid session should still exist
    assert manager.get_session(session2.id) is not None


# ============================================================================
# Auth Integration Tests
# ============================================================================

def test_auth_initialization():
    """Test Auth initialization."""
    auth = Auth()
    
    assert auth.secret is not None
    assert auth.token_type == TokenType.JWT
    assert auth.policy_engine is not None
    assert auth.session_manager is not None


def test_auth_add_provider():
    """Test adding authentication providers."""
    auth = Auth()
    provider = LocalAuthProvider()
    
    auth.add_provider("local", provider)
    
    assert "local" in auth.providers


def test_auth_login_flow():
    """Test complete login flow."""
    auth = Auth()
    provider = LocalAuthProvider()
    auth.add_provider("local", provider)
    
    # Register user
    provider.register_user(username="alice", password="secure_password")
    
    # Login
    result = auth.login("local", {"username": "alice", "password": "secure_password"})
    
    assert result is not None
    assert "access_token" in result
    assert "refresh_token" in result
    assert "session_id" in result
    assert result["user"].username == "alice"


def test_auth_login_invalid_credentials():
    """Test login with invalid credentials."""
    auth = Auth()
    provider = LocalAuthProvider()
    auth.add_provider("local", provider)
    
    provider.register_user(username="alice", password="secure_password")
    
    # Invalid password
    result = auth.login("local", {"username": "alice", "password": "wrong_password"})
    assert result is None


def test_auth_verify_token():
    """Test token verification."""
    auth = Auth()
    provider = LocalAuthProvider()
    auth.add_provider("local", provider)
    
    provider.register_user(username="alice", password="secure_password")
    result = auth.login("local", {"username": "alice", "password": "secure_password"})
    
    # Verify access token
    token = auth.verify_token(result["access_token"])
    assert token is not None
    assert token.user_id == result["user"].id


def test_auth_token_revocation():
    """Test token revocation."""
    auth = Auth()
    provider = LocalAuthProvider()
    auth.add_provider("local", provider)
    
    provider.register_user(username="alice", password="secure_password")
    result = auth.login("local", {"username": "alice", "password": "secure_password"})
    
    access_token = result["access_token"]
    
    # Token should be valid
    assert auth.verify_token(access_token) is not None
    
    # Revoke token
    auth.revoke_token(access_token)
    
    # Token should now be invalid
    assert auth.verify_token(access_token) is None


def test_auth_refresh_token():
    """Test token refresh."""
    import time
    
    auth = Auth()
    provider = LocalAuthProvider()
    auth.add_provider("local", provider)
    
    provider.register_user(username="alice", password="secure_password")
    result = auth.login("local", {"username": "alice", "password": "secure_password"})
    
    refresh_token = result["refresh_token"]
    
    # Small delay to ensure different timestamp
    time.sleep(1)
    
    # Refresh token
    new_tokens = auth.refresh_token(refresh_token)
    
    assert new_tokens is not None
    assert "access_token" in new_tokens
    assert new_tokens["access_token"] != result["access_token"]


def test_auth_check_permission():
    """Test permission checking."""
    auth = Auth()
    
    # Add role permission
    auth.policy_engine.add_role_permission("admin", "read:*")
    
    user = User(
        id="user123",
        username="alice",
        roles={"admin"}
    )
    
    assert auth.check_permission(user, "read", "document:123")
    assert not auth.check_permission(user, "write", "document:123")


def test_auth_opaque_tokens():
    """Test Auth with opaque tokens."""
    auth = Auth(token_type=TokenType.OPAQUE)
    provider = LocalAuthProvider()
    auth.add_provider("local", provider)
    
    provider.register_user(username="alice", password="secure_password")
    result = auth.login("local", {"username": "alice", "password": "secure_password"})
    
    assert result is not None
    assert "access_token" in result
    
    # Verify token
    token = auth.verify_token(result["access_token"])
    assert token is not None
    assert token.type == TokenType.OPAQUE


# ============================================================================
# Run Tests
# ============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
