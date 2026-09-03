# Auth & Authorization Framework (Python)

A unified identity, session, token, and permission framework with pluggable providers, strong defaults, and production-ready security.

## Features

- ✅ **Multiple Authentication Methods**
  - Username/password with secure password hashing (PBKDF2)
  - OAuth2/OIDC support (pluggable)
  - SAML support (pluggable)
  - API key authentication

- ✅ **Token Management**
  - JWT tokens (simple implementation, no external dependencies)
  - Opaque tokens with server-side storage
  - Refresh token support
  - Token revocation

- ✅ **Authorization**
  - Role-Based Access Control (RBAC)
  - Attribute-Based Access Control (ABAC)
  - Policy engine with wildcard matching
  - Multi-tenant permission scoping

- ✅ **Session Management**
  - Device and IP tracking
  - Session expiry and renewal
  - Multi-device support
  - Session revocation

- ✅ **Security**
  - Secure password hashing (PBKDF2 with salt)
  - Token signature verification
  - Audit logging support
  - Zero dependencies for core functionality

## Installation

### From PyPI (Recommended)

```bash
pip install auth-framework-py
```

### From Source

```bash
git clone https://github.com/parthivrawat/auth-framework
cd auth-framework/python
pip install -e .
```

### Development Installation

```bash
pip install -e ".[dev]"
```

## Quick Start

### Basic Authentication

```python
from auth_framework import Auth, LocalAuthProvider

# Initialize auth framework (a strong secret is required)
auth = Auth("your-256-bit-secret")

# Add local authentication provider
provider = LocalAuthProvider()
auth.add_provider("local", provider)

# Register a user
user = provider.register_user(
    username="alice",
    password="secure_password",
    email="alice@example.com",
    roles={"admin", "user"}
)

# Login
result = auth.login("local", {
    "username": "alice",
    "password": "secure_password"
})

print(f"Access Token: {result['access_token']}")
print(f"Refresh Token: {result['refresh_token']}")
print(f"Session ID: {result['session_id']}")
```

### Token Verification

```python
# Verify an access token
token = auth.verify_token(result['access_token'])

if token and not token.is_expired():
    print(f"Token is valid for user: {token.user_id}")
else:
    print("Token is invalid or expired")
```

### Permission Checking (RBAC)

```python
from auth_framework import User

# Create a user with roles
user = User(
    id="user123",
    username="alice",
    roles={"admin"}
)

# Add role permissions
auth.policy_engine.add_role_permission("admin", "read:*")
auth.policy_engine.add_role_permission("admin", "write:*")

# Check permissions
if auth.check_permission(user, "read", "document:123"):
    print("User can read the document")

if auth.check_permission(user, "write", "document:123"):
    print("User can write the document")
```

### Policy Rules (ABAC)

```python
from auth_framework import PolicyRule

# Add a custom policy rule
auth.policy_engine.add_rule(PolicyRule(
    subject="user:alice",
    action="delete",
    resource="document:*",
    effect="allow",
    conditions={"tenant": "tenant1"}
))

# Check with context
context = {"tenant": "tenant1"}
if auth.check_permission(user, "delete", "document:123", context):
    print("User can delete the document in tenant1")
```

### API Key Authentication

```python
from auth_framework import APIKeyAuthProvider

# Add API key provider
api_provider = APIKeyAuthProvider()
auth.add_provider("api_key", api_provider)

# Create an API key for a user
api_key = api_provider.create_api_key(user)
print(f"API Key: {api_key}")

# Authenticate with API key
authenticated_user = auth.authenticate("api_key", {"api_key": api_key})
if authenticated_user:
    print(f"Authenticated as: {authenticated_user.username}")
```

### Session Management

```python
# Create a session
session = auth.session_manager.create_session(
    user_id=user.id,
    device_id="device123",
    ip_address="192.168.1.1",
    user_agent="Mozilla/5.0",
    ttl=3600  # 1 hour
)

# Get session
active_session = auth.session_manager.get_session(session.id)
if active_session and not active_session.is_expired():
    print(f"Session is active for user: {active_session.user_id}")

# Revoke session
auth.session_manager.revoke_session(session.id)

# Revoke all sessions for a user
auth.session_manager.revoke_user_sessions(user.id)
```

### Token Refresh

```python
# Refresh an access token using refresh token
new_tokens = auth.refresh_token(result['refresh_token'])

if new_tokens:
    print(f"New Access Token: {new_tokens['access_token']}")
```

### Opaque Tokens

```python
from auth_framework import TokenType

# Use opaque tokens instead of JWT
auth = Auth("your-256-bit-secret", token_type=TokenType.OPAQUE)

# Rest of the code remains the same
# Opaque tokens are stored server-side and can be easily revoked
```

## Advanced Usage

### Custom Password Hasher

```python
from auth_framework import PasswordHasher

class CustomHasher(PasswordHasher):
    def hash(self, password: str) -> str:
        # Your custom hashing logic
        pass
    
    def verify(self, password: str, hashed: str) -> bool:
        # Your custom verification logic
        pass

# Use custom hasher
provider = LocalAuthProvider(password_hasher=CustomHasher())
```

### Custom Authentication Provider

```python
from auth_framework import AuthProvider, User

class LDAPAuthProvider(AuthProvider):
    def authenticate(self, credentials: dict) -> Optional[User]:
        # Your LDAP authentication logic
        username = credentials.get('username')
        password = credentials.get('password')
        
        # Authenticate against LDAP
        # ...
        
        return User(
            id=ldap_user_id,
            username=username,
            roles=ldap_roles,
            permissions=ldap_permissions
        )

# Add custom provider
auth.add_provider("ldap", LDAPAuthProvider())
```

### Multi-Tenant Support

```python
# Register users with tenant IDs
user1 = provider.register_user(
    username="alice",
    password="password",
    tenant_id="tenant1"
)

user2 = provider.register_user(
    username="bob",
    password="password",
    tenant_id="tenant2"
)

# Add tenant-scoped policy rules
auth.policy_engine.add_rule(PolicyRule(
    subject="user:alice",
    action="read",
    resource="document:*",
    effect="allow",
    conditions={"tenant": "tenant1"}
))

# Check with tenant context
context = {"tenant": "tenant1"}
can_read = auth.check_permission(user1, "read", "document:123", context)
```

## API Reference

### Core Classes

- **Auth**: Main authentication and authorization framework
- **User**: Represents an authenticated user
- **Token**: Represents an authentication token
- **Session**: Represents a user session
- **PolicyRule**: Represents a policy rule for RBAC/ABAC

### Providers

- **LocalAuthProvider**: Username/password authentication
- **APIKeyAuthProvider**: API key authentication
- **AuthProvider**: Abstract base class for custom providers

### Token Generators

- **SimpleJWTGenerator**: JWT token generation (no external dependencies)
- **OpaqueTokenGenerator**: Opaque token generation with server-side storage

### Utilities

- **PolicyEngine**: RBAC/ABAC policy engine
- **SessionManager**: Session management
- **PBKDF2Hasher**: Secure password hashing

## Testing

Run the test suite:

```bash
pytest test_auth_framework.py -v
```

With coverage:

```bash
pytest test_auth_framework.py -v --cov=auth_framework --cov-report=term-missing
```

## Security Considerations

1. **Password Storage**: Passwords are hashed using PBKDF2 with 100,000 iterations and a random salt
2. **Token Secrets**: Provide a strong, externalized secret when constructing `Auth`
3. **Token Expiry**: Set appropriate TTLs for access and refresh tokens
4. **Session Security**: Track device IDs and IP addresses for session validation
5. **HTTPS**: Always use HTTPS in production to protect tokens in transit
6. **Token Revocation**: Implement token revocation for logout and security events

## Performance

- **Zero Dependencies**: Core functionality has no external dependencies
- **Efficient Token Verification**: JWT tokens are verified without database lookups
- **Session Cleanup**: Regularly cleanup expired sessions with `session_manager.cleanup_expired()`
- **Policy Caching**: Consider caching policy decisions for frequently accessed resources

## License

MIT License - see LICENSE file for details

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Support

For issues and questions, please open an issue on GitHub.
