"""
Example usage of Auth & Authorization Framework
"""

from auth_framework import (
    Auth, LocalAuthProvider, APIKeyAuthProvider,
    PolicyRule, TokenType, User
)


def main():
    print("=" * 60)
    print("Auth & Authorization Framework - Example")
    print("=" * 60)
    print()
    
    # ========================================================================
    # 1. Initialize Auth Framework
    # ========================================================================
    print("1. Initializing Auth Framework...")
    auth = Auth()
    
    # Add local authentication provider
    local_provider = LocalAuthProvider()
    auth.add_provider("local", local_provider)
    
    # Add API key provider
    api_provider = APIKeyAuthProvider()
    auth.add_provider("api_key", api_provider)
    
    print("✓ Auth framework initialized")
    print()
    
    # ========================================================================
    # 2. Register Users
    # ========================================================================
    print("2. Registering users...")
    
    alice = local_provider.register_user(
        username="alice",
        password="alice_password",
        email="alice@example.com",
        roles={"admin", "editor"},
        permissions={"read:all", "write:all"}
    )
    print(f"✓ Registered user: {alice.username} (roles: {alice.roles})")
    
    bob = local_provider.register_user(
        username="bob",
        password="bob_password",
        email="bob@example.com",
        roles={"viewer"},
        permissions={"read:documents"}
    )
    print(f"✓ Registered user: {bob.username} (roles: {bob.roles})")
    print()
    
    # ========================================================================
    # 3. Login and Get Tokens
    # ========================================================================
    print("3. Logging in users...")
    
    alice_login = auth.login("local", {
        "username": "alice",
        "password": "alice_password",
        "device_id": "device_001",
        "ip_address": "192.168.1.100"
    })
    
    if alice_login:
        print(f"✓ Alice logged in successfully")
        print(f"  Access Token: {alice_login['access_token'][:50]}...")
        print(f"  Refresh Token: {alice_login['refresh_token'][:50]}...")
        print(f"  Session ID: {alice_login['session_id']}")
    
    bob_login = auth.login("local", {
        "username": "bob",
        "password": "bob_password"
    })
    
    if bob_login:
        print(f"✓ Bob logged in successfully")
    print()
    
    # ========================================================================
    # 4. Verify Tokens
    # ========================================================================
    print("4. Verifying tokens...")
    
    alice_token = auth.verify_token(alice_login['access_token'])
    if alice_token:
        print(f"✓ Alice's token is valid")
        print(f"  User ID: {alice_token.user_id}")
        print(f"  Expires in: {alice_token.time_until_expiry()}")
    
    # Try invalid token
    invalid_token = auth.verify_token("invalid.token.here")
    print(f"✓ Invalid token rejected: {invalid_token is None}")
    print()
    
    # ========================================================================
    # 5. Setup RBAC Permissions
    # ========================================================================
    print("5. Setting up RBAC permissions...")
    
    # Add role-based permissions
    auth.policy_engine.add_role_permission("admin", "read:*")
    auth.policy_engine.add_role_permission("admin", "write:*")
    auth.policy_engine.add_role_permission("admin", "delete:*")
    
    auth.policy_engine.add_role_permission("editor", "read:*")
    auth.policy_engine.add_role_permission("editor", "write:*")
    
    auth.policy_engine.add_role_permission("viewer", "read:*")
    
    print("✓ Role permissions configured")
    print()
    
    # ========================================================================
    # 6. Check Permissions
    # ========================================================================
    print("6. Checking permissions...")
    
    # Alice (admin) should have all permissions
    alice_can_read = auth.check_permission(alice, "read", "document:123")
    alice_can_write = auth.check_permission(alice, "write", "document:123")
    alice_can_delete = auth.check_permission(alice, "delete", "document:123")
    
    print(f"Alice permissions:")
    print(f"  Can read: {alice_can_read}")
    print(f"  Can write: {alice_can_write}")
    print(f"  Can delete: {alice_can_delete}")
    
    # Bob (viewer) should only be able to read
    bob_can_read = auth.check_permission(bob, "read", "document:123")
    bob_can_write = auth.check_permission(bob, "write", "document:123")
    bob_can_delete = auth.check_permission(bob, "delete", "document:123")
    
    print(f"Bob permissions:")
    print(f"  Can read: {bob_can_read}")
    print(f"  Can write: {bob_can_write}")
    print(f"  Can delete: {bob_can_delete}")
    print()
    
    # ========================================================================
    # 7. Add Custom Policy Rules (ABAC)
    # ========================================================================
    print("7. Adding custom policy rules...")
    
    # Add a rule that allows Alice to access sensitive documents
    auth.policy_engine.add_rule(PolicyRule(
        subject="user:alice",
        action="read",
        resource="sensitive:*",
        effect="allow"
    ))
    
    # Add a rule that denies Bob from deleting anything
    auth.policy_engine.add_rule(PolicyRule(
        subject="user:bob",
        action="delete",
        resource="*",
        effect="deny"
    ))
    
    print("✓ Custom policy rules added")
    
    # Check custom rules
    alice_sensitive = auth.check_permission(alice, "read", "sensitive:report")
    bob_sensitive = auth.check_permission(bob, "read", "sensitive:report")
    
    print(f"Alice can read sensitive documents: {alice_sensitive}")
    print(f"Bob can read sensitive documents: {bob_sensitive}")
    print()
    
    # ========================================================================
    # 8. API Key Authentication
    # ========================================================================
    print("8. Creating and using API keys...")
    
    alice_api_key = api_provider.create_api_key(alice)
    print(f"✓ Created API key for Alice: {alice_api_key}")
    
    # Authenticate with API key
    api_user = auth.authenticate("api_key", {"api_key": alice_api_key})
    if api_user:
        print(f"✓ Authenticated via API key: {api_user.username}")
    print()
    
    # ========================================================================
    # 9. Session Management
    # ========================================================================
    print("9. Managing sessions...")
    
    alice_session_id = alice_login['session_id']
    alice_session = auth.session_manager.get_session(alice_session_id)
    
    if alice_session:
        print(f"✓ Alice's session is active")
        print(f"  Session ID: {alice_session.id}")
        print(f"  Device ID: {alice_session.device_id}")
        print(f"  IP Address: {alice_session.ip_address}")
        print(f"  Created: {alice_session.created_at}")
        print(f"  Last Activity: {alice_session.last_activity}")
    
    # Revoke Bob's session
    bob_session_id = bob_login['session_id']
    auth.session_manager.revoke_session(bob_session_id)
    print(f"✓ Bob's session revoked")
    
    # Try to get revoked session
    revoked_session = auth.session_manager.get_session(bob_session_id)
    print(f"✓ Revoked session is inaccessible: {revoked_session is None}")
    print()
    
    # ========================================================================
    # 10. Token Refresh
    # ========================================================================
    print("10. Refreshing tokens...")
    
    new_tokens = auth.refresh_token(alice_login['refresh_token'])
    if new_tokens:
        print(f"✓ Token refreshed successfully")
        print(f"  New Access Token: {new_tokens['access_token'][:50]}...")
    print()
    
    # ========================================================================
    # 11. Token Revocation
    # ========================================================================
    print("11. Revoking tokens...")
    
    # Revoke Alice's original access token
    auth.revoke_token(alice_login['access_token'])
    print(f"✓ Alice's original token revoked")
    
    # Try to verify revoked token
    revoked_token = auth.verify_token(alice_login['access_token'])
    print(f"✓ Revoked token is invalid: {revoked_token is None}")
    
    # New token should still work
    new_token_valid = auth.verify_token(new_tokens['access_token'])
    print(f"✓ New token is still valid: {new_token_valid is not None}")
    print()
    
    # ========================================================================
    # 12. Multi-Tenant Example
    # ========================================================================
    print("12. Multi-tenant example...")
    
    # Register users in different tenants
    tenant1_user = local_provider.register_user(
        username="tenant1_user",
        password="password",
        tenant_id="tenant1",
        roles={"user"}
    )
    
    tenant2_user = local_provider.register_user(
        username="tenant2_user",
        password="password",
        tenant_id="tenant2",
        roles={"user"}
    )
    
    # Add tenant-specific policy rule
    auth.policy_engine.add_rule(PolicyRule(
        subject="user:tenant1_user",
        action="read",
        resource="document:*",
        effect="allow",
        conditions={"tenant": "tenant1"}
    ))
    
    # Check with tenant context
    context_tenant1 = {"tenant": "tenant1"}
    context_tenant2 = {"tenant": "tenant2"}
    
    can_access_tenant1 = auth.check_permission(tenant1_user, "read", "document:123", context_tenant1)
    cannot_access_tenant2 = auth.check_permission(tenant1_user, "read", "document:123", context_tenant2)
    
    print(f"✓ Tenant1 user can access tenant1 documents: {can_access_tenant1}")
    print(f"✓ Tenant1 user cannot access tenant2 documents: {not cannot_access_tenant2}")
    print()
    
    # ========================================================================
    # 13. Cleanup
    # ========================================================================
    print("13. Cleanup...")
    
    # Cleanup expired sessions
    auth.session_manager.cleanup_expired()
    print("✓ Expired sessions cleaned up")
    
    # Revoke API key
    api_provider.revoke_api_key(alice_api_key)
    print("✓ API key revoked")
    
    # Verify revoked API key doesn't work
    revoked_api_user = auth.authenticate("api_key", {"api_key": alice_api_key})
    print(f"✓ Revoked API key is invalid: {revoked_api_user is None}")
    print()
    
    print("=" * 60)
    print("Example completed successfully!")
    print("=" * 60)


if __name__ == "__main__":
    main()
