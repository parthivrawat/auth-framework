package authframework

import (
	"testing"
	"time"
)

func TestUserCreation(t *testing.T) {
	user := NewUser("user123", "alice")
	user.Email = "alice@example.com"
	user.Roles["admin"] = true
	user.Permissions["read:documents"] = true

	if user.ID != "user123" {
		t.Errorf("Expected ID user123, got %s", user.ID)
	}
	if !user.HasRole("admin") {
		t.Error("Expected user to have admin role")
	}
	if !user.HasPermission("read:documents") {
		t.Error("Expected user to have read:documents permission")
	}
}

func TestTokenExpiry(t *testing.T) {
	expiredToken := &Token{
		Value:     "token123",
		Type:      TokenTypeJWT,
		UserID:    "user123",
		ExpiresAt: time.Now().Add(-time.Hour),
	}

	validToken := &Token{
		Value:     "token456",
		Type:      TokenTypeJWT,
		UserID:    "user123",
		ExpiresAt: time.Now().Add(time.Hour),
	}

	if !expiredToken.IsExpired() {
		t.Error("Expected token to be expired")
	}
	if validToken.IsExpired() {
		t.Error("Expected token to be valid")
	}
}

func TestSessionExpiry(t *testing.T) {
	expiredTime := time.Now().Add(-time.Hour)
	expiredSession := &Session{
		ID:        "session123",
		UserID:    "user123",
		ExpiresAt: &expiredTime,
	}

	validTime := time.Now().Add(time.Hour)
	validSession := &Session{
		ID:        "session456",
		UserID:    "user123",
		ExpiresAt: &validTime,
	}

	if !expiredSession.IsExpired() {
		t.Error("Expected session to be expired")
	}
	if validSession.IsExpired() {
		t.Error("Expected session to be valid")
	}
}

func TestPolicyRuleMatching(t *testing.T) {
	rule := &PolicyRule{
		Subject:  "user:alice",
		Action:   "read",
		Resource: "document:123",
		Effect:   "allow",
	}

	if !rule.Matches("user:alice", "read", "document:123", nil) {
		t.Error("Expected rule to match")
	}
	if rule.Matches("user:bob", "read", "document:123", nil) {
		t.Error("Expected rule not to match")
	}
}

func TestPBKDF2Hasher(t *testing.T) {
	hasher := NewPBKDF2Hasher()
	password := "secure_password_123"

	hashed, err := hasher.Hash(password)
	if err != nil {
		t.Fatalf("Failed to hash password: %v", err)
	}

	if err := hasher.Verify(password, hashed); err != nil {
		t.Error("Failed to verify correct password")
	}

	if err := hasher.Verify("wrong_password", hashed); err == nil {
		t.Error("Expected verification to fail for wrong password")
	}
}

func TestSimpleJWTGenerator(t *testing.T) {
	generator := NewSimpleJWTGenerator("test_secret_key")

	user := NewUser("user123", "alice")
	user.Roles["admin"] = true

	token, err := generator.Generate(user, 3600)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	if token.Type != TokenTypeJWT {
		t.Errorf("Expected token type JWT, got %s", token.Type)
	}

	verified, err := generator.Verify(token.Value)
	if err != nil {
		t.Errorf("Failed to verify token: %v", err)
	}
	if verified.UserID != "user123" {
		t.Errorf("Expected user ID user123, got %s", verified.UserID)
	}
}

func TestOpaqueTokenGenerator(t *testing.T) {
	generator := NewOpaqueTokenGenerator()

	user := NewUser("user123", "alice")
	token, err := generator.Generate(user, 3600)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	if token.Type != TokenTypeOpaque {
		t.Errorf("Expected token type OPAQUE, got %s", token.Type)
	}

	verified, err := generator.Verify(token.Value)
	if err != nil {
		t.Errorf("Failed to verify token: %v", err)
	}
	if verified.UserID != "user123" {
		t.Errorf("Expected user ID user123, got %s", verified.UserID)
	}

	// Test revocation
	generator.Revoke(token.Value)
	if _, err := generator.Verify(token.Value); err == nil {
		t.Error("Expected verification to fail after revocation")
	}
}

func TestLocalAuthProvider(t *testing.T) {
	provider := NewLocalAuthProvider()

	roles := map[string]bool{"admin": true}
	permissions := map[string]bool{"read:all": true}

	_, err := provider.RegisterUser("alice", "secure_password", "alice@example.com", roles, permissions, "")
	if err != nil {
		t.Fatalf("Failed to register user: %v", err)
	}

	// Valid credentials
	user, err := provider.Authenticate(map[string]interface{}{
		"username": "alice",
		"password": "secure_password",
	})
	if err != nil {
		t.Errorf("Failed to authenticate with valid credentials: %v", err)
	}
	if user.Username != "alice" {
		t.Errorf("Expected username alice, got %s", user.Username)
	}

	// Invalid password
	_, err = provider.Authenticate(map[string]interface{}{
		"username": "alice",
		"password": "wrong_password",
	})
	if err == nil {
		t.Error("Expected authentication to fail with wrong password")
	}
}

func TestPolicyEngine(t *testing.T) {
	engine := NewPolicyEngine()

	user := NewUser("user123", "alice")
	user.Permissions["read:document:123"] = true

	if !engine.Check(user, "read", "document:123", nil) {
		t.Error("Expected permission check to pass")
	}
	if engine.Check(user, "write", "document:123", nil) {
		t.Error("Expected permission check to fail")
	}

	// Test role-based permissions
	engine.AddRolePermission("admin", "write:*")
	user.Roles["admin"] = true

	if !engine.Check(user, "write", "document:123", nil) {
		t.Error("Expected role-based permission check to pass")
	}
}

func TestSessionManager(t *testing.T) {
	manager := NewSessionManager(3600)

	session := manager.CreateSession("user123", "device1", "192.168.1.1", "Mozilla/5.0", 0)

	if session.UserID != "user123" {
		t.Errorf("Expected user ID user123, got %s", session.UserID)
	}

	retrieved := manager.GetSession(session.ID)
	if retrieved == nil {
		t.Error("Expected to retrieve session")
	}

	manager.RevokeSession(session.ID)
	if manager.GetSession(session.ID) != nil {
		t.Error("Expected session to be revoked")
	}
}

func TestAuthLogin(t *testing.T) {
	auth := NewAuth("test_secret", TokenTypeJWT)
	provider := NewLocalAuthProvider()
	auth.AddProvider("local", provider)

	roles := map[string]bool{"admin": true}
	provider.RegisterUser("alice", "secure_password", "alice@example.com", roles, nil, "")

	result, err := auth.Login("local", map[string]interface{}{
		"username": "alice",
		"password": "secure_password",
	}, true, 3600)

	if err != nil {
		t.Fatalf("Login failed: %v", err)
	}
	if result.User.Username != "alice" {
		t.Errorf("Expected username alice, got %s", result.User.Username)
	}
	if result.AccessToken == "" {
		t.Error("Expected access token")
	}
	if result.SessionID == "" {
		t.Error("Expected session ID")
	}
}

func TestAuthTokenVerification(t *testing.T) {
	auth := NewAuth("test_secret", TokenTypeJWT)
	provider := NewLocalAuthProvider()
	auth.AddProvider("local", provider)

	provider.RegisterUser("alice", "secure_password", "", nil, nil, "")
	result, _ := auth.Login("local", map[string]interface{}{
		"username": "alice",
		"password": "secure_password",
	}, false, 3600)

	token, err := auth.VerifyToken(result.AccessToken)
	if err != nil {
		t.Errorf("Failed to verify token: %v", err)
	}
	if token.UserID != result.User.ID {
		t.Error("Token user ID mismatch")
	}
}

func TestAuthTokenRevocation(t *testing.T) {
	auth := NewAuth("test_secret", TokenTypeJWT)
	provider := NewLocalAuthProvider()
	auth.AddProvider("local", provider)

	provider.RegisterUser("alice", "secure_password", "", nil, nil, "")
	result, _ := auth.Login("local", map[string]interface{}{
		"username": "alice",
		"password": "secure_password",
	}, false, 3600)

	// Token should be valid
	if _, err := auth.VerifyToken(result.AccessToken); err != nil {
		t.Error("Expected token to be valid")
	}

	// Revoke token
	auth.RevokeToken(result.AccessToken)

	// Token should now be invalid
	if _, err := auth.VerifyToken(result.AccessToken); err == nil {
		t.Error("Expected token to be revoked")
	}
}

func TestAuthPermissionCheck(t *testing.T) {
	auth := NewAuth("test_secret", TokenTypeJWT)

	auth.PolicyEngine.AddRolePermission("admin", "read:*")

	user := NewUser("user123", "alice")
	user.Roles["admin"] = true

	if !auth.CheckPermission(user, "read", "document:123", nil) {
		t.Error("Expected permission check to pass")
	}
	if auth.CheckPermission(user, "write", "document:123", nil) {
		t.Error("Expected permission check to fail")
	}
}
