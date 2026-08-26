// Package authframework provides a unified identity, session, token, and permission framework
// with pluggable providers, strong defaults, and production-ready security.
//
// # Features
//
//   - Multiple authentication methods (local, API key, OAuth2, OIDC)
//   - JWT and opaque token generation with refresh support
//   - RBAC (Role-Based Access Control) and ABAC (Attribute-Based Access Control)
//   - Session management with device tracking
//   - Multi-tenant support
//   - Wildcard pattern matching in policies
//   - Goroutine-safe implementations
//
// # Quick Start
//
// Initialize the auth framework:
//
//	auth := authframework.NewAuth("your-secret-key", authframework.TokenTypeJWT)
//
// Add a local authentication provider:
//
//	provider := authframework.NewLocalAuthProvider()
//	auth.AddProvider("local", provider)
//
// Register a user:
//
//	roles := map[string]bool{"admin": true}
//	user, err := provider.RegisterUser("alice", "password", "alice@example.com", roles, nil, "")
//	if err != nil {
//	    log.Fatal(err)
//	}
//
// Login and get tokens:
//
//	result, err := auth.Login("local", map[string]interface{}{
//	    "username": "alice",
//	    "password": "password",
//	}, true, 3600)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Println("Access Token:", result.AccessToken)
//
// Check permissions:
//
//	auth.PolicyEngine.AddRolePermission("admin", "read:*")
//	if auth.CheckPermission(user, "read", "document:123", nil) {
//	    fmt.Println("Access granted!")
//	}
//
// # Security
//
// The framework implements industry-standard security practices:
//
//   - PBKDF2-SHA256 password hashing with 100,000 iterations
//   - HMAC-SHA256 token signatures
//   - Timing-safe password comparison
//   - Cryptographically secure random token generation
//   - Server-side token revocation
//
// # Thread Safety
//
// All components are goroutine-safe and can be used concurrently without
// external synchronization.
//
// # Examples
//
// See the examples directory for complete working examples including:
//
//   - Basic authentication and authorization
//   - Session management
//   - Multi-tenant applications
//   - Custom authentication providers
//
// # Documentation
//
// For complete documentation, visit:
// https://pkg.go.dev/github.com/parthivrawat/auth-framework
//
// # Source Code
//
// https://github.com/parthivrawat/auth-framework
package authframework
