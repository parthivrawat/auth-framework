# Auth & Authorization Framework (Go)

A unified identity, session, token, and permission framework with pluggable providers, strong defaults, and production-ready security.

## Features

- ✅ **Multiple Authentication Methods**
  - Username/password with PBKDF2 password hashing
  - API key authentication
  
- ✅ **Token Management**
  - JWT tokens (simple implementation)
  - Opaque tokens with server-side storage
  - Token revocation

- ✅ **Authorization**
  - Role-Based Access Control (RBAC)
  - Attribute-Based Access Control (ABAC)
  - Policy engine with wildcard matching

- ✅ **Session Management**
  - Device and IP tracking
  - Session expiry and renewal
  - Goroutine-safe

## Installation

### Using Go Modules (Recommended)

```bash
go get github.com/parthivrawat/auth-framework@latest
```

Or add to your `go.mod`:

```go
require github.com/parthivrawat/auth-framework v1.0.0
```

Then run:

```bash
go mod tidy
```

### From Source

```bash
git clone https://github.com/parthivrawat/auth-framework
cd auth-framework/go
go build
```

## Quick Start

```go
package main

import (
    "fmt"
    auth "github.com/parthivrawat/auth-framework"
)

func main() {
    // Initialize auth framework
    authFramework := auth.NewAuth("secret_key", auth.TokenTypeJWT)

    // Add local authentication provider
    provider := auth.NewLocalAuthProvider()
    authFramework.AddProvider("local", provider)

    // Register a user
    roles := map[string]bool{"admin": true}
    user, _ := provider.RegisterUser("alice", "password", "alice@example.com", roles, nil, "")

    // Login
    result, _ := authFramework.Login("local", map[string]interface{}{
        "username": "alice",
        "password": "password",
    }, true, 3600)

    fmt.Println("Access Token:", result.AccessToken)
}
```

## Testing

```bash
go test -v
```

## License

MIT License - see LICENSE file for details
