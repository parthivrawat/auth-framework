# Auth & Authorization Framework (Rust)

A unified identity, session, token, and permission framework with pluggable providers, strong defaults, and production-ready security.

## Features

- **Multiple Authentication Methods**
  - Username/password with PBKDF2 password hashing
  - API key authentication

- **Token Management**
  - JWT tokens (simple HMAC-SHA256 implementation)
  - Opaque tokens with server-side storage
  - Token revocation and refresh

- **Authorization**
  - Role-Based Access Control (RBAC)
  - Attribute-Based Access Control (ABAC)
  - Policy engine with wildcard matching

- **Session Management**
  - Device and IP tracking
  - Session expiry
  - Thread-safe using standard library locks

## Installation

### From Source

```bash
git clone https://github.com/parthivrawat/auth-framework
cd auth-framework/rust
cargo build
```

### As a Dependency

```toml
[dependencies]
auth-framework-rs = { git = "https://github.com/parthivrawat/auth-framework" }
```

## Quick Start

```rust
use std::collections::HashMap;
use auth_framework_rs::{Auth, LocalAuthProvider, TokenType};

fn main() {
    let auth = Auth::new("secret_key", TokenType::JWT);
    let provider = LocalAuthProvider::new();
    auth.add_provider("local", Box::new(provider));

    let provider = auth
        .providers
        .lock()
        .unwrap()
        .get("local")
        .unwrap();
    provider
        .register_user("alice", "password", None, None, None, None)
        .unwrap();

    let mut creds = HashMap::new();
    creds.insert("username".to_string(), "alice".to_string());
    creds.insert("password".to_string(), "password".to_string());

    let result = auth.login("local", &creds, true, 3600).unwrap().unwrap();
    println!("Access Token: {}", result.access_token);
}
```

## Testing

```bash
cargo test
```

## License

MIT License - see LICENSE file for details.
