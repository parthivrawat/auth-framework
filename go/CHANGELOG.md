# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2024-08-26

### Added
- Initial release of Auth & Authorization Framework (Go)
- Local authentication with PBKDF2 password hashing (100k iterations)
- API key authentication provider (planned)
- JWT token generation and verification
- Opaque token support with server-side storage
- Token revocation mechanisms
- RBAC (Role-Based Access Control) engine
- ABAC (Attribute-Based Access Control) with policy rules
- Session management with device tracking
- Multi-tenant support with tenant isolation
- Wildcard pattern matching in policy rules
- Context-aware policy decisions
- Goroutine-safe implementations with proper mutex usage
- Comprehensive test suite (14 tests, 100% passing)
- Complete documentation with godoc comments

### Security
- PBKDF2-SHA256 password hashing with 100,000 iterations
- HMAC-SHA256 token signatures
- Timing-safe password comparison
- Cryptographically secure random token generation
- Server-side token revocation list

### Performance
- Efficient concurrent access with RWMutex
- Zero-allocation token verification
- Optimized policy checking

## [Unreleased]

### Planned
- OAuth2/OIDC provider implementation
- SAML provider implementation
- Redis-backed session storage
- Database-backed token storage
- Gin middleware integration
- Echo middleware integration
- gRPC interceptors
- Rate limiting for authentication endpoints

[1.0.0]: https://github.com/parthivrawat/auth-framework/releases/tag/v1.0.0
