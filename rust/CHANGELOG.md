# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.1] - 2026-08-27

### Added
- Initial Rust release of the Auth & Authorization Framework
- Local authentication with PBKDF2-SHA256 password hashing (100k iterations)
- API key authentication provider
- JWT token generation and verification using HMAC-SHA256
- Opaque token support with server-side storage
- Token refresh and revocation mechanisms
- RBAC (Role-Based Access Control) engine
- ABAC (Attribute-Based Access Control) with policy rules
- Session management with device tracking
- Multi-tenant support with tenant isolation
- Wildcard pattern matching in policy rules
- Context-aware policy decisions
- Thread-safe implementations using standard library locks
- Comprehensive test suite (18 tests, 100% passing)
- Complete documentation with rustdoc comments

### Security
- PBKDF2-SHA256 password hashing with 100,000 iterations
- HMAC-SHA256 token signatures
- Constant-time password comparison
- Cryptographically secure random token generation
- Server-side token revocation list

## [Unreleased]

### Planned
- OAuth2/OIDC provider implementation
- SAML provider implementation
- Redis-backed session storage
- Database-backed token storage
- Axum middleware integration
- Rate limiting for authentication endpoints

[1.0.1]: https://github.com/parthivrawat/auth-framework/releases/tag/v1.0.1
