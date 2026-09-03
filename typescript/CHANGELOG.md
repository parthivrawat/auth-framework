# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2024-08-26

### Added
- Initial release of Auth & Authorization Framework (TypeScript)
- Local authentication with PBKDF2 password hashing (100k iterations)
- API key authentication provider
- JWT token generation and verification (minimal dependencies)
- Opaque token support with server-side storage
- Token refresh and revocation mechanisms
- RBAC (Role-Based Access Control) engine
- ABAC (Attribute-Based Access Control) with policy rules
- Session management with device tracking
- Multi-tenant support with tenant isolation
- Wildcard pattern matching in policy rules
- Context-aware policy decisions
- Full TypeScript type safety
- Comprehensive test suite (38 tests, 100% passing)
- Complete documentation and examples

### Security
- PBKDF2-SHA256 password hashing with 100,000 iterations
- HMAC-SHA256 token signatures
- Timing-safe password comparison
- Cryptographically secure random token generation
- Server-side token revocation list

## [1.0.1] - 2026-08-27

### Added
- Added Rust implementation to the multi-language Auth & Authorization Framework
- GitHub Actions CI and publish support for the Rust crate

## [1.0.3] - 2026-09-03

### Added
- Pluggable `StorageBackend` abstraction for sessions, token revocation lists, and opaque tokens
- Real refresh-token rotation with family binding and reuse detection
- Optional JWT claims (`iss`, `aud`, `jti`, `kid`) and allowed-algorithm whitelist
- Multi-wildcard (`*`, `?`) pattern matching for policy resources

### Changed
- `Auth` constructor now requires an explicit signing secret
- Build now produces dual CJS/ESM output via `tsup` with corrected `exports` map

### Fixed
- Policy engine now evaluates explicit `deny` rules before any `allow` checks

## [Unreleased]

### Planned
- OAuth2/OIDC provider implementation
- SAML provider implementation
- Redis-backed session storage
- Database-backed token storage
- Decorator support for route protection
- Express.js middleware
- NestJS integration
- Rate limiting for authentication endpoints

[1.0.3]: https://github.com/parthivrawat/auth-framework/releases/tag/v1.0.3
[1.0.1]: https://github.com/parthivrawat/auth-framework/releases/tag/v1.0.1
[1.0.0]: https://github.com/parthivrawat/auth-framework/releases/tag/v1.0.0
