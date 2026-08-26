# Auth & Authorization Framework (TypeScript)

A unified identity, session, token, and permission framework with pluggable providers, strong defaults, and production-ready security.

## Features

- ✅ **Multiple Authentication Methods**
  - Username/password with secure password hashing (PBKDF2)
  - OAuth2/OIDC support (pluggable)
  - API key authentication
  
- ✅ **Token Management**
  - JWT tokens (simple implementation, minimal dependencies)
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

- ✅ **Type Safety**
  - Full TypeScript support
  - Strict type checking
  - IDE autocomplete

## Installation

### From NPM (Recommended)

```bash
npm install @parthivrawat/auth-framework
```

Or with Yarn:

```bash
yarn add @parthivrawat/auth-framework
```

Or with pnpm:

```bash
pnpm add @parthivrawat/auth-framework
```

### From Source

```bash
git clone https://github.com/parthivrawat/auth-framework
cd auth-framework/typescript
npm install
npm run build
```

## Quick Start

```typescript
import { Auth, LocalAuthProvider } from 'auth-framework';

// Initialize auth framework
const auth = new Auth();

// Add local authentication provider
const provider = new LocalAuthProvider();
auth.addProvider('local', provider);

// Register a user
const user = await provider.registerUser(
  'alice',
  'secure_password',
  'alice@example.com',
  new Set(['admin', 'user'])
);

// Login
const result = await auth.login('local', {
  username: 'alice',
  password: 'secure_password'
});

console.log('Access Token:', result.accessToken);
console.log('Session ID:', result.sessionId);
```

## API Reference

See the [full documentation](./docs/) for detailed API reference.

## Testing

```bash
npm test
```

## License

MIT License - see LICENSE file for details
