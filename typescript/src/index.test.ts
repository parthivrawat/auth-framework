/**
 * Comprehensive tests for Auth & Authorization Framework (TypeScript)
 */

import { describe, it, expect, beforeEach } from 'vitest';
import {
  Auth,
  UserImpl,
  TokenImpl,
  SessionImpl,
  PolicyRuleImpl,
  TokenType,
  LocalAuthProvider,
  APIKeyAuthProvider,
  PBKDF2Hasher,
  SimpleJWTGenerator,
  OpaqueTokenGenerator,
  PolicyEngine,
  SessionManager,
} from './index';

// ============================================================================
// User Tests
// ============================================================================

describe('User', () => {
  it('should create user with properties', () => {
    const user = new UserImpl(
      'user123',
      'alice',
      'alice@example.com',
      new Set(['admin', 'user']),
      new Set(['read:documents', 'write:documents']),
      {},
      'tenant1'
    );

    expect(user.id).toBe('user123');
    expect(user.username).toBe('alice');
    expect(user.email).toBe('alice@example.com');
    expect(user.hasRole('admin')).toBe(true);
    expect(user.hasPermission('read:documents')).toBe(true);
    expect(user.tenantId).toBe('tenant1');
  });

  it('should check roles correctly', () => {
    const user = new UserImpl(
      'user123',
      'alice',
      undefined,
      new Set(['admin', 'editor'])
    );

    expect(user.hasRole('admin')).toBe(true);
    expect(user.hasRole('viewer')).toBe(false);
    expect(user.hasAnyRole(['admin', 'viewer'])).toBe(true);
    expect(user.hasAllRoles(['admin', 'editor'])).toBe(true);
    expect(user.hasAllRoles(['admin', 'viewer'])).toBe(false);
  });

  it('should check permissions correctly', () => {
    const user = new UserImpl(
      'user123',
      'alice',
      undefined,
      new Set(),
      new Set(['read:documents', 'write:documents'])
    );

    expect(user.hasPermission('read:documents')).toBe(true);
    expect(user.hasPermission('delete:documents')).toBe(false);
  });
});

// ============================================================================
// Token Tests
// ============================================================================

describe('Token', () => {
  it('should check expiry correctly', () => {
    const expiredToken = new TokenImpl(
      'token123',
      TokenType.JWT,
      'user123',
      new Date(Date.now() - 3600 * 1000) // 1 hour ago
    );

    const validToken = new TokenImpl(
      'token456',
      TokenType.JWT,
      'user123',
      new Date(Date.now() + 3600 * 1000) // 1 hour from now
    );

    expect(expiredToken.isExpired()).toBe(true);
    expect(validToken.isExpired()).toBe(false);
  });

  it('should calculate time until expiry', () => {
    const token = new TokenImpl(
      'token123',
      TokenType.JWT,
      'user123',
      new Date(Date.now() + 3600 * 1000) // 1 hour from now
    );

    const timeLeft = token.timeUntilExpiry();
    expect(timeLeft).toBeGreaterThan(3500 * 1000); // ~1 hour minus a bit
  });
});

// ============================================================================
// Session Tests
// ============================================================================

describe('Session', () => {
  it('should create session with properties', () => {
    const session = new SessionImpl(
      'session123',
      'user123',
      'device1',
      '192.168.1.1',
      'Mozilla/5.0'
    );

    expect(session.id).toBe('session123');
    expect(session.userId).toBe('user123');
    expect(session.deviceId).toBe('device1');
    expect(session.isExpired()).toBe(false);
  });

  it('should check expiry correctly', () => {
    const expiredSession = new SessionImpl(
      'session123',
      'user123',
      undefined,
      undefined,
      undefined,
      new Date(),
      new Date(),
      new Date(Date.now() - 3600 * 1000) // 1 hour ago
    );

    const validSession = new SessionImpl(
      'session456',
      'user123',
      undefined,
      undefined,
      undefined,
      new Date(),
      new Date(),
      new Date(Date.now() + 3600 * 1000) // 1 hour from now
    );

    expect(expiredSession.isExpired()).toBe(true);
    expect(validSession.isExpired()).toBe(false);
  });

  it('should update last activity on touch', async () => {
    const session = new SessionImpl('session123', 'user123');
    const originalTime = session.lastActivity;

    await new Promise(resolve => setTimeout(resolve, 10));
    session.touch();

    expect(session.lastActivity.getTime()).toBeGreaterThan(originalTime.getTime());
  });
});

// ============================================================================
// Policy Rule Tests
// ============================================================================

describe('PolicyRule', () => {
  it('should match exact rules', () => {
    const rule = new PolicyRuleImpl('user:alice', 'read', 'document:123');

    expect(rule.matches('user:alice', 'read', 'document:123')).toBe(true);
    expect(rule.matches('user:bob', 'read', 'document:123')).toBe(false);
    expect(rule.matches('user:alice', 'write', 'document:123')).toBe(false);
  });

  it('should match wildcard rules', () => {
    const rule = new PolicyRuleImpl('role:admin', '*', 'document:*');

    expect(rule.matches('role:admin', 'read', 'document:123')).toBe(true);
    expect(rule.matches('role:admin', 'write', 'document:456')).toBe(true);
    expect(rule.matches('role:user', 'read', 'document:123')).toBe(false);
  });

  it('should match rules with conditions', () => {
    const rule = new PolicyRuleImpl(
      'user:alice',
      'read',
      'document:*',
      'allow',
      { tenant: 'tenant1' }
    );

    expect(rule.matches('user:alice', 'read', 'document:123', { tenant: 'tenant1' })).toBe(true);
    expect(rule.matches('user:alice', 'read', 'document:123', { tenant: 'tenant2' })).toBe(false);
  });
});

// ============================================================================
// Password Hasher Tests
// ============================================================================

describe('PBKDF2Hasher', () => {
  it('should hash and verify passwords', async () => {
    const hasher = new PBKDF2Hasher();
    const password = 'secure_password_123';

    const hashed = await hasher.hash(password);
    expect(hashed).toContain('pbkdf2_sha256$');
    expect(await hasher.verify(password, hashed)).toBe(true);
    expect(await hasher.verify('wrong_password', hashed)).toBe(false);
  });

  it('should produce different hashes for same password', async () => {
    const hasher = new PBKDF2Hasher();
    const password = 'secure_password_123';

    const hash1 = await hasher.hash(password);
    const hash2 = await hasher.hash(password);

    expect(hash1).not.toBe(hash2);
    expect(await hasher.verify(password, hash1)).toBe(true);
    expect(await hasher.verify(password, hash2)).toBe(true);
  });
});

// ============================================================================
// Token Generator Tests
// ============================================================================

describe('SimpleJWTGenerator', () => {
  it('should generate and verify JWT tokens', async () => {
    const generator = new SimpleJWTGenerator('test_secret_key');

    const user = new UserImpl(
      'user123',
      'alice',
      undefined,
      new Set(['admin']),
      new Set(['read:all'])
    );

    const token = await generator.generate(user, 3600);

    expect(token.type).toBe(TokenType.JWT);
    expect(token.userId).toBe('user123');
    expect(token.isExpired()).toBe(false);

    // Verify token
    const verified = await generator.verify(token.value);
    expect(verified).not.toBeNull();
    expect(verified!.userId).toBe('user123');
    expect(verified!.metadata?.username).toBe('alice');
  });

  it('should reject invalid tokens', async () => {
    const generator = new SimpleJWTGenerator('test_secret_key');

    const verified = await generator.verify('invalid.token.here');
    expect(verified).toBeNull();
  });

  it('should reject expired tokens', async () => {
    const generator = new SimpleJWTGenerator('test_secret_key');

    const user = new UserImpl('user123', 'alice');
    const token = await generator.generate(user, -1); // Already expired

    const verified = await generator.verify(token.value);
    expect(verified).toBeNull();
  });
});

describe('OpaqueTokenGenerator', () => {
  it('should generate and verify opaque tokens', async () => {
    const generator = new OpaqueTokenGenerator();

    const user = new UserImpl('user123', 'alice');
    const token = await generator.generate(user, 3600);

    expect(token.type).toBe(TokenType.OPAQUE);
    expect(token.userId).toBe('user123');

    // Verify token
    const verified = await generator.verify(token.value);
    expect(verified).not.toBeNull();
    expect(verified!.userId).toBe('user123');
  });

  it('should revoke tokens', async () => {
    const generator = new OpaqueTokenGenerator();

    const user = new UserImpl('user123', 'alice');
    const token = await generator.generate(user, 3600);

    // Token should be valid
    expect(await generator.verify(token.value)).not.toBeNull();

    // Revoke token
    generator.revoke(token.value);

    // Token should now be invalid
    expect(await generator.verify(token.value)).toBeNull();
  });
});

// ============================================================================
// Local Auth Provider Tests
// ============================================================================

describe('LocalAuthProvider', () => {
  it('should register and authenticate users', async () => {
    const provider = new LocalAuthProvider();

    await provider.registerUser(
      'alice',
      'secure_password',
      'alice@example.com',
      new Set(['admin']),
      new Set(['read:all'])
    );

    // Valid credentials
    const user = await provider.authenticate({
      username: 'alice',
      password: 'secure_password',
    });
    expect(user).not.toBeNull();
    expect(user!.username).toBe('alice');

    // Invalid password
    const invalidUser = await provider.authenticate({
      username: 'alice',
      password: 'wrong_password',
    });
    expect(invalidUser).toBeNull();

    // Non-existent user
    const nonExistent = await provider.authenticate({
      username: 'bob',
      password: 'password',
    });
    expect(nonExistent).toBeNull();
  });
});

// ============================================================================
// API Key Auth Provider Tests
// ============================================================================

describe('APIKeyAuthProvider', () => {
  it('should create and authenticate with API keys', async () => {
    const provider = new APIKeyAuthProvider();

    const user = new UserImpl('user123', 'alice');
    const apiKey = provider.createApiKey(user);

    expect(apiKey).toContain('ak_');

    // Authenticate with API key
    const authenticatedUser = await provider.authenticate({ apiKey });
    expect(authenticatedUser).not.toBeNull();
    expect(authenticatedUser!.id).toBe('user123');
  });

  it('should revoke API keys', async () => {
    const provider = new APIKeyAuthProvider();

    const user = new UserImpl('user123', 'alice');
    const apiKey = provider.createApiKey(user);

    // Key should work
    expect(await provider.authenticate({ apiKey })).not.toBeNull();

    // Revoke key
    provider.revokeApiKey(apiKey);

    // Key should no longer work
    expect(await provider.authenticate({ apiKey })).toBeNull();
  });
});

// ============================================================================
// Policy Engine Tests
// ============================================================================

describe('PolicyEngine', () => {
  it('should check direct permissions', () => {
    const engine = new PolicyEngine();

    const user = new UserImpl(
      'user123',
      'alice',
      undefined,
      new Set(),
      new Set(['read:document:123'])
    );

    expect(engine.check(user, 'read', 'document:123')).toBe(true);
    expect(engine.check(user, 'write', 'document:123')).toBe(false);
  });

  it('should check role-based permissions', () => {
    const engine = new PolicyEngine();

    engine.addRolePermission('admin', 'read:*');
    engine.addRolePermission('admin', 'write:*');

    const user = new UserImpl(
      'user123',
      'alice',
      undefined,
      new Set(['admin'])
    );

    expect(engine.check(user, 'read', 'document:123')).toBe(true);
    expect(engine.check(user, 'write', 'document:123')).toBe(true);
  });

  it('should check custom policy rules', () => {
    const engine = new PolicyEngine();

    engine.addRule(new PolicyRuleImpl('user:alice', 'read', 'document:*', 'allow'));

    const user = new UserImpl('user123', 'alice');

    expect(engine.check(user, 'read', 'document:123')).toBe(true);
    expect(engine.check(user, 'write', 'document:123')).toBe(false);
  });

  it('should handle deny rules', () => {
    const engine = new PolicyEngine();

    engine.addRule(new PolicyRuleImpl('user:alice', 'delete', 'document:*', 'deny'));

    const user = new UserImpl('user123', 'alice');

    expect(engine.check(user, 'delete', 'document:123')).toBe(false);
  });
});

// ============================================================================
// Session Manager Tests
// ============================================================================

describe('SessionManager', () => {
  it('should create and retrieve sessions', () => {
    const manager = new SessionManager();

    const session = manager.createSession(
      'user123',
      'device1',
      '192.168.1.1'
    );

    expect(session.userId).toBe('user123');
    expect(session.deviceId).toBe('device1');

    const retrieved = manager.getSession(session.id);
    expect(retrieved).not.toBeNull();
    expect(retrieved!.id).toBe(session.id);
  });

  it('should revoke sessions', () => {
    const manager = new SessionManager();

    const session = manager.createSession('user123');

    // Session should exist
    expect(manager.getSession(session.id)).not.toBeNull();

    // Revoke session
    manager.revokeSession(session.id);

    // Session should no longer exist
    expect(manager.getSession(session.id)).toBeNull();
  });

  it('should revoke all user sessions', () => {
    const manager = new SessionManager();

    const session1 = manager.createSession('user123');
    const session2 = manager.createSession('user123');
    const session3 = manager.createSession('user456');

    // Revoke all sessions for user123
    manager.revokeUserSessions('user123');

    // user123 sessions should be gone
    expect(manager.getSession(session1.id)).toBeNull();
    expect(manager.getSession(session2.id)).toBeNull();

    // user456 session should still exist
    expect(manager.getSession(session3.id)).not.toBeNull();
  });

  it('should cleanup expired sessions', () => {
    const manager = new SessionManager();

    // Create expired session
    const session1 = manager.createSession('user123', undefined, undefined, undefined, -1);

    // Create valid session
    const session2 = manager.createSession('user456', undefined, undefined, undefined, 3600);

    // Cleanup expired
    manager.cleanupExpired();

    // Expired session should be gone
    expect(manager.getSession(session1.id)).toBeNull();

    // Valid session should still exist
    expect(manager.getSession(session2.id)).not.toBeNull();
  });
});

// ============================================================================
// Auth Integration Tests
// ============================================================================

describe('Auth', () => {
  it('should initialize correctly', () => {
    const auth = new Auth();

    expect(auth).toBeDefined();
    expect(auth.policyEngine).toBeDefined();
    expect(auth.sessionManager).toBeDefined();
  });

  it('should add providers', () => {
    const auth = new Auth();
    const provider = new LocalAuthProvider();

    auth.addProvider('local', provider);

    // Should not throw
    expect(() => auth.addProvider('local', provider)).not.toThrow();
  });

  it('should complete login flow', async () => {
    const auth = new Auth();
    const provider = new LocalAuthProvider();
    auth.addProvider('local', provider);

    // Register user
    await provider.registerUser('alice', 'secure_password');

    // Login
    const result = await auth.login('local', {
      username: 'alice',
      password: 'secure_password',
    });

    expect(result).not.toBeNull();
    expect(result!.accessToken).toBeDefined();
    expect(result!.refreshToken).toBeDefined();
    expect(result!.sessionId).toBeDefined();
    expect(result!.user.username).toBe('alice');
  });

  it('should reject invalid credentials', async () => {
    const auth = new Auth();
    const provider = new LocalAuthProvider();
    auth.addProvider('local', provider);

    await provider.registerUser('alice', 'secure_password');

    // Invalid password
    const result = await auth.login('local', {
      username: 'alice',
      password: 'wrong_password',
    });
    expect(result).toBeNull();
  });

  it('should verify tokens', async () => {
    const auth = new Auth();
    const provider = new LocalAuthProvider();
    auth.addProvider('local', provider);

    await provider.registerUser('alice', 'secure_password');
    const result = await auth.login('local', {
      username: 'alice',
      password: 'secure_password',
    });

    // Verify access token
    const token = await auth.verifyToken(result!.accessToken);
    expect(token).not.toBeNull();
    expect(token!.userId).toBe(result!.user.id);
  });

  it('should revoke tokens', async () => {
    const auth = new Auth();
    const provider = new LocalAuthProvider();
    auth.addProvider('local', provider);

    await provider.registerUser('alice', 'secure_password');
    const result = await auth.login('local', {
      username: 'alice',
      password: 'secure_password',
    });

    const accessToken = result!.accessToken;

    // Token should be valid
    expect(await auth.verifyToken(accessToken)).not.toBeNull();

    // Revoke token
    auth.revokeToken(accessToken);

    // Token should now be invalid
    expect(await auth.verifyToken(accessToken)).toBeNull();
  });

  it('should refresh tokens', async () => {
    const auth = new Auth();
    const provider = new LocalAuthProvider();
    auth.addProvider('local', provider);

    await provider.registerUser('alice', 'secure_password');
    const result = await auth.login('local', {
      username: 'alice',
      password: 'secure_password',
    });

    const refreshToken = result!.refreshToken;

    // Small delay to ensure different timestamp
    await new Promise(resolve => setTimeout(resolve, 1000));

    // Refresh token
    const newTokens = await auth.refreshToken(refreshToken);

    expect(newTokens).not.toBeNull();
    expect(newTokens!.accessToken).toBeDefined();
    expect(newTokens!.accessToken).not.toBe(result!.accessToken);
  });

  it('should check permissions', () => {
    const auth = new Auth();

    // Add role permission
    auth.policyEngine.addRolePermission('admin', 'read:*');

    const user = new UserImpl(
      'user123',
      'alice',
      undefined,
      new Set(['admin'])
    );

    expect(auth.checkPermission(user, 'read', 'document:123')).toBe(true);
    expect(auth.checkPermission(user, 'write', 'document:123')).toBe(false);
  });

  it('should work with opaque tokens', async () => {
    const auth = new Auth(undefined, TokenType.OPAQUE);
    const provider = new LocalAuthProvider();
    auth.addProvider('local', provider);

    await provider.registerUser('alice', 'secure_password');
    const result = await auth.login('local', {
      username: 'alice',
      password: 'secure_password',
    });

    expect(result).not.toBeNull();
    expect(result!.accessToken).toBeDefined();

    // Verify token
    const token = await auth.verifyToken(result!.accessToken);
    expect(token).not.toBeNull();
    expect(token!.type).toBe(TokenType.OPAQUE);
  });
});
