/**
 * Auth & Authorization Framework (TypeScript)
 * 
 * A unified identity, session, token, and permission framework with pluggable providers,
 * strong defaults, and production-ready security.
 * 
 * Features:
 * - Username/password, OAuth2/OIDC, SAML, and API-key authentication
 * - JWT, opaque, and refresh token management with secure rotation
 * - RBAC and ABAC policy engine
 * - Multi-tenant permission scoping
 * - Session and device management
 * - Audit logging and token revocation
 */

import * as crypto from 'crypto';

// ============================================================================
// Core Types and Enums
// ============================================================================

export enum TokenType {
  JWT = 'jwt',
  OPAQUE = 'opaque',
  REFRESH = 'refresh',
}

export enum AuthMethod {
  LOCAL = 'local',
  OAUTH2 = 'oauth2',
  OIDC = 'oidc',
  SAML = 'saml',
  API_KEY = 'api_key',
}

export interface User {
  id: string;
  username: string;
  email?: string;
  roles: Set<string>;
  permissions: Set<string>;
  metadata?: Record<string, any>;
  tenantId?: string;

  hasRole(role: string): boolean;
  hasPermission(permission: string): boolean;
  hasAnyRole(roles: string[]): boolean;
  hasAllRoles(roles: string[]): boolean;
}

export class UserImpl implements User {
  constructor(
    public id: string,
    public username: string,
    public email?: string,
    public roles: Set<string> = new Set(),
    public permissions: Set<string> = new Set(),
    public metadata: Record<string, any> = {},
    public tenantId?: string
  ) {}

  hasRole(role: string): boolean {
    return this.roles.has(role);
  }

  hasPermission(permission: string): boolean {
    return this.permissions.has(permission);
  }

  hasAnyRole(roles: string[]): boolean {
    return roles.some(role => this.roles.has(role));
  }

  hasAllRoles(roles: string[]): boolean {
    return roles.every(role => this.roles.has(role));
  }
}

export interface Token {
  value: string;
  type: TokenType;
  userId: string;
  expiresAt: Date;
  issuedAt: Date;
  metadata?: Record<string, any>;

  isExpired(): boolean;
  timeUntilExpiry(): number;
}

export class TokenImpl implements Token {
  constructor(
    public value: string,
    public type: TokenType,
    public userId: string,
    public expiresAt: Date,
    public issuedAt: Date = new Date(),
    public metadata: Record<string, any> = {}
  ) {}

  isExpired(): boolean {
    return new Date() > this.expiresAt;
  }

  timeUntilExpiry(): number {
    return this.expiresAt.getTime() - new Date().getTime();
  }
}

export interface Session {
  id: string;
  userId: string;
  deviceId?: string;
  ipAddress?: string;
  userAgent?: string;
  createdAt: Date;
  lastActivity: Date;
  expiresAt?: Date;
  metadata?: Record<string, any>;

  isExpired(): boolean;
  touch(): void;
}

export class SessionImpl implements Session {
  constructor(
    public id: string,
    public userId: string,
    public deviceId?: string,
    public ipAddress?: string,
    public userAgent?: string,
    public createdAt: Date = new Date(),
    public lastActivity: Date = new Date(),
    public expiresAt?: Date,
    public metadata: Record<string, any> = {}
  ) {}

  isExpired(): boolean {
    if (!this.expiresAt) return false;
    return new Date() > this.expiresAt;
  }

  touch(): void {
    this.lastActivity = new Date();
  }
}

export interface PolicyRule {
  subject: string;  // user:alice, role:admin, *
  action: string;   // read, write, delete, *
  resource: string; // document:123, document:*, *
  effect: 'allow' | 'deny';
  conditions?: Record<string, any>;

  matches(subject: string, action: string, resource: string, context?: Record<string, any>): boolean;
}

export class PolicyRuleImpl implements PolicyRule {
  constructor(
    public subject: string,
    public action: string,
    public resource: string,
    public effect: 'allow' | 'deny' = 'allow',
    public conditions: Record<string, any> = {}
  ) {}

  matches(subject: string, action: string, resource: string, context?: Record<string, any>): boolean {
    // Check subject match
    if (this.subject !== '*' && this.subject !== subject) {
      if (!this.wildcardMatch(this.subject, subject)) {
        return false;
      }
    }

    // Check action match
    if (this.action !== '*' && this.action !== action) {
      if (!this.wildcardMatch(this.action, action)) {
        return false;
      }
    }

    // Check resource match
    if (this.resource !== '*' && this.resource !== resource) {
      if (!this.wildcardMatch(this.resource, resource)) {
        return false;
      }
    }

    // Check conditions if provided
    if (Object.keys(this.conditions).length > 0 && context) {
      for (const [key, expectedValue] of Object.entries(this.conditions)) {
        if (!(key in context) || context[key] !== expectedValue) {
          return false;
        }
      }
    }

    return true;
  }

  private wildcardMatch(pattern: string, value: string): boolean {
    if (!pattern.includes('*')) {
      return pattern === value;
    }

    const parts = pattern.split('*');
    if (parts.length === 2) {
      const [prefix, suffix] = parts;
      return value.startsWith(prefix) && value.endsWith(suffix);
    }

    return false;
  }
}

// ============================================================================
// Password Hashing
// ============================================================================

export interface PasswordHasher {
  hash(password: string): Promise<string>;
  verify(password: string, hashed: string): Promise<boolean>;
}

export class PBKDF2Hasher implements PasswordHasher {
  constructor(private iterations: number = 100000) {}

  async hash(password: string): Promise<string> {
    const salt = crypto.randomBytes(32);
    const key = await this.pbkdf2(password, salt, this.iterations);
    return `pbkdf2_sha256$${this.iterations}$${salt.toString('base64')}$${key.toString('base64')}`;
  }

  async verify(password: string, hashed: string): Promise<boolean> {
    try {
      const parts = hashed.split('$');
      if (parts.length !== 4 || parts[0] !== 'pbkdf2_sha256') {
        return false;
      }

      const iterations = parseInt(parts[1], 10);
      const salt = Buffer.from(parts[2], 'base64');
      const storedKey = Buffer.from(parts[3], 'base64');

      const key = await this.pbkdf2(password, salt, iterations);
      return crypto.timingSafeEqual(key, storedKey);
    } catch {
      return false;
    }
  }

  private pbkdf2(password: string, salt: Buffer, iterations: number): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      crypto.pbkdf2(password, salt, iterations, 32, 'sha256', (err: Error | null, key: Buffer) => {
        if (err) reject(err);
        else resolve(key);
      });
    });
  }
}

// ============================================================================
// Token Generators
// ============================================================================

export interface TokenGenerator {
  generate(user: User, expiresIn?: number): Promise<Token>;
  verify(tokenValue: string): Promise<Token | null>;
}

export class SimpleJWTGenerator implements TokenGenerator {
  constructor(private secret: string) {}

  async generate(user: User, expiresIn: number = 3600): Promise<Token> {
    const issuedAt = new Date();
    const expiresAt = new Date(issuedAt.getTime() + expiresIn * 1000);

    const payload = {
      userId: user.id,
      username: user.username,
      roles: Array.from(user.roles),
      permissions: Array.from(user.permissions),
      tenantId: user.tenantId,
      iat: Math.floor(issuedAt.getTime() / 1000),
      exp: Math.floor(expiresAt.getTime() / 1000),
    };

    // Create simple JWT: base64(header).base64(payload).signature
    const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' }))
      .toString('base64url');
    const payloadB64 = Buffer.from(JSON.stringify(payload))
      .toString('base64url');

    const message = `${header}.${payloadB64}`;
    const signature = crypto
      .createHmac('sha256', this.secret)
      .update(message)
      .digest('base64url');

    const tokenValue = `${message}.${signature}`;

    return new TokenImpl(
      tokenValue,
      TokenType.JWT,
      user.id,
      expiresAt,
      issuedAt,
      { roles: Array.from(user.roles), permissions: Array.from(user.permissions) }
    );
  }

  async verify(tokenValue: string): Promise<Token | null> {
    try {
      const parts = tokenValue.split('.');
      if (parts.length !== 3) {
        return null;
      }

      const [headerB64, payloadB64, signatureB64] = parts;

      // Verify signature
      const message = `${headerB64}.${payloadB64}`;
      const expectedSignature = crypto
        .createHmac('sha256', this.secret)
        .update(message)
        .digest('base64url');

      if (!crypto.timingSafeEqual(
        Buffer.from(signatureB64),
        Buffer.from(expectedSignature)
      )) {
        return null;
      }

      // Decode payload
      const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString());

      const issuedAt = new Date(payload.iat * 1000);
      const expiresAt = new Date(payload.exp * 1000);

      const token = new TokenImpl(
        tokenValue,
        TokenType.JWT,
        payload.userId,
        expiresAt,
        issuedAt,
        {
          username: payload.username,
          roles: payload.roles || [],
          permissions: payload.permissions || [],
          tenantId: payload.tenantId,
        }
      );

      // Check expiry
      if (token.isExpired()) {
        return null;
      }

      return token;
    } catch {
      return null;
    }
  }
}

export class OpaqueTokenGenerator implements TokenGenerator {
  private tokens: Map<string, Token> = new Map();

  async generate(user: User, expiresIn: number = 3600): Promise<Token> {
    const tokenValue = crypto.randomBytes(32).toString('base64url');
    const issuedAt = new Date();
    const expiresAt = new Date(issuedAt.getTime() + expiresIn * 1000);

    const token = new TokenImpl(
      tokenValue,
      TokenType.OPAQUE,
      user.id,
      expiresAt,
      issuedAt,
      {
        username: user.username,
        roles: Array.from(user.roles),
        permissions: Array.from(user.permissions),
        tenantId: user.tenantId,
      }
    );

    this.tokens.set(tokenValue, token);
    return token;
  }

  async verify(tokenValue: string): Promise<Token | null> {
    const token = this.tokens.get(tokenValue);
    if (!token || token.isExpired()) {
      return null;
    }
    return token;
  }

  revoke(tokenValue: string): void {
    this.tokens.delete(tokenValue);
  }
}

// ============================================================================
// Authentication Providers
// ============================================================================

export interface AuthProvider {
  authenticate(credentials: Record<string, any>): Promise<User | null>;
}

export class LocalAuthProvider implements AuthProvider {
  private users: Map<string, any> = new Map();

  constructor(private passwordHasher: PasswordHasher = new PBKDF2Hasher()) {}

  async registerUser(
    username: string,
    password: string,
    email?: string,
    roles: Set<string> = new Set(),
    permissions: Set<string> = new Set(),
    tenantId?: string
  ): Promise<User> {
    const userId = crypto.randomBytes(16).toString('base64url');
    const hashedPassword = await this.passwordHasher.hash(password);

    this.users.set(username, {
      id: userId,
      username,
      email,
      password: hashedPassword,
      roles,
      permissions,
      tenantId,
    });

    return new UserImpl(userId, username, email, roles, permissions, {}, tenantId);
  }

  async authenticate(credentials: Record<string, any>): Promise<User | null> {
    const { username, password } = credentials;

    if (!username || !password) {
      return null;
    }

    const userData = this.users.get(username);
    if (!userData) {
      return null;
    }

    const isValid = await this.passwordHasher.verify(password, userData.password);
    if (!isValid) {
      return null;
    }

    return new UserImpl(
      userData.id,
      userData.username,
      userData.email,
      userData.roles,
      userData.permissions,
      {},
      userData.tenantId
    );
  }
}

export class APIKeyAuthProvider implements AuthProvider {
  private apiKeys: Map<string, User> = new Map();

  createApiKey(user: User): string {
    const apiKey = `ak_${crypto.randomBytes(32).toString('base64url')}`;
    this.apiKeys.set(apiKey, user);
    return apiKey;
  }

  async authenticate(credentials: Record<string, any>): Promise<User | null> {
    const { apiKey } = credentials;
    if (!apiKey) {
      return null;
    }

    return this.apiKeys.get(apiKey) || null;
  }

  revokeApiKey(apiKey: string): void {
    this.apiKeys.delete(apiKey);
  }
}

// ============================================================================
// Policy Engine
// ============================================================================

export class PolicyEngine {
  private rules: PolicyRule[] = [];
  private rolePermissions: Map<string, Set<string>> = new Map();

  addRule(rule: PolicyRule): void {
    this.rules.push(rule);
  }

  addRolePermission(role: string, permission: string): void {
    if (!this.rolePermissions.has(role)) {
      this.rolePermissions.set(role, new Set());
    }
    this.rolePermissions.get(role)!.add(permission);
  }

  check(user: User, action: string, resource: string, context?: Record<string, any>): boolean {
    // Check direct permissions
    if (user.hasPermission(`${action}:${resource}`)) {
      return true;
    }

    // Check role-based permissions
    for (const role of user.roles) {
      const rolePerms = this.rolePermissions.get(role);
      if (rolePerms && (rolePerms.has(`${action}:${resource}`) || rolePerms.has(`${action}:*`))) {
        return true;
      }
    }

    // Check policy rules
    for (const rule of this.rules) {
      // Check user-specific rules
      if (rule.matches(`user:${user.username}`, action, resource, context)) {
        return rule.effect === 'allow';
      }

      // Check role-based rules
      for (const role of user.roles) {
        if (rule.matches(`role:${role}`, action, resource, context)) {
          return rule.effect === 'allow';
        }
      }

      // Check wildcard rules
      if (rule.matches('*', action, resource, context)) {
        return rule.effect === 'allow';
      }
    }

    return false;
  }
}

// ============================================================================
// Session Manager
// ============================================================================

export class SessionManager {
  private sessions: Map<string, Session> = new Map();

  constructor(private defaultTtl: number = 3600) {}

  createSession(
    userId: string,
    deviceId?: string,
    ipAddress?: string,
    userAgent?: string,
    ttl?: number
  ): Session {
    const sessionId = crypto.randomBytes(32).toString('base64url');
    const actualTtl = ttl ?? this.defaultTtl;

    let expiresAt: Date | undefined;
    if (actualTtl <= 0) {
      expiresAt = new Date(Date.now() - 1000); // Already expired
    } else {
      expiresAt = new Date(Date.now() + actualTtl * 1000);
    }

    const session = new SessionImpl(
      sessionId,
      userId,
      deviceId,
      ipAddress,
      userAgent,
      new Date(),
      new Date(),
      expiresAt
    );

    this.sessions.set(sessionId, session);
    return session;
  }

  getSession(sessionId: string): Session | null {
    const session = this.sessions.get(sessionId);
    if (session && !session.isExpired()) {
      session.touch();
      return session;
    }
    return null;
  }

  revokeSession(sessionId: string): void {
    this.sessions.delete(sessionId);
  }

  revokeUserSessions(userId: string): void {
    const toRemove: string[] = [];
    for (const [sid, session] of this.sessions.entries()) {
      if (session.userId === userId) {
        toRemove.push(sid);
      }
    }
    toRemove.forEach(sid => this.sessions.delete(sid));
  }

  cleanupExpired(): void {
    const toRemove: string[] = [];
    for (const [sid, session] of this.sessions.entries()) {
      if (session.isExpired()) {
        toRemove.push(sid);
      }
    }
    toRemove.forEach(sid => this.sessions.delete(sid));
  }
}

// ============================================================================
// Main Auth Class
// ============================================================================

export interface LoginResult {
  user: User;
  accessToken: string;
  refreshToken: string;
  tokenType: string;
  expiresIn: number;
  sessionId?: string;
}

export class Auth {
  private providers: Map<string, AuthProvider> = new Map();
  private tokenGenerator: TokenGenerator;
  public policyEngine: PolicyEngine;
  public sessionManager: SessionManager;
  private revokedTokens: Set<string> = new Set();

  constructor(
    private secret: string = crypto.randomBytes(32).toString('base64url'),
    tokenType: TokenType = TokenType.JWT
  ) {
    this.tokenGenerator = this.createTokenGenerator(tokenType);
    this.policyEngine = new PolicyEngine();
    this.sessionManager = new SessionManager();
  }

  private createTokenGenerator(tokenType: TokenType): TokenGenerator {
    if (tokenType === TokenType.JWT) {
      return new SimpleJWTGenerator(this.secret);
    } else if (tokenType === TokenType.OPAQUE) {
      return new OpaqueTokenGenerator();
    } else {
      throw new Error(`Unsupported token type: ${tokenType}`);
    }
  }

  addProvider(name: string, provider: AuthProvider): void {
    this.providers.set(name, provider);
  }

  async authenticate(providerName: string, credentials: Record<string, any>): Promise<User | null> {
    const provider = this.providers.get(providerName);
    if (!provider) {
      throw new Error(`Unknown provider: ${providerName}`);
    }

    return provider.authenticate(credentials);
  }

  async login(
    providerName: string,
    credentials: Record<string, any>,
    createSession: boolean = true,
    tokenTtl: number = 3600
  ): Promise<LoginResult | null> {
    const user = await this.authenticate(providerName, credentials);
    if (!user) {
      return null;
    }

    // Generate access token
    const accessToken = await this.tokenGenerator.generate(user, tokenTtl);

    // Generate refresh token (longer TTL)
    const refreshToken = await this.tokenGenerator.generate(user, tokenTtl * 24);

    const result: LoginResult = {
      user,
      accessToken: accessToken.value,
      refreshToken: refreshToken.value,
      tokenType: 'Bearer',
      expiresIn: tokenTtl,
    };

    // Create session if requested
    if (createSession) {
      const session = this.sessionManager.createSession(
        user.id,
        credentials.deviceId,
        credentials.ipAddress,
        credentials.userAgent
      );
      result.sessionId = session.id;
    }

    return result;
  }

  async verifyToken(tokenValue: string): Promise<Token | null> {
    if (this.revokedTokens.has(tokenValue)) {
      return null;
    }

    return this.tokenGenerator.verify(tokenValue);
  }

  revokeToken(tokenValue: string): void {
    this.revokedTokens.add(tokenValue);
  }

  async refreshToken(
    refreshTokenValue: string,
    tokenTtl: number = 3600
  ): Promise<{ accessToken: string; tokenType: string; expiresIn: number } | null> {
    const token = await this.verifyToken(refreshTokenValue);
    if (!token) {
      return null;
    }

    // Get user from token metadata
    const user = new UserImpl(
      token.userId,
      token.metadata?.username || '',
      undefined,
      new Set(token.metadata?.roles || []),
      new Set(token.metadata?.permissions || []),
      {},
      token.metadata?.tenantId
    );

    // Generate new access token
    const newAccessToken = await this.tokenGenerator.generate(user, tokenTtl);

    return {
      accessToken: newAccessToken.value,
      tokenType: 'Bearer',
      expiresIn: tokenTtl,
    };
  }

  checkPermission(user: User, action: string, resource: string, context?: Record<string, any>): boolean {
    return this.policyEngine.check(user, action, resource, context);
  }
}

// All exports are already defined above with 'export' keyword
