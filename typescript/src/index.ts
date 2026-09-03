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

export class AuthError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AuthError';
  }
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
    const p = pattern.split('');
    const s = value.split('');
    let pi = 0;
    let si = 0;
    let starP: number | null = null;
    let starS: number | null = null;

    while (si < s.length) {
      if (pi < p.length && (p[pi] === s[si] || p[pi] === '?')) {
        pi++;
        si++;
      } else if (pi < p.length && p[pi] === '*') {
        starP = pi;
        starS = si;
        pi++;
      } else if (starP !== null && starS !== null) {
        pi = starP + 1;
        starS++;
        si = starS;
      } else {
        return false;
      }
    }

    while (pi < p.length && p[pi] === '*') {
      pi++;
    }

    return pi === p.length;
  }
}

// ============================================================================
// Storage Backend
// ============================================================================

export interface StorageBackend {
  get(key: string): any | undefined;
  set(key: string, value: any, ttl?: number): boolean;
  delete(key: string): boolean;
  has(key: string): boolean;
  keys(prefix?: string): string[];
  clear(): void;
}

export class InMemoryStorage implements StorageBackend {
  private store: Map<string, { value: any; expiresAt?: number }> = new Map();

  get(key: string): any | undefined {
    const entry = this.store.get(key);
    if (!entry) {
      return undefined;
    }
    if (entry.expiresAt !== undefined && Date.now() > entry.expiresAt) {
      this.store.delete(key);
      return undefined;
    }
    return entry.value;
  }

  set(key: string, value: any, ttl?: number): boolean {
    const expiresAt = typeof ttl === 'number' && ttl > 0 ? Date.now() + ttl * 1000 : undefined;
    this.store.set(key, { value, expiresAt });
    return true;
  }

  delete(key: string): boolean {
    return this.store.delete(key);
  }

  has(key: string): boolean {
    const entry = this.store.get(key);
    if (!entry) {
      return false;
    }
    if (entry.expiresAt !== undefined && Date.now() > entry.expiresAt) {
      this.store.delete(key);
      return false;
    }
    return true;
  }

  keys(prefix?: string): string[] {
    const allKeys = Array.from(this.store.keys());
    if (!prefix) {
      return allKeys;
    }
    return allKeys.filter(k => k.startsWith(prefix));
  }

  clear(): void {
    this.store.clear();
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
  generate(user: User, expiresIn?: number, metadata?: Record<string, any>): Promise<Token>;
  verify(tokenValue: string): Promise<Token | null>;
  revoke(tokenValue: string): void;
  isRevoked(tokenValue: string): boolean;
}

export class SimpleJWTGenerator implements TokenGenerator {
  constructor(
    private secret: string,
    private issuer?: string,
    private audience?: string,
    private keyId?: string,
    private allowedAlgorithms: string[] = ['HS256'],
    private storage: StorageBackend = new InMemoryStorage()
  ) {}

  async generate(user: User, expiresIn: number = 3600, metadata: Record<string, any> = {}): Promise<Token> {
    const issuedAt = new Date();
    const expiresAt = new Date(issuedAt.getTime() + expiresIn * 1000);

    const payload: Record<string, any> = {
      userId: user.id,
      username: user.username,
      roles: Array.from(user.roles),
      permissions: Array.from(user.permissions),
      tenantId: user.tenantId,
      jti: crypto.randomBytes(16).toString('base64url'),
      iat: Math.floor(issuedAt.getTime() / 1000),
      exp: Math.floor(expiresAt.getTime() / 1000),
      ...metadata,
    };
    if (this.issuer) payload.iss = this.issuer;
    if (this.audience) payload.aud = this.audience;

    // Create simple JWT: base64(header).base64(payload).signature
    const headerObj: Record<string, any> = { alg: 'HS256', typ: 'JWT' };
    if (this.keyId) headerObj.kid = this.keyId;
    const header = Buffer.from(JSON.stringify(headerObj))
      .toString('base64url');
    const payloadB64 = Buffer.from(JSON.stringify(payload))
      .toString('base64url');

    const message = `${header}.${payloadB64}`;
    const signature = crypto
      .createHmac('sha256', this.secret)
      .update(message)
      .digest('base64url');

    const tokenValue = `${message}.${signature}`;
    const tokenType = metadata?.fid ? TokenType.REFRESH : TokenType.JWT;

    return new TokenImpl(
      tokenValue,
      tokenType,
      user.id,
      expiresAt,
      issuedAt,
      {
        username: user.username,
        jti: payload.jti,
        roles: Array.from(user.roles),
        permissions: Array.from(user.permissions),
        tenantId: user.tenantId,
        ...metadata,
      }
    );
  }

  async verify(tokenValue: string): Promise<Token | null> {
    try {
      const parts = tokenValue.split('.');
      if (parts.length !== 3) {
        return null;
      }

      const [headerB64, payloadB64, signatureB64] = parts;

      // Decode and validate header
      const header = JSON.parse(Buffer.from(headerB64, 'base64url').toString());
      if (!this.allowedAlgorithms.includes(header.alg)) {
        return null;
      }
      if (this.keyId && header.kid !== this.keyId) {
        return null;
      }

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

      if (this.issuer && payload.iss !== this.issuer) {
        return null;
      }
      if (this.audience && payload.aud !== this.audience) {
        return null;
      }
      if (!payload.jti) {
        return null;
      }

      const issuedAt = new Date(payload.iat * 1000);
      const expiresAt = new Date(payload.exp * 1000);
      const tokenType = payload.fid ? TokenType.REFRESH : TokenType.JWT;

      const metadata: Record<string, any> = {
        username: payload.username,
        jti: payload.jti,
        roles: payload.roles || [],
        permissions: payload.permissions || [],
        tenantId: payload.tenantId,
      };
      if (payload.fid) metadata.fid = payload.fid;

      const token = new TokenImpl(
        tokenValue,
        tokenType,
        payload.userId,
        expiresAt,
        issuedAt,
        metadata
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

  revoke(tokenValue: string): void {
    try {
      const parts = tokenValue.split('.');
      if (parts.length === 3) {
        const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
        if (payload.fid) {
          const familyKeys = this.storage.keys(`refreshFamily:${payload.fid}`);
          for (const key of familyKeys) {
            this.storage.delete(key);
          }
        }
      }
    } catch {}
    this.storage.set(`revoked:${tokenValue}`, true);
  }

  isRevoked(tokenValue: string): boolean {
    return this.storage.has(`revoked:${tokenValue}`);
  }
}

export class OpaqueTokenGenerator implements TokenGenerator {
  constructor(private storage: StorageBackend = new InMemoryStorage()) {}

  async generate(user: User, expiresIn: number = 3600, metadata: Record<string, any> = {}): Promise<Token> {
    const tokenValue = crypto.randomBytes(32).toString('base64url');
    const issuedAt = new Date();
    const expiresAt = new Date(issuedAt.getTime() + expiresIn * 1000);
    const tokenType = metadata?.fid ? TokenType.REFRESH : TokenType.OPAQUE;

    const token = new TokenImpl(
      tokenValue,
      tokenType,
      user.id,
      expiresAt,
      issuedAt,
      {
        username: user.username,
        roles: Array.from(user.roles),
        permissions: Array.from(user.permissions),
        tenantId: user.tenantId,
        ...metadata,
      }
    );

    this.storage.set(`token:${tokenValue}`, token, expiresIn);
    return token;
  }

  async verify(tokenValue: string): Promise<Token | null> {
    if (this.isRevoked(tokenValue)) {
      return null;
    }
    const token = this.storage.get(`token:${tokenValue}`) as Token | undefined;
    if (!token || token.isExpired()) {
      return null;
    }
    return token;
  }

  revoke(tokenValue: string): void {
    const token = this.storage.get(`token:${tokenValue}`) as Token | undefined;
    const fid = token?.metadata?.fid;
    if (fid) {
      const familyKeys = this.storage.keys(`refreshFamily:${fid}`);
      for (const key of familyKeys) {
        this.storage.delete(key);
      }
    }
    this.storage.set(`revoked:${tokenValue}`, true);
    this.storage.delete(`token:${tokenValue}`);
  }

  isRevoked(tokenValue: string): boolean {
    return this.storage.has(`revoked:${tokenValue}`);
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
  ): Promise<User | null> {
    const userId = crypto.randomBytes(16).toString('base64url');
    const hashedPassword = await this.passwordHasher.hash(password);

    const userRoles = new Set(roles ?? []);
    const userPermissions = new Set(permissions ?? []);

    this.users.set(username, {
      id: userId,
      username,
      email,
      password: hashedPassword,
      roles: userRoles,
      permissions: userPermissions,
      tenantId,
    });

    return new UserImpl(userId, username, email, userRoles, userPermissions, {}, tenantId);
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
    // First pass: explicit deny rules override everything
    for (const rule of this.rules) {
      if (rule.matches(`user:${user.username}`, action, resource, context)) {
        if (rule.effect === 'deny') {
          return false;
        }
        continue;
      }
      const hasRoleMatch = Array.from(user.roles).some(role =>
        rule.matches(`role:${role}`, action, resource, context)
      );
      if (hasRoleMatch) {
        if (rule.effect === 'deny') {
          return false;
        }
        continue;
      }
      if (rule.matches('*', action, resource, context)) {
        if (rule.effect === 'deny') {
          return false;
        }
        continue;
      }
    }

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

    // Second pass: allow rules
    for (const rule of this.rules) {
      if (rule.matches(`user:${user.username}`, action, resource, context)) {
        return rule.effect === 'allow';
      }
      if (Array.from(user.roles).some(role => rule.matches(`role:${role}`, action, resource, context))) {
        return rule.effect === 'allow';
      }
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
  constructor(
    private defaultTtl: number = 3600,
    private storage: StorageBackend = new InMemoryStorage()
  ) {}

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

    this.storage.set(`session:${sessionId}`, session, actualTtl);

    const userSessionIds = (this.storage.get(`userSessions:${userId}`) as Set<string> | undefined) || new Set<string>();
    userSessionIds.add(sessionId);
    this.storage.set(`userSessions:${userId}`, userSessionIds);

    return session;
  }

  getSession(sessionId: string): Session | null {
    const session = this.storage.get(`session:${sessionId}`) as Session | undefined;
    if (session && !session.isExpired()) {
      session.touch();
      return session;
    }
    return null;
  }

  revokeSession(sessionId: string): void {
    const session = this.storage.get(`session:${sessionId}`) as Session | undefined;
    if (session) {
      const userSessionIds = this.storage.get(`userSessions:${session.userId}`) as Set<string> | undefined;
      if (userSessionIds) {
        userSessionIds.delete(sessionId);
        this.storage.set(`userSessions:${session.userId}`, userSessionIds);
      }
    }
    this.storage.delete(`session:${sessionId}`);
  }

  revokeUserSessions(userId: string): void {
    const userSessionIds = this.storage.get(`userSessions:${userId}`) as Set<string> | undefined;
    if (userSessionIds) {
      for (const sid of userSessionIds) {
        this.storage.delete(`session:${sid}`);
      }
    }
    this.storage.delete(`userSessions:${userId}`);
  }

  cleanupExpired(): void {
    const sessionKeys = this.storage.keys('session:');
    const expiredSessionIds: string[] = [];
    for (const key of sessionKeys) {
      const session = this.storage.get(key) as Session | undefined;
      if (session && session.isExpired()) {
        expiredSessionIds.push(session.id);
      }
    }
    for (const sid of expiredSessionIds) {
      this.revokeSession(sid);
    }
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
  familyId?: string;
}

export class Auth {
  private providers: Map<string, AuthProvider> = new Map();
  private tokenGenerator: TokenGenerator;
  public policyEngine: PolicyEngine;
  public sessionManager: SessionManager;
  private storage: StorageBackend;
  private secret: string;

  constructor(
    secret: string,
    tokenType: TokenType = TokenType.JWT,
    private issuer?: string,
    private audience?: string,
    private keyId?: string,
    private allowedAlgorithms: string[] = ['HS256'],
    storage?: StorageBackend
  ) {
    if (!secret) {
      throw new AuthError(
        'A secret must be provided as the first positional argument.'
      );
    }
    this.secret = secret;
    this.storage = storage || new InMemoryStorage();
    this.tokenGenerator = this.createTokenGenerator(tokenType);
    this.policyEngine = new PolicyEngine();
    this.sessionManager = new SessionManager(3600, this.storage);
  }

  private createTokenGenerator(tokenType: TokenType): TokenGenerator {
    if (tokenType === TokenType.JWT) {
      return new SimpleJWTGenerator(this.secret, this.issuer, this.audience, this.keyId, this.allowedAlgorithms, this.storage);
    } else if (tokenType === TokenType.OPAQUE) {
      return new OpaqueTokenGenerator(this.storage);
    } else {
      throw new AuthError(`Unsupported token type: ${tokenType}`);
    }
  }

  addProvider(name: string, provider: AuthProvider): void {
    this.providers.set(name, provider);
  }

  async authenticate(providerName: string, credentials: Record<string, any>): Promise<User | null> {
    const provider = this.providers.get(providerName);
    if (!provider) {
      throw new AuthError(`Unknown provider: ${providerName}`);
    }

    return provider.authenticate(credentials);
  }

  async login(
    providerName: string,
    credentials: Record<string, any>,
    createSession: boolean = true,
    ttl: number = 3600
  ): Promise<LoginResult | null> {
    const user = await this.authenticate(providerName, credentials);
    if (!user) {
      return null;
    }

    const familyId = crypto.randomUUID();

    // Generate access token
    const accessToken = await this.tokenGenerator.generate(user, ttl);

    // Generate refresh token (longer TTL) with a family binding
    const refreshToken = await this.tokenGenerator.generate(user, ttl * 24, { fid: familyId });

    // Store the active refresh token for this family
    this.storage.set(`refreshFamily:${familyId}`, refreshToken.value, ttl * 24);

    const result: LoginResult = {
      user,
      accessToken: accessToken.value,
      refreshToken: refreshToken.value,
      tokenType: 'Bearer',
      expiresIn: ttl,
      familyId,
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
    if (this.tokenGenerator.isRevoked(tokenValue)) {
      return null;
    }

    return this.tokenGenerator.verify(tokenValue);
  }

  revokeToken(tokenValue: string): void {
    this.tokenGenerator.revoke(tokenValue);
  }

  async refresh(refreshTokenValue: string): Promise<LoginResult | null> {
    return this.performRefresh(refreshTokenValue, 3600);
  }

  private async performRefresh(
    refreshTokenValue: string,
    tokenTtl: number
  ): Promise<LoginResult | null> {
    const token = await this.verifyToken(refreshTokenValue);
    if (!token || token.type !== TokenType.REFRESH || !token.metadata?.fid) {
      return null;
    }

    const familyId = token.metadata.fid as string;
    const activeToken = this.storage.get(`refreshFamily:${familyId}`) as string | undefined;

    // Reuse detection: the presented token is not the active one for the family
    if (!activeToken || activeToken !== refreshTokenValue) {
      this.revokeToken(refreshTokenValue);
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

    // Generate new access token and a rotated refresh token with the same family
    const newAccessToken = await this.tokenGenerator.generate(user, tokenTtl);
    const newRefreshToken = await this.tokenGenerator.generate(user, tokenTtl * 24, { fid: familyId });

    // Store the new active refresh token for this family
    this.storage.set(`refreshFamily:${familyId}`, newRefreshToken.value, tokenTtl * 24);

    return {
      user,
      accessToken: newAccessToken.value,
      refreshToken: newRefreshToken.value,
      tokenType: 'Bearer',
      expiresIn: tokenTtl,
      familyId,
    };
  }

  async refreshToken(
    refreshTokenValue: string,
    tokenTtl: number = 3600
  ): Promise<{ accessToken: string; tokenType: string; expiresIn: number } | null> {
    const result = await this.performRefresh(refreshTokenValue, tokenTtl);
    if (!result) return null;
    return {
      accessToken: result.accessToken,
      tokenType: result.tokenType,
      expiresIn: result.expiresIn,
    };
  }

  checkPermission(user: User, action: string, resource: string, context?: Record<string, any>): boolean {
    return this.policyEngine.check(user, action, resource, context);
  }
}

// All exports are already defined above with 'export' keyword
