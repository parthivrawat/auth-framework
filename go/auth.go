// Package authframework provides a unified identity, session, token, and permission framework
// with pluggable providers, strong defaults, and production-ready security.
package authframework

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

// ============================================================================
// Core Types and Enums
// ============================================================================

// TokenType represents the type of authentication token
type TokenType string

const (
	TokenTypeJWT     TokenType = "jwt"
	TokenTypeOpaque  TokenType = "opaque"
	TokenTypeRefresh TokenType = "refresh"
)

// AuthMethod represents the authentication method
type AuthMethod string

const (
	AuthMethodLocal  AuthMethod = "local"
	AuthMethodOAuth2 AuthMethod = "oauth2"
	AuthMethodOIDC   AuthMethod = "oidc"
	AuthMethodSAML   AuthMethod = "saml"
	AuthMethodAPIKey AuthMethod = "api_key"
)

// User represents an authenticated user
type User struct {
	ID          string
	Username    string
	Email       string
	Roles       map[string]bool
	Permissions map[string]bool
	Metadata    map[string]interface{}
	TenantID    string
}

// NewUser creates a new user
func NewUser(id, username string) *User {
	return &User{
		ID:          id,
		Username:    username,
		Roles:       make(map[string]bool),
		Permissions: make(map[string]bool),
		Metadata:    make(map[string]interface{}),
	}
}

// HasRole checks if user has a specific role
func (u *User) HasRole(role string) bool {
	return u.Roles[role]
}

// HasPermission checks if user has a specific permission
func (u *User) HasPermission(permission string) bool {
	return u.Permissions[permission]
}

// Token represents an authentication token
type Token struct {
	Value     string
	Type      TokenType
	UserID    string
	ExpiresAt time.Time
	IssuedAt  time.Time
	Metadata  map[string]interface{}
}

// IsExpired checks if the token is expired
func (t *Token) IsExpired() bool {
	return time.Now().After(t.ExpiresAt)
}

// Session represents a user session
type Session struct {
	ID           string
	UserID       string
	DeviceID     string
	IPAddress    string
	UserAgent    string
	CreatedAt    time.Time
	LastActivity time.Time
	ExpiresAt    *time.Time
	Metadata     map[string]interface{}
}

// IsExpired checks if the session is expired
func (s *Session) IsExpired() bool {
	if s.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*s.ExpiresAt)
}

// Touch updates the last activity timestamp
func (s *Session) Touch() {
	s.LastActivity = time.Now()
}

// PolicyRule represents a policy rule for RBAC/ABAC
type PolicyRule struct {
	Subject    string                 // user:alice, role:admin, *
	Action     string                 // read, write, delete, *
	Resource   string                 // document:123, document:*, *
	Effect     string                 // allow or deny
	Conditions map[string]interface{} // optional conditions
}

// Matches checks if this rule matches the given parameters
func (r *PolicyRule) Matches(subject, action, resource string, context map[string]interface{}) bool {
	// Check subject match
	if r.Subject != "*" && r.Subject != subject {
		if !wildcardMatch(r.Subject, subject) {
			return false
		}
	}

	// Check action match
	if r.Action != "*" && r.Action != action {
		if !wildcardMatch(r.Action, action) {
			return false
		}
	}

	// Check resource match
	if r.Resource != "*" && r.Resource != resource {
		if !wildcardMatch(r.Resource, resource) {
			return false
		}
	}

	// Check conditions if provided
	if len(r.Conditions) > 0 && context != nil {
		for key, expectedValue := range r.Conditions {
			if contextValue, ok := context[key]; !ok || contextValue != expectedValue {
				return false
			}
		}
	}

	return true
}

func wildcardMatch(pattern, value string) bool {
	if !strings.Contains(pattern, "*") {
		return pattern == value
	}

	parts := strings.Split(pattern, "*")
	if len(parts) == 2 {
		return strings.HasPrefix(value, parts[0]) && strings.HasSuffix(value, parts[1])
	}

	return false
}

// ============================================================================
// Password Hashing
// ============================================================================

// PasswordHasher interface for password hashing
type PasswordHasher interface {
	Hash(password string) (string, error)
	Verify(password, hashed string) error
}

// PBKDF2Hasher implements PasswordHasher using PBKDF2
type PBKDF2Hasher struct {
	Iterations int
}

// NewPBKDF2Hasher creates a new PBKDF2 hasher
func NewPBKDF2Hasher() *PBKDF2Hasher {
	return &PBKDF2Hasher{Iterations: 100000}
}

// Hash hashes a password using PBKDF2
func (h *PBKDF2Hasher) Hash(password string) (string, error) {
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	key := pbkdf2.Key([]byte(password), salt, h.Iterations, 32, sha256.New)

	return fmt.Sprintf("pbkdf2_sha256$%d$%s$%s",
		h.Iterations,
		base64.StdEncoding.EncodeToString(salt),
		base64.StdEncoding.EncodeToString(key),
	), nil
}

// Verify verifies a password against a hash
func (h *PBKDF2Hasher) Verify(password, hashed string) error {
	parts := strings.Split(hashed, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2_sha256" {
		return errors.New("invalid hash format")
	}

	var iterations int
	if _, err := fmt.Sscanf(parts[1], "%d", &iterations); err != nil {
		return err
	}

	salt, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return err
	}

	storedKey, err := base64.StdEncoding.DecodeString(parts[3])
	if err != nil {
		return err
	}

	key := pbkdf2.Key([]byte(password), salt, iterations, 32, sha256.New)

	if !hmac.Equal(key, storedKey) {
		return errors.New("invalid password")
	}

	return nil
}

// ============================================================================
// Token Generators
// ============================================================================

// TokenGenerator interface for token generation
type TokenGenerator interface {
	Generate(user *User, expiresIn int) (*Token, error)
	Verify(tokenValue string) (*Token, error)
}

// SimpleJWTGenerator implements TokenGenerator using simple JWT
type SimpleJWTGenerator struct {
	Secret []byte
}

// NewSimpleJWTGenerator creates a new JWT generator
func NewSimpleJWTGenerator(secret string) *SimpleJWTGenerator {
	return &SimpleJWTGenerator{Secret: []byte(secret)}
}

// Generate generates a JWT token
func (g *SimpleJWTGenerator) Generate(user *User, expiresIn int) (*Token, error) {
	issuedAt := time.Now()
	expiresAt := issuedAt.Add(time.Duration(expiresIn) * time.Second)

	roles := make([]string, 0, len(user.Roles))
	for role := range user.Roles {
		roles = append(roles, role)
	}

	permissions := make([]string, 0, len(user.Permissions))
	for perm := range user.Permissions {
		permissions = append(permissions, perm)
	}

	payload := map[string]interface{}{
		"userId":      user.ID,
		"username":    user.Username,
		"roles":       roles,
		"permissions": permissions,
		"tenantId":    user.TenantID,
		"iat":         issuedAt.Unix(),
		"exp":         expiresAt.Unix(),
	}

	// Create simple JWT
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payloadJSON, _ := json.Marshal(payload)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	message := header + "." + payloadB64
	mac := hmac.New(sha256.New, g.Secret)
	mac.Write([]byte(message))
	signature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	tokenValue := message + "." + signature

	return &Token{
		Value:     tokenValue,
		Type:      TokenTypeJWT,
		UserID:    user.ID,
		ExpiresAt: expiresAt,
		IssuedAt:  issuedAt,
		Metadata: map[string]interface{}{
			"roles":       roles,
			"permissions": permissions,
		},
	}, nil
}

// Verify verifies a JWT token
func (g *SimpleJWTGenerator) Verify(tokenValue string) (*Token, error) {
	parts := strings.Split(tokenValue, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid token format")
	}

	message := parts[0] + "." + parts[1]
	mac := hmac.New(sha256.New, g.Secret)
	mac.Write([]byte(message))
	expectedSignature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(parts[2]), []byte(expectedSignature)) {
		return nil, errors.New("invalid signature")
	}

	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		return nil, err
	}

	exp := int64(payload["exp"].(float64))
	iat := int64(payload["iat"].(float64))

	token := &Token{
		Value:     tokenValue,
		Type:      TokenTypeJWT,
		UserID:    payload["userId"].(string),
		ExpiresAt: time.Unix(exp, 0),
		IssuedAt:  time.Unix(iat, 0),
		Metadata:  payload,
	}

	if token.IsExpired() {
		return nil, errors.New("token expired")
	}

	return token, nil
}

// OpaqueTokenGenerator implements TokenGenerator using opaque tokens
type OpaqueTokenGenerator struct {
	mu     sync.RWMutex
	tokens map[string]*Token
}

// NewOpaqueTokenGenerator creates a new opaque token generator
func NewOpaqueTokenGenerator() *OpaqueTokenGenerator {
	return &OpaqueTokenGenerator{
		tokens: make(map[string]*Token),
	}
}

// Generate generates an opaque token
func (g *OpaqueTokenGenerator) Generate(user *User, expiresIn int) (*Token, error) {
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, err
	}

	tokenValue := base64.RawURLEncoding.EncodeToString(tokenBytes)
	issuedAt := time.Now()
	expiresAt := issuedAt.Add(time.Duration(expiresIn) * time.Second)

	roles := make([]string, 0, len(user.Roles))
	for role := range user.Roles {
		roles = append(roles, role)
	}

	token := &Token{
		Value:     tokenValue,
		Type:      TokenTypeOpaque,
		UserID:    user.ID,
		ExpiresAt: expiresAt,
		IssuedAt:  issuedAt,
		Metadata: map[string]interface{}{
			"username": user.Username,
			"roles":    roles,
		},
	}

	g.mu.Lock()
	g.tokens[tokenValue] = token
	g.mu.Unlock()

	return token, nil
}

// Verify verifies an opaque token
func (g *OpaqueTokenGenerator) Verify(tokenValue string) (*Token, error) {
	g.mu.RLock()
	token, ok := g.tokens[tokenValue]
	g.mu.RUnlock()

	if !ok || token.IsExpired() {
		return nil, errors.New("invalid or expired token")
	}

	return token, nil
}

// Revoke revokes an opaque token
func (g *OpaqueTokenGenerator) Revoke(tokenValue string) {
	g.mu.Lock()
	delete(g.tokens, tokenValue)
	g.mu.Unlock()
}

// ============================================================================
// Authentication Providers
// ============================================================================

// AuthProvider interface for authentication providers
type AuthProvider interface {
	Authenticate(credentials map[string]interface{}) (*User, error)
}

// LocalAuthProvider implements local username/password authentication
type LocalAuthProvider struct {
	mu             sync.RWMutex
	users          map[string]map[string]interface{}
	passwordHasher PasswordHasher
}

// NewLocalAuthProvider creates a new local auth provider
func NewLocalAuthProvider() *LocalAuthProvider {
	return &LocalAuthProvider{
		users:          make(map[string]map[string]interface{}),
		passwordHasher: NewPBKDF2Hasher(),
	}
}

// RegisterUser registers a new user
func (p *LocalAuthProvider) RegisterUser(username, password, email string, roles, permissions map[string]bool, tenantID string) (*User, error) {
	userIDBytes := make([]byte, 16)
	rand.Read(userIDBytes)
	userID := base64.RawURLEncoding.EncodeToString(userIDBytes)

	hashedPassword, err := p.passwordHasher.Hash(password)
	if err != nil {
		return nil, err
	}

	p.mu.Lock()
	p.users[username] = map[string]interface{}{
		"id":          userID,
		"username":    username,
		"email":       email,
		"password":    hashedPassword,
		"roles":       roles,
		"permissions": permissions,
		"tenantId":    tenantID,
	}
	p.mu.Unlock()

	user := NewUser(userID, username)
	user.Email = email
	user.Roles = roles
	user.Permissions = permissions
	user.TenantID = tenantID

	return user, nil
}

// Authenticate authenticates a user
func (p *LocalAuthProvider) Authenticate(credentials map[string]interface{}) (*User, error) {
	username, _ := credentials["username"].(string)
	password, _ := credentials["password"].(string)

	if username == "" || password == "" {
		return nil, errors.New("username and password required")
	}

	p.mu.RLock()
	userData, ok := p.users[username]
	p.mu.RUnlock()

	if !ok {
		return nil, errors.New("user not found")
	}

	hashedPassword := userData["password"].(string)
	if err := p.passwordHasher.Verify(password, hashedPassword); err != nil {
		return nil, errors.New("invalid password")
	}

	user := NewUser(userData["id"].(string), username)
	user.Email, _ = userData["email"].(string)
	if roles, ok := userData["roles"].(map[string]bool); ok {
		user.Roles = roles
	}
	if permissions, ok := userData["permissions"].(map[string]bool); ok {
		user.Permissions = permissions
	}
	user.TenantID, _ = userData["tenantId"].(string)

	return user, nil
}

// ============================================================================
// Policy Engine
// ============================================================================

// PolicyEngine implements RBAC/ABAC policy engine
type PolicyEngine struct {
	mu              sync.RWMutex
	rules           []*PolicyRule
	rolePermissions map[string]map[string]bool
}

// NewPolicyEngine creates a new policy engine
func NewPolicyEngine() *PolicyEngine {
	return &PolicyEngine{
		rules:           make([]*PolicyRule, 0),
		rolePermissions: make(map[string]map[string]bool),
	}
}

// AddRule adds a policy rule
func (e *PolicyEngine) AddRule(rule *PolicyRule) {
	e.mu.Lock()
	e.rules = append(e.rules, rule)
	e.mu.Unlock()
}

// AddRolePermission adds a permission to a role
func (e *PolicyEngine) AddRolePermission(role, permission string) {
	e.mu.Lock()
	if e.rolePermissions[role] == nil {
		e.rolePermissions[role] = make(map[string]bool)
	}
	e.rolePermissions[role][permission] = true
	e.mu.Unlock()
}

// Check checks if user is allowed to perform action on resource
func (e *PolicyEngine) Check(user *User, action, resource string, context map[string]interface{}) bool {
	// Check direct permissions
	if user.HasPermission(action + ":" + resource) {
		return true
	}

	// Check role-based permissions
	e.mu.RLock()
	for role := range user.Roles {
		if perms, ok := e.rolePermissions[role]; ok {
			if perms[action+":"+resource] || perms[action+":*"] {
				e.mu.RUnlock()
				return true
			}
		}
	}

	// Check policy rules
	for _, rule := range e.rules {
		if rule.Matches("user:"+user.Username, action, resource, context) {
			e.mu.RUnlock()
			return rule.Effect == "allow"
		}

		for role := range user.Roles {
			if rule.Matches("role:"+role, action, resource, context) {
				e.mu.RUnlock()
				return rule.Effect == "allow"
			}
		}

		if rule.Matches("*", action, resource, context) {
			e.mu.RUnlock()
			return rule.Effect == "allow"
		}
	}
	e.mu.RUnlock()

	return false
}

// ============================================================================
// Session Manager
// ============================================================================

// SessionManager manages user sessions
type SessionManager struct {
	mu         sync.RWMutex
	sessions   map[string]*Session
	defaultTTL int
}

// NewSessionManager creates a new session manager
func NewSessionManager(defaultTTL int) *SessionManager {
	return &SessionManager{
		sessions:   make(map[string]*Session),
		defaultTTL: defaultTTL,
	}
}

// CreateSession creates a new session
func (m *SessionManager) CreateSession(userID, deviceID, ipAddress, userAgent string, ttl int) *Session {
	sessionIDBytes := make([]byte, 32)
	rand.Read(sessionIDBytes)
	sessionID := base64.RawURLEncoding.EncodeToString(sessionIDBytes)

	if ttl == 0 {
		ttl = m.defaultTTL
	}

	var expiresAt *time.Time
	if ttl <= 0 {
		t := time.Now().Add(-time.Second)
		expiresAt = &t
	} else {
		t := time.Now().Add(time.Duration(ttl) * time.Second)
		expiresAt = &t
	}

	session := &Session{
		ID:           sessionID,
		UserID:       userID,
		DeviceID:     deviceID,
		IPAddress:    ipAddress,
		UserAgent:    userAgent,
		CreatedAt:    time.Now(),
		LastActivity: time.Now(),
		ExpiresAt:    expiresAt,
		Metadata:     make(map[string]interface{}),
	}

	m.mu.Lock()
	m.sessions[sessionID] = session
	m.mu.Unlock()

	return session
}

// GetSession gets a session by ID
func (m *SessionManager) GetSession(sessionID string) *Session {
	m.mu.RLock()
	session, ok := m.sessions[sessionID]
	m.mu.RUnlock()

	if ok && !session.IsExpired() {
		session.Touch()
		return session
	}

	return nil
}

// RevokeSession revokes a session
func (m *SessionManager) RevokeSession(sessionID string) {
	m.mu.Lock()
	delete(m.sessions, sessionID)
	m.mu.Unlock()
}

// RevokeUserSessions revokes all sessions for a user
func (m *SessionManager) RevokeUserSessions(userID string) {
	m.mu.Lock()
	for sid, session := range m.sessions {
		if session.UserID == userID {
			delete(m.sessions, sid)
		}
	}
	m.mu.Unlock()
}

// CleanupExpired removes expired sessions
func (m *SessionManager) CleanupExpired() {
	m.mu.Lock()
	for sid, session := range m.sessions {
		if session.IsExpired() {
			delete(m.sessions, sid)
		}
	}
	m.mu.Unlock()
}

// ============================================================================
// Main Auth Class
// ============================================================================

// LoginResult represents the result of a login operation
type LoginResult struct {
	User         *User
	AccessToken  string
	RefreshToken string
	TokenType    string
	ExpiresIn    int
	SessionID    string
}

// Auth is the main authentication and authorization framework
type Auth struct {
	mu             sync.RWMutex
	providers      map[string]AuthProvider
	tokenGenerator TokenGenerator
	PolicyEngine   *PolicyEngine
	SessionManager *SessionManager
	revokedTokens  map[string]bool
}

// NewAuth creates a new Auth instance
func NewAuth(secret string, tokenType TokenType) *Auth {
	var tokenGenerator TokenGenerator
	if tokenType == TokenTypeJWT {
		tokenGenerator = NewSimpleJWTGenerator(secret)
	} else {
		tokenGenerator = NewOpaqueTokenGenerator()
	}

	return &Auth{
		providers:      make(map[string]AuthProvider),
		tokenGenerator: tokenGenerator,
		PolicyEngine:   NewPolicyEngine(),
		SessionManager: NewSessionManager(3600),
		revokedTokens:  make(map[string]bool),
	}
}

// AddProvider adds an authentication provider
func (a *Auth) AddProvider(name string, provider AuthProvider) {
	a.mu.Lock()
	a.providers[name] = provider
	a.mu.Unlock()
}

// Authenticate authenticates a user using the specified provider
func (a *Auth) Authenticate(providerName string, credentials map[string]interface{}) (*User, error) {
	a.mu.RLock()
	provider, ok := a.providers[providerName]
	a.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("unknown provider: %s", providerName)
	}

	return provider.Authenticate(credentials)
}

// Login authenticates and creates tokens/session
func (a *Auth) Login(providerName string, credentials map[string]interface{}, createSession bool, tokenTTL int) (*LoginResult, error) {
	user, err := a.Authenticate(providerName, credentials)
	if err != nil {
		return nil, err
	}

	// Generate access token
	accessToken, err := a.tokenGenerator.Generate(user, tokenTTL)
	if err != nil {
		return nil, err
	}

	// Generate refresh token (longer TTL)
	refreshToken, err := a.tokenGenerator.Generate(user, tokenTTL*24)
	if err != nil {
		return nil, err
	}

	result := &LoginResult{
		User:         user,
		AccessToken:  accessToken.Value,
		RefreshToken: refreshToken.Value,
		TokenType:    "Bearer",
		ExpiresIn:    tokenTTL,
	}

	// Create session if requested
	if createSession {
		deviceID, _ := credentials["deviceId"].(string)
		ipAddress, _ := credentials["ipAddress"].(string)
		userAgent, _ := credentials["userAgent"].(string)

		session := a.SessionManager.CreateSession(user.ID, deviceID, ipAddress, userAgent, 0)
		result.SessionID = session.ID
	}

	return result, nil
}

// VerifyToken verifies a token
func (a *Auth) VerifyToken(tokenValue string) (*Token, error) {
	a.mu.RLock()
	if a.revokedTokens[tokenValue] {
		a.mu.RUnlock()
		return nil, errors.New("token revoked")
	}
	a.mu.RUnlock()

	return a.tokenGenerator.Verify(tokenValue)
}

// RevokeToken revokes a token
func (a *Auth) RevokeToken(tokenValue string) {
	a.mu.Lock()
	a.revokedTokens[tokenValue] = true
	a.mu.Unlock()
}

// CheckPermission checks if user has permission
func (a *Auth) CheckPermission(user *User, action, resource string, context map[string]interface{}) bool {
	return a.PolicyEngine.Check(user, action, resource, context)
}
