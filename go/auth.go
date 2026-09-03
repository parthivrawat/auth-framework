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
	"path"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

// ErrAuthInvalidSecret is returned when a required secret is empty.
var ErrAuthInvalidSecret = errors.New("auth secret is required and cannot be empty")

// ErrUnknownProvider is returned when the requested authentication provider is not registered.
var ErrUnknownProvider = errors.New("unknown provider")

// ErrInvalidCredentials is returned when the provided credentials are invalid.
var ErrInvalidCredentials = errors.New("invalid credentials")

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
	matched, err := path.Match(pattern, value)
	return err == nil && matched
}

func containsString(list []string, value string) bool {
	for _, v := range list {
		if v == value {
			return true
		}
	}
	return false
}

// ============================================================================
// Storage Backend
// ============================================================================

// StorageBackend defines a pluggable key/value store used by token and session
// managers to share a single storage abstraction.
type StorageBackend interface {
	Get(key string) (interface{}, bool)
	Set(key string, value interface{}) bool
	Delete(key string) bool
	Has(key string) bool
	Keys(prefix string) []string
	Clear()
}

// InMemoryStorage is the default StorageBackend implementation. It is backed by
// a map and is safe for concurrent use.
type InMemoryStorage struct {
	mu   sync.RWMutex
	data map[string]interface{}
}

// NewInMemoryStorage creates a new in-memory storage backend.
func NewInMemoryStorage() *InMemoryStorage {
	return &InMemoryStorage{
		data: make(map[string]interface{}),
	}
}

// Get retrieves a value by key.
func (s *InMemoryStorage) Get(key string) (interface{}, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.data[key]
	return v, ok
}

// Set stores a value under the given key.
func (s *InMemoryStorage) Set(key string, value interface{}) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[key] = value
	return true
}

// Delete removes a value by key.
func (s *InMemoryStorage) Delete(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.data[key]
	delete(s.data, key)
	return ok
}

// Has reports whether a key exists.
func (s *InMemoryStorage) Has(key string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.data[key]
	return ok
}

// Keys returns all keys that start with the given prefix.
func (s *InMemoryStorage) Keys(prefix string) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var keys []string
	for k := range s.data {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	return keys
}

// Clear removes all stored values.
func (s *InMemoryStorage) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data = make(map[string]interface{})
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

// RefreshTokenGenerator extends token generation with refresh-token support.
type RefreshTokenGenerator interface {
	GenerateRefresh(user *User, expiresIn int, familyID string) (*Token, error)
}

// SimpleJWTGenerator implements TokenGenerator using simple JWT
type SimpleJWTGenerator struct {
	Secret            []byte
	Issuer            string
	Audience          string
	KeyID             string
	AllowedAlgorithms []string
	ExpectedIssuer    string
	ExpectedAudience  string
}

// NewSimpleJWTGenerator creates a new JWT generator
func NewSimpleJWTGenerator(secret string) *SimpleJWTGenerator {
	return &SimpleJWTGenerator{
		Secret:            []byte(secret),
		AllowedAlgorithms: []string{"HS256"},
	}
}

// Generate generates a JWT token
func (g *SimpleJWTGenerator) Generate(user *User, expiresIn int) (*Token, error) {
	return g.generateToken(user, expiresIn, "", TokenTypeJWT)
}

// GenerateRefresh generates a refresh JWT token bound to a family.
func (g *SimpleJWTGenerator) GenerateRefresh(user *User, expiresIn int, familyID string) (*Token, error) {
	return g.generateToken(user, expiresIn, familyID, TokenTypeRefresh)
}

func (g *SimpleJWTGenerator) generateToken(user *User, expiresIn int, familyID string, tokenType TokenType) (*Token, error) {
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

	jtiBytes := make([]byte, 16)
	if _, err := rand.Read(jtiBytes); err != nil {
		return nil, err
	}
	jti := base64.RawURLEncoding.EncodeToString(jtiBytes)

	payload := map[string]interface{}{
		"userId":      user.ID,
		"username":    user.Username,
		"roles":       roles,
		"permissions": permissions,
		"tenantId":    user.TenantID,
		"jti":         jti,
		"iat":         issuedAt.Unix(),
		"exp":         expiresAt.Unix(),
	}
	if tokenType == TokenTypeRefresh {
		payload["tokenType"] = string(tokenType)
		payload["fid"] = familyID
	}
	if g.Issuer != "" {
		payload["iss"] = g.Issuer
	}
	if g.Audience != "" {
		payload["aud"] = g.Audience
	}

	// Create simple JWT
	headerObj := map[string]interface{}{"alg": "HS256", "typ": "JWT"}
	if g.KeyID != "" {
		headerObj["kid"] = g.KeyID
	}
	headerJSON, _ := json.Marshal(headerObj)
	header := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadJSON, _ := json.Marshal(payload)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	message := header + "." + payloadB64
	mac := hmac.New(sha256.New, g.Secret)
	mac.Write([]byte(message))
	signature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	tokenValue := message + "." + signature

	return &Token{
		Value:     tokenValue,
		Type:      tokenType,
		UserID:    user.ID,
		ExpiresAt: expiresAt,
		IssuedAt:  issuedAt,
		Metadata:  payload,
	}, nil
}

// Verify verifies a JWT token
func (g *SimpleJWTGenerator) Verify(tokenValue string) (*Token, error) {
	parts := strings.Split(tokenValue, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid token format")
	}

	// Decode and validate header
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}
	var header map[string]interface{}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, err
	}
	alg, ok := header["alg"].(string)
	if !ok || !containsString(g.AllowedAlgorithms, alg) {
		return nil, errors.New("invalid or unsupported algorithm")
	}
	if g.KeyID != "" {
		kid, _ := header["kid"].(string)
		if kid != g.KeyID {
			return nil, errors.New("invalid key id")
		}
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

	if g.ExpectedIssuer != "" && payload["iss"] != g.ExpectedIssuer {
		return nil, errors.New("invalid issuer")
	}
	if g.ExpectedAudience != "" && payload["aud"] != g.ExpectedAudience {
		return nil, errors.New("invalid audience")
	}
	if jti, ok := payload["jti"].(string); !ok || jti == "" {
		return nil, errors.New("missing token id")
	}

	exp, ok := payload["exp"].(float64)
	if !ok {
		return nil, errors.New("missing exp")
	}
	iat, ok := payload["iat"].(float64)
	if !ok {
		return nil, errors.New("missing iat")
	}
	userID, ok := payload["userId"].(string)
	if !ok {
		return nil, errors.New("missing user id")
	}

	tokenType := TokenTypeJWT
	if t, ok := payload["tokenType"].(string); ok && t != "" {
		tokenType = TokenType(t)
	}

	token := &Token{
		Value:     tokenValue,
		Type:      tokenType,
		UserID:    userID,
		ExpiresAt: time.Unix(int64(exp), 0),
		IssuedAt:  time.Unix(int64(iat), 0),
		Metadata:  payload,
	}

	if token.IsExpired() {
		return nil, errors.New("token expired")
	}

	return token, nil
}

// OpaqueTokenGenerator implements TokenGenerator using opaque tokens
type OpaqueTokenGenerator struct {
	storage StorageBackend
}

// NewOpaqueTokenGenerator creates a new opaque token generator with in-memory storage.
func NewOpaqueTokenGenerator() *OpaqueTokenGenerator {
	return NewOpaqueTokenGeneratorWithStorage(NewInMemoryStorage())
}

// NewOpaqueTokenGeneratorWithStorage creates a new opaque token generator backed by the given storage.
func NewOpaqueTokenGeneratorWithStorage(storage StorageBackend) *OpaqueTokenGenerator {
	return &OpaqueTokenGenerator{
		storage: storage,
	}
}

// Generate generates an opaque token
func (g *OpaqueTokenGenerator) Generate(user *User, expiresIn int) (*Token, error) {
	return g.generateToken(user, expiresIn, TokenTypeOpaque, nil)
}

// GenerateRefresh generates an opaque refresh token bound to a family.
func (g *OpaqueTokenGenerator) GenerateRefresh(user *User, expiresIn int, familyID string) (*Token, error) {
	return g.generateToken(user, expiresIn, TokenTypeRefresh, map[string]interface{}{
		"fid":       familyID,
		"tokenType": "refresh",
		"user":      user,
	})
}

func (g *OpaqueTokenGenerator) generateToken(user *User, expiresIn int, tokenType TokenType, extra map[string]interface{}) (*Token, error) {
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

	metadata := map[string]interface{}{
		"username": user.Username,
		"roles":    roles,
	}
	if extra != nil {
		for k, v := range extra {
			metadata[k] = v
		}
	}

	token := &Token{
		Value:     tokenValue,
		Type:      tokenType,
		UserID:    user.ID,
		ExpiresAt: expiresAt,
		IssuedAt:  issuedAt,
		Metadata:  metadata,
	}

	g.storage.Set("token:"+tokenValue, token)

	return token, nil
}

// Verify verifies an opaque token
func (g *OpaqueTokenGenerator) Verify(tokenValue string) (*Token, error) {
	if g.isRevoked(tokenValue) {
		return nil, errors.New("token revoked")
	}

	v, ok := g.storage.Get("token:" + tokenValue)
	if !ok {
		return nil, errors.New("invalid or expired token")
	}

	token, ok := v.(*Token)
	if !ok || token.IsExpired() {
		return nil, errors.New("invalid or expired token")
	}

	return token, nil
}

// revoke stores a revocation sentinel for the token.
func (g *OpaqueTokenGenerator) revoke(tokenValue string) {
	g.storage.Set("revoked:"+tokenValue, true)
}

// isRevoked reports whether the token has been revoked.
func (g *OpaqueTokenGenerator) isRevoked(tokenValue string) bool {
	return g.storage.Has("revoked:" + tokenValue)
}

// Revoke revokes an opaque token
func (g *OpaqueTokenGenerator) Revoke(tokenValue string) {
	g.revoke(tokenValue)

	if v, ok := g.storage.Get("token:" + tokenValue); ok {
		if t, ok := v.(*Token); ok {
			if fid, ok := t.Metadata["fid"].(string); ok && fid != "" {
				g.storage.Delete("refreshFamily:" + fid)
			}
		}
	}
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
		return nil, ErrInvalidCredentials
	}

	p.mu.RLock()
	userData, ok := p.users[username]
	p.mu.RUnlock()

	if !ok {
		return nil, ErrInvalidCredentials
	}

	hashedPassword := userData["password"].(string)
	if err := p.passwordHasher.Verify(password, hashedPassword); err != nil {
		return nil, ErrInvalidCredentials
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
	e.mu.RLock()
	defer e.mu.RUnlock()

	// Helper to determine whether a rule matches the user/action/resource.
	matchesRule := func(rule *PolicyRule) bool {
		if rule.Matches("user:"+user.Username, action, resource, context) {
			return true
		}
		for role := range user.Roles {
			if rule.Matches("role:"+role, action, resource, context) {
				return true
			}
		}
		return rule.Matches("*", action, resource, context)
	}

	// First pass: explicit deny rules override everything
	for _, rule := range e.rules {
		if matchesRule(rule) && rule.Effect == "deny" {
			return false
		}
	}

	// Check direct permissions
	if user.HasPermission(action + ":" + resource) {
		return true
	}

	// Check role-based permissions
	for role := range user.Roles {
		if perms, ok := e.rolePermissions[role]; ok {
			if perms[action+":"+resource] || perms[action+":*"] {
				return true
			}
		}
	}

	// Second pass: allow rules
	for _, rule := range e.rules {
		if matchesRule(rule) && rule.Effect == "allow" {
			return true
		}
	}

	return false
}

// ============================================================================
// Session Manager
// ============================================================================

const sessionKeyPrefix = "session:"
const userSessionsKeyPrefix = "userSessions:"

func sessionKey(id string) string      { return sessionKeyPrefix + id }
func userSessionsKey(userID string) string { return userSessionsKeyPrefix + userID }

// SessionManager manages user sessions
type SessionManager struct {
	storage    StorageBackend
	defaultTTL int
}

// NewSessionManager creates a new session manager with in-memory storage.
func NewSessionManager(defaultTTL int) *SessionManager {
	return NewSessionManagerWithStorage(defaultTTL, NewInMemoryStorage())
}

// NewSessionManagerWithStorage creates a new session manager backed by the given storage.
func NewSessionManagerWithStorage(defaultTTL int, storage StorageBackend) *SessionManager {
	return &SessionManager{
		storage:    storage,
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

	m.storage.Set(sessionKey(sessionID), session)

	var userSessionIDs []string
	if v, ok := m.storage.Get(userSessionsKey(userID)); ok {
		if ids, ok := v.([]string); ok {
			userSessionIDs = ids
		}
	}
	m.storage.Set(userSessionsKey(userID), append(userSessionIDs, sessionID))

	return session
}

// GetSession gets a session by ID
func (m *SessionManager) GetSession(sessionID string) *Session {
	v, ok := m.storage.Get(sessionKey(sessionID))
	if !ok {
		return nil
	}

	session, ok := v.(*Session)
	if !ok || session.IsExpired() {
		return nil
	}

	session.Touch()
	m.storage.Set(sessionKey(sessionID), session)
	return session
}

// removeSessionFromIndex removes a session ID from the per-user session index.
func (m *SessionManager) removeSessionFromIndex(userID, sessionID string) {
	key := userSessionsKey(userID)
	if v, ok := m.storage.Get(key); ok {
		if ids, ok := v.([]string); ok {
			filtered := make([]string, 0, len(ids))
			for _, id := range ids {
				if id != sessionID {
					filtered = append(filtered, id)
				}
			}
			if len(filtered) > 0 {
				m.storage.Set(key, filtered)
			} else {
				m.storage.Delete(key)
			}
		}
	}
}

// RevokeSession revokes a session
func (m *SessionManager) RevokeSession(sessionID string) {
	if v, ok := m.storage.Get(sessionKey(sessionID)); ok {
		if s, ok := v.(*Session); ok {
			m.removeSessionFromIndex(s.UserID, sessionID)
		}
	}
	m.storage.Delete(sessionKey(sessionID))
}

// RevokeUserSessions revokes all sessions for a user
func (m *SessionManager) RevokeUserSessions(userID string) {
	key := userSessionsKey(userID)
	if v, ok := m.storage.Get(key); ok {
		if ids, ok := v.([]string); ok {
			for _, id := range ids {
				m.storage.Delete(sessionKey(id))
			}
		}
	}
	m.storage.Delete(key)
}

// CleanupExpired removes expired sessions
func (m *SessionManager) CleanupExpired() {
	for _, key := range m.storage.Keys(sessionKeyPrefix) {
		sessionID := strings.TrimPrefix(key, sessionKeyPrefix)
		v, ok := m.storage.Get(key)
		if !ok {
			continue
		}
		session, ok := v.(*Session)
		if !ok {
			continue
		}
		if session.IsExpired() {
			m.removeSessionFromIndex(session.UserID, sessionID)
			m.storage.Delete(key)
		}
	}
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
	FamilyID     string
}

// Auth is the main authentication and authorization framework
type Auth struct {
	mu                sync.RWMutex
	providers         map[string]AuthProvider
	tokenGenerator    TokenGenerator
	refreshGenerator  RefreshTokenGenerator
	PolicyEngine      *PolicyEngine
	SessionManager    *SessionManager
	storage           StorageBackend
	issuer            string
	audience          string
	keyID             string
	allowedAlgorithms []string
	defaultTokenTTL   int
}

// AuthOption configures an Auth instance.
type AuthOption func(*Auth)

// WithIssuer sets the token issuer.
func WithIssuer(issuer string) AuthOption {
	return func(a *Auth) { a.issuer = issuer }
}

// WithAudience sets the token audience.
func WithAudience(audience string) AuthOption {
	return func(a *Auth) { a.audience = audience }
}

// WithKeyID sets the token key ID.
func WithKeyID(keyID string) AuthOption {
	return func(a *Auth) { a.keyID = keyID }
}

// WithAllowedAlgorithms sets the allowed signing algorithms.
func WithAllowedAlgorithms(algorithms []string) AuthOption {
	return func(a *Auth) { a.allowedAlgorithms = algorithms }
}

// WithStorage sets the storage backend.
func WithStorage(storage StorageBackend) AuthOption {
	return func(a *Auth) { a.storage = storage }
}

// NewAuth creates a new Auth instance
func NewAuth(secret string, tokenType TokenType, options ...AuthOption) (*Auth, error) {
	if secret == "" {
		return nil, ErrAuthInvalidSecret
	}

	auth := &Auth{
		providers:         make(map[string]AuthProvider),
		PolicyEngine:      NewPolicyEngine(),
		storage:           NewInMemoryStorage(),
		allowedAlgorithms: []string{"HS256"},
		defaultTokenTTL:   3600,
	}
	for _, opt := range options {
		opt(auth)
	}

	auth.SessionManager = NewSessionManagerWithStorage(3600, auth.storage)

	var tokenGenerator TokenGenerator
	var refreshGenerator RefreshTokenGenerator
	if tokenType == TokenTypeJWT {
		g := NewSimpleJWTGenerator(secret)
		g.Issuer = auth.issuer
		g.Audience = auth.audience
		g.KeyID = auth.keyID
		g.ExpectedIssuer = auth.issuer
		g.ExpectedAudience = auth.audience
		if len(auth.allowedAlgorithms) > 0 {
			g.AllowedAlgorithms = auth.allowedAlgorithms
		}
		tokenGenerator = g
		refreshGenerator = g
	} else {
		og := NewOpaqueTokenGeneratorWithStorage(auth.storage)
		tokenGenerator = og
		refreshGenerator = og
	}
	auth.tokenGenerator = tokenGenerator
	auth.refreshGenerator = refreshGenerator

	return auth, nil
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
	a.mu.RLock()
	provider, ok := a.providers[providerName]
	a.mu.RUnlock()

	if !ok {
		return nil, ErrUnknownProvider
	}

	user, err := provider.Authenticate(credentials)
	if err != nil {
		return nil, ErrInvalidCredentials
	}

	// Generate access token
	accessToken, err := a.tokenGenerator.Generate(user, tokenTTL)
	if err != nil {
		return nil, err
	}

	// Generate refresh token (longer TTL) bound to a new family
	familyID, err := generateFamilyID()
	if err != nil {
		return nil, err
	}
	refreshToken, err := a.refreshGenerator.GenerateRefresh(user, tokenTTL*24, familyID)
	if err != nil {
		return nil, err
	}
	a.storage.Set("refreshFamily:"+familyID, refreshToken.Value)

	result := &LoginResult{
		User:         user,
		AccessToken:  accessToken.Value,
		RefreshToken: refreshToken.Value,
		TokenType:    "Bearer",
		ExpiresIn:    tokenTTL,
		FamilyID:     familyID,
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
	if a.storage.Has("revoked:" + tokenValue) {
		return nil, errors.New("token revoked")
	}

	return a.tokenGenerator.Verify(tokenValue)
}

// RevokeToken revokes a token
func (a *Auth) RevokeToken(tokenValue string) {
	a.storage.Set("revoked:"+tokenValue, true)

	if familyID, ok := a.extractRefreshFamily(tokenValue); ok {
		a.revokeFamily(familyID)
	}
}

// RefreshTokens issues a new access/refresh token pair using a refresh token.
func (a *Auth) RefreshTokens(refreshToken string) (*LoginResult, error) {
	token, err := a.VerifyToken(refreshToken)
	if err != nil {
		return nil, err
	}

	if token.Type != TokenTypeRefresh {
		return nil, errors.New("token is not a refresh token")
	}

	familyID, ok := token.Metadata["fid"].(string)
	if !ok || familyID == "" {
		return nil, errors.New("missing token family")
	}

	activeToken, ok := a.storage.Get("refreshFamily:" + familyID)
	if !ok {
		a.revokeFamily(familyID)
		return nil, errors.New("invalid refresh token family")
	}

	active, ok := activeToken.(string)
	if !ok || active != refreshToken {
		a.revokeFamily(familyID)
		return nil, errors.New("refresh token reuse detected")
	}

	user, err := userFromToken(token)
	if err != nil {
		return nil, err
	}

	tokenTTL := a.defaultTokenTTL
	if tokenTTL <= 0 {
		tokenTTL = 3600
	}

	// Rotate: new refresh token replaces the active one, same family.
	accessToken, err := a.tokenGenerator.Generate(user, tokenTTL)
	if err != nil {
		return nil, err
	}
	newRefresh, err := a.refreshGenerator.GenerateRefresh(user, tokenTTL*24, familyID)
	if err != nil {
		return nil, err
	}
	a.storage.Set("refreshFamily:"+familyID, newRefresh.Value)

	return &LoginResult{
		User:         user,
		AccessToken:  accessToken.Value,
		RefreshToken: newRefresh.Value,
		TokenType:    "Bearer",
		ExpiresIn:    tokenTTL,
		FamilyID:     familyID,
	}, nil
}

func (a *Auth) revokeFamily(familyID string) {
	for _, key := range a.storage.Keys("refreshFamily:" + familyID) {
		a.storage.Delete(key)
	}
}

func (a *Auth) extractRefreshFamily(tokenValue string) (string, bool) {
	// Try opaque token storage first.
	if v, ok := a.storage.Get("token:" + tokenValue); ok {
		if t, ok := v.(*Token); ok {
			if tokenType, _ := t.Metadata["tokenType"].(string); tokenType == "refresh" {
				if fid, ok := t.Metadata["fid"].(string); ok && fid != "" {
					return fid, true
				}
			}
		}
	}

	// Otherwise, treat it as a JWT and parse the payload for the family id.
	parts := strings.Split(tokenValue, ".")
	if len(parts) != 3 {
		return "", false
	}
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", false
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		return "", false
	}
	if tokenType, _ := payload["tokenType"].(string); tokenType != "refresh" {
		return "", false
	}
	fid, ok := payload["fid"].(string)
	return fid, ok && fid != ""
}

func generateFamilyID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func userFromToken(token *Token) (*User, error) {
	if u, ok := token.Metadata["user"].(*User); ok {
		return u, nil
	}

	userID := token.UserID
	if userID == "" {
		return nil, errors.New("missing user id in token")
	}

	username, _ := token.Metadata["username"].(string)
	user := NewUser(userID, username)

	if roles, ok := token.Metadata["roles"].([]interface{}); ok {
		for _, r := range roles {
			if s, ok := r.(string); ok {
				user.Roles[s] = true
			}
		}
	} else if roles, ok := token.Metadata["roles"].([]string); ok {
		for _, r := range roles {
			user.Roles[r] = true
		}
	}

	if permissions, ok := token.Metadata["permissions"].([]interface{}); ok {
		for _, p := range permissions {
			if s, ok := p.(string); ok {
				user.Permissions[s] = true
			}
		}
	} else if permissions, ok := token.Metadata["permissions"].([]string); ok {
		for _, p := range permissions {
			user.Permissions[p] = true
		}
	}

	if tenantID, ok := token.Metadata["tenantId"].(string); ok {
		user.TenantID = tenantID
	}

	return user, nil
}

// CheckPermission checks if user has permission
func (a *Auth) CheckPermission(user *User, action, resource string, context map[string]interface{}) bool {
	return a.PolicyEngine.Check(user, action, resource, context)
}
