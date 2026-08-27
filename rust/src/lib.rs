//! Auth & Authorization Framework (Rust)
//!
//! A unified identity, session, token, and permission framework with pluggable
//! providers, strong defaults, and production-ready security.
//!
//! Features:
//! - Username/password and API-key authentication
//! - JWT and opaque token management
//! - RBAC and ABAC policy engine
//! - Session and device management
//! - Token revocation and refresh

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::num::NonZeroU32;
use std::str::FromStr;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::{
    engine::general_purpose::STANDARD, engine::general_purpose::URL_SAFE_NO_PAD, Engine as _,
};
use ring::rand::SecureRandom;
use ring::{hmac, pbkdf2, rand};
use serde_json::Value;
use subtle::ConstantTimeEq;

// ============================================================================
// Errors
// ============================================================================

/// Errors that can occur in the auth framework.
#[derive(Debug)]
pub enum AuthError {
    InvalidCredentials,
    InvalidToken,
    InvalidSignature,
    TokenExpired,
    UnknownProvider(String),
    InvalidHashFormat,
    Serialization(String),
    Base64(String),
    Crypto(String),
    TimeError,
    MissingField(String),
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthError::InvalidCredentials => write!(f, "invalid credentials"),
            AuthError::InvalidToken => write!(f, "invalid token"),
            AuthError::InvalidSignature => write!(f, "invalid token signature"),
            AuthError::TokenExpired => write!(f, "token expired"),
            AuthError::UnknownProvider(name) => write!(f, "unknown provider: {name}"),
            AuthError::InvalidHashFormat => write!(f, "invalid password hash format"),
            AuthError::Serialization(msg) => write!(f, "serialization error: {msg}"),
            AuthError::Base64(msg) => write!(f, "base64 error: {msg}"),
            AuthError::Crypto(msg) => write!(f, "cryptographic error: {msg}"),
            AuthError::TimeError => write!(f, "system time error"),
            AuthError::MissingField(name) => write!(f, "missing field: {name}"),
        }
    }
}

impl std::error::Error for AuthError {}

impl From<serde_json::Error> for AuthError {
    fn from(err: serde_json::Error) -> Self {
        AuthError::Serialization(err.to_string())
    }
}

impl From<base64::DecodeError> for AuthError {
    fn from(err: base64::DecodeError) -> Self {
        AuthError::Base64(err.to_string())
    }
}

impl From<ring::error::Unspecified> for AuthError {
    fn from(_: ring::error::Unspecified) -> Self {
        AuthError::Crypto("ring operation failed".to_string())
    }
}

impl From<std::time::SystemTimeError> for AuthError {
    fn from(_: std::time::SystemTimeError) -> Self {
        AuthError::TimeError
    }
}

// ============================================================================
// Helpers
// ============================================================================

fn random_bytes(len: usize) -> Result<Vec<u8>, AuthError> {
    let rng = rand::SystemRandom::new();
    let mut buf = vec![0u8; len];
    rng.fill(&mut buf)?;
    Ok(buf)
}

fn random_id(len: usize) -> Result<String, AuthError> {
    Ok(URL_SAFE_NO_PAD.encode(&random_bytes(len)?))
}

// ============================================================================
// Core Types and Enums
// ============================================================================

/// Token types supported by the framework.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenType {
    JWT,
    Opaque,
    Refresh,
}

/// Authentication methods.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMethod {
    Local,
    OAuth2,
    Oidc,
    Saml,
    ApiKey,
}

/// Represents an authenticated user.
#[derive(Debug, Clone)]
pub struct User {
    pub id: String,
    pub username: String,
    pub email: Option<String>,
    pub roles: HashSet<String>,
    pub permissions: HashSet<String>,
    pub metadata: HashMap<String, Value>,
    pub tenant_id: Option<String>,
}

impl User {
    /// Create a new user.
    pub fn new(id: &str, username: &str) -> Self {
        Self {
            id: id.to_string(),
            username: username.to_string(),
            email: None,
            roles: HashSet::new(),
            permissions: HashSet::new(),
            metadata: HashMap::new(),
            tenant_id: None,
        }
    }

    /// Check if the user has a specific role.
    pub fn has_role(&self, role: &str) -> bool {
        self.roles.contains(role)
    }

    /// Check if the user has a specific permission.
    pub fn has_permission(&self, permission: &str) -> bool {
        self.permissions.contains(permission)
    }

    /// Check if the user has any of the specified roles.
    pub fn has_any_role(&self, roles: &[&str]) -> bool {
        roles.iter().any(|&r| self.roles.contains(r))
    }

    /// Check if the user has all of the specified roles.
    pub fn has_all_roles(&self, roles: &[&str]) -> bool {
        roles.iter().all(|&r| self.roles.contains(r))
    }
}

/// Represents an authentication token.
#[derive(Debug, Clone)]
pub struct Token {
    pub value: String,
    pub token_type: TokenType,
    pub user_id: String,
    pub expires_at: SystemTime,
    pub issued_at: SystemTime,
    pub metadata: HashMap<String, Value>,
}

impl Token {
    /// Check if the token is expired.
    pub fn is_expired(&self) -> bool {
        SystemTime::now() > self.expires_at
    }
}

/// Represents a user session.
#[derive(Debug, Clone)]
pub struct Session {
    pub id: String,
    pub user_id: String,
    pub device_id: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub created_at: SystemTime,
    pub last_activity: SystemTime,
    pub expires_at: Option<SystemTime>,
    pub metadata: HashMap<String, Value>,
}

impl Session {
    /// Check if the session is expired.
    pub fn is_expired(&self) -> bool {
        self.expires_at.is_some_and(|e| SystemTime::now() > e)
    }

    /// Update the last activity timestamp.
    pub fn touch(&mut self) {
        self.last_activity = SystemTime::now();
    }
}

/// Represents a policy rule for RBAC/ABAC.
#[derive(Debug, Clone)]
pub struct PolicyRule {
    pub subject: String,
    pub action: String,
    pub resource: String,
    pub effect: String,
    pub conditions: HashMap<String, String>,
}

impl PolicyRule {
    /// Create a new policy rule.
    pub fn new(subject: &str, action: &str, resource: &str) -> Self {
        Self {
            subject: subject.to_string(),
            action: action.to_string(),
            resource: resource.to_string(),
            effect: "allow".to_string(),
            conditions: HashMap::new(),
        }
    }

    /// Set the effect ("allow" or "deny").
    pub fn with_effect(mut self, effect: &str) -> Self {
        self.effect = effect.to_string();
        self
    }

    /// Set optional conditions for the rule.
    pub fn with_conditions(mut self, conditions: HashMap<String, String>) -> Self {
        self.conditions = conditions;
        self
    }

    /// Check if this rule matches the given parameters.
    pub fn matches(
        &self,
        subject: &str,
        action: &str,
        resource: &str,
        context: Option<&HashMap<String, String>>,
    ) -> bool {
        if !self.matches_pattern(&self.subject, subject) {
            return false;
        }
        if !self.matches_pattern(&self.action, action) {
            return false;
        }
        if !self.matches_pattern(&self.resource, resource) {
            return false;
        }

        if !self.conditions.is_empty() {
            if let Some(ctx) = context {
                for (key, expected) in &self.conditions {
                    if ctx.get(key) != Some(expected) {
                        return false;
                    }
                }
            } else {
                return false;
            }
        }

        true
    }

    fn matches_pattern(&self, pattern: &str, value: &str) -> bool {
        if pattern == "*" {
            return true;
        }
        if !pattern.contains('*') {
            return pattern == value;
        }

        let parts: Vec<&str> = pattern.split('*').collect();
        if parts.len() == 2 {
            return value.starts_with(parts[0]) && value.ends_with(parts[1]);
        }

        false
    }
}

// ============================================================================
// Password Hashing
// ============================================================================

/// PBKDF2 password hasher using SHA-256.
pub struct PBKDF2Hasher {
    iterations: u32,
}

impl PBKDF2Hasher {
    /// Create a new PBKDF2 hasher with the default 100,000 iterations.
    pub fn new() -> Self {
        Self {
            iterations: 100_000,
        }
    }

    /// Hash a password.
    pub fn hash(&self, password: &str) -> Result<String, AuthError> {
        let salt = random_bytes(32)?;
        let mut out = [0u8; 32];
        let iterations = NonZeroU32::new(self.iterations).unwrap();
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256,
            iterations,
            &salt,
            password.as_bytes(),
            &mut out,
        );

        Ok(format!(
            "pbkdf2_sha256${}${}${}",
            self.iterations,
            STANDARD.encode(&salt),
            STANDARD.encode(out)
        ))
    }

    /// Verify a password against a hash.
    pub fn verify(&self, password: &str, hashed: &str) -> Result<bool, AuthError> {
        let parts: Vec<&str> = hashed.split('$').collect();
        if parts.len() != 4 || parts[0] != "pbkdf2_sha256" {
            return Ok(false);
        }

        let iterations = u32::from_str(parts[1]).map_err(|_| AuthError::InvalidHashFormat)?;
        let salt = STANDARD.decode(parts[2])?;
        let stored = STANDARD.decode(parts[3])?;
        if stored.len() != 32 {
            return Ok(false);
        }

        let mut out = [0u8; 32];
        let iterations = NonZeroU32::new(iterations).unwrap();
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256,
            iterations,
            &salt,
            password.as_bytes(),
            &mut out,
        );

        Ok(bool::from(out.as_slice().ct_eq(stored.as_slice())))
    }
}

impl Default for PBKDF2Hasher {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Token Generators
// ============================================================================

/// Trait for token generators.
pub trait TokenGenerator: Send + Sync {
    /// Generate a token for the given user.
    fn generate(&self, user: &User, expires_in: i64) -> Result<Token, AuthError>;
    /// Verify and decode a token value.
    fn verify(&self, token_value: &str) -> Result<Option<Token>, AuthError>;
}

/// Simple JWT token generator using HMAC-SHA256.
pub struct SimpleJWTGenerator {
    key: hmac::Key,
}

impl SimpleJWTGenerator {
    /// Create a new JWT generator with the given secret.
    pub fn new(secret: &str) -> Self {
        Self {
            key: hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes()),
        }
    }
}

impl TokenGenerator for SimpleJWTGenerator {
    fn generate(&self, user: &User, expires_in: i64) -> Result<Token, AuthError> {
        let issued_at = SystemTime::now();
        let expires_at = if expires_in > 0 {
            issued_at + Duration::from_secs(expires_in as u64)
        } else {
            issued_at - Duration::from_secs(1)
        };

        let iat = issued_at.duration_since(UNIX_EPOCH)?.as_secs();
        let exp = expires_at.duration_since(UNIX_EPOCH)?.as_secs();

        let header = serde_json::json!({"alg": "HS256", "typ": "JWT"});
        let payload = serde_json::json!({
            "user_id": user.id,
            "username": user.username,
            "roles": user.roles.iter().collect::<Vec<_>>(),
            "permissions": user.permissions.iter().collect::<Vec<_>>(),
            "tenant_id": user.tenant_id,
            "iat": iat,
            "exp": exp,
        });

        let header_b64 = URL_SAFE_NO_PAD.encode(&serde_json::to_vec(&header)?);
        let payload_b64 = URL_SAFE_NO_PAD.encode(&serde_json::to_vec(&payload)?);

        let message = format!("{}.{}", header_b64, payload_b64);
        let signature = hmac::sign(&self.key, message.as_bytes());
        let signature_b64 = URL_SAFE_NO_PAD.encode(signature.as_ref());

        let token_value = format!("{}.{}", message, signature_b64);

        let mut metadata = HashMap::new();
        metadata.insert("username".to_string(), Value::String(user.username.clone()));
        metadata.insert(
            "roles".to_string(),
            Value::Array(
                user.roles
                    .iter()
                    .map(|s| Value::String(s.clone()))
                    .collect(),
            ),
        );
        metadata.insert(
            "permissions".to_string(),
            Value::Array(
                user.permissions
                    .iter()
                    .map(|s| Value::String(s.clone()))
                    .collect(),
            ),
        );
        if let Some(tenant) = &user.tenant_id {
            metadata.insert("tenant_id".to_string(), Value::String(tenant.clone()));
        }

        Ok(Token {
            value: token_value,
            token_type: TokenType::JWT,
            user_id: user.id.clone(),
            expires_at,
            issued_at,
            metadata,
        })
    }

    fn verify(&self, token_value: &str) -> Result<Option<Token>, AuthError> {
        let parts: Vec<&str> = token_value.split('.').collect();
        if parts.len() != 3 {
            return Ok(None);
        }

        let message = format!("{}.{}", parts[0], parts[1]);
        let signature = URL_SAFE_NO_PAD.decode(parts[2])?;
        if hmac::verify(&self.key, message.as_bytes(), &signature).is_err() {
            return Ok(None);
        }

        let payload_json = URL_SAFE_NO_PAD.decode(parts[1])?;
        let payload: Value = serde_json::from_slice(&payload_json)?;

        let user_id = payload
            .get("user_id")
            .and_then(Value::as_str)
            .ok_or_else(|| AuthError::MissingField("user_id".to_string()))?;
        let username = payload
            .get("username")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let tenant_id = payload
            .get("tenant_id")
            .and_then(Value::as_str)
            .map(String::from);

        let roles: HashSet<String> = payload
            .get("roles")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(Value::as_str)
                    .map(String::from)
                    .collect()
            })
            .unwrap_or_default();

        let permissions: HashSet<String> = payload
            .get("permissions")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(Value::as_str)
                    .map(String::from)
                    .collect()
            })
            .unwrap_or_default();

        let iat = payload
            .get("iat")
            .and_then(Value::as_u64)
            .ok_or_else(|| AuthError::MissingField("iat".to_string()))?;
        let exp = payload
            .get("exp")
            .and_then(Value::as_u64)
            .ok_or_else(|| AuthError::MissingField("exp".to_string()))?;

        let issued_at = UNIX_EPOCH + Duration::from_secs(iat);
        let expires_at = UNIX_EPOCH + Duration::from_secs(exp);

        if SystemTime::now() > expires_at {
            return Ok(None);
        }

        let mut metadata = HashMap::new();
        metadata.insert("username".to_string(), Value::String(username.clone()));
        metadata.insert(
            "roles".to_string(),
            Value::Array(roles.iter().map(|s| Value::String(s.clone())).collect()),
        );
        metadata.insert(
            "permissions".to_string(),
            Value::Array(
                permissions
                    .iter()
                    .map(|s| Value::String(s.clone()))
                    .collect(),
            ),
        );
        if let Some(tenant) = &tenant_id {
            metadata.insert("tenant_id".to_string(), Value::String(tenant.clone()));
        }

        Ok(Some(Token {
            value: token_value.to_string(),
            token_type: TokenType::JWT,
            user_id: user_id.to_string(),
            expires_at,
            issued_at,
            metadata,
        }))
    }
}

/// Opaque token generator with server-side storage.
pub struct OpaqueTokenGenerator {
    tokens: Mutex<HashMap<String, Token>>,
}

impl OpaqueTokenGenerator {
    /// Create a new opaque token generator.
    pub fn new() -> Self {
        Self {
            tokens: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for OpaqueTokenGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl TokenGenerator for OpaqueTokenGenerator {
    fn generate(&self, user: &User, expires_in: i64) -> Result<Token, AuthError> {
        let token_value = random_id(32)?;
        let issued_at = SystemTime::now();
        let expires_at = if expires_in > 0 {
            issued_at + Duration::from_secs(expires_in as u64)
        } else {
            issued_at - Duration::from_secs(1)
        };

        let mut metadata = HashMap::new();
        metadata.insert("username".to_string(), Value::String(user.username.clone()));
        metadata.insert(
            "roles".to_string(),
            Value::Array(
                user.roles
                    .iter()
                    .map(|s| Value::String(s.clone()))
                    .collect(),
            ),
        );
        metadata.insert(
            "permissions".to_string(),
            Value::Array(
                user.permissions
                    .iter()
                    .map(|s| Value::String(s.clone()))
                    .collect(),
            ),
        );
        if let Some(tenant) = &user.tenant_id {
            metadata.insert("tenant_id".to_string(), Value::String(tenant.clone()));
        }

        let token = Token {
            value: token_value.clone(),
            token_type: TokenType::Opaque,
            user_id: user.id.clone(),
            expires_at,
            issued_at,
            metadata,
        };

        self.tokens
            .lock()
            .unwrap()
            .insert(token_value, token.clone());
        Ok(token)
    }

    fn verify(&self, token_value: &str) -> Result<Option<Token>, AuthError> {
        let tokens = self.tokens.lock().unwrap();
        if let Some(token) = tokens.get(token_value) {
            if token.is_expired() {
                Ok(None)
            } else {
                Ok(Some(token.clone()))
            }
        } else {
            Ok(None)
        }
    }
}

impl OpaqueTokenGenerator {
    /// Revoke an opaque token.
    pub fn revoke(&self, token_value: &str) {
        self.tokens.lock().unwrap().remove(token_value);
    }
}

// ============================================================================
// Authentication Providers
// ============================================================================

/// Trait for authentication providers.
pub trait AuthProvider: Send + Sync {
    /// Authenticate a user with the given credentials.
    fn authenticate(
        &self,
        credentials: &HashMap<String, String>,
    ) -> Result<Option<User>, AuthError>;
}

struct LocalUserRecord {
    id: String,
    username: String,
    email: Option<String>,
    password: String,
    roles: HashSet<String>,
    permissions: HashSet<String>,
    tenant_id: Option<String>,
}

/// Local username/password authentication provider.
pub struct LocalAuthProvider {
    users: Mutex<HashMap<String, LocalUserRecord>>,
    password_hasher: PBKDF2Hasher,
}

impl LocalAuthProvider {
    /// Create a new local auth provider.
    pub fn new() -> Self {
        Self {
            users: Mutex::new(HashMap::new()),
            password_hasher: PBKDF2Hasher::new(),
        }
    }

    /// Register a new user.
    pub fn register_user(
        &self,
        username: &str,
        password: &str,
        email: Option<&str>,
        roles: Option<HashSet<String>>,
        permissions: Option<HashSet<String>>,
        tenant_id: Option<&str>,
    ) -> Result<User, AuthError> {
        let user_id = random_id(16)?;
        let hashed_password = self.password_hasher.hash(password)?;
        let roles = roles.unwrap_or_default();
        let permissions = permissions.unwrap_or_default();

        let record = LocalUserRecord {
            id: user_id.clone(),
            username: username.to_string(),
            email: email.map(|s| s.to_string()),
            password: hashed_password,
            roles: roles.clone(),
            permissions: permissions.clone(),
            tenant_id: tenant_id.map(|s| s.to_string()),
        };

        self.users
            .lock()
            .unwrap()
            .insert(username.to_string(), record);

        Ok(User {
            id: user_id,
            username: username.to_string(),
            email: email.map(|s| s.to_string()),
            roles,
            permissions,
            metadata: HashMap::new(),
            tenant_id: tenant_id.map(|s| s.to_string()),
        })
    }
}

impl Default for LocalAuthProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl AuthProvider for LocalAuthProvider {
    fn authenticate(
        &self,
        credentials: &HashMap<String, String>,
    ) -> Result<Option<User>, AuthError> {
        let username = credentials.get("username").cloned().unwrap_or_default();
        let password = credentials.get("password").cloned().unwrap_or_default();

        if username.is_empty() || password.is_empty() {
            return Ok(None);
        }

        let users = self.users.lock().unwrap();
        if let Some(record) = users.get(&username) {
            if !self.password_hasher.verify(&password, &record.password)? {
                return Ok(None);
            }

            Ok(Some(User {
                id: record.id.clone(),
                username: record.username.clone(),
                email: record.email.clone(),
                roles: record.roles.clone(),
                permissions: record.permissions.clone(),
                metadata: HashMap::new(),
                tenant_id: record.tenant_id.clone(),
            }))
        } else {
            Ok(None)
        }
    }
}

/// API key authentication provider.
pub struct APIKeyAuthProvider {
    api_keys: Mutex<HashMap<String, User>>,
}

impl APIKeyAuthProvider {
    /// Create a new API key provider.
    pub fn new() -> Self {
        Self {
            api_keys: Mutex::new(HashMap::new()),
        }
    }

    /// Create an API key for a user.
    pub fn create_api_key(&self, user: &User) -> Result<String, AuthError> {
        let key = format!("ak_{}", random_id(32)?);
        self.api_keys
            .lock()
            .unwrap()
            .insert(key.clone(), user.clone());
        Ok(key)
    }

    /// Revoke an API key.
    pub fn revoke_api_key(&self, api_key: &str) {
        self.api_keys.lock().unwrap().remove(api_key);
    }
}

impl Default for APIKeyAuthProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl AuthProvider for APIKeyAuthProvider {
    fn authenticate(
        &self,
        credentials: &HashMap<String, String>,
    ) -> Result<Option<User>, AuthError> {
        if let Some(api_key) = credentials.get("api_key") {
            Ok(self.api_keys.lock().unwrap().get(api_key).cloned())
        } else {
            Ok(None)
        }
    }
}

// ============================================================================
// Policy Engine
// ============================================================================

/// RBAC/ABAC policy engine.
pub struct PolicyEngine {
    rules: Mutex<Vec<PolicyRule>>,
    role_permissions: Mutex<HashMap<String, HashSet<String>>>,
}

impl PolicyEngine {
    /// Create a new policy engine.
    pub fn new() -> Self {
        Self {
            rules: Mutex::new(Vec::new()),
            role_permissions: Mutex::new(HashMap::new()),
        }
    }

    /// Add a policy rule.
    pub fn add_rule(&self, rule: PolicyRule) {
        self.rules.lock().unwrap().push(rule);
    }

    /// Add a permission to a role.
    pub fn add_role_permission(&self, role: &str, permission: &str) {
        let mut perms = self.role_permissions.lock().unwrap();
        perms
            .entry(role.to_string())
            .or_default()
            .insert(permission.to_string());
    }

    /// Check if a user is allowed to perform an action on a resource.
    pub fn check(
        &self,
        user: &User,
        action: &str,
        resource: &str,
        context: Option<&HashMap<String, String>>,
    ) -> bool {
        let permission = format!("{}:{}", action, resource);

        if user.has_permission(&permission) {
            return true;
        }

        let role_permissions = self.role_permissions.lock().unwrap().clone();
        for role in &user.roles {
            if let Some(perms) = role_permissions.get(role) {
                if perms.contains(&permission) || perms.contains(&format!("{}:*", action)) {
                    return true;
                }
            }
        }

        let rules = self.rules.lock().unwrap().clone();
        for rule in &rules {
            if rule.matches(
                &format!("user:{}", user.username),
                action,
                resource,
                context,
            ) {
                return rule.effect == "allow";
            }

            for role in &user.roles {
                if rule.matches(&format!("role:{}", role), action, resource, context) {
                    return rule.effect == "allow";
                }
            }

            if rule.matches("*", action, resource, context) {
                return rule.effect == "allow";
            }
        }

        false
    }
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Session Manager
// ============================================================================

/// Manages user sessions.
pub struct SessionManager {
    sessions: Mutex<HashMap<String, Session>>,
    default_ttl: i64,
}

impl SessionManager {
    /// Create a new session manager with the given default TTL in seconds.
    pub fn new(default_ttl: i64) -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            default_ttl,
        }
    }

    /// Create a new session.
    pub fn create_session(
        &self,
        user_id: &str,
        device_id: Option<&str>,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
        ttl: i64,
    ) -> Result<Session, AuthError> {
        let id = random_id(32)?;
        let now = SystemTime::now();
        let actual_ttl = if ttl == 0 { self.default_ttl } else { ttl };

        let expires_at = if actual_ttl <= 0 {
            Some(now - Duration::from_secs(1))
        } else {
            Some(now + Duration::from_secs(actual_ttl as u64))
        };

        let session = Session {
            id: id.clone(),
            user_id: user_id.to_string(),
            device_id: device_id.map(|s| s.to_string()),
            ip_address: ip_address.map(|s| s.to_string()),
            user_agent: user_agent.map(|s| s.to_string()),
            created_at: now,
            last_activity: now,
            expires_at,
            metadata: HashMap::new(),
        };

        self.sessions
            .lock()
            .unwrap()
            .insert(id.clone(), session.clone());
        Ok(session)
    }

    /// Get a session by ID, updating its last activity.
    pub fn get_session(&self, session_id: &str) -> Option<Session> {
        let mut sessions = self.sessions.lock().unwrap();
        if let Some(session) = sessions.get_mut(session_id) {
            if session.is_expired() {
                return None;
            }
            session.touch();
            return Some(session.clone());
        }
        None
    }

    /// Revoke a session by ID.
    pub fn revoke_session(&self, session_id: &str) {
        self.sessions.lock().unwrap().remove(session_id);
    }

    /// Revoke all sessions for a user.
    pub fn revoke_user_sessions(&self, user_id: &str) {
        let mut sessions = self.sessions.lock().unwrap();
        sessions.retain(|_, s| s.user_id != user_id);
    }

    /// Remove all expired sessions.
    pub fn cleanup_expired(&self) {
        let mut sessions = self.sessions.lock().unwrap();
        sessions.retain(|_, s| !s.is_expired());
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new(3600)
    }
}

// ============================================================================
// Main Auth Class
// ============================================================================

/// Result of a successful login.
#[derive(Debug, Clone)]
pub struct LoginResult {
    pub user: User,
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub session_id: Option<String>,
}

/// Result of a token refresh.
#[derive(Debug, Clone)]
pub struct RefreshResult {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
}

/// Main authentication and authorization framework.
pub struct Auth {
    providers: Mutex<HashMap<String, Box<dyn AuthProvider + Send + Sync>>>,
    token_generator: Mutex<Box<dyn TokenGenerator + Send + Sync>>,
    pub policy_engine: PolicyEngine,
    pub session_manager: SessionManager,
    revoked_tokens: Mutex<HashSet<String>>,
}

impl Auth {
    /// Create a new Auth instance.
    pub fn new(secret: &str, token_type: TokenType) -> Self {
        let token_generator: Box<dyn TokenGenerator + Send + Sync> = match token_type {
            TokenType::JWT => Box::new(SimpleJWTGenerator::new(secret)),
            _ => Box::new(OpaqueTokenGenerator::new()),
        };

        Self {
            providers: Mutex::new(HashMap::new()),
            token_generator: Mutex::new(token_generator),
            policy_engine: PolicyEngine::new(),
            session_manager: SessionManager::new(3600),
            revoked_tokens: Mutex::new(HashSet::new()),
        }
    }

    /// Add an authentication provider.
    pub fn add_provider(&self, name: &str, provider: Box<dyn AuthProvider + Send + Sync>) {
        self.providers
            .lock()
            .unwrap()
            .insert(name.to_string(), provider);
    }

    /// Authenticate a user using the specified provider.
    pub fn authenticate(
        &self,
        provider_name: &str,
        credentials: &HashMap<String, String>,
    ) -> Result<Option<User>, AuthError> {
        let providers = self.providers.lock().unwrap();
        let provider = providers
            .get(provider_name)
            .ok_or_else(|| AuthError::UnknownProvider(provider_name.to_string()))?;
        provider.authenticate(credentials)
    }

    /// Authenticate and create tokens and an optional session.
    pub fn login(
        &self,
        provider_name: &str,
        credentials: &HashMap<String, String>,
        create_session: bool,
        token_ttl: i64,
    ) -> Result<Option<LoginResult>, AuthError> {
        let user = match self.authenticate(provider_name, credentials)? {
            Some(u) => u,
            None => return Ok(None),
        };

        let access_token = {
            let generator = self.token_generator.lock().unwrap();
            generator.generate(&user, token_ttl)?
        };

        let refresh_token = {
            let generator = self.token_generator.lock().unwrap();
            generator.generate(&user, token_ttl * 24)?
        };

        let mut result = LoginResult {
            user,
            access_token: access_token.value,
            refresh_token: refresh_token.value,
            token_type: "Bearer".to_string(),
            expires_in: token_ttl,
            session_id: None,
        };

        if create_session {
            let session = self.session_manager.create_session(
                &result.user.id,
                credentials.get("device_id").map(|s| s.as_str()),
                credentials.get("ip_address").map(|s| s.as_str()),
                credentials.get("user_agent").map(|s| s.as_str()),
                0,
            )?;
            result.session_id = Some(session.id);
        }

        Ok(Some(result))
    }

    /// Verify a token, respecting the revocation list.
    pub fn verify_token(&self, token_value: &str) -> Result<Option<Token>, AuthError> {
        {
            let revoked = self.revoked_tokens.lock().unwrap();
            if revoked.contains(token_value) {
                return Ok(None);
            }
        }

        let generator = self.token_generator.lock().unwrap();
        generator.verify(token_value)
    }

    /// Revoke a token.
    pub fn revoke_token(&self, token_value: &str) {
        self.revoked_tokens
            .lock()
            .unwrap()
            .insert(token_value.to_string());
    }

    /// Refresh an access token using a refresh token.
    pub fn refresh_token(
        &self,
        refresh_token_value: &str,
        token_ttl: i64,
    ) -> Result<Option<RefreshResult>, AuthError> {
        let token = match self.verify_token(refresh_token_value)? {
            Some(t) => t,
            None => return Ok(None),
        };

        let username = token
            .metadata
            .get("username")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let tenant_id = token
            .metadata
            .get("tenant_id")
            .and_then(Value::as_str)
            .map(String::from);

        let roles: HashSet<String> = token
            .metadata
            .get("roles")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(Value::as_str)
                    .map(String::from)
                    .collect()
            })
            .unwrap_or_default();

        let permissions: HashSet<String> = token
            .metadata
            .get("permissions")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(Value::as_str)
                    .map(String::from)
                    .collect()
            })
            .unwrap_or_default();

        let user = User {
            id: token.user_id,
            username,
            email: None,
            roles,
            permissions,
            metadata: HashMap::new(),
            tenant_id,
        };

        let new_token = {
            let generator = self.token_generator.lock().unwrap();
            generator.generate(&user, token_ttl)?
        };

        Ok(Some(RefreshResult {
            access_token: new_token.value,
            token_type: "Bearer".to_string(),
            expires_in: token_ttl,
        }))
    }

    /// Check if a user has permission to perform an action on a resource.
    pub fn check_permission(
        &self,
        user: &User,
        action: &str,
        resource: &str,
        context: Option<&HashMap<String, String>>,
    ) -> bool {
        self.policy_engine.check(user, action, resource, context)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_creation_and_checks() {
        let user = User {
            id: "user123".to_string(),
            username: "alice".to_string(),
            email: Some("alice@example.com".to_string()),
            roles: HashSet::from(["admin".to_string(), "user".to_string()]),
            permissions: HashSet::from(["read:documents".to_string()]),
            metadata: HashMap::new(),
            tenant_id: Some("tenant1".to_string()),
        };

        assert_eq!(user.id, "user123");
        assert!(user.has_role("admin"));
        assert!(!user.has_role("viewer"));
        assert!(user.has_any_role(&["admin", "viewer"]));
        assert!(user.has_all_roles(&["admin", "user"]));
        assert!(!user.has_all_roles(&["admin", "viewer"]));
        assert!(user.has_permission("read:documents"));
        assert!(!user.has_permission("delete:documents"));
    }

    #[test]
    fn token_expiry() {
        let expired = Token {
            value: "token123".to_string(),
            token_type: TokenType::JWT,
            user_id: "user123".to_string(),
            expires_at: SystemTime::now() - Duration::from_secs(3600),
            issued_at: SystemTime::now() - Duration::from_secs(7200),
            metadata: HashMap::new(),
        };
        let valid = Token {
            value: "token456".to_string(),
            token_type: TokenType::JWT,
            user_id: "user123".to_string(),
            expires_at: SystemTime::now() + Duration::from_secs(3600),
            issued_at: SystemTime::now(),
            metadata: HashMap::new(),
        };

        assert!(expired.is_expired());
        assert!(!valid.is_expired());
    }

    #[test]
    fn session_expiry_and_touch() {
        let expired = Session {
            id: "session123".to_string(),
            user_id: "user123".to_string(),
            device_id: None,
            ip_address: None,
            user_agent: None,
            created_at: SystemTime::now() - Duration::from_secs(7200),
            last_activity: SystemTime::now() - Duration::from_secs(7200),
            expires_at: Some(SystemTime::now() - Duration::from_secs(3600)),
            metadata: HashMap::new(),
        };
        let mut valid = Session {
            id: "session456".to_string(),
            user_id: "user123".to_string(),
            device_id: None,
            ip_address: None,
            user_agent: None,
            created_at: SystemTime::now(),
            last_activity: SystemTime::now(),
            expires_at: Some(SystemTime::now() + Duration::from_secs(3600)),
            metadata: HashMap::new(),
        };

        assert!(expired.is_expired());
        assert!(!valid.is_expired());

        let original = valid.last_activity;
        std::thread::sleep(Duration::from_millis(10));
        valid.touch();
        assert!(valid.last_activity > original);
    }

    #[test]
    fn policy_rule_matching() {
        let rule = PolicyRule::new("user:alice", "read", "document:123");

        assert!(rule.matches("user:alice", "read", "document:123", None));
        assert!(!rule.matches("user:bob", "read", "document:123", None));
        assert!(!rule.matches("user:alice", "write", "document:123", None));
    }

    #[test]
    fn policy_rule_wildcard_and_conditions() {
        let rule = PolicyRule::new("role:admin", "*", "document:*");
        let mut conditions = HashMap::new();
        conditions.insert("tenant".to_string(), "tenant1".to_string());
        let rule2 = PolicyRule::new("user:alice", "read", "document:*").with_conditions(conditions);

        assert!(rule.matches("role:admin", "read", "document:123", None));
        assert!(rule.matches("role:admin", "write", "document:456", None));
        assert!(!rule.matches("role:user", "read", "document:123", None));

        let mut context = HashMap::new();
        context.insert("tenant".to_string(), "tenant1".to_string());
        assert!(rule2.matches("user:alice", "read", "document:123", Some(&context)));

        context.insert("tenant".to_string(), "tenant2".to_string());
        assert!(!rule2.matches("user:alice", "read", "document:123", Some(&context)));
    }

    #[test]
    fn pbkdf2_hasher() {
        let hasher = PBKDF2Hasher::new();
        let password = "secure_password_123";

        let hashed = hasher.hash(password).unwrap();
        assert!(hashed.starts_with("pbkdf2_sha256$"));
        assert!(hasher.verify(password, &hashed).unwrap());
        assert!(!hasher.verify("wrong_password", &hashed).unwrap());

        let hashed2 = hasher.hash(password).unwrap();
        assert_ne!(hashed, hashed2);
        assert!(hasher.verify(password, &hashed2).unwrap());
    }

    #[test]
    fn simple_jwt_generator() {
        let generator = SimpleJWTGenerator::new("test_secret_key");
        let mut user = User::new("user123", "alice");
        user.roles.insert("admin".to_string());

        let token = generator.generate(&user, 3600).unwrap();
        assert_eq!(token.token_type, TokenType::JWT);
        assert_eq!(token.user_id, "user123");
        assert!(!token.is_expired());

        let verified = generator.verify(&token.value).unwrap();
        assert!(verified.is_some());
        assert_eq!(verified.unwrap().user_id, "user123");
    }

    #[test]
    fn jwt_rejects_invalid_and_expired() {
        let generator = SimpleJWTGenerator::new("test_secret_key");

        assert!(generator.verify("invalid.token.here").unwrap().is_none());

        let user = User::new("user123", "alice");
        let token = generator.generate(&user, -1).unwrap();
        assert!(generator.verify(&token.value).unwrap().is_none());
    }

    #[test]
    fn opaque_token_generator() {
        let generator = OpaqueTokenGenerator::new();
        let user = User::new("user123", "alice");

        let token = generator.generate(&user, 3600).unwrap();
        assert_eq!(token.token_type, TokenType::Opaque);
        assert_eq!(token.user_id, "user123");

        let verified = generator.verify(&token.value).unwrap();
        assert!(verified.is_some());

        generator.revoke(&token.value);
        assert!(generator.verify(&token.value).unwrap().is_none());
    }

    #[test]
    fn local_auth_provider() {
        let provider = LocalAuthProvider::new();
        let roles = HashSet::from(["admin".to_string()]);
        let permissions = HashSet::from(["read:all".to_string()]);

        let user = provider
            .register_user(
                "alice",
                "secure_password",
                Some("alice@example.com"),
                Some(roles),
                Some(permissions),
                None,
            )
            .unwrap();
        assert_eq!(user.username, "alice");

        let mut creds = HashMap::new();
        creds.insert("username".to_string(), "alice".to_string());
        creds.insert("password".to_string(), "secure_password".to_string());

        let authenticated = provider.authenticate(&creds).unwrap();
        assert!(authenticated.is_some());
        assert_eq!(authenticated.unwrap().username, "alice");

        creds.insert("password".to_string(), "wrong_password".to_string());
        assert!(provider.authenticate(&creds).unwrap().is_none());

        creds.insert("username".to_string(), "bob".to_string());
        assert!(provider.authenticate(&creds).unwrap().is_none());
    }

    #[test]
    fn api_key_auth_provider() {
        let provider = APIKeyAuthProvider::new();
        let user = User::new("user123", "alice");

        let api_key = provider.create_api_key(&user).unwrap();
        assert!(api_key.starts_with("ak_"));

        let mut creds = HashMap::new();
        creds.insert("api_key".to_string(), api_key);
        assert!(provider.authenticate(&creds).unwrap().is_some());

        provider.revoke_api_key(creds.get("api_key").unwrap());
        assert!(provider.authenticate(&creds).unwrap().is_none());
    }

    #[test]
    fn policy_engine_checks() {
        let engine = PolicyEngine::new();

        let mut user = User::new("user123", "alice");
        user.permissions.insert("read:document:123".to_string());

        assert!(engine.check(&user, "read", "document:123", None));
        assert!(!engine.check(&user, "write", "document:123", None));

        engine.add_role_permission("admin", "read:*");
        user.roles.insert("admin".to_string());
        assert!(engine.check(&user, "read", "document:123", None));

        engine.add_rule(PolicyRule::new("user:alice", "write", "document:*"));
        assert!(engine.check(&user, "write", "document:123", None));

        engine.add_rule(PolicyRule::new("user:alice", "delete", "document:*").with_effect("deny"));
        assert!(!engine.check(&user, "delete", "document:123", None));
    }

    #[test]
    fn session_manager_lifecycle() {
        let manager = SessionManager::new(3600);

        let session = manager
            .create_session("user123", Some("device1"), Some("192.168.1.1"), None, 0)
            .unwrap();
        assert_eq!(session.user_id, "user123");

        let retrieved = manager.get_session(&session.id);
        assert!(retrieved.is_some());

        manager.revoke_session(&session.id);
        assert!(manager.get_session(&session.id).is_none());

        let s1 = manager
            .create_session("user123", None, None, None, 0)
            .unwrap();
        let s2 = manager
            .create_session("user123", None, None, None, 0)
            .unwrap();
        let s3 = manager
            .create_session("user456", None, None, None, 0)
            .unwrap();

        manager.revoke_user_sessions("user123");
        assert!(manager.get_session(&s1.id).is_none());
        assert!(manager.get_session(&s2.id).is_none());
        assert!(manager.get_session(&s3.id).is_some());

        let expired = manager
            .create_session("user123", None, None, None, -1)
            .unwrap();
        assert!(manager.get_session(&expired.id).is_none());
        manager.cleanup_expired();
    }

    #[test]
    fn auth_login_flow() {
        let auth = Auth::new("test_secret", TokenType::JWT);
        let provider = LocalAuthProvider::new();
        provider
            .register_user("alice", "secure_password", None, None, None, None)
            .unwrap();
        auth.add_provider("local", Box::new(provider));

        let mut creds = HashMap::new();
        creds.insert("username".to_string(), "alice".to_string());
        creds.insert("password".to_string(), "secure_password".to_string());

        let result = auth.login("local", &creds, true, 3600).unwrap();
        assert!(result.is_some());
        let result = result.unwrap();
        assert_eq!(result.user.username, "alice");
        assert!(!result.access_token.is_empty());
        assert!(!result.refresh_token.is_empty());
        assert!(result.session_id.is_some());
    }

    #[test]
    fn auth_token_verification_and_revocation() {
        let auth = Auth::new("test_secret", TokenType::JWT);
        let provider = LocalAuthProvider::new();
        provider
            .register_user("alice", "secure_password", None, None, None, None)
            .unwrap();
        auth.add_provider("local", Box::new(provider));

        let mut creds = HashMap::new();
        creds.insert("username".to_string(), "alice".to_string());
        creds.insert("password".to_string(), "secure_password".to_string());

        let result = auth.login("local", &creds, false, 3600).unwrap().unwrap();
        let token = auth.verify_token(&result.access_token).unwrap();
        assert!(token.is_some());

        auth.revoke_token(&result.access_token);
        assert!(auth.verify_token(&result.access_token).unwrap().is_none());
    }

    #[test]
    fn auth_refresh_token() {
        let auth = Auth::new("test_secret", TokenType::JWT);
        let provider = LocalAuthProvider::new();
        provider
            .register_user("alice", "secure_password", None, None, None, None)
            .unwrap();
        auth.add_provider("local", Box::new(provider));

        let mut creds = HashMap::new();
        creds.insert("username".to_string(), "alice".to_string());
        creds.insert("password".to_string(), "secure_password".to_string());

        let result = auth.login("local", &creds, false, 3600).unwrap().unwrap();

        std::thread::sleep(Duration::from_secs(1));
        let new_tokens = auth.refresh_token(&result.refresh_token, 3600).unwrap();
        assert!(new_tokens.is_some());
        let new_tokens = new_tokens.unwrap();
        assert!(!new_tokens.access_token.is_empty());
        assert_ne!(new_tokens.access_token, result.access_token);
    }

    #[test]
    fn auth_check_permission() {
        let auth = Auth::new("test_secret", TokenType::JWT);
        auth.policy_engine.add_role_permission("admin", "read:*");

        let mut user = User::new("user123", "alice");
        user.roles.insert("admin".to_string());

        assert!(auth.check_permission(&user, "read", "document:123", None));
        assert!(!auth.check_permission(&user, "write", "document:123", None));
    }

    #[test]
    fn auth_opaque_tokens() {
        let auth = Auth::new("test_secret", TokenType::Opaque);
        let provider = LocalAuthProvider::new();
        provider
            .register_user("alice", "secure_password", None, None, None, None)
            .unwrap();
        auth.add_provider("local", Box::new(provider));

        let mut creds = HashMap::new();
        creds.insert("username".to_string(), "alice".to_string());
        creds.insert("password".to_string(), "secure_password".to_string());

        let result = auth.login("local", &creds, false, 3600).unwrap().unwrap();
        let token = auth.verify_token(&result.access_token).unwrap();
        assert!(token.is_some());
        assert_eq!(token.unwrap().token_type, TokenType::Opaque);
    }
}
