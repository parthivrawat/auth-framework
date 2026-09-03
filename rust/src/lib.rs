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
use std::sync::{Arc, Mutex};
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
    InvalidSecret,
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
            AuthError::InvalidSecret => write!(f, "invalid secret"),
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
// Storage Backend
// ============================================================================

/// Pluggable key/value storage backend for tokens, sessions, and revocation.
pub trait StorageBackend: Send + Sync {
    /// Get the value for a key, if it exists.
    fn get(&self, key: &str) -> Option<String>;
    /// Store a value under a key.
    fn set(&self, key: &str, value: String) -> bool;
    /// Delete a key and its value.
    fn delete(&self, key: &str) -> bool;
    /// Check if a key exists.
    fn has(&self, key: &str) -> bool;
    /// Return all keys matching the given prefix.
    fn keys(&self, prefix: &str) -> Vec<String>;
    /// Remove all stored data.
    fn clear(&self);
}

/// In-memory storage backend backed by a `Mutex<HashMap>`.
pub struct InMemoryStorage {
    data: Mutex<HashMap<String, String>>,
}

impl InMemoryStorage {
    /// Create a new empty in-memory storage backend.
    pub fn new() -> Self {
        Self {
            data: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for InMemoryStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl StorageBackend for InMemoryStorage {
    fn get(&self, key: &str) -> Option<String> {
        self.data.lock().unwrap().get(key).cloned()
    }

    fn set(&self, key: &str, value: String) -> bool {
        self.data.lock().unwrap().insert(key.to_string(), value);
        true
    }

    fn delete(&self, key: &str) -> bool {
        self.data.lock().unwrap().remove(key).is_some()
    }

    fn has(&self, key: &str) -> bool {
        self.data.lock().unwrap().contains_key(key)
    }

    fn keys(&self, prefix: &str) -> Vec<String> {
        self.data
            .lock()
            .unwrap()
            .keys()
            .filter(|k| k.starts_with(prefix))
            .cloned()
            .collect()
    }

    fn clear(&self) {
        self.data.lock().unwrap().clear();
    }
}

fn storage_revoked_key(token_value: &str) -> String {
    format!("revoked:{}", token_value)
}

fn storage_token_key(token_value: &str) -> String {
    format!("opaque:{}", token_value)
}

fn storage_session_key(session_id: &str) -> String {
    format!("session:{}", session_id)
}

fn storage_user_sessions_key(user_id: &str) -> String {
    format!("user_sessions:{}", user_id)
}

fn storage_refresh_family_key(family_id: &str) -> String {
    format!("refresh_family:{}", family_id)
}

fn storage_refresh_token_key(token_value: &str) -> String {
    format!("refresh:{}", token_value)
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
        let p: Vec<char> = pattern.chars().collect();
        let s: Vec<char> = value.chars().collect();
        let (mut pi, mut si) = (0usize, 0usize);
        let (mut star_pi, mut star_si) = (None::<usize>, None::<usize>);

        while si < s.len() {
            if pi < p.len() && (p[pi] == s[si] || p[pi] == '?') {
                pi += 1;
                si += 1;
            } else if pi < p.len() && p[pi] == '*' {
                star_pi = Some(pi);
                star_si = Some(si);
                pi += 1;
            } else if let (Some(sp), Some(ss)) = (star_pi, star_si) {
                pi = sp + 1;
                star_si = Some(ss + 1);
                si = ss + 1;
            } else {
                return false;
            }
        }

        while pi < p.len() && p[pi] == '*' {
            pi += 1;
        }

        pi == p.len()
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
    /// Generate a refresh token for the given user and family.
    fn generate_refresh(
        &self,
        user: &User,
        expires_in: i64,
        family_id: &str,
    ) -> Result<Token, AuthError> {
        let mut token = self.generate(user, expires_in)?;
        token.token_type = TokenType::Refresh;
        token
            .metadata
            .insert("fid".to_string(), Value::String(family_id.to_string()));
        Ok(token)
    }
    /// Verify and decode a token value.
    fn verify(&self, token_value: &str) -> Result<Option<Token>, AuthError>;
    /// Revoke a token value.
    fn revoke(&self, token_value: &str);
    /// Check whether a token value has been revoked.
    fn is_revoked(&self, token_value: &str) -> bool;
}

/// Simple JWT token generator using HMAC-SHA256.
pub struct SimpleJWTGenerator {
    key: hmac::Key,
    issuer: Option<String>,
    audience: Option<String>,
    key_id: Option<String>,
    expected_issuer: Option<String>,
    expected_audience: Option<String>,
    allowed_algorithms: Vec<String>,
    storage: Arc<Mutex<dyn StorageBackend + Send + Sync>>,
}

impl SimpleJWTGenerator {
    /// Create a new JWT generator with the given secret.
    pub fn new(secret: &str) -> Self {
        Self {
            key: hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes()),
            issuer: None,
            audience: None,
            key_id: None,
            expected_issuer: None,
            expected_audience: None,
            allowed_algorithms: vec!["HS256".to_string()],
            storage: Arc::new(Mutex::new(InMemoryStorage::new())),
        }
    }

    /// Use a custom storage backend.
    pub fn with_storage(mut self, storage: Arc<Mutex<dyn StorageBackend + Send + Sync>>) -> Self {
        self.storage = storage;
        self
    }

    /// Set the token issuer.
    pub fn with_issuer(mut self, issuer: &str) -> Self {
        self.issuer = Some(issuer.to_string());
        self
    }

    /// Set the token audience.
    pub fn with_audience(mut self, audience: &str) -> Self {
        self.audience = Some(audience.to_string());
        self
    }

    /// Set the key ID for the token header.
    pub fn with_key_id(mut self, key_id: &str) -> Self {
        self.key_id = Some(key_id.to_string());
        self
    }

    /// Set the expected issuer for verification.
    pub fn with_expected_issuer(mut self, issuer: &str) -> Self {
        self.expected_issuer = Some(issuer.to_string());
        self
    }

    /// Set the expected audience for verification.
    pub fn with_expected_audience(mut self, audience: &str) -> Self {
        self.expected_audience = Some(audience.to_string());
        self
    }

    /// Set the allowed signing algorithms.
    pub fn with_allowed_algorithms(mut self, algorithms: Vec<String>) -> Self {
        self.allowed_algorithms = algorithms;
        self
    }
}

impl SimpleJWTGenerator {
    fn generate_jwt(
        &self,
        user: &User,
        expires_in: i64,
        token_type: TokenType,
        family_id: Option<&str>,
    ) -> Result<Token, AuthError> {
        let issued_at = SystemTime::now();
        let expires_at = if expires_in > 0 {
            issued_at + Duration::from_secs(expires_in as u64)
        } else {
            issued_at - Duration::from_secs(1)
        };

        let iat = issued_at.duration_since(UNIX_EPOCH)?.as_secs();
        let exp = expires_at.duration_since(UNIX_EPOCH)?.as_secs();

        let jti = random_id(16)?;

        let mut header = serde_json::json!({"alg": "HS256", "typ": "JWT"});
        if let Some(kid) = &self.key_id {
            header["kid"] = serde_json::Value::String(kid.clone());
        }

        let type_str = match token_type {
            TokenType::JWT => "JWT",
            TokenType::Opaque => "Opaque",
            TokenType::Refresh => "Refresh",
        };

        let mut payload = serde_json::json!({
            "user_id": user.id,
            "username": user.username,
            "roles": user.roles.iter().collect::<Vec<_>>(),
            "permissions": user.permissions.iter().collect::<Vec<_>>(),
            "tenant_id": user.tenant_id,
            "jti": jti,
            "iat": iat,
            "exp": exp,
            "token_type": type_str,
        });
        if let Some(iss) = &self.issuer {
            payload["iss"] = serde_json::Value::String(iss.clone());
        }
        if let Some(aud) = &self.audience {
            payload["aud"] = serde_json::Value::String(aud.clone());
        }
        if let Some(fid) = family_id {
            payload["fid"] = serde_json::Value::String(fid.to_string());
        }

        let header_b64 = URL_SAFE_NO_PAD.encode(&serde_json::to_vec(&header)?);
        let payload_b64 = URL_SAFE_NO_PAD.encode(&serde_json::to_vec(&payload)?);

        let message = format!("{}.{}", header_b64, payload_b64);
        let signature = hmac::sign(&self.key, message.as_bytes());
        let signature_b64 = URL_SAFE_NO_PAD.encode(signature.as_ref());

        let token_value = format!("{}.{}", message, signature_b64);

        let mut metadata = HashMap::new();
        metadata.insert("username".to_string(), Value::String(user.username.clone()));
        metadata.insert("jti".to_string(), Value::String(jti.clone()));
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
        if let Some(fid) = family_id {
            metadata.insert("fid".to_string(), Value::String(fid.to_string()));
        }

        Ok(Token {
            value: token_value,
            token_type,
            user_id: user.id.clone(),
            expires_at,
            issued_at,
            metadata,
        })
    }

    fn extract_family_id(&self, token_value: &str) -> Option<String> {
        let parts: Vec<&str> = token_value.split('.').collect();
        if parts.len() != 3 {
            return None;
        }
        let payload_json = URL_SAFE_NO_PAD.decode(parts[1]).ok()?;
        let payload: Value = serde_json::from_slice(&payload_json).ok()?;
        payload.get("fid").and_then(Value::as_str).map(String::from)
    }

    fn revoke_family(&self, family_id: &str) {
        let storage = self.storage.lock().unwrap();
        let family_key = storage_refresh_family_key(family_id);
        storage.delete(&family_key);
        for key in storage.keys("refresh:") {
            if let Some(json) = storage.get(&key) {
                if let Ok(v) = serde_json::from_str::<Value>(&json) {
                    if v.get("metadata")
                        .and_then(|m| m.get("fid"))
                        .and_then(Value::as_str)
                        == Some(family_id)
                    {
                        storage.delete(&key);
                    }
                }
            }
        }
    }
}

impl TokenGenerator for SimpleJWTGenerator {
    fn generate(&self, user: &User, expires_in: i64) -> Result<Token, AuthError> {
        self.generate_jwt(user, expires_in, TokenType::JWT, None)
    }

    fn generate_refresh(
        &self,
        user: &User,
        expires_in: i64,
        family_id: &str,
    ) -> Result<Token, AuthError> {
        self.generate_jwt(user, expires_in, TokenType::Refresh, Some(family_id))
    }

    fn verify(&self, token_value: &str) -> Result<Option<Token>, AuthError> {
        let parts: Vec<&str> = token_value.split('.').collect();
        if parts.len() != 3 {
            return Ok(None);
        }

        // Decode and validate header
        let header_json = match URL_SAFE_NO_PAD.decode(parts[0]) {
            Ok(v) => v,
            Err(_) => return Ok(None),
        };
        let header: Value = match serde_json::from_slice(&header_json) {
            Ok(v) => v,
            Err(_) => return Ok(None),
        };
        let alg = header
            .get("alg")
            .and_then(Value::as_str)
            .ok_or_else(|| AuthError::InvalidToken)?;
        if !self.allowed_algorithms.iter().any(|a| a == alg) {
            return Ok(None);
        }
        if let Some(expected_kid) = &self.key_id {
            let kid = header.get("kid").and_then(Value::as_str).unwrap_or("");
            if kid != expected_kid {
                return Ok(None);
            }
        }

        let message = format!("{}.{}", parts[0], parts[1]);
        let signature = match URL_SAFE_NO_PAD.decode(parts[2]) {
            Ok(v) => v,
            Err(_) => return Ok(None),
        };
        if hmac::verify(&self.key, message.as_bytes(), &signature).is_err() {
            return Ok(None);
        }

        let payload_json = match URL_SAFE_NO_PAD.decode(parts[1]) {
            Ok(v) => v,
            Err(_) => return Ok(None),
        };
        let payload: Value = match serde_json::from_slice(&payload_json) {
            Ok(v) => v,
            Err(_) => return Ok(None),
        };

        if let Some(expected_iss) = &self.expected_issuer {
            if payload.get("iss").and_then(Value::as_str) != Some(expected_iss) {
                return Ok(None);
            }
        }
        if let Some(expected_aud) = &self.expected_audience {
            if payload.get("aud").and_then(Value::as_str) != Some(expected_aud) {
                return Ok(None);
            }
        }
        if payload.get("jti").and_then(Value::as_str).is_none() {
            return Ok(None);
        }

        let token_type = match payload.get("token_type").and_then(Value::as_str) {
            Some("Refresh") => TokenType::Refresh,
            _ => TokenType::JWT,
        };

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

        let family_id = payload
            .get("fid")
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
            "jti".to_string(),
            Value::String(
                payload
                    .get("jti")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
            ),
        );
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
        if let Some(fid) = &family_id {
            metadata.insert("fid".to_string(), Value::String(fid.clone()));
        }

        Ok(Some(Token {
            value: token_value.to_string(),
            token_type,
            user_id: user_id.to_string(),
            expires_at,
            issued_at,
            metadata,
        }))
    }

    fn revoke(&self, token_value: &str) {
        self.storage
            .lock()
            .unwrap()
            .set(&storage_revoked_key(token_value), "revoked".to_string());
        if let Some(fid) = self.extract_family_id(token_value) {
            self.revoke_family(&fid);
        }
    }

    fn is_revoked(&self, token_value: &str) -> bool {
        self.storage
            .lock()
            .unwrap()
            .has(&storage_revoked_key(token_value))
    }
}

fn token_to_json(token: &Token) -> Result<String, AuthError> {
    let token_type = match token.token_type {
        TokenType::JWT => "JWT",
        TokenType::Opaque => "Opaque",
        TokenType::Refresh => "Refresh",
    };
    let expires_at = token.expires_at.duration_since(UNIX_EPOCH)?.as_secs();
    let issued_at = token.issued_at.duration_since(UNIX_EPOCH)?.as_secs();
    let metadata = Value::Object(token.metadata.clone().into_iter().collect());
    let value = serde_json::json!({
        "value": token.value,
        "token_type": token_type,
        "user_id": token.user_id,
        "expires_at": expires_at,
        "issued_at": issued_at,
        "metadata": metadata,
    });
    Ok(serde_json::to_string(&value)?)
}

fn token_from_json(token_value: &str, s: &str) -> Result<Option<Token>, AuthError> {
    let v: Value = serde_json::from_str(s)?;
    let token_type = match v["token_type"].as_str() {
        Some("JWT") => TokenType::JWT,
        Some("Opaque") => TokenType::Opaque,
        Some("Refresh") => TokenType::Refresh,
        _ => return Ok(None),
    };
    let user_id = v["user_id"].as_str().unwrap_or("").to_string();
    let expires_at = v["expires_at"]
        .as_u64()
        .map(|t| UNIX_EPOCH + Duration::from_secs(t))
        .unwrap_or(UNIX_EPOCH);
    let issued_at = v["issued_at"]
        .as_u64()
        .map(|t| UNIX_EPOCH + Duration::from_secs(t))
        .unwrap_or(UNIX_EPOCH);
    let metadata = v["metadata"]
        .as_object()
        .map(|o| o.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
        .unwrap_or_default();

    if SystemTime::now() > expires_at {
        return Ok(None);
    }

    Ok(Some(Token {
        value: token_value.to_string(),
        token_type,
        user_id,
        expires_at,
        issued_at,
        metadata,
    }))
}

/// Opaque token generator with server-side storage.
pub struct OpaqueTokenGenerator {
    storage: Arc<Mutex<dyn StorageBackend + Send + Sync>>,
}

impl OpaqueTokenGenerator {
    /// Create a new opaque token generator.
    pub fn new() -> Self {
        Self {
            storage: Arc::new(Mutex::new(InMemoryStorage::new())),
        }
    }

    /// Use a custom storage backend.
    pub fn with_storage(mut self, storage: Arc<Mutex<dyn StorageBackend + Send + Sync>>) -> Self {
        self.storage = storage;
        self
    }

    fn generate_opaque(
        &self,
        user: &User,
        expires_in: i64,
        token_type: TokenType,
        family_id: Option<&str>,
    ) -> Result<Token, AuthError> {
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
        if let Some(fid) = family_id {
            metadata.insert("fid".to_string(), Value::String(fid.to_string()));
        }

        let token = Token {
            value: token_value.clone(),
            token_type,
            user_id: user.id.clone(),
            expires_at,
            issued_at,
            metadata,
        };

        let json = token_to_json(&token)?;
        let key = match token_type {
            TokenType::Refresh => storage_refresh_token_key(&token_value),
            _ => storage_token_key(&token_value),
        };
        self.storage.lock().unwrap().set(&key, json);
        Ok(token)
    }
}

impl Default for OpaqueTokenGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl TokenGenerator for OpaqueTokenGenerator {
    fn generate(&self, user: &User, expires_in: i64) -> Result<Token, AuthError> {
        self.generate_opaque(user, expires_in, TokenType::Opaque, None)
    }

    fn generate_refresh(
        &self,
        user: &User,
        expires_in: i64,
        family_id: &str,
    ) -> Result<Token, AuthError> {
        self.generate_opaque(user, expires_in, TokenType::Refresh, Some(family_id))
    }

    fn verify(&self, token_value: &str) -> Result<Option<Token>, AuthError> {
        if self.is_revoked(token_value) {
            return Ok(None);
        }
        let storage = self.storage.lock().unwrap();
        if let Some(s) = storage.get(&storage_token_key(token_value)) {
            drop(storage);
            return token_from_json(token_value, &s);
        }
        if let Some(s) = storage.get(&storage_refresh_token_key(token_value)) {
            drop(storage);
            return token_from_json(token_value, &s);
        }
        Ok(None)
    }

    fn revoke(&self, token_value: &str) {
        let storage = self.storage.lock().unwrap();
        storage.set(&storage_revoked_key(token_value), "revoked".to_string());

        if let Some(s) = storage.get(&storage_refresh_token_key(token_value)) {
            if let Ok(v) = serde_json::from_str::<Value>(&s) {
                if let Some(fid) = v
                    .get("metadata")
                    .and_then(|m| m.get("fid"))
                    .and_then(Value::as_str)
                {
                    storage.delete(&storage_refresh_family_key(fid));
                    for key in storage.keys("refresh:") {
                        if let Some(json) = storage.get(&key) {
                            if let Ok(v2) = serde_json::from_str::<Value>(&json) {
                                if v2.get("metadata")
                                    .and_then(|m| m.get("fid"))
                                    .and_then(Value::as_str)
                                    == Some(fid)
                                {
                                    storage.delete(&key);
                                }
                            }
                        }
                    }
                }
            }
            storage.delete(&storage_refresh_token_key(token_value));
        }
        storage.delete(&storage_token_key(token_value));
    }

    fn is_revoked(&self, token_value: &str) -> bool {
        self.storage
            .lock()
            .unwrap()
            .has(&storage_revoked_key(token_value))
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
        roles: Option<&HashSet<String>>,
        permissions: Option<&HashSet<String>>,
        tenant_id: Option<&str>,
    ) -> Result<User, AuthError> {
        let user_id = random_id(16)?;
        let hashed_password = self.password_hasher.hash(password)?;
        let roles = roles.cloned().unwrap_or_default();
        let permissions = permissions.cloned().unwrap_or_default();

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
        let rules = self.rules.lock().unwrap().clone();

        let matches_rule = |rule: &PolicyRule| -> bool {
            if rule.matches(&format!("user:{}", user.username), action, resource, context) {
                return true;
            }
            for role in &user.roles {
                if rule.matches(&format!("role:{}", role), action, resource, context) {
                    return true;
                }
            }
            rule.matches("*", action, resource, context)
        };

        // First pass: explicit deny rules override everything
        for rule in &rules {
            if matches_rule(rule) && rule.effect == "deny" {
                return false;
            }
        }

        // Direct permissions
        let permission = format!("{}:{}", action, resource);
        if user.has_permission(&permission) {
            return true;
        }

        // Role-based permissions
        let role_permissions = self.role_permissions.lock().unwrap().clone();
        for role in &user.roles {
            if let Some(perms) = role_permissions.get(role) {
                if perms.contains(&permission) || perms.contains(&format!("{}:*", action)) {
                    return true;
                }
            }
        }

        // Second pass: allow rules
        for rule in &rules {
            if matches_rule(rule) && rule.effect == "allow" {
                return true;
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

fn session_to_json(session: &Session) -> Result<String, AuthError> {
    let created_at = session.created_at.duration_since(UNIX_EPOCH)?.as_secs();
    let last_activity = session.last_activity.duration_since(UNIX_EPOCH)?.as_secs();
    let expires_value = if let Some(exp) = session.expires_at {
        let secs = exp.duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        serde_json::json!(secs)
    } else {
        serde_json::Value::Null
    };
    let metadata = Value::Object(session.metadata.clone().into_iter().collect());
    let value = serde_json::json!({
        "id": session.id,
        "user_id": session.user_id,
        "device_id": session.device_id,
        "ip_address": session.ip_address,
        "user_agent": session.user_agent,
        "created_at": created_at,
        "last_activity": last_activity,
        "expires_at": expires_value,
        "metadata": metadata,
    });
    Ok(serde_json::to_string(&value)?)
}

fn session_from_json(s: &str) -> Option<Session> {
    let v: Value = serde_json::from_str(s).ok()?;
    let id = v["id"].as_str()?.to_string();
    let user_id = v["user_id"].as_str()?.to_string();
    let device_id = v["device_id"].as_str().map(String::from);
    let ip_address = v["ip_address"].as_str().map(String::from);
    let user_agent = v["user_agent"].as_str().map(String::from);
    let created_at = v["created_at"]
        .as_u64()
        .map(|t| UNIX_EPOCH + Duration::from_secs(t))?;
    let last_activity = v["last_activity"]
        .as_u64()
        .map(|t| UNIX_EPOCH + Duration::from_secs(t))?;
    let expires_at = if v["expires_at"].is_null() {
        None
    } else {
        v["expires_at"].as_u64().map(|t| UNIX_EPOCH + Duration::from_secs(t))
    };
    let metadata = v["metadata"]
        .as_object()
        .map(|o| o.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
        .unwrap_or_default();
    Some(Session {
        id,
        user_id,
        device_id,
        ip_address,
        user_agent,
        created_at,
        last_activity,
        expires_at,
        metadata,
    })
}

/// Manages user sessions.
pub struct SessionManager {
    storage: Arc<Mutex<dyn StorageBackend + Send + Sync>>,
    default_ttl: i64,
}

impl SessionManager {
    /// Create a new session manager with the given default TTL in seconds.
    pub fn new(default_ttl: i64) -> Self {
        Self {
            storage: Arc::new(Mutex::new(InMemoryStorage::new())),
            default_ttl,
        }
    }

    /// Create a new session manager with the given storage backend.
    pub fn new_with_storage(
        default_ttl: i64,
        storage: Arc<Mutex<dyn StorageBackend + Send + Sync>>,
    ) -> Self {
        Self { storage, default_ttl }
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

        let json = session_to_json(&session)?;
        self.storage
            .lock()
            .unwrap()
            .set(&storage_session_key(&id), json);

        let index_key = storage_user_sessions_key(user_id);
        let list_str = self
            .storage
            .lock()
            .unwrap()
            .get(&index_key)
            .unwrap_or_else(|| "[]".to_string());
        let mut list: Vec<String> = serde_json::from_str(&list_str).unwrap_or_default();
        list.push(id.clone());
        self.storage
            .lock()
            .unwrap()
            .set(&index_key, serde_json::to_string(&list).unwrap());

        Ok(session)
    }

    /// Get a session by ID, updating its last activity.
    pub fn get_session(&self, session_id: &str) -> Option<Session> {
        let s = self
            .storage
            .lock()
            .unwrap()
            .get(&storage_session_key(session_id))?;
        let mut session = session_from_json(&s)?;
        if session.is_expired() {
            return None;
        }
        session.touch();
        let json = session_to_json(&session).ok()?;
        self.storage
            .lock()
            .unwrap()
            .set(&storage_session_key(session_id), json);
        Some(session)
    }

    /// Revoke a session by ID.
    pub fn revoke_session(&self, session_id: &str) {
        let key = storage_session_key(session_id);
        let session_json = self.storage.lock().unwrap().get(&key);
        if let Some(s) = session_json {
            if let Ok(v) = serde_json::from_str::<Value>(&s) {
                if let Some(user_id) = v["user_id"].as_str() {
                    let index_key = storage_user_sessions_key(user_id);
                    let list_str = self.storage.lock().unwrap().get(&index_key);
                    if let Some(list_str) = list_str {
                        if let Ok(list) = serde_json::from_str::<Vec<String>>(&list_str) {
                            let updated: Vec<String> =
                                list.into_iter().filter(|x| x != session_id).collect();
                            if updated.is_empty() {
                                self.storage.lock().unwrap().delete(&index_key);
                            } else {
                                self.storage.lock().unwrap().set(
                                    &index_key,
                                    serde_json::to_string(&updated).unwrap(),
                                );
                            }
                        }
                    }
                }
            }
        }
        self.storage.lock().unwrap().delete(&key);
    }

    /// Revoke all sessions for a user.
    pub fn revoke_user_sessions(&self, user_id: &str) {
        let index_key = storage_user_sessions_key(user_id);
        let list_str = self.storage.lock().unwrap().get(&index_key);
        if let Some(list_str) = list_str {
            if let Ok(list) = serde_json::from_str::<Vec<String>>(&list_str) {
                for id in list {
                    self.storage
                        .lock()
                        .unwrap()
                        .delete(&storage_session_key(&id));
                }
            }
        }
        self.storage.lock().unwrap().delete(&index_key);
    }

    /// Remove all expired sessions.
    pub fn cleanup_expired(&self) {
        let keys = self.storage.lock().unwrap().keys("session:");
        for key in keys {
            let s = self.storage.lock().unwrap().get(&key);
            if let Some(s) = s {
                if let Some(session) = session_from_json(&s) {
                    if session.is_expired() {
                        if let Ok(v) = serde_json::from_str::<Value>(&s) {
                            if let Some(user_id) = v["user_id"].as_str() {
                                let index_key = storage_user_sessions_key(user_id);
                                let list_str = self.storage.lock().unwrap().get(&index_key);
                                if let Some(list_str) = list_str {
                                    if let Ok(list) =
                                        serde_json::from_str::<Vec<String>>(&list_str)
                                    {
                                        let updated: Vec<String> = list
                                            .into_iter()
                                            .filter(|x| x != session.id.as_str())
                                            .collect();
                                        if updated.is_empty() {
                                            self.storage.lock().unwrap().delete(&index_key);
                                        } else {
                                            self.storage.lock().unwrap().set(
                                                &index_key,
                                                serde_json::to_string(&updated).unwrap(),
                                            );
                                        }
                                    }
                                }
                            }
                        }
                        self.storage.lock().unwrap().delete(&key);
                    }
                }
            }
        }
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
    pub family_id: Option<String>,
}

/// Result of a token refresh.
#[derive(Debug, Clone)]
pub struct RefreshResult {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
}

/// Configuration for an Auth instance.
pub struct AuthConfig {
    pub issuer: Option<String>,
    pub audience: Option<String>,
    pub key_id: Option<String>,
    pub allowed_algorithms: Vec<String>,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            issuer: None,
            audience: None,
            key_id: None,
            allowed_algorithms: vec!["HS256".to_string()],
        }
    }
}

/// Main authentication and authorization framework.
pub struct Auth {
    providers: Mutex<HashMap<String, Box<dyn AuthProvider + Send + Sync>>>,
    token_generator: Mutex<Box<dyn TokenGenerator + Send + Sync>>,
    storage: Arc<Mutex<dyn StorageBackend + Send + Sync>>,
    pub policy_engine: PolicyEngine,
    pub session_manager: SessionManager,
}

impl Auth {
    /// Create a new Auth instance with default configuration.
    pub fn new(
        secret: &str,
        token_type: TokenType,
        storage: Option<Arc<Mutex<dyn StorageBackend + Send + Sync>>>,
    ) -> Result<Self, AuthError> {
        Self::new_with_config(secret, token_type, AuthConfig::default(), storage)
    }

    /// Create a new Auth instance with the provided configuration.
    pub fn new_with_config(
        secret: &str,
        token_type: TokenType,
        config: AuthConfig,
        storage: Option<Arc<Mutex<dyn StorageBackend + Send + Sync>>>,
    ) -> Result<Self, AuthError> {
        if secret.is_empty() {
            return Err(AuthError::InvalidSecret);
        }

        let storage =
            storage.unwrap_or_else(|| Arc::new(Mutex::new(InMemoryStorage::new())));

        let token_generator: Box<dyn TokenGenerator + Send + Sync> = match token_type {
            TokenType::JWT => {
                let mut g = SimpleJWTGenerator::new(secret)
                    .with_allowed_algorithms(config.allowed_algorithms.clone())
                    .with_storage(storage.clone());
                if let Some(iss) = &config.issuer {
                    g = g.with_issuer(iss).with_expected_issuer(iss);
                }
                if let Some(aud) = &config.audience {
                    g = g.with_audience(aud).with_expected_audience(aud);
                }
                if let Some(kid) = &config.key_id {
                    g = g.with_key_id(kid);
                }
                Box::new(g)
            }
            _ => Box::new(OpaqueTokenGenerator::new().with_storage(storage.clone())),
        };
        let session_manager = SessionManager::new_with_storage(3600, storage.clone());

        Ok(Self {
            providers: Mutex::new(HashMap::new()),
            token_generator: Mutex::new(token_generator),
            storage,
            policy_engine: PolicyEngine::new(),
            session_manager,
        })
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
        ttl: i64,
    ) -> Result<Option<LoginResult>, AuthError> {
        let user = match self.authenticate(provider_name, credentials)? {
            Some(u) => u,
            None => return Ok(None),
        };

        let family_id = random_id(16)?;
        let (access_token, refresh_token) = {
            let generator = self.token_generator.lock().unwrap();
            let access = generator.generate(&user, ttl)?;
            let refresh = generator.generate_refresh(&user, ttl * 24, &family_id)?;
            (access, refresh)
        };

        self.storage.lock().unwrap().set(
            &storage_refresh_family_key(&family_id),
            refresh_token.value.clone(),
        );

        let mut result = LoginResult {
            user,
            access_token: access_token.value,
            refresh_token: refresh_token.value,
            token_type: "Bearer".to_string(),
            expires_in: ttl,
            session_id: None,
            family_id: Some(family_id),
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
        let generator = self.token_generator.lock().unwrap();
        if generator.is_revoked(token_value) {
            return Ok(None);
        }
        generator.verify(token_value)
    }

    /// Revoke a token.
    pub fn revoke_token(&self, token_value: &str) {
        let generator = self.token_generator.lock().unwrap();
        generator.revoke(token_value);
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

    /// Refresh an access token using a refresh token, with rotation and
    /// reuse detection.
    pub fn refresh_tokens(
        &self,
        refresh_token_value: &str,
    ) -> Result<Option<LoginResult>, AuthError> {
        let token = match self.verify_token(refresh_token_value)? {
            Some(t) => t,
            None => return Ok(None),
        };

        if token.token_type != TokenType::Refresh {
            return Ok(None);
        }

        let family_id = token
            .metadata
            .get("fid")
            .and_then(Value::as_str)
            .ok_or(AuthError::InvalidToken)?
            .to_string();

        let active = self
            .storage
            .lock()
            .unwrap()
            .get(&storage_refresh_family_key(&family_id));
        if active.as_deref() != Some(refresh_token_value) {
            self.revoke_token(refresh_token_value);
            return Err(AuthError::InvalidToken);
        }

        self.revoke_token(refresh_token_value);

        let refresh_ttl = token
            .expires_at
            .duration_since(token.issued_at)
            .map_err(|_| AuthError::TimeError)?
            .as_secs() as i64;
        let access_ttl = if refresh_ttl > 0 {
            (refresh_ttl / 24).max(1)
        } else {
            3600
        };
        let new_refresh_ttl = access_ttl * 24;

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

        let (new_access, new_refresh) = {
            let generator = self.token_generator.lock().unwrap();
            let access = generator.generate(&user, access_ttl)?;
            let refresh = generator.generate_refresh(&user, new_refresh_ttl, &family_id)?;
            (access, refresh)
        };

        self.storage.lock().unwrap().set(
            &storage_refresh_family_key(&family_id),
            new_refresh.value.clone(),
        );

        Ok(Some(LoginResult {
            user,
            access_token: new_access.value,
            refresh_token: new_refresh.value,
            token_type: "Bearer".to_string(),
            expires_in: access_ttl,
            session_id: None,
            family_id: Some(family_id),
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
                Some(&roles),
                Some(&permissions),
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
        let auth = Auth::new("test_secret", TokenType::JWT, None).unwrap();
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
        let auth = Auth::new("test_secret", TokenType::JWT, None).unwrap();
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
        let auth = Auth::new("test_secret", TokenType::JWT, None).unwrap();
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
        let auth = Auth::new("test_secret", TokenType::JWT, None).unwrap();
        auth.policy_engine.add_role_permission("admin", "read:*");

        let mut user = User::new("user123", "alice");
        user.roles.insert("admin".to_string());

        assert!(auth.check_permission(&user, "read", "document:123", None));
        assert!(!auth.check_permission(&user, "write", "document:123", None));
    }

    #[test]
    fn auth_opaque_tokens() {
        let auth = Auth::new("test_secret", TokenType::Opaque, None).unwrap();
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
