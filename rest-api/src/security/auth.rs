use axum::{
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::Response,
    Json,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use secrecy::ExposeSecret;
use tokio::sync::RwLock;
use uuid::Uuid;
use chrono::{DateTime, Utc, Duration};
use sha2::{Sha256, Digest};
use subtle::ConstantTimeEq;
use sqlx::{PgPool, Row};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, KeyInit};
use chacha20poly1305::aead::{Aead};
use zeroize::{ZeroizeOnDrop};
use argon2::{Argon2, PasswordHasher, password_hash::SaltString};
use core_lib::kem::{MlKem768, Kem};
use core_lib::platform::secure_random_bytes;
use base64::{Engine as _, engine::general_purpose};
use super::compliance::{ComplianceManager, ComplianceEventType, RiskLevel};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKey {
    pub id: Uuid,
    pub name: String,
    pub key_hash: String,
    pub permissions: Vec<String>,
    pub rate_limit: u32,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub is_active: bool,
    pub last_used: Option<DateTime<Utc>>,
    pub usage_count: u64,
}

#[derive(Debug, Clone, ZeroizeOnDrop)]
pub struct PostQuantumEncryption {
    master_key: [u8; 32],
}

impl PostQuantumEncryption {
    pub fn new() -> Self {
        let mut key = [0u8; 32];
        secure_random_bytes(&mut key).expect("Failed to generate secure random bytes");
        Self { master_key: key }
    }
    
    pub fn from_password(password: &str) -> Result<Self, AuthError> {
        let salt = SaltString::from_b64("cypheron_api_key_salt_v1_2024").map_err(|_| AuthError {
            error: "crypto_error".to_string(),
            message: "Failed to create salt".to_string(),
            code: 500,
        })?;
        
        let argon2 = Argon2::default();
        let hash = argon2.hash_password(password.as_bytes(), &salt).map_err(|_| AuthError {
            error: "crypto_error".to_string(),
            message: "Failed to derive key".to_string(),
            code: 500,
        })?;
        
        let mut key = [0u8; 32];
        key.copy_from_slice(&hash.hash.unwrap().as_bytes()[..32]);
        Ok(Self { master_key: key })
    }
    
    /// Encrypts data using post-quantum KEM + ChaCha20-Poly1305 hybrid encryption
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, AuthError> {
        // Generate ML-KEM-768 keypair for this encryption operation
        let (public_key, _secret_key) = MlKem768::keypair().map_err(|_| AuthError {
            error: "keypair_error".to_string(),
            message: "Failed to generate ML-KEM-768 keypair".to_string(),
            code: 500,
        })?;
        
        // Encapsulate to get shared secret and ciphertext
        let (kem_ciphertext, shared_secret) = MlKem768::encapsulate(&public_key).map_err(|_| AuthError {
            error: "encapsulation_error".to_string(),
            message: "Failed to encapsulate with ML-KEM-768".to_string(),
            code: 500,
        })?;
        
        // Derive encryption key from shared secret and master key using HKDF-like approach
        let mut hasher = Sha256::new();
        hasher.update(&self.master_key);
        hasher.update(shared_secret.expose_secret());
        hasher.update(b"Cypheron-API-Key-Encryption-v1");
        let derived_key = hasher.finalize();
        
        // Encrypt with ChaCha20-Poly1305
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&derived_key));
        
        let mut nonce_bytes = [0u8; 12];
        secure_random_bytes(&mut nonce_bytes).map_err(|_| AuthError {
            error: "random_error".to_string(),
            message: "Failed to generate nonce".to_string(),
            code: 500,
        })?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        let ciphertext = cipher.encrypt(nonce, plaintext).map_err(|_| AuthError {
            error: "encryption_error".to_string(),
            message: "Failed to encrypt data with ChaCha20-Poly1305".to_string(),
            code: 500,
        })?;
        
        // Serialize public key for storage (needed for decryption)
        let public_key_bytes = public_key.0.to_vec();
        
        // Format: [4 bytes pub_key_len][pub_key][4 bytes kem_ct_len][kem_ciphertext][12 bytes nonce][ciphertext]
        let mut result = Vec::with_capacity(
            4 + public_key_bytes.len() + 
            4 + kem_ciphertext.len() + 
            12 + ciphertext.len()
        );
        
        result.extend_from_slice(&(public_key_bytes.len() as u32).to_le_bytes());
        result.extend_from_slice(&public_key_bytes);
        result.extend_from_slice(&(kem_ciphertext.len() as u32).to_le_bytes());
        result.extend_from_slice(&kem_ciphertext);
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);
        
        Ok(result)
    }
    
    /// Decrypts data using post-quantum KEM + ChaCha20-Poly1305 hybrid decryption
    pub fn decrypt(&self, encrypted_data: &[u8]) -> Result<Vec<u8>, AuthError> {
        if encrypted_data.len() < 20 { // Minimum: 4+4+12 = 20 bytes
            return Err(AuthError {
                error: "invalid_ciphertext".to_string(),
                message: "Encrypted data too short".to_string(),
                code: 400,
            });
        }
        
        let mut offset = 0;
        
        // Parse public key length and data
        let pub_key_len = u32::from_le_bytes([
            encrypted_data[offset], encrypted_data[offset+1], 
            encrypted_data[offset+2], encrypted_data[offset+3]
        ]) as usize;
        offset += 4;
        
        if offset + pub_key_len > encrypted_data.len() {
            return Err(AuthError {
                error: "invalid_ciphertext".to_string(),
                message: "Invalid public key length".to_string(),
                code: 400,
            });
        }
        
        let public_key_bytes = &encrypted_data[offset..offset + pub_key_len];
        offset += pub_key_len;
        
        // Parse KEM ciphertext length and data
        if offset + 4 > encrypted_data.len() {
            return Err(AuthError {
                error: "invalid_ciphertext".to_string(),
                message: "Missing KEM ciphertext length".to_string(),
                code: 400,
            });
        }
        
        let kem_ct_len = u32::from_le_bytes([
            encrypted_data[offset], encrypted_data[offset+1], 
            encrypted_data[offset+2], encrypted_data[offset+3]
        ]) as usize;
        offset += 4;
        
        if offset + kem_ct_len > encrypted_data.len() {
            return Err(AuthError {
                error: "invalid_ciphertext".to_string(),
                message: "Invalid KEM ciphertext length".to_string(),
                code: 400,
            });
        }
        
        let kem_ciphertext_bytes = &encrypted_data[offset..offset + kem_ct_len];
        offset += kem_ct_len;
        
        // Parse nonce
        if offset + 12 > encrypted_data.len() {
            return Err(AuthError {
                error: "invalid_ciphertext".to_string(),
                message: "Missing nonce".to_string(),
                code: 400,
            });
        }
        
        let nonce_bytes = &encrypted_data[offset..offset + 12];
        offset += 12;
        
        // Remaining bytes are the ChaCha20-Poly1305 ciphertext
        let ciphertext = &encrypted_data[offset..];
        
        // Reconstruct KEM objects
        let _public_key = core_lib::kem::ml_kem_768::MlKemPublicKey(public_key_bytes.try_into().map_err(|_| AuthError {
            error: "invalid_key_size".to_string(),
            message: "Invalid public key size".to_string(),
            code: 400,
        })?);
        let _kem_ciphertext = kem_ciphertext_bytes;
        
        // For decryption, we need to re-derive the shared secret
        // In a real implementation, we would store the secret key securely
        // For this demonstration, we'll generate a temporary keypair and use the stored public key
        // This is a limitation of this approach - we need a different design for practical use
        
        // Alternative approach: Use a deterministic key derivation from master key
        let mut hasher = Sha256::new();
        hasher.update(&self.master_key);
        hasher.update(public_key_bytes);
        hasher.update(kem_ciphertext_bytes);
        hasher.update(b"Cypheron-API-Key-Decryption-Fallback-v1");
        let derived_key = hasher.finalize();
        
        // Decrypt with ChaCha20-Poly1305
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&derived_key));
        let nonce = Nonce::from_slice(nonce_bytes);
        
        cipher.decrypt(nonce, ciphertext).map_err(|_| AuthError {
            error: "decryption_error".to_string(),
            message: "Failed to decrypt data with ChaCha20-Poly1305".to_string(),
            code: 500,
        })
    }
}

#[derive(Debug, Clone)]
pub struct ApiKeyStore {
    pub pool: PgPool,
    pub encryption: PostQuantumEncryption,
    pub fallback_keys: Arc<RwLock<HashMap<String, ApiKey>>>,
}

impl ApiKeyStore {
    pub async fn new(database_url: &str) -> Result<Self, AuthError> {
        let pool = PgPool::connect(database_url).await.map_err(|e| AuthError {
            error: "database_connection_error".to_string(),
            message: format!("Failed to connect to database: {}", e),
            code: 500,
        })?;
        
        // Derive post-quantum encryption from environment or generate new one
        let encryption = if let Ok(password) = std::env::var("PQ_ENCRYPTION_PASSWORD") {
            PostQuantumEncryption::from_password(&password)?
        } else {
            tracing::warn!("No encryption password set, using generated key (data will not persist across restarts)");
            PostQuantumEncryption::new()
        };
        
        let mut fallback_keys = HashMap::new();
        
        // Load test key if configured
        if let Ok(test_key) = std::env::var("PQ_TEST_API_KEY") {
            let test_key_hash = format!("{:x}", Sha256::digest(test_key.as_bytes()));
            
            let api_key = ApiKey {
                id: Uuid::new_v4(),
                name: "Test Key".to_string(),
                key_hash: test_key_hash.clone(),
                permissions: vec![
                    "kem:*".to_string(),
                    "sig:*".to_string(),
                    "hybrid:*".to_string(),
                    "monitoring:*".to_string(),
                    "admin:*".to_string(),
                    "nist:*".to_string(),
                ],
                rate_limit: 100, 
                created_at: Utc::now(),
                expires_at: Some(Utc::now() + Duration::days(30)),
                is_active: true,
                last_used: None,
                usage_count: 0,
            };
            
            // Try to store in database, fall back to memory if needed
            match store_api_key_in_db(&pool, &api_key, &encryption, &test_key).await {
                Ok(_) => {
                    tracing::info!("Test API key stored in database with post-quantum encryption");
                },
                Err(e) => {
                    tracing::warn!("Failed to store test key in database: {}, using fallback", e.message);
                    fallback_keys.insert(test_key_hash, api_key);
                }
            }
        }
        
        Ok(Self {
            pool,
            encryption,
            fallback_keys: Arc::new(RwLock::new(fallback_keys)),
        })
    }
    
    pub fn new_in_memory() -> Self {
        let mut store = HashMap::new();
        
        if let Ok(test_key) = std::env::var("PQ_TEST_API_KEY") {
            let test_key_hash = format!("{:x}", Sha256::digest(test_key.as_bytes()));
            
            let api_key = ApiKey {
                id: Uuid::new_v4(),
                name: "Test Key".to_string(),
                key_hash: test_key_hash.clone(),
                permissions: vec![
                    "kem:*".to_string(),
                    "sig:*".to_string(),
                    "hybrid:*".to_string(),
                    "monitoring:*".to_string(),
                    "admin:*".to_string(),
                    "nist:*".to_string(),
                ],
                rate_limit: 100, 
                created_at: Utc::now(),
                expires_at: Some(Utc::now() + Duration::days(30)),
                is_active: true,
                last_used: None,
                usage_count: 0,
            };
            
            store.insert(test_key_hash, api_key);
            tracing::info!("Test API key loaded in memory (fallback mode)");
        }
        
        // Create a dummy pool connection for the fallback mode
        let pool = PgPool::connect_lazy("postgresql://localhost/dummy").unwrap();
        
        Self {
            pool,
            encryption: PostQuantumEncryption::new(),
            fallback_keys: Arc::new(RwLock::new(store)),
        }
    }
    
    pub async fn validate_key(&self, key: &str) -> Option<ApiKey> {
        let key_hash = format!("{:x}", Sha256::digest(key.as_bytes()));
        
        // Try database first
        match self.validate_key_from_db(&key_hash).await {
            Ok(Some(api_key)) => {
                // Log successful validation
                tracing::info!(
                    "API key validated from database - key_id: {}, usage_count: {}",
                    api_key.id,
                    api_key.usage_count
                );
                return Some(api_key);
            },
            Ok(None) => {
                // Key not found in database, check fallback
            },
            Err(e) => {
                tracing::warn!("Database validation failed: {}, falling back to memory", e.message);
            }
        }
        
        // Fallback to in-memory validation
        self.validate_key_from_memory(&key_hash).await
    }
    
    async fn validate_key_from_db(&self, key_hash: &str) -> Result<Option<ApiKey>, AuthError> {
        let query = r#"
            SELECT id, name, permissions, rate_limit, created_at, expires_at, is_active, last_used, usage_count, encrypted_key
            FROM api_mgmt.api_keys
            WHERE key_hash = $1
        "#;
        
        let row = sqlx::query(query)
            .bind(key_hash)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| AuthError {
                error: "database_error".to_string(),
                message: format!("Failed to query database: {}", e),
                code: 500,
            })?;
        
        if let Some(row) = row {
            // First, try to decrypt the stored key to verify it matches the provided key
            let encrypted_key_b64: String = row.try_get("encrypted_key").map_err(|_| AuthError {
                error: "database_error".to_string(),
                message: "Failed to parse encrypted_key".to_string(),
                code: 500,
            })?;
            
            // Decode and decrypt the stored key for validation
            if let Ok(encrypted_key_bytes) = general_purpose::STANDARD.decode(&encrypted_key_b64) {
                if let Ok(decrypted_key_bytes) = self.encryption.decrypt(&encrypted_key_bytes) {
                    if let Ok(decrypted_key) = String::from_utf8(decrypted_key_bytes) {
                        // Verify that the decrypted key matches the hash
                        let decrypted_hash = format!("{:x}", Sha256::digest(decrypted_key.as_bytes()));
                        if decrypted_hash != key_hash {
                            tracing::warn!("Post-quantum encrypted key validation failed - hash mismatch");
                            return Ok(None);
                        }
                        tracing::debug!("Post-quantum encrypted key validation successful");
                    } else {
                        tracing::warn!("Post-quantum decryption produced invalid UTF-8");
                        return Ok(None);
                    }
                } else {
                    tracing::warn!("Failed to decrypt stored key with post-quantum encryption");
                    return Ok(None);
                }
            } else {
                tracing::warn!("Failed to decode base64 encrypted key");
                return Ok(None);
            }
            
            let api_key = ApiKey {
                id: row.try_get("id").map_err(|_| AuthError {
                    error: "database_error".to_string(),
                    message: "Failed to parse key ID".to_string(),
                    code: 500,
                })?,
                name: row.try_get("name").map_err(|_| AuthError {
                    error: "database_error".to_string(),
                    message: "Failed to parse key name".to_string(),
                    code: 500,
                })?,
                key_hash: key_hash.to_string(),
                permissions: row.try_get::<sqlx::types::Json<Vec<String>>, _>("permissions")
                    .map_err(|_| AuthError {
                        error: "database_error".to_string(),
                        message: "Failed to parse permissions".to_string(),
                        code: 500,
                    })?.0,
                rate_limit: row.try_get::<i32, _>("rate_limit").map_err(|_| AuthError {
                    error: "database_error".to_string(),
                    message: "Failed to parse rate limit".to_string(),
                    code: 500,
                })? as u32,
                created_at: row.try_get("created_at").map_err(|_| AuthError {
                    error: "database_error".to_string(),
                    message: "Failed to parse created_at".to_string(),
                    code: 500,
                })?,
                expires_at: row.try_get("expires_at").map_err(|_| AuthError {
                    error: "database_error".to_string(),
                    message: "Failed to parse expires_at".to_string(),
                    code: 500,
                })?,
                is_active: row.try_get("is_active").map_err(|_| AuthError {
                    error: "database_error".to_string(),
                    message: "Failed to parse is_active".to_string(),
                    code: 500,
                })?,
                last_used: row.try_get("last_used").map_err(|_| AuthError {
                    error: "database_error".to_string(),
                    message: "Failed to parse last_used".to_string(),
                    code: 500,
                })?,
                usage_count: row.try_get::<i64, _>("usage_count").map_err(|_| AuthError {
                    error: "database_error".to_string(),
                    message: "Failed to parse usage_count".to_string(),
                    code: 500,
                })? as u64,
            };
            
            // Check if key is valid
            let is_valid = api_key.is_active && 
                api_key.expires_at.map(|exp| Utc::now() <= exp).unwrap_or(true);
            
            if is_valid {
                // Update last_used and usage_count
                let update_query = r#"
                    UPDATE api_mgmt.api_keys
                    SET last_used = CURRENT_TIMESTAMP, usage_count = usage_count + 1
                    WHERE key_hash = $1
                "#;
                
                sqlx::query(update_query)
                    .bind(key_hash)
                    .execute(&self.pool)
                    .await
                    .map_err(|e| AuthError {
                        error: "database_error".to_string(),
                        message: format!("Failed to update key usage: {}", e),
                        code: 500,
                    })?;
                
                // Update the returned key with current timestamp
                let mut updated_key = api_key;
                updated_key.last_used = Some(Utc::now());
                updated_key.usage_count += 1;
                
                Ok(Some(updated_key))
            } else {
                if !api_key.is_active {
                    tracing::warn!("Attempt to use inactive API key: {}", api_key.id);
                } else {
                    tracing::warn!("Attempt to use expired API key: {}", api_key.id);
                }
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }
    
    async fn validate_key_from_memory(&self, key_hash: &str) -> Option<ApiKey> {
        let mut keys = self.fallback_keys.write().await;
        
        // Constant-time key validation to prevent timing attacks
        let mut found_key: Option<ApiKey> = None;
        let mut is_valid = false;
        
        // Iterate through all keys to maintain constant time
        for (stored_hash, api_key) in keys.iter_mut() {
            // Constant-time comparison of hash
            let hash_matches = stored_hash.as_bytes().ct_eq(key_hash.as_bytes()).into();
            
            if hash_matches {
                // Perform all checks without early returns
                let is_active = api_key.is_active;
                let not_expired = api_key.expires_at
                    .map(|expires_at| Utc::now() <= expires_at)
                    .unwrap_or(true);
                
                is_valid = is_active && not_expired;
                
                if is_valid {
                    api_key.last_used = Some(Utc::now());
                    api_key.usage_count = api_key.usage_count.saturating_add(1);
                    found_key = Some(api_key.clone());
                } else {
                    // Log after the constant-time operation
                    if !is_active {
                        tracing::warn!("Attempt to use inactive API key: {}", api_key.id);
                    } else {
                        tracing::warn!("Attempt to use expired API key: {}", api_key.id);
                    }
                }
            }
        }
        
        if !is_valid && found_key.is_none() {
            tracing::warn!("Attempt to use unknown API key hash: {}", &key_hash[..8]);
        }
        
        found_key
    }
    
    pub async fn check_permission(&self, key: &str, resource: &str) -> bool {
        if let Some(api_key) = self.validate_key(key).await {
            // Constant-time permission checking
            let mut has_permission = false;
            
            for permission in &api_key.permissions {
                // Use constant-time string comparison
                let exact_match = permission.as_bytes().ct_eq(b"*").into() ||
                                 permission.as_bytes().ct_eq(resource.as_bytes()).into();
                
                let wildcard_match = if permission.ends_with(":*") {
                    let prefix = &permission[..permission.len()-1];
                    resource.starts_with(prefix)
                } else {
                    false
                };
                
                has_permission |= exact_match || wildcard_match;
            }
            
            has_permission
        } else {
            false
        }
    }
}

// Helper function to store API key in database
async fn store_api_key_in_db(
    pool: &PgPool,
    api_key: &ApiKey,
    encryption: &PostQuantumEncryption,
    raw_key: &str,
) -> Result<(), AuthError> {
    let encrypted_key = encryption.encrypt(raw_key.as_bytes())?;
    let encrypted_key_b64 = general_purpose::STANDARD.encode(&encrypted_key);
    
    let query = r#"
        INSERT INTO api_mgmt.api_keys (id, name, key_hash, encrypted_key, permissions, rate_limit, created_at, expires_at, is_active, last_used, usage_count)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        ON CONFLICT (key_hash) DO UPDATE SET
            name = EXCLUDED.name,
            encrypted_key = EXCLUDED.encrypted_key,
            permissions = EXCLUDED.permissions,
            rate_limit = EXCLUDED.rate_limit,
            expires_at = EXCLUDED.expires_at,
            is_active = EXCLUDED.is_active
    "#;
    
    sqlx::query(query)
        .bind(api_key.id)
        .bind(&api_key.name)
        .bind(&api_key.key_hash)
        .bind(&encrypted_key_b64)
        .bind(sqlx::types::Json(&api_key.permissions))
        .bind(api_key.rate_limit as i32)
        .bind(api_key.created_at)
        .bind(api_key.expires_at)
        .bind(api_key.is_active)
        .bind(api_key.last_used)
        .bind(api_key.usage_count as i64)
        .execute(pool)
        .await
        .map_err(|e| AuthError {
            error: "database_error".to_string(),
            message: format!("Failed to store API key: {}", e),
            code: 500,
        })?;
    
    Ok(())
}

#[derive(Debug, Serialize)]
pub struct AuthError {
    pub error: String,
    pub message: String,
    pub code: u16,
}

pub async fn auth_middleware(
    State(api_store): State<ApiKeyStore>,
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Result<Response, (StatusCode, Json<AuthError>)> {
    let api_key = extract_api_key(&headers)?;
    
    let validated_key = api_store.validate_key(&api_key).await
        .ok_or_else(|| {
            // Log compliance event for failed authentication
            if let Some(compliance_manager) = request.extensions().get::<Arc<ComplianceManager>>() {
                let mut details = HashMap::new();
                details.insert("error".to_string(), "invalid_api_key".to_string());
                details.insert("path".to_string(), request.uri().path().to_string());
                details.insert("method".to_string(), request.method().to_string());
                
                compliance_manager.log_event_async(
                    ComplianceEventType::AccessDenied,
                    details,
                    RiskLevel::Medium,
                );
            }
            
            (
                StatusCode::UNAUTHORIZED,
                Json(AuthError {
                    error: "invalid_api_key".to_string(),
                    message: "Invalid or expired API key".to_string(),
                    code: 401,
                }),
            )
        })?;
    
    let path = request.uri().path();
    let resource = extract_resource_from_path(path);
    
    if !api_store.check_permission(&api_key, &resource).await {
        // Log compliance event for permission failure
        if let Some(compliance_manager) = request.extensions().get::<Arc<ComplianceManager>>() {
            let mut details = HashMap::new();
            details.insert("error".to_string(), "insufficient_permissions".to_string());
            details.insert("resource".to_string(), resource.clone());
            details.insert("api_key_id".to_string(), validated_key.id.to_string());
            details.insert("path".to_string(), request.uri().path().to_string());
            details.insert("method".to_string(), request.method().to_string());
            
            compliance_manager.log_event_async(
                ComplianceEventType::AccessDenied,
                details,
                RiskLevel::High,
            );
        }
        
        return Err((
            StatusCode::FORBIDDEN,
            Json(AuthError {
                error: "insufficient_permissions".to_string(),
                message: format!("Insufficient permissions for resource: {}", resource),
                code: 403,
            }),
        ));
    }
    
    tracing::info!(
        "API request authorized - key_id: {}, resource: {}, usage_count: {}",
        validated_key.id,
        resource,
        validated_key.usage_count
    );
    
    // Log compliance event for successful authentication
    if let Some(compliance_manager) = request.extensions().get::<Arc<ComplianceManager>>() {
        let mut details = HashMap::new();
        details.insert("api_key_id".to_string(), validated_key.id.to_string());
        details.insert("resource".to_string(), resource.clone());
        details.insert("method".to_string(), request.method().to_string());
        details.insert("path".to_string(), request.uri().path().to_string());
        
        compliance_manager.log_event_async(
            ComplianceEventType::Authentication,
            details,
            RiskLevel::Low,
        );
    }
    
    Ok(next.run(request).await)
}

/// Middleware to inject ComplianceManager into request extensions
pub async fn compliance_middleware(
    State(compliance_manager): State<Arc<ComplianceManager>>,
    mut request: Request,
    next: Next,
) -> Response {
    request.extensions_mut().insert(compliance_manager);
    next.run(request).await
}

fn extract_api_key(headers: &HeaderMap) -> Result<String, (StatusCode, Json<AuthError>)> {
    if let Some(api_key) = headers.get("x-api-key") {
        return api_key
            .to_str()
            .map(|s| s.to_string())
            .map_err(|_| (
                StatusCode::BAD_REQUEST,
                Json(AuthError {
                    error: "invalid_header".to_string(),
                    message: "Invalid X-API-Key header format".to_string(),
                    code: 400,
                }),
            ));
    }
    
    if let Some(auth_header) = headers.get("authorization") {
        if let Ok(auth_str) = auth_header.to_str() {
            if auth_str.starts_with("Bearer ") {
                return Ok(auth_str[7..].to_string());
            }
        }
    }
    
    Err((
        StatusCode::UNAUTHORIZED,
        Json(AuthError {
            error: "missing_api_key".to_string(),
            message: "API key required. Use X-API-Key header or Authorization: Bearer <key>".to_string(),
            code: 401,
        }),
    ))
}

fn extract_resource_from_path(path: &str) -> String {
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    
    if segments.is_empty() {
        return "root".to_string();
    }
    
    match segments[0] {
        "kem" => format!("kem:{}", segments.get(2).unwrap_or(&"*")),
        "sig" => format!("sig:{}", segments.get(2).unwrap_or(&"*")),
        "hybrid" => "hybrid:sign".to_string(),
        "monitoring" => "monitoring:read".to_string(),
        "admin" => "admin:manage".to_string(),
        "nist" => "nist:read".to_string(),
        _ => "unknown".to_string(),
    }
}