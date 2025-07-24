use super::compliance::{ComplianceEventType, ComplianceManager, RiskLevel};
use argon2::{password_hash::SaltString, Argon2, PasswordHasher};
use axum::{
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::Response,
    Json,
};
use base64::{engine::general_purpose, Engine as _};
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
use chrono::{DateTime, Duration, Utc};
use core_lib::kem::{Kem, MlKem768};
use core_lib::platform::secure_random_bytes;
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;
use tokio::sync::{Mutex, RwLock};
use uuid::Uuid;
use zeroize::ZeroizeOnDrop;
use reqwest::Client;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use ring::rand::SystemRandom;
use rsa::{RsaPrivateKey, pkcs1::DecodeRsaPrivateKey, pkcs8::DecodePrivateKey};
use serde_json::Value as JsonValue;

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

pub struct PostQuantumEncryption {
    master_key: [u8; 32],
    kem_public_key: core_lib::kem::ml_kem_768::MlKemPublicKey,
    kem_secret_key: core_lib::kem::ml_kem_768::MlKemSecretKey,
}

impl std::fmt::Debug for PostQuantumEncryption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PostQuantumEncryption")
            .field("master_key", &"[REDACTED]")
            .field("kem_public_key", &"[REDACTED]")
            .field("kem_secret_key", &"[REDACTED]")
            .finish()
    }
}

impl Clone for PostQuantumEncryption {
    fn clone(&self) -> Self {
        // For security reasons, generate a new keypair rather than cloning the secret key
        let key = self.master_key;
        let (kem_public_key, kem_secret_key) = MlKem768::keypair()
            .expect("Failed to generate ML-KEM-768 keypair for clone");
        Self {
            master_key: key,
            kem_public_key,
            kem_secret_key,
        }
    }
}

impl PostQuantumEncryption {
    pub fn new() -> Self {
        let mut key = [0u8; 32];
        secure_random_bytes(&mut key).expect("Failed to generate secure random bytes");
        
        let (kem_public_key, kem_secret_key) = MlKem768::keypair()
            .expect("Failed to generate ML-KEM-768 master keypair");
            
        Self { 
            master_key: key,
            kem_public_key,
            kem_secret_key,
        }
    }

    pub fn from_password(password: &str) -> Result<Self, AuthError> {
        let salt =
            SaltString::from_b64("cypheron_api_key_salt_v1_2024").map_err(|_| AuthError {
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
        
        let (kem_public_key, kem_secret_key) = MlKem768::keypair()
            .map_err(|_| AuthError {
                error: "keypair_error".to_string(),
                message: "Failed to generate ML-KEM-768 master keypair".to_string(),
                code: 500,
            })?;
            
        Ok(Self { 
            master_key: key,
            kem_public_key,
            kem_secret_key,
        })
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, AuthError> {
        let (kem_ciphertext, shared_secret) = MlKem768::encapsulate(&self.kem_public_key)
            .map_err(|_| AuthError {
                error: "encapsulation_error".to_string(),
                message: "Failed to encapsulate with ML-KEM-768".to_string(),
                code: 500,
            })?;

        let mut hasher = Sha256::new();
        hasher.update(&self.master_key);
        hasher.update(shared_secret.expose_secret());
        hasher.update(b"Cypheron-Hybrid-PQ-Encryption-v1");
        let derived_key = hasher.finalize();

        let mut nonce_bytes = [0u8; 12];
        secure_random_bytes(&mut nonce_bytes).map_err(|_| AuthError {
            error: "random_error".to_string(),
            message: "Failed to generate nonce".to_string(),
            code: 500,
        })?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        let cipher = ChaCha20Poly1305::new(Key::from_slice(&derived_key));
        let ciphertext = cipher.encrypt(nonce, plaintext).map_err(|_| AuthError {
            error: "encryption_error".to_string(),
            message: "Failed to encrypt with ChaCha20-Poly1305".to_string(),
            code: 500,
        })?;

        let mut result = Vec::with_capacity(4 + kem_ciphertext.len() + 12 + ciphertext.len());
        result.extend_from_slice(&(kem_ciphertext.len() as u32).to_le_bytes());
        result.extend_from_slice(&kem_ciphertext);
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    pub fn decrypt(&self, encrypted_data: &[u8]) -> Result<Vec<u8>, AuthError> {
        if encrypted_data.len() < 16 {
            return Err(AuthError {
                error: "invalid_ciphertext".to_string(),
                message: "Encrypted data too short".to_string(),
                code: 400,
            });
        }

        let mut offset = 0;

        let kem_ct_len = u32::from_le_bytes([
            encrypted_data[offset],
            encrypted_data[offset + 1],
            encrypted_data[offset + 2],
            encrypted_data[offset + 3],
        ]) as usize;
        offset += 4;

        if offset + kem_ct_len + 12 > encrypted_data.len() {
            return Err(AuthError {
                error: "invalid_ciphertext".to_string(),
                message: "Invalid KEM ciphertext length".to_string(),
                code: 400,
            });
        }

        let kem_ciphertext_bytes = &encrypted_data[offset..offset + kem_ct_len];
        offset += kem_ct_len;

        let nonce_bytes = &encrypted_data[offset..offset + 12];
        offset += 12;
        let ciphertext = &encrypted_data[offset..];

        let shared_secret = MlKem768::decapsulate(&kem_ciphertext_bytes.to_vec(), &self.kem_secret_key)
            .map_err(|_| AuthError {
                error: "decapsulation_error".to_string(),
                message: "Failed to decapsulate with ML-KEM-768".to_string(),
                code: 500,
            })?;

        let mut hasher = Sha256::new();
        hasher.update(&self.master_key);
        hasher.update(shared_secret.expose_secret());
        hasher.update(b"Cypheron-Hybrid-PQ-Encryption-v1");
        let derived_key = hasher.finalize();

        let cipher = ChaCha20Poly1305::new(Key::from_slice(&derived_key));
        let nonce = Nonce::from_slice(nonce_bytes);

        cipher.decrypt(nonce, ciphertext).map_err(|_| AuthError {
            error: "decryption_error".to_string(),
            message: "Failed to decrypt with ChaCha20-Poly1305".to_string(),
            code: 500,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceAccount {
    #[serde(rename = "type")]
    pub account_type: String,
    pub project_id: String,
    pub private_key_id: String,
    pub private_key: String,
    pub client_email: String,
    pub client_id: String,
    pub auth_uri: String,
    pub token_uri: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirestoreValue {
    #[serde(rename = "stringValue", skip_serializing_if = "Option::is_none")]
    pub string_value: Option<String>,
    #[serde(rename = "integerValue", skip_serializing_if = "Option::is_none")]
    pub integer_value: Option<String>,
    #[serde(rename = "booleanValue", skip_serializing_if = "Option::is_none")]
    pub boolean_value: Option<bool>,
    #[serde(rename = "timestampValue", skip_serializing_if = "Option::is_none")]
    pub timestamp_value: Option<String>,
    #[serde(rename = "arrayValue", skip_serializing_if = "Option::is_none")]
    pub array_value: Option<FirestoreArrayValue>,
    #[serde(rename = "nullValue", skip_serializing_if = "Option::is_none")]
    pub null_value: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirestoreArrayValue {
    pub values: Vec<FirestoreValue>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirestoreDocument {
    pub name: String,
    pub fields: HashMap<String, FirestoreValue>,
    #[serde(rename = "createTime")]
    pub create_time: String,
    #[serde(rename = "updateTime")]
    pub update_time: String,
}

#[derive(Debug)]
pub struct FirestoreClient {
    http_client: Client,
    project_id: String,
    database_id: String,
    access_token: Arc<Mutex<Option<String>>>,
    token_expires_at: Arc<Mutex<Option<SystemTime>>>,
    service_account: ServiceAccount,
}

#[derive(Debug, Clone)]
pub struct ApiKeyStore {
    firestore_client: Arc<FirestoreClient>,
    collection_name: String,
    encryption: PostQuantumEncryption,
}

impl FirestoreClient {
    pub async fn new(project_id: String, credentials_path: &str) -> Result<Self, AuthError> {
        let service_account = Self::load_service_account(credentials_path).await?;
        
        let http_client = Client::builder()
            .pool_max_idle_per_host(10)
            .pool_idle_timeout(std::time::Duration::from_secs(30))
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| AuthError {
                error: "http_client_error".to_string(),
                message: format!("Failed to create HTTP client: {}", e),
                code: 500,
            })?;

        Ok(Self {
            http_client,
            project_id,
            database_id: "(default)".to_string(),
            access_token: Arc::new(Mutex::new(None)),
            token_expires_at: Arc::new(Mutex::new(None)),
            service_account,
        })
    }

    async fn load_service_account(path: &str) -> Result<ServiceAccount, AuthError> {
        let content = tokio::fs::read_to_string(path).await.map_err(|e| AuthError {
            error: "credentials_read_error".to_string(),
            message: format!("Failed to read service account file: {}", e),
            code: 500,
        })?;

        serde_json::from_str(&content).map_err(|e| AuthError {
            error: "credentials_parse_error".to_string(),
            message: format!("Failed to parse service account JSON: {}", e),
            code: 500,
        })
    }

    async fn get_access_token(&self) -> Result<String, AuthError> {
        let now = SystemTime::now();
        
        {
            let token_guard = self.access_token.lock().await;
            let expires_guard = self.token_expires_at.lock().await;
            
            if let (Some(token), Some(expires_at)) = (token_guard.as_ref(), expires_guard.as_ref()) {
                if now < *expires_at {
                    return Ok(token.clone());
                }
            }
        }

        let new_token = self.generate_access_token().await?;
        let expires_at = now + std::time::Duration::from_secs(3300);

        {
            let mut token_guard = self.access_token.lock().await;
            let mut expires_guard = self.token_expires_at.lock().await;
            *token_guard = Some(new_token.clone());
            *expires_guard = Some(expires_at);
        }

        Ok(new_token)
    }

    async fn generate_access_token(&self) -> Result<String, AuthError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let claims = serde_json::json!({
            "iss": self.service_account.client_email,
            "scope": "https://www.googleapis.com/auth/datastore",
            "aud": "https://oauth2.googleapis.com/token",
            "exp": now + 3600,
            "iat": now
        });

        let private_key = self.service_account.private_key
            .replace("-----BEGIN PRIVATE KEY-----", "")
            .replace("-----END PRIVATE KEY-----", "")
            .replace('\n', "");

        let key_bytes = general_purpose::STANDARD.decode(&private_key).map_err(|e| AuthError {
            error: "key_decode_error".to_string(),
            message: format!("Failed to decode private key: {}", e),
            code: 500,
        })?;

        let encoding_key = EncodingKey::from_rsa_der(&key_bytes);

        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(self.service_account.private_key_id.clone());

        let jwt = encode(&header, &claims, &encoding_key).map_err(|e| AuthError {
            error: "jwt_creation_error".to_string(),
            message: format!("Failed to create JWT: {}", e),
            code: 500,
        })?;

        let response = self.http_client
            .post("https://oauth2.googleapis.com/token")
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                ("assertion", &jwt),
            ])
            .send()
            .await
            .map_err(|e| AuthError {
                error: "token_request_error".to_string(),
                message: format!("Failed to request access token: {}", e),
                code: 500,
            })?;

        let token_response: JsonValue = response.json().await.map_err(|e| AuthError {
            error: "token_parse_error".to_string(),
            message: format!("Failed to parse token response: {}", e),
            code: 500,
        })?;

        token_response["access_token"]
            .as_str()
            .ok_or_else(|| AuthError {
                error: "token_missing_error".to_string(),
                message: "Access token not found in response".to_string(),
                code: 500,
            })
            .map(|s| s.to_string())
    }

    pub async fn get_document(&self, collection: &str, document_id: &str) -> Result<Option<FirestoreDocument>, AuthError> {
        let token = self.get_access_token().await?;
        let url = format!(
            "https://firestore.googleapis.com/v1/projects/{}/databases/{}/documents/{}/{}",
            self.project_id, self.database_id, collection, document_id
        );

        let response = self.http_client
            .get(&url)
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await
            .map_err(|e| AuthError {
                error: "firestore_request_error".to_string(),
                message: format!("Failed to get document: {}", e),
                code: 500,
            })?;

        match response.status().as_u16() {
            404 => Ok(None),
            200 => {
                let doc: FirestoreDocument = response.json().await.map_err(|e| AuthError {
                    error: "firestore_parse_error".to_string(),
                    message: format!("Failed to parse document: {}", e),
                    code: 500,
                })?;
                Ok(Some(doc))
            }
            _ => {
                let error_text = response.text().await.unwrap_or_default();
                Err(AuthError {
                    error: "firestore_error".to_string(),
                    message: format!("Firestore error: {}", error_text),
                    code: 500,
                })
            }
        }
    }

    pub async fn create_document(&self, collection: &str, document_id: &str, fields: HashMap<String, FirestoreValue>) -> Result<FirestoreDocument, AuthError> {
        let token = self.get_access_token().await?;
        let url = format!(
            "https://firestore.googleapis.com/v1/projects/{}/databases/{}/documents/{}?documentId={}",
            self.project_id, self.database_id, collection, document_id
        );

        let request_body = serde_json::json!({
            "fields": fields
        });

        let response = self.http_client
            .post(&url)
            .header("Authorization", format!("Bearer {}", token))
            .header("Content-Type", "application/json")
            .json(&request_body)
            .send()
            .await
            .map_err(|e| AuthError {
                error: "firestore_request_error".to_string(),
                message: format!("Failed to create document: {}", e),
                code: 500,
            })?;

        if response.status().is_success() {
            response.json().await.map_err(|e| AuthError {
                error: "firestore_parse_error".to_string(),
                message: format!("Failed to parse created document: {}", e),
                code: 500,
            })
        } else {
            let error_text = response.text().await.unwrap_or_default();
            Err(AuthError {
                error: "firestore_create_error".to_string(),
                message: format!("Failed to create document: {}", error_text),
                code: 500,
            })
        }
    }

    pub async fn update_document(&self, collection: &str, document_id: &str, fields: HashMap<String, FirestoreValue>) -> Result<FirestoreDocument, AuthError> {
        let token = self.get_access_token().await?;
        let url = format!(
            "https://firestore.googleapis.com/v1/projects/{}/databases/{}/documents/{}/{}",
            self.project_id, self.database_id, collection, document_id
        );

        let request_body = serde_json::json!({
            "fields": fields
        });

        let response = self.http_client
            .patch(&url)
            .header("Authorization", format!("Bearer {}", token))
            .header("Content-Type", "application/json")
            .json(&request_body)
            .send()
            .await
            .map_err(|e| AuthError {
                error: "firestore_request_error".to_string(),
                message: format!("Failed to update document: {}", e),
                code: 500,
            })?;

        if response.status().is_success() {
            response.json().await.map_err(|e| AuthError {
                error: "firestore_parse_error".to_string(),
                message: format!("Failed to parse updated document: {}", e),
                code: 500,
            })
        } else {
            let error_text = response.text().await.unwrap_or_default();
            Err(AuthError {
                error: "firestore_update_error".to_string(),
                message: format!("Failed to update document: {}", error_text),
                code: 500,
            })
        }
    }

    pub async fn delete_document(&self, collection: &str, document_id: &str) -> Result<(), AuthError> {
        let token = self.get_access_token().await?;
        let url = format!(
            "https://firestore.googleapis.com/v1/projects/{}/databases/{}/documents/{}/{}",
            self.project_id, self.database_id, collection, document_id
        );

        let response = self.http_client
            .delete(&url)
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await
            .map_err(|e| AuthError {
                error: "firestore_request_error".to_string(),
                message: format!("Failed to delete document: {}", e),
                code: 500,
            })?;

        if response.status().is_success() {
            Ok(())
        } else {
            let error_text = response.text().await.unwrap_or_default();
            Err(AuthError {
                error: "firestore_delete_error".to_string(),
                message: format!("Failed to delete document: {}", error_text),
                code: 500,
            })
        }
    }
}

impl ApiKeyStore {
    pub async fn new_with_firestore(project_id: &str) -> Result<Self, AuthError> {
        let credentials_path = std::env::var("GOOGLE_APPLICATION_CREDENTIALS")
            .map_err(|_| AuthError {
                error: "credentials_missing".to_string(),
                message: "GOOGLE_APPLICATION_CREDENTIALS environment variable not set".to_string(),
                code: 500,
            })?;

        let collection_name = std::env::var("FIRESTORE_COLLECTION")
            .unwrap_or_else(|_| "api_keys".to_string());

        let encryption = if let Ok(password) = std::env::var("PQ_ENCRYPTION_PASSWORD") {
            PostQuantumEncryption::from_password(&password)?
        } else {
            PostQuantumEncryption::new()
        };

        let firestore_client = Arc::new(FirestoreClient::new(project_id.to_string(), &credentials_path).await?);

        Ok(Self {
            firestore_client,
            collection_name,
            encryption,
        })
    }

    fn api_key_to_firestore_fields(&self, api_key: &ApiKey, raw_key: &str) -> Result<HashMap<String, FirestoreValue>, AuthError> {
        let encrypted_key = self.encryption.encrypt(raw_key.as_bytes())?;
        let encrypted_key_b64 = general_purpose::STANDARD.encode(&encrypted_key);
        
        let permissions_values: Vec<FirestoreValue> = api_key.permissions
            .iter()
            .map(|p| FirestoreValue {
                string_value: Some(p.clone()),
                integer_value: None,
                boolean_value: None,
                timestamp_value: None,
                array_value: None,
                null_value: None,
            })
            .collect();

        let mut fields = HashMap::new();
        
        fields.insert("id".to_string(), FirestoreValue {
            string_value: Some(api_key.id.to_string()),
            integer_value: None,
            boolean_value: None,
            timestamp_value: None,
            array_value: None,
            null_value: None,
        });
        
        fields.insert("name".to_string(), FirestoreValue {
            string_value: Some(api_key.name.clone()),
            integer_value: None,
            boolean_value: None,
            timestamp_value: None,
            array_value: None,
            null_value: None,
        });
        
        fields.insert("key_hash".to_string(), FirestoreValue {
            string_value: Some(api_key.key_hash.clone()),
            integer_value: None,
            boolean_value: None,
            timestamp_value: None,
            array_value: None,
            null_value: None,
        });
        
        fields.insert("encrypted_key".to_string(), FirestoreValue {
            string_value: Some(encrypted_key_b64),
            integer_value: None,
            boolean_value: None,
            timestamp_value: None,
            array_value: None,
            null_value: None,
        });
        
        fields.insert("permissions".to_string(), FirestoreValue {
            string_value: None,
            integer_value: None,
            boolean_value: None,
            timestamp_value: None,
            array_value: Some(FirestoreArrayValue { values: permissions_values }),
            null_value: None,
        });
        
        fields.insert("rate_limit".to_string(), FirestoreValue {
            string_value: None,
            integer_value: Some(api_key.rate_limit.to_string()),
            boolean_value: None,
            timestamp_value: None,
            array_value: None,
            null_value: None,
        });
        
        fields.insert("created_at".to_string(), FirestoreValue {
            string_value: None,
            integer_value: None,
            boolean_value: None,
            timestamp_value: Some(api_key.created_at.to_rfc3339()),
            array_value: None,
            null_value: None,
        });
        
        if let Some(expires_at) = api_key.expires_at {
            fields.insert("expires_at".to_string(), FirestoreValue {
                string_value: None,
                integer_value: None,
                boolean_value: None,
                timestamp_value: Some(expires_at.to_rfc3339()),
                array_value: None,
                null_value: None,
            });
        } else {
            fields.insert("expires_at".to_string(), FirestoreValue {
                string_value: None,
                integer_value: None,
                boolean_value: None,
                timestamp_value: None,
                array_value: None,
                null_value: Some("NULL_VALUE".to_string()),
            });
        }
        
        fields.insert("is_active".to_string(), FirestoreValue {
            string_value: None,
            integer_value: None,
            boolean_value: Some(api_key.is_active),
            timestamp_value: None,
            array_value: None,
            null_value: None,
        });
        
        if let Some(last_used) = api_key.last_used {
            fields.insert("last_used".to_string(), FirestoreValue {
                string_value: None,
                integer_value: None,
                boolean_value: None,
                timestamp_value: Some(last_used.to_rfc3339()),
                array_value: None,
                null_value: None,
            });
        } else {
            fields.insert("last_used".to_string(), FirestoreValue {
                string_value: None,
                integer_value: None,
                boolean_value: None,
                timestamp_value: None,
                array_value: None,
                null_value: Some("NULL_VALUE".to_string()),
            });
        }
        
        fields.insert("usage_count".to_string(), FirestoreValue {
            string_value: None,
            integer_value: Some(api_key.usage_count.to_string()),
            boolean_value: None,
            timestamp_value: None,
            array_value: None,
            null_value: None,
        });
        
        Ok(fields)
    }

    fn firestore_document_to_api_key(&self, doc: &FirestoreDocument) -> Result<ApiKey, AuthError> {
        let fields = &doc.fields;
        
        let id_str = fields.get("id")
            .and_then(|v| v.string_value.as_ref())
            .ok_or_else(|| AuthError {
                error: "parse_error".to_string(),
                message: "Missing or invalid id field".to_string(),
                code: 500,
            })?;
        
        let id = Uuid::parse_str(id_str).map_err(|_| AuthError {
            error: "parse_error".to_string(),
            message: "Invalid UUID format for id".to_string(),
            code: 500,
        })?;
        
        let name = fields.get("name")
            .and_then(|v| v.string_value.as_ref())
            .ok_or_else(|| AuthError {
                error: "parse_error".to_string(),
                message: "Missing or invalid name field".to_string(),
                code: 500,
            })?
            .clone();
        
        let key_hash = fields.get("key_hash")
            .and_then(|v| v.string_value.as_ref())
            .ok_or_else(|| AuthError {
                error: "parse_error".to_string(),
                message: "Missing or invalid key_hash field".to_string(),
                code: 500,
            })?
            .clone();
        
        let permissions = fields.get("permissions")
            .and_then(|v| v.array_value.as_ref())
            .ok_or_else(|| AuthError {
                error: "parse_error".to_string(),
                message: "Missing or invalid permissions field".to_string(),
                code: 500,
            })?
            .values
            .iter()
            .filter_map(|v| v.string_value.as_ref())
            .cloned()
            .collect();
        
        let rate_limit = fields.get("rate_limit")
            .and_then(|v| v.integer_value.as_ref())
            .ok_or_else(|| AuthError {
                error: "parse_error".to_string(),
                message: "Missing or invalid rate_limit field".to_string(),
                code: 500,
            })?
            .parse::<u32>()
            .map_err(|_| AuthError {
                error: "parse_error".to_string(),
                message: "Invalid rate_limit format".to_string(),
                code: 500,
            })?;
        
        let created_at = fields.get("created_at")
            .and_then(|v| v.timestamp_value.as_ref())
            .ok_or_else(|| AuthError {
                error: "parse_error".to_string(),
                message: "Missing or invalid created_at field".to_string(),
                code: 500,
            })?;
        
        let created_at = DateTime::parse_from_rfc3339(created_at)
            .map_err(|_| AuthError {
                error: "parse_error".to_string(),
                message: "Invalid created_at timestamp format".to_string(),
                code: 500,
            })?
            .with_timezone(&Utc);
        
        let expires_at = fields.get("expires_at")
            .and_then(|v| {
                if v.null_value.is_some() {
                    None
                } else {
                    v.timestamp_value.as_ref()
                }
            })
            .map(|ts| {
                DateTime::parse_from_rfc3339(ts)
                    .map(|dt| dt.with_timezone(&Utc))
                    .map_err(|_| AuthError {
                        error: "parse_error".to_string(),
                        message: "Invalid expires_at timestamp format".to_string(),
                        code: 500,
                    })
            })
            .transpose()?;
        
        let is_active = fields.get("is_active")
            .and_then(|v| v.boolean_value)
            .ok_or_else(|| AuthError {
                error: "parse_error".to_string(),
                message: "Missing or invalid is_active field".to_string(),
                code: 500,
            })?;
        
        let last_used = fields.get("last_used")
            .and_then(|v| {
                if v.null_value.is_some() {
                    None
                } else {
                    v.timestamp_value.as_ref()
                }
            })
            .map(|ts| {
                DateTime::parse_from_rfc3339(ts)
                    .map(|dt| dt.with_timezone(&Utc))
                    .map_err(|_| AuthError {
                        error: "parse_error".to_string(),
                        message: "Invalid last_used timestamp format".to_string(),
                        code: 500,
                    })
            })
            .transpose()?;
        
        let usage_count = fields.get("usage_count")
            .and_then(|v| v.integer_value.as_ref())
            .ok_or_else(|| AuthError {
                error: "parse_error".to_string(),
                message: "Missing or invalid usage_count field".to_string(),
                code: 500,
            })?
            .parse::<u64>()
            .map_err(|_| AuthError {
                error: "parse_error".to_string(),
                message: "Invalid usage_count format".to_string(),
                code: 500,
            })?;
        
        Ok(ApiKey {
            id,
            name,
            key_hash,
            permissions,
            rate_limit,
            created_at,
            expires_at,
            is_active,
            last_used,
            usage_count,
        })
    }

    pub async fn validate_key(&self, key: &str) -> Option<ApiKey> {
        let key_hash = format!("{:x}", Sha256::digest(key.as_bytes()));
        
        match self.firestore_client.get_document(&self.collection_name, &key_hash).await {
            Ok(Some(doc)) => {
                match self.firestore_document_to_api_key(&doc) {
                    Ok(mut api_key) => {
                        let encrypted_key_b64 = doc.fields.get("encrypted_key")
                            .and_then(|v| v.string_value.as_ref());
                        
                        if let Some(encrypted_key_b64) = encrypted_key_b64 {
                            if let Ok(encrypted_key_bytes) = general_purpose::STANDARD.decode(encrypted_key_b64) {
                                if let Ok(decrypted_key_bytes) = self.encryption.decrypt(&encrypted_key_bytes) {
                                    if let Ok(decrypted_key) = String::from_utf8(decrypted_key_bytes) {
                                        let decrypted_hash = format!("{:x}", Sha256::digest(decrypted_key.as_bytes()));
                                        if decrypted_hash == key_hash {
                                            if api_key.is_active && api_key.expires_at.map(|exp| Utc::now() <= exp).unwrap_or(true) {
                                                api_key.last_used = Some(Utc::now());
                                                api_key.usage_count += 1;
                                                
                                                let mut update_fields = HashMap::new();
                                                update_fields.insert("last_used".to_string(), FirestoreValue {
                                                    string_value: None,
                                                    integer_value: None,
                                                    boolean_value: None,
                                                    timestamp_value: Some(Utc::now().to_rfc3339()),
                                                    array_value: None,
                                                    null_value: None,
                                                });
                                                update_fields.insert("usage_count".to_string(), FirestoreValue {
                                                    string_value: None,
                                                    integer_value: Some(api_key.usage_count.to_string()),
                                                    boolean_value: None,
                                                    timestamp_value: None,
                                                    array_value: None,
                                                    null_value: None,
                                                });
                                                
                                                if let Err(e) = self.firestore_client.update_document(&self.collection_name, &key_hash, update_fields).await {
                                                    tracing::warn!("Failed to update usage tracking: {}", e.message);
                                                }
                                                
                                                return Some(api_key);
                                            } else {
                                                if !api_key.is_active {
                                                    tracing::warn!("Attempt to use inactive API key: {}", api_key.id);
                                                } else {
                                                    tracing::warn!("Attempt to use expired API key: {}", api_key.id);
                                                }
                                            }
                                        } else {
                                            tracing::warn!("Post-quantum encrypted key validation failed - hash mismatch");
                                        }
                                    } else {
                                        tracing::warn!("Post-quantum decryption produced invalid UTF-8");
                                    }
                                } else {
                                    tracing::warn!("Failed to decrypt stored key with post-quantum encryption");
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!("Failed to parse Firestore document: {}", e.message);
                    }
                }
            }
            Ok(None) => {
                tracing::warn!("Attempt to use unknown API key hash: {}", &key_hash[..8]);
            }
            Err(e) => {
                tracing::error!("Firestore validation error: {}", e.message);
            }
        }
        
        None
    }

    pub async fn store_api_key(&self, api_key: &ApiKey, raw_key: &str) -> Result<(), AuthError> {
        let fields = self.api_key_to_firestore_fields(api_key, raw_key)?;
        self.firestore_client.create_document(&self.collection_name, &api_key.key_hash, fields).await?;
        Ok(())
    }

    pub async fn delete_api_key(&self, key_hash: &str) -> Result<(), AuthError> {
        self.firestore_client.delete_document(&self.collection_name, key_hash).await
    }

    pub async fn check_permission(&self, key: &str, resource: &str) -> bool {
        if let Some(api_key) = self.validate_key(key).await {
            let mut has_permission = false;

            for permission in &api_key.permissions {
                let exact_match = permission.as_bytes().ct_eq(b"*").into()
                    || permission.as_bytes().ct_eq(resource.as_bytes()).into();

                let wildcard_match = if permission.ends_with(":*") {
                    let prefix = &permission[..permission.len() - 1];
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

    let validated_key = api_store.validate_key(&api_key).await.ok_or_else(|| {
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
        return api_key.to_str().map(|s| s.to_string()).map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                Json(AuthError {
                    error: "invalid_header".to_string(),
                    message: "Invalid X-API-Key header format".to_string(),
                    code: 400,
                }),
            )
        });
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
            message: "API key required. Use X-API-Key header or Authorization: Bearer <key>"
                .to_string(),
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
