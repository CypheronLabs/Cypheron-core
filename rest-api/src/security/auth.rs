use super::compliance::{ComplianceEventType, ComplianceManager, RiskLevel};
use axum::{
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::Response,
    Json,
};
use base64::{engine::general_purpose, Engine as _};
use chrono::{DateTime, Utc, TimeZone};
use core_lib::platform::secure_random_bytes;
use ring::{aead, pbkdf2, rand};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::SystemTime;
use subtle::ConstantTimeEq;
use uuid::Uuid;


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
    key: [u8; 32],
}

impl std::fmt::Debug for PostQuantumEncryption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PostQuantumEncryption")
            .field("key", &"[REDACTED]")
            .finish()
    }
}

impl Clone for PostQuantumEncryption {
    fn clone(&self) -> Self {
        Self {
            key: self.key,
        }
    }
}

impl PostQuantumEncryption {
    pub fn new() -> Self {
        let mut key = [0u8; 32];
        secure_random_bytes(&mut key).expect("Failed to generate secure random bytes");
        Self { key }
    }

    pub fn from_password(password: &str) -> Result<Self, AuthError> {
        const SALT: &[u8] = b"Q3lwaGVyb25BcGlLZXlTYWx0";
        const PBKDF2_ITERATIONS: u32 = 100_000;
        
        let mut key = [0u8; 32];
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256,
            std::num::NonZeroU32::new(PBKDF2_ITERATIONS).unwrap(),
            SALT,
            password.as_bytes(),
            &mut key,
        );
        
        Ok(Self { key })
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, AuthError> {
        let sealing_key = aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::AES_256_GCM, &self.key)
                .map_err(|_| AuthError {
                    error: "key_error".to_string(),
                    message: "Failed to create encryption key".to_string(),
                    code: 500,
                })?
        );

        let mut nonce_bytes = [0u8; 12];
        secure_random_bytes(&mut nonce_bytes).map_err(|_| AuthError {
            error: "random_error".to_string(),
            message: "Failed to generate nonce".to_string(),
            code: 500,
        })?;
        
        let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);
        let mut in_out = plaintext.to_vec();
        
        sealing_key.seal_in_place_append_tag(nonce, aead::Aad::empty(), &mut in_out)
            .map_err(|_| AuthError {
                error: "encryption_error".to_string(),
                message: "Failed to encrypt data".to_string(),
                code: 500,
            })?;

        let mut result = Vec::with_capacity(12 + in_out.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&in_out);
        
        Ok(result)
    }

    pub fn decrypt(&self, encrypted_data: &[u8]) -> Result<Vec<u8>, AuthError> {
        if encrypted_data.len() < 12 + 16 {
            return Err(AuthError {
                error: "invalid_ciphertext".to_string(),
                message: "Encrypted data too short".to_string(),
                code: 400,
            });
        }

        let opening_key = aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::AES_256_GCM, &self.key)
                .map_err(|_| AuthError {
                    error: "key_error".to_string(),
                    message: "Failed to create decryption key".to_string(),
                    code: 500,
                })?
        );

        let (nonce_bytes, ciphertext) = encrypted_data.split_at(12);
        let mut nonce_array = [0u8; 12];
        nonce_array.copy_from_slice(nonce_bytes);
        
        let nonce = aead::Nonce::assume_unique_for_key(nonce_array);
        let mut in_out = ciphertext.to_vec();
        
        let plaintext = opening_key.open_in_place(nonce, aead::Aad::empty(), &mut in_out)
            .map_err(|_| AuthError {
                error: "decryption_error".to_string(),
                message: "Failed to decrypt data".to_string(),
                code: 500,
            })?;

        Ok(plaintext.to_vec())
    }
}






use gcloud_sdk::google::firestore::v1::{Document, DocumentMask, Value, CreateDocumentRequest, GetDocumentRequest, UpdateDocumentRequest, DeleteDocumentRequest, ArrayValue};
use gcloud_sdk::google::firestore::v1::value::ValueType;
use gcloud_sdk::google::firestore::v1::firestore_client::FirestoreClient;
use gcloud_sdk::{GoogleApi, GoogleAuthMiddleware};

#[derive(Clone)]
pub struct ApiKeyStore {
    firestore_client: Arc<GoogleApi<FirestoreClient<GoogleAuthMiddleware>>>,
    project_id: String,
    database_id: String,
    collection_name: String,
    encryption: PostQuantumEncryption,
}



impl ApiKeyStore {
    pub async fn new_with_firestore(project_id: &str) -> Result<Self, AuthError> {
        let collection_name = std::env::var("FIRESTORE_COLLECTION")
            .unwrap_or_else(|_| "api_keys".to_string());

        let encryption = if let Ok(password) = std::env::var("PQ_ENCRYPTION_PASSWORD") {
            PostQuantumEncryption::from_password(&password)?
        } else {
            PostQuantumEncryption::new()
        };

        let firestore_client = Arc::new(
            GoogleApi::from_function(
                FirestoreClient::new,
                "https://firestore.googleapis.com",
                None,
            ).await.map_err(|e| AuthError {
                error: "firestore_init_error".to_string(),
                message: format!("Failed to initialize Firestore client: {}", e),
                code: 500,
            })?
        );

        Ok(Self {
            firestore_client,
            project_id: project_id.to_string(),
            database_id: "(default)".to_string(),
            collection_name,
            encryption,
        })
    }

    fn api_key_to_firestore_fields(&self, api_key: &ApiKey, raw_key: &str) -> Result<HashMap<String, Value>, AuthError> {
        let encrypted_key = self.encryption.encrypt(raw_key.as_bytes())?;
        let encrypted_key_b64 = general_purpose::STANDARD.encode(&encrypted_key);

        let permissions_values: Vec<Value> = api_key.permissions
            .iter()
            .map(|p| Value {
                value_type: Some(ValueType::StringValue(p.clone())),
            })
            .collect();

        let mut fields = HashMap::new();

        fields.insert("id".to_string(), Value {
            value_type: Some(ValueType::StringValue(api_key.id.to_string())),
        });

        fields.insert("name".to_string(), Value {
            value_type: Some(ValueType::StringValue(api_key.name.clone())),
        });

        fields.insert("key_hash".to_string(), Value {
            value_type: Some(ValueType::StringValue(api_key.key_hash.clone())),
        });

        fields.insert("encrypted_key".to_string(), Value {
            value_type: Some(ValueType::StringValue(encrypted_key_b64)),
        });

        fields.insert("permissions".to_string(), Value {
            value_type: Some(ValueType::ArrayValue(ArrayValue { values: permissions_values })),
        });

        fields.insert("rate_limit".to_string(), Value {
            value_type: Some(ValueType::IntegerValue(api_key.rate_limit as i64)),
        });

        fields.insert("created_at".to_string(), Value {
            value_type: Some(ValueType::TimestampValue(gcloud_sdk::prost_types::Timestamp::from(SystemTime::from(api_key.created_at)))),
        });

        if let Some(expires_at) = api_key.expires_at {
            fields.insert("expires_at".to_string(), Value {
                value_type: Some(ValueType::TimestampValue(gcloud_sdk::prost_types::Timestamp::from(SystemTime::from(expires_at)))),
            });
        } else {
            fields.insert("expires_at".to_string(), Value {
                value_type: Some(ValueType::NullValue(0)),
            });
        }

        fields.insert("is_active".to_string(), Value {
            value_type: Some(ValueType::BooleanValue(api_key.is_active)),
        });

        if let Some(last_used) = api_key.last_used {
            fields.insert("last_used".to_string(), Value {
                value_type: Some(ValueType::TimestampValue(gcloud_sdk::prost_types::Timestamp::from(SystemTime::from(last_used)))),
            });
        } else {
            fields.insert("last_used".to_string(), Value {
                value_type: Some(ValueType::NullValue(0)),
            });
        }

        fields.insert("usage_count".to_string(), Value {
            value_type: Some(ValueType::IntegerValue(api_key.usage_count as i64)),
        });

        Ok(fields)
    }

    fn firestore_document_to_api_key(&self, doc: &Document) -> Result<ApiKey, AuthError> {
        let fields = &doc.fields;

        let id_str = fields.get("id")
            .and_then(|v| v.value_type.as_ref())
            .and_then(|vt| if let ValueType::StringValue(s) = vt { Some(s.as_str()) } else { None })
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
            .and_then(|v| v.value_type.as_ref())
            .and_then(|vt| if let ValueType::StringValue(s) = vt { Some(s.clone()) } else { None })
            .ok_or_else(|| AuthError {
                error: "parse_error".to_string(),
                message: "Missing or invalid name field".to_string(),
                code: 500,
            })?;

        let key_hash = fields.get("key_hash")
            .and_then(|v| v.value_type.as_ref())
            .and_then(|vt| if let ValueType::StringValue(s) = vt { Some(s.clone()) } else { None })
            .ok_or_else(|| AuthError {
                error: "parse_error".to_string(),
                message: "Missing or invalid key_hash field".to_string(),
                code: 500,
            })?;

        let permissions = fields.get("permissions")
            .and_then(|v| v.value_type.as_ref())
            .and_then(|vt| if let ValueType::ArrayValue(a) = vt { Some(a) } else { None })
            .ok_or_else(|| AuthError {
                error: "parse_error".to_string(),
                message: "Missing or invalid permissions field".to_string(),
                code: 500,
            })?
            .values
            .iter()
            .filter_map(|v| v.value_type.as_ref())
            .filter_map(|vt| if let ValueType::StringValue(s) = vt { Some(s.clone()) } else { None })
            .collect();

        let rate_limit = fields.get("rate_limit")
            .and_then(|v| v.value_type.as_ref())
            .and_then(|vt| if let ValueType::IntegerValue(i) = vt { Some(*i as u32) } else { None })
            .ok_or_else(|| AuthError {
                error: "parse_error".to_string(),
                message: "Missing or invalid rate_limit field".to_string(),
                code: 500,
            })?;

        let created_at_prost = fields.get("created_at")
            .and_then(|v| v.value_type.as_ref())
            .and_then(|vt| if let ValueType::TimestampValue(ts) = vt { Some(ts) } else { None })
            .ok_or_else(|| AuthError {
                error: "parse_error".to_string(),
                message: "Missing or invalid created_at field".to_string(),
                code: 500,
            })?;

        let created_at = Utc.timestamp_opt(created_at_prost.seconds, created_at_prost.nanos as u32)
            .single()
            .ok_or_else(|| AuthError {
                error: "parse_error".to_string(),
                message: "Invalid created_at timestamp".to_string(),
                code: 500,
            })?;

        let expires_at = fields.get("expires_at")
            .and_then(|v| v.value_type.as_ref())
            .and_then(|vt| if let ValueType::TimestampValue(ts) = vt { Some(ts) } else { None })
            .map(|ts| Utc.timestamp_opt(ts.seconds, ts.nanos as u32).single())
            .flatten();

        let is_active = fields.get("is_active")
            .and_then(|v| v.value_type.as_ref())
            .and_then(|vt| if let ValueType::BooleanValue(b) = vt { Some(*b) } else { None })
            .ok_or_else(|| AuthError {
                error: "parse_error".to_string(),
                message: "Missing or invalid is_active field".to_string(),
                code: 500,
            })?;

        let last_used = fields.get("last_used")
            .and_then(|v| v.value_type.as_ref())
            .and_then(|vt| if let ValueType::TimestampValue(ts) = vt { Some(ts) } else { None })
            .map(|ts| Utc.timestamp_opt(ts.seconds, ts.nanos as u32).single())
            .flatten();

        let usage_count = fields.get("usage_count")
            .and_then(|v| v.value_type.as_ref())
            .and_then(|vt| if let ValueType::IntegerValue(i) = vt { Some(*i as u64) } else { None })
            .ok_or_else(|| AuthError {
                error: "parse_error".to_string(),
                message: "Missing or invalid usage_count field".to_string(),
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

        let request = GetDocumentRequest {
            name: format!("projects/{}/databases/{}/documents/{}/{}", self.project_id, self.database_id, self.collection_name, key_hash),
            mask: None,
            consistency_selector: None,
        };

        match self.firestore_client.get().get_document(request).await {
            Ok(response) => {
                let doc = response.into_inner();
                match self.firestore_document_to_api_key(&doc) {
                    Ok(mut api_key) => {
                        let encrypted_key_b64 = doc.fields.get("encrypted_key")
                            .and_then(|v| v.value_type.as_ref())
                            .and_then(|vt| if let ValueType::StringValue(s) = vt { Some(s.as_str()) } else { None });

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
                                                update_fields.insert("last_used".to_string(), Value {
                                                    value_type: Some(ValueType::TimestampValue(gcloud_sdk::prost_types::Timestamp::from(SystemTime::from(Utc::now())))),
                                                });
                                                update_fields.insert("usage_count".to_string(), Value {
                                                    value_type: Some(ValueType::IntegerValue(api_key.usage_count as i64)),
                                                });

                                                let request = UpdateDocumentRequest {
                                                    document: Some(Document {
                                                        name: format!("projects/{}/databases/{}/documents/{}/{}", self.project_id, self.database_id, self.collection_name, key_hash),
                                                        fields: update_fields,
                                                        create_time: None,
                                                        update_time: None,
                                                    }),
                                                    update_mask: Some(DocumentMask {
                                                        field_paths: vec!["last_used".to_string(), "usage_count".to_string()],
                                                    }),
                                                    mask: None,
                                                    current_document: None,
                                                };

                                                if let Err(e) = self.firestore_client.get().update_document(request).await {
                                                    tracing::warn!("Failed to update usage tracking: {}", e);
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
            Err(e) => {
                tracing::error!("Firestore validation error: {}", e);
            }
        }

        None
    }

    pub async fn store_api_key(&self, api_key: &ApiKey, raw_key: &str) -> Result<(), AuthError> {
        let fields = self.api_key_to_firestore_fields(api_key, raw_key)?;

        let request = CreateDocumentRequest {
            parent: format!("projects/{}/databases/{}/documents", self.project_id, self.database_id),
            collection_id: self.collection_name.clone(),
            document_id: api_key.key_hash.clone(),
            document: Some(Document {
                name: "".to_string(),
                fields,
                create_time: None,
                update_time: None,
            }),
            mask: None,
        };

        self.firestore_client.get().create_document(request).await.map_err(|e| AuthError {
            error: "firestore_create_error".to_string(),
            message: format!("Failed to create document: {}", e),
            code: 500,
        })?;

        Ok(())
    }

    pub async fn delete_api_key(&self, key_hash: &str) -> Result<(), AuthError> {
        let request = DeleteDocumentRequest {
            name: format!("projects/{}/databases/{}/documents/{}/{}", self.project_id, self.database_id, self.collection_name, key_hash),
            current_document: None,
        };

        self.firestore_client.get().delete_document(request).await.map_err(|e| AuthError {
            error: "firestore_delete_error".to_string(),
            message: format!("Failed to delete document: {}", e),
            code: 500,
        })?;

        Ok(())
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

    // Add user_id and api_key_prefix to request extensions for logging
    request.extensions_mut().insert(validated_key.id.to_string());
    request.extensions_mut().insert(api_key[..8].to_string());

    Ok(next.run(request).await)
}

pub async fn admin_auth_middleware(
    State(_api_store): State<ApiKeyStore>,
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Result<Response, (StatusCode, Json<AuthError>)> {
    let master_admin_key = std::env::var("PQ_MASTER_ADMIN_KEY").map_err(|_| {
        tracing::error!("PQ_MASTER_ADMIN_KEY environment variable not set");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(AuthError {
                error: "admin_config_error".to_string(),
                message: "Admin authentication not properly configured".to_string(),
                code: 500,
            }),
        )
    })?;

    let provided_key = extract_api_key(&headers).map_err(|e| {
        tracing::warn!("Admin endpoint access attempt without API key from: {:?}", request.uri());
        e
    })?;

    if provided_key.as_bytes().ct_eq(master_admin_key.as_bytes()).into() {
        tracing::info!("Master admin authenticated for: {}", request.uri().path());
        Ok(next.run(request).await)
    } else {
        tracing::error!("Unauthorized admin access attempt with key: {}... from: {}", 
                       &provided_key[..std::cmp::min(10, provided_key.len())], 
                       request.uri().path());
        
        Err((
            StatusCode::FORBIDDEN,
            Json(AuthError {
                error: "admin_access_denied".to_string(),
                message: "Admin access requires master admin key".to_string(),
                code: 403,
            }),
        ))
    }
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
