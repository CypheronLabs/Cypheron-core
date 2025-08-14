use super::{ValidationContext, ValidationResult, ValidationStep, UsageUpdateInfo};
use crate::security::auth::{AuthError, ApiKey, PostQuantumEncryption};
use crate::security::auth::hybrid_encryption::{HybridEncryption, VersionedEncryptedData};
use base64::{engine::general_purpose, Engine as _};
use chrono::Utc;
use gcloud_sdk::google::firestore::v1::value::ValueType;
use gcloud_sdk::google::firestore::v1::Document;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use uuid::Uuid;

pub async fn validate_decryption(
    context: &ValidationContext,
    encryption: &Arc<PostQuantumEncryption>,
) -> Result<ValidationStep, AuthError> {
    let encrypted_key_b64 = context.firestore_document.fields.get("encrypted_key")
        .and_then(|v| v.value_type.as_ref())
        .and_then(|vt| if let ValueType::StringValue(s) = vt { Some(s.as_str()) } else { None })
        .ok_or_else(|| AuthError {
            error: "missing_encrypted_key".to_string(),
            message: "Encrypted key not found in document".to_string(),
            code: 500,
        })?;

    let encrypted_key_bytes = general_purpose::STANDARD.decode(encrypted_key_b64)
        .map_err(|_| AuthError {
            error: "decode_error".to_string(),
            message: "Failed to decode encrypted key".to_string(),
            code: 500,
        })?;

    let decrypted_key_bytes = encryption.decrypt(&encrypted_key_bytes)
        .map_err(|_| {
            tracing::warn!("Failed to decrypt stored key with post-quantum encryption");
            AuthError {
                error: "decryption_failed".to_string(),
                message: "Failed to decrypt stored key".to_string(),
                code: 500,
            }
        })?;

    let _decrypted_key = String::from_utf8(decrypted_key_bytes)
        .map_err(|_| {
            tracing::warn!("Post-quantum decryption produced invalid UTF-8");
            AuthError {
                error: "invalid_utf8".to_string(),
                message: "Decrypted key contains invalid UTF-8".to_string(),
                code: 500,
            }
        })?;

    Ok(ValidationStep::Continue(context.clone()))
}

pub async fn validate_hash(
    context: &ValidationContext,
    encryption: &Arc<PostQuantumEncryption>,
) -> Result<ValidationStep, AuthError> {
    let encrypted_key_b64 = context.firestore_document.fields.get("encrypted_key")
        .and_then(|v| v.value_type.as_ref())
        .and_then(|vt| if let ValueType::StringValue(s) = vt { Some(s.as_str()) } else { None })
        .unwrap();

    let encrypted_key_bytes = general_purpose::STANDARD.decode(encrypted_key_b64).unwrap();
    let decrypted_key_bytes = encryption.decrypt(&encrypted_key_bytes).unwrap();
    let decrypted_key = String::from_utf8(decrypted_key_bytes).unwrap();
    
    let decrypted_hash = format!("{:x}", Sha256::digest(decrypted_key.as_bytes()));
    
    if decrypted_hash != context.key_hash {
        tracing::warn!("Post-quantum encrypted key validation failed - hash mismatch");
        return Ok(ValidationStep::Failed("Hash validation failed".to_string()));
    }

    Ok(ValidationStep::Continue(context.clone()))
}

pub async fn validate_expiration(context: &ValidationContext) -> Result<ValidationStep, AuthError> {
    let api_key = parse_firestore_document_to_api_key(&context.firestore_document)?;

    if !api_key.is_active {
        tracing::warn!("Attempt to use inactive API key: {}", api_key.id);
        return Ok(ValidationStep::Failed("API key is inactive".to_string()));
    }

    if let Some(expires_at) = api_key.expires_at {
        if Utc::now() > expires_at {
            tracing::warn!("Attempt to use expired API key: {}", api_key.id);
            return Ok(ValidationStep::Failed("API key has expired".to_string()));
        }
    }

    Ok(ValidationStep::Continue(context.clone()))
}

pub async fn validate_completion(context: &ValidationContext) -> Result<ValidationStep, AuthError> {
    let mut api_key = parse_firestore_document_to_api_key(&context.firestore_document)?;
    
    api_key.last_used = Some(Utc::now());
    api_key.usage_count += 1;

    let usage_info = UsageUpdateInfo {
        key_hash: context.key_hash.clone(),
        last_used: api_key.last_used.unwrap(),
        usage_count: api_key.usage_count,
    };

    let result = ValidationResult {
        api_key,
        needs_usage_update: true,
        usage_info: Some(usage_info),
    };

    Ok(ValidationStep::Complete(result))
}

pub fn parse_firestore_document_to_api_key(doc: &Document) -> Result<ApiKey, AuthError> {
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

    let created_at = chrono::TimeZone::timestamp_opt(&Utc, created_at_prost.seconds, created_at_prost.nanos as u32)
        .single()
        .ok_or_else(|| AuthError {
            error: "parse_error".to_string(),
            message: "Invalid created_at timestamp".to_string(),
            code: 500,
        })?;

    let expires_at = fields.get("expires_at")
        .and_then(|v| v.value_type.as_ref())
        .and_then(|vt| if let ValueType::TimestampValue(ts) = vt { Some(ts) } else { None })
        .map(|ts| chrono::TimeZone::timestamp_opt(&Utc, ts.seconds, ts.nanos as u32).single())
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
        .map(|ts| chrono::TimeZone::timestamp_opt(&Utc, ts.seconds, ts.nanos as u32).single())
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

pub async fn validate_hybrid_decryption(
    context: &ValidationContext,
    legacy: &Arc<PostQuantumEncryption>,
    hybrid: &Arc<HybridEncryption>,
) -> Result<ValidationStep, AuthError> {
    // First try to find versioned encrypted key (V2 hybrid format)
    if let Some(encrypted_key_versioned) = context.firestore_document.fields.get("encrypted_key_versioned")
        .and_then(|v| v.value_type.as_ref())
        .and_then(|vt| if let ValueType::StringValue(s) = vt { Some(s.as_str()) } else { None })
    {
        // Handle V2 hybrid format
        let encrypted_data_bytes = general_purpose::STANDARD.decode(encrypted_key_versioned)
            .map_err(|_| AuthError {
                error: "decode_error".to_string(),
                message: "Failed to decode versioned encrypted key".to_string(),
                code: 500,
            })?;

        // Deserialize the versioned encrypted data
        let versioned_data: VersionedEncryptedData = 
            serde_json::from_slice(&encrypted_data_bytes).map_err(|e| AuthError {
                error: "deserialization_error".to_string(),
                message: format!("Failed to deserialize versioned encrypted data: {}", e),
                code: 500,
            })?;

        // Decrypt using hybrid encryption
        let decrypted_key_bytes = hybrid.decrypt(&versioned_data)
            .map_err(|_| {
                tracing::warn!("Failed to decrypt stored key with hybrid encryption (V2)");
                AuthError {
                    error: "decryption_failed".to_string(),
                    message: "Failed to decrypt stored key with hybrid encryption".to_string(),
                    code: 500,
                }
            })?;

        let _decrypted_key = String::from_utf8(decrypted_key_bytes)
            .map_err(|_| {
                tracing::warn!("Hybrid decryption produced invalid UTF-8");
                AuthError {
                    error: "invalid_utf8".to_string(),
                    message: "Decrypted key contains invalid UTF-8".to_string(),
                    code: 500,
                }
            })?;

        tracing::debug!("Successfully decrypted API key using hybrid encryption (V2)");
        Ok(ValidationStep::Continue(context.clone()))
    }
    // Fall back to legacy format
    else if let Some(encrypted_key) = context.firestore_document.fields.get("encrypted_key")
        .and_then(|v| v.value_type.as_ref())
        .and_then(|vt| if let ValueType::StringValue(s) = vt { Some(s.as_str()) } else { None })
    {
        // Handle legacy format
        let encrypted_key_bytes = general_purpose::STANDARD.decode(encrypted_key)
            .map_err(|_| AuthError {
                error: "decode_error".to_string(),
                message: "Failed to decode encrypted key".to_string(),
                code: 500,
            })?;

        let decrypted_key_bytes = legacy.decrypt(&encrypted_key_bytes)
            .map_err(|_| {
                tracing::warn!("Failed to decrypt stored key with legacy post-quantum encryption");
                AuthError {
                    error: "decryption_failed".to_string(),
                    message: "Failed to decrypt stored key".to_string(),
                    code: 500,
                }
            })?;

        let _decrypted_key = String::from_utf8(decrypted_key_bytes)
            .map_err(|_| {
                tracing::warn!("Legacy decryption produced invalid UTF-8");
                AuthError {
                    error: "invalid_utf8".to_string(),
                    message: "Decrypted key contains invalid UTF-8".to_string(),
                    code: 500,
                }
            })?;

        tracing::debug!("Successfully decrypted API key using legacy encryption");
        Ok(ValidationStep::Continue(context.clone()))
    }
    else {
        Err(AuthError {
            error: "missing_encrypted_key".to_string(),
            message: "Neither encrypted_key_versioned nor encrypted_key found in document".to_string(),
            code: 500,
        })
    }
}

pub async fn validate_hybrid_hash(
    context: &ValidationContext,
    legacy: &Arc<PostQuantumEncryption>,
    hybrid: &Arc<HybridEncryption>,
) -> Result<ValidationStep, AuthError> {
    // First try versioned encrypted key (V2 hybrid format)
    if let Some(encrypted_key_versioned) = context.firestore_document.fields.get("encrypted_key_versioned")
        .and_then(|v| v.value_type.as_ref())
        .and_then(|vt| if let ValueType::StringValue(s) = vt { Some(s.as_str()) } else { None })
    {
        // Handle V2 hybrid format
        let encrypted_data_bytes = general_purpose::STANDARD.decode(encrypted_key_versioned)
            .map_err(|_| AuthError {
                error: "decode_error".to_string(),
                message: "Failed to decode versioned encrypted key".to_string(),
                code: 500,
            })?;

        // Deserialize the versioned encrypted data
        let versioned_data: VersionedEncryptedData = 
            serde_json::from_slice(&encrypted_data_bytes).map_err(|e| AuthError {
                error: "deserialization_error".to_string(),
                message: format!("Failed to deserialize versioned encrypted data: {}", e),
                code: 500,
            })?;

        // Decrypt using hybrid encryption
        let decrypted_key_bytes = hybrid.decrypt(&versioned_data)
            .map_err(|_| {
                tracing::warn!("Failed to decrypt stored key with hybrid encryption for hash validation");
                AuthError {
                    error: "decryption_failed".to_string(),
                    message: "Failed to decrypt stored key with hybrid encryption".to_string(),
                    code: 500,
                }
            })?;

        let decrypted_key = String::from_utf8(decrypted_key_bytes)
            .map_err(|_| {
                tracing::warn!("Hybrid decryption produced invalid UTF-8 for hash validation");
                AuthError {
                    error: "invalid_utf8".to_string(),
                    message: "Decrypted key contains invalid UTF-8".to_string(),
                    code: 500,
                }
            })?;

        let decrypted_hash = format!("{:x}", Sha256::digest(decrypted_key.as_bytes()));
        
        if decrypted_hash != context.key_hash {
            tracing::warn!("Hybrid encrypted key validation failed - hash mismatch");
            return Ok(ValidationStep::Failed("Hash validation failed".to_string()));
        }

        tracing::debug!("Hash validation successful for hybrid encrypted key");
        Ok(ValidationStep::Continue(context.clone()))
    }
    // Fall back to legacy format
    else if let Some(encrypted_key) = context.firestore_document.fields.get("encrypted_key")
        .and_then(|v| v.value_type.as_ref())
        .and_then(|vt| if let ValueType::StringValue(s) = vt { Some(s.as_str()) } else { None })
    {
        // Handle legacy format
        let encrypted_key_bytes = general_purpose::STANDARD.decode(encrypted_key)
            .map_err(|_| AuthError {
                error: "decode_error".to_string(),
                message: "Failed to decode encrypted key".to_string(),
                code: 500,
            })?;

        let decrypted_key_bytes = legacy.decrypt(&encrypted_key_bytes)
            .map_err(|_| {
                tracing::warn!("Failed to decrypt stored key with legacy encryption for hash validation");
                AuthError {
                    error: "decryption_failed".to_string(),
                    message: "Failed to decrypt stored key".to_string(),
                    code: 500,
                }
            })?;

        let decrypted_key = String::from_utf8(decrypted_key_bytes)
            .map_err(|_| {
                tracing::warn!("Legacy decryption produced invalid UTF-8 for hash validation");
                AuthError {
                    error: "invalid_utf8".to_string(),
                    message: "Decrypted key contains invalid UTF-8".to_string(),
                    code: 500,
                }
            })?;
        
        let decrypted_hash = format!("{:x}", Sha256::digest(decrypted_key.as_bytes()));
        
        if decrypted_hash != context.key_hash {
            tracing::warn!("Legacy encrypted key validation failed - hash mismatch");
            return Ok(ValidationStep::Failed("Hash validation failed".to_string()));
        }

        tracing::debug!("Hash validation successful for legacy encrypted key");
        Ok(ValidationStep::Continue(context.clone()))
    }
    else {
        Err(AuthError {
            error: "missing_encrypted_key".to_string(),
            message: "Neither encrypted_key_versioned nor encrypted_key found in document".to_string(),
            code: 500,
        })
    }
}