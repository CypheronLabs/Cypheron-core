use crate::security::auth::{AuthError, ApiKey};
use chrono::{DateTime, Utc};
use gcloud_sdk::google::firestore::v1::Document;

pub mod pipeline;
pub mod validators;

pub use pipeline::ValidationPipeline;

#[derive(Debug, Clone)]
pub struct ValidationContext {
    pub key_hash: String,
    pub provided_key: String,
    pub firestore_document: Document,
}

#[derive(Debug)]
pub struct ValidationResult {
    pub api_key: ApiKey,
    pub needs_usage_update: bool,
    pub usage_info: Option<UsageUpdateInfo>,
}

#[derive(Debug)]
pub struct UsageUpdateInfo {
    pub key_hash: String,
    pub last_used: DateTime<Utc>,
    pub usage_count: u64,
}

#[derive(Debug, Clone)]
pub enum ValidatorType {
    DocumentParsing,
    Decryption(std::sync::Arc<crate::security::auth::PostQuantumEncryption>),
    Hash(std::sync::Arc<crate::security::auth::PostQuantumEncryption>),
    HybridDecryption {
        legacy: std::sync::Arc<crate::security::auth::PostQuantumEncryption>,
        hybrid: std::sync::Arc<crate::security::auth::hybrid_encryption::HybridEncryption>,
    },
    HybridHash {
        legacy: std::sync::Arc<crate::security::auth::PostQuantumEncryption>,
        hybrid: std::sync::Arc<crate::security::auth::hybrid_encryption::HybridEncryption>,
    },
    Expiration,
    Completion,
}

impl ValidatorType {
    pub async fn validate(&self, context: &ValidationContext) -> Result<ValidationStep, AuthError> {
        match self {
            ValidatorType::DocumentParsing => {
                let _api_key = validators::parse_firestore_document_to_api_key(&context.firestore_document)?;
                Ok(ValidationStep::Continue(context.clone()))
            }
            ValidatorType::Decryption(encryption) => {
                validators::validate_decryption(context, encryption).await
            }
            ValidatorType::Hash(encryption) => {
                validators::validate_hash(context, encryption).await
            }
            ValidatorType::HybridDecryption { legacy, hybrid } => {
                validators::validate_hybrid_decryption(context, legacy, hybrid).await
            }
            ValidatorType::HybridHash { legacy, hybrid } => {
                validators::validate_hybrid_hash(context, legacy, hybrid).await
            }
            ValidatorType::Expiration => {
                validators::validate_expiration(context).await
            }
            ValidatorType::Completion => {
                validators::validate_completion(context).await
            }
        }
    }
}

#[derive(Debug)]
pub enum ValidationStep {
    Continue(ValidationContext),
    Complete(ValidationResult),
    Failed(String),
}

#[derive(Debug)]
pub enum ValidationError {
    DecryptionFailed(String),
    HashMismatch,
    KeyExpired(DateTime<Utc>),
    KeyInactive,
    DatabaseError(String),
    ParseError(String),
}

impl From<ValidationError> for AuthError {
    fn from(error: ValidationError) -> Self {
        match error {
            ValidationError::DecryptionFailed(msg) => AuthError {
                error: "decryption_error".to_string(),
                message: msg,
                code: 500,
            },
            ValidationError::HashMismatch => AuthError {
                error: "invalid_key".to_string(),
                message: "Key validation failed".to_string(),
                code: 401,
            },
            ValidationError::KeyExpired(exp_date) => AuthError {
                error: "key_expired".to_string(),
                message: format!("API key expired on {}", exp_date.format("%Y-%m-%d %H:%M:%S UTC")),
                code: 401,
            },
            ValidationError::KeyInactive => AuthError {
                error: "key_inactive".to_string(),
                message: "API key is disabled".to_string(),
                code: 401,
            },
            ValidationError::DatabaseError(msg) => AuthError {
                error: "database_error".to_string(),
                message: msg,
                code: 500,
            },
            ValidationError::ParseError(msg) => AuthError {
                error: "parse_error".to_string(),
                message: msg,
                code: 500,
            },
        }
    }
}