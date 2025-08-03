use sha2::{Digest, Sha256};
use std::sync::Arc;

use super::models::ApiKey;
use crate::security::repository::ApiKeyRepository;

pub struct KeyValidator {
    repository: Arc<dyn ApiKeyRepository>,
    validation_pipeline: crate::security::validation::ValidationPipeline,
}

impl KeyValidator {
    pub fn new(
        repository: Arc<dyn ApiKeyRepository>,
        validation_pipeline: crate::security::validation::ValidationPipeline,
    ) -> Self {
        Self {
            repository,
            validation_pipeline,
        }
    }

    pub async fn validate_key(&self, key: &str) -> Option<ApiKey> {
        let key_hash = format!("{:x}", Sha256::digest(key.as_bytes()));

        let document = match self.repository.get_key_document(&key_hash).await {
            Ok(Some(doc)) => doc,
            Ok(None) => {
                tracing::warn!("API key not found: {}", &key_hash[..8]);
                return None;
            }
            Err(e) => {
                tracing::error!("Database error during key validation: {}", e.message);
                return None;
            }
        };

        let context = crate::security::validation::ValidationContext {
            key_hash,
            provided_key: key.to_string(),
            firestore_document: document,
        };

        match self.validation_pipeline.validate(context).await {
            Ok(result) => {
                if result.needs_usage_update {
                    if let Some(usage_info) = result.usage_info {
                        if let Err(e) = self.repository.update_usage(&usage_info).await {
                            tracing::warn!("Failed to update usage tracking: {}", e.message);
                        }
                    }
                }
                Some(result.api_key)
            }
            Err(e) => {
                tracing::warn!("Key validation failed: {}", e.message);
                None
            }
        }
    }
}