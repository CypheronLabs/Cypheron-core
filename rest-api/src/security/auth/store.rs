use std::sync::Arc;

use gcloud_sdk::google::firestore::v1::firestore_client::FirestoreClient;
use gcloud_sdk::GoogleApi;

use crate::security::api_key::UpdateAPIKeyRequest;
use crate::security::repository::LegacyApiKeyRepository;
use super::{
    encryption::PostQuantumEncryption,
    errors::AuthError,
    hybrid_encryption::HybridEncryption,
    models::ApiKey,
    permissions::check_permission,
    repository::FirestoreApiKeyRepository,
    validation::KeyValidator,
};

#[derive(Clone)]
pub struct ApiKeyStore {
    repository: Arc<FirestoreApiKeyRepository>,
    key_validator: Arc<KeyValidator>,
    hybrid_encryption: Arc<HybridEncryption>,
}

impl ApiKeyStore {
    pub async fn new_with_firestore(project_id: &str) -> Result<Self, AuthError> {
        let collection_name = std::env::var("FIRESTORE_COLLECTION")
            .unwrap_or_else(|_| "api_keys".to_string());

        let password = std::env::var("PQ_ENCRYPTION_PASSWORD").map_err(|_| AuthError {
            error: "missing_encryption_password".to_string(),
            message: "PQ_ENCRYPTION_PASSWORD environment variable is required for secure operation".to_string(),
            code: 500,
        })?;

        let encryption = PostQuantumEncryption::from_password(&password)?;
        
        // Create hybrid encryption with legacy support for existing keys
        let hybrid_encryption = Arc::new(HybridEncryption::with_legacy_support(&password)?);

        let firestore_client = Arc::new(
            GoogleApi::from_function(
                FirestoreClient::new,
                "https://firestore.googleapis.com",
                None,
            )
            .await
            .map_err(|e| AuthError {
                error: "firestore_init_error".to_string(),
                message: format!("Failed to initialize Firestore client: {}", e),
                code: 500,
            })?,
        );

        let repository = Arc::new(FirestoreApiKeyRepository::new(
            firestore_client.clone(),
            project_id.to_string(),
            "(default)".to_string(),
            collection_name.clone(),
            encryption.clone(),
        ));

        let firestore_repo = Arc::new(crate::security::repository::FirestoreRepository::new(
            firestore_client.clone(),
            project_id.to_string(),
            "(default)".to_string(),
            collection_name.clone(),
        ));

        let validation_pipeline = crate::security::validation::ValidationPipeline::new_hybrid(
            Arc::new(encryption.clone()),
            hybrid_encryption.clone(),
        );

        let key_validator = Arc::new(KeyValidator::new(
            firestore_repo as Arc<dyn LegacyApiKeyRepository>,
            validation_pipeline,
        ));

        Ok(Self {
            repository,
            key_validator,
            hybrid_encryption,
        })
    }

    pub async fn validate_key(&self, key: &str) -> Option<ApiKey> {
        self.key_validator.validate_key(key).await
    }

    pub async fn store_api_key(&self, api_key: &ApiKey, raw_key: &str) -> Result<(), AuthError> {
        self.repository.store_api_key(api_key, raw_key).await
    }

    pub async fn delete_api_key(&self, key_hash: &str) -> Result<(), AuthError> {
        self.repository.delete_api_key(key_hash).await
    }

    pub async fn get_api_key(&self, key_hash: &str) -> Result<Option<ApiKey>, AuthError> {
        self.repository.get_api_key(key_hash).await
    }

    pub async fn list_api_keys(&self) -> Result<Vec<ApiKey>, AuthError> {
        self.repository.list_api_keys().await
    }

    pub async fn check_permission(&self, key: &str, resource: &str) -> bool {
        if let Some(api_key) = self.validate_key(key).await {
            check_permission(&api_key, resource)
        } else {
            false
        }
    }

    pub async fn store_api_key_hybrid(&self, api_key: &ApiKey, raw_key: &str) -> Result<(), AuthError> {
        let encrypted_data = self.hybrid_encryption.encrypt(raw_key.as_bytes())?;
        
        let serialized_data = serde_json::to_vec(&encrypted_data).map_err(|e| AuthError {
            error: "serialization_error".to_string(),
            message: format!("Failed to serialize versioned encrypted data: {}", e),
            code: 500,
        })?;

        self.repository.store_api_key_versioned(api_key, &serialized_data).await?;

        tracing::info!("Stored API key with hybrid encryption (V2): {} ({})", api_key.name, api_key.id);
        Ok(())
    }

    pub fn get_hybrid_encryption(&self) -> Arc<HybridEncryption> {
        self.hybrid_encryption.clone()
    }

    

    pub async fn update_api_key(&self, key_id: &str, update_request: &UpdateAPIKeyRequest) -> Result<ApiKey, AuthError> {
        self.repository.update_api_key(key_id, update_request).await
    }
    
    pub async fn revoke_api_key(&self, key_id: &str) -> Result<(), AuthError> {
        self.repository.delete_api_key(key_id).await
    }
}