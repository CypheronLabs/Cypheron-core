use gcloud_sdk::google::firestore::v1::firestore_client::FirestoreClient;
use gcloud_sdk::GoogleApi;
use std::sync::Arc;

use super::{
    encryption::PostQuantumEncryption,
    errors::AuthError,
    models::ApiKey,
    permissions::check_permission,
    repository::FirestoreApiKeyRepository,
    validation::KeyValidator,
};
use crate::security::repository::ApiKeyRepository;

#[derive(Clone)]
pub struct ApiKeyStore {
    repository: Arc<FirestoreApiKeyRepository>,
    key_validator: Arc<KeyValidator>,
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

        let validation_pipeline = crate::security::validation::ValidationPipeline::new_default(
            Arc::new(encryption.clone()),
        );

        let key_validator = Arc::new(KeyValidator::new(
            firestore_repo as Arc<dyn ApiKeyRepository>,
            validation_pipeline,
        ));

        Ok(Self {
            repository,
            key_validator,
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

    pub async fn check_permission(&self, key: &str, resource: &str) -> bool {
        if let Some(api_key) = self.validate_key(key).await {
            check_permission(&api_key, resource)
        } else {
            false
        }
    }
}