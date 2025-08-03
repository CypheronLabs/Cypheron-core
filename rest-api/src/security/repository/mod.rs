use crate::security::auth::AuthError;
use crate::security::validation::UsageUpdateInfo;
use gcloud_sdk::google::firestore::v1::Document;
use std::sync::Arc;

pub mod firestore_repository;

pub use firestore_repository::FirestoreRepository;

#[async_trait::async_trait]
pub trait ApiKeyRepository: Send + Sync {
    async fn get_key_document(&self, key_hash: &str) -> Result<Option<Document>, AuthError>;
    async fn update_usage(&self, usage_info: &UsageUpdateInfo) -> Result<(), AuthError>;
}

pub type ApiKeyRepositoryRef = Arc<dyn ApiKeyRepository>;