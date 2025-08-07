use crate::security::auth::{AuthError, ApiKey};
use crate::security::validation::UsageUpdateInfo;
use chrono::{DateTime, Utc};
use gcloud_sdk::google::firestore::v1::Document;
use std::sync::Arc;
use uuid::Uuid;

pub mod firestore_repository;
pub mod postgres_repository;

pub use firestore_repository::FirestoreRepository;
pub use postgres_repository::PostgresRepository;

/// Audit log entry for comprehensive security monitoring
#[derive(Debug, Clone)]
pub struct AuditLogEntry {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub event_type: String,
    pub api_key_id: Option<Uuid>,
    pub api_key_hash: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub request_path: Option<String>,
    pub request_method: Option<String>,
    pub response_status: Option<i32>,
    pub response_time_ms: Option<i32>,
    pub metadata: serde_json::Value,
    pub risk_level: String,
}

/// Analytics entry for API usage tracking
#[derive(Debug, Clone)]
pub struct AnalyticsEntry {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub api_key_id: Option<Uuid>,
    pub endpoint: String,
    pub method: String,
    pub response_time_ms: i32,
    pub request_size_bytes: Option<i32>,
    pub response_size_bytes: Option<i32>,
    pub success: bool,
    pub error_type: Option<String>,
    pub region: Option<String>,
    pub client_type: Option<String>,
    pub metrics: serde_json::Value,
}

/// Enhanced repository trait supporting multiple backends
#[async_trait::async_trait]
pub trait ApiKeyRepository: Send + Sync {
    // Core API Key operations
    async fn store_api_key(&self, api_key: &ApiKey, raw_key: &str) -> Result<(), AuthError>;
    async fn get_api_key_by_hash(&self, key_hash: &str) -> Result<Option<ApiKey>, AuthError>;
    async fn update_api_key(&self, api_key: &ApiKey) -> Result<(), AuthError>;
    async fn delete_api_key(&self, key_hash: &str) -> Result<(), AuthError>;
    async fn list_api_keys(&self, limit: Option<i32>, offset: Option<i32>) -> Result<Vec<ApiKey>, AuthError>;
    
    // Usage tracking
    async fn update_usage(&self, usage_info: &UsageUpdateInfo) -> Result<(), AuthError>;
    
    // Audit logging
    async fn log_audit_event(&self, entry: &AuditLogEntry) -> Result<(), AuthError>;
    async fn get_audit_logs(
        &self, 
        api_key_id: Option<Uuid>, 
        start_time: Option<DateTime<Utc>>,
        end_time: Option<DateTime<Utc>>,
        limit: Option<i32>
    ) -> Result<Vec<AuditLogEntry>, AuthError>;
    
    // Analytics
    async fn record_analytics(&self, entry: &AnalyticsEntry) -> Result<(), AuthError>;
    
    // Health check
    async fn health_check(&self) -> Result<(), AuthError>;
}

/// Legacy trait for backward compatibility with existing validation system
#[async_trait::async_trait]
pub trait LegacyApiKeyRepository: Send + Sync {
    async fn get_key_document(&self, key_hash: &str) -> Result<Option<Document>, AuthError>;
    async fn update_usage(&self, usage_info: &UsageUpdateInfo) -> Result<(), AuthError>;
}

pub type ApiKeyRepositoryRef = Arc<dyn ApiKeyRepository>;
pub type LegacyApiKeyRepositoryRef = Arc<dyn LegacyApiKeyRepository>;