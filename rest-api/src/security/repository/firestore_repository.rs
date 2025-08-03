use super::ApiKeyRepository;
use crate::security::auth::AuthError;
use crate::security::validation::UsageUpdateInfo;
use gcloud_sdk::google::firestore::v1::{
    Document, DocumentMask, GetDocumentRequest, UpdateDocumentRequest, Value,
};
use gcloud_sdk::google::firestore::v1::firestore_client::FirestoreClient;
use gcloud_sdk::google::firestore::v1::value::ValueType;
use gcloud_sdk::{GoogleApi, GoogleAuthMiddleware};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::SystemTime;

pub struct FirestoreRepository {
    firestore_client: Arc<GoogleApi<FirestoreClient<GoogleAuthMiddleware>>>,
    project_id: String,
    database_id: String,
    collection_name: String,
}

impl FirestoreRepository {
    pub fn new(
        firestore_client: Arc<GoogleApi<FirestoreClient<GoogleAuthMiddleware>>>,
        project_id: String,
        database_id: String,
        collection_name: String,
    ) -> Self {
        Self {
            firestore_client,
            project_id,
            database_id,
            collection_name,
        }
    }
}

#[async_trait::async_trait]
impl ApiKeyRepository for FirestoreRepository {
    async fn get_key_document(&self, key_hash: &str) -> Result<Option<Document>, AuthError> {
        let request = GetDocumentRequest {
            name: format!(
                "projects/{}/databases/{}/documents/{}/{}",
                self.project_id, self.database_id, self.collection_name, key_hash
            ),
            mask: None,
            consistency_selector: None,
        };

        match self.firestore_client.get().get_document(request).await {
            Ok(response) => Ok(Some(response.into_inner())),
            Err(e) => {
                if e.code() == gcloud_sdk::tonic::Code::NotFound {
                    Ok(None)
                } else {
                    tracing::error!("Firestore validation error: {}", e);
                    Err(AuthError {
                        error: "database_error".to_string(),
                        message: format!("Database error: {}", e),
                        code: 500,
                    })
                }
            }
        }
    }

    async fn update_usage(&self, usage_info: &UsageUpdateInfo) -> Result<(), AuthError> {
        let mut update_fields = HashMap::new();
        
        update_fields.insert("last_used".to_string(), Value {
            value_type: Some(ValueType::TimestampValue(
                gcloud_sdk::prost_types::Timestamp::from(SystemTime::from(usage_info.last_used))
            )),
        });
        
        update_fields.insert("usage_count".to_string(), Value {
            value_type: Some(ValueType::IntegerValue(usage_info.usage_count as i64)),
        });

        let request = UpdateDocumentRequest {
            document: Some(Document {
                name: format!(
                    "projects/{}/databases/{}/documents/{}/{}",
                    self.project_id, self.database_id, self.collection_name, usage_info.key_hash
                ),
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
            return Err(AuthError {
                error: "database_update_error".to_string(),
                message: format!("Failed to update usage tracking: {}", e),
                code: 500,
            });
        }

        Ok(())
    }
}