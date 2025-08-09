use base64::{engine::general_purpose, Engine as _};
use chrono::{Utc, TimeZone};
use gcloud_sdk::google::firestore::v1::{
    firestore_client::FirestoreClient, value::ValueType, ArrayValue, CreateDocumentRequest,
    DeleteDocumentRequest, Document, Value, GetDocumentRequest, ListDocumentsRequest,
};
use gcloud_sdk::{GoogleApi, GoogleAuthMiddleware};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::SystemTime;
use uuid::Uuid;

use super::{encryption::PostQuantumEncryption, errors::AuthError, models::ApiKey};

#[derive(Clone)]
pub struct FirestoreApiKeyRepository {
    firestore_client: Arc<GoogleApi<FirestoreClient<GoogleAuthMiddleware>>>,
    project_id: String,
    database_id: String,
    collection_name: String,
    encryption: PostQuantumEncryption,
}

impl FirestoreApiKeyRepository {
    pub fn new(
        firestore_client: Arc<GoogleApi<FirestoreClient<GoogleAuthMiddleware>>>,
        project_id: String,
        database_id: String,
        collection_name: String,
        encryption: PostQuantumEncryption,
    ) -> Self {
        Self {
            firestore_client,
            project_id,
            database_id,
            collection_name,
            encryption,
        }
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

    /// Store API key with versioned encrypted data (for hybrid encryption)
    pub async fn store_api_key_versioned(&self, api_key: &ApiKey, versioned_encrypted_data: &[u8]) -> Result<(), AuthError> {
        let encrypted_data_b64 = general_purpose::STANDARD.encode(versioned_encrypted_data);

        let permissions_values: Vec<Value> = api_key
            .permissions
            .iter()
            .map(|p| Value {
                value_type: Some(ValueType::StringValue(p.clone())),
            })
            .collect();

        let mut fields = HashMap::new();

        fields.insert(
            "id".to_string(),
            Value {
                value_type: Some(ValueType::StringValue(api_key.id.to_string())),
            },
        );

        fields.insert(
            "name".to_string(),
            Value {
                value_type: Some(ValueType::StringValue(api_key.name.clone())),
            },
        );

        fields.insert(
            "key_hash".to_string(),
            Value {
                value_type: Some(ValueType::StringValue(api_key.key_hash.clone())),
            },
        );

        // Store versioned encrypted data instead of legacy format
        fields.insert(
            "encrypted_key_versioned".to_string(),
            Value {
                value_type: Some(ValueType::StringValue(encrypted_data_b64)),
            },
        );

        fields.insert(
            "permissions".to_string(),
            Value {
                value_type: Some(ValueType::ArrayValue(ArrayValue {
                    values: permissions_values,
                })),
            },
        );

        fields.insert(
            "rate_limit".to_string(),
            Value {
                value_type: Some(ValueType::IntegerValue(api_key.rate_limit as i64)),
            },
        );

        fields.insert(
            "created_at".to_string(),
            Value {
                value_type: Some(ValueType::TimestampValue(
                    gcloud_sdk::prost_types::Timestamp::from(SystemTime::from(api_key.created_at)),
                )),
            },
        );

        if let Some(expires_at) = api_key.expires_at {
            fields.insert(
                "expires_at".to_string(),
                Value {
                    value_type: Some(ValueType::TimestampValue(
                        gcloud_sdk::prost_types::Timestamp::from(SystemTime::from(expires_at)),
                    )),
                },
            );
        } else {
            fields.insert(
                "expires_at".to_string(),
                Value {
                    value_type: Some(ValueType::NullValue(0)),
                },
            );
        }

        fields.insert(
            "is_active".to_string(),
            Value {
                value_type: Some(ValueType::BooleanValue(api_key.is_active)),
            },
        );

        if let Some(last_used) = api_key.last_used {
            fields.insert(
                "last_used".to_string(),
                Value {
                    value_type: Some(ValueType::TimestampValue(
                        gcloud_sdk::prost_types::Timestamp::from(SystemTime::from(last_used)),
                    )),
                },
            );
        } else {
            fields.insert(
                "last_used".to_string(),
                Value {
                    value_type: Some(ValueType::NullValue(0)),
                },
            );
        }

        fields.insert(
            "usage_count".to_string(),
            Value {
                value_type: Some(ValueType::IntegerValue(api_key.usage_count as i64)),
            },
        );

        fields.insert(
            "encryption_version".to_string(),
            Value {
                value_type: Some(ValueType::StringValue("V2".to_string())),
            },
        );

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
            name: format!(
                "projects/{}/databases/{}/documents/{}/{}",
                self.project_id, self.database_id, self.collection_name, key_hash
            ),
            current_document: None,
        };

        self.firestore_client.get().delete_document(request).await.map_err(|e| AuthError {
            error: "firestore_delete_error".to_string(),
            message: format!("Failed to delete document: {}", e),
            code: 500,
        })?;

        Ok(())
    }

    pub async fn get_api_key(&self, key_hash: &str) -> Result<Option<ApiKey>, AuthError> {
        let request = GetDocumentRequest {
            name: format!(
                "projects/{}/databases/{}/documents/{}/{}",
                self.project_id, self.database_id, self.collection_name, key_hash
            ),
            mask: None,
            consistency_selector: None,
        };

        match self.firestore_client.get().get_document(request).await {
            Ok(response) => {
                let document = response.into_inner();
                let api_key = self.firestore_document_to_api_key(&document)?;
                Ok(Some(api_key))
            }
            Err(e) => {
                // Check if error is "not found" - this is expected behavior
                let error_message = format!("{}", e);
                if error_message.contains("NOT_FOUND") {
                    Ok(None)
                } else {
                    Err(AuthError {
                        error: "firestore_get_error".to_string(),
                        message: format!("Failed to get document: {}", e),
                        code: 500,
                    })
                }
            }
        }
    }

    pub async fn list_api_keys(&self) -> Result<Vec<ApiKey>, AuthError> {
        let request = ListDocumentsRequest {
            parent: format!("projects/{}/databases/{}/documents", self.project_id, self.database_id),
            collection_id: self.collection_name.clone(),
            page_size: 100, // Reasonable limit for admin operations
            page_token: String::new(),
            order_by: String::new(),
            mask: None,
            show_missing: false,
            consistency_selector: None,
        };

        let response = self.firestore_client.get().list_documents(request).await.map_err(|e| AuthError {
            error: "firestore_list_error".to_string(),
            message: format!("Failed to list documents: {}", e),
            code: 500,
        })?;

        let documents = response.into_inner().documents;
        let mut api_keys = Vec::new();

        for document in documents {
            match self.firestore_document_to_api_key(&document) {
                Ok(api_key) => api_keys.push(api_key),
                Err(e) => {
                    tracing::warn!("Failed to parse API key document: {}", e.message);
                    // Continue processing other documents instead of failing the entire operation
                }
            }
        }

        Ok(api_keys)
    }

    fn api_key_to_firestore_fields(
        &self,
        api_key: &ApiKey,
        raw_key: &str,
    ) -> Result<HashMap<String, Value>, AuthError> {
        let encrypted_key = self.encryption.encrypt(raw_key.as_bytes())?;
        let encrypted_key_b64 = general_purpose::STANDARD.encode(&encrypted_key);

        let permissions_values: Vec<Value> = api_key
            .permissions
            .iter()
            .map(|p| Value {
                value_type: Some(ValueType::StringValue(p.clone())),
            })
            .collect();

        let mut fields = HashMap::new();

        fields.insert(
            "id".to_string(),
            Value {
                value_type: Some(ValueType::StringValue(api_key.id.to_string())),
            },
        );

        fields.insert(
            "name".to_string(),
            Value {
                value_type: Some(ValueType::StringValue(api_key.name.clone())),
            },
        );

        fields.insert(
            "key_hash".to_string(),
            Value {
                value_type: Some(ValueType::StringValue(api_key.key_hash.clone())),
            },
        );

        fields.insert(
            "encrypted_key".to_string(),
            Value {
                value_type: Some(ValueType::StringValue(encrypted_key_b64)),
            },
        );

        fields.insert(
            "permissions".to_string(),
            Value {
                value_type: Some(ValueType::ArrayValue(ArrayValue {
                    values: permissions_values,
                })),
            },
        );

        fields.insert(
            "rate_limit".to_string(),
            Value {
                value_type: Some(ValueType::IntegerValue(api_key.rate_limit as i64)),
            },
        );

        fields.insert(
            "created_at".to_string(),
            Value {
                value_type: Some(ValueType::TimestampValue(
                    gcloud_sdk::prost_types::Timestamp::from(SystemTime::from(api_key.created_at)),
                )),
            },
        );

        if let Some(expires_at) = api_key.expires_at {
            fields.insert(
                "expires_at".to_string(),
                Value {
                    value_type: Some(ValueType::TimestampValue(
                        gcloud_sdk::prost_types::Timestamp::from(SystemTime::from(expires_at)),
                    )),
                },
            );
        } else {
            fields.insert(
                "expires_at".to_string(),
                Value {
                    value_type: Some(ValueType::NullValue(0)),
                },
            );
        }

        fields.insert(
            "is_active".to_string(),
            Value {
                value_type: Some(ValueType::BooleanValue(api_key.is_active)),
            },
        );

        if let Some(last_used) = api_key.last_used {
            fields.insert(
                "last_used".to_string(),
                Value {
                    value_type: Some(ValueType::TimestampValue(
                        gcloud_sdk::prost_types::Timestamp::from(SystemTime::from(last_used)),
                    )),
                },
            );
        } else {
            fields.insert(
                "last_used".to_string(),
                Value {
                    value_type: Some(ValueType::NullValue(0)),
                },
            );
        }

        fields.insert(
            "usage_count".to_string(),
            Value {
                value_type: Some(ValueType::IntegerValue(api_key.usage_count as i64)),
            },
        );

        Ok(fields)
    }

    pub fn firestore_document_to_api_key(&self, doc: &Document) -> Result<ApiKey, AuthError> {
        let fields = &doc.fields;

        let id_str = fields
            .get("id")
            .and_then(|v| v.value_type.as_ref())
            .and_then(|vt| {
                if let ValueType::StringValue(s) = vt {
                    Some(s.as_str())
                } else {
                    None
                }
            })
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

        let name = fields
            .get("name")
            .and_then(|v| v.value_type.as_ref())
            .and_then(|vt| {
                if let ValueType::StringValue(s) = vt {
                    Some(s.clone())
                } else {
                    None
                }
            })
            .ok_or_else(|| AuthError {
                error: "parse_error".to_string(),
                message: "Missing or invalid name field".to_string(),
                code: 500,
            })?;

        let key_hash = fields
            .get("key_hash")
            .and_then(|v| v.value_type.as_ref())
            .and_then(|vt| {
                if let ValueType::StringValue(s) = vt {
                    Some(s.clone())
                } else {
                    None
                }
            })
            .ok_or_else(|| AuthError {
                error: "parse_error".to_string(),
                message: "Missing or invalid key_hash field".to_string(),
                code: 500,
            })?;

        let permissions = fields
            .get("permissions")
            .and_then(|v| v.value_type.as_ref())
            .and_then(|vt| {
                if let ValueType::ArrayValue(a) = vt {
                    Some(a)
                } else {
                    None
                }
            })
            .ok_or_else(|| AuthError {
                error: "parse_error".to_string(),
                message: "Missing or invalid permissions field".to_string(),
                code: 500,
            })?
            .values
            .iter()
            .filter_map(|v| v.value_type.as_ref())
            .filter_map(|vt| {
                if let ValueType::StringValue(s) = vt {
                    Some(s.clone())
                } else {
                    None
                }
            })
            .collect();

        let rate_limit = fields
            .get("rate_limit")
            .and_then(|v| v.value_type.as_ref())
            .and_then(|vt| {
                if let ValueType::IntegerValue(i) = vt {
                    Some(*i as u32)
                } else {
                    None
                }
            })
            .ok_or_else(|| AuthError {
                error: "parse_error".to_string(),
                message: "Missing or invalid rate_limit field".to_string(),
                code: 500,
            })?;

        let created_at_prost = fields
            .get("created_at")
            .and_then(|v| v.value_type.as_ref())
            .and_then(|vt| {
                if let ValueType::TimestampValue(ts) = vt {
                    Some(ts)
                } else {
                    None
                }
            })
            .ok_or_else(|| AuthError {
                error: "parse_error".to_string(),
                message: "Missing or invalid created_at field".to_string(),
                code: 500,
            })?;

        let created_at = Utc
            .timestamp_opt(
                created_at_prost.seconds,
                created_at_prost.nanos as u32,
            )
            .single()
            .ok_or_else(|| AuthError {
                error: "parse_error".to_string(),
                message: "Invalid created_at timestamp".to_string(),
                code: 500,
            })?;

        let expires_at = fields
            .get("expires_at")
            .and_then(|v| v.value_type.as_ref())
            .and_then(|vt| {
                if let ValueType::TimestampValue(ts) = vt {
                    Some(ts)
                } else {
                    None
                }
            })
            .map(|ts| Utc.timestamp_opt(ts.seconds, ts.nanos as u32).single())
            .flatten();

        let is_active = fields
            .get("is_active")
            .and_then(|v| v.value_type.as_ref())
            .and_then(|vt| {
                if let ValueType::BooleanValue(b) = vt {
                    Some(*b)
                } else {
                    None
                }
            })
            .ok_or_else(|| AuthError {
                error: "parse_error".to_string(),
                message: "Missing or invalid is_active field".to_string(),
                code: 500,
            })?;

        let last_used = fields
            .get("last_used")
            .and_then(|v| v.value_type.as_ref())
            .and_then(|vt| {
                if let ValueType::TimestampValue(ts) = vt {
                    Some(ts)
                } else {
                    None
                }
            })
            .map(|ts| Utc.timestamp_opt(ts.seconds, ts.nanos as u32).single())
            .flatten();

        let usage_count = fields
            .get("usage_count")
            .and_then(|v| v.value_type.as_ref())
            .and_then(|vt| {
                if let ValueType::IntegerValue(i) = vt {
                    Some(*i as u64)
                } else {
                    None
                }
            })
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
}