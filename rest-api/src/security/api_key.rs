use axum::{
    extract::State,
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use chrono::{DateTime, Duration, Utc};
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::auth::{ApiKey, ApiKeyStore};

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateApiKeyRequest {
    pub name: String,
    pub permissions: Vec<String>,
    pub rate_limit: Option<u32>,
    pub expires_in_days: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct CreateApiKeyResponse {
    pub api_key: String,
    pub key_info: ApiKeyInfo,
}

#[derive(Debug, Serialize)]
pub struct ApiKeyInfo {
    pub id: Uuid,
    pub name: String,
    pub permissions: Vec<String>,
    pub rate_limit: u32,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub is_active: bool,
    pub last_used: Option<DateTime<Utc>>,
    pub usage_count: u64,
}

#[derive(Debug, Serialize)]
pub struct ApiKeyListResponse {
    pub keys: Vec<ApiKeyInfo>,
}

#[derive(Debug, Serialize)]
pub struct ApiKeyManagementError {
    pub error: String,
    pub message: String,
    pub code: u16,
}

fn generate_api_key() -> String {
    let random_part: String =
        thread_rng().sample_iter(&Alphanumeric).take(32).map(char::from).collect();

    format!("pq_live_{}", random_part)
}

pub async fn create_api_key(
    State(api_store): State<ApiKeyStore>,
    Json(request): Json<CreateApiKeyRequest>,
) -> Result<Json<CreateApiKeyResponse>, (StatusCode, Json<ApiKeyManagementError>)> {
    let valid_permissions = [
        "kem:*",
        "kem:keygen",
        "kem:encapsulate",
        "kem:decapsulate",
        "sig:*",
        "sig:keygen",
        "sig:sign",
        "sig:verify",
        "hybrid:*",
        "hybrid:sign",
        "*",
    ];

    for permission in &request.permissions {
        if !valid_permissions.contains(&permission.as_str()) {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ApiKeyManagementError {
                    error: "invalid_permission".to_string(),
                    message: format!("Invalid permission: {}", permission),
                    code: 400,
                }),
            ));
        }
    }

    let api_key_raw = generate_api_key();
    let api_key_hash = format!("{:x}", Sha256::digest(api_key_raw.as_bytes()));

    let expires_at = request.expires_in_days.map(|days| Utc::now() + Duration::days(days));

    let api_key = ApiKey {
        id: Uuid::new_v4(),
        name: request.name,
        key_hash: api_key_hash.clone(),
        permissions: request.permissions,
        rate_limit: request.rate_limit.unwrap_or(60),
        created_at: Utc::now(),
        expires_at,
        is_active: true,
        last_used: None,
        usage_count: 0,
    };

    let key_info = ApiKeyInfo {
        id: api_key.id,
        name: api_key.name.clone(),
        permissions: api_key.permissions.clone(),
        rate_limit: api_key.rate_limit,
        created_at: api_key.created_at,
        expires_at: api_key.expires_at,
        is_active: api_key.is_active,
        last_used: api_key.last_used,
        usage_count: api_key.usage_count,
    };

    let mut keys = api_store.fallback_keys.write().await;
    keys.insert(api_key_hash, api_key);

    tracing::info!("Created new API key: {} ({})", key_info.name, key_info.id);

    Ok(Json(CreateApiKeyResponse { api_key: api_key_raw, key_info }))
}

pub async fn list_api_keys(State(api_store): State<ApiKeyStore>) -> Json<ApiKeyListResponse> {
    let keys = api_store.fallback_keys.read().await;

    let key_infos: Vec<ApiKeyInfo> = keys
        .values()
        .map(|key| ApiKeyInfo {
            id: key.id,
            name: key.name.clone(),
            permissions: key.permissions.clone(),
            rate_limit: key.rate_limit,
            created_at: key.created_at,
            expires_at: key.expires_at,
            is_active: key.is_active,
            last_used: key.last_used,
            usage_count: key.usage_count,
        })
        .collect();

    Json(ApiKeyListResponse { keys: key_infos })
}

pub async fn get_api_key_info(
    State(_api_store): State<ApiKeyStore>,
) -> Result<Json<ApiKeyInfo>, (StatusCode, Json<ApiKeyManagementError>)> {
    Err((
        StatusCode::NOT_IMPLEMENTED,
        Json(ApiKeyManagementError {
            error: "not_implemented".to_string(),
            message: "Individual key lookup not implemented yet".to_string(),
            code: 501,
        }),
    ))
}

pub fn api_key_management_routes() -> Router<ApiKeyStore> {
    Router::new()
        .route("/admin/api-keys", post(create_api_key))
        .route("/admin/api-keys", get(list_api_keys))
        .route("/admin/api-keys/{id}", get(get_api_key_info))
}
