use axum::{
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::Response,
    Json,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;
use chrono::{DateTime, Utc, Duration};
use sha2::{Sha256, Digest};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKey {
    pub id: Uuid,
    pub name: String,
    pub key_hash: String,
    pub permissions: Vec<String>,
    pub rate_limit: u32,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub is_active: bool,
    pub last_used: Option<DateTime<Utc>>,
    pub usage_count: u64,
}

#[derive(Debug, Clone)]
pub struct ApiKeyStore {
    pub keys: Arc<RwLock<HashMap<String, ApiKey>>>,
}

impl ApiKeyStore {
    pub fn new() -> Self {
        let mut store = HashMap::new();
        
        if let Ok(test_key) = std::env::var("PQ_TEST_API_KEY") {
            let test_key_hash = format!("{:x}", Sha256::digest(test_key.as_bytes()));
            
            let api_key = ApiKey {
                id: Uuid::new_v4(),
                name: "Test Key".to_string(),
                key_hash: test_key_hash.clone(),
                permissions: vec![
                    "kem:*".to_string(),
                    "sig:*".to_string(),
                    "hybrid:*".to_string(),
                ],
                rate_limit: 100, 
                created_at: Utc::now(),
                expires_at: Some(Utc::now() + Duration::days(30)),
                is_active: true,
                last_used: None,
                usage_count: 0,
            };
            
            store.insert(test_key_hash, api_key);
            tracing::info!("Test API key loaded from environment");
        }
        
        Self {
            keys: Arc::new(RwLock::new(store)),
        }
    }
    
    pub async fn validate_key(&self, key: &str) -> Option<ApiKey> {
        let key_hash = format!("{:x}", Sha256::digest(key.as_bytes()));
        let mut keys = self.keys.write().await;
        
        if let Some(api_key) = keys.get_mut(&key_hash) {
            // Check if key is active and not expired
            if !api_key.is_active {
                tracing::warn!("Attempt to use inactive API key: {}", api_key.id);
                return None;
            }
            
            if let Some(expires_at) = api_key.expires_at {
                if Utc::now() > expires_at {
                    tracing::warn!("Attempt to use expired API key: {}", api_key.id);
                    return None;
                }
            }
            
            api_key.last_used = Some(Utc::now());
            api_key.usage_count = api_key.usage_count.saturating_add(1);
            
            Some(api_key.clone())
        } else {
            tracing::warn!("Attempt to use unknown API key hash: {}", &key_hash[..8]);
            None
        }
    }
    
    pub async fn check_permission(&self, key: &str, resource: &str) -> bool {
        if let Some(api_key) = self.validate_key(key).await {
            for permission in &api_key.permissions {
                if permission == "*" || permission == resource || 
                   (permission.ends_with(":*") && resource.starts_with(&permission[..permission.len()-1])) {
                    return true;
                }
            }
        }
        false
    }
}

#[derive(Debug, Serialize)]
pub struct AuthError {
    pub error: String,
    pub message: String,
    pub code: u16,
}

pub async fn auth_middleware(
    State(api_store): State<ApiKeyStore>,
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Result<Response, (StatusCode, Json<AuthError>)> {
    let api_key = extract_api_key(&headers)?;
    
    let validated_key = api_store.validate_key(&api_key).await
        .ok_or_else(|| (
            StatusCode::UNAUTHORIZED,
            Json(AuthError {
                error: "invalid_api_key".to_string(),
                message: "Invalid or expired API key".to_string(),
                code: 401,
            }),
        ))?;
    
    let path = request.uri().path();
    let resource = extract_resource_from_path(path);
    
    if !api_store.check_permission(&api_key, &resource).await {
        return Err((
            StatusCode::FORBIDDEN,
            Json(AuthError {
                error: "insufficient_permissions".to_string(),
                message: format!("Insufficient permissions for resource: {}", resource),
                code: 403,
            }),
        ));
    }
    
    tracing::info!(
        "API request authorized - key_id: {}, resource: {}, usage_count: {}",
        validated_key.id,
        resource,
        validated_key.usage_count
    );
    
    Ok(next.run(request).await)
}

fn extract_api_key(headers: &HeaderMap) -> Result<String, (StatusCode, Json<AuthError>)> {
    if let Some(api_key) = headers.get("x-api-key") {
        return api_key
            .to_str()
            .map(|s| s.to_string())
            .map_err(|_| (
                StatusCode::BAD_REQUEST,
                Json(AuthError {
                    error: "invalid_header".to_string(),
                    message: "Invalid X-API-Key header format".to_string(),
                    code: 400,
                }),
            ));
    }
    
    if let Some(auth_header) = headers.get("authorization") {
        if let Ok(auth_str) = auth_header.to_str() {
            if auth_str.starts_with("Bearer ") {
                return Ok(auth_str[7..].to_string());
            }
        }
    }
    
    Err((
        StatusCode::UNAUTHORIZED,
        Json(AuthError {
            error: "missing_api_key".to_string(),
            message: "API key required. Use X-API-Key header or Authorization: Bearer <key>".to_string(),
            code: 401,
        }),
    ))
}

fn extract_resource_from_path(path: &str) -> String {
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    
    if segments.is_empty() {
        return "root".to_string();
    }
    
    match segments[0] {
        "kem" => format!("kem:{}", segments.get(2).unwrap_or(&"*")),
        "sig" => format!("sig:{}", segments.get(2).unwrap_or(&"*")),
        "hybrid" => "hybrid:sign".to_string(),
        _ => "unknown".to_string(),
    }
}