use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
    Json,
};
use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use chrono::{DateTime, Utc};
use crate::config::GatewayConfig;
use super::{SecurityError, auth::ApiKeyStore};

#[derive(Debug, Serialize, Deserialize)]
pub struct GatewayToken {
    pub user_id: String,
    pub permissions: Vec<String>,
    pub exp: usize,
    pub iat: usize,
    pub iss: Option<String>, 
    pub sub: Option<String>, 
}

#[derive(Debug, Clone)]
pub struct GatewayAuthContext {
    pub user_id: String,
    pub permissions: Vec<String>,
    pub token_issued_at: DateTime<Utc>,
    pub token_expires_at: DateTime<Utc>,
}

pub async fn flexible_auth_middleware(
    State((gateway_config, api_key_store)): State<(GatewayConfig, Arc<ApiKeyStore>)>,
    mut request: Request,
    next: Next,
) -> Result<Response, (StatusCode, Json<SecurityError>)> {
    if gateway_config.enabled {
        if let Some(auth_header) = request.headers().get(&gateway_config.internal_token_header) {
            if let Ok(token) = auth_header.to_str() {
                match validate_gateway_token(token, &gateway_config).await {
                    Ok(auth_context) => {
                        request.extensions_mut().insert(auth_context);
                        return Ok(next.run(request).await);
                    }
                    Err(e) => {
                        tracing::warn!("Gateway token validation failed: {}", e);
                    }
                }
            }
        }
    }

    let headers = request.headers().clone();
    super::auth_middleware(State((*api_key_store).clone()), headers, request, next).await
        .map_err(|(status, json_error)| {
            let sanitized = json_error.0; 
            let security_error = SecurityError {
                error: sanitized.error,
                message: sanitized.message,
                code: status.as_u16(),
            };
            (status, Json(security_error))
        })
}

async fn validate_gateway_token(
    token: &str,
    gateway_config: &GatewayConfig,
) -> Result<GatewayAuthContext, GatewayAuthError> {
    let jwt_secret = gateway_config.jwt_secret.as_ref()
        .ok_or(GatewayAuthError::MissingJwtSecret)?;

    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;
    
    let token_data = decode::<GatewayToken>(
        token,
        &DecodingKey::from_secret(jwt_secret.as_bytes()),
        &validation,
    )
    .map_err(|e| GatewayAuthError::InvalidToken(e.to_string()))?;

    let claims = token_data.claims;

    if claims.user_id.is_empty() {
        return Err(GatewayAuthError::InvalidClaims("Empty user_id".to_string()));
    }

    if claims.permissions.is_empty() {
        return Err(GatewayAuthError::InvalidClaims("No permissions granted".to_string()));
    }

    let permissions = claims.permissions.clone();

    let token_issued_at = DateTime::from_timestamp(claims.iat as i64, 0)
        .unwrap_or_else(|| Utc::now());
    let token_expires_at = DateTime::from_timestamp(claims.exp as i64, 0)
        .unwrap_or_else(|| Utc::now());

    tracing::debug!(
        "Gateway token validated for user {} with {} permissions",
        claims.user_id,
        permissions.len()
    );

    Ok(GatewayAuthContext {
        user_id: claims.user_id,
        permissions,
        token_issued_at,
        token_expires_at,
    })
}

pub fn has_permission(auth_context: &GatewayAuthContext, required_permission: &str) -> bool {
    auth_context.permissions.iter().any(|perm| {
        perm == required_permission || 
        perm == "*" || 
        perm.ends_with(":*") && required_permission.starts_with(&perm[..perm.len()-1])
    })
}

pub fn get_gateway_auth_context(request: &Request) -> Option<&GatewayAuthContext> {
    request.extensions().get::<GatewayAuthContext>()
}
pub fn create_permission_middleware(
    required_permission: String,
) -> impl Fn(Request, Next) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Response, (StatusCode, Json<SecurityError>)>> + Send>> + Clone {
    move |request: Request, next: Next| {
        let required_permission = required_permission.clone();
        Box::pin(async move {
            if let Some(auth_context) = get_gateway_auth_context(&request) {
                if has_permission(auth_context, &required_permission) {
                    Ok(next.run(request).await)
                } else {
                    Err((
                        StatusCode::FORBIDDEN,
                        Json(SecurityError {
                            error: "insufficient_permissions".to_string(),
                            message: format!("Permission '{}' required", required_permission),
                            code: 403,
                        }),
                    ))
                }
            } else {
                Ok(next.run(request).await)
            }
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum GatewayAuthError {
    #[error("JWT secret not configured")]
    MissingJwtSecret,
    
    #[error("Invalid token: {0}")]
    InvalidToken(String),
    
    #[error("Invalid token claims: {0}")]
    InvalidClaims(String),
    
    #[error("Token expired")]
    TokenExpired,
    
    #[error("Cache error: {0}")]
    CacheError(String),
}

#[allow(dead_code)]
fn get_cache_ttl_seconds() -> u64 {
    std::env::var("GATEWAY_CACHE_TTL_SECONDS")
        .unwrap_or_else(|_| "300".to_string())
        .parse()
        .unwrap_or(300)
}