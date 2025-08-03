use axum::{
    http::{HeaderMap, StatusCode},
    Json,
};

use super::errors::AuthError;

pub fn extract_api_key(headers: &HeaderMap) -> Result<String, (StatusCode, Json<AuthError>)> {
    if let Some(api_key) = headers.get("x-api-key") {
        return api_key.to_str().map(|s| s.to_string()).map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                Json(AuthError {
                    error: "invalid_header".to_string(),
                    message: "Invalid X-API-Key header format".to_string(),
                    code: 400,
                }),
            )
        });
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
            message: "API key required. Use X-API-Key header or Authorization: Bearer <key>"
                .to_string(),
            code: 401,
        }),
    ))
}