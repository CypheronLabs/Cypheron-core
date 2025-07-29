use axum::{
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::Response,
    Json,
};
use serde::Serialize;
use std::time::Duration;
use tower::timeout::TimeoutLayer;

#[derive(Debug, Serialize)]
pub struct TimeoutError {
    pub error: String,
    pub message: String,
    pub code: u16,
}

pub fn determine_timeout_for_path(path: &str) -> Duration {
    if path.starts_with("/kem/") || path.starts_with("/sig/") || path.starts_with("/hybrid/") {
        Duration::from_secs(45)
    } else if path.starts_with("/health") {
        Duration::from_secs(5)
    } else if path.starts_with("/admin/") {
        Duration::from_secs(30)
    } else if path.starts_with("/monitoring/") || path.starts_with("/nist/") {
        Duration::from_secs(15)
    } else {
        Duration::from_secs(15)
    }
}

pub async fn smart_timeout_middleware(
    request: Request,
    next: Next,
) -> Result<Response, (StatusCode, Json<TimeoutError>)> {
    let path = request.uri().path().to_string();
    let timeout_duration = determine_timeout_for_path(&path);
    
    match tokio::time::timeout(timeout_duration, next.run(request)).await {
        Ok(response) => Ok(response),
        Err(_) => {
            tracing::warn!(
                "Request timeout: path={}, timeout={}s", 
                path, 
                timeout_duration.as_secs()
            );
            
            Err((
                StatusCode::REQUEST_TIMEOUT,
                Json(TimeoutError {
                    error: "request_timeout".to_string(),
                    message: format!(
                        "Request timed out after {} seconds. Please try again.",
                        timeout_duration.as_secs()
                    ),
                    code: 408,
                }),
            ))
        }
    }
}
pub fn create_connection_limit_layer(max_connections: usize) -> tower::limit::ConcurrencyLimitLayer {
    tower::limit::ConcurrencyLimitLayer::new(max_connections)
}

pub fn create_global_timeout_layer(timeout_seconds: u64) -> TimeoutLayer {
    TimeoutLayer::new(Duration::from_secs(timeout_seconds))
}

pub fn create_request_size_limit_layer() -> tower_http::limit::RequestBodyLimitLayer {
    tower_http::limit::RequestBodyLimitLayer::new(1024 * 1024)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crypto_timeout_determination() {
        assert_eq!(determine_timeout_for_path("/kem/ml-kem-768/keygen"), Duration::from_secs(45));
        assert_eq!(determine_timeout_for_path("/sig/ml-dsa-65/sign"), Duration::from_secs(45));
        assert_eq!(determine_timeout_for_path("/hybrid/sign"), Duration::from_secs(45));
    }

    #[test]
    fn test_health_timeout_determination() {
        assert_eq!(determine_timeout_for_path("/health"), Duration::from_secs(5));
        assert_eq!(determine_timeout_for_path("/health/detailed"), Duration::from_secs(5));
    }

    #[test]
    fn test_admin_timeout_determination() {
        assert_eq!(determine_timeout_for_path("/admin/api-keys"), Duration::from_secs(30));
        assert_eq!(determine_timeout_for_path("/admin/audit-logs"), Duration::from_secs(30));
    }

    #[test]
    fn test_default_timeout_determination() {
        assert_eq!(determine_timeout_for_path("/unknown"), Duration::from_secs(15));
        assert_eq!(determine_timeout_for_path("/"), Duration::from_secs(15));
    }
}