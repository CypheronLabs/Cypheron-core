use axum::{
    extract::{Request, State},
    middleware::Next,
    response::Response,
};
use std::time::Instant;
use crate::models::analytics::ApiUsageLog;
use crate::security::repository::AnalyticsEntry;
use crate::security::auth::middleware::{UserId, ApiKeyPrefix};
use crate::state::AppState;
use uuid::Uuid;

/// Axum middleware for analytics logging
pub async fn analytics_middleware(
    State(app_state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let start_time = Instant::now();
    
    // Extract request info before processing
    let method = request.method().clone();
    let uri = request.uri().clone();
    let path = uri.path().to_string();
    
    // Get user agent
    let user_agent = request
        .headers()
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // Get API key info from extensions if available (set by auth middleware)
    let api_key_id = request.extensions().get::<Uuid>().cloned();
    let user_id = request.extensions().get::<UserId>().map(|u| u.0.clone());
    let api_key_prefix = request.extensions().get::<ApiKeyPrefix>().map(|p| p.0.clone());
    
    // Process the request
    let response = next.run(request).await;
    
    let latency = start_time.elapsed();
    let status = response.status();
    
    // Log analytics if we have the required info
    if let (Some(user_id), Some(api_key_prefix)) = (user_id, api_key_prefix) {
        // Check if PostgreSQL analytics is enabled
        let use_postgres = std::env::var("ANALYTICS_STORAGE")
            .unwrap_or_else(|_| "firestore".to_string())
            .to_lowercase() == "postgresql";

        if use_postgres {
            // Use PostgreSQL for analytics
            if let Some(analytics_repo) = &app_state.analytics_repository {
                let analytics_entry = AnalyticsEntry {
                    id: Uuid::new_v4(),
                    timestamp: chrono::Utc::now(),
                    api_key_id,
                    endpoint: path,
                    method: method.to_string(),
                    response_time_ms: latency.as_millis() as i32,
                    request_size_bytes: None, // Could be extracted from request headers
                    response_size_bytes: None, // Could be extracted from response headers
                    success: status.is_success(),
                    error_type: if status.is_client_error() || status.is_server_error() {
                        Some(format!("HTTP_{}", status.as_u16()))
                    } else {
                        None
                    },
                    region: None, // Could be extracted from request headers
                    client_type: user_agent,
                    metrics: serde_json::json!({
                        "user_id": user_id,
                        "api_key_prefix": api_key_prefix,
                        "latency_ms": latency.as_millis()
                    }),
                };

                let repo = analytics_repo.clone();
                tokio::spawn(async move {
                    if let Err(e) = repo.record_analytics(&analytics_entry).await {
                        tracing::warn!("Failed to record analytics to PostgreSQL: {}", e);
                    }
                });
            }
        } else {
            // Fallback to original logging (for backward compatibility)
            let log_entry = ApiUsageLog::new(
                user_id,
                api_key_prefix,
                path,
                method.to_string(),
                status.as_u16(),
                latency.as_millis(),
            );

            tokio::spawn(async move {
                tracing::info!("Analytics (Firestore fallback): {:?}", log_entry);
            });
        }
    }
    
    response
}
