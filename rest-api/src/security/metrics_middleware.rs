use axum::{
    extract::{Request, State},
    middleware::Next,
    response::Response,
};
use std::sync::Arc;
use std::time::Instant;
use chrono::Utc;
use uuid::Uuid;
use crate::metrics::{FirestoreMetricsClient, MetricEvent};

pub async fn metrics_middleware(
    State(metrics_client): State<Arc<FirestoreMetricsClient>>,
    request: Request,
    next: Next,
) -> Response {
    let start_time = Instant::now();
    let method = request.method().to_string();
    let path = request.uri().path().to_string();
    let user_agent = request
        .headers()
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());
    
    let ip_address = request
        .headers()
        .get("x-forwarded-for")
        .and_then(|h| h.to_str().ok())
        .or_else(|| {
            request
                .headers()
                .get("x-real-ip")
                .and_then(|h| h.to_str().ok())
        })
        .map(|s| s.to_string());

    let api_key_id = extract_api_key_id_from_request(&request);

    let response = next.run(request).await;
    
    let response_time = start_time.elapsed().as_millis() as u64;
    let status_code = response.status().as_u16();
    
    let error_message = if status_code >= 400 {
        Some(format!("HTTP {}", status_code))
    } else {
        None
    };

    let metric_event = MetricEvent {
        api_key_id,
        endpoint: path,
        method,
        status_code,
        response_time_ms: response_time,
        timestamp: Utc::now(),
        user_agent,
        ip_address,
        error_message,
    };

    metrics_client.record_api_call(metric_event);

    response
}

fn extract_api_key_id_from_request(request: &Request) -> Option<Uuid> {
    request
        .headers()
        .get("x-api-key-id")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| Uuid::parse_str(s).ok())
}