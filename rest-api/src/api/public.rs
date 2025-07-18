use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::Json,
    routing::get,
    Router,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use crate::metrics::FirestoreMetricsClient;

#[derive(Debug, Deserialize)]
pub struct DaysQuery {
    days: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct PublicMetricsResponse {
    pub daily_stats: Vec<serde_json::Value>,
    pub endpoint_performance: Vec<serde_json::Value>,
    pub summary: MetricsSummary,
}

#[derive(Debug, Serialize)]
pub struct MetricsSummary {
    pub total_requests_today: u64,
    pub total_requests_7_days: u64,
    pub avg_response_time_ms: f64,
    pub error_rate_percent: f64,
    pub most_used_endpoint: String,
    pub active_api_keys: u64,
}

pub async fn get_public_metrics(
    State(metrics_client): State<Arc<FirestoreMetricsClient>>,
    Query(params): Query<DaysQuery>,
) -> Result<Json<PublicMetricsResponse>, (StatusCode, Json<serde_json::Value>)> {
    let days = params.days.unwrap_or(7).min(30);
    
    let daily_stats = metrics_client
        .get_daily_stats(days)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "Failed to fetch daily stats",
                    "message": e.to_string()
                }))
            )
        })?;

    let endpoint_performance = metrics_client
        .get_endpoint_performance()
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "Failed to fetch endpoint performance",
                    "message": e.to_string()
                }))
            )
        })?;

    let summary = calculate_summary(&daily_stats, &endpoint_performance);

    Ok(Json(PublicMetricsResponse {
        daily_stats,
        endpoint_performance,
        summary,
    }))
}

pub async fn get_daily_stats(
    State(metrics_client): State<Arc<FirestoreMetricsClient>>,
    Query(params): Query<DaysQuery>,
) -> Result<Json<Vec<serde_json::Value>>, (StatusCode, Json<serde_json::Value>)> {
    let days = params.days.unwrap_or(30).min(90);
    
    let stats = metrics_client
        .get_daily_stats(days)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "Failed to fetch daily stats",
                    "message": e.to_string()
                }))
            )
        })?;

    Ok(Json(stats))
}

pub async fn get_endpoint_performance(
    State(metrics_client): State<Arc<FirestoreMetricsClient>>,
) -> Result<Json<Vec<serde_json::Value>>, (StatusCode, Json<serde_json::Value>)> {
    let performance = metrics_client
        .get_endpoint_performance()
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "Failed to fetch endpoint performance",
                    "message": e.to_string()
                }))
            )
        })?;

    Ok(Json(performance))
}

pub async fn get_api_status() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "operational",
        "version": "0.2.0",
        "features": [
            "ML-KEM Key Encapsulation",
            "ML-DSA Digital Signatures", 
            "Hybrid Cryptography",
            "NIST Compliance",
            "Real-time Metrics"
        ],
        "compliance": {
            "fips_203": true,
            "fips_204": true,
            "fips_205": true
        },
        "encryption": "Post-Quantum (ML-KEM-768 + ChaCha20-Poly1305)"
    }))
}

fn calculate_summary(
    daily_stats: &[serde_json::Value],
    endpoint_performance: &[serde_json::Value],
) -> MetricsSummary {
    let total_requests_today = daily_stats
        .first()
        .and_then(|s| s.get("total_requests"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    let total_requests_7_days = daily_stats
        .iter()
        .take(7)
        .filter_map(|s| s.get("total_requests"))
        .filter_map(|v| v.as_u64())
        .sum();

    let avg_response_time_ms = daily_stats
        .iter()
        .take(7)
        .filter_map(|s| s.get("avg_response_time"))
        .filter_map(|v| v.as_f64())
        .sum::<f64>() / 7.0;

    let error_rate_percent = daily_stats
        .iter()
        .take(7)
        .filter_map(|s| s.get("error_rate"))
        .filter_map(|v| v.as_f64())
        .sum::<f64>() / 7.0;

    let most_used_endpoint = endpoint_performance
        .first()
        .and_then(|e| e.get("endpoint"))
        .and_then(|v| v.as_str())
        .unwrap_or("N/A")
        .to_string();

    let active_api_keys = daily_stats
        .first()
        .and_then(|s| s.get("unique_keys"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    MetricsSummary {
        total_requests_today,
        total_requests_7_days,
        avg_response_time_ms,
        error_rate_percent,
        most_used_endpoint,
        active_api_keys,
    }
}

pub fn routes() -> Router<Arc<FirestoreMetricsClient>> {
    Router::new()
        .route("/public/metrics", get(get_public_metrics))
        .route("/public/metrics/daily", get(get_daily_stats))
        .route("/public/metrics/endpoints", get(get_endpoint_performance))
        .route("/public/status", get(get_api_status))
}