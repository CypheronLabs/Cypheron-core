// Metrics module - now using Cloud Monitoring instead of Firestore

use crate::monitoring::security_events::{SecurityEventType, SecuritySeverity};
use chrono::Duration;
use serde_json::Value;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Simple metrics collector for basic monitoring
/// Real metrics are handled by Google Cloud Monitoring
#[derive(Debug)]
pub struct MetricsCollector {
    _capacity: usize,
    _data: Arc<RwLock<Vec<()>>>, // Placeholder
}

impl MetricsCollector {
    pub fn new(capacity: usize) -> Self {
        Self { _capacity: capacity, _data: Arc::new(RwLock::new(Vec::new())) }
    }

    pub async fn record_metric(&self, _metric: &str, _value: f64) {
        // No-op - using Cloud Monitoring instead
    }

    pub async fn get_crypto_metrics(&self, _limit: Option<usize>) -> Vec<Value> {
        // Return empty metrics - Cloud Monitoring handles this
        vec![]
    }

    pub async fn get_security_metrics(&self, _limit: Option<usize>) -> Vec<Value> {
        // Return empty metrics - Cloud Monitoring handles this
        vec![]
    }

    pub async fn get_performance_metrics(&self, _limit: Option<usize>) -> Vec<Value> {
        // Return empty metrics - Cloud Monitoring handles this
        vec![]
    }

    pub async fn get_metrics_summary(&self, _time_window: Duration) -> Value {
        // Return basic summary - Cloud Monitoring handles detailed metrics
        serde_json::json!({
            "total_requests": 0,
            "average_response_time_ms": 0.0,
            "operations_per_second": 0.0,
            "error_rate": 0.0,
            "security_events": 0,
            "compliance_score": 100.0,
            "status": "metrics_handled_by_cloud_monitoring"
        })
    }

    pub async fn detect_timing_anomalies(&self) -> Vec<Value> {
        // Return empty - Cloud Monitoring handles anomaly detection
        vec![]
    }

    pub async fn detect_usage_anomalies(&self) -> Vec<Value> {
        // Return empty - Cloud Monitoring handles anomaly detection
        vec![]
    }

    pub async fn record_security_event(
        &self,
        _event_type: SecurityEventType,
        _severity: SecuritySeverity,
        _description: String,
    ) {
        // No-op - using Cloud Monitoring for security events
    }
}
