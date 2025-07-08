use axum::{Router, routing::{get, post, put, delete}};
use crate::handlers::monitoring_handler;

pub fn routes() -> Router {
    Router::new()
        // General monitoring status
        .route("/monitoring", get(monitoring_handler::get_monitoring_status))
        .route("/monitoring/dashboard", get(monitoring_handler::get_monitoring_dashboard))
        
        // Metrics endpoints
        .route("/monitoring/metrics/summary", get(monitoring_handler::get_metrics_summary))
        .route("/monitoring/metrics/crypto", get(monitoring_handler::get_crypto_metrics))
        .route("/monitoring/metrics/security", get(monitoring_handler::get_security_metrics))
        .route("/monitoring/metrics/performance", get(monitoring_handler::get_performance_metrics))
        
        // Alert management
        .route("/monitoring/alerts", get(monitoring_handler::get_alerts))
        .route("/monitoring/alerts/check", post(monitoring_handler::trigger_manual_alert_check))
        .route("/monitoring/alerts/:alert_id/acknowledge", post(monitoring_handler::acknowledge_alert))
        .route("/monitoring/alerts/:alert_id/resolve", post(monitoring_handler::resolve_alert))
        
        // Alert rules management
        .route("/monitoring/alert-rules", get(monitoring_handler::get_alert_rules))
        .route("/monitoring/alert-rules", post(monitoring_handler::add_alert_rule))
        .route("/monitoring/alert-rules/:rule_id", put(monitoring_handler::update_alert_rule))
        .route("/monitoring/alert-rules/:rule_id", delete(monitoring_handler::delete_alert_rule))
        
        // Health checks
        .route("/health", get(monitoring_handler::get_health_status))
        .route("/health/detailed", get(monitoring_handler::get_detailed_health_report))
        .route("/health/ready", get(monitoring_handler::get_readiness_check))
        .route("/health/live", get(monitoring_handler::get_liveness_check))
        
        // Security monitoring
        .route("/monitoring/security/events", get(monitoring_handler::get_security_events))
        .route("/monitoring/security/summary", get(monitoring_handler::get_security_summary))
        .route("/monitoring/security/anomalies", get(monitoring_handler::get_anomaly_detection_results))
        
        // Compliance monitoring
        .route("/monitoring/compliance/report", get(monitoring_handler::get_compliance_report))
        .route("/monitoring/compliance/dashboard", get(monitoring_handler::get_compliance_dashboard))
        .route("/monitoring/compliance/assess", post(monitoring_handler::assess_compliance_framework))
}