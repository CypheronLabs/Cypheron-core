use axum::{extract::{Query, Path, State}, Json};
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc, Duration};
use uuid::Uuid;
use std::collections::HashMap;
use std::sync::Arc;

use crate::error::AppError;
use crate::monitoring::{
    MetricsCollector, AlertManager, HealthChecker, ComplianceChecker,
    SecurityEventMonitor, Alert, AlertRule, SecurityEvent, ComplianceFramework
};

#[derive(Debug, Deserialize)]
pub struct MetricsQuery {
    pub limit: Option<usize>,
    pub hours: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct AlertQuery {
    pub status: Option<String>,
    pub severity: Option<String>,
    pub limit: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct MonitoringStatus {
    pub service: String,
    pub status: String,
    pub timestamp: DateTime<Utc>,
    pub uptime_seconds: u64,
    pub active_monitors: u32,
    pub total_metrics: u64,
    pub active_alerts: u32,
}

pub async fn get_monitoring_status(
    State(metrics_collector): State<Arc<MetricsCollector>>,
    State(alert_manager): State<Arc<AlertManager>>,
) -> Result<Json<MonitoringStatus>, AppError> {
    let crypto_metrics = metrics_collector.get_crypto_metrics(Some(1)).await;
    let active_alerts = alert_manager.get_active_alerts().await;
    
    let status = MonitoringStatus {
        service: "Cypheron Security Monitoring".to_string(),
        status: "operational".to_string(),
        timestamp: Utc::now(),
        uptime_seconds: 3600, // Would track actual uptime
        active_monitors: 5, // Number of monitoring components
        total_metrics: crypto_metrics.len() as u64,
        active_alerts: active_alerts.len() as u32,
    };

    Ok(Json(status))
}

pub async fn get_metrics_summary(
    Query(params): Query<MetricsQuery>,
    State(metrics_collector): State<Arc<MetricsCollector>>,
) -> Result<Json<serde_json::Value>, AppError> {
    let hours = params.hours.unwrap_or(24);
    let time_window = Duration::hours(hours as i64);
    
    let summary = metrics_collector.get_metrics_summary(time_window).await;
    Ok(Json(serde_json::to_value(summary).unwrap()))
}

pub async fn get_crypto_metrics(
    Query(params): Query<MetricsQuery>,
    State(metrics_collector): State<Arc<MetricsCollector>>,
) -> Result<Json<serde_json::Value>, AppError> {
    let limit = params.limit.unwrap_or(100);
    let metrics = metrics_collector.get_crypto_metrics(Some(limit)).await;
    Ok(Json(serde_json::to_value(metrics).unwrap()))
}

pub async fn get_security_metrics(
    Query(params): Query<MetricsQuery>,
    State(metrics_collector): State<Arc<MetricsCollector>>,
) -> Result<Json<serde_json::Value>, AppError> {
    let limit = params.limit.unwrap_or(100);
    let metrics = metrics_collector.get_security_metrics(Some(limit)).await;
    Ok(Json(serde_json::to_value(metrics).unwrap()))
}

pub async fn get_performance_metrics(
    Query(params): Query<MetricsQuery>,
    State(metrics_collector): State<Arc<MetricsCollector>>,
) -> Result<Json<serde_json::Value>, AppError> {
    let limit = params.limit.unwrap_or(100);
    let metrics = metrics_collector.get_performance_metrics(Some(limit)).await;
    Ok(Json(serde_json::to_value(metrics).unwrap()))
}

pub async fn get_alerts(
    Query(params): Query<AlertQuery>,
    State(alert_manager): State<Arc<AlertManager>>,
) -> Result<Json<Vec<Alert>>, AppError> {
    let limit = params.limit.unwrap_or(50);
    
    let alerts = if params.status.as_deref() == Some("active") {
        alert_manager.get_active_alerts().await
    } else {
        alert_manager.get_all_alerts(Some(limit)).await
    };

    Ok(Json(alerts))
}

pub async fn acknowledge_alert(
    Path(alert_id): Path<Uuid>,
    State(alert_manager): State<Arc<AlertManager>>,
) -> Result<Json<serde_json::Value>, AppError> {
    let success = alert_manager.acknowledge_alert(alert_id).await;
    
    if success {
        Ok(Json(serde_json::json!({
            "success": true,
            "message": "Alert acknowledged",
            "alert_id": alert_id
        })))
    } else {
        Err(AppError::NotFound)
    }
}

#[derive(Debug, Deserialize)]
pub struct ResolveAlertRequest {
    pub resolution_note: Option<String>,
}

pub async fn resolve_alert(
    Path(alert_id): Path<Uuid>,
    Json(request): Json<ResolveAlertRequest>,
    State(alert_manager): State<Arc<AlertManager>>,
) -> Result<Json<serde_json::Value>, AppError> {
    let success = alert_manager.resolve_alert(alert_id, request.resolution_note).await;
    
    if success {
        Ok(Json(serde_json::json!({
            "success": true,
            "message": "Alert resolved",
            "alert_id": alert_id
        })))
    } else {
        Err(AppError::NotFound)
    }
}

pub async fn get_alert_rules(
    State(alert_manager): State<Arc<AlertManager>>,
) -> Result<Json<Vec<AlertRule>>, AppError> {
    let rules = alert_manager.get_alert_rules().await;
    Ok(Json(rules))
}

pub async fn add_alert_rule(
    Json(rule): Json<AlertRule>,
    State(alert_manager): State<Arc<AlertManager>>,
) -> Result<Json<serde_json::Value>, AppError> {
    alert_manager.add_alert_rule(rule.clone()).await;
    
    Ok(Json(serde_json::json!({
        "success": true,
        "message": "Alert rule added",
        "rule_id": rule.rule_id
    })))
}

pub async fn update_alert_rule(
    Path(rule_id): Path<Uuid>,
    Json(rule): Json<AlertRule>,
    State(alert_manager): State<Arc<AlertManager>>,
) -> Result<Json<serde_json::Value>, AppError> {
    let success = alert_manager.update_alert_rule(rule_id, rule).await;
    
    if success {
        Ok(Json(serde_json::json!({
            "success": true,
            "message": "Alert rule updated",
            "rule_id": rule_id
        })))
    } else {
        Err(AppError::NotFound)
    }
}

pub async fn delete_alert_rule(
    Path(rule_id): Path<Uuid>,
    State(alert_manager): State<Arc<AlertManager>>,
) -> Result<Json<serde_json::Value>, AppError> {
    let success = alert_manager.delete_alert_rule(rule_id).await;
    
    if success {
        Ok(Json(serde_json::json!({
            "success": true,
            "message": "Alert rule deleted",
            "rule_id": rule_id
        })))
    } else {
        Err(AppError::NotFound)
    }
}

pub async fn get_health_status(
    State(health_checker): State<Arc<HealthChecker>>,
) -> Result<Json<serde_json::Value>, AppError> {
    let health = health_checker.get_health_status().await;
    Ok(Json(serde_json::to_value(health).unwrap()))
}

pub async fn get_detailed_health_report(
    State(health_checker): State<Arc<HealthChecker>>,
) -> Result<Json<serde_json::Value>, AppError> {
    let report = health_checker.get_detailed_health_report().await;
    Ok(Json(serde_json::to_value(report).unwrap()))
}

pub async fn get_readiness_check(
    State(health_checker): State<Arc<HealthChecker>>,
) -> Result<Json<serde_json::Value>, AppError> {
    let ready = health_checker.get_readiness_status().await;
    
    let status_code = if ready { 200 } else { 503 };
    Ok(Json(serde_json::json!({
        "ready": ready,
        "status_code": status_code,
        "timestamp": Utc::now()
    })))
}

pub async fn get_liveness_check(
    State(health_checker): State<Arc<HealthChecker>>,
) -> Result<Json<serde_json::Value>, AppError> {
    let alive = health_checker.get_liveness_status().await;
    
    let status_code = if alive { 200 } else { 503 };
    Ok(Json(serde_json::json!({
        "alive": alive,
        "status_code": status_code,
        "timestamp": Utc::now()
    })))
}

pub async fn get_security_events(
    Query(params): Query<MetricsQuery>,
    State(security_monitor): State<Arc<SecurityEventMonitor>>,
) -> Result<Json<Vec<SecurityEvent>>, AppError> {
    let limit = params.limit.unwrap_or(100);
    let events = security_monitor.get_events(Some(limit)).await;
    Ok(Json(events))
}

#[derive(Debug, Deserialize)]
pub struct SecuritySummaryQuery {
    pub hours: Option<u64>,
}

pub async fn get_security_summary(
    Query(params): Query<SecuritySummaryQuery>,
    State(security_monitor): State<Arc<SecurityEventMonitor>>,
) -> Result<Json<serde_json::Value>, AppError> {
    let hours = params.hours.unwrap_or(24);
    let time_window = Duration::hours(hours as i64);
    
    let summary = security_monitor.get_security_summary(time_window).await;
    Ok(Json(serde_json::to_value(summary).unwrap()))
}

pub async fn get_compliance_report(
    State(compliance_checker): State<Arc<ComplianceChecker>>,
) -> Result<Json<serde_json::Value>, AppError> {
    let reports = compliance_checker.generate_comprehensive_report().await;
    Ok(Json(serde_json::to_value(reports).unwrap()))
}

pub async fn get_compliance_dashboard(
    State(compliance_checker): State<Arc<ComplianceChecker>>,
) -> Result<Json<serde_json::Value>, AppError> {
    let dashboard = compliance_checker.get_compliance_dashboard().await;
    Ok(Json(serde_json::to_value(dashboard).unwrap()))
}

#[derive(Debug, Deserialize)]
pub struct ComplianceAssessmentRequest {
    pub framework: String,
}

pub async fn assess_compliance_framework(
    Json(request): Json<ComplianceAssessmentRequest>,
    State(compliance_checker): State<Arc<ComplianceChecker>>,
) -> Result<Json<serde_json::Value>, AppError> {
    let report = match request.framework.as_str() {
        "NIST_FIPS_203" => compliance_checker.assess_nist_fips_203_compliance().await,
        "NIST_FIPS_204" => compliance_checker.assess_nist_fips_204_compliance().await,
        "SOC_2" => compliance_checker.assess_soc2_compliance().await,
        _ => return Err(AppError::InvalidVariant),
    };
    
    Ok(Json(serde_json::to_value(report).unwrap()))
}

pub async fn get_anomaly_detection_results(
    State(metrics_collector): State<Arc<MetricsCollector>>,
) -> Result<Json<serde_json::Value>, AppError> {
    let timing_anomalies = metrics_collector.detect_timing_anomalies().await;
    let usage_anomalies = metrics_collector.detect_usage_anomalies().await;
    
    Ok(Json(serde_json::json!({
        "timing_anomalies": timing_anomalies,
        "usage_anomalies": usage_anomalies,
        "total_anomalies": timing_anomalies.len() + usage_anomalies.len(),
        "analysis_timestamp": Utc::now()
    })))
}

pub async fn trigger_manual_alert_check(
    State(alert_manager): State<Arc<AlertManager>>,
) -> Result<Json<serde_json::Value>, AppError> {
    alert_manager.check_alert_conditions().await;
    
    Ok(Json(serde_json::json!({
        "success": true,
        "message": "Manual alert condition check triggered",
        "timestamp": Utc::now()
    })))
}

#[derive(Debug, Serialize)]
pub struct MonitoringDashboard {
    pub system_health: String,
    pub active_alerts: u32,
    pub security_events_24h: u64,
    pub compliance_score: f64,
    pub threat_level: String,
    pub uptime_percent: f64,
    pub avg_response_time_ms: f64,
    pub requests_per_minute: f64,
    pub error_rate_percent: f64,
    pub last_updated: DateTime<Utc>,
}

pub async fn get_monitoring_dashboard(
    State(metrics_collector): State<Arc<MetricsCollector>>,
    State(alert_manager): State<Arc<AlertManager>>,
    State(health_checker): State<Arc<HealthChecker>>,
    State(security_monitor): State<Arc<SecurityEventMonitor>>,
    State(compliance_checker): State<Arc<ComplianceChecker>>,
) -> Result<Json<MonitoringDashboard>, AppError> {
    // Gather data from all monitoring components
    let health = health_checker.get_health_status().await;
    let active_alerts = alert_manager.get_active_alerts().await;
    let security_summary = security_monitor.get_security_summary(Duration::hours(24)).await;
    let metrics_summary = metrics_collector.get_metrics_summary(Duration::hours(24)).await;
    let compliance_dashboard = compliance_checker.get_compliance_dashboard().await;
    
    let dashboard = MonitoringDashboard {
        system_health: format!("{:?}", health.status),
        active_alerts: active_alerts.len() as u32,
        security_events_24h: security_summary.total_events,
        compliance_score: compliance_dashboard.overall_compliance_score,
        threat_level: format!("{:?}", security_summary.threat_level),
        uptime_percent: 99.9, // Would calculate from actual data
        avg_response_time_ms: metrics_summary.average_response_time_ms,
        requests_per_minute: metrics_summary.operations_per_second * 60.0,
        error_rate_percent: metrics_summary.error_rate,
        last_updated: Utc::now(),
    };

    Ok(Json(dashboard))
}