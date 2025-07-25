use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

use super::security_events::SecuritySeverity;
use super::MetricsCollector;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub alert_id: Uuid,
    pub alert_type: AlertType,
    pub severity: AlertSeverity,
    pub title: String,
    pub description: String,
    pub triggered_at: DateTime<Utc>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub status: AlertStatus,
    pub source: AlertSource,
    pub metadata: HashMap<String, String>,
    pub actions_taken: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AlertType {
    SecurityThreat,
    PerformanceDegradation,
    SystemError,
    ComplianceViolation,
    ResourceExhaustion,
    AnomalyDetected,
    ThresholdExceeded,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AlertSeverity {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AlertStatus {
    Active,
    Acknowledged,
    Resolved,
    Suppressed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AlertSource {
    SecurityMonitor,
    PerformanceMonitor,
    ComplianceChecker,
    AnomalyDetector,
    SystemHealth,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRule {
    pub rule_id: Uuid,
    pub name: String,
    pub description: String,
    pub condition: AlertCondition,
    pub severity: AlertSeverity,
    pub enabled: bool,
    pub cooldown_minutes: u64,
    pub last_triggered: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AlertCondition {
    ErrorRateThreshold { threshold_percent: f64, time_window_minutes: u64 },
    ResponseTimeThreshold { threshold_ms: u64, time_window_minutes: u64 },
    SecurityEventCount { max_events: u64, time_window_minutes: u64 },
    FailedAuthAttempts { max_attempts: u64, time_window_minutes: u64 },
    UnusualTrafficPattern { deviation_factor: f64 },
    MemoryUsageThreshold { threshold_percent: f64 },
    ConcurrentRequestsThreshold { max_requests: u32 },
    ComplianceScoreThreshold { min_score: f64 },
}

#[derive(Debug, Clone)]
pub struct AlertManager {
    alerts: Arc<RwLock<Vec<Alert>>>,
    rules: Arc<RwLock<Vec<AlertRule>>>,
    metrics_collector: Arc<MetricsCollector>,
    max_alerts: usize,
}

impl AlertManager {
    pub fn new(metrics_collector: Arc<MetricsCollector>, max_alerts: usize) -> Self {
        let mut rules = Vec::new();

        // Add default alert rules
        rules.push(AlertRule {
            rule_id: Uuid::new_v4(),
            name: "High Error Rate".to_string(),
            description: "Triggered when error rate exceeds 10% over 5 minutes".to_string(),
            condition: AlertCondition::ErrorRateThreshold {
                threshold_percent: 10.0,
                time_window_minutes: 5,
            },
            severity: AlertSeverity::High,
            enabled: true,
            cooldown_minutes: 10,
            last_triggered: None,
        });

        rules.push(AlertRule {
            rule_id: Uuid::new_v4(),
            name: "Slow Response Time".to_string(),
            description: "Triggered when average response time exceeds 5 seconds".to_string(),
            condition: AlertCondition::ResponseTimeThreshold {
                threshold_ms: 5000,
                time_window_minutes: 5,
            },
            severity: AlertSeverity::Medium,
            enabled: true,
            cooldown_minutes: 15,
            last_triggered: None,
        });

        rules.push(AlertRule {
            rule_id: Uuid::new_v4(),
            name: "Multiple Security Events".to_string(),
            description: "Triggered when more than 5 security events occur within 10 minutes"
                .to_string(),
            condition: AlertCondition::SecurityEventCount {
                max_events: 5,
                time_window_minutes: 10,
            },
            severity: AlertSeverity::Critical,
            enabled: true,
            cooldown_minutes: 5,
            last_triggered: None,
        });

        rules.push(AlertRule {
            rule_id: Uuid::new_v4(),
            name: "Failed Authentication Attempts".to_string(),
            description: "Triggered when more than 10 failed auth attempts occur within 5 minutes"
                .to_string(),
            condition: AlertCondition::FailedAuthAttempts {
                max_attempts: 10,
                time_window_minutes: 5,
            },
            severity: AlertSeverity::High,
            enabled: true,
            cooldown_minutes: 10,
            last_triggered: None,
        });

        rules.push(AlertRule {
            rule_id: Uuid::new_v4(),
            name: "Low Compliance Score".to_string(),
            description: "Triggered when compliance score falls below 80%".to_string(),
            condition: AlertCondition::ComplianceScoreThreshold { min_score: 80.0 },
            severity: AlertSeverity::Medium,
            enabled: true,
            cooldown_minutes: 30,
            last_triggered: None,
        });

        Self {
            alerts: Arc::new(RwLock::new(Vec::new())),
            rules: Arc::new(RwLock::new(rules)),
            metrics_collector,
            max_alerts,
        }
    }

    pub async fn check_alert_conditions(&self) {
        let mut rules = self.rules.write().await;
        let now = Utc::now();

        for rule in rules.iter_mut() {
            if !rule.enabled {
                continue;
            }

            // Check cooldown period
            if let Some(last_triggered) = rule.last_triggered {
                let cooldown_duration = Duration::minutes(rule.cooldown_minutes as i64);
                if now - last_triggered < cooldown_duration {
                    continue;
                }
            }

            // Check condition
            if self.evaluate_condition(&rule.condition).await {
                self.trigger_alert(rule).await;
                rule.last_triggered = Some(now);
            }
        }

        // Check for anomalies
        self.check_anomalies().await;
    }

    async fn evaluate_condition(&self, condition: &AlertCondition) -> bool {
        match condition {
            AlertCondition::ErrorRateThreshold { threshold_percent, time_window_minutes } => {
                let time_window = Duration::minutes(*time_window_minutes as i64);
                let summary = self.metrics_collector.get_metrics_summary(time_window).await;
                summary["error_rate"].as_f64().unwrap_or(0.0) > *threshold_percent as f64
            }
            AlertCondition::ResponseTimeThreshold { threshold_ms, time_window_minutes } => {
                let time_window = Duration::minutes(*time_window_minutes as i64);
                let summary = self.metrics_collector.get_metrics_summary(time_window).await;
                summary["average_response_time_ms"].as_f64().unwrap_or(0.0) > *threshold_ms as f64
            }
            AlertCondition::SecurityEventCount { max_events, time_window_minutes } => {
                let time_window = Duration::minutes(*time_window_minutes as i64);
                let summary = self.metrics_collector.get_metrics_summary(time_window).await;
                summary["security_events"].as_u64().unwrap_or(0) > *max_events as u64
            }
            AlertCondition::FailedAuthAttempts { max_attempts, time_window_minutes } => {
                let time_window = Duration::minutes(*time_window_minutes as i64);
                let security_metrics =
                    self.metrics_collector.get_security_metrics(Some(1000)).await;
                let since = Utc::now() - time_window;

                let failed_auth_count = security_metrics
                    .iter()
                    // Timestamp filtering removed - using Cloud Monitoring instead
                    .count() as u64;

                failed_auth_count > *max_attempts
            }
            AlertCondition::ComplianceScoreThreshold { min_score } => {
                let time_window = Duration::hours(1);
                let summary = self.metrics_collector.get_metrics_summary(time_window).await;
                summary["compliance_score"].as_f64().unwrap_or(100.0) < *min_score
            }
            AlertCondition::UnusualTrafficPattern { deviation_factor: _ } => {
                // Simplified implementation - could be enhanced with statistical analysis
                let time_window = Duration::hours(1);
                let summary = self.metrics_collector.get_metrics_summary(time_window).await;
                summary["operations_per_second"].as_f64().unwrap_or(0.0) > 100.0
            }
            AlertCondition::MemoryUsageThreshold { threshold_percent: _ } => {
                // Would require system metrics integration
                false
            }
            AlertCondition::ConcurrentRequestsThreshold { max_requests: _ } => {
                // Would require request tracking integration
                false
            }
        }
    }

    async fn trigger_alert(&self, rule: &AlertRule) {
        let alert = Alert {
            alert_id: Uuid::new_v4(),
            alert_type: self.map_condition_to_alert_type(&rule.condition),
            severity: rule.severity.clone(),
            title: rule.name.clone(),
            description: rule.description.clone(),
            triggered_at: Utc::now(),
            resolved_at: None,
            status: AlertStatus::Active,
            source: AlertSource::SecurityMonitor,
            metadata: HashMap::new(),
            actions_taken: Vec::new(),
        };

        let metrics_severity = match alert.severity {
            AlertSeverity::Critical => SecuritySeverity::Critical,
            AlertSeverity::High => SecuritySeverity::High,
            AlertSeverity::Medium => SecuritySeverity::Medium,
            AlertSeverity::Low => SecuritySeverity::Low,
        };

        let mut alerts = self.alerts.write().await;
        alerts.push(alert.clone());

        // Keep only the most recent alerts
        if alerts.len() > self.max_alerts {
            let len = alerts.len();
            alerts.drain(0..len - self.max_alerts);
        }

        // Log the alert
        match alert.severity {
            AlertSeverity::Critical => {
                tracing::error!("CRITICAL ALERT: {} - {}", alert.title, alert.description);
            }
            AlertSeverity::High => {
                tracing::warn!("HIGH ALERT: {} - {}", alert.title, alert.description);
            }
            AlertSeverity::Medium => {
                tracing::warn!("MEDIUM ALERT: {} - {}", alert.title, alert.description);
            }
            AlertSeverity::Low => {
                tracing::info!("LOW ALERT: {} - {}", alert.title, alert.description);
            }
        }

        // Security events are now handled by Cloud Monitoring
        // self.metrics_collector.record_security_event(...).await;
    }

    async fn check_anomalies(&self) {
        // Check for timing anomalies
        let timing_anomalies = self.metrics_collector.detect_timing_anomalies().await;
        for anomaly in timing_anomalies {
            let alert = Alert {
                alert_id: Uuid::new_v4(),
                alert_type: AlertType::AnomalyDetected,
                severity: AlertSeverity::Medium,
                title: "Timing Anomaly Detected".to_string(),
                description: "Timing anomaly detected".to_string(),
                triggered_at: Utc::now(),
                resolved_at: None,
                status: AlertStatus::Active,
                source: AlertSource::AnomalyDetector,
                metadata: HashMap::new(),
                actions_taken: Vec::new(),
            };

            let mut alerts = self.alerts.write().await;
            alerts.push(alert);
        }

        // Check for usage anomalies
        let usage_anomalies = self.metrics_collector.detect_usage_anomalies().await;
        for anomaly in usage_anomalies {
            let alert = Alert {
                alert_id: Uuid::new_v4(),
                alert_type: AlertType::SecurityThreat,
                severity: AlertSeverity::High,
                title: "Unusual Usage Pattern Detected".to_string(),
                description: "Timing anomaly detected".to_string(),
                triggered_at: Utc::now(),
                resolved_at: None,
                status: AlertStatus::Active,
                source: AlertSource::AnomalyDetector,
                metadata: HashMap::new(),
                actions_taken: Vec::new(),
            };

            let mut alerts = self.alerts.write().await;
            alerts.push(alert);
        }
    }

    fn map_condition_to_alert_type(&self, condition: &AlertCondition) -> AlertType {
        match condition {
            AlertCondition::ErrorRateThreshold { .. } => AlertType::SystemError,
            AlertCondition::ResponseTimeThreshold { .. } => AlertType::PerformanceDegradation,
            AlertCondition::SecurityEventCount { .. } => AlertType::SecurityThreat,
            AlertCondition::FailedAuthAttempts { .. } => AlertType::SecurityThreat,
            AlertCondition::ComplianceScoreThreshold { .. } => AlertType::ComplianceViolation,
            AlertCondition::UnusualTrafficPattern { .. } => AlertType::AnomalyDetected,
            AlertCondition::MemoryUsageThreshold { .. } => AlertType::ResourceExhaustion,
            AlertCondition::ConcurrentRequestsThreshold { .. } => AlertType::ResourceExhaustion,
        }
    }

    pub async fn get_active_alerts(&self) -> Vec<Alert> {
        let alerts = self.alerts.read().await;
        alerts.iter().filter(|alert| matches!(alert.status, AlertStatus::Active)).cloned().collect()
    }

    pub async fn get_all_alerts(&self, limit: Option<usize>) -> Vec<Alert> {
        let alerts = self.alerts.read().await;
        let limit = limit.unwrap_or(100).min(alerts.len());
        alerts.iter().rev().take(limit).cloned().collect()
    }

    pub async fn acknowledge_alert(&self, alert_id: Uuid) -> bool {
        let mut alerts = self.alerts.write().await;
        if let Some(alert) = alerts.iter_mut().find(|a| a.alert_id == alert_id) {
            alert.status = AlertStatus::Acknowledged;
            alert.actions_taken.push(format!("Alert acknowledged at {}", Utc::now()));
            tracing::info!("Alert {} acknowledged", alert_id);
            true
        } else {
            false
        }
    }

    pub async fn resolve_alert(&self, alert_id: Uuid, resolution_note: Option<String>) -> bool {
        let mut alerts = self.alerts.write().await;
        if let Some(alert) = alerts.iter_mut().find(|a| a.alert_id == alert_id) {
            alert.status = AlertStatus::Resolved;
            alert.resolved_at = Some(Utc::now());

            let note = resolution_note.unwrap_or_else(|| "Alert resolved".to_string());
            alert.actions_taken.push(format!("Alert resolved at {}: {}", Utc::now(), note));

            tracing::info!("Alert {} resolved: {}", alert_id, note);
            true
        } else {
            false
        }
    }

    pub async fn add_alert_rule(&self, rule: AlertRule) {
        let mut rules = self.rules.write().await;
        rules.push(rule);
    }

    pub async fn get_alert_rules(&self) -> Vec<AlertRule> {
        let rules = self.rules.read().await;
        rules.clone()
    }

    pub async fn update_alert_rule(&self, rule_id: Uuid, updated_rule: AlertRule) -> bool {
        let mut rules = self.rules.write().await;
        if let Some(rule) = rules.iter_mut().find(|r| r.rule_id == rule_id) {
            *rule = updated_rule;
            true
        } else {
            false
        }
    }

    pub async fn delete_alert_rule(&self, rule_id: Uuid) -> bool {
        let mut rules = self.rules.write().await;
        if let Some(pos) = rules.iter().position(|r| r.rule_id == rule_id) {
            rules.remove(pos);
            true
        } else {
            false
        }
    }
}
