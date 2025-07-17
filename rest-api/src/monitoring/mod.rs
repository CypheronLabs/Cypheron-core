pub mod metrics;
pub mod alerts;
pub mod compliance;
pub mod security_events;
pub mod health;

// Export key types with specific names to avoid conflicts
pub use metrics::{MetricsCollector, CryptoMetrics, SecurityEventType as MetricsSecurityEventType, SecuritySeverity as MetricsSecuritySeverity};
pub use alerts::{AlertManager, Alert, AlertRule, AlertStatus, AlertSeverity};
pub use compliance::{ComplianceChecker, ComplianceFramework, ComplianceStatus as ComplianceCheckStatus};
pub use security_events::{SecurityEventMonitor, SecurityEvent, SecurityEventType as EventSecurityEventType, SecuritySeverity as EventSecuritySeverity, ThreatLevel as EventThreatLevel};
pub use health::{HealthChecker, HealthStatus, ServiceHealth, ServiceStatus, ThreatLevel as HealthThreatLevel};

use std::sync::Arc;
use axum::extract::FromRef;
use crate::security::AuditLogger;

/// Combined monitoring state for the API routes
#[derive(Clone)]
pub struct MonitoringState {
    pub metrics: Arc<MetricsCollector>,
    pub alerts: Arc<AlertManager>,
    pub compliance: Arc<ComplianceChecker>,
    pub security_events: Arc<SecurityEventMonitor>,
    pub health: Arc<HealthChecker>,
    pub audit: Arc<AuditLogger>,
}

impl MonitoringState {
    pub fn new(
        metrics: Arc<MetricsCollector>,
        alerts: Arc<AlertManager>,
        compliance: Arc<ComplianceChecker>,
        security_events: Arc<SecurityEventMonitor>,
        health: Arc<HealthChecker>,
    ) -> Self {
        // Create audit logger with reasonable defaults
        let audit = Arc::new(AuditLogger::new(10000));
        
        Self {
            metrics,
            alerts,
            compliance,
            security_events,
            health,
            audit,
        }
    }
    
    pub fn new_with_audit(
        metrics: Arc<MetricsCollector>,
        alerts: Arc<AlertManager>,
        compliance: Arc<ComplianceChecker>,
        security_events: Arc<SecurityEventMonitor>,
        health: Arc<HealthChecker>,
        audit: Arc<AuditLogger>,
    ) -> Self {
        Self {
            metrics,
            alerts,
            compliance,
            security_events,
            health,
            audit,
        }
    }
}

// Enable individual extractors for each monitoring component
impl FromRef<MonitoringState> for Arc<MetricsCollector> {
    fn from_ref(state: &MonitoringState) -> Arc<MetricsCollector> {
        state.metrics.clone()
    }
}

impl FromRef<MonitoringState> for Arc<AlertManager> {
    fn from_ref(state: &MonitoringState) -> Arc<AlertManager> {
        state.alerts.clone()
    }
}

impl FromRef<MonitoringState> for Arc<ComplianceChecker> {
    fn from_ref(state: &MonitoringState) -> Arc<ComplianceChecker> {
        state.compliance.clone()
    }
}

impl FromRef<MonitoringState> for Arc<SecurityEventMonitor> {
    fn from_ref(state: &MonitoringState) -> Arc<SecurityEventMonitor> {
        state.security_events.clone()
    }
}

impl FromRef<MonitoringState> for Arc<HealthChecker> {
    fn from_ref(state: &MonitoringState) -> Arc<HealthChecker> {
        state.health.clone()
    }
}

impl FromRef<MonitoringState> for Arc<AuditLogger> {
    fn from_ref(state: &MonitoringState) -> Arc<AuditLogger> {
        state.audit.clone()
    }
}