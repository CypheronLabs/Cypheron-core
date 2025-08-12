pub mod alerts;
pub mod analytics_logger;
pub mod compliance;
pub mod health;
pub mod metrics;
pub mod security_events;

pub use alerts::{Alert, AlertManager, AlertRule};
pub use analytics_logger::analytics_middleware;
pub use compliance::{ComplianceChecker, ComplianceFramework};
pub use health::HealthChecker;
pub use metrics::MetricsCollector;
pub use security_events::{SecurityEvent, SecurityEventMonitor};

use crate::security::{AuditLogger, ComplianceManager};
use axum::extract::FromRef;
use std::sync::Arc;

#[derive(Clone)]
pub struct MonitoringState {
    pub metrics: Arc<MetricsCollector>,
    pub alerts: Arc<AlertManager>,
    pub compliance: Arc<ComplianceChecker>,
    pub security_events: Arc<SecurityEventMonitor>,
    pub health: Arc<HealthChecker>,
    pub audit: Arc<AuditLogger>,
    pub compliance_manager: Arc<ComplianceManager>,
}

impl MonitoringState {
    pub fn new(
        metrics: Arc<MetricsCollector>,
        alerts: Arc<AlertManager>,
        compliance: Arc<ComplianceChecker>,
        security_events: Arc<SecurityEventMonitor>,
        health: Arc<HealthChecker>,
    ) -> Self {
        let audit = Arc::new(AuditLogger::new(10000));
        let compliance_manager = Arc::new(ComplianceManager::new());

        Self { metrics, alerts, compliance, security_events, health, audit, compliance_manager }
    }

    pub fn new_with_audit(
        metrics: Arc<MetricsCollector>,
        alerts: Arc<AlertManager>,
        compliance: Arc<ComplianceChecker>,
        security_events: Arc<SecurityEventMonitor>,
        health: Arc<HealthChecker>,
        audit: Arc<AuditLogger>,
    ) -> Self {
        let compliance_manager = Arc::new(ComplianceManager::new());

        Self { metrics, alerts, compliance, security_events, health, audit, compliance_manager }
    }
}

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

impl FromRef<MonitoringState> for Arc<ComplianceManager> {
    fn from_ref(state: &MonitoringState) -> Arc<ComplianceManager> {
        state.compliance_manager.clone()
    }
}
