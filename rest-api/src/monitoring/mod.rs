pub mod metrics;
pub mod alerts;
pub mod compliance;
pub mod security_events;
pub mod health;

// Export key types with specific names to avoid conflicts
pub use metrics::MetricsCollector;
pub use alerts::{AlertManager, Alert, AlertRule};
pub use compliance::{ComplianceChecker, ComplianceFramework};
pub use security_events::{SecurityEventMonitor, SecurityEvent};
pub use health::HealthChecker;

use std::sync::Arc;
use axum::extract::FromRef;
use crate::security::{AuditLogger, ComplianceManager};

/// Combined monitoring state for the API routes
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
        // Create audit logger with reasonable defaults
        let audit = Arc::new(AuditLogger::new(10000));
        let compliance_manager = Arc::new(ComplianceManager::new());
        
        Self {
            metrics,
            alerts,
            compliance,
            security_events,
            health,
            audit,
            compliance_manager,
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
        let compliance_manager = Arc::new(ComplianceManager::new());
        
        Self {
            metrics,
            alerts,
            compliance,
            security_events,
            health,
            audit,
            compliance_manager,
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

impl FromRef<MonitoringState> for Arc<ComplianceManager> {
    fn from_ref(state: &MonitoringState) -> Arc<ComplianceManager> {
        state.compliance_manager.clone()
    }
}