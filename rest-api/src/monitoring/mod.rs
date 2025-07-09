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

/// Combined monitoring state for the API routes
#[derive(Clone)]
pub struct MonitoringState {
    pub metrics: Arc<MetricsCollector>,
    pub alerts: Arc<AlertManager>,
    pub compliance: Arc<ComplianceChecker>,
    pub security_events: Arc<SecurityEventMonitor>,
    pub health: Arc<HealthChecker>,
}

impl MonitoringState {
    pub fn new(
        metrics: Arc<MetricsCollector>,
        alerts: Arc<AlertManager>,
        compliance: Arc<ComplianceChecker>,
        security_events: Arc<SecurityEventMonitor>,
        health: Arc<HealthChecker>,
    ) -> Self {
        Self {
            metrics,
            alerts,
            compliance,
            security_events,
            health,
        }
    }
}