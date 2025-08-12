use crate::security::{AuditLogger, ComplianceManager};
use crate::security::repository::ApiKeyRepositoryRef;
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub audit_logger: Arc<AuditLogger>,
    pub compliance_manager: Arc<ComplianceManager>,
    pub analytics_repository: Option<ApiKeyRepositoryRef>,
}

impl AppState {
    pub fn new(audit_logger: Arc<AuditLogger>, compliance_manager: Arc<ComplianceManager>) -> Self {
        Self { 
            audit_logger, 
            compliance_manager,
            analytics_repository: None,
        }
    }

    pub fn with_analytics_repository(
        audit_logger: Arc<AuditLogger>, 
        compliance_manager: Arc<ComplianceManager>,
        analytics_repository: ApiKeyRepositoryRef,
    ) -> Self {
        Self { 
            audit_logger, 
            compliance_manager,
            analytics_repository: Some(analytics_repository),
        }
    }

    pub fn sanitize_sensitive_data(&self, data: &str) -> String {
        self.compliance_manager.sanitize_sensitive_data(data)
    }

    pub fn pseudonymize_user_id(&self, user_id: &str) -> String {
        self.compliance_manager.pseudonymize_user_id(user_id)
    }

    pub async fn log_compliance_with_user(
        &self,
        event_type: crate::security::ComplianceEventType,
        details: std::collections::HashMap<String, String>,
        risk_level: crate::security::RiskLevel,
        user_id: Option<&str>,
        ip_address: Option<&str>,
    ) {
        self.compliance_manager
            .log_event_with_user(event_type, details, risk_level, user_id, ip_address)
            .await;
    }
}
