use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub event_type: AuditEventType,
    pub api_key_id: Option<Uuid>,
    pub ip_address: String,
    pub user_agent: Option<String>,
    pub request_method: String,
    pub request_path: String,
    pub response_status: u16,
    pub response_time_ms: u64,
    pub error_message: Option<String>,
    pub resource_accessed: String,
    pub additional_data: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditEventType {
    ApiKeyCreated,
    ApiKeyUsed,
    ApiKeyExpired,
    AuthenticationFailed,
    AuthorizationFailed,
    RateLimitExceeded,
    SuspiciousActivity,
    CryptoOperation,
    CryptoVerification,
    ErrorOccurred,
}

#[derive(Debug, Clone)]
pub struct AuditLogger {
    events: Arc<RwLock<VecDeque<AuditEvent>>>,
    max_events: usize,
}

impl AuditLogger {
    pub fn new(max_events: usize) -> Self {
        Self {
            events: Arc::new(RwLock::new(VecDeque::with_capacity(max_events))),
            max_events,
        }
    }

    pub async fn log_event(&self, event: AuditEvent) {
        let mut events = self.events.write().await;
        
        // Remove oldest event if at capacity
        if events.len() >= self.max_events {
            events.pop_front();
        }
        
        // Log to tracing as well
        match event.event_type {
            AuditEventType::AuthenticationFailed | 
            AuditEventType::AuthorizationFailed |
            AuditEventType::SuspiciousActivity => {
                tracing::warn!(
                    "Security event: {:?} - IP: {} - Path: {} - Status: {}",
                    event.event_type,
                    event.ip_address,
                    event.request_path,
                    event.response_status
                );
            }
            AuditEventType::RateLimitExceeded => {
                tracing::warn!(
                    "Rate limit exceeded: IP: {} - Path: {} - API Key: {:?}",
                    event.ip_address,
                    event.request_path,
                    event.api_key_id
                );
            }
            AuditEventType::ErrorOccurred => {
                tracing::error!(
                    "API error: {} - Path: {} - Error: {:?}",
                    event.response_status,
                    event.request_path,
                    event.error_message
                );
            }
            _ => {
                tracing::info!(
                    "Audit event: {:?} - Path: {} - Status: {} - Duration: {}ms",
                    event.event_type,
                    event.request_path,
                    event.response_status,
                    event.response_time_ms
                );
            }
        }
        
        events.push_back(event);
    }

    pub async fn get_recent_events(&self, limit: Option<usize>) -> Vec<AuditEvent> {
        let events = self.events.read().await;
        let limit = limit.unwrap_or(100).min(events.len());
        
        events
            .iter()
            .rev() // Most recent first
            .take(limit)
            .cloned()
            .collect()
    }

    pub async fn get_events_by_type(&self, event_type: AuditEventType, limit: Option<usize>) -> Vec<AuditEvent> {
        let events = self.events.read().await;
        let limit = limit.unwrap_or(100);
        
        events
            .iter()
            .filter(|e| std::mem::discriminant(&e.event_type) == std::mem::discriminant(&event_type))
            .rev()
            .take(limit)
            .cloned()
            .collect()
    }

    pub async fn get_events_by_api_key(&self, api_key_id: Uuid, limit: Option<usize>) -> Vec<AuditEvent> {
        let events = self.events.read().await;
        let limit = limit.unwrap_or(100);
        
        events
            .iter()
            .filter(|e| e.api_key_id == Some(api_key_id))
            .rev()
            .take(limit)
            .cloned()
            .collect()
    }

    pub async fn get_security_events(&self, limit: Option<usize>) -> Vec<AuditEvent> {
        let events = self.events.read().await;
        let limit = limit.unwrap_or(100);
        
        events
            .iter()
            .filter(|e| matches!(
                e.event_type,
                AuditEventType::AuthenticationFailed |
                AuditEventType::AuthorizationFailed |
                AuditEventType::RateLimitExceeded |
                AuditEventType::SuspiciousActivity
            ))
            .rev()
            .take(limit)
            .cloned()
            .collect()
    }
}

// Helper function to create audit events
impl AuditEvent {
    pub fn new(
        event_type: AuditEventType,
        request_method: String,
        request_path: String,
        response_status: u16,
        response_time_ms: u64,
        ip_address: String,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            event_type,
            api_key_id: None,
            ip_address,
            user_agent: None,
            request_method,
            request_path,
            response_status,
            response_time_ms,
            error_message: None,
            resource_accessed: "unknown".to_string(),
            additional_data: None,
        }
    }

    pub fn with_api_key_id(mut self, api_key_id: Uuid) -> Self {
        self.api_key_id = Some(api_key_id);
        self
    }

    pub fn with_user_agent(mut self, user_agent: String) -> Self {
        self.user_agent = Some(user_agent);
        self
    }

    pub fn with_error_message(mut self, error_message: String) -> Self {
        self.error_message = Some(error_message);
        self
    }

    pub fn with_resource(mut self, resource: String) -> Self {
        self.resource_accessed = resource;
        self
    }

    pub fn with_additional_data(mut self, data: serde_json::Value) -> Self {
        self.additional_data = Some(data);
        self
    }
}

#[derive(Debug, Serialize)]
pub struct AuditLogResponse {
    pub events: Vec<AuditEvent>,
    pub total_count: usize,
    pub event_types: Vec<String>,
}

// Audit log endpoints for admin access
use axum::{
    extract::{Query, State},
    response::Json,
    routing::get,
    Router,
};
use std::collections::HashMap;

pub async fn get_audit_logs(
    State(audit_logger): State<AuditLogger>,
    Query(params): Query<HashMap<String, String>>,
) -> Json<AuditLogResponse> {
    let limit = params
        .get("limit")
        .and_then(|s| s.parse().ok())
        .unwrap_or(100);

    let events = if let Some(event_type_str) = params.get("type") {
        match event_type_str.as_str() {
            "security" => audit_logger.get_security_events(Some(limit)).await,
            "auth_failed" => audit_logger.get_events_by_type(AuditEventType::AuthenticationFailed, Some(limit)).await,
            "rate_limit" => audit_logger.get_events_by_type(AuditEventType::RateLimitExceeded, Some(limit)).await,
            _ => audit_logger.get_recent_events(Some(limit)).await,
        }
    } else {
        audit_logger.get_recent_events(Some(limit)).await
    };

    let event_types = vec![
        "api_key_created".to_string(),
        "api_key_used".to_string(),
        "authentication_failed".to_string(),
        "authorization_failed".to_string(),
        "rate_limit_exceeded".to_string(),
        "suspicious_activity".to_string(),
        "crypto_operation".to_string(),
        "error_occurred".to_string(),
    ];

    Json(AuditLogResponse {
        total_count: events.len(),
        events,
        event_types,
    })
}

pub fn audit_routes() -> Router<AuditLogger> {
    Router::new()
        .route("/admin/audit-logs", get(get_audit_logs))
}