use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub event_id: Uuid,
    pub event_type: SecurityEventType,
    pub severity: SecuritySeverity,
    pub source: EventSource,
    pub target: Option<EventTarget>,
    pub description: String,
    pub timestamp: DateTime<Utc>,
    pub client_ip: Option<String>,
    pub user_agent: Option<String>,
    pub api_key_id: Option<Uuid>,
    pub request_id: Option<String>,
    pub additional_context: HashMap<String, String>,
    pub indicators: Vec<ThreatIndicator>,
    pub response_action: Option<ResponseAction>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityEventType {
    // Authentication Events
    AuthenticationSuccess,
    AuthenticationFailure,
    AuthorizationFailure,
    PrivilegeEscalation,

    // API Security Events
    RateLimitExceeded,
    InvalidApiKey,
    SuspiciousApiUsage,
    ApiAbuseDetected,

    // Cryptographic Events
    CryptographicFailure,
    KeyGenerationRequest,
    SignatureVerificationFailure,
    EncryptionDecryptionFailure,

    // Attack Indicators
    BruteForceAttack,
    TimingAttack,
    InjectionAttempt,
    DataExfiltrationAttempt,

    // System Events
    SecurityPolicyViolation,
    ConfigurationChange,
    SystemIntegrityIssue,
    ComplianceViolation,

    // Anomaly Detection
    UnusualTrafficPattern,
    GeographicAnomaly,
    TimeBasedAnomaly,
    BehavioralAnomaly,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecuritySeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EventSource {
    ApiGateway,
    AuthenticationService,
    CryptoEngine,
    RateLimiter,
    Monitor,
    User,
    System,
    External,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventTarget {
    pub target_type: TargetType,
    pub target_id: String,
    pub target_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TargetType {
    User,
    ApiKey,
    Endpoint,
    Resource,
    System,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIndicator {
    pub indicator_type: IndicatorType,
    pub value: String,
    pub confidence: f64, // 0.0 - 1.0
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IndicatorType {
    IpAddress,
    UserAgent,
    RequestPattern,
    TimingPattern,
    GeographicLocation,
    ApiKeyPattern,
    PayloadSignature,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseAction {
    pub action_type: ActionType,
    pub description: String,
    pub applied_at: DateTime<Utc>,
    pub applied_by: String,
    pub effective_until: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ActionType {
    Block,
    Throttle,
    Monitor,
    Alert,
    Quarantine,
    Escalate,
    NoAction,
}

#[derive(Debug, Clone)]
pub struct SecurityEventMonitor {
    events: Arc<RwLock<Vec<SecurityEvent>>>,
    threat_indicators: Arc<RwLock<HashMap<String, ThreatIndicator>>>,
    blocked_ips: Arc<RwLock<HashMap<String, DateTime<Utc>>>>,
    max_events: usize,
}

impl SecurityEventMonitor {
    pub fn new(max_events: usize) -> Self {
        Self {
            events: Arc::new(RwLock::new(Vec::new())),
            threat_indicators: Arc::new(RwLock::new(HashMap::new())),
            blocked_ips: Arc::new(RwLock::new(HashMap::new())),
            max_events,
        }
    }

    pub async fn record_event(&self, mut event: SecurityEvent) {
        self.analyze_event(&mut event).await;

        self.apply_automatic_response(&mut event).await;

        let mut events = self.events.write().await;
        events.push(event.clone());

        if events.len() > self.max_events {
            let len = events.len();
            events.drain(0..len - self.max_events);
        }

        match event.severity {
            SecuritySeverity::Critical => {
                tracing::error!(
                    "CRITICAL SECURITY EVENT: {:?} - {}",
                    event.event_type,
                    event.description
                );
            }
            SecuritySeverity::High => {
                tracing::warn!(
                    "HIGH SECURITY EVENT: {:?} - {}",
                    event.event_type,
                    event.description
                );
            }
            SecuritySeverity::Medium => {
                tracing::warn!(
                    "MEDIUM SECURITY EVENT: {:?} - {}",
                    event.event_type,
                    event.description
                );
            }
            SecuritySeverity::Low => {
                tracing::info!(
                    "LOW SECURITY EVENT: {:?} - {}",
                    event.event_type,
                    event.description
                );
            }
            SecuritySeverity::Info => {
                tracing::info!("SECURITY INFO: {:?} - {}", event.event_type, event.description);
            }
        }
    }

    async fn analyze_event(&self, event: &mut SecurityEvent) {
        // Extract potential threat indicators
        if let Some(ip) = &event.client_ip {
            self.update_threat_indicator(
                IndicatorType::IpAddress,
                ip.clone(),
                0.5, // Base confidence
                event.timestamp,
            )
            .await;
        }

        if let Some(user_agent) = &event.user_agent {
            self.update_threat_indicator(
                IndicatorType::UserAgent,
                user_agent.clone(),
                0.3,
                event.timestamp,
            )
            .await;
        }

        // Check for patterns that indicate attacks
        match event.event_type {
            SecurityEventType::AuthenticationFailure => {
                if let Some(ip) = &event.client_ip {
                    let recent_failures = self
                        .count_recent_events_by_ip(
                            ip,
                            SecurityEventType::AuthenticationFailure,
                            Duration::minutes(5),
                        )
                        .await;

                    if recent_failures >= 5 {
                        event.event_type = SecurityEventType::BruteForceAttack;
                        event.severity = SecuritySeverity::High;
                        event.description = format!(
                            "Brute force attack detected: {} failed authentication attempts from {}",
                            recent_failures, ip
                        );
                    }
                }
            }
            SecurityEventType::RateLimitExceeded => {
                if let Some(ip) = &event.client_ip {
                    let rate_limit_events = self
                        .count_recent_events_by_ip(
                            ip,
                            SecurityEventType::RateLimitExceeded,
                            Duration::minutes(10),
                        )
                        .await;

                    if rate_limit_events >= 3 {
                        event.event_type = SecurityEventType::ApiAbuseDetected;
                        event.severity = SecuritySeverity::High;
                    }
                }
            }
            _ => {}
        }
    }

    async fn apply_automatic_response(&self, event: &mut SecurityEvent) {
        let action = match (&event.event_type, &event.severity) {
            (SecurityEventType::BruteForceAttack, SecuritySeverity::High) => {
                if let Some(ip) = &event.client_ip {
                    self.block_ip(ip.clone(), Duration::hours(1)).await;
                    Some(ResponseAction {
                        action_type: ActionType::Block,
                        description: format!(
                            "IP {} blocked for 1 hour due to brute force attack",
                            ip
                        ),
                        applied_at: Utc::now(),
                        applied_by: "AutoResponseSystem".to_string(),
                        effective_until: Some(Utc::now() + Duration::hours(1)),
                    })
                } else {
                    None
                }
            }
            (SecurityEventType::ApiAbuseDetected, SecuritySeverity::High) => {
                if let Some(ip) = &event.client_ip {
                    self.block_ip(ip.clone(), Duration::minutes(30)).await;
                    Some(ResponseAction {
                        action_type: ActionType::Throttle,
                        description: format!("IP {} throttled for 30 minutes due to API abuse", ip),
                        applied_at: Utc::now(),
                        applied_by: "AutoResponseSystem".to_string(),
                        effective_until: Some(Utc::now() + Duration::minutes(30)),
                    })
                } else {
                    None
                }
            }
            (_, SecuritySeverity::Critical) => Some(ResponseAction {
                action_type: ActionType::Escalate,
                description: "Critical security event escalated to security team".to_string(),
                applied_at: Utc::now(),
                applied_by: "AutoResponseSystem".to_string(),
                effective_until: None,
            }),
            _ => Some(ResponseAction {
                action_type: ActionType::Monitor,
                description: "Event logged for monitoring".to_string(),
                applied_at: Utc::now(),
                applied_by: "SecurityMonitor".to_string(),
                effective_until: None,
            }),
        };

        event.response_action = action;
    }

    async fn update_threat_indicator(
        &self,
        indicator_type: IndicatorType,
        value: String,
        base_confidence: f64,
        timestamp: DateTime<Utc>,
    ) {
        let mut indicators = self.threat_indicators.write().await;
        let key = format!("{:?}:{}", indicator_type, value);

        match indicators.get_mut(&key) {
            Some(indicator) => {
                indicator.last_seen = timestamp;
                indicator.count += 1;
                // Increase confidence with repeated observations
                indicator.confidence = (indicator.confidence + 0.1).min(1.0);
            }
            None => {
                let indicator = ThreatIndicator {
                    indicator_type,
                    value,
                    confidence: base_confidence,
                    first_seen: timestamp,
                    last_seen: timestamp,
                    count: 1,
                };
                indicators.insert(key, indicator);
            }
        }
    }

    async fn count_recent_events_by_ip(
        &self,
        ip: &str,
        event_type: SecurityEventType,
        time_window: Duration,
    ) -> u64 {
        let events = self.events.read().await;
        let since = Utc::now() - time_window;

        events
            .iter()
            .filter(|e| e.timestamp >= since)
            .filter(|e| e.client_ip.as_ref() == Some(&ip.to_string()))
            .filter(|e| {
                std::mem::discriminant(&e.event_type) == std::mem::discriminant(&event_type)
            })
            .count() as u64
    }

    async fn block_ip(&self, ip: String, duration: Duration) {
        let mut blocked_ips = self.blocked_ips.write().await;
        let unblock_time = Utc::now() + duration;
        blocked_ips.insert(ip.clone(), unblock_time);

        tracing::warn!("IP {} blocked until {}", ip, unblock_time);
    }

    pub async fn is_ip_blocked(&self, ip: &str) -> bool {
        let mut blocked_ips = self.blocked_ips.write().await;
        let now = Utc::now();

        // Clean up expired blocks
        blocked_ips.retain(|_, unblock_time| *unblock_time > now);

        blocked_ips.contains_key(ip)
    }

    pub async fn get_events(&self, limit: Option<usize>) -> Vec<SecurityEvent> {
        let events = self.events.read().await;
        let limit = limit.unwrap_or(100).min(events.len());
        events.iter().rev().take(limit).cloned().collect()
    }

    pub async fn get_events_by_type(
        &self,
        event_type: SecurityEventType,
        limit: Option<usize>,
    ) -> Vec<SecurityEvent> {
        let events = self.events.read().await;
        let limit = limit.unwrap_or(100);

        events
            .iter()
            .rev()
            .filter(|e| {
                std::mem::discriminant(&e.event_type) == std::mem::discriminant(&event_type)
            })
            .take(limit)
            .cloned()
            .collect()
    }

    pub async fn get_events_by_severity(
        &self,
        severity: SecuritySeverity,
        limit: Option<usize>,
    ) -> Vec<SecurityEvent> {
        let events = self.events.read().await;
        let limit = limit.unwrap_or(100);

        events
            .iter()
            .rev()
            .filter(|e| std::mem::discriminant(&e.severity) == std::mem::discriminant(&severity))
            .take(limit)
            .cloned()
            .collect()
    }

    pub async fn get_threat_indicators(&self) -> HashMap<String, ThreatIndicator> {
        let indicators = self.threat_indicators.read().await;
        indicators.clone()
    }

    pub async fn get_security_summary(&self, time_window: Duration) -> SecuritySummary {
        let events = self.events.read().await;
        let since = Utc::now() - time_window;

        let recent_events: Vec<_> = events.iter().filter(|e| e.timestamp >= since).collect();

        let total_events = recent_events.len() as u64;

        let critical_events = recent_events
            .iter()
            .filter(|e| matches!(e.severity, SecuritySeverity::Critical))
            .count() as u64;

        let high_events =
            recent_events.iter().filter(|e| matches!(e.severity, SecuritySeverity::High)).count()
                as u64;

        let authentication_failures = recent_events
            .iter()
            .filter(|e| matches!(e.event_type, SecurityEventType::AuthenticationFailure))
            .count() as u64;

        let rate_limit_violations = recent_events
            .iter()
            .filter(|e| matches!(e.event_type, SecurityEventType::RateLimitExceeded))
            .count() as u64;

        let blocked_ips = self.blocked_ips.read().await;
        let active_blocks = blocked_ips.len() as u64;

        SecuritySummary {
            time_window,
            total_events,
            critical_events,
            high_events,
            authentication_failures,
            rate_limit_violations,
            active_blocks,
            threat_level: self.calculate_threat_level(critical_events, high_events),
        }
    }

    fn calculate_threat_level(&self, critical_events: u64, high_events: u64) -> ThreatLevel {
        if critical_events > 0 {
            ThreatLevel::Critical
        } else if high_events > 5 {
            ThreatLevel::High
        } else if high_events > 0 {
            ThreatLevel::Medium
        } else {
            ThreatLevel::Low
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecuritySummary {
    pub time_window: Duration,
    pub total_events: u64,
    pub critical_events: u64,
    pub high_events: u64,
    pub authentication_failures: u64,
    pub rate_limit_violations: u64,
    pub active_blocks: u64,
    pub threat_level: ThreatLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ThreatLevel {
    Low,
    Medium,
    High,
    Critical,
}
