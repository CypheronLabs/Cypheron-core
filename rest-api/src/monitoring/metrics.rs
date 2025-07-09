use std::sync::Arc;
use std::collections::HashMap;
use tokio::sync::RwLock;
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc, Duration};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoMetrics {
    pub operation_id: Uuid,
    pub algorithm: String,
    pub operation_type: String, // "keygen", "sign", "verify", "encapsulate", "decapsulate"
    pub duration_ms: u64,
    pub success: bool,
    pub key_size: Option<usize>,
    pub message_size: Option<usize>,
    pub timestamp: DateTime<Utc>,
    pub api_key_id: Option<Uuid>,
    pub client_ip: Option<String>,
    pub user_agent: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityMetrics {
    pub event_id: Uuid,
    pub event_type: SecurityEventType,
    pub severity: SecuritySeverity,
    pub description: String,
    pub timestamp: DateTime<Utc>,
    pub source_ip: Option<String>,
    pub api_key_id: Option<Uuid>,
    pub additional_data: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityEventType {
    AuthenticationFailure,
    RateLimitExceeded,
    InvalidInput,
    SuspiciousActivity,
    TimingAttackDetected,
    UnusualUsagePattern,
    ComplianceViolation,
    SystemAlert,
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
pub struct PerformanceMetrics {
    pub metric_id: Uuid,
    pub endpoint: String,
    pub response_time_ms: u64,
    pub memory_usage_mb: f64,
    pub cpu_usage_percent: f64,
    pub concurrent_requests: u32,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsSummary {
    pub time_window: Duration,
    pub total_operations: u64,
    pub successful_operations: u64,
    pub failed_operations: u64,
    pub average_response_time_ms: f64,
    pub operations_per_second: f64,
    pub top_algorithms: Vec<(String, u64)>,
    pub error_rate: f64,
    pub security_events: u64,
    pub compliance_score: f64,
}

#[derive(Debug, Clone)]
pub struct MetricsCollector {
    crypto_metrics: Arc<RwLock<Vec<CryptoMetrics>>>,
    security_metrics: Arc<RwLock<Vec<SecurityMetrics>>>,
    performance_metrics: Arc<RwLock<Vec<PerformanceMetrics>>>,
    max_metrics: usize,
}

impl MetricsCollector {
    pub fn new(max_metrics: usize) -> Self {
        Self {
            crypto_metrics: Arc::new(RwLock::new(Vec::new())),
            security_metrics: Arc::new(RwLock::new(Vec::new())),
            performance_metrics: Arc::new(RwLock::new(Vec::new())),
            max_metrics,
        }
    }

    pub async fn record_crypto_operation(
        &self,
        algorithm: String,
        operation_type: String,
        duration_ms: u64,
        success: bool,
        key_size: Option<usize>,
        message_size: Option<usize>,
        api_key_id: Option<Uuid>,
        client_ip: Option<String>,
        user_agent: Option<String>,
    ) {
        let metric = CryptoMetrics {
            operation_id: Uuid::new_v4(),
            algorithm,
            operation_type,
            duration_ms,
            success,
            key_size,
            message_size,
            timestamp: Utc::now(),
            api_key_id,
            client_ip,
            user_agent,
        };

        let mut metrics = self.crypto_metrics.write().await;
        
        // Log important metrics before moving
        tracing::info!(
            "Crypto operation recorded: {} {} in {}ms (success: {})",
            metric.algorithm,
            metric.operation_type,
            metric.duration_ms,
            metric.success
        );
        
        metrics.push(metric);

        // Keep only the most recent metrics
        if metrics.len() > self.max_metrics {
            let len = metrics.len();
            metrics.drain(0..len - self.max_metrics);
        }
    }

    pub async fn record_security_event(
        &self,
        event_type: SecurityEventType,
        severity: SecuritySeverity,
        description: String,
        source_ip: Option<String>,
        api_key_id: Option<Uuid>,
        additional_data: HashMap<String, String>,
    ) {
        let metric = SecurityMetrics {
            event_id: Uuid::new_v4(),
            event_type: event_type.clone(),
            severity: severity.clone(),
            description: description.clone(),
            timestamp: Utc::now(),
            source_ip,
            api_key_id,
            additional_data,
        };

        let mut metrics = self.security_metrics.write().await;
        metrics.push(metric);

        // Keep only the most recent metrics
        if metrics.len() > self.max_metrics {
            let len = metrics.len();
            metrics.drain(0..len - self.max_metrics);
        }

        // Log security events with appropriate level
        match severity {
            SecuritySeverity::Critical => {
                tracing::error!("CRITICAL SECURITY EVENT: {:?} - {}", event_type, description);
            }
            SecuritySeverity::High => {
                tracing::warn!("HIGH SECURITY EVENT: {:?} - {}", event_type, description);
            }
            SecuritySeverity::Medium => {
                tracing::warn!("MEDIUM SECURITY EVENT: {:?} - {}", event_type, description);
            }
            SecuritySeverity::Low => {
                tracing::info!("LOW SECURITY EVENT: {:?} - {}", event_type, description);
            }
            SecuritySeverity::Info => {
                tracing::info!("SECURITY INFO: {:?} - {}", event_type, description);
            }
        }
    }

    pub async fn record_performance_metric(
        &self,
        endpoint: String,
        response_time_ms: u64,
        memory_usage_mb: f64,
        cpu_usage_percent: f64,
        concurrent_requests: u32,
    ) {
        let metric = PerformanceMetrics {
            metric_id: Uuid::new_v4(),
            endpoint,
            response_time_ms,
            memory_usage_mb,
            cpu_usage_percent,
            concurrent_requests,
            timestamp: Utc::now(),
        };

        let mut metrics = self.performance_metrics.write().await;
        metrics.push(metric);

        // Keep only the most recent metrics
        if metrics.len() > self.max_metrics {
            let len = metrics.len();
            metrics.drain(0..len - self.max_metrics);
        }
    }

    pub async fn get_metrics_summary(&self, time_window: Duration) -> MetricsSummary {
        let now = Utc::now();
        let since = now - time_window;

        let crypto_metrics = self.crypto_metrics.read().await;
        let security_metrics = self.security_metrics.read().await;

        // Filter metrics within time window
        let recent_crypto: Vec<_> = crypto_metrics
            .iter()
            .filter(|m| m.timestamp >= since)
            .collect();

        let recent_security: Vec<_> = security_metrics
            .iter()
            .filter(|m| m.timestamp >= since)
            .collect();

        // Calculate summary statistics
        let total_operations = recent_crypto.len() as u64;
        let successful_operations = recent_crypto.iter().filter(|m| m.success).count() as u64;
        let failed_operations = total_operations - successful_operations;

        let average_response_time_ms = if total_operations > 0 {
            recent_crypto.iter().map(|m| m.duration_ms as f64).sum::<f64>() / total_operations as f64
        } else {
            0.0
        };

        let operations_per_second = if time_window.num_seconds() > 0 {
            total_operations as f64 / time_window.num_seconds() as f64
        } else {
            0.0
        };

        // Calculate top algorithms
        let mut algorithm_counts: HashMap<String, u64> = HashMap::new();
        for metric in &recent_crypto {
            *algorithm_counts.entry(metric.algorithm.clone()).or_insert(0) += 1;
        }
        let mut top_algorithms: Vec<_> = algorithm_counts.into_iter().collect();
        top_algorithms.sort_by(|a, b| b.1.cmp(&a.1));
        top_algorithms.truncate(10);

        let error_rate = if total_operations > 0 {
            (failed_operations as f64 / total_operations as f64) * 100.0
        } else {
            0.0
        };

        let security_events = recent_security.len() as u64;

        // Calculate compliance score (100% - error_rate - security_penalty)
        let security_penalty = match security_events {
            0 => 0.0,
            1..=5 => 5.0,
            6..=10 => 10.0,
            _ => 20.0,
        };
        let compliance_score = (100.0 - error_rate - security_penalty).max(0.0);

        MetricsSummary {
            time_window,
            total_operations,
            successful_operations,
            failed_operations,
            average_response_time_ms,
            operations_per_second,
            top_algorithms,
            error_rate,
            security_events,
            compliance_score,
        }
    }

    pub async fn get_crypto_metrics(&self, limit: Option<usize>) -> Vec<CryptoMetrics> {
        let metrics = self.crypto_metrics.read().await;
        let limit = limit.unwrap_or(100).min(metrics.len());
        metrics.iter().rev().take(limit).cloned().collect()
    }

    pub async fn get_security_metrics(&self, limit: Option<usize>) -> Vec<SecurityMetrics> {
        let metrics = self.security_metrics.read().await;
        let limit = limit.unwrap_or(100).min(metrics.len());
        metrics.iter().rev().take(limit).cloned().collect()
    }

    pub async fn get_performance_metrics(&self, limit: Option<usize>) -> Vec<PerformanceMetrics> {
        let metrics = self.performance_metrics.read().await;
        let limit = limit.unwrap_or(100).min(metrics.len());
        metrics.iter().rev().take(limit).cloned().collect()
    }

    // Anomaly detection methods
    pub async fn detect_timing_anomalies(&self) -> Vec<SecurityMetrics> {
        let crypto_metrics = self.crypto_metrics.read().await;
        let mut anomalies = Vec::new();

        // Group by algorithm and calculate average timing
        let mut algorithm_timings: HashMap<String, Vec<u64>> = HashMap::new();
        for metric in crypto_metrics.iter() {
            algorithm_timings
                .entry(metric.algorithm.clone())
                .or_default()
                .push(metric.duration_ms);
        }

        // Detect outliers (operations taking >3x average time)
        for (algorithm, timings) in algorithm_timings {
            if timings.len() < 10 { continue; } // Need sufficient data

            let average: f64 = timings.iter().map(|&x| x as f64).sum::<f64>() / timings.len() as f64;
            let threshold = average * 3.0;

            let outliers = timings.iter().filter(|&&time| time as f64 > threshold).count();
            
            if outliers > 0 {
                let anomaly = SecurityMetrics {
                    event_id: Uuid::new_v4(),
                    event_type: SecurityEventType::TimingAttackDetected,
                    severity: SecuritySeverity::Medium,
                    description: format!(
                        "Detected {} timing anomalies for {} (avg: {:.2}ms, threshold: {:.2}ms)",
                        outliers, algorithm, average, threshold
                    ),
                    timestamp: Utc::now(),
                    source_ip: None,
                    api_key_id: None,
                    additional_data: {
                        let mut data = HashMap::new();
                        data.insert("algorithm".to_string(), algorithm);
                        data.insert("outlier_count".to_string(), outliers.to_string());
                        data.insert("average_time_ms".to_string(), average.to_string());
                        data
                    },
                };
                anomalies.push(anomaly);
            }
        }

        anomalies
    }

    pub async fn detect_usage_anomalies(&self) -> Vec<SecurityMetrics> {
        let crypto_metrics = self.crypto_metrics.read().await;
        let mut anomalies = Vec::new();

        // Group by API key and detect unusual patterns
        let mut api_key_usage: HashMap<Option<Uuid>, Vec<&CryptoMetrics>> = HashMap::new();
        for metric in crypto_metrics.iter() {
            api_key_usage.entry(metric.api_key_id).or_default().push(metric);
        }

        for (api_key_id, metrics) in api_key_usage {
            if metrics.len() < 10 { continue; } // Need sufficient data

            // Check for rapid succession of operations (potential automated attack)
            let mut rapid_operations = 0;
            for window in metrics.windows(5) {
                let time_span = window.last().unwrap().timestamp - window.first().unwrap().timestamp;
                if time_span.num_seconds() < 1 { // 5 operations in 1 second
                    rapid_operations += 1;
                }
            }

            if rapid_operations > 3 {
                let anomaly = SecurityMetrics {
                    event_id: Uuid::new_v4(),
                    event_type: SecurityEventType::UnusualUsagePattern,
                    severity: SecuritySeverity::High,
                    description: format!(
                        "Detected rapid succession of operations from API key {:?} ({} rapid bursts)",
                        api_key_id, rapid_operations
                    ),
                    timestamp: Utc::now(),
                    source_ip: metrics.first().and_then(|m| m.client_ip.clone()),
                    api_key_id,
                    additional_data: {
                        let mut data = HashMap::new();
                        data.insert("rapid_operation_bursts".to_string(), rapid_operations.to_string());
                        data.insert("total_operations".to_string(), metrics.len().to_string());
                        data
                    },
                };
                anomalies.push(anomaly);
            }
        }

        anomalies
    }
}