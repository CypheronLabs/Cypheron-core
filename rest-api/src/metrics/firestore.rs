use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;
use std::sync::Arc;
use tokio::sync::mpsc;
use google_cloud_firestore::FirestoreApi;
use google_cloud_auth::{Credentials, CredentialsFile};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricEvent {
    pub api_key_id: Option<Uuid>,
    pub endpoint: String,
    pub method: String,
    pub status_code: u16,
    pub response_time_ms: u64,
    pub timestamp: DateTime<Utc>,
    pub user_agent: Option<String>,
    pub ip_address: Option<String>,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MetricType {
    ApiCall(MetricEvent),
    DailyStats {
        date: String,
        total_requests: u64,
        unique_keys: u64,
        avg_response_time: f64,
        error_rate: f64,
    },
    EndpointPerformance {
        endpoint: String,
        method: String,
        total_calls: u64,
        avg_response_time: f64,
        error_count: u64,
    },
}

#[derive(Clone)]
pub struct FirestoreMetricsClient {
    sender: mpsc::UnboundedSender<MetricType>,
    enabled: bool,
}

impl FirestoreMetricsClient {
    pub async fn new() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let enabled = std::env::var("FIRESTORE_PROJECT_ID").is_ok();
        
        if !enabled {
            tracing::warn!("Firestore metrics disabled - FIRESTORE_PROJECT_ID not set");
            let (sender, _) = mpsc::unbounded_channel();
            return Ok(Self { sender, enabled: false });
        }

        let project_id = std::env::var("FIRESTORE_PROJECT_ID")?;
        
        let credentials = if let Ok(creds_path) = std::env::var("GOOGLE_APPLICATION_CREDENTIALS") {
            Credentials::from_file(&creds_path).await?
        } else {
            Credentials::default().await?
        };

        let firestore = FirestoreApi::new(credentials, &project_id).await?;
        let (sender, mut receiver) = mpsc::unbounded_channel::<MetricType>();

        let firestore_worker = firestore.clone();
        tokio::spawn(async move {
            while let Some(metric) = receiver.recv().await {
                if let Err(e) = Self::write_metric(&firestore_worker, &metric).await {
                    tracing::error!("Failed to write metric to Firestore: {}", e);
                }
            }
        });

        Ok(Self { sender, enabled: true })
    }

    pub fn record_metric(&self, metric: MetricType) {
        if !self.enabled {
            return;
        }

        if let Err(e) = self.sender.send(metric) {
            tracing::error!("Failed to queue metric for Firestore: {}", e);
        }
    }

    pub fn record_api_call(&self, event: MetricEvent) {
        self.record_metric(MetricType::ApiCall(event));
    }

    async fn write_metric(
        firestore: &FirestoreApi,
        metric: &MetricType,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        match metric {
            MetricType::ApiCall(event) => {
                let doc_id = Uuid::new_v4().to_string();
                let collection = "usage_metrics";
                
                firestore
                    .collection(collection)
                    .document(&doc_id)
                    .set(event)
                    .await?;
                
                Self::update_daily_stats(firestore, event).await?;
                Self::update_endpoint_stats(firestore, event).await?;
            }
            MetricType::DailyStats { .. } => {
                // Handle daily stats aggregation
            }
            MetricType::EndpointPerformance { .. } => {
                // Handle endpoint performance metrics
            }
        }
        Ok(())
    }

    async fn update_daily_stats(
        firestore: &FirestoreApi,
        event: &MetricEvent,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let date = event.timestamp.format("%Y-%m-%d").to_string();
        let doc_id = format!("daily_{}", date);
        
        let stats_doc = firestore
            .collection("daily_stats")
            .document(&doc_id);

        let existing = stats_doc.get().await.ok();
        
        let (total_requests, unique_keys_set, total_response_time, error_count) = if let Some(doc) = existing {
            let data: serde_json::Value = doc.data().unwrap_or_default();
            (
                data.get("total_requests").and_then(|v| v.as_u64()).unwrap_or(0),
                std::collections::HashSet::<String>::new(),
                data.get("total_response_time").and_then(|v| v.as_f64()).unwrap_or(0.0),
                data.get("error_count").and_then(|v| v.as_u64()).unwrap_or(0),
            )
        } else {
            (0, std::collections::HashSet::new(), 0.0, 0)
        };

        let new_total = total_requests + 1;
        let new_response_time = total_response_time + event.response_time_ms as f64;
        let new_errors = if event.status_code >= 400 { error_count + 1 } else { error_count };
        let avg_response_time = new_response_time / new_total as f64;
        let error_rate = (new_errors as f64 / new_total as f64) * 100.0;

        let stats = serde_json::json!({
            "date": date,
            "total_requests": new_total,
            "unique_keys": unique_keys_set.len() as u64,
            "avg_response_time": avg_response_time,
            "error_rate": error_rate,
            "total_response_time": new_response_time,
            "error_count": new_errors,
            "last_updated": Utc::now()
        });

        stats_doc.set(&stats).await?;
        Ok(())
    }

    async fn update_endpoint_stats(
        firestore: &FirestoreApi,
        event: &MetricEvent,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let endpoint_key = format!("{}_{}", event.method, event.endpoint.replace("/", "_"));
        let doc_id = format!("endpoint_{}", endpoint_key);
        
        let stats_doc = firestore
            .collection("endpoint_performance")
            .document(&doc_id);

        let existing = stats_doc.get().await.ok();
        
        let (total_calls, total_response_time, error_count) = if let Some(doc) = existing {
            let data: serde_json::Value = doc.data().unwrap_or_default();
            (
                data.get("total_calls").and_then(|v| v.as_u64()).unwrap_or(0),
                data.get("total_response_time").and_then(|v| v.as_f64()).unwrap_or(0.0),
                data.get("error_count").and_then(|v| v.as_u64()).unwrap_or(0),
            )
        } else {
            (0, 0.0, 0)
        };

        let new_total = total_calls + 1;
        let new_response_time = total_response_time + event.response_time_ms as f64;
        let new_errors = if event.status_code >= 400 { error_count + 1 } else { error_count };
        let avg_response_time = new_response_time / new_total as f64;

        let stats = serde_json::json!({
            "endpoint": event.endpoint,
            "method": event.method,
            "total_calls": new_total,
            "avg_response_time": avg_response_time,
            "error_count": new_errors,
            "total_response_time": new_response_time,
            "last_updated": Utc::now()
        });

        stats_doc.set(&stats).await?;
        Ok(())
    }

    pub async fn get_daily_stats(
        &self,
        days: u32,
    ) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error + Send + Sync>> {
        if !self.enabled {
            return Ok(vec![]);
        }

        let project_id = std::env::var("FIRESTORE_PROJECT_ID")?;
        let credentials = Credentials::default().await?;
        let firestore = FirestoreApi::new(credentials, &project_id).await?;

        let docs = firestore
            .collection("daily_stats")
            .order_by("date", google_cloud_firestore::Order::Descending)
            .limit(days as i32)
            .get()
            .await?;

        let mut results = Vec::new();
        for doc in docs {
            if let Ok(data) = doc.data() {
                results.push(data);
            }
        }

        Ok(results)
    }

    pub async fn get_endpoint_performance(
        &self,
    ) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error + Send + Sync>> {
        if !self.enabled {
            return Ok(vec![]);
        }

        let project_id = std::env::var("FIRESTORE_PROJECT_ID")?;
        let credentials = Credentials::default().await?;
        let firestore = FirestoreApi::new(credentials, &project_id).await?;

        let docs = firestore
            .collection("endpoint_performance")
            .order_by("total_calls", google_cloud_firestore::Order::Descending)
            .limit(50)
            .get()
            .await?;

        let mut results = Vec::new();
        for doc in docs {
            if let Ok(data) = doc.data() {
                results.push(data);
            }
        }

        Ok(results)
    }
}