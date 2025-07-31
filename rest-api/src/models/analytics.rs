use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ApiUsageLog {
    #[serde(rename = "logId")]
    pub log_id: String,
    #[serde(rename = "userId")]
    pub user_id: String,
    #[serde(rename = "apiKey")]
    pub api_key: String,
    pub timestamp: DateTime<Utc>,
    pub endpoint: String,
    #[serde(rename = "httpMethod")]
    pub http_method: String,
    #[serde(rename = "statusCode")]
    pub status_code: u16,
    #[serde(rename = "latencyMs")]
    pub latency_ms: u128,
}

impl ApiUsageLog {
    pub fn new(user_id: String, api_key: String, endpoint: String, http_method: String, status_code: u16, latency_ms: u128) -> Self {
        Self {
            log_id: Uuid::new_v4().to_string(),
            user_id,
            api_key,
            timestamp: Utc::now(),
            endpoint,
            http_method,
            status_code,
            latency_ms,
        }
    }
}
