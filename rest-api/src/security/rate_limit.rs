use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
    Json,
};
use serde::Serialize;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

#[derive(Debug, Clone)]
pub struct RateLimitEntry {
    pub count: u32,
    pub window_start: Instant,
    pub blocked_until: Option<Instant>,
}

#[derive(Debug, Clone)]
pub struct RateLimiter {
    pub entries: Arc<RwLock<HashMap<String, RateLimitEntry>>>,
    pub requests_per_minute: u32,
    pub block_duration: Duration,
}

impl RateLimiter {
    pub fn new(requests_per_minute: u32) -> Self {
        Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
            requests_per_minute,
            block_duration: Duration::from_secs(60), // 1 minute block
        }
    }

    pub async fn check_rate_limit(&self, identifier: &str) -> Result<(), RateLimitError> {
        let now = Instant::now();
        let mut entries = self.entries.write().await;

        let entry = entries.entry(identifier.to_string()).or_insert(RateLimitEntry {
            count: 0,
            window_start: now,
            blocked_until: None,
        });

        // Check if currently blocked
        if let Some(blocked_until) = entry.blocked_until {
            if now < blocked_until {
                return Err(RateLimitError {
                    error: "rate_limit_exceeded".to_string(),
                    message: "Rate limit exceeded. Please wait before making more requests."
                        .to_string(),
                    retry_after: (blocked_until - now).as_secs(),
                    code: 429,
                });
            } else {
                // Block period expired, reset
                entry.blocked_until = None;
                entry.count = 0;
                entry.window_start = now;
            }
        }

        // Reset window if more than 1 minute has passed
        if now.duration_since(entry.window_start) >= Duration::from_secs(60) {
            entry.count = 0;
            entry.window_start = now;
        }

        // Check rate limit
        if entry.count >= self.requests_per_minute {
            entry.blocked_until = Some(now + self.block_duration);
            return Err(RateLimitError {
                error: "rate_limit_exceeded".to_string(),
                message: format!(
                    "Rate limit of {} requests per minute exceeded",
                    self.requests_per_minute
                ),
                retry_after: self.block_duration.as_secs(),
                code: 429,
            });
        }

        entry.count += 1;
        Ok(())
    }
}

#[derive(Debug, Serialize)]
pub struct RateLimitError {
    pub error: String,
    pub message: String,
    pub retry_after: u64,
    pub code: u16,
}

pub async fn rate_limit_middleware(
    State(rate_limiter): State<RateLimiter>,
    request: Request,
    next: Next,
) -> Result<Response, (StatusCode, Json<RateLimitError>)> {
    // Use IP address as identifier (in production, could use API key)
    let identifier = request
        .headers()
        .get("x-forwarded-for")
        .and_then(|hv| hv.to_str().ok())
        .unwrap_or("unknown")
        .to_string();

    rate_limiter
        .check_rate_limit(&identifier)
        .await
        .map_err(|e| (StatusCode::TOO_MANY_REQUESTS, Json(e)))?;

    Ok(next.run(request).await)
}
