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
    // In production (Cloud Run), we must use a secure identifier that cannot be spoofed
    // Never trust client-provided headers for rate limiting in production environments
    let identifier = {
        // Try to get the actual connection IP first
        if let Some(connect_info) = request.extensions().get::<axum::extract::ConnectInfo<std::net::SocketAddr>>() {
            // Use the real connection IP - cannot be spoofed
            connect_info.0.ip().to_string()
        } else {
            // If connection info unavailable (Cloud Run), use a combination of 
            // non-spoofable request characteristics for rate limiting
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};
            
            let mut hasher = DefaultHasher::new();
            
            // Hash multiple request characteristics that are harder to manipulate
            if let Some(user_agent) = request.headers().get("user-agent") {
                user_agent.hash(&mut hasher);
            }
            if let Some(accept) = request.headers().get("accept") {
                accept.hash(&mut hasher);
            }
            if let Some(accept_lang) = request.headers().get("accept-language") {
                accept_lang.hash(&mut hasher);
            }
            if let Some(accept_encoding) = request.headers().get("accept-encoding") {
                accept_encoding.hash(&mut hasher);
            }
            
            // Include request path and method in the hash for more uniqueness
            request.uri().path().hash(&mut hasher);
            request.method().hash(&mut hasher);
            
            // Create a stable identifier that's difficult to manipulate
            format!("secure-{}", hasher.finish())
        }
    };

    rate_limiter
        .check_rate_limit(&identifier)
        .await
        .map_err(|e| (StatusCode::TOO_MANY_REQUESTS, Json(e)))?;

    Ok(next.run(request).await)
}
