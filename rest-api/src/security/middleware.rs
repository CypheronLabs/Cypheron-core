use axum::{
    extract::Request,
    http::{HeaderValue, Method, StatusCode},
    middleware::Next,
    response::Response,
    Json,
};
use serde::Serialize;
use std::time::Instant;
use tower_http::cors::CorsLayer;

#[derive(Debug, Serialize)]
pub struct SecurityError {
    pub error: String,
    pub message: String,
    pub code: u16,
}

// Security headers middleware
pub async fn security_headers_middleware(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();

    // OWASP recommended security headers
    headers.insert("X-Content-Type-Options", HeaderValue::from_static("nosniff"));
    headers.insert("X-Frame-Options", HeaderValue::from_static("DENY"));
    headers.insert("X-XSS-Protection", HeaderValue::from_static("1; mode=block"));
    headers.insert("Referrer-Policy", HeaderValue::from_static("strict-origin-when-cross-origin"));
    headers.insert(
        "Permissions-Policy",
        HeaderValue::from_static("camera=(), microphone=(), geolocation=()"),
    );
    headers.insert(
        "Strict-Transport-Security",
        HeaderValue::from_static("max-age=31536000; includeSubDomains"),
    );
    headers.insert(
        "Content-Security-Policy",
        HeaderValue::from_static(
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'",
        ),
    );

    response
}

// Request validation middleware
pub async fn request_validation_middleware(
    request: Request,
    next: Next,
) -> Result<Response, (StatusCode, Json<SecurityError>)> {
    let method = request.method();
    let path = request.uri().path();

    // Validate HTTP methods
    match method {
        &Method::GET | &Method::POST => {
            // Allowed methods
        }
        _ => {
            return Err((
                StatusCode::METHOD_NOT_ALLOWED,
                Json(SecurityError {
                    error: "method_not_allowed".to_string(),
                    message: format!("HTTP method {} not allowed", method),
                    code: 405,
                }),
            ));
        }
    }

    // Validate path characters
    if path.contains("..") || path.contains("//") {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(SecurityError {
                error: "invalid_path".to_string(),
                message: "Invalid characters in request path".to_string(),
                code: 400,
            }),
        ));
    }

    // Check for suspicious patterns
    let suspicious_patterns = [
        "<script",
        "javascript:",
        "onload=",
        "onerror=",
        "SELECT",
        "UNION",
        "DROP",
        "INSERT",
        "UPDATE",
        "eval(",
        "exec(",
        "system(",
    ];

    for pattern in &suspicious_patterns {
        if path.to_lowercase().contains(&pattern.to_lowercase()) {
            tracing::warn!("Suspicious pattern detected in path: {}", path);
            return Err((
                StatusCode::BAD_REQUEST,
                Json(SecurityError {
                    error: "suspicious_request".to_string(),
                    message: "Request contains suspicious patterns".to_string(),
                    code: 400,
                }),
            ));
        }
    }

    Ok(next.run(request).await)
}

// Request timing middleware for audit logs
pub async fn timing_middleware(request: Request, next: Next) -> Response {
    let start_time = Instant::now();
    let method = request.method().clone();
    let path = request.uri().path().to_string();

    let response = next.run(request).await;

    let duration = start_time.elapsed();
    let status = response.status();

    tracing::info!(
        "Request completed - {} {} - Status: {} - Duration: {:?}",
        method,
        path,
        status,
        duration
    );

    // Log slow requests (> 5 seconds)
    if duration.as_secs() > 5 {
        tracing::warn!("Slow request detected - {} {} - Duration: {:?}", method, path, duration);
    }

    response
}

// Create CORS middleware
pub fn create_cors_middleware() -> CorsLayer {
    CorsLayer::new()
        .allow_origin("http://localhost:3000".parse::<HeaderValue>().unwrap())
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([
            "content-type".parse().unwrap(),
            "x-api-key".parse().unwrap(),
            "authorization".parse().unwrap(),
        ])
}
