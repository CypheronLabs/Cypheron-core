use axum::{serve, Router, middleware};
use tokio::net::TcpListener;
use tracing_subscriber;

mod api;
mod handlers;
mod models;
mod services;
mod error;
mod utils;
mod security;
mod validation;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let api_key_store = security::ApiKeyStore::new();
    let rate_limiter = security::RateLimiter::new(60); 
    let audit_logger = security::AuditLogger::new(10000); 

    let api_routes = Router::new()
        .merge(api::kem::routes())
        .merge(api::sig::routes())
        .merge(api::hybrid::routes())
        .layer(middleware::from_fn_with_state(
            api_key_store.clone(),
            security::auth_middleware,
        ))
        .layer(middleware::from_fn_with_state(
            rate_limiter.clone(),
            security::rate_limit_middleware,
        ))
        .layer(middleware::from_fn(security::request_validation_middleware))
        .layer(middleware::from_fn(security::timing_middleware))
        .layer(middleware::from_fn(security::security_headers_middleware));

    let admin_api_routes = security::api_key_management_routes()
        .with_state(api_key_store.clone());
    
    let admin_audit_routes = security::audit_routes()
        .with_state(audit_logger.clone());

    // Combine all routes with CORS middleware
    let app = Router::new()
        .merge(api_routes)
        .merge(admin_api_routes)
        .merge(admin_audit_routes)
        .layer(security::create_cors_middleware());

    let listener = TcpListener::bind("127.0.0.1:3000")
        .await
        .expect("Failed to bind port");

    tracing::info!("PQ-Core API Server listening on http://127.0.0.1:3000");
    tracing::info!("API Security Features Enabled:");
    tracing::info!("  - API Key Authentication");
    tracing::info!("  - Rate Limiting (60 req/min default)");
    tracing::info!("  - Request Validation");
    tracing::info!("  - Security Headers");
    tracing::info!("  - Audit Logging");
    
    if std::env::var("PQ_TEST_API_KEY").is_ok() {
        tracing::info!("Test API Key loaded from PQ_TEST_API_KEY environment variable");
    } else {
        tracing::info!("No test API key configured. Use PQ_TEST_API_KEY environment variable for testing.");
    }
    
    tracing::info!("Admin endpoints: /admin/api-keys, /admin/audit-logs");

    serve(listener, app)
        .await
        .expect("Server error");
}