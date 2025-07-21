use axum::{middleware, routing::get, serve, Router};
use tokio::net::TcpListener;
use tracing_subscriber;

mod api;
mod config;
mod error;
mod handlers;
mod models;
mod monitoring;
mod security;
mod services;
mod state;
mod utils;
mod validation;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    // Initialize API key store with database support
    let api_key_store = if let Ok(database_url) = std::env::var("DATABASE_URL") {
        match security::ApiKeyStore::new(&database_url).await {
            Ok(store) => {
                tracing::info!("API key store connected to PostgreSQL database");
                store
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to connect to database: {}, falling back to in-memory storage",
                    e.message
                );
                security::ApiKeyStore::new_in_memory()
            }
        }
    } else {
        tracing::info!("No DATABASE_URL configured, using in-memory API key storage");
        security::ApiKeyStore::new_in_memory()
    };

    let rate_limiter = security::RateLimiter::new(60);
    let audit_logger = Arc::new(security::AuditLogger::new(10000));

    // Metrics now handled by Google Cloud Monitoring

    // Initialize monitoring and alerting system
    use chrono::Duration;
    use std::sync::Arc;

    let metrics_collector = Arc::new(monitoring::MetricsCollector::new(10000));
    let security_monitor = Arc::new(monitoring::SecurityEventMonitor::new(5000));
    let alert_manager = Arc::new(monitoring::AlertManager::new(metrics_collector.clone(), 1000));
    let health_checker = Arc::new(monitoring::HealthChecker::new("0.2.0".to_string()));
    let compliance_checker = Arc::new(monitoring::ComplianceChecker::new(
        monitoring::ComplianceFramework::NistFips203,
        Duration::days(30),
    ));

    // Initialize compliance manager for SOC 2 and GDPR compliance
    let compliance_manager = Arc::new(security::ComplianceManager::new());

    // Create combined app state
    let app_state = state::AppState::new(audit_logger.clone(), compliance_manager.clone());

    // Start background monitoring tasks
    let alert_manager_bg = alert_manager.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            alert_manager_bg.check_alert_conditions().await;
        }
    });

    // Start background data retention cleanup task
    let compliance_manager_bg = compliance_manager.clone();
    let audit_logger_bg = audit_logger.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(3600)); // Run every hour
        loop {
            interval.tick().await;

            // Cleanup old compliance events
            compliance_manager_bg.cleanup_old_events().await;

            // Cleanup old audit logs (based on retention policy)
            let retention_policy = compliance_manager_bg.get_retention_policy();
            let audit_cutoff_days = retention_policy.audit_retention_days;
            audit_logger_bg.cleanup_old_events(audit_cutoff_days).await;

            tracing::info!("Data retention cleanup cycle completed");
        }
    });

    tracing::info!("Security monitoring and alerting system initialized");
    tracing::info!("Enhanced security features enabled:");
    tracing::info!(
        "  - Data Retention Policy: {} day default, {} day audit retention",
        compliance_manager.get_retention_policy().default_retention_days,
        compliance_manager.get_retention_policy().audit_retention_days
    );
    tracing::info!("  - Privacy Controls: PII sanitization and pseudonymization active");
    tracing::info!("  - Post-Quantum Encryption: API key storage and retrieval");
    tracing::info!("  - Background Data Cleanup: Hourly retention enforcement");

    // Create the combined monitoring state with audit logger
    let monitoring_state = monitoring::MonitoringState::new_with_audit(
        metrics_collector.clone(),
        alert_manager.clone(),
        compliance_checker.clone(),
        security_monitor.clone(),
        health_checker.clone(),
        audit_logger.clone(),
    );

    let monitoring_routes = api::monitoring::routes().with_state(monitoring_state.clone());

    // Health check routes (no auth required)
    let public_routes = Router::new()
        .route("/health", get(handlers::monitoring_handler::get_health_status))
        .route("/health/detailed", get(handlers::monitoring_handler::get_detailed_health_report))
        .route("/health/ready", get(handlers::monitoring_handler::get_readiness_check))
        .route("/health/live", get(handlers::monitoring_handler::get_liveness_check))
        .with_state(monitoring_state)
        .merge(api::public::routes());

    // Authenticated API routes
    let api_routes = Router::new()
        .merge(api::kem::routes().with_state(app_state.clone()))
        .merge(api::sig::routes().with_state(audit_logger.clone()))
        .merge(api::hybrid::routes())
        .merge(api::nist::routes())
        .merge(monitoring_routes)
        .layer(middleware::from_fn_with_state(api_key_store.clone(), security::auth_middleware))
        .layer(middleware::from_fn_with_state(
            rate_limiter.clone(),
            security::rate_limit_middleware,
        ))
        .layer(middleware::from_fn_with_state(
            compliance_manager.clone(),
            security::compliance_middleware,
        ))
        .layer(middleware::from_fn(security::request_validation_middleware))
        .layer(middleware::from_fn(security::timing_middleware))
        .layer(middleware::from_fn(security::security_headers_middleware));

    let admin_api_routes = security::api_key_management_routes().with_state(api_key_store.clone());

    let admin_audit_routes = security::audit_routes().with_state((*audit_logger).clone());

    // Combine all routes with CORS middleware
    let app = Router::new()
        .merge(public_routes)
        .merge(api_routes)
        .merge(admin_api_routes)
        .merge(admin_audit_routes)
        .layer(security::create_cors_middleware());

    let config = config::AppConfig::from_env();
    let bind_addr = format!("{}:{}", config.server.host, config.server.port);

    let listener = TcpListener::bind(&bind_addr).await.expect("Failed to bind port");

    tracing::info!("PQ-Core API Server listening on http://{}", bind_addr);
    tracing::info!("API Security Features Enabled:");
    tracing::info!("  - API Key Authentication (with encrypted persistent storage)");
    tracing::info!("  - Rate Limiting (60 req/min default)");
    tracing::info!("  - Request Validation");
    tracing::info!("  - Security Headers");
    tracing::info!("  - Audit Logging");
    tracing::info!("  - Post-Quantum ML-KEM-768 + ChaCha20-Poly1305 Encryption at Rest");
    tracing::info!("  - Constant-time Authentication");

    if std::env::var("PQ_TEST_API_KEY").is_ok() {
        tracing::info!("Test API Key loaded from PQ_TEST_API_KEY environment variable");
    } else {
        tracing::info!(
            "No test API key configured. Use PQ_TEST_API_KEY environment variable for testing."
        );
    }

    if std::env::var("DATABASE_URL").is_ok() {
        tracing::info!("Database storage: PostgreSQL with encrypted API keys");
    } else {
        tracing::info!("Database storage: In-memory fallback mode");
    }

    if std::env::var("PQ_ENCRYPTION_PASSWORD").is_ok() {
        tracing::info!(
            "Encryption: Post-Quantum ML-KEM-768 + ChaCha20-Poly1305 with Argon2 key derivation"
        );
    } else {
        tracing::warn!(
            "Encryption: Generated post-quantum key (data will not persist across restarts)"
        );
    }

    tracing::info!("Admin endpoints: /admin/api-keys, /admin/audit-logs");
    tracing::info!("NIST compliance endpoints: /nist/compliance, /nist/deprecation");
    tracing::info!("Monitoring endpoints: /monitoring/*, /health/*");
    tracing::info!("Security monitoring: Real-time threat detection enabled");
    tracing::info!("Compliance monitoring: NIST FIPS 203/204/205 compliance tracking active");

    serve(listener, app).await.expect("Server error");
}
