use axum::{middleware, routing::get, serve, Router};
use tokio::net::TcpListener;
use tracing_subscriber;

mod api;
mod config;
mod database;
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
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");
    
    tracing_subscriber::fmt::init();

    let db_config = database::DatabaseConfiguration::from_environment().await
        .expect("Failed to initialize database configuration");

    let api_key_store = db_config.api_key_store.clone();

    tracing::info!("Database backend initialized: {}", db_config.get_backend_type());
    
    let health_status = db_config.health_check().await
        .expect("Database health check failed");
    tracing::info!("Database health check passed: healthy={}", health_status.is_healthy());

    let rate_limiter = security::RateLimiter::new(60);
    let audit_logger = Arc::new(security::AuditLogger::new(10000));

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

    let compliance_manager = Arc::new(security::ComplianceManager::new());

    // Initialize analytics repository if PostgreSQL is enabled
    let app_state = if std::env::var("ANALYTICS_STORAGE")
        .unwrap_or_else(|_| "firestore".to_string())
        .to_lowercase() == "postgresql" 
    {
        tracing::info!("Initializing PostgreSQL analytics repository...");
        
        // Check if we can create a PostgreSQL connection for analytics
        match database::DatabaseConfig::from_env() {
            Ok(db_config) => {
                match db_config.create_pool().await {
                    Ok(pool) => {
                        // We need to create a PostgreSQL repository for analytics
                        // For now, we'll use a simple encryption setup for the repository
                        use crate::security::auth::PostQuantumEncryption;
                        use crate::security::repository::PostgresRepository;
                        use std::sync::Arc;
                        
                        // Create a minimal encryption setup for the analytics repository
                        let encryption_password = std::env::var("PQ_ENCRYPTION_PASSWORD")
                            .unwrap_or_else(|_| "analytics_temp_key".to_string());
                        
                        match PostQuantumEncryption::from_password(&encryption_password) {
                            Ok(encryption) => {
                                let analytics_repo = Arc::new(PostgresRepository::new(
                                    pool, 
                                    Arc::new(encryption)
                                )) as security::repository::ApiKeyRepositoryRef;
                                
                                tracing::info!("PostgreSQL analytics repository initialized successfully");
                                state::AppState::with_analytics_repository(
                                    audit_logger.clone(), 
                                    compliance_manager.clone(),
                                    analytics_repo
                                )
                            },
                            Err(e) => {
                                tracing::warn!("Failed to initialize encryption for analytics: {}, falling back to Firestore logging", e);
                                state::AppState::new(audit_logger.clone(), compliance_manager.clone())
                            }
                        }
                    },
                    Err(e) => {
                        tracing::warn!("Failed to create PostgreSQL pool for analytics: {}, falling back to Firestore logging", e);
                        state::AppState::new(audit_logger.clone(), compliance_manager.clone())
                    }
                }
            },
            Err(e) => {
                tracing::warn!("PostgreSQL configuration error for analytics: {}, falling back to Firestore logging", e);
                state::AppState::new(audit_logger.clone(), compliance_manager.clone())
            }
        }
    } else {
        tracing::info!("Using Firestore fallback for analytics logging");
        state::AppState::new(audit_logger.clone(), compliance_manager.clone())
    };

    let alert_manager_bg = alert_manager.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            alert_manager_bg.check_alert_conditions().await;
        }
    });

    let compliance_manager_bg = compliance_manager.clone();
    let audit_logger_bg = audit_logger.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(3600)); 
        loop {
            interval.tick().await;

            compliance_manager_bg.cleanup_old_events().await;

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

    let monitoring_state = monitoring::MonitoringState::new_with_audit(
        metrics_collector.clone(),
        alert_manager.clone(),
        compliance_checker.clone(),
        security_monitor.clone(),
        health_checker.clone(),
        audit_logger.clone(),
    );

    let monitoring_routes = api::monitoring::routes().with_state(monitoring_state.clone());

    let public_routes = Router::new()
        .route("/", get(handlers::status_handler::serve_static_index))
        .route("/static/index.html", get(handlers::status_handler::serve_static_index))
        .route("/health", get(handlers::monitoring_handler::get_health_status))
        .route("/health/detailed", get(handlers::monitoring_handler::get_detailed_health_report))
        .route("/health/ready", get(handlers::monitoring_handler::get_readiness_check))
        .route("/health/live", get(handlers::monitoring_handler::get_liveness_check))
        .with_state(monitoring_state)
        .merge(api::public::routes());

    let admin_api_routes = security::api_key_management_routes().with_state(api_key_store.clone());
    let admin_audit_routes = security::audit_routes().with_state((*audit_logger).clone());

    let api_routes = Router::new()
        .merge(api::kem::routes().with_state(app_state.clone()))
        .merge(api::sig::routes().with_state(audit_logger.clone()))
        .merge(api::hybrid::routes())
        .merge(api::nist::routes())
        .merge(monitoring_routes)
        .layer(middleware::from_fn_with_state(app_state.clone(), monitoring::analytics_middleware))
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
        .layer(middleware::from_fn(security::security_headers_middleware))
        .layer(middleware::from_fn(security::smart_timeout_middleware));

    let admin_routes = Router::new()
        .merge(admin_api_routes)
        .merge(admin_audit_routes)
        .layer(middleware::from_fn_with_state(api_key_store.clone(), security::admin_auth_middleware))
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
        .layer(middleware::from_fn(security::security_headers_middleware))
        .layer(middleware::from_fn(security::smart_timeout_middleware));

    let config = config::AppConfig::from_env();

    let demo_routes = if let Some(jwt_secret) = &config.security.jwt_secret {
        let jwt_validator = Arc::new(security::JwtValidator::new(jwt_secret.clone()));
        
        Some(Router::new()
            .merge(api::kem::routes().with_state(app_state.clone()))
            .merge(api::sig::routes().with_state(audit_logger.clone()))
            .merge(api::hybrid::routes())
            .merge(api::nist::routes())
            .layer(middleware::from_fn_with_state(app_state.clone(), monitoring::analytics_middleware))
            .layer(middleware::from_fn_with_state(jwt_validator, security::jwt_auth_middleware))
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
            .layer(middleware::from_fn(security::security_headers_middleware))
            .layer(middleware::from_fn(security::smart_timeout_middleware)))
    } else {
        None
    };

    let mut app = Router::new()
        .merge(public_routes)
        .merge(api_routes)
        .merge(admin_routes);

    if let Some(demo_routes) = demo_routes {
        app = app.merge(demo_routes);
    }

    let app = app
        .layer(security::create_cors_middleware())
        .layer(security::create_request_size_limit_layer())
        .layer(security::create_connection_limit_layer(config.server.max_concurrent_connections));
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
    tracing::info!("  - Smart Timeout Protection (Crypto: {}s, Standard: {}s, Health: {}s)", 
        config.server.crypto_timeout_seconds, 
        config.server.request_timeout_seconds, 
        config.server.health_timeout_seconds);
    tracing::info!("  - Connection Limits ({} max concurrent)", config.server.max_concurrent_connections);
    tracing::info!("  - Request Size Limits (1MB max)");

    if config.security.jwt_secret.is_some() {
        tracing::info!("JWT Demo Authentication enabled:");
        tracing::info!("  - Demo JWT authentication configured");
        tracing::info!("  - Demo permissions: kem:encapsulate, sig:verify, hybrid:sign, nist:read, monitoring:read");
        tracing::info!("  - JWT expiry: {} hours", config.security.jwt_expiry_hours);
    } else {
        tracing::info!("JWT Demo Authentication disabled (DEMO_JWT_SECRET not configured)");
    }

    if std::env::var("PQ_TEST_API_KEY").is_ok() {
        tracing::info!("Test API Key loaded from PQ_TEST_API_KEY environment variable");
    } else {
        tracing::info!(
            "No test API key configured. Use PQ_TEST_API_KEY environment variable for testing."
        );
    }

    if std::env::var("PQ_MASTER_ADMIN_KEY").is_ok() {
        tracing::info!("Master admin key configured - admin endpoints secured");
    } else {
        tracing::error!("PQ_MASTER_ADMIN_KEY not set - admin endpoints will be inaccessible");
        tracing::error!("Set PQ_MASTER_ADMIN_KEY environment variable with a secure admin key");
    }

    tracing::info!("Storage backend: {} with post-quantum encryption", db_config.get_backend_type());
    
    // Log analytics configuration
    let analytics_storage = std::env::var("ANALYTICS_STORAGE")
        .unwrap_or_else(|_| "firestore".to_string());
    tracing::info!("Analytics storage: {}", analytics_storage);
    
    if analytics_storage.to_lowercase() == "postgresql" {
        if app_state.analytics_repository.is_some() {
            tracing::info!("PostgreSQL analytics repository active - will record usage metrics to Cloud SQL");
        } else {
            tracing::warn!("PostgreSQL analytics requested but failed to initialize - falling back to Firestore logging");
        }
    }
    
    if let Some(response_time) = health_status.response_time_ms() {
        tracing::info!("Database response time: {}ms", response_time);
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

    tracing::info!("Admin endpoints: /admin/api-keys, /admin/audit-logs (authentication required)");
    tracing::info!("NIST compliance endpoints: /nist/compliance, /nist/deprecation");
    tracing::info!("Monitoring endpoints: /monitoring/*, /health/*");
    tracing::info!("Security monitoring: Real-time threat detection enabled");
    tracing::info!("Compliance monitoring: NIST FIPS 203/204/205 compliance tracking active");

    serve(listener, app).await.expect("Server error");
}
