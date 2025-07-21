use serde::{Deserialize, Serialize};
use std::env;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub api_key_expiry_days: u32,
    pub max_request_size: usize,
    pub rate_limit_per_minute: u32,
    pub session_timeout_minutes: u32,
    pub password_min_length: usize,
    pub failed_login_lockout_minutes: u32,
    pub audit_log_retention_days: u32,
    pub enable_request_logging: bool,
    pub enable_response_logging: bool,
    pub log_sensitive_data: bool,
    pub require_tls: bool,
    pub allowed_origins: Vec<String>,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            api_key_expiry_days: 90,
            max_request_size: 10 * 1024 * 1024,
            rate_limit_per_minute: 60,
            session_timeout_minutes: 30,
            password_min_length: 12,
            failed_login_lockout_minutes: 15,
            audit_log_retention_days: 2555,
            enable_request_logging: true,
            enable_response_logging: false,
            log_sensitive_data: false,
            require_tls: true,
            allowed_origins: vec!["http://localhost:3000".to_string()],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceConfig {
    pub enable_soc2_logging: bool,
    pub enable_gdpr_privacy_controls: bool,
    pub data_retention_days: u32,
    pub audit_retention_days: u32,
    pub enable_data_encryption: bool,
    pub enable_pseudonymization: bool,
    pub enable_access_reviews: bool,
    pub access_review_interval_days: u32,
    pub enable_vulnerability_scanning: bool,
    pub enable_security_monitoring: bool,
}

impl Default for ComplianceConfig {
    fn default() -> Self {
        Self {
            enable_soc2_logging: true,
            enable_gdpr_privacy_controls: true,
            data_retention_days: 90,
            audit_retention_days: 2555,
            enable_data_encryption: true,
            enable_pseudonymization: true,
            enable_access_reviews: true,
            access_review_interval_days: 90,
            enable_vulnerability_scanning: false,
            enable_security_monitoring: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub security: SecurityConfig,
    pub compliance: ComplianceConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub environment: Environment,
    pub log_level: String,
    pub enable_metrics: bool,
    pub enable_health_check: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Environment {
    Development,
    Staging,
    Production,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "0.0.0.0".to_string(),
            port: 3000,
            environment: Environment::Development,
            log_level: "info".to_string(),
            enable_metrics: true,
            enable_health_check: true,
        }
    }
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig::default(),
            security: SecurityConfig::default(),
            compliance: ComplianceConfig::default(),
        }
    }
}

impl AppConfig {
    pub fn from_env() -> Self {
        let mut config = AppConfig::default();

        // Server configuration from environment
        if let Ok(host) = env::var("PQ_HOST") {
            config.server.host = host;
        }

        // Check PQ_PORT first, then fall back to Cloud Run's PORT
        if let Ok(port) = env::var("PQ_PORT").or_else(|_| env::var("PORT")) {
            if let Ok(port_num) = port.parse::<u16>() {
                config.server.port = port_num;
            }
        }

        if let Ok(env_str) = env::var("PQ_ENVIRONMENT") {
            config.server.environment = match env_str.to_lowercase().as_str() {
                "production" | "prod" => Environment::Production,
                "staging" | "stage" => Environment::Staging,
                _ => Environment::Development,
            };
        }

        if let Ok(log_level) = env::var("PQ_LOG_LEVEL") {
            config.server.log_level = log_level;
        }

        // Security configuration from environment
        if let Ok(rate_limit) = env::var("PQ_RATE_LIMIT") {
            if let Ok(rate) = rate_limit.parse::<u32>() {
                config.security.rate_limit_per_minute = rate;
            }
        }

        if let Ok(max_size) = env::var("PQ_MAX_REQUEST_SIZE") {
            if let Ok(size) = max_size.parse::<usize>() {
                config.security.max_request_size = size;
            }
        }

        // Compliance configuration from environment
        if let Ok(soc2) = env::var("PQ_ENABLE_SOC2") {
            config.compliance.enable_soc2_logging = soc2.to_lowercase() == "true";
        }

        if let Ok(gdpr) = env::var("PQ_ENABLE_GDPR") {
            config.compliance.enable_gdpr_privacy_controls = gdpr.to_lowercase() == "true";
        }

        // Production security hardening
        if matches!(config.server.environment, Environment::Production) {
            config.security.log_sensitive_data = false;
            config.security.enable_response_logging = false;
            config.security.require_tls = true;
            config.security.allowed_origins = vec!["https://yourdomain.com".to_string()];
            config.compliance.enable_soc2_logging = true;
            config.compliance.enable_gdpr_privacy_controls = true;
        }

        config
    }

    #[allow(dead_code)]
    pub fn validate(&self) -> Result<(), String> {
        // Validate server configuration
        if self.server.port == 0 {
            return Err("Invalid port number".to_string());
        }

        if self.server.host.is_empty() {
            return Err("Host cannot be empty".to_string());
        }

        // Validate security configuration
        if self.security.rate_limit_per_minute == 0 {
            return Err("Rate limit must be greater than 0".to_string());
        }

        if self.security.max_request_size == 0 {
            return Err("Max request size must be greater than 0".to_string());
        }

        if self.security.password_min_length < 8 {
            return Err("Password minimum length must be at least 8 characters".to_string());
        }

        // Production environment validation
        if matches!(self.server.environment, Environment::Production) {
            if !self.security.require_tls {
                return Err("TLS is required in production environment".to_string());
            }

            if self.security.log_sensitive_data {
                return Err("Sensitive data logging must be disabled in production".to_string());
            }

            if !self.compliance.enable_soc2_logging {
                return Err("SOC 2 logging must be enabled in production".to_string());
            }
        }

        Ok(())
    }
}

#[allow(dead_code)]
pub fn load_config() -> Result<AppConfig, Box<dyn std::error::Error>> {
    let config = AppConfig::from_env();
    config.validate().map_err(|e| format!("Configuration validation failed: {}", e))?;

    tracing::info!("Configuration loaded successfully");
    tracing::debug!("Server config: {:?}", config.server);
    tracing::debug!("Security config: {:?}", config.security);
    tracing::debug!("Compliance config: {:?}", config.compliance);

    Ok(config)
}
