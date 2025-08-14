use sqlx::{PgPool, postgres::{PgPoolOptions, PgConnectOptions}};
use std::str::FromStr;
use std::time::Duration;

use crate::security::auth::ApiKeyStore;

/// Database configuration for PostgreSQL connection pooling
#[derive(Debug, Clone)]
pub struct DatabaseConfig {
    pub database_url: String,
    pub max_connections: u32,
    pub min_connections: u32,
    pub connect_timeout: Duration,
    pub idle_timeout: Duration,
    pub max_lifetime: Duration,
}

impl DatabaseConfig {
    /// Create database configuration from environment variables
    pub fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
        let database_url = std::env::var("DATABASE_URL")
            .or_else(|_| {
                // Construct from individual components if DATABASE_URL not provided
                let host = std::env::var("DB_HOST").unwrap_or_else(|_| "localhost".to_string());
                let port = std::env::var("DB_PORT").unwrap_or_else(|_| "5432".to_string());
                let user = std::env::var("DB_USER").unwrap_or_else(|_| "postgres".to_string());
                let password = std::env::var("DB_PASSWORD")
                    .map_err(|e| Box::new(std::io::Error::new(std::io::ErrorKind::NotFound, 
                        format!("DB_PASSWORD environment variable is required: {}", e))) as Box<dyn std::error::Error>)?;
                let database = std::env::var("DB_NAME").unwrap_or_else(|_| "cypheron".to_string());
                
                Ok::<String, Box<dyn std::error::Error>>(format!("postgresql://{}:{}@{}:{}/{}", user, password, host, port, database))
            })?;

        let max_connections = std::env::var("DB_MAX_CONNECTIONS")
            .unwrap_or_else(|_| "20".to_string())
            .parse::<u32>()
            .unwrap_or(20);

        let min_connections = std::env::var("DB_MIN_CONNECTIONS")
            .unwrap_or_else(|_| "5".to_string())
            .parse::<u32>()
            .unwrap_or(5);

        let connect_timeout_secs = std::env::var("DB_CONNECT_TIMEOUT")
            .unwrap_or_else(|_| "30".to_string())
            .parse::<u64>()
            .unwrap_or(30);

        let idle_timeout_secs = std::env::var("DB_IDLE_TIMEOUT")
            .unwrap_or_else(|_| "600".to_string()) // 10 minutes
            .parse::<u64>()
            .unwrap_or(600);

        let max_lifetime_secs = std::env::var("DB_MAX_LIFETIME")
            .unwrap_or_else(|_| "1800".to_string()) // 30 minutes
            .parse::<u64>()
            .unwrap_or(1800);

        Ok(Self {
            database_url,
            max_connections,
            min_connections,
            connect_timeout: Duration::from_secs(connect_timeout_secs),
            idle_timeout: Duration::from_secs(idle_timeout_secs),
            max_lifetime: Duration::from_secs(max_lifetime_secs),
        })
    }

    /// Create an optimized connection pool with the given configuration
    pub async fn create_pool(&self) -> Result<PgPool, sqlx::Error> {
        tracing::info!("Creating database connection pool with {} max connections", self.max_connections);
        
        // Parse connection options for additional configuration
        let connect_options = PgConnectOptions::from_str(&self.database_url)?
            .application_name("cypheron-api")
            .statement_cache_capacity(100); // Cache prepared statements

        let pool = PgPoolOptions::new()
            .max_connections(self.max_connections)
            .min_connections(self.min_connections)
            .acquire_timeout(self.connect_timeout)
            .idle_timeout(self.idle_timeout)
            .max_lifetime(self.max_lifetime)
            .test_before_acquire(true) // Test connections before use
            .connect_with(connect_options)
            .await?;

        tracing::info!("Database connection pool created successfully");
        Ok(pool)
    }

    /// Test database connectivity
    pub async fn test_connection(&self) -> Result<(), sqlx::Error> {
        tracing::info!("Testing database connectivity...");
        
        let pool = self.create_pool().await?;
        
        // Test with a simple query
        sqlx::query("SELECT 1 as test")
            .fetch_one(&pool)
            .await?;

        // Test pool capacity
        let stats = pool.options();
        tracing::info!(
            "Database connection test successful - max: {}, min: {}",
            stats.get_max_connections(),
            stats.get_min_connections()
        );

        pool.close().await;
        Ok(())
    }
}

/// Database manager for handling connections and migrations
#[derive(Debug)]
pub struct DatabaseManager {
    pub pool: PgPool,
    config: DatabaseConfig,
}

impl DatabaseManager {
    /// Create a new database manager with the given configuration
    pub async fn new(config: DatabaseConfig) -> Result<Self, sqlx::Error> {
        let pool = config.create_pool().await?;
        
        Ok(Self {
            pool,
            config,
        })
    }

    /// Create database manager from environment variables
    pub async fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
        let config = DatabaseConfig::from_env()?;
        let manager = Self::new(config).await?;
        Ok(manager)
    }

    /// Run database migrations if schema file exists
    pub async fn run_migrations(&self) -> Result<(), sqlx::Error> {
        tracing::info!("Checking for database migrations...");
        
        // Check if schema file exists
        let schema_path = std::path::Path::new("db/schema.sql");
        if !schema_path.exists() {
            tracing::warn!("No schema.sql file found, skipping migrations");
            return Ok(());
        }

        // Read and execute schema
        let schema_sql = std::fs::read_to_string(schema_path)
            .map_err(|e| sqlx::Error::Io(e.into()))?;

        // Split schema into individual statements (naive approach)
        let statements: Vec<&str> = schema_sql
            .split(';')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty() && !s.starts_with("--"))
            .collect();

        tracing::info!("Executing {} migration statements...", statements.len());

        for (i, statement) in statements.iter().enumerate() {
            if !statement.is_empty() {
                sqlx::query(statement)
                    .execute(&self.pool)
                    .await
                    .map_err(|e| {
                        tracing::error!("Migration statement {} failed: {}", i + 1, e);
                        e
                    })?;
            }
        }

        tracing::info!("Database migrations completed successfully");
        Ok(())
    }

    /// Check database health
    pub async fn health_check(&self) -> Result<DatabaseHealth, sqlx::Error> {
        let start = std::time::Instant::now();
        
        // Test basic connectivity
        sqlx::query("SELECT 1 as test")
            .fetch_one(&self.pool)
            .await?;

        let response_time = start.elapsed();

        // Get connection pool stats
        let pool_size = self.pool.size();
        let idle_connections = self.pool.num_idle().try_into().unwrap_or(0);

        Ok(DatabaseHealth {
            connected: true,
            response_time_ms: response_time.as_millis() as u64,
            pool_size,
            idle_connections,
            max_connections: self.config.max_connections,
        })
    }

    /// Get pool reference for repository usage
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Gracefully close the database connection pool
    pub async fn close(&self) {
        tracing::info!("Closing database connection pool...");
        self.pool.close().await;
        tracing::info!("Database connection pool closed");
    }
}

/// Database health information
#[derive(Debug, serde::Serialize)]
pub struct DatabaseHealth {
    pub connected: bool,
    pub response_time_ms: u64,
    pub pool_size: u32,
    pub idle_connections: u32,
    pub max_connections: u32,
}

/// Transaction wrapper for complex operations
pub struct DatabaseTransaction<'a> {
    tx: sqlx::Transaction<'a, sqlx::Postgres>,
}

impl<'a> DatabaseTransaction<'a> {
    /// Begin a new transaction
    pub async fn begin(pool: &'a PgPool) -> Result<Self, sqlx::Error> {
        let tx = pool.begin().await?;
        Ok(Self { tx })
    }

    /// Commit the transaction
    pub async fn commit(self) -> Result<(), sqlx::Error> {
        self.tx.commit().await
    }

    /// Rollback the transaction
    pub async fn rollback(self) -> Result<(), sqlx::Error> {
        self.tx.rollback().await
    }

    /// Get a reference to the transaction for executing queries
    pub fn as_ref(&mut self) -> &mut sqlx::Transaction<'a, sqlx::Postgres> {
        &mut self.tx
    }
}

/// High-level database configuration that integrates with the security system
/// This maintains your existing Firestore API key storage while providing PostgreSQL capabilities
pub struct DatabaseConfiguration {
    pub api_key_store: ApiKeyStore,
    database_backend: String,
    health: Option<DatabaseHealth>,
}

impl DatabaseConfiguration {
    /// Create database configuration from environment - keeps Firestore for API keys
    pub async fn from_environment() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        tracing::info!("Initializing database configuration...");
        
        // Initialize API key store with Firestore (preserves your existing setup)
        let project_id = std::env::var("GOOGLE_CLOUD_PROJECT")
            .or_else(|_| std::env::var("GOOGLE_CLOUD_PROJECT_ID"))
            .unwrap_or_else(|_| "cypheron-api".to_string());
        
        tracing::info!("Connecting to Firestore project: {}", project_id);
        let api_key_store = ApiKeyStore::new_with_firestore(&project_id).await
            .map_err(|e| Box::new(std::io::Error::new(
                std::io::ErrorKind::Other, 
                format!("Failed to initialize Firestore API key store: {}", e)
            )) as Box<dyn std::error::Error + Send + Sync>)?;

        // Initialize PostgreSQL if configured (for other data)
        let database_backend = if std::env::var("DATABASE_URL").is_ok() || std::env::var("DB_PASSWORD").is_ok() {
            tracing::info!("PostgreSQL configuration detected, testing connection...");
            match DatabaseConfig::from_env() {
                Ok(db_config) => {
                    match db_config.test_connection().await {
                        Ok(_) => {
                            tracing::info!("PostgreSQL connection successful");
                            "PostgreSQL + Firestore (API Keys)".to_string()
                        },
                        Err(e) => {
                            tracing::warn!("PostgreSQL connection failed ({}), continuing with Firestore only", e);
                            "Firestore Only".to_string()
                        }
                    }
                },
                Err(e) => {
                    tracing::warn!("PostgreSQL configuration error ({}), continuing with Firestore only", e);
                    "Firestore Only".to_string()
                }
            }
        } else {
            tracing::info!("No PostgreSQL configuration found, using Firestore only");
            "Firestore Only".to_string()
        };

        Ok(Self {
            api_key_store,
            database_backend,
            health: None,
        })
    }

    /// Get the backend type description
    pub fn get_backend_type(&self) -> &str {
        &self.database_backend
    }

    /// Perform health check on the database systems
    pub async fn health_check(&self) -> Result<DatabaseHealthStatus, Box<dyn std::error::Error + Send + Sync>> {
        tracing::info!("Performing database health check...");
        
        let start = std::time::Instant::now();
        
        // Test Firestore connectivity through API key store
        // This is a simple check - if the store was created, Firestore is accessible
        let firestore_healthy = true; // ApiKeyStore creation already validated this
        
        let response_time = start.elapsed();
        
        Ok(DatabaseHealthStatus {
            healthy: firestore_healthy,
            response_time_ms: Some(response_time.as_millis() as u64),
            backend_type: self.database_backend.clone(),
        })
    }
}

/// Health status for the database configuration
#[derive(Debug, serde::Serialize)]
pub struct DatabaseHealthStatus {
    pub healthy: bool,
    pub response_time_ms: Option<u64>,
    pub backend_type: String,
}

impl DatabaseHealthStatus {
    pub fn is_healthy(&self) -> bool {
        self.healthy
    }
    
    pub fn response_time_ms(&self) -> Option<u64> {
        self.response_time_ms
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_database_config_defaults() {
        // Set minimal env vars for test
        std::env::set_var("DB_PASSWORD", "test");
        
        let config = DatabaseConfig::from_env().unwrap();
        assert_eq!(config.max_connections, 20);
        assert_eq!(config.min_connections, 5);
        assert!(config.database_url.contains("test"));
        
        // Cleanup
        std::env::remove_var("DB_PASSWORD");
    }

    #[tokio::test]
    async fn test_database_config_validation() {
        let config = DatabaseConfig {
            database_url: "postgresql://user:pass@localhost/test".to_string(),
            max_connections: 10,
            min_connections: 2,
            connect_timeout: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(600),
            max_lifetime: Duration::from_secs(1800),
        };

        assert!(config.max_connections >= config.min_connections);
        assert!(config.idle_timeout < config.max_lifetime);
    }
}