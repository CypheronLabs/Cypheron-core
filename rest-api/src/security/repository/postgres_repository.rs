use super::{ApiKeyRepository, AuditLogEntry, AnalyticsEntry};
use crate::security::auth::{ApiKey, AuthError, PostQuantumEncryption};
use crate::security::validation::UsageUpdateInfo;
use base64::{engine::general_purpose, Engine as _};
use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row};
use std::sync::Arc;
use uuid::Uuid;

/// PostgreSQL implementation of the ApiKeyRepository trait
/// Provides full CRUD operations with transaction support
#[derive(Debug)]
pub struct PostgresRepository {
    pool: PgPool,
    encryption: Arc<PostQuantumEncryption>,
}

impl PostgresRepository {
    pub fn new(pool: PgPool, encryption: Arc<PostQuantumEncryption>) -> Self {
        Self { pool, encryption }
    }

    /// Convert PostgreSQL row to ApiKey struct
    fn row_to_api_key(&self, row: &sqlx::postgres::PgRow) -> Result<ApiKey, AuthError> {
        Ok(ApiKey {
            id: row.try_get("id").map_err(|e| AuthError {
                error: "database_parse_error".to_string(),
                message: format!("Failed to parse id: {}", e),
                code: 500,
            })?,
            name: row.try_get("name").map_err(|e| AuthError {
                error: "database_parse_error".to_string(),
                message: format!("Failed to parse name: {}", e),
                code: 500,
            })?,
            key_hash: row.try_get("key_hash").map_err(|e| AuthError {
                error: "database_parse_error".to_string(),
                message: format!("Failed to parse key_hash: {}", e),
                code: 500,
            })?,
            permissions: row.try_get::<Vec<String>, _>("permissions").map_err(|e| AuthError {
                error: "database_parse_error".to_string(),
                message: format!("Failed to parse permissions: {}", e),
                code: 500,
            })?,
            rate_limit: row.try_get::<i32, _>("rate_limit").map_err(|e| AuthError {
                error: "database_parse_error".to_string(),
                message: format!("Failed to parse rate_limit: {}", e),
                code: 500,
            })? as u32,
            created_at: row.try_get("created_at").map_err(|e| AuthError {
                error: "database_parse_error".to_string(),
                message: format!("Failed to parse created_at: {}", e),
                code: 500,
            })?,
            expires_at: row.try_get("expires_at").ok(),
            is_active: row.try_get("is_active").map_err(|e| AuthError {
                error: "database_parse_error".to_string(),
                message: format!("Failed to parse is_active: {}", e),
                code: 500,
            })?,
            last_used: row.try_get("last_used").ok(),
            usage_count: row.try_get::<i64, _>("usage_count").map_err(|e| AuthError {
                error: "database_parse_error".to_string(),
                message: format!("Failed to parse usage_count: {}", e),
                code: 500,
            })? as u64,
        })
    }

    /// Convert PostgreSQL row to AuditLogEntry struct
    fn row_to_audit_entry(&self, row: &sqlx::postgres::PgRow) -> Result<AuditLogEntry, AuthError> {
        Ok(AuditLogEntry {
            id: row.try_get("id").map_err(|e| AuthError {
                error: "database_parse_error".to_string(),
                message: format!("Failed to parse audit id: {}", e),
                code: 500,
            })?,
            timestamp: row.try_get("timestamp").map_err(|e| AuthError {
                error: "database_parse_error".to_string(),
                message: format!("Failed to parse timestamp: {}", e),
                code: 500,
            })?,
            event_type: row.try_get("event_type").map_err(|e| AuthError {
                error: "database_parse_error".to_string(),
                message: format!("Failed to parse event_type: {}", e),
                code: 500,
            })?,
            api_key_id: row.try_get("api_key_id").ok(),
            api_key_hash: row.try_get("api_key_hash").ok(),
            ip_address: row.try_get("ip_address").ok(),
            user_agent: row.try_get("user_agent").ok(),
            request_path: row.try_get("request_path").ok(),
            request_method: row.try_get("request_method").ok(),
            response_status: row.try_get("response_status").ok(),
            response_time_ms: row.try_get("response_time_ms").ok(),
            metadata: row.try_get("metadata").unwrap_or_else(|_| serde_json::json!({})),
            risk_level: row.try_get("risk_level").map_err(|e| AuthError {
                error: "database_parse_error".to_string(),
                message: format!("Failed to parse risk_level: {}", e),
                code: 500,
            })?,
        })
    }
}

#[async_trait::async_trait]
impl ApiKeyRepository for PostgresRepository {
    async fn store_api_key(&self, api_key: &ApiKey, raw_key: &str) -> Result<(), AuthError> {
        // Encrypt the raw key
        let encrypted_key = self.encryption.encrypt(raw_key.as_bytes())?;
        let encrypted_key_b64 = general_purpose::STANDARD.encode(&encrypted_key);

        // Begin transaction for atomicity
        let mut tx = self.pool.begin().await.map_err(|e| AuthError {
            error: "database_transaction_error".to_string(),
            message: format!("Failed to begin transaction: {}", e),
            code: 500,
        })?;

        // Insert API key
        sqlx::query(
            r#"
            INSERT INTO api_keys (
                id, name, key_hash, encrypted_key, permissions, rate_limit,
                created_at, expires_at, is_active, last_used, usage_count
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            "#
        )
        .bind(api_key.id)
        .bind(&api_key.name)
        .bind(&api_key.key_hash)
        .bind(encrypted_key_b64)
        .bind(&api_key.permissions)
        .bind(api_key.rate_limit as i32)
        .bind(api_key.created_at)
        .bind(api_key.expires_at)
        .bind(api_key.is_active)
        .bind(api_key.last_used)
        .bind(api_key.usage_count as i64)
        .execute(&mut *tx)
        .await
        .map_err(|e| AuthError {
            error: "database_insert_error".to_string(),
            message: format!("Failed to insert API key: {}", e),
            code: 500,
        })?;

        // Log audit event
        sqlx::query(
            r#"
            INSERT INTO audit_logs (
                event_type, api_key_id, api_key_hash, metadata, risk_level
            ) VALUES ($1, $2, $3, $4, $5)
            "#
        )
        .bind("api_key_created")
        .bind(api_key.id)
        .bind(&api_key.key_hash)
        .bind(serde_json::json!({
            "name": api_key.name,
            "permissions": api_key.permissions,
            "rate_limit": api_key.rate_limit
        }))
        .bind("low")
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            tracing::warn!("Failed to log audit event: {}", e);
            e
        })
        .ok(); // Don't fail the transaction for audit log errors

        // Commit transaction
        tx.commit().await.map_err(|e| AuthError {
            error: "database_commit_error".to_string(),
            message: format!("Failed to commit transaction: {}", e),
            code: 500,
        })?;

        Ok(())
    }

    async fn get_api_key_by_hash(&self, key_hash: &str) -> Result<Option<ApiKey>, AuthError> {
        let row = sqlx::query(
            r#"
            SELECT id, name, key_hash, permissions, rate_limit, created_at, 
                   expires_at, is_active, last_used, usage_count
            FROM api_keys 
            WHERE key_hash = $1 AND is_active = true
            "#
        )
        .bind(key_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AuthError {
            error: "database_query_error".to_string(),
            message: format!("Failed to query API key: {}", e),
            code: 500,
        })?;

        match row {
            Some(row) => Ok(Some(self.row_to_api_key(&row)?)),
            None => Ok(None),
        }
    }

    async fn update_api_key(&self, api_key: &ApiKey) -> Result<(), AuthError> {
        let mut tx = self.pool.begin().await.map_err(|e| AuthError {
            error: "database_transaction_error".to_string(),
            message: format!("Failed to begin transaction: {}", e),
            code: 500,
        })?;

        let result = sqlx::query(
            r#"
            UPDATE api_keys 
            SET name = $1, permissions = $2, rate_limit = $3, expires_at = $4, 
                is_active = $5, updated_at = NOW()
            WHERE key_hash = $6
            "#
        )
        .bind(&api_key.name)
        .bind(&api_key.permissions)
        .bind(api_key.rate_limit as i32)
        .bind(api_key.expires_at)
        .bind(api_key.is_active)
        .bind(&api_key.key_hash)
        .execute(&mut *tx)
        .await
        .map_err(|e| AuthError {
            error: "database_update_error".to_string(),
            message: format!("Failed to update API key: {}", e),
            code: 500,
        })?;

        if result.rows_affected() == 0 {
            return Err(AuthError {
                error: "api_key_not_found".to_string(),
                message: "API key not found for update".to_string(),
                code: 404,
            });
        }

        // Log audit event
        sqlx::query(
            r#"
            INSERT INTO audit_logs (
                event_type, api_key_id, api_key_hash, metadata, risk_level
            ) VALUES ($1, $2, $3, $4, $5)
            "#
        )
        .bind("api_key_updated")
        .bind(api_key.id)
        .bind(&api_key.key_hash)
        .bind(serde_json::json!({
            "name": api_key.name,
            "permissions": api_key.permissions,
            "is_active": api_key.is_active
        }))
        .bind("low")
        .execute(&mut *tx)
        .await
        .ok(); // Don't fail for audit log errors

        tx.commit().await.map_err(|e| AuthError {
            error: "database_commit_error".to_string(),
            message: format!("Failed to commit transaction: {}", e),
            code: 500,
        })?;

        Ok(())
    }

    async fn delete_api_key(&self, key_hash: &str) -> Result<(), AuthError> {
        let mut tx = self.pool.begin().await.map_err(|e| AuthError {
            error: "database_transaction_error".to_string(),
            message: format!("Failed to begin transaction: {}", e),
            code: 500,
        })?;

        // Get API key info before deletion for audit log
        let api_key = self.get_api_key_by_hash(key_hash).await?;
        
        let result = sqlx::query(
            "DELETE FROM api_keys WHERE key_hash = $1"
        )
        .bind(key_hash)
        .execute(&mut *tx)
        .await
        .map_err(|e| AuthError {
            error: "database_delete_error".to_string(),
            message: format!("Failed to delete API key: {}", e),
            code: 500,
        })?;

        if result.rows_affected() == 0 {
            return Err(AuthError {
                error: "api_key_not_found".to_string(),
                message: "API key not found for deletion".to_string(),
                code: 404,
            });
        }

        // Log audit event if we had the key info
        if let Some(key) = api_key {
            sqlx::query(
                r#"
                INSERT INTO audit_logs (
                    event_type, api_key_id, api_key_hash, metadata, risk_level
                ) VALUES ($1, $2, $3, $4, $5)
                "#
            )
            .bind("api_key_deleted")
            .bind(key.id)
            .bind(&key.key_hash)
            .bind(serde_json::json!({
                "name": key.name,
                "permissions": key.permissions
            }))
            .bind("medium")
            .execute(&mut *tx)
            .await
            .ok(); // Don't fail for audit log errors
        }

        tx.commit().await.map_err(|e| AuthError {
            error: "database_commit_error".to_string(),
            message: format!("Failed to commit transaction: {}", e),
            code: 500,
        })?;

        Ok(())
    }

    async fn list_api_keys(&self, limit: Option<i32>, offset: Option<i32>) -> Result<Vec<ApiKey>, AuthError> {
        let limit = limit.unwrap_or(100).min(1000); // Cap at 1000 for performance
        let offset = offset.unwrap_or(0).max(0);

        let rows = sqlx::query(
            r#"
            SELECT id, name, key_hash, permissions, rate_limit, created_at, 
                   expires_at, is_active, last_used, usage_count
            FROM api_keys 
            ORDER BY created_at DESC
            LIMIT $1 OFFSET $2
            "#
        )
        .bind(limit as i32)
        .bind(offset as i32)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AuthError {
            error: "database_query_error".to_string(),
            message: format!("Failed to list API keys: {}", e),
            code: 500,
        })?;

        let mut api_keys = Vec::new();
        for row in rows {
            api_keys.push(self.row_to_api_key(&row)?);
        }

        Ok(api_keys)
    }

    async fn update_usage(&self, usage_info: &UsageUpdateInfo) -> Result<(), AuthError> {
        sqlx::query(
            r#"
            UPDATE api_keys 
            SET last_used = $1, usage_count = $2, updated_at = NOW()
            WHERE key_hash = $3
            "#
        )
        .bind(usage_info.last_used)
        .bind(usage_info.usage_count as i64)
        .bind(&usage_info.key_hash)
        .execute(&self.pool)
        .await
        .map_err(|e| AuthError {
            error: "database_update_error".to_string(),
            message: format!("Failed to update usage: {}", e),
            code: 500,
        })?;

        Ok(())
    }

    async fn log_audit_event(&self, entry: &AuditLogEntry) -> Result<(), AuthError> {
        sqlx::query(
            r#"
            INSERT INTO audit_logs (
                id, timestamp, event_type, api_key_id, api_key_hash,
                ip_address, user_agent, request_path, request_method,
                response_status, response_time_ms, metadata, risk_level
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
            "#
        )
        .bind(entry.id)
        .bind(entry.timestamp)
        .bind(&entry.event_type)
        .bind(entry.api_key_id)
        .bind(&entry.api_key_hash)
        .bind(&entry.ip_address)
        .bind(&entry.user_agent)
        .bind(&entry.request_path)
        .bind(&entry.request_method)
        .bind(entry.response_status)
        .bind(entry.response_time_ms)
        .bind(&entry.metadata)
        .bind(&entry.risk_level)
        .execute(&self.pool)
        .await
        .map_err(|e| AuthError {
            error: "database_insert_error".to_string(),
            message: format!("Failed to log audit event: {}", e),
            code: 500,
        })?;

        Ok(())
    }

    async fn get_audit_logs(
        &self,
        api_key_id: Option<Uuid>,
        start_time: Option<DateTime<Utc>>,
        end_time: Option<DateTime<Utc>>,
        limit: Option<i32>,
    ) -> Result<Vec<AuditLogEntry>, AuthError> {
        let limit = limit.unwrap_or(100).min(1000);

        let rows = if let Some(api_key_id) = api_key_id {
            sqlx::query(
                r#"
                SELECT id, timestamp, event_type, api_key_id, api_key_hash,
                       ip_address, user_agent, request_path, request_method,
                       response_status, response_time_ms, metadata, risk_level
                FROM audit_logs
                WHERE api_key_id = $1
                  AND ($2::timestamptz IS NULL OR timestamp >= $2)
                  AND ($3::timestamptz IS NULL OR timestamp <= $3)
                ORDER BY timestamp DESC
                LIMIT $4
                "#
            )
            .bind(api_key_id)
            .bind(start_time)
            .bind(end_time)
            .bind(limit as i32)
            .fetch_all(&self.pool)
            .await
        } else {
            sqlx::query(
                r#"
                SELECT id, timestamp, event_type, api_key_id, api_key_hash,
                       ip_address, user_agent, request_path, request_method,
                       response_status, response_time_ms, metadata, risk_level
                FROM audit_logs
                WHERE ($1::timestamptz IS NULL OR timestamp >= $1)
                  AND ($2::timestamptz IS NULL OR timestamp <= $2)
                ORDER BY timestamp DESC
                LIMIT $3
                "#
            )
            .bind(start_time)
            .bind(end_time)
            .bind(limit as i32)
            .fetch_all(&self.pool)
            .await
        };

        let rows = rows.map_err(|e| AuthError {
            error: "database_query_error".to_string(),
            message: format!("Failed to query audit logs: {}", e),
            code: 500,
        })?;

        let mut audit_logs = Vec::new();
        for row in rows {
            audit_logs.push(self.row_to_audit_entry(&row)?);
        }

        Ok(audit_logs)
    }

    async fn record_analytics(&self, entry: &AnalyticsEntry) -> Result<(), AuthError> {
        sqlx::query(
            r#"
            INSERT INTO analytics (
                id, timestamp, api_key_id, endpoint, method,
                response_time_ms, request_size_bytes, response_size_bytes,
                success, error_type, region, client_type, metrics
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
            "#
        )
        .bind(entry.id)
        .bind(entry.timestamp)
        .bind(entry.api_key_id)
        .bind(&entry.endpoint)
        .bind(&entry.method)
        .bind(entry.response_time_ms)
        .bind(entry.request_size_bytes)
        .bind(entry.response_size_bytes)
        .bind(entry.success)
        .bind(&entry.error_type)
        .bind(&entry.region)
        .bind(&entry.client_type)
        .bind(&entry.metrics)
        .execute(&self.pool)
        .await
        .map_err(|e| AuthError {
            error: "database_insert_error".to_string(),
            message: format!("Failed to record analytics: {}", e),
            code: 500,
        })?;

        Ok(())
    }

    async fn health_check(&self) -> Result<(), AuthError> {
        sqlx::query("SELECT 1")
            .execute(&self.pool)
            .await
            .map_err(|e| AuthError {
                error: "database_health_error".to_string(),
                message: format!("Database health check failed: {}", e),
                code: 500,
            })?;

        Ok(())
    }
}