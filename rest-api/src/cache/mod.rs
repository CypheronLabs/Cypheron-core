use redis::{Client, RedisResult, AsyncCommands};
use redis::aio::ConnectionManager;
use serde::{Deserialize, Serialize};
use crate::config::RedisConfig;
use crate::security::auth::ApiKey;

pub struct CacheService {
    redis: Option<ConnectionManager>,
    enabled: bool,
    default_ttl_seconds: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CachedUserPermissions {
    pub user_id: String,
    pub permissions: Vec<String>,
    pub cached_at: chrono::DateTime<chrono::Utc>,
}

impl CacheService {
    pub async fn new(config: &RedisConfig) -> Result<Self, Box<dyn std::error::Error>> {
        if !config.enabled || config.url.is_none() {
            tracing::info!("Redis disabled - running without cache");
            return Ok(Self {
                redis: None,
                enabled: false,
                default_ttl_seconds: config.default_ttl_seconds,
            });
        }

        match Self::connect_redis(config).await {
            Ok(manager) => {
                tracing::info!("Redis connected successfully");
                Ok(Self {
                    redis: Some(manager),
                    enabled: true,
                    default_ttl_seconds: config.default_ttl_seconds,
                })
            }
            Err(e) => {
                tracing::warn!("Redis connection failed: {} - continuing without cache", e);
                Ok(Self {
                    redis: None,
                    enabled: false,
                    default_ttl_seconds: config.default_ttl_seconds,
                })
            }
        }
    }

    async fn connect_redis(config: &RedisConfig) -> RedisResult<ConnectionManager> {
        let redis_url = config.url.as_ref().unwrap();
        
        let client = if let Some(password) = &config.password {
            let url_with_auth = if redis_url.contains("://") {
                let parts: Vec<&str> = redis_url.splitn(2, "://").collect();
                if parts.len() == 2 {
                    format!("{}://default:{}@{}", parts[0], password, parts[1])
                } else {
                    redis_url.clone()
                }
            } else {
                redis_url.clone()
            };
            Client::open(url_with_auth)?
        } else {
            Client::open(redis_url.as_str())?
        };

        let manager = client
            .get_connection_manager()
            .await
            .map_err(|e| {
                tracing::error!("Failed to create Redis connection manager: {}", e);
                e
            })?;

        let mut test_conn = manager.clone();
        let _: String = redis::cmd("PING").query_async(&mut test_conn).await?;
        
        tracing::info!("Redis connection test successful");
        Ok(manager)
    }

    pub async fn get_user_permissions(&self, user_id: &str) -> Option<Vec<String>> {
        if !self.enabled || self.redis.is_none() {
            return None;
        }

        let mut conn = self.redis.as_ref()?.clone();
        let cache_key = format!("user_permissions:{}", user_id);

        match conn.get::<_, String>(&cache_key).await {
            Ok(cached_data) => {
                match serde_json::from_str::<CachedUserPermissions>(&cached_data) {
                    Ok(cached_perms) => {
                        tracing::debug!("Cache hit for user permissions: {}", user_id);
                        Some(cached_perms.permissions)
                    }
                    Err(e) => {
                        tracing::warn!("Failed to deserialize cached permissions for {}: {}", user_id, e);
                        let _ = conn.del::<_, ()>(&cache_key).await;
                        None
                    }
                }
            }
            Err(e) => {
                tracing::debug!("Cache miss or Redis error for user permissions {}: {}", user_id, e);
                None
            }
        }
    }

    pub async fn cache_user_permissions(&self, user_id: &str, permissions: &[String], ttl_seconds: u64) {
        if !self.enabled || self.redis.is_none() {
            return;
        }

        let mut conn = match self.redis.as_ref() {
            Some(conn) => conn.clone(),
            None => return,
        };

        let cache_key = format!("user_permissions:{}", user_id);
        let cached_data = CachedUserPermissions {
            user_id: user_id.to_string(),
            permissions: permissions.to_vec(),
            cached_at: chrono::Utc::now(),
        };

        match serde_json::to_string(&cached_data) {
            Ok(serialized) => {
                let result: RedisResult<()> = conn.set_ex(&cache_key, &serialized, ttl_seconds).await;
                match result {
                    Ok(_) => {
                        tracing::debug!("Cached user permissions for {} (TTL: {}s)", user_id, ttl_seconds);
                    }
                    Err(e) => {
                        tracing::warn!("Failed to cache user permissions for {}: {}", user_id, e);
                    }
                }
            }
            Err(e) => {
                tracing::warn!("Failed to serialize user permissions for {}: {}", user_id, e);
            }
        }
    }

    pub async fn get_cached_api_key(&self, key_hash: &str) -> Option<ApiKey> {
        if !self.enabled || self.redis.is_none() {
            return None;
        }

        let mut conn = self.redis.as_ref()?.clone();
        let cache_key = format!("api_key:{}", key_hash);

        match conn.get::<_, String>(&cache_key).await {
            Ok(cached_data) => {
                match serde_json::from_str::<ApiKey>(&cached_data) {
                    Ok(api_key) => {
                        tracing::debug!("Cache hit for API key: {}", key_hash);
                        Some(api_key)
                    }
                    Err(e) => {
                        tracing::warn!("Failed to deserialize cached API key {}: {}", key_hash, e);
                        let _ = conn.del::<_, ()>(&cache_key).await;
                        None
                    }
                }
            }
            Err(e) => {
                tracing::debug!("Cache miss or Redis error for API key {}: {}", key_hash, e);
                None
            }
        }
    }

    pub async fn cache_api_key(&self, key_hash: &str, api_key: &ApiKey, ttl_seconds: u64) {
        if !self.enabled || self.redis.is_none() {
            return;
        }

        let mut conn = match self.redis.as_ref() {
            Some(conn) => conn.clone(),
            None => return,
        };

        let cache_key = format!("api_key:{}", key_hash);

        match serde_json::to_string(api_key) {
            Ok(serialized) => {
                let result: RedisResult<()> = conn.set_ex(&cache_key, &serialized, ttl_seconds).await;
                match result {
                    Ok(_) => {
                        tracing::debug!("Cached API key {} (TTL: {}s)", key_hash, ttl_seconds);
                    }
                    Err(e) => {
                        tracing::warn!("Failed to cache API key {}: {}", key_hash, e);
                    }
                }
            }
            Err(e) => {
                tracing::warn!("Failed to serialize API key {}: {}", key_hash, e);
            }
        }
    }

    pub async fn invalidate_api_key(&self, key_hash: &str) {
        if !self.enabled || self.redis.is_none() {
            return;
        }

        let mut conn = match self.redis.as_ref() {
            Some(conn) => conn.clone(),
            None => return,
        };

        let cache_key = format!("api_key:{}", key_hash);
        match conn.del::<_, i32>(&cache_key).await {
            Ok(deleted) => {
                if deleted > 0 {
                    tracing::debug!("Invalidated cached API key: {}", key_hash);
                }
            }
            Err(e) => {
                tracing::warn!("Failed to invalidate cached API key {}: {}", key_hash, e);
            }
        }
    }

    pub async fn invalidate_user_permissions(&self, user_id: &str) {
        if !self.enabled || self.redis.is_none() {
            return;
        }

        let mut conn = match self.redis.as_ref() {
            Some(conn) => conn.clone(),
            None => return,
        };

        let cache_key = format!("user_permissions:{}", user_id);
        match conn.del::<_, i32>(&cache_key).await {
            Ok(deleted) => {
                if deleted > 0 {
                    tracing::debug!("Invalidated cached user permissions: {}", user_id);
                }
            }
            Err(e) => {
                tracing::warn!("Failed to invalidate cached user permissions {}: {}", user_id, e);
            }
        }
    }
    pub async fn health_check(&self) -> bool {
        if !self.enabled {
            return true;
        }

        let mut conn = match self.redis.as_ref() {
            Some(conn) => conn.clone(),
            None => return false,
        };

        match redis::cmd("PING").query_async::<_, String>(&mut conn).await {
            Ok(_) => {
                tracing::debug!("Redis health check: OK");
                true
            }
            Err(e) => {
                tracing::error!("Redis health check failed: {}", e);
                false
            }
        }
    }

    pub async fn get_stats(&self) -> Option<CacheStats> {
        if !self.enabled || self.redis.is_none() {
            return None;
        }

        let mut conn = self.redis.as_ref()?.clone();

        match redis::cmd("INFO").query_async::<_, String>(&mut conn).await {
            Ok(info) => {
                let mut stats = CacheStats::default();
                
                for line in info.lines() {
                    if let Some((key, value)) = line.split_once(':') {
                        match key {
                            "used_memory" => {
                                if let Ok(mem) = value.parse::<u64>() {
                                    stats.memory_used_bytes = mem;
                                }
                            }
                            "keyspace_hits" => {
                                if let Ok(hits) = value.parse::<u64>() {
                                    stats.keyspace_hits = hits;
                                }
                            }
                            "keyspace_misses" => {
                                if let Ok(misses) = value.parse::<u64>() {
                                    stats.keyspace_misses = misses;
                                }
                            }
                            "connected_clients" => {
                                if let Ok(clients) = value.parse::<u32>() {
                                    stats.connected_clients = clients;
                                }
                            }
                            _ => {}
                        }
                    }
                }
                
                Some(stats)
            }
            Err(e) => {
                tracing::warn!("Failed to get Redis stats: {}", e);
                None
            }
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct CacheStats {
    pub memory_used_bytes: u64,
    pub keyspace_hits: u64,
    pub keyspace_misses: u64,
    pub connected_clients: u32,
}

impl CacheStats {
    pub fn hit_rate(&self) -> f64 {
        let total = self.keyspace_hits + self.keyspace_misses;
        if total == 0 {
            0.0
        } else {
            self.keyspace_hits as f64 / total as f64
        }
    }
}