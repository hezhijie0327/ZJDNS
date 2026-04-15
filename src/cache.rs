use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use async_trait::async_trait;
use lru::LruCache;
use redis::{aio::ConnectionManager, AsyncCommands, Client};
use tokio::sync::Mutex;

use crate::types::{CacheEntry, ECSOption, ServerConfig};

#[async_trait]
pub trait CacheManager: Send + Sync {
    async fn get(&self, key: &str) -> Result<Option<(Vec<u8>, bool)>>;
    async fn set(&self, key: &str, bytes: &[u8], ttl: u32, validated: bool, ecs: Option<ECSOption>) -> Result<()>;
}

pub struct MemoryCache {
    inner: Mutex<LruCache<String, CacheEntry>>,
}

impl MemoryCache {
    pub fn new(capacity: usize) -> Self {
        MemoryCache {
            inner: Mutex::new(LruCache::new(std::num::NonZeroUsize::new(capacity).unwrap_or_else(|| std::num::NonZeroUsize::new(1).unwrap()))),
        }
    }
}

#[async_trait]
impl CacheManager for MemoryCache {
    async fn get(&self, key: &str) -> Result<Option<(Vec<u8>, bool)>> {
        let mut cache = self.inner.lock().await;
        if let Some(entry) = cache.get(key) {
            let expired = Instant::now() >= entry.expires_at;
            Ok(Some((entry.bytes.clone(), expired)))
        } else {
            Ok(None)
        }
    }

    async fn set(&self, key: &str, bytes: &[u8], ttl: u32, validated: bool, ecs: Option<ECSOption>) -> Result<()> {
        let mut cache = self.inner.lock().await;
        let expires_at = Instant::now() + Duration::from_secs(ttl as u64).max(Duration::from_secs(10));
        cache.put(
            key.to_string(),
            CacheEntry {
                bytes: bytes.to_vec(),
                expires_at,
                validated,
                ecs_address: ecs.map(|e| e.address),
            },
        );
        Ok(())
    }
}

pub struct RedisCache {
    memory: Arc<MemoryCache>,
    redis: ConnectionManager,
}

impl RedisCache {
    pub async fn new(config: &ServerConfig) -> Result<Self> {
        let client = Client::open(format!("redis://{}", config.redis.address))
            .context("connect redis")?;
        let manager = client
            .get_tokio_connection_manager()
            .await
            .context("create redis connection manager")?;
        Ok(RedisCache {
            memory: Arc::new(MemoryCache::new(config.server.memory_cache_size)),
            redis: manager,
        })
    }
}

#[async_trait]
impl CacheManager for RedisCache {
    async fn get(&self, key: &str) -> Result<Option<(Vec<u8>, bool)>> {
        if let Some(value) = self.memory.get(key).await? {
            return Ok(Some(value));
        }

        let mut conn = self.redis.clone();
        let bytes: Option<Vec<u8>> = conn.get(key).await.context("redis GET")?;
        if let Some(bytes) = bytes {
            let ttl: Option<i64> = conn.ttl(key).await.context("redis TTL")?;
            let expired = ttl.map(|remaining| remaining <= 0).unwrap_or(false);
            self.memory
                .set(key, &bytes, 30, false, None)
                .await
                .ok();
            return Ok(Some((bytes, expired)));
        }
        Ok(None)
    }

    async fn set(&self, key: &str, bytes: &[u8], ttl: u32, _validated: bool, _ecs: Option<ECSOption>) -> Result<()> {
        self.memory.set(key, bytes, ttl, _validated, _ecs).await?;
        let mut conn = self.redis.clone();
        conn.set_ex::<_, _, ()>(key, bytes.to_vec(), ttl as usize)
            .await
            .context("redis SETEX")?;
        Ok(())
    }
}
