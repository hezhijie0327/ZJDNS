// Package main implements ZJDNS - High Performance DNS Server
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"slices"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/redis/go-redis/v9"
	"github.com/redis/go-redis/v9/logging"
	"golang.org/x/sync/errgroup"
)

// =============================================================================
// NullCache Implementation
// =============================================================================

// NewNullCache creates a new no-op cache
func NewNullCache() *NullCache {
	LogInfo("CACHE: Null cache mode enabled")
	return &NullCache{}
}

// Get returns empty cache result
func (nc *NullCache) Get(key string) (*CacheEntry, bool, bool) { return nil, false, false }

// Set is a no-op
func (nc *NullCache) Set(key string, answer, authority, additional []dns.RR, validated bool, ecs *ECSOption) {
}

// Close is a no-op
func (nc *NullCache) Close() error { return nil }

// =============================================================================
// RedisCache Implementation
// =============================================================================

// NewRedisCache creates a new Redis-backed cache
func NewRedisCache(config *ServerConfig) (*RedisCache, error) {
	logging.Disable()

	rdb := redis.NewClient(&redis.Options{
		Addr:     config.Redis.Address,
		Password: config.Redis.Password,
		DB:       config.Redis.Database,
	})

	ctx, cancel := context.WithTimeout(context.Background(), DefaultTimeout)
	defer cancel()

	if err := rdb.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("redis connection: %w", err)
	}

	cacheCtx, cacheCancel := context.WithCancelCause(context.Background())
	bgGroup, bgCtx := errgroup.WithContext(cacheCtx)

	cache := &RedisCache{
		client:  rdb,
		config:  config,
		ctx:     cacheCtx,
		cancel:  cacheCancel,
		bgGroup: bgGroup,
		bgCtx:   bgCtx,
	}

	LogInfo("CACHE: Redis cache initialized")
	return cache, nil
}

// Get retrieves a value from the cache
func (rc *RedisCache) Get(key string) (*CacheEntry, bool, bool) {
	defer HandlePanic("Redis cache get")

	if atomic.LoadInt32(&rc.closed) != 0 {
		return nil, false, false
	}

	ctx, cancel := context.WithTimeout(rc.ctx, OperationTimeout)
	defer cancel()

	data, err := rc.client.Get(ctx, key).Result()
	if err != nil {
		return nil, false, false
	}

	var entry CacheEntry
	if err := json.Unmarshal([]byte(data), &entry); err != nil {
		rc.bgGroup.Go(func() error {
			defer HandlePanic("Clean corrupted cache")
			cleanCtx, cleanCancel := context.WithTimeout(rc.bgCtx, OperationTimeout)
			defer cleanCancel()
			if err := rc.client.Del(cleanCtx, key).Err(); err != nil {
				LogError("CACHE: Failed to clean corrupted cache key %s: %v", key, err)
				return nil
			}
			return nil
		})
		return nil, false, false
	}

	isExpired := entry.IsExpired()

	entry.AccessTime = time.Now().Unix()
	rc.bgGroup.Go(func() error {
		defer HandlePanic("Update access time")
		if atomic.LoadInt32(&rc.closed) == 0 {
			updateCtx, updateCancel := context.WithTimeout(rc.bgCtx, OperationTimeout)
			defer updateCancel()
			if data, err := json.Marshal(entry); err == nil {
				if err := rc.client.Set(updateCtx, key, data, redis.KeepTTL).Err(); err != nil {
					LogError("CACHE: Failed to update access time for key %s: %v", key, err)
				}
			}
		}
		return nil
	})

	return &entry, true, isExpired
}

// Set stores a value in the cache
func (rc *RedisCache) Set(key string, answer, authority, additional []dns.RR, validated bool, ecs *ECSOption) {
	defer HandlePanic("Redis cache set")

	if atomic.LoadInt32(&rc.closed) != 0 {
		return
	}

	allRRs := slices.Concat(answer, authority, additional)
	cacheTTL := calculateTTL(allRRs)
	now := time.Now().Unix()

	entry := &CacheEntry{
		Answer:      compactRecords(answer),
		Authority:   compactRecords(authority),
		Additional:  compactRecords(additional),
		TTL:         cacheTTL,
		OriginalTTL: cacheTTL,
		Timestamp:   now,
		Validated:   validated,
		AccessTime:  now,
	}

	if ecs != nil {
		entry.ECSFamily = ecs.Family
		entry.ECSSourcePrefix = ecs.SourcePrefix
		entry.ECSScopePrefix = ecs.ScopePrefix
		entry.ECSAddress = ecs.Address.String()
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return
	}

	ctx, cancel := context.WithTimeout(rc.ctx, OperationTimeout)
	defer cancel()

	expiration := time.Duration(cacheTTL)*time.Second + time.Duration(StaleMaxAge)*time.Second
	rc.client.Set(ctx, key, data, expiration)
}

// Close shuts down the Redis cache
func (rc *RedisCache) Close() error {
	if !atomic.CompareAndSwapInt32(&rc.closed, 0, 1) {
		return nil
	}

	LogInfo("CACHE: Shutting down Redis cache")

	rc.cancel(errors.New("redis cache shutdown"))

	done := make(chan error, 1)
	go func() {
		defer HandlePanic("Redis background group wait")
		done <- rc.bgGroup.Wait()
	}()

	select {
	case err := <-done:
		if err != nil {
			LogError("CACHE: Background goroutine error: %v", err)
		}
		LogDebug("CACHE: All Redis background goroutines finished gracefully")
	case <-time.After(IdleTimeout):
		LogWarn("CACHE: Redis background goroutine shutdown timeout")
	}

	if err := rc.client.Close(); err != nil {
		LogError("CACHE: Redis client shutdown failed: %v", err)
	}

	LogInfo("CACHE: Redis cache shut down")
	return nil
}

// =============================================================================
// CacheEntry Implementation
// =============================================================================

// IsExpired checks if the cache entry is expired
func (c *CacheEntry) IsExpired() bool {
	return c != nil && time.Now().Unix()-c.Timestamp > int64(c.TTL)
}

// ShouldRefresh checks if the cache entry should be refreshed
func (c *CacheEntry) ShouldRefresh() bool {
	if c == nil {
		return false
	}
	now := time.Now().Unix()
	refreshInterval := int64(c.OriginalTTL)
	if refreshInterval <= 0 {
		refreshInterval = int64(c.TTL)
	}
	return c.IsExpired() && (now-c.Timestamp) > refreshInterval
}

// GetRemainingTTL returns the remaining TTL for the cache entry
func (c *CacheEntry) GetRemainingTTL() uint32 {
	if c == nil {
		return 0
	}
	now := time.Now().Unix()
	elapsed := now - c.Timestamp
	remaining := int64(c.TTL) - elapsed
	if remaining > 0 {
		return uint32(remaining)
	}

	staleElapsed := elapsed - int64(c.TTL)
	staleCycle := staleElapsed % int64(StaleTTL)
	staleTTLRemaining := int64(StaleTTL) - staleCycle
	if staleTTLRemaining <= 0 {
		staleTTLRemaining = int64(StaleTTL)
	}
	return uint32(staleTTLRemaining)
}

// GetECSOption returns the ECS option from the cache entry
func (c *CacheEntry) GetECSOption() *ECSOption {
	if c == nil || c.ECSAddress == "" {
		return nil
	}
	if ip := net.ParseIP(c.ECSAddress); ip != nil {
		return &ECSOption{
			Family:       c.ECSFamily,
			SourcePrefix: c.ECSSourcePrefix,
			ScopePrefix:  c.ECSScopePrefix,
			Address:      ip,
		}
	}
	return nil
}
