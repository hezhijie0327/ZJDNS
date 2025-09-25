package cache

import (
	"net"

	"time"

	"zjdns/types"
)

// IsExpired 检查缓存条目是否已过期
func (c *CacheEntry) IsExpired() bool {
	if c == nil {
		return true
	}
	return time.Now().Unix()-c.Timestamp > int64(c.TTL)
}

// IsStale 检查缓存条目是否为陈旧数据
func (c *CacheEntry) IsStale() bool {
	if c == nil {
		return true
	}
	return time.Now().Unix()-c.Timestamp > int64(c.TTL+types.CacheStaleMaxAgeSeconds)
}

// ShouldRefresh 检查缓存条目是否应该刷新
func (c *CacheEntry) ShouldRefresh() bool {
	if c == nil {
		return false
	}

	now := time.Now().Unix()
	refreshInterval := int64(c.OriginalTTL)
	if refreshInterval <= 0 {
		refreshInterval = int64(c.TTL)
	}

	return c.IsExpired() &&
		(now-c.Timestamp) > refreshInterval &&
		(now-c.RefreshTime) > refreshInterval
}

// GetRemainingTTL 获取缓存条目剩余TTL
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
	staleCycle := staleElapsed % int64(types.StaleTTLSeconds)
	staleTTLRemaining := int64(types.StaleTTLSeconds) - staleCycle

	if staleTTLRemaining <= 0 {
		staleTTLRemaining = int64(types.StaleTTLSeconds)
	}

	return uint32(staleTTLRemaining)
}

// GetECSOption 获取缓存条目的ECS选项
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
