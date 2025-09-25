package types

import "time"

// 常量定义
const (
	// Redis配置
	RedisConnectionPoolSize    = 20
	RedisMinIdleConnections    = 5
	RedisMaxRetryAttempts      = 3
	RedisConnectionPoolTimeout = 5 * time.Second
	RedisReadTimeout           = 3 * time.Second
	RedisWriteTimeout          = 3 * time.Second
	RedisDialTimeout           = 5 * time.Second

	// 超时配置
	StandardOperationTimeout = 5 * time.Second

	// 缓存配置
	CacheRefreshQueueSize   = 500
	CacheStaleMaxAgeSeconds = 259200
	StaleTTLSeconds         = 30
)
