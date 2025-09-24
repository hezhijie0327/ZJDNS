package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"

	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/redis/go-redis/v9"
	"github.com/redis/go-redis/v9/hitless"
	"github.com/redis/go-redis/v9/logging"
)

func NewRedisDNSCache(config *ServerConfig, server *RecursiveDNSServer) (*RedisDNSCache, error) {
	// 使用go-redis内置的VoidLogger来禁用日志
	logging.Disable()

	rdb := redis.NewClient(&redis.Options{
		Addr:            config.Redis.Address,
		Password:        config.Redis.Password,
		DB:              config.Redis.Database,
		PoolSize:        RedisConnectionPoolSize,
		MinIdleConns:    RedisMinIdleConnections,
		MaxRetries:      RedisMaxRetryAttempts,
		PoolTimeout:     RedisConnectionPoolTimeout,
		ReadTimeout:     RedisReadTimeout,
		WriteTimeout:    RedisWriteTimeout,
		DialTimeout:     RedisDialTimeout,
		DisableIdentity: true, // 禁用CLIENT SETINFO命令，包括maint_notifications
		HitlessUpgradeConfig: &hitless.Config{
			Mode: hitless.MaintNotificationsDisabled, // 明确禁用维护通知功能
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), StandardOperationTimeout)
	defer cancel()

	if err := rdb.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("💾 Redis连接失败: %w", err)
	}

	cacheCtx, cacheCancel := context.WithCancel(context.Background())
	cache := &RedisDNSCache{
		client:       rdb,
		config:       config,
		keyPrefix:    config.Redis.KeyPrefix,
		refreshQueue: make(chan RefreshRequest, CacheRefreshQueueSize),
		ctx:          cacheCtx,
		cancel:       cacheCancel,
		taskManager:  NewTaskManager(10),
		server:       server,
	}

	if config.Server.Features.ServeStale && config.Server.Features.Prefetch {
		cache.startRefreshProcessor()
	}

	writeLog(LogInfo, "✅ Redis缓存系统初始化完成")
	return cache, nil
}

func (rc *RedisDNSCache) startRefreshProcessor() {
	workerCount := 2

	for i := 0; i < workerCount; i++ {
		rc.wg.Add(1)
		go func(workerID int) {
			defer rc.wg.Done()
			defer func() { handlePanicWithContext(fmt.Sprintf("Redis刷新Worker %d", workerID)) }()

			for {
				select {
				case req := <-rc.refreshQueue:
					rc.handleRefreshRequest(req)
				case <-rc.ctx.Done():
					return
				}
			}
		}(i)
	}
}

func (rc *RedisDNSCache) handleRefreshRequest(req RefreshRequest) {
	defer func() { handlePanicWithContext("Redis刷新请求处理") }()

	if atomic.LoadInt32(&rc.closed) != 0 {
		return
	}

	answer, authority, additional, validated, ecsResponse, err := rc.server.QueryForRefresh(
		req.Question, req.ECS, req.ServerDNSSECEnabled)

	if err != nil {
		rc.updateRefreshTime(req.CacheKey)
		return
	}

	// 对A和AAAA记录进行测速和排序（如果启用了speedtest功能）
	if len(rc.server.config.Speedtest) > 0 && (req.Question.Qtype == dns.TypeA || req.Question.Qtype == dns.TypeAAAA) {
		// 构建临时消息用于测速
		tempMsg := &dns.Msg{
			Answer: answer,
			Ns:     authority,
			Extra:  additional,
		}

		// 执行测速和排序
		speedTester := NewSpeedTester(*rc.server.config)
		speedTester.PerformSpeedTestAndSort(tempMsg)

		// 更新记录
		answer = tempMsg.Answer
		authority = tempMsg.Ns
		additional = tempMsg.Extra
	}

	allRRs := make([]dns.RR, 0, len(answer)+len(authority)+len(additional))
	allRRs = append(allRRs, answer...)
	allRRs = append(allRRs, authority...)
	allRRs = append(allRRs, additional...)

	cacheTTL := globalCacheUtils.CalculateTTL(allRRs)
	now := time.Now().Unix()

	entry := &CacheEntry{
		Answer:      globalRecordHandler.CompactRecords(answer),
		Authority:   globalRecordHandler.CompactRecords(authority),
		Additional:  globalRecordHandler.CompactRecords(additional),
		TTL:         cacheTTL,
		OriginalTTL: cacheTTL,
		Timestamp:   now,
		Validated:   validated,
		AccessTime:  now,
		RefreshTime: now,
	}

	if ecsResponse != nil {
		entry.ECSFamily = ecsResponse.Family
		entry.ECSSourcePrefix = ecsResponse.SourcePrefix
		entry.ECSScopePrefix = ecsResponse.ScopePrefix
		entry.ECSAddress = ecsResponse.Address.String()
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return
	}

	fullKey := rc.keyPrefix + req.CacheKey
	expiration := time.Duration(cacheTTL) * time.Second
	if rc.config.Server.Features.ServeStale {
		expiration += time.Duration(StaleMaxAgeSeconds) * time.Second
	}

	rc.client.Set(rc.ctx, fullKey, data, expiration)
}

func (rc *RedisDNSCache) updateRefreshTime(cacheKey string) {
	defer func() { handlePanicWithContext("更新刷新时间") }()

	if atomic.LoadInt32(&rc.closed) != 0 {
		return
	}

	fullKey := rc.keyPrefix + cacheKey
	data, err := rc.client.Get(rc.ctx, fullKey).Result()
	if err != nil {
		return
	}

	var entry CacheEntry
	if err := json.Unmarshal([]byte(data), &entry); err != nil {
		return
	}

	entry.RefreshTime = time.Now().Unix()

	updatedData, err := json.Marshal(entry)
	if err != nil {
		return
	}

	rc.client.Set(rc.ctx, fullKey, updatedData, redis.KeepTTL)
}

func (rc *RedisDNSCache) Get(key string) (*CacheEntry, bool, bool) {
	defer func() { handlePanicWithContext("Redis缓存获取") }()

	if atomic.LoadInt32(&rc.closed) != 0 {
		return nil, false, false
	}

	fullKey := rc.keyPrefix + key
	data, err := rc.client.Get(rc.ctx, fullKey).Result()
	if err != nil {
		return nil, false, false
	}

	var entry CacheEntry
	if err := json.Unmarshal([]byte(data), &entry); err != nil {
		writeLog(LogDebug, "💥 缓存条目解析失败: %v", err)
		go func() {
			defer func() { handlePanicWithContext("清理损坏缓存") }()
			rc.client.Del(context.Background(), fullKey)
		}()
		return nil, false, false
	}

	// 检查是否需要删除过期缓存
	if entry.IsStale() {
		go func() {
			defer func() { handlePanicWithContext("清理过期缓存") }()
			rc.client.Del(context.Background(), fullKey)
		}()
		return nil, false, false
	}

	entry.AccessTime = time.Now().Unix()
	go func() {
		defer func() { handlePanicWithContext("更新访问时间") }()
		rc.updateAccessInfo(fullKey, &entry)
	}()

	isExpired := entry.IsExpired()

	if !rc.config.Server.Features.ServeStale && isExpired {
		go func() {
			defer func() { handlePanicWithContext("清理过期缓存") }()
			rc.client.Del(context.Background(), fullKey)
		}()
		return nil, false, false
	}

	return &entry, true, isExpired
}

func (rc *RedisDNSCache) Set(key string, answer, authority, additional []dns.RR, validated bool, ecs *ECSOption) {
	defer func() { handlePanicWithContext("Redis缓存设置") }()

	if atomic.LoadInt32(&rc.closed) != 0 {
		return
	}

	allRRs := make([]dns.RR, 0, len(answer)+len(authority)+len(additional))
	allRRs = append(allRRs, answer...)
	allRRs = append(allRRs, authority...)
	allRRs = append(allRRs, additional...)

	cacheTTL := globalCacheUtils.CalculateTTL(allRRs)
	now := time.Now().Unix()

	entry := &CacheEntry{
		Answer:      globalRecordHandler.CompactRecords(answer),
		Authority:   globalRecordHandler.CompactRecords(authority),
		Additional:  globalRecordHandler.CompactRecords(additional),
		TTL:         cacheTTL,
		OriginalTTL: cacheTTL,
		Timestamp:   now,
		Validated:   validated,
		AccessTime:  now,
		RefreshTime: 0,
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

	fullKey := rc.keyPrefix + key
	expiration := time.Duration(cacheTTL) * time.Second
	if rc.config.Server.Features.ServeStale {
		expiration += time.Duration(StaleMaxAgeSeconds) * time.Second
	}

	rc.client.Set(rc.ctx, fullKey, data, expiration)
}

func (rc *RedisDNSCache) updateAccessInfo(fullKey string, entry *CacheEntry) {
	defer func() { handlePanicWithContext("Redis访问信息更新") }()

	if atomic.LoadInt32(&rc.closed) != 0 {
		return
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return
	}
	rc.client.Set(rc.ctx, fullKey, data, redis.KeepTTL)
}

func (rc *RedisDNSCache) RequestRefresh(req RefreshRequest) {
	if atomic.LoadInt32(&rc.closed) != 0 {
		return
	}

	select {
	case rc.refreshQueue <- req:
	default:
	}
}

func (rc *RedisDNSCache) Shutdown() {
	if !atomic.CompareAndSwapInt32(&rc.closed, 0, 1) {
		return
	}

	writeLog(LogInfo, "💾 正在关闭Redis缓存...")

	if err := rc.taskManager.Shutdown(5 * time.Second); err != nil {
		writeLog(LogError, "💥 任务管理器关闭失败: %v", err)
	}

	rc.cancel()
	close(rc.refreshQueue)

	done := make(chan struct{})
	go func() {
		rc.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
	}

	if err := rc.client.Close(); err != nil {
		writeLog(LogError, "💥 Redis客户端关闭失败: %v", err)
	}

	writeLog(LogInfo, "✅ Redis缓存已关闭")
}

func (c *CacheEntry) IsExpired() bool {
	if c == nil {
		return true
	}
	return time.Now().Unix()-c.Timestamp > int64(c.TTL)
}

func (c *CacheEntry) IsStale() bool {
	if c == nil {
		return true
	}
	return time.Now().Unix()-c.Timestamp > int64(c.TTL+StaleMaxAgeSeconds)
}

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
	staleCycle := staleElapsed % int64(StaleTTLSeconds)
	staleTTLRemaining := int64(StaleTTLSeconds) - staleCycle

	if staleTTLRemaining <= 0 {
		staleTTLRemaining = int64(StaleTTLSeconds)
	}

	return uint32(staleTTLRemaining)
}

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
