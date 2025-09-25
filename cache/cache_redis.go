package cache

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

	"zjdns/types"
	"zjdns/utils"
)

// NewRedisDNSCache 创建新的Redis DNS缓存实例
func NewRedisDNSCache(config *types.ServerConfig, server types.RecursiveDNSServer) (*RedisDNSCache, error) {
	// 使用go-redis内置的VoidLogger来禁用日志
	logging.Disable()

	rdb := redis.NewClient(&redis.Options{
		Addr:            config.Redis.Address,
		Password:        config.Redis.Password,
		DB:              config.Redis.Database,
		PoolSize:        types.RedisConnectionPoolSize,
		MinIdleConns:    types.RedisMinIdleConnections,
		MaxRetries:      types.RedisMaxRetryAttempts,
		PoolTimeout:     types.RedisConnectionPoolTimeout,
		ReadTimeout:     types.RedisReadTimeout,
		WriteTimeout:    types.RedisWriteTimeout,
		DialTimeout:     types.RedisDialTimeout,
		DisableIdentity: true, // 禁用CLIENT SETINFO命令，包括maint_notifications
		HitlessUpgradeConfig: &hitless.Config{
			Mode: hitless.MaintNotificationsDisabled, // 明确禁用维护通知功能
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), types.StandardOperationTimeout)
	defer cancel()

	if err := rdb.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("💾 Redis连接失败: %w", err)
	}

	cacheCtx, cacheCancel := context.WithCancel(context.Background())
	cache := &RedisDNSCache{
		client:       rdb,
		config:       config,
		keyPrefix:    config.Redis.KeyPrefix,
		refreshQueue: make(chan RefreshRequest, types.CacheRefreshQueueSize),
		ctx:          cacheCtx,
		cancel:       cacheCancel,
		taskManager:  utils.NewTaskManager(10),
		server:       server,
	}

	if config.Server.Features.ServeStale && config.Server.Features.Prefetch {
		cache.startRefreshProcessor()
	}

	utils.WriteLog(utils.LogInfo, "✅ Redis缓存系统初始化完成")
	return cache, nil
}

// startRefreshProcessor 启动缓存刷新处理器
func (rc *RedisDNSCache) startRefreshProcessor() {
	workerCount := 2

	for i := 0; i < workerCount; i++ {
		rc.wg.Add(1)
		go func(workerID int) {
			defer rc.wg.Done()
			defer func() { utils.HandlePanicWithContext(fmt.Sprintf("Redis刷新Worker %d", workerID)) }()

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

// handleRefreshRequest 处理缓存刷新请求
func (rc *RedisDNSCache) handleRefreshRequest(req RefreshRequest) {
	defer func() { utils.HandlePanicWithContext("Redis刷新请求处理") }()

	if atomic.LoadInt32(&rc.closed) != 0 {
		return
	}

	answer, authority, additional, validated, ecsResponse, err := rc.server.QueryForRefresh(
		req.Question, (*types.ECSOption)(req.ECS), req.ServerDNSSECEnabled)

	if err != nil {
		rc.updateRefreshTime(req.CacheKey)
		return
	}

	// 对A和AAAA记录进行测速和排序（如果启用了speedtest功能）
	if len(rc.server.GetConfig().Speedtest) > 0 && (req.Question.Qtype == dns.TypeA || req.Question.Qtype == dns.TypeAAAA) {
		// 构建临时消息用于测速
		tempMsg := &dns.Msg{
			Answer: answer,
			Ns:     authority,
			Extra:  additional,
		}

		// 执行测速和排序
		speedTester := utils.NewSpeedTester(rc.server.GetConfig().Speedtest)
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

	cacheTTL := utils.GlobalCacheUtils.CalculateTTL(allRRs)
	now := time.Now().Unix()

	// 转换utils.CompactDNSRecord到cache.CompactDNSRecord
	answerRecords := utils.GlobalRecordHandler.CompactRecords(answer)
	authorityRecords := utils.GlobalRecordHandler.CompactRecords(authority)
	additionalRecords := utils.GlobalRecordHandler.CompactRecords(additional)

	answerCacheRecords := make([]*CompactDNSRecord, len(answerRecords))
	authorityCacheRecords := make([]*CompactDNSRecord, len(authorityRecords))
	additionalCacheRecords := make([]*CompactDNSRecord, len(additionalRecords))

	for i, record := range answerRecords {
		answerCacheRecords[i] = &CompactDNSRecord{
			Text:    record.Text,
			OrigTTL: record.OrigTTL,
			Type:    record.Type,
		}
	}

	for i, record := range authorityRecords {
		authorityCacheRecords[i] = &CompactDNSRecord{
			Text:    record.Text,
			OrigTTL: record.OrigTTL,
			Type:    record.Type,
		}
	}

	for i, record := range additionalRecords {
		additionalCacheRecords[i] = &CompactDNSRecord{
			Text:    record.Text,
			OrigTTL: record.OrigTTL,
			Type:    record.Type,
		}
	}

	entry := &CacheEntry{
		Answer:      answerCacheRecords,
		Authority:   authorityCacheRecords,
		Additional:  additionalCacheRecords,
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
		expiration += time.Duration(types.CacheStaleMaxAgeSeconds) * time.Second
	}

	rc.client.Set(rc.ctx, fullKey, data, expiration)
}

// updateRefreshTime 更新缓存刷新时间
func (rc *RedisDNSCache) updateRefreshTime(cacheKey string) {
	defer func() { utils.HandlePanicWithContext("更新刷新时间") }()

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
	defer func() { utils.HandlePanicWithContext("Redis缓存获取") }()

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
		utils.WriteLog(utils.LogDebug, "💥 缓存条目解析失败: %v", err)
		go func() {
			defer func() { utils.HandlePanicWithContext("清理损坏缓存") }()
			rc.client.Del(context.Background(), fullKey)
		}()
		return nil, false, false
	}

	// 检查是否需要删除过期缓存
	if entry.IsStale() {
		go func() {
			defer func() { utils.HandlePanicWithContext("清理过期缓存") }()
			rc.client.Del(context.Background(), fullKey)
		}()
		return nil, false, false
	}

	entry.AccessTime = time.Now().Unix()
	go func() {
		defer func() { utils.HandlePanicWithContext("更新访问时间") }()
		rc.updateAccessInfo(fullKey, &entry)
	}()

	isExpired := entry.IsExpired()

	if !rc.config.Server.Features.ServeStale && isExpired {
		go func() {
			defer func() { utils.HandlePanicWithContext("清理过期缓存") }()
			rc.client.Del(context.Background(), fullKey)
		}()
		return nil, false, false
	}

	return &entry, true, isExpired
}

func (rc *RedisDNSCache) Set(key string, answer, authority, additional []dns.RR, validated bool, ecs *types.ECSOption) {
	defer func() { utils.HandlePanicWithContext("Redis缓存设置") }()

	if atomic.LoadInt32(&rc.closed) != 0 {
		return
	}

	allRRs := make([]dns.RR, 0, len(answer)+len(authority)+len(additional))
	allRRs = append(allRRs, answer...)
	allRRs = append(allRRs, authority...)
	allRRs = append(allRRs, additional...)

	cacheTTL := utils.GlobalCacheUtils.CalculateTTL(allRRs)
	now := time.Now().Unix()

	// 转换utils.CompactDNSRecord到cache.CompactDNSRecord
	answerRecords2 := utils.GlobalRecordHandler.CompactRecords(answer)
	authorityRecords2 := utils.GlobalRecordHandler.CompactRecords(authority)
	additionalRecords2 := utils.GlobalRecordHandler.CompactRecords(additional)

	answerCacheRecords2 := make([]*CompactDNSRecord, len(answerRecords2))
	authorityCacheRecords2 := make([]*CompactDNSRecord, len(authorityRecords2))
	additionalCacheRecords2 := make([]*CompactDNSRecord, len(additionalRecords2))

	for i, record := range answerRecords2 {
		answerCacheRecords2[i] = &CompactDNSRecord{
			Text:    record.Text,
			OrigTTL: record.OrigTTL,
			Type:    record.Type,
		}
	}

	for i, record := range authorityRecords2 {
		authorityCacheRecords2[i] = &CompactDNSRecord{
			Text:    record.Text,
			OrigTTL: record.OrigTTL,
			Type:    record.Type,
		}
	}

	for i, record := range additionalRecords2 {
		additionalCacheRecords2[i] = &CompactDNSRecord{
			Text:    record.Text,
			OrigTTL: record.OrigTTL,
			Type:    record.Type,
		}
	}

	entry := &CacheEntry{
		Answer:      answerCacheRecords2,
		Authority:   authorityCacheRecords2,
		Additional:  additionalCacheRecords2,
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
		expiration += time.Duration(types.CacheStaleMaxAgeSeconds) * time.Second
	}

	rc.client.Set(rc.ctx, fullKey, data, expiration)
}

// updateAccessInfo 更新缓存访问信息
func (rc *RedisDNSCache) updateAccessInfo(fullKey string, entry *CacheEntry) {
	defer func() { utils.HandlePanicWithContext("Redis访问信息更新") }()

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

	utils.WriteLog(utils.LogInfo, "💾 正在关闭Redis缓存...")

	if err := rc.taskManager.Shutdown(5 * time.Second); err != nil {
		utils.WriteLog(utils.LogError, "💥 任务管理器关闭失败: %v", err)
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
		utils.WriteLog(utils.LogError, "💥 Redis客户端关闭失败: %v", err)
	}

	utils.WriteLog(utils.LogInfo, "✅ Redis缓存已关闭")
}

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
