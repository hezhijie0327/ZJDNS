package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/miekg/dns"
)

// 日志级别和颜色定义
type LogLevel int

const (
	LogNone LogLevel = iota - 1
	LogError
	LogWarn
	LogInfo
	LogDebug
)

// ANSI颜色代码
const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorYellow = "\033[33m"
	ColorGreen  = "\033[32m"
	ColorBlue   = "\033[34m"
	ColorGray   = "\033[37m"
)

// 日志配置
type LogConfig struct {
	level     LogLevel
	useColor  bool
	useEmojis bool
}

var logConfig = &LogConfig{
	level:     LogWarn,
	useColor:  true,
	useEmojis: true,
}

var customLogger *log.Logger

func init() {
	customLogger = log.New(os.Stdout, "", 0)
}

func (l LogLevel) String() string {
	configs := []struct {
		name  string
		emoji string
		color string
	}{
		{"NONE", "🔇", ColorGray},
		{"ERROR", "🔥", ColorRed},
		{"WARN", "⚠️", ColorYellow},
		{"INFO", "📋", ColorGreen},
		{"DEBUG", "🔍", ColorBlue},
	}

	index := int(l) + 1
	if index >= 0 && index < len(configs) {
		config := configs[index]
		result := config.name
		if logConfig.useEmojis {
			result = config.emoji + " " + result
		}
		if logConfig.useColor {
			result = config.color + result + ColorReset
		}
		return result
	}
	return "UNKNOWN"
}

func logf(level LogLevel, format string, args ...interface{}) {
	if level <= logConfig.level {
		timestamp := time.Now().Format("15:04:05")
		message := fmt.Sprintf(format, args...)
		logLine := fmt.Sprintf("%s[%s] %s %s", ColorGray, timestamp, level.String(), message)
		if logConfig.useColor {
			logLine += ColorReset
		}
		customLogger.Println(logLine)
	}
}

// 统计信息
type ServerStats struct {
	queries      int64
	cacheHits    int64
	cacheMisses  int64
	errors       int64
	avgQueryTime int64
}

func (s *ServerStats) recordQuery(duration time.Duration, fromCache bool, hasError bool) {
	atomic.AddInt64(&s.queries, 1)
	atomic.StoreInt64(&s.avgQueryTime, duration.Milliseconds())

	if hasError {
		atomic.AddInt64(&s.errors, 1)
	} else if fromCache {
		atomic.AddInt64(&s.cacheHits, 1)
	} else {
		atomic.AddInt64(&s.cacheMisses, 1)
	}
}

func (s *ServerStats) String() string {
	queries := atomic.LoadInt64(&s.queries)
	hits := atomic.LoadInt64(&s.cacheHits)
	errors := atomic.LoadInt64(&s.errors)
	avgTime := atomic.LoadInt64(&s.avgQueryTime)

	var hitRate float64
	if queries > 0 {
		hitRate = float64(hits) / float64(queries) * 100
	}

	return fmt.Sprintf("📊 查询: %d, 缓存命中率: %.1f%%, 错误: %d, 平均耗时: %dms",
		queries, hitRate, errors, avgTime)
}

// 服务器配置结构（完整版）
type ServerConfig struct {
	Network struct {
		Port       string `json:"port"`
		EnableIPv6 bool   `json:"enable_ipv6"`
		DefaultECS string `json:"default_ecs_subnet"`
	} `json:"network"`

	Cache struct {
		MaxSize     int `json:"max_size"`
		DefaultTTL  int `json:"default_ttl"`
		MinTTL      int `json:"min_ttl"`
		MaxTTL      int `json:"max_ttl"`
		NegativeTTL int `json:"negative_ttl"`
	} `json:"cache"`

	DNSSEC struct {
		Enable          bool `json:"enable"`
		ValidateRecords bool `json:"validate_records"`
	} `json:"dnssec"`

	Performance struct {
		MaxConcurrency int `json:"max_concurrency"`
		ConnPoolSize   int `json:"conn_pool_size"`
		QueryTimeout   int `json:"query_timeout"`
		MaxRecursion   int `json:"max_recursion"`
	} `json:"performance"`

	Logging struct {
		Level         string `json:"level"`
		EnableStats   bool   `json:"enable_stats"`
		StatsInterval int    `json:"stats_interval"`
	} `json:"logging"`

	Features struct {
		ServeStale      bool `json:"serve_stale"`
		StaleMaxAge     int  `json:"stale_max_age"`
		StaleTTL        int  `json:"stale_ttl"`
		PrefetchEnabled bool `json:"prefetch_enabled"`
	} `json:"features"`

	Redis struct {
		Address     string `json:"address"`
		Password    string `json:"password"`
		Database    int    `json:"database"`
		PoolSize    int    `json:"pool_size"`
		IdleTimeout int    `json:"idle_timeout"`
		KeyPrefix   string `json:"key_prefix"`
		Compression bool   `json:"compression"`
	} `json:"redis"`
}

// 默认配置
func getDefaultConfig() *ServerConfig {
	config := &ServerConfig{}

	// 网络配置默认值
	config.Network.Port = "53"
	config.Network.EnableIPv6 = false
	config.Network.DefaultECS = ""

	// 缓存配置默认值
	config.Cache.MaxSize = 100000
	config.Cache.DefaultTTL = 3600
	config.Cache.MinTTL = 300
	config.Cache.MaxTTL = 86400
	config.Cache.NegativeTTL = 300

	// DNSSEC配置默认值
	config.DNSSEC.Enable = true
	config.DNSSEC.ValidateRecords = true

	// 性能配置默认值
	config.Performance.MaxConcurrency = 50
	config.Performance.ConnPoolSize = 100
	config.Performance.QueryTimeout = 5
	config.Performance.MaxRecursion = 10

	// 日志配置默认值
	config.Logging.Level = "warn"
	config.Logging.EnableStats = true
	config.Logging.StatsInterval = 300

	// 功能配置默认值
	config.Features.ServeStale = true
	config.Features.StaleMaxAge = 604800
	config.Features.StaleTTL = 30
	config.Features.PrefetchEnabled = true

	// Redis配置默认值
	config.Redis.Address = "localhost:6379"
	config.Redis.Password = ""
	config.Redis.Database = 0
	config.Redis.PoolSize = 20
	config.Redis.IdleTimeout = 300
	config.Redis.KeyPrefix = "dns:"
	config.Redis.Compression = true

	return config
}

// 加载配置文件
func loadConfig(filename string) (*ServerConfig, error) {
	config := getDefaultConfig()

	if filename == "" {
		logf(LogInfo, "📄 使用默认配置")
		return config, nil
	}

	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("读取配置文件失败: %v", err)
	}

	if err := json.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("解析配置文件失败: %v", err)
	}

	logf(LogInfo, "📄 配置文件加载成功: %s", filename)
	return config, nil
}

// 生成示例配置文件
func generateExampleConfig() string {
	config := getDefaultConfig()
	// 设置一些示例值
	config.Network.Port = "53"
	config.Redis.Address = "127.0.0.1:6379"
	config.Redis.Password = ""
	config.Redis.Database = 1
	config.Logging.Level = "info"

	data, _ := json.MarshalIndent(config, "", "  ")
	return string(data)
}

var validLogLevels = map[string]LogLevel{
	"none": LogNone, "error": LogError, "warn": LogWarn, "info": LogInfo, "debug": LogDebug,
}

// 验证配置
func validateConfig(config *ServerConfig) error {
	// 验证日志级别
	if level, ok := validLogLevels[strings.ToLower(config.Logging.Level)]; ok {
		logConfig.level = level
	} else {
		return fmt.Errorf("无效的日志级别: %s", config.Logging.Level)
	}

	// 验证网络配置
	if config.Network.DefaultECS != "" {
		if _, _, err := net.ParseCIDR(config.Network.DefaultECS); err != nil {
			return fmt.Errorf("ECS子网格式错误: %v", err)
		}
	}

	// 验证TTL配置
	if config.Cache.MinTTL > config.Cache.MaxTTL {
		return fmt.Errorf("最小TTL不能大于最大TTL")
	}

	// 验证Redis地址
	if _, _, err := net.SplitHostPort(config.Redis.Address); err != nil {
		return fmt.Errorf("Redis地址格式错误: %v", err)
	}

	// 验证数值范围
	checks := map[string]struct{ value, min, max int }{
		"cache.max_size":        {config.Cache.MaxSize, 1000, 10000000},
		"cache.default_ttl":     {config.Cache.DefaultTTL, 1, 604800},
		"cache.min_ttl":         {config.Cache.MinTTL, 1, 3600},
		"cache.max_ttl":         {config.Cache.MaxTTL, 1, 604800},
		"perf.max_concurrency":  {config.Performance.MaxConcurrency, 1, 1000},
		"perf.conn_pool_size":   {config.Performance.ConnPoolSize, 1, 500},
		"perf.query_timeout":    {config.Performance.QueryTimeout, 1, 30},
		"redis.pool_size":       {config.Redis.PoolSize, 1, 200},
	}

	for field, check := range checks {
		if check.value < check.min || check.value > check.max {
			return fmt.Errorf("%s 必须在 %d-%d 之间", field, check.min, check.max)
		}
	}

	return nil
}

// DNS记录结构
type CompactDNSRecord struct {
	Text    string `json:"text"`
	OrigTTL uint32 `json:"orig_ttl"`
	Type    uint16 `json:"type"`
}

// 对象池
var (
	rrPool = sync.Pool{
		New: func() interface{} { return make([]*CompactDNSRecord, 0, 16) },
	}
	stringPool = sync.Pool{
		New: func() interface{} { return make(map[string]bool, 32) },
	}
)

func compactRR(rr dns.RR) *CompactDNSRecord {
	if rr == nil {
		return nil
	}
	return &CompactDNSRecord{
		Text:    rr.String(),
		OrigTTL: rr.Header().Ttl,
		Type:    rr.Header().Rrtype,
	}
}

func expandRR(cr *CompactDNSRecord) dns.RR {
	if cr == nil || cr.Text == "" {
		return nil
	}
	rr, err := dns.NewRR(cr.Text)
	if err != nil {
		logf(LogDebug, "解析DNS记录失败: %v", err)
		return nil
	}
	return rr
}

func compactRRs(rrs []dns.RR) []*CompactDNSRecord {
	if len(rrs) == 0 {
		return nil
	}

	result := rrPool.Get().([]*CompactDNSRecord)
	result = result[:0]

	seen := stringPool.Get().(map[string]bool)
	defer func() {
		for k := range seen {
			delete(seen, k)
		}
		stringPool.Put(seen)
	}()

	for _, rr := range rrs {
		if rr == nil || rr.Header().Rrtype == dns.TypeOPT {
			continue
		}

		rrText := rr.String()
		if !seen[rrText] {
			seen[rrText] = true
			if cr := compactRR(rr); cr != nil {
				result = append(result, cr)
			}
		}
	}

	if len(result) == 0 {
		rrPool.Put(result)
		return nil
	}

	final := make([]*CompactDNSRecord, len(result))
	copy(final, result)
	rrPool.Put(result)
	return final
}

func expandRRs(crs []*CompactDNSRecord) []dns.RR {
	if len(crs) == 0 {
		return nil
	}
	result := make([]dns.RR, 0, len(crs))
	for _, cr := range crs {
		if rr := expandRR(cr); rr != nil {
			result = append(result, rr)
		}
	}
	return result
}

// Redis缓存条目
type RedisCacheEntry struct {
	Answer      []*CompactDNSRecord `json:"answer"`
	Authority   []*CompactDNSRecord `json:"authority"`
	Additional  []*CompactDNSRecord `json:"additional"`
	TTL         int                 `json:"ttl"`
	Timestamp   int64               `json:"timestamp"`
	Validated   bool                `json:"validated"`
	AccessTime  int64               `json:"access_time"`
	RefreshTime int64               `json:"refresh_time"`
	HitCount    int32               `json:"hit_count"`
}

func (c *RedisCacheEntry) IsExpired() bool {
	return time.Now().Unix()-c.Timestamp > int64(c.TTL)
}

func (c *RedisCacheEntry) IsStale(maxAge int) bool {
	return time.Now().Unix()-c.Timestamp > int64(c.TTL+maxAge)
}

func (c *RedisCacheEntry) ShouldRefresh() bool {
	now := time.Now().Unix()
	return c.IsExpired() && (now-c.Timestamp) > int64(c.TTL+300) && (now-c.RefreshTime) > 600
}

func (c *RedisCacheEntry) GetRemainingTTL(staleTTL int) uint32 {
	remaining := int64(c.TTL) - (time.Now().Unix() - c.Timestamp)
	if remaining <= 0 {
		return uint32(staleTTL)
	}
	return uint32(remaining)
}

func (c *RedisCacheEntry) GetAnswerRRs() []dns.RR     { return expandRRs(c.Answer) }
func (c *RedisCacheEntry) GetAuthorityRRs() []dns.RR  { return expandRRs(c.Authority) }
func (c *RedisCacheEntry) GetAdditionalRRs() []dns.RR { return expandRRs(c.Additional) }

// 刷新请求
type RefreshRequest struct {
	Question dns.Question
	ECS      *ECSOption
	CacheKey string
}

// Redis缓存
type RedisDNSCache struct {
	client       *redis.Client
	config       *ServerConfig
	keyPrefix    string
	refreshQueue chan RefreshRequest
	stats        *CacheStats
}

type CacheStats struct {
	hits, misses, evictions, refreshes, errors int64
}

func (cs *CacheStats) RecordHit()      { atomic.AddInt64(&cs.hits, 1) }
func (cs *CacheStats) RecordMiss()     { atomic.AddInt64(&cs.misses, 1) }
func (cs *CacheStats) RecordEviction() { atomic.AddInt64(&cs.evictions, 1) }
func (cs *CacheStats) RecordRefresh()  { atomic.AddInt64(&cs.refreshes, 1) }
func (cs *CacheStats) RecordError()    { atomic.AddInt64(&cs.errors, 1) }

func NewRedisDNSCache(config *ServerConfig) (*RedisDNSCache, error) {
	rdb := redis.NewClient(&redis.Options{
		Addr:         config.Redis.Address,
		Password:     config.Redis.Password,
		DB:           config.Redis.Database,
		PoolSize:     config.Redis.PoolSize,
		IdleTimeout:  time.Duration(config.Redis.IdleTimeout) * time.Second,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := rdb.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("Redis连接失败: %v", err)
	}

	cache := &RedisDNSCache{
		client:       rdb,
		config:       config,
		keyPrefix:    config.Redis.KeyPrefix,
		refreshQueue: make(chan RefreshRequest, 500),
		stats:        &CacheStats{},
	}

	if config.Features.ServeStale && config.Features.PrefetchEnabled {
		cache.startRefreshProcessor()
	}

	logf(LogInfo, "✅ Redis缓存系统初始化完成")
	return cache, nil
}

func (rc *RedisDNSCache) startRefreshProcessor() {
	for i := 0; i < 3; i++ {
		go func(workerID int) {
			logf(LogDebug, "🔄 Redis后台刷新Worker %d启动", workerID)
			for req := range rc.refreshQueue {
				rc.handleRefreshRequest(req)
			}
		}(i)
	}
}

func (rc *RedisDNSCache) handleRefreshRequest(req RefreshRequest) {
	rc.stats.RecordRefresh()
	logf(LogDebug, "🔄 接收到刷新请求: %s", req.CacheKey)
}

func (rc *RedisDNSCache) Get(key string) (*RedisCacheEntry, bool, bool) {
	ctx := context.Background()
	fullKey := rc.keyPrefix + key

	data, err := rc.client.Get(ctx, fullKey).Result()
	if err != nil {
		if err == redis.Nil {
			rc.stats.RecordMiss()
			return nil, false, false
		}
		rc.stats.RecordError()
		logf(LogWarn, "Redis获取失败: %v", err)
		return nil, false, false
	}

	var entry RedisCacheEntry
	if err := json.Unmarshal([]byte(data), &entry); err != nil {
		rc.stats.RecordError()
		logf(LogWarn, "Redis数据解析失败: %v", err)
		return nil, false, false
	}

	now := time.Now().Unix()

	if rc.config.Features.ServeStale &&
		now-entry.Timestamp > int64(entry.TTL+rc.config.Features.StaleMaxAge) {
		rc.stats.RecordMiss()
		go rc.removeStaleEntry(fullKey)
		return nil, false, false
	}

	entry.AccessTime = now
	entry.HitCount++
	go rc.updateAccessInfo(fullKey, &entry)

	rc.stats.RecordHit()
	isExpired := entry.IsExpired()

	if !rc.config.Features.ServeStale && isExpired {
		go rc.removeStaleEntry(fullKey)
		return nil, false, false
	}

	return &entry, true, isExpired
}

func (rc *RedisDNSCache) Set(key string, answer, authority, additional []dns.RR, validated bool) {
	minTTL := rc.config.Cache.DefaultTTL

	for _, rrs := range [][]dns.RR{answer, authority, additional} {
		for _, rr := range rrs {
			if ttl := int(rr.Header().Ttl); ttl > 0 && ttl < minTTL {
				minTTL = ttl
			}
		}
	}

	if minTTL < rc.config.Cache.MinTTL {
		minTTL = rc.config.Cache.MinTTL
	} else if minTTL > rc.config.Cache.MaxTTL {
		minTTL = rc.config.Cache.MaxTTL
	}

	now := time.Now().Unix()
	entry := &RedisCacheEntry{
		Answer:      compactRRs(answer),
		Authority:   compactRRs(authority),
		Additional:  compactRRs(additional),
		TTL:         minTTL,
		Timestamp:   now,
		Validated:   validated,
		AccessTime:  now,
		RefreshTime: 0,
		HitCount:    0,
	}

	data, err := json.Marshal(entry)
	if err != nil {
		rc.stats.RecordError()
		logf(LogWarn, "Redis数据序列化失败: %v", err)
		return
	}

	ctx := context.Background()
	fullKey := rc.keyPrefix + key

	expiration := time.Duration(minTTL) * time.Second
	if rc.config.Features.ServeStale {
		expiration += time.Duration(rc.config.Features.StaleMaxAge) * time.Second
	}

	if err := rc.client.Set(ctx, fullKey, data, expiration).Err(); err != nil {
		rc.stats.RecordError()
		logf(LogWarn, "Redis设置失败: %v", err)
		return
	}

	validatedStr := ""
	if validated {
		validatedStr = " 🔐"
	}
	logf(LogDebug, "💾 Redis缓存记录: %s (TTL: %ds, 答案: %d条)%s", key, minTTL, len(answer), validatedStr)
}

func (rc *RedisDNSCache) updateAccessInfo(fullKey string, entry *RedisCacheEntry) {
	data, err := json.Marshal(entry)
	if err != nil {
		return
	}
	ctx := context.Background()
	rc.client.Set(ctx, fullKey, data, redis.KeepTTL)
}

func (rc *RedisDNSCache) removeStaleEntry(fullKey string) {
	ctx := context.Background()
	if err := rc.client.Del(ctx, fullKey).Err(); err != nil {
		rc.stats.RecordError()
		logf(LogDebug, "Redis删除过期条目失败: %v", err)
	} else {
		rc.stats.RecordEviction()
	}
}

func (rc *RedisDNSCache) UpdateRefreshTime(key string) {
	ctx := context.Background()
	fullKey := rc.keyPrefix + key

	data, err := rc.client.Get(ctx, fullKey).Result()
	if err != nil {
		return
	}

	var entry RedisCacheEntry
	if err := json.Unmarshal([]byte(data), &entry); err != nil {
		return
	}

	entry.RefreshTime = time.Now().Unix()
	if newData, err := json.Marshal(entry); err == nil {
		rc.client.Set(ctx, fullKey, newData, redis.KeepTTL)
	}
}

func (rc *RedisDNSCache) RequestRefresh(req RefreshRequest) {
	rc.stats.RecordRefresh()
	select {
	case rc.refreshQueue <- req:
	default:
		logf(LogDebug, "刷新队列已满，跳过刷新请求")
	}
}

func (rc *RedisDNSCache) Shutdown() {
	logf(LogInfo, "🛑 正在关闭Redis缓存系统...")
	close(rc.refreshQueue)
	if err := rc.client.Close(); err != nil {
		logf(LogWarn, "Redis关闭失败: %v", err)
	} else {
		logf(LogInfo, "✅ Redis缓存系统已安全关闭")
	}
}

func (rc *RedisDNSCache) GetStats() *CacheStats {
	return rc.stats
}

// 工具函数
func adjustTTL(rrs []dns.RR, ttl uint32) []dns.RR {
	if len(rrs) == 0 {
		return nil
	}
	result := make([]dns.RR, len(rrs))
	for i, rr := range rrs {
		result[i] = dns.Copy(rr)
		result[i].Header().Ttl = ttl
	}
	return result
}

func filterDNSSECRecords(rrs []dns.RR, includeDNSSEC bool) []dns.RR {
	if includeDNSSEC || len(rrs) == 0 {
		return rrs
	}

	filtered := make([]dns.RR, 0, len(rrs))
	for _, rr := range rrs {
		switch rr.(type) {
		case *dns.RRSIG, *dns.NSEC, *dns.NSEC3, *dns.DNSKEY, *dns.DS:
			// 跳过DNSSEC记录
		default:
			filtered = append(filtered, rr)
		}
	}
	return filtered
}

// ECS选项
type ECSOption struct {
	Family       uint16
	SourcePrefix uint8
	Address      net.IP
}

func ParseECS(opt *dns.EDNS0_SUBNET) *ECSOption {
	if opt == nil {
		return nil
	}
	return &ECSOption{
		Family:       opt.Family,
		SourcePrefix: opt.SourceNetmask,
		Address:      opt.Address,
	}
}

func parseDefaultECS(subnet string) (*ECSOption, error) {
	if subnet == "" {
		return nil, nil
	}

	_, ipNet, err := net.ParseCIDR(subnet)
	if err != nil {
		return nil, fmt.Errorf("解析CIDR失败: %v", err)
	}

	prefix, _ := ipNet.Mask.Size()
	family := uint16(1)
	if ipNet.IP.To4() == nil {
		family = 2
	}

	return &ECSOption{
		Family:       family,
		SourcePrefix: uint8(prefix),
		Address:      ipNet.IP,
	}, nil
}

// DNSSEC验证器
type DNSSECValidator struct{}

func NewDNSSECValidator() *DNSSECValidator {
	return &DNSSECValidator{}
}

func (v *DNSSECValidator) HasDNSSECRecords(response *dns.Msg) bool {
	for _, sections := range [][]dns.RR{response.Answer, response.Ns, response.Extra} {
		for _, rr := range sections {
			switch rr.(type) {
			case *dns.RRSIG, *dns.NSEC, *dns.NSEC3:
				logf(LogDebug, "🔐 发现DNSSEC记录")
				return true
			}
		}
	}
	return false
}

// 连接池
type ConnectionPool struct {
	clients []*dns.Client
	pool    chan *dns.Client
	timeout time.Duration
}

func NewConnectionPool(size int, timeout time.Duration) *ConnectionPool {
	pool := &ConnectionPool{
		clients: make([]*dns.Client, 0, size),
		pool:    make(chan *dns.Client, size),
		timeout: timeout,
	}

	for i := 0; i < size; i++ {
		client := &dns.Client{Timeout: timeout, Net: "udp"}
		pool.clients = append(pool.clients, client)
		pool.pool <- client
	}

	logf(LogDebug, "🏊 连接池初始化完成: %d个连接", size)
	return pool
}

func (cp *ConnectionPool) Get() *dns.Client {
	select {
	case client := <-cp.pool:
		return client
	default:
		return &dns.Client{Timeout: cp.timeout, Net: "udp"}
	}
}

func (cp *ConnectionPool) Put(client *dns.Client) {
	select {
	case cp.pool <- client:
	default:
		// 池满时丢弃
	}
}

// 查询结果
type QueryResult struct {
	Response *dns.Msg
	Server   string
	Error    error
	Duration time.Duration
}

// 主服务器
type RecursiveDNSServer struct {
	config           *ServerConfig
	cache            *RedisDNSCache
	rootServersV4    []string
	rootServersV6    []string
	connPool         *ConnectionPool
	dnssecVal        *DNSSECValidator
	defaultECS       *ECSOption
	stats            *ServerStats
	concurrencyLimit chan struct{}
}

func NewRecursiveDNSServer(config *ServerConfig) (*RecursiveDNSServer, error) {
	rootServersV4 := []string{
		"198.41.0.4:53", "170.247.170.2:53", "192.33.4.12:53", "199.7.91.13:53",
		"192.203.230.10:53", "192.5.5.241:53", "192.112.36.4:53", "198.97.190.53:53",
		"192.36.148.17:53", "192.58.128.30:53", "193.0.14.129:53", "199.7.83.42:53",
		"202.12.27.33:53",
	}

	rootServersV6 := []string{
		"[2001:503:ba3e::2:30]:53", "[2801:1b8:10::b]:53", "[2001:500:2::c]:53",
		"[2001:500:2d::d]:53", "[2001:500:a8::e]:53", "[2001:500:2f::f]:53",
		"[2001:500:12::d0d]:53", "[2001:500:1::53]:53", "[2001:7fe::53]:53",
		"[2001:503:c27::2:30]:53", "[2001:7fd::1]:53", "[2001:500:9f::42]:53",
		"[2001:dc3::35]:53",
	}

	defaultECS, err := parseDefaultECS(config.Network.DefaultECS)
	if err != nil {
		return nil, fmt.Errorf("ECS配置错误: %v", err)
	}

	cache, err := NewRedisDNSCache(config)
	if err != nil {
		return nil, fmt.Errorf("Redis缓存初始化失败: %v", err)
	}

	server := &RecursiveDNSServer{
		config:           config,
		cache:            cache,
		rootServersV4:    rootServersV4,
		rootServersV6:    rootServersV6,
		connPool:         NewConnectionPool(config.Performance.ConnPoolSize, time.Duration(config.Performance.QueryTimeout)*time.Second),
		dnssecVal:        NewDNSSECValidator(),
		defaultECS:       defaultECS,
		stats:            &ServerStats{},
		concurrencyLimit: make(chan struct{}, config.Performance.MaxConcurrency),
	}

	if config.Features.ServeStale && config.Features.PrefetchEnabled {
		server.startRefreshProcessor()
	}

	if config.Logging.EnableStats {
		server.startStatsReporter(time.Duration(config.Logging.StatsInterval) * time.Second)
	}

	server.setupSignalHandling()
	return server, nil
}

func (r *RecursiveDNSServer) startStatsReporter(interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for range ticker.C {
			logf(LogInfo, r.stats.String())

			cacheStats := r.cache.GetStats()
			hits := atomic.LoadInt64(&cacheStats.hits)
			misses := atomic.LoadInt64(&cacheStats.misses)
			evictions := atomic.LoadInt64(&cacheStats.evictions)
			refreshes := atomic.LoadInt64(&cacheStats.refreshes)
			errors := atomic.LoadInt64(&cacheStats.errors)

			var hitRate float64
			if hits+misses > 0 {
				hitRate = float64(hits) / float64(hits+misses) * 100
			}

			logf(LogInfo, "💾 Redis缓存状态: 命中率=%.1f%%, 淘汰=%d, 刷新=%d, 错误=%d",
				hitRate, evictions, refreshes, errors)
		}
	}()
}

func (r *RecursiveDNSServer) startRefreshProcessor() {
	for i := 0; i < 3; i++ {
		go func(workerID int) {
			logf(LogDebug, "🔄 后台刷新Worker %d启动", workerID)
			for req := range r.cache.refreshQueue {
				r.handleRefreshRequest(req)
			}
		}(i)
	}
}

func (r *RecursiveDNSServer) handleRefreshRequest(req RefreshRequest) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	logf(LogDebug, "🔄 后台刷新: %s %s", dns.TypeToString[req.Question.Qtype], req.Question.Name)

	r.cache.UpdateRefreshTime(req.CacheKey)

	answer, authority, additional, validated, err := r.resolveWithCNAME(ctx, req.Question, req.ECS)
	if err != nil {
		logf(LogWarn, "后台刷新失败 %s: %v", req.Question.Name, err)
		return
	}

	r.cache.Set(req.CacheKey, answer, authority, additional, validated)
	logf(LogDebug, "✅ 后台刷新成功: %s", req.CacheKey)
}

func (r *RecursiveDNSServer) setupSignalHandling() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigChan
		logf(LogInfo, "🛑 收到信号 %v，开始优雅关闭...", sig)
		logf(LogInfo, "📊 最终统计: %s", r.stats.String())
		r.cache.Shutdown()
		os.Exit(0)
	}()
}

func (r *RecursiveDNSServer) getRootServers() []string {
	if r.config.Network.EnableIPv6 {
		mixed := make([]string, 0, len(r.rootServersV4)+len(r.rootServersV6))
		mixed = append(mixed, r.rootServersV4...)
		mixed = append(mixed, r.rootServersV6...)
		return mixed
	}
	return r.rootServersV4
}

func (r *RecursiveDNSServer) Start() error {
	var wg sync.WaitGroup
	errChan := make(chan error, 2)

	logf(LogInfo, "🚀 启动高性能DNS服务器 v2.1")
	logf(LogInfo, "🌐 监听端口: %s", r.config.Network.Port)
	logf(LogInfo, "💾 Redis缓存: %s", r.config.Redis.Address)
	logf(LogInfo, "⚡ 最大并发: %d", r.config.Performance.MaxConcurrency)
	logf(LogInfo, "🏊 连接池大小: %d", r.config.Performance.ConnPoolSize)

	if r.config.Network.EnableIPv6 {
		logf(LogInfo, "🔗 IPv6支持: 启用")
	}
	if r.config.Features.ServeStale {
		logf(LogInfo, "⏰ 过期缓存服务: 启用 (TTL: %ds, 最大保留: %ds)",
			r.config.Features.StaleTTL, r.config.Features.StaleMaxAge)
	}
	if r.defaultECS != nil {
		logf(LogInfo, "🌍 默认ECS: %s/%d", r.defaultECS.Address, r.defaultECS.SourcePrefix)
	}

	wg.Add(2)

	// UDP服务器
	go func() {
		defer wg.Done()
		server := &dns.Server{
			Addr:    ":" + r.config.Network.Port,
			Net:     "udp",
			Handler: dns.HandlerFunc(r.handleDNSRequest),
		}
		logf(LogInfo, "📡 UDP服务器启动中...")
		if err := server.ListenAndServe(); err != nil {
			errChan <- fmt.Errorf("UDP启动失败: %v", err)
		}
	}()

	// TCP服务器
	go func() {
		defer wg.Done()
		server := &dns.Server{
			Addr:    ":" + r.config.Network.Port,
			Net:     "tcp",
			Handler: dns.HandlerFunc(r.handleDNSRequest),
		}
		logf(LogInfo, "🔌 TCP服务器启动中...")
		if err := server.ListenAndServe(); err != nil {
			errChan <- fmt.Errorf("TCP启动失败: %v", err)
		}
	}()

	time.Sleep(100 * time.Millisecond)
	logf(LogInfo, "✅ DNS服务器启动完成！")

	go func() {
		wg.Wait()
		close(errChan)
	}()

	for err := range errChan {
		if err != nil {
			return err
		}
	}

	select {}
}

func (r *RecursiveDNSServer) handleDNSRequest(w dns.ResponseWriter, req *dns.Msg) {
	start := time.Now()
	response := r.processDNSQuery(req, getClientIP(w))
	duration := time.Since(start)

	fromCache := response.Rcode == dns.RcodeSuccess && len(response.Answer) > 0
	hasError := response.Rcode != dns.RcodeSuccess
	r.stats.recordQuery(duration, fromCache, hasError)

	w.WriteMsg(response)
}

func (r *RecursiveDNSServer) processDNSQuery(req *dns.Msg, clientIP net.IP) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetReply(req)
	msg.Authoritative = false
	msg.RecursionAvailable = true

	if len(req.Question) == 0 {
		msg.Rcode = dns.RcodeFormatError
		return msg
	}

	question := req.Question[0]
	dnssecOK := false
	var ecsOpt *ECSOption

	if opt := req.IsEdns0(); opt != nil {
		dnssecOK = opt.Do()
		for _, option := range opt.Option {
			if subnet, ok := option.(*dns.EDNS0_SUBNET); ok {
				ecsOpt = ParseECS(subnet)
				logf(LogDebug, "🌍 客户端ECS: %s/%d", ecsOpt.Address, ecsOpt.SourcePrefix)
				break
			}
		}
	}

	if ecsOpt == nil && r.defaultECS != nil {
		ecsOpt = r.defaultECS
		logf(LogDebug, "🌍 使用默认ECS: %s/%d", ecsOpt.Address, ecsOpt.SourcePrefix)
	}

	cacheKey := r.buildCacheKey(question, ecsOpt, dnssecOK)

	if entry, found, isExpired := r.cache.Get(cacheKey); found {
		if isExpired {
			logf(LogDebug, "💾 缓存命中(过期): %s %s", question.Name, dns.TypeToString[question.Qtype])
		} else {
			logf(LogDebug, "💾 缓存命中: %s %s", question.Name, dns.TypeToString[question.Qtype])
		}

		responseTTL := entry.GetRemainingTTL(r.config.Features.StaleTTL)

		msg.Answer = adjustTTL(filterDNSSECRecords(entry.GetAnswerRRs(), dnssecOK), responseTTL)
		msg.Ns = adjustTTL(filterDNSSECRecords(entry.GetAuthorityRRs(), dnssecOK), responseTTL)
		msg.Extra = adjustTTL(filterDNSSECRecords(entry.GetAdditionalRRs(), dnssecOK), responseTTL)

		if isExpired && r.config.Features.ServeStale && r.config.Features.PrefetchEnabled && entry.ShouldRefresh() {
			r.cache.RequestRefresh(RefreshRequest{
				Question: question,
				ECS:      ecsOpt,
				CacheKey: cacheKey,
			})
		}

		if dnssecOK {
			if opt := msg.IsEdns0(); opt != nil {
				opt.SetDo(true)
			} else {
				opt := new(dns.OPT)
				opt.Hdr.Name = "."
				opt.Hdr.Rrtype = dns.TypeOPT
				opt.SetDo(true)
				msg.Extra = append(msg.Extra, opt)
			}

			if entry.Validated {
				msg.AuthenticatedData = true
			}
		}

		return msg
	}

	logf(LogInfo, "🔍 递归解析: %s %s", dns.TypeToString[question.Qtype], question.Name)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	answer, authority, additional, validated, err := r.resolveWithCNAME(ctx, question, ecsOpt)
	if err != nil {
		logf(LogWarn, "查询失败: %v", err)

		// Serve-Stale fallback
		if r.config.Features.ServeStale {
			if entry, found, _ := r.cache.Get(cacheKey); found {
				logf(LogInfo, "⏰ 使用过期缓存回退: %s %s", question.Name, dns.TypeToString[question.Qtype])

				responseTTL := uint32(r.config.Features.StaleTTL)
				msg.Answer = adjustTTL(filterDNSSECRecords(entry.GetAnswerRRs(), dnssecOK), responseTTL)
				msg.Ns = adjustTTL(filterDNSSECRecords(entry.GetAuthorityRRs(), dnssecOK), responseTTL)
				msg.Extra = adjustTTL(filterDNSSECRecords(entry.GetAdditionalRRs(), dnssecOK), responseTTL)

				if dnssecOK {
					if opt := msg.IsEdns0(); opt != nil {
						opt.SetDo(true)
					} else {
						opt := new(dns.OPT)
						opt.Hdr.Name = "."
						opt.Hdr.Rrtype = dns.TypeOPT
						opt.SetDo(true)
						msg.Extra = append(msg.Extra, opt)
					}

					if entry.Validated {
						msg.AuthenticatedData = true
					}
				}

				return msg
			}
		}

		msg.Rcode = dns.RcodeServerFailure
		return msg
	}

	r.cache.Set(cacheKey, answer, authority, additional, validated)

	msg.Answer = filterDNSSECRecords(answer, dnssecOK)
	msg.Ns = filterDNSSECRecords(authority, dnssecOK)
	msg.Extra = filterDNSSECRecords(additional, dnssecOK)

	if dnssecOK {
		if opt := msg.IsEdns0(); opt != nil {
			opt.SetDo(true)
		} else {
			opt := new(dns.OPT)
			opt.Hdr.Name = "."
			opt.Hdr.Rrtype = dns.TypeOPT
			opt.SetDo(true)
			msg.Extra = append(msg.Extra, opt)
		}

		if validated {
			msg.AuthenticatedData = true
		}
	}

	return msg
}

func (r *RecursiveDNSServer) resolveWithCNAME(ctx context.Context, question dns.Question, ecs *ECSOption) ([]dns.RR, []dns.RR, []dns.RR, bool, error) {
	var allAnswers []dns.RR
	var finalAuthority, finalAdditional []dns.RR
	allValidated := true

	currentQuestion := question
	visitedCNAMEs := make(map[string]bool, 10)

	for i := 0; i < 10; i++ {
		select {
		case <-ctx.Done():
			return nil, nil, nil, false, ctx.Err()
		default:
		}

		currentName := strings.ToLower(currentQuestion.Name)
		if visitedCNAMEs[currentName] {
			return nil, nil, nil, false, fmt.Errorf("CNAME循环检测: %s", currentName)
		}
		visitedCNAMEs[currentName] = true

		answer, authority, additional, validated, err := r.recursiveQuery(ctx, currentQuestion, ecs, 0)
		if err != nil {
			return nil, nil, nil, false, err
		}

		if !validated {
			allValidated = false
		}

		allAnswers = append(allAnswers, answer...)
		finalAuthority = authority
		finalAdditional = additional

		var nextCNAME *dns.CNAME
		hasTargetType := false

		for _, rr := range answer {
			if cname, ok := rr.(*dns.CNAME); ok {
				if strings.EqualFold(rr.Header().Name, currentQuestion.Name) {
					nextCNAME = cname
					logf(LogDebug, "🔄 发现CNAME: %s -> %s", currentQuestion.Name, cname.Target)
				}
			} else if rr.Header().Rrtype == currentQuestion.Qtype {
				hasTargetType = true
			}
		}

		if hasTargetType || currentQuestion.Qtype == dns.TypeCNAME || nextCNAME == nil {
			break
		}

		currentQuestion = dns.Question{
			Name:   nextCNAME.Target,
			Qtype:  question.Qtype,
			Qclass: question.Qclass,
		}
	}

	return allAnswers, finalAuthority, finalAdditional, allValidated, nil
}

func (r *RecursiveDNSServer) recursiveQuery(ctx context.Context, question dns.Question, ecs *ECSOption, depth int) ([]dns.RR, []dns.RR, []dns.RR, bool, error) {
	if depth > r.config.Performance.MaxRecursion {
		return nil, nil, nil, false, fmt.Errorf("递归深度超限: %d", depth)
	}

	qname := dns.Fqdn(question.Name)
	question.Name = qname
	nameservers := r.getRootServers()
	currentDomain := "."

	for {
		select {
		case <-ctx.Done():
			return nil, nil, nil, false, ctx.Err()
		default:
		}

		logf(LogDebug, "🔍 查询域 %s，使用NS: %v", currentDomain, nameservers)

		response, err := r.queryNameserversConcurrent(ctx, nameservers, question, ecs)
		if err != nil {
			return nil, nil, nil, false, fmt.Errorf("查询%s失败: %v", currentDomain, err)
		}

		validated := r.dnssecVal.HasDNSSECRecords(response)

		if len(response.Answer) > 0 {
			logf(LogDebug, "✅ 找到答案: %d条记录", len(response.Answer))
			return response.Answer, response.Ns, response.Extra, validated, nil
		}

		bestMatch := ""
		var bestNSRecords []*dns.NS

		for _, rr := range response.Ns {
			if ns, ok := rr.(*dns.NS); ok {
				nsName := strings.ToLower(strings.TrimSuffix(rr.Header().Name, "."))
				qnameNoRoot := strings.ToLower(strings.TrimSuffix(qname, "."))

				if qnameNoRoot == nsName || strings.HasSuffix(qnameNoRoot, "."+nsName) {
					if len(nsName) > len(bestMatch) {
						bestMatch = nsName
						bestNSRecords = []*dns.NS{ns}
					} else if len(nsName) == len(bestMatch) {
						bestNSRecords = append(bestNSRecords, ns)
					}
				}
			}
		}

		if len(bestNSRecords) == 0 {
			return nil, nil, nil, false, fmt.Errorf("未找到适当的NS记录")
		}

		if bestMatch == strings.TrimSuffix(currentDomain, ".") {
			return nil, nil, nil, false, fmt.Errorf("检测到递归循环: %s", bestMatch)
		}

		currentDomain = bestMatch + "."
		var nextNS []string

		for _, ns := range bestNSRecords {
			for _, rr := range response.Extra {
				switch a := rr.(type) {
				case *dns.A:
					if strings.EqualFold(a.Header().Name, ns.Ns) {
						nextNS = append(nextNS, net.JoinHostPort(a.A.String(), "53"))
					}
				case *dns.AAAA:
					if r.config.Network.EnableIPv6 && strings.EqualFold(a.Header().Name, ns.Ns) {
						nextNS = append(nextNS, net.JoinHostPort(a.AAAA.String(), "53"))
					}
				}
			}
		}

		if len(nextNS) == 0 {
			nextNS = r.resolveNSAddressesConcurrent(ctx, bestNSRecords, qname, depth)
		}

		if len(nextNS) == 0 {
			return nil, nil, nil, false, fmt.Errorf("无法解析NS地址")
		}

		logf(LogDebug, "🔄 切换到NS: %v", nextNS)
		nameservers = nextNS
	}
}

func (r *RecursiveDNSServer) queryNameserversConcurrent(ctx context.Context, nameservers []string, question dns.Question, ecs *ECSOption) (*dns.Msg, error) {
	if len(nameservers) == 0 {
		return nil, fmt.Errorf("没有可用的nameserver")
	}

	select {
	case r.concurrencyLimit <- struct{}{}:
		defer func() { <-r.concurrencyLimit }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	concurrency := len(nameservers)
	if concurrency > 5 {
		concurrency = 5
	}

	resultChan := make(chan QueryResult, concurrency)
	queryTimeout := time.Duration(r.config.Performance.QueryTimeout) * time.Second
	queryCtx, queryCancel := context.WithTimeout(ctx, queryTimeout)
	defer queryCancel()

	for i := 0; i < concurrency && i < len(nameservers); i++ {
		go func(ns string) {
			start := time.Now()
			client := r.connPool.Get()
			defer r.connPool.Put(client)

			msg := new(dns.Msg)
			msg.SetQuestion(question.Name, question.Qtype)
			msg.RecursionDesired = false

			opt := &dns.OPT{
				Hdr: dns.RR_Header{
					Name:   ".",
					Rrtype: dns.TypeOPT,
					Class:  1232,
				},
			}
			if r.config.DNSSEC.Enable {
				opt.SetDo(true)
			}

			if ecs != nil {
				ecsOption := &dns.EDNS0_SUBNET{
					Code:          dns.EDNS0SUBNET,
					Family:        ecs.Family,
					SourceNetmask: ecs.SourcePrefix,
					SourceScope:   0,
					Address:       ecs.Address,
				}
				opt.Option = append(opt.Option, ecsOption)
			}

			msg.Extra = append(msg.Extra, opt)

			response, _, err := client.ExchangeContext(queryCtx, msg, ns)
			duration := time.Since(start)

			resultChan <- QueryResult{
				Response: response,
				Server:   ns,
				Error:    err,
				Duration: duration,
			}
		}(nameservers[i])
	}

	for i := 0; i < concurrency; i++ {
		select {
		case result := <-resultChan:
			if result.Error != nil {
				logf(LogDebug, "查询%s失败: %v (%v)", result.Server, result.Error, result.Duration)
				continue
			}

			if result.Response.Rcode == dns.RcodeSuccess || result.Response.Rcode == dns.RcodeNameError {
				logf(LogDebug, "✅ 查询%s成功 (%v)", result.Server, result.Duration)
				return result.Response, nil
			}

			logf(LogDebug, "⚠️ 查询%s返回: %s (%v)", result.Server, dns.RcodeToString[result.Response.Rcode], result.Duration)

		case <-queryCtx.Done():
			return nil, fmt.Errorf("查询超时")
		}
	}

	return nil, fmt.Errorf("所有nameserver查询失败")
}

func (r *RecursiveDNSServer) resolveNSAddressesConcurrent(ctx context.Context, nsRecords []*dns.NS, qname string, depth int) []string {
	var nextNS []string
	nsChan := make(chan []string, len(nsRecords))

	resolveCount := len(nsRecords)
	if resolveCount > 3 {
		resolveCount = 3
	}

	for i := 0; i < resolveCount; i++ {
		go func(ns *dns.NS) {
			defer func() { nsChan <- nil }()

			if strings.EqualFold(strings.TrimSuffix(ns.Ns, "."), strings.TrimSuffix(qname, ".")) {
				return
			}

			var addresses []string

			nsQuestion := dns.Question{Name: dns.Fqdn(ns.Ns), Qtype: dns.TypeA, Qclass: dns.ClassINET}
			if nsAnswer, _, _, _, err := r.recursiveQuery(ctx, nsQuestion, nil, depth+1); err == nil {
				for _, rr := range nsAnswer {
					if a, ok := rr.(*dns.A); ok {
						addresses = append(addresses, net.JoinHostPort(a.A.String(), "53"))
					}
				}
			}

			if r.config.Network.EnableIPv6 && len(addresses) == 0 {
				nsQuestionV6 := dns.Question{Name: dns.Fqdn(ns.Ns), Qtype: dns.TypeAAAA, Qclass: dns.ClassINET}
				if nsAnswerV6, _, _, _, err := r.recursiveQuery(ctx, nsQuestionV6, nil, depth+1); err == nil {
					for _, rr := range nsAnswerV6 {
						if aaaa, ok := rr.(*dns.AAAA); ok {
							addresses = append(addresses, net.JoinHostPort(aaaa.AAAA.String(), "53"))
						}
					}
				}
			}

			nsChan <- addresses
		}(nsRecords[i])
	}

	for i := 0; i < resolveCount; i++ {
		select {
		case addresses := <-nsChan:
			if len(addresses) > 0 {
				nextNS = append(nextNS, addresses...)
				if len(nextNS) >= 3 {
					return nextNS
				}
			}
		case <-ctx.Done():
			return nextNS
		case <-time.After(3 * time.Second):
			logf(LogDebug, "⏰ NS解析超时")
			return nextNS
		}
	}

	return nextNS
}

func getClientIP(w dns.ResponseWriter) net.IP {
	if addr := w.RemoteAddr(); addr != nil {
		if udpAddr, ok := addr.(*net.UDPAddr); ok {
			return udpAddr.IP
		}
		if tcpAddr, ok := addr.(*net.TCPAddr); ok {
			return tcpAddr.IP
		}
	}
	return nil
}

func (r *RecursiveDNSServer) buildCacheKey(q dns.Question, ecs *ECSOption, dnssecOK bool) string {
	key := fmt.Sprintf("%s:%d:%d", strings.ToLower(q.Name), q.Qtype, q.Qclass)
	if ecs != nil {
		key += fmt.Sprintf(":%s/%d", ecs.Address.String(), ecs.SourcePrefix)
	}
	if dnssecOK {
		key += ":dnssec"
	}
	return key
}

func main() {
	var configFile string
	var generateConfig bool

	flag.StringVar(&configFile, "config", "", "配置文件路径 (JSON格式)")
	flag.BoolVar(&generateConfig, "generate-config", false, "生成示例配置文件")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "🚀 ZJDNS Server v2.1 - 高性能递归DNS服务器\n\n")
		fmt.Fprintf(os.Stderr, "用法:\n")
		fmt.Fprintf(os.Stderr, "  %s -config <配置文件>     # 使用配置文件启动\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -generate-config       # 生成示例配置文件\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s                         # 使用默认配置启动\n\n", os.Args[0])

		fmt.Fprintf(os.Stderr, "选项:\n")
		fmt.Fprintf(os.Stderr, "  -config string            配置文件路径 (JSON格式)\n")
		fmt.Fprintf(os.Stderr, "  -generate-config          生成示例配置文件到标准输出\n")
		fmt.Fprintf(os.Stderr, "  -h, -help                 显示此帮助信息\n\n")

		fmt.Fprintf(os.Stderr, "示例:\n")
		fmt.Fprintf(os.Stderr, "  # 生成配置文件\n")
		fmt.Fprintf(os.Stderr, "  %s -generate-config > config.json\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  # 使用配置文件启动\n")
		fmt.Fprintf(os.Stderr, "  %s -config config.json\n\n", os.Args[0])
	}

	flag.Parse()

	if generateConfig {
		fmt.Println(generateExampleConfig())
		return
	}

	config, err := loadConfig(configFile)
	if err != nil {
		customLogger.Fatalf("❌ 配置加载失败: %v", err)
	}

	if err := validateConfig(config); err != nil {
		customLogger.Fatalf("❌ 配置验证失败: %v", err)
	}

	server, err := NewRecursiveDNSServer(config)
	if err != nil {
		customLogger.Fatalf("❌ 服务器创建失败: %v", err)
	}

	if err := server.Start(); err != nil {
		customLogger.Fatalf("❌ 服务器启动失败: %v", err)
	}
}
