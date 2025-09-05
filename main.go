package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"regexp"
	"runtime"
	"sort"
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
	ColorPurple = "\033[35m"
	ColorCyan   = "\033[36m"
)

// 常量定义
const (
	DefaultQueryTimeout = 5 * time.Second
	MaxRetries         = 3
	DefaultBufferSize  = 1232  // RFC 标准，不可配置
	MaxCNAMEChain     = 10
	RecursiveAddress   = "recursive" // 特殊地址，表示使用递归解析
)

// 日志配置
type LogConfig struct {
	level     LogLevel
	useColor  bool
	useEmojis bool
}

var (
	logConfig = &LogConfig{
		level:     LogWarn,
		useColor:  true,
		useEmojis: true,
	}
	customLogger = log.New(os.Stdout, "", 0)
)

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
	queries       int64
	cacheHits     int64
	cacheMisses   int64
	errors        int64
	avgQueryTime  int64
	totalTime     int64
	startTime     time.Time
	// 新增统计
	filteredResults int64
	rewrittenQueries int64
	recursiveQueries int64
	upstreamQueries  map[string]int64
	mu               sync.RWMutex
}

func NewServerStats() *ServerStats {
	return &ServerStats{
		startTime:       time.Now(),
		upstreamQueries: make(map[string]int64),
	}
}

func (s *ServerStats) recordQuery(duration time.Duration, fromCache bool, hasError bool) {
	atomic.AddInt64(&s.queries, 1)
	atomic.AddInt64(&s.totalTime, duration.Milliseconds())

	queries := atomic.LoadInt64(&s.queries)
	total := atomic.LoadInt64(&s.totalTime)
	if queries > 0 {
		atomic.StoreInt64(&s.avgQueryTime, total/queries)
	}

	if hasError {
		atomic.AddInt64(&s.errors, 1)
	} else if fromCache {
		atomic.AddInt64(&s.cacheHits, 1)
	} else {
		atomic.AddInt64(&s.cacheMisses, 1)
	}
}

func (s *ServerStats) recordFiltered() {
	atomic.AddInt64(&s.filteredResults, 1)
}

func (s *ServerStats) recordRewritten() {
	atomic.AddInt64(&s.rewrittenQueries, 1)
}

func (s *ServerStats) recordRecursive() {
	atomic.AddInt64(&s.recursiveQueries, 1)
}

func (s *ServerStats) recordUpstreamQuery(server string) {
	s.mu.Lock()
	s.upstreamQueries[server]++
	s.mu.Unlock()
}

func (s *ServerStats) String() string {
	queries := atomic.LoadInt64(&s.queries)
	hits := atomic.LoadInt64(&s.cacheHits)
	errors := atomic.LoadInt64(&s.errors)
	avgTime := atomic.LoadInt64(&s.avgQueryTime)
	filtered := atomic.LoadInt64(&s.filteredResults)
	rewritten := atomic.LoadInt64(&s.rewrittenQueries)
	recursive := atomic.LoadInt64(&s.recursiveQueries)
	uptime := time.Since(s.startTime)

	var hitRate float64
	if queries > 0 {
		hitRate = float64(hits) / float64(queries) * 100
	}

	var qps float64
	if uptime.Seconds() > 0 {
		qps = float64(queries) / uptime.Seconds()
	}

	return fmt.Sprintf("📊 运行时间: %v, 查询: %d (%.1f qps), 缓存命中率: %.1f%%, 错误: %d, 平均耗时: %dms, 过滤: %d, 重写: %d, 递归: %d",
		uptime.Truncate(time.Second), queries, qps, hitRate, errors, avgTime, filtered, rewritten, recursive)
}

// IP地理位置过滤器
type IPFilter struct {
	cnCIDRs   []*net.IPNet
	cnCIDRsV6 []*net.IPNet
	mu        sync.RWMutex
}

func NewIPFilter() *IPFilter {
	return &IPFilter{
		cnCIDRs:   make([]*net.IPNet, 0),
		cnCIDRsV6: make([]*net.IPNet, 0),
	}
}

func (f *IPFilter) LoadChinaCIDRs(filename string) error {
	if filename == "" {
		logf(LogWarn, "🌍 未指定中国CIDR文件，IP过滤功能禁用")
		return nil
	}

	file, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("打开CIDR文件失败: %w", err)
	}
	defer file.Close()

	f.mu.Lock()
	defer f.mu.Unlock()

	f.cnCIDRs = f.cnCIDRs[:0]
	f.cnCIDRsV6 = f.cnCIDRsV6[:0]

	scanner := bufio.NewScanner(file)
	lineCount := 0
	v4Count := 0
	v6Count := 0

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		_, ipNet, err := net.ParseCIDR(line)
		if err != nil {
			logf(LogWarn, "跳过无效CIDR: %s", line)
			continue
		}

		if ipNet.IP.To4() != nil {
			f.cnCIDRs = append(f.cnCIDRs, ipNet)
			v4Count++
		} else {
			f.cnCIDRsV6 = append(f.cnCIDRsV6, ipNet)
			v6Count++
		}
		lineCount++
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("读取CIDR文件失败: %w", err)
	}

	// 按网络大小排序以优化查找性能
	sort.Slice(f.cnCIDRs, func(i, j int) bool {
		sizeI, _ := f.cnCIDRs[i].Mask.Size()
		sizeJ, _ := f.cnCIDRs[j].Mask.Size()
		return sizeI > sizeJ
	})

	sort.Slice(f.cnCIDRsV6, func(i, j int) bool {
		sizeI, _ := f.cnCIDRsV6[i].Mask.Size()
		sizeJ, _ := f.cnCIDRsV6[j].Mask.Size()
		return sizeI > sizeJ
	})

	logf(LogInfo, "🌍 加载中国CIDR: IPv4=%d条, IPv6=%d条, 总计=%d条", v4Count, v6Count, lineCount)
	return nil
}

func (f *IPFilter) IsChinaIP(ip net.IP) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()

	if ip.To4() != nil {
		for _, cidr := range f.cnCIDRs {
			if cidr.Contains(ip) {
				return true
			}
		}
	} else {
		for _, cidr := range f.cnCIDRsV6 {
			if cidr.Contains(ip) {
				return true
			}
		}
	}
	return false
}

func (f *IPFilter) HasCIDRs() bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return len(f.cnCIDRs) > 0 || len(f.cnCIDRsV6) > 0
}

// 上游服务器配置
type UpstreamServer struct {
	Address     string `json:"address"`     // 特殊值 "recursive" 表示使用递归解析
	Name        string `json:"name"`
	TrustPolicy string `json:"trust_policy"` // "all", "cn_only", "non_cn_only"
	Weight      int    `json:"weight"`
	Timeout     int    `json:"timeout"`
	Enabled     bool   `json:"enabled"`
}

func (u *UpstreamServer) IsRecursive() bool {
	return strings.ToLower(u.Address) == RecursiveAddress
}

func (u *UpstreamServer) ShouldTrustResult(hasChineseIP, hasNonChineseIP bool) bool {
	switch u.TrustPolicy {
	case "all":
		return true
	case "cn_only":
		return hasChineseIP && !hasNonChineseIP
	case "non_cn_only":
		return !hasChineseIP
	default:
		return true
	}
}

// DNS重写规则
type RewriteRuleType int

const (
	RewriteExact RewriteRuleType = iota
	RewriteSuffix
	RewriteRegex
	RewritePrefix
)

type RewriteRule struct {
	Type        RewriteRuleType `json:"-"`
	TypeString  string          `json:"type"`
	Pattern     string          `json:"pattern"`
	Replacement string          `json:"replacement"`
	Enabled     bool            `json:"enabled"`
	regex       *regexp.Regexp  `json:"-"`
}

type DNSRewriter struct {
	rules []RewriteRule
	mu    sync.RWMutex
}

func NewDNSRewriter() *DNSRewriter {
	return &DNSRewriter{
		rules: make([]RewriteRule, 0),
	}
}

func (r *DNSRewriter) LoadRules(rules []RewriteRule) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.rules = make([]RewriteRule, 0, len(rules))

	for i, rule := range rules {
		if !rule.Enabled {
			continue
		}

		// 解析重写类型
		switch strings.ToLower(rule.TypeString) {
		case "exact":
			rule.Type = RewriteExact
		case "suffix":
			rule.Type = RewriteSuffix
		case "prefix":
			rule.Type = RewritePrefix
		case "regex":
			rule.Type = RewriteRegex
			regex, err := regexp.Compile(rule.Pattern)
			if err != nil {
				return fmt.Errorf("重写规则 %d 正则表达式编译失败: %w", i, err)
			}
			rule.regex = regex
		default:
			return fmt.Errorf("重写规则 %d 类型无效: %s", i, rule.TypeString)
		}

		r.rules = append(r.rules, rule)
	}

	logf(LogInfo, "🔄 加载DNS重写规则: %d条", len(r.rules))
	return nil
}

func (r *DNSRewriter) Rewrite(domain string) (string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	domain = strings.ToLower(strings.TrimSuffix(domain, "."))

	for _, rule := range r.rules {
		var matched bool
		var result string

		switch rule.Type {
		case RewriteExact:
			if domain == strings.ToLower(rule.Pattern) {
				matched = true
				result = rule.Replacement
			}

		case RewriteSuffix:
			pattern := strings.ToLower(rule.Pattern)
			if domain == pattern || strings.HasSuffix(domain, "."+pattern) {
				matched = true
				if strings.Contains(rule.Replacement, "$1") {
					// 支持子域名替换
					if domain == pattern {
						result = strings.ReplaceAll(rule.Replacement, "$1", "")
					} else {
						prefix := strings.TrimSuffix(domain, "."+pattern)
						result = strings.ReplaceAll(rule.Replacement, "$1", prefix+".")
					}
					result = strings.TrimSuffix(result, ".")
				} else {
					result = rule.Replacement
				}
			}

		case RewritePrefix:
			pattern := strings.ToLower(rule.Pattern)
			if strings.HasPrefix(domain, pattern) {
				matched = true
				if strings.Contains(rule.Replacement, "$1") {
					suffix := strings.TrimPrefix(domain, pattern)
					result = strings.ReplaceAll(rule.Replacement, "$1", suffix)
				} else {
					result = rule.Replacement
				}
			}

		case RewriteRegex:
			if rule.regex.MatchString(domain) {
				matched = true
				result = rule.regex.ReplaceAllString(domain, rule.Replacement)
			}
		}

		if matched {
			result = dns.Fqdn(result)
			logf(LogDebug, "🔄 域名重写: %s -> %s (规则: %s)", domain, result, rule.Pattern)
			return result, true
		}
	}

	return domain, false
}

// ECS选项
type ECSOption struct {
	Family       uint16
	SourcePrefix uint8
	ScopePrefix  uint8
	Address      net.IP
}

func ParseECS(opt *dns.EDNS0_SUBNET) *ECSOption {
	if opt == nil {
		return nil
	}
	return &ECSOption{
		Family:       opt.Family,
		SourcePrefix: opt.SourceNetmask,
		ScopePrefix:  opt.SourceScope,
		Address:      opt.Address,
	}
}

func parseDefaultECS(subnet string) (*ECSOption, error) {
	if subnet == "" {
		return nil, nil
	}

	_, ipNet, err := net.ParseCIDR(subnet)
	if err != nil {
		return nil, fmt.Errorf("解析CIDR失败: %w", err)
	}

	prefix, _ := ipNet.Mask.Size()
	family := uint16(1)
	if ipNet.IP.To4() == nil {
		family = 2
	}

	return &ECSOption{
		Family:       family,
		SourcePrefix: uint8(prefix),
		ScopePrefix:  uint8(prefix),
		Address:      ipNet.IP,
	}, nil
}

// 优化的服务器配置结构
type ServerConfig struct {
	Network struct {
		Port       string `json:"port"`
		EnableIPv6 bool   `json:"enable_ipv6"`
		DefaultECS string `json:"default_ecs_subnet"`
	} `json:"network"`

	TTL struct {
		DefaultTTL  int `json:"default_ttl"`
		MinTTL      int `json:"min_ttl"`
		MaxTTL      int `json:"max_ttl"`
		StaleTTL    int `json:"stale_ttl"`
		StaleMaxAge int `json:"stale_max_age"`
	} `json:"ttl"`

	Performance struct {
		MaxConcurrency int `json:"max_concurrency"`
		ConnPoolSize   int `json:"conn_pool_size"`
		QueryTimeout   int `json:"query_timeout"`
		MaxRecursion   int `json:"max_recursion"`
		WorkerCount    int `json:"worker_count"`
	} `json:"performance"`

	Logging struct {
		Level         string `json:"level"`
		EnableStats   bool   `json:"enable_stats"`
		StatsInterval int    `json:"stats_interval"`
	} `json:"logging"`

	Features struct {
		ServeStale      bool `json:"serve_stale"`
		PrefetchEnabled bool `json:"prefetch_enabled"`
		DNSSEC          bool `json:"dnssec"`
	} `json:"features"`

	Redis struct {
		Address     string `json:"address"`     // 空字符串表示不使用缓存
		Password    string `json:"password"`
		Database    int    `json:"database"`
		PoolSize    int    `json:"pool_size"`
		IdleTimeout int    `json:"idle_timeout"`
		KeyPrefix   string `json:"key_prefix"`
	} `json:"redis"`

	// 新增：上游服务器配置
	Upstream struct {
		Servers          []UpstreamServer `json:"servers"`
		ChinaCIDRFile    string           `json:"china_cidr_file"`
		FilteringEnabled bool             `json:"filtering_enabled"`
		Strategy         string           `json:"strategy"` // "first_valid", "prefer_trusted", "round_robin"
	} `json:"upstream"`

	// 新增：DNS重写配置
	Rewrite struct {
		Enabled bool          `json:"enabled"`
		Rules   []RewriteRule `json:"rules"`
	} `json:"rewrite"`
}

func getDefaultConfig() *ServerConfig {
	config := &ServerConfig{}

	config.Network.Port = "53"
	config.Network.EnableIPv6 = true
	config.Network.DefaultECS = ""

	config.TTL.DefaultTTL = 3600
	config.TTL.MinTTL = 0
	config.TTL.MaxTTL = 0
	config.TTL.StaleTTL = 30
	config.TTL.StaleMaxAge = 604800

	config.Performance.MaxConcurrency = 100
	config.Performance.ConnPoolSize = 50
	config.Performance.QueryTimeout = 5
	config.Performance.MaxRecursion = 10
	config.Performance.WorkerCount = runtime.NumCPU()

	config.Logging.Level = "info"
	config.Logging.EnableStats = true
	config.Logging.StatsInterval = 300

	config.Features.ServeStale = false    // 无缓存模式下禁用
	config.Features.PrefetchEnabled = false // 无缓存模式下禁用
	config.Features.DNSSEC = true

	// 默认不使用Redis缓存（地址为空）
	config.Redis.Address = ""
	config.Redis.Password = ""
	config.Redis.Database = 0
	config.Redis.PoolSize = 20
	config.Redis.IdleTimeout = 300
	config.Redis.KeyPrefix = "zjdns:"

	// 默认上游服务器配置
	config.Upstream.Servers = []UpstreamServer{}
	config.Upstream.ChinaCIDRFile = ""
	config.Upstream.FilteringEnabled = false
	config.Upstream.Strategy = "first_valid"

	// 默认DNS重写配置
	config.Rewrite.Enabled = false
	config.Rewrite.Rules = []RewriteRule{}

	return config
}

func loadConfig(filename string) (*ServerConfig, error) {
	config := getDefaultConfig()

	if filename == "" {
		logf(LogInfo, "📄 使用默认配置（递归模式）")
		return config, nil
	}

	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("读取配置文件失败: %w", err)
	}

	if err := json.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("解析配置文件失败: %w", err)
	}

	logf(LogInfo, "📄 配置文件加载成功: %s", filename)
	return config, nil
}

func generateExampleConfig() string {
	config := getDefaultConfig()
	// 生成示例配置时提供完整示例
	config.Redis.Address = "127.0.0.1:6379"
	config.Features.ServeStale = true
	config.Features.PrefetchEnabled = true

	// 示例上游服务器配置，包含递归选项
	config.Upstream.Servers = []UpstreamServer{
		{
			Address:     "8.8.8.8:53",
			Name:        "Google DNS (海外可信)",
			TrustPolicy: "all",
			Weight:      10,
			Timeout:     5,
			Enabled:     true,
		},
		{
			Address:     "114.114.114.114:53",
			Name:        "114 DNS (仅信任中国IP)",
			TrustPolicy: "cn_only",
			Weight:      8,
			Timeout:     3,
			Enabled:     true,
		},
		{
			Address:     "recursive",
			Name:        "递归解析 (回退选项)",
			TrustPolicy: "all",
			Weight:      5,
			Timeout:     10,
			Enabled:     true,
		},
	}
	config.Upstream.ChinaCIDRFile = "china_cidr.txt"
	config.Upstream.FilteringEnabled = true
	config.Upstream.Strategy = "prefer_trusted"

	// 示例DNS重写规则
	config.Rewrite.Enabled = true
	config.Rewrite.Rules = []RewriteRule{
		{
			TypeString:  "exact",
			Pattern:     "blocked.example.com",
			Replacement: "127.0.0.1",
			Enabled:     true,
		},
		{
			TypeString:  "suffix",
			Pattern:     "ads.example.com",
			Replacement: "127.0.0.1",
			Enabled:     true,
		},
		{
			TypeString:  "regex",
			Pattern:     `^(.+)\.cdn\.example\.com$`,
			Replacement: "$1.fastcdn.example.net",
			Enabled:     false,
		},
	}

	data, _ := json.MarshalIndent(config, "", "  ")
	return string(data)
}

var validLogLevels = map[string]LogLevel{
	"none": LogNone, "error": LogError, "warn": LogWarn,
	"info": LogInfo, "debug": LogDebug,
}

func validateConfig(config *ServerConfig) error {
	if level, ok := validLogLevels[strings.ToLower(config.Logging.Level)]; ok {
		logConfig.level = level
	} else {
		return fmt.Errorf("无效的日志级别: %s", config.Logging.Level)
	}

	if config.Network.DefaultECS != "" {
		if _, _, err := net.ParseCIDR(config.Network.DefaultECS); err != nil {
			return fmt.Errorf("ECS子网格式错误: %w", err)
		}
	}

	if config.TTL.MinTTL > 0 && config.TTL.MaxTTL > 0 && config.TTL.MinTTL > config.TTL.MaxTTL {
		return errors.New("最小TTL不能大于最大TTL")
	}

	// 验证上游服务器配置
	for i, server := range config.Upstream.Servers {
		if server.Enabled {
			// 检查是否为递归解析特殊地址
			if !server.IsRecursive() {
				if _, _, err := net.SplitHostPort(server.Address); err != nil {
					return fmt.Errorf("上游服务器 %d 地址格式错误: %w", i, err)
				}
			}
			if server.TrustPolicy != "all" && server.TrustPolicy != "cn_only" && server.TrustPolicy != "non_cn_only" {
				return fmt.Errorf("上游服务器 %d 信任策略无效: %s", i, server.TrustPolicy)
			}
		}
	}

	// 只有当Redis地址不为空时才验证Redis配置
	if config.Redis.Address != "" {
		if _, _, err := net.SplitHostPort(config.Redis.Address); err != nil {
			return fmt.Errorf("Redis地址格式错误: %w", err)
		}
	} else {
		// 无缓存模式下，禁用依赖缓存的功能
		if config.Features.ServeStale {
			logf(LogWarn, "⚠️  无缓存模式下禁用过期缓存服务功能")
			config.Features.ServeStale = false
		}
		if config.Features.PrefetchEnabled {
			logf(LogWarn, "⚠️  无缓存模式下禁用预取功能")
			config.Features.PrefetchEnabled = false
		}
	}

	checks := []struct {
		name     string
		value    int
		min, max int
	}{
		{"ttl.default_ttl", config.TTL.DefaultTTL, 1, 604800},
		{"ttl.min_ttl", config.TTL.MinTTL, 0, 604800},
		{"ttl.max_ttl", config.TTL.MaxTTL, 0, 604800},
		{"ttl.stale_ttl", config.TTL.StaleTTL, 1, 3600},
		{"ttl.stale_max_age", config.TTL.StaleMaxAge, 1, 2592000},
		{"perf.max_concurrency", config.Performance.MaxConcurrency, 1, 2000},
		{"perf.conn_pool_size", config.Performance.ConnPoolSize, 1, 500},
		{"perf.query_timeout", config.Performance.QueryTimeout, 1, 30},
		{"perf.worker_count", config.Performance.WorkerCount, 1, 100},
		{"redis.pool_size", config.Redis.PoolSize, 1, 200},
	}

	for _, check := range checks {
		if check.value < check.min || check.value > check.max {
			return fmt.Errorf("%s 必须在 %d-%d 之间", check.name, check.min, check.max)
		}
	}

	return nil
}

// TTL计算器
type TTLCalculator struct {
	config *ServerConfig
}

func NewTTLCalculator(config *ServerConfig) *TTLCalculator {
	return &TTLCalculator{config: config}
}

func (tc *TTLCalculator) CalculateCacheTTL(rrs []dns.RR) int {
	if len(rrs) == 0 {
		return tc.config.TTL.DefaultTTL
	}

	minUpstreamTTL := int(rrs[0].Header().Ttl)
	for _, rr := range rrs {
		if ttl := int(rr.Header().Ttl); ttl > 0 && (minUpstreamTTL == 0 || ttl < minUpstreamTTL) {
			minUpstreamTTL = ttl
		}
	}

	if minUpstreamTTL <= 0 {
		minUpstreamTTL = tc.config.TTL.DefaultTTL
	}

	if tc.config.TTL.MinTTL > 0 && minUpstreamTTL < tc.config.TTL.MinTTL {
		minUpstreamTTL = tc.config.TTL.MinTTL
	}

	if tc.config.TTL.MaxTTL > 0 && minUpstreamTTL > tc.config.TTL.MaxTTL {
		minUpstreamTTL = tc.config.TTL.MaxTTL
	}

	return minUpstreamTTL
}

// 优化的DNS记录结构
type CompactDNSRecord struct {
	Text    string `json:"text"`
	OrigTTL uint32 `json:"orig_ttl"`
	Type    uint16 `json:"type"`
}

// 优化的对象池
var (
	rrPool = sync.Pool{
		New: func() interface{} {
			return make([]*CompactDNSRecord, 0, 16)
		},
	}
	stringPool = sync.Pool{
		New: func() interface{} {
			return make(map[string]bool, 32)
		},
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
	defer rrPool.Put(result)

	seen := stringPool.Get().(map[string]bool)
	defer func() {
		for k := range seen {
			delete(seen, k)
		}
		stringPool.Put(seen)
	}()

	final := make([]*CompactDNSRecord, 0, len(rrs))
	for _, rr := range rrs {
		if rr == nil || rr.Header().Rrtype == dns.TypeOPT {
			continue
		}

		rrText := rr.String()
		if !seen[rrText] {
			seen[rrText] = true
			if cr := compactRR(rr); cr != nil {
				final = append(final, cr)
			}
		}
	}

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

// 缓存条目结构
type CacheEntry struct {
	Answer      []*CompactDNSRecord `json:"answer"`
	Authority   []*CompactDNSRecord `json:"authority"`
	Additional  []*CompactDNSRecord `json:"additional"`
	TTL         int                 `json:"ttl"`
	Timestamp   int64               `json:"timestamp"`
	Validated   bool                `json:"validated"`
	AccessTime  int64               `json:"access_time"`
	RefreshTime int64               `json:"refresh_time"`
	HitCount    int32               `json:"hit_count"`
	// ECS信息
	ECSFamily       uint16 `json:"ecs_family,omitempty"`
	ECSSourcePrefix uint8  `json:"ecs_source_prefix,omitempty"`
	ECSScopePrefix  uint8  `json:"ecs_scope_prefix,omitempty"`
	ECSAddress      string `json:"ecs_address,omitempty"`
}

func (c *CacheEntry) IsExpired() bool {
	return time.Now().Unix()-c.Timestamp > int64(c.TTL)
}

func (c *CacheEntry) IsStale(maxAge int) bool {
	return time.Now().Unix()-c.Timestamp > int64(c.TTL+maxAge)
}

func (c *CacheEntry) ShouldRefresh() bool {
	now := time.Now().Unix()
	return c.IsExpired() &&
		(now-c.Timestamp) > int64(c.TTL+300) &&
		(now-c.RefreshTime) > 600
}

func (c *CacheEntry) GetRemainingTTL(staleTTL int) uint32 {
	remaining := int64(c.TTL) - (time.Now().Unix() - c.Timestamp)
	if remaining <= 0 {
		return uint32(staleTTL)
	}
	return uint32(remaining)
}

func (c *CacheEntry) GetAnswerRRs() []dns.RR     { return expandRRs(c.Answer) }
func (c *CacheEntry) GetAuthorityRRs() []dns.RR  { return expandRRs(c.Authority) }
func (c *CacheEntry) GetAdditionalRRs() []dns.RR { return expandRRs(c.Additional) }

func (c *CacheEntry) GetECSOption() *ECSOption {
	if c.ECSAddress == "" {
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

// 刷新请求
type RefreshRequest struct {
	Question dns.Question
	ECS      *ECSOption
	CacheKey string
}

// 缓存统计
type CacheStats struct {
	hits, misses, evictions, refreshes, errors int64
}

func (cs *CacheStats) RecordHit()      { atomic.AddInt64(&cs.hits, 1) }
func (cs *CacheStats) RecordMiss()     { atomic.AddInt64(&cs.misses, 1) }
func (cs *CacheStats) RecordEviction() { atomic.AddInt64(&cs.evictions, 1) }
func (cs *CacheStats) RecordRefresh()  { atomic.AddInt64(&cs.refreshes, 1) }
func (cs *CacheStats) RecordError()    { atomic.AddInt64(&cs.errors, 1) }

// 缓存接口
type DNSCache interface {
	Get(key string) (*CacheEntry, bool, bool)
	Set(key string, answer, authority, additional []dns.RR, validated bool, ecs *ECSOption)
	RequestRefresh(req RefreshRequest)
	Shutdown()
	GetStats() *CacheStats
}

// 空缓存实现（无缓存模式）
type NullCache struct {
	stats *CacheStats
}

func NewNullCache() *NullCache {
	logf(LogInfo, "🚫 启用无缓存模式")
	return &NullCache{
		stats: &CacheStats{},
	}
}

func (nc *NullCache) Get(key string) (*CacheEntry, bool, bool) {
	nc.stats.RecordMiss()
	return nil, false, false
}

func (nc *NullCache) Set(key string, answer, authority, additional []dns.RR, validated bool, ecs *ECSOption) {
	// 无缓存模式，不存储任何内容
}

func (nc *NullCache) RequestRefresh(req RefreshRequest) {
	// 无缓存模式，无需刷新
}

func (nc *NullCache) Shutdown() {
	logf(LogInfo, "🚫 无缓存模式关闭")
}

func (nc *NullCache) GetStats() *CacheStats {
	return nc.stats
}

// Redis缓存实现
type RedisDNSCache struct {
	client       *redis.Client
	config       *ServerConfig
	ttlCalc      *TTLCalculator
	keyPrefix    string
	refreshQueue chan RefreshRequest
	stats        *CacheStats
	ctx          context.Context
	cancel       context.CancelFunc
	wg           sync.WaitGroup
}

func NewRedisDNSCache(config *ServerConfig) (*RedisDNSCache, error) {
	rdb := redis.NewClient(&redis.Options{
		Addr:         config.Redis.Address,
		Password:     config.Redis.Password,
		DB:           config.Redis.Database,
		PoolSize:     config.Redis.PoolSize,
		IdleTimeout:  time.Duration(config.Redis.IdleTimeout) * time.Second,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
		DialTimeout:  5 * time.Second,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := rdb.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("Redis连接失败: %w", err)
	}

	cacheCtx, cacheCancel := context.WithCancel(context.Background())
	cache := &RedisDNSCache{
		client:       rdb,
		config:       config,
		ttlCalc:      NewTTLCalculator(config),
		keyPrefix:    config.Redis.KeyPrefix,
		refreshQueue: make(chan RefreshRequest, 1000),
		stats:        &CacheStats{},
		ctx:          cacheCtx,
		cancel:       cacheCancel,
	}

	if config.Features.ServeStale && config.Features.PrefetchEnabled {
		cache.startRefreshProcessor()
	}

	logf(LogInfo, "✅ Redis缓存系统初始化完成")
	return cache, nil
}

func (rc *RedisDNSCache) startRefreshProcessor() {
	workerCount := rc.config.Performance.WorkerCount
	if workerCount > 10 {
		workerCount = 10
	}

	for i := 0; i < workerCount; i++ {
		rc.wg.Add(1)
		go func(workerID int) {
			defer rc.wg.Done()
			logf(LogDebug, "🔄 Redis后台刷新Worker %d启动", workerID)

			for {
				select {
				case req := <-rc.refreshQueue:
					rc.handleRefreshRequest(req)
				case <-rc.ctx.Done():
					logf(LogDebug, "🔄 Worker %d停止", workerID)
					return
				}
			}
		}(i)
	}
}

func (rc *RedisDNSCache) handleRefreshRequest(req RefreshRequest) {
	rc.stats.RecordRefresh()
	logf(LogDebug, "🔄 处理刷新请求: %s", req.CacheKey)
}

func (rc *RedisDNSCache) Get(key string) (*CacheEntry, bool, bool) {
	fullKey := rc.keyPrefix + key

	data, err := rc.client.Get(rc.ctx, fullKey).Result()
	if err != nil {
		if err == redis.Nil {
			rc.stats.RecordMiss()
			return nil, false, false
		}
		rc.stats.RecordError()
		logf(LogDebug, "Redis获取失败: %v", err)
		return nil, false, false
	}

	var entry CacheEntry
	if err := json.Unmarshal([]byte(data), &entry); err != nil {
		rc.stats.RecordError()
		logf(LogDebug, "Redis数据解析失败: %v", err)
		return nil, false, false
	}

	now := time.Now().Unix()

	if rc.config.Features.ServeStale &&
		now-entry.Timestamp > int64(entry.TTL+rc.config.TTL.StaleMaxAge) {
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

func (rc *RedisDNSCache) Set(key string, answer, authority, additional []dns.RR, validated bool, ecs *ECSOption) {
	allRRs := make([]dns.RR, 0, len(answer)+len(authority)+len(additional))
	allRRs = append(allRRs, answer...)
	allRRs = append(allRRs, authority...)
	allRRs = append(allRRs, additional...)

	cacheTTL := rc.ttlCalc.CalculateCacheTTL(allRRs)

	now := time.Now().Unix()
	entry := &CacheEntry{
		Answer:      compactRRs(answer),
		Authority:   compactRRs(authority),
		Additional:  compactRRs(additional),
		TTL:         cacheTTL,
		Timestamp:   now,
		Validated:   validated,
		AccessTime:  now,
		RefreshTime: 0,
		HitCount:    0,
	}

	// 存储ECS信息
	if ecs != nil {
		entry.ECSFamily = ecs.Family
		entry.ECSSourcePrefix = ecs.SourcePrefix
		entry.ECSScopePrefix = ecs.ScopePrefix
		entry.ECSAddress = ecs.Address.String()
	}

	data, err := json.Marshal(entry)
	if err != nil {
		rc.stats.RecordError()
		logf(LogDebug, "Redis数据序列化失败: %v", err)
		return
	}

	fullKey := rc.keyPrefix + key
	expiration := time.Duration(cacheTTL) * time.Second
	if rc.config.Features.ServeStale {
		expiration += time.Duration(rc.config.TTL.StaleMaxAge) * time.Second
	}

	if err := rc.client.Set(rc.ctx, fullKey, data, expiration).Err(); err != nil {
		rc.stats.RecordError()
		logf(LogDebug, "Redis设置失败: %v", err)
		return
	}

	validatedStr := ""
	if validated {
		validatedStr = " 🔐"
	}

	ecsStr := ""
	if ecs != nil {
		ecsStr = fmt.Sprintf(" ECS: %s/%d/%d", ecs.Address, ecs.SourcePrefix, ecs.ScopePrefix)
	}

	logf(LogDebug, "💾 Redis缓存记录: %s (TTL: %ds, 答案: %d条)%s%s",
		key, cacheTTL, len(answer), validatedStr, ecsStr)
}

func (rc *RedisDNSCache) updateAccessInfo(fullKey string, entry *CacheEntry) {
	data, err := json.Marshal(entry)
	if err != nil {
		return
	}
	rc.client.Set(rc.ctx, fullKey, data, redis.KeepTTL)
}

func (rc *RedisDNSCache) removeStaleEntry(fullKey string) {
	if err := rc.client.Del(rc.ctx, fullKey).Err(); err != nil {
		rc.stats.RecordError()
		logf(LogDebug, "Redis删除过期条目失败: %v", err)
	} else {
		rc.stats.RecordEviction()
	}
}

func (rc *RedisDNSCache) RequestRefresh(req RefreshRequest) {
	select {
	case rc.refreshQueue <- req:
		rc.stats.RecordRefresh()
	default:
		logf(LogDebug, "刷新队列已满，跳过刷新请求")
	}
}

func (rc *RedisDNSCache) Shutdown() {
	logf(LogInfo, "🛑 正在关闭Redis缓存系统...")
	rc.cancel()
	close(rc.refreshQueue)

	done := make(chan struct{})
	go func() {
		rc.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		logf(LogWarn, "Redis缓存关闭超时")
	}

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
		default:
			filtered = append(filtered, rr)
		}
	}
	return filtered
}

// 检查DNS响应是否包含中国IP
func containsChinaIP(rrs []dns.RR, filter *IPFilter) bool {
	for _, rr := range rrs {
		switch record := rr.(type) {
		case *dns.A:
			if filter.IsChinaIP(record.A) {
				return true
			}
		case *dns.AAAA:
			if filter.IsChinaIP(record.AAAA) {
				return true
			}
		}
	}
	return false
}

// 检查DNS响应是否包含非中国IP
func containsNonChinaIP(rrs []dns.RR, filter *IPFilter) bool {
	for _, rr := range rrs {
		switch record := rr.(type) {
		case *dns.A:
			if !filter.IsChinaIP(record.A) {
				return true
			}
		case *dns.AAAA:
			if !filter.IsChinaIP(record.AAAA) {
				return true
			}
		}
	}
	return false
}

// 优化的DNSSEC验证器
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

// 优化的连接池
type ConnectionPool struct {
	clients   []*dns.Client
	pool      chan *dns.Client
	timeout   time.Duration
	created   int64
	available int64
}

func NewConnectionPool(size int, timeout time.Duration) *ConnectionPool {
	pool := &ConnectionPool{
		clients: make([]*dns.Client, 0, size),
		pool:    make(chan *dns.Client, size),
		timeout: timeout,
	}

	for i := 0; i < size; i++ {
		client := &dns.Client{
			Timeout: timeout,
			Net:     "udp",
			UDPSize: DefaultBufferSize,
		}
		pool.clients = append(pool.clients, client)
		pool.pool <- client
		atomic.AddInt64(&pool.created, 1)
		atomic.AddInt64(&pool.available, 1)
	}

	logf(LogDebug, "🏊 连接池初始化完成: %d个连接", size)
	return pool
}

func (cp *ConnectionPool) Get() *dns.Client {
	select {
	case client := <-cp.pool:
		atomic.AddInt64(&cp.available, -1)
		return client
	default:
		return &dns.Client{
			Timeout: cp.timeout,
			Net:     "udp",
			UDPSize: DefaultBufferSize,
		}
	}
}

func (cp *ConnectionPool) Put(client *dns.Client) {
	select {
	case cp.pool <- client:
		atomic.AddInt64(&cp.available, 1)
	default:
	}
}

func (cp *ConnectionPool) Stats() (created, available int64) {
	return atomic.LoadInt64(&cp.created), atomic.LoadInt64(&cp.available)
}

// 查询结果
type QueryResult struct {
	Response *dns.Msg
	Server   string
	Error    error
	Duration time.Duration
}

// 上游查询结果
type UpstreamResult struct {
	Response     *dns.Msg
	Server       *UpstreamServer
	Error        error
	Duration     time.Duration
	HasChinaIP   bool
	HasNonChinaIP bool
	Trusted      bool
}

// 优化的主服务器
type RecursiveDNSServer struct {
	config           *ServerConfig
	cache            DNSCache // 使用接口
	rootServersV4    []string
	rootServersV6    []string
	connPool         *ConnectionPool
	dnssecVal        *DNSSECValidator
	defaultECS       *ECSOption
	stats            *ServerStats
	concurrencyLimit chan struct{}
	ctx              context.Context
	cancel           context.CancelFunc
	shutdown         chan struct{}
	// 新增组件
	ipFilter    *IPFilter
	dnsRewriter *DNSRewriter
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
		return nil, fmt.Errorf("ECS配置错误: %w", err)
	}

	// 根据配置选择缓存实现
	var cache DNSCache
	if config.Redis.Address == "" {
		cache = NewNullCache()
	} else {
		redisCache, err := NewRedisDNSCache(config)
		if err != nil {
			return nil, fmt.Errorf("Redis缓存初始化失败: %w", err)
		}
		cache = redisCache
	}

	ctx, cancel := context.WithCancel(context.Background())

	// 初始化IP过滤器
	ipFilter := NewIPFilter()
	if config.Upstream.FilteringEnabled {
		if err := ipFilter.LoadChinaCIDRs(config.Upstream.ChinaCIDRFile); err != nil {
			return nil, fmt.Errorf("加载中国CIDR文件失败: %w", err)
		}
	}

	// 初始化DNS重写器
	dnsRewriter := NewDNSRewriter()
	if config.Rewrite.Enabled {
		if err := dnsRewriter.LoadRules(config.Rewrite.Rules); err != nil {
			return nil, fmt.Errorf("加载DNS重写规则失败: %w", err)
		}
	}

	server := &RecursiveDNSServer{
		config:           config,
		cache:            cache,
		rootServersV4:    rootServersV4,
		rootServersV6:    rootServersV6,
		connPool:         NewConnectionPool(config.Performance.ConnPoolSize, DefaultQueryTimeout),
		dnssecVal:        NewDNSSECValidator(),
		defaultECS:       defaultECS,
		stats:            NewServerStats(),
		concurrencyLimit: make(chan struct{}, config.Performance.MaxConcurrency),
		ctx:              ctx,
		cancel:           cancel,
		shutdown:         make(chan struct{}),
		ipFilter:         ipFilter,
		dnsRewriter:      dnsRewriter,
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

		for {
			select {
			case <-ticker.C:
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

				created, available := r.connPool.Stats()

				// 根据缓存类型显示不同的统计信息
				if r.config.Redis.Address == "" {
					logf(LogInfo, "🚫 无缓存模式: 查询=%d, 连接池=%d/%d", misses, available, created)
				} else {
					logf(LogInfo, "💾 Redis缓存: 命中率=%.1f%%, 淘汰=%d, 刷新=%d, 错误=%d, 连接池=%d/%d",
						hitRate, evictions, refreshes, errors, available, created)
				}

				// 显示上游服务器统计
				if len(r.config.Upstream.Servers) > 0 {
					r.stats.mu.RLock()
					logf(LogInfo, "🔗 上游查询统计: %v", r.stats.upstreamQueries)
					r.stats.mu.RUnlock()
				}

			case <-r.ctx.Done():
				return
			}
		}
	}()
}

func (r *RecursiveDNSServer) setupSignalHandling() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigChan
		logf(LogInfo, "🛑 收到信号 %v，开始优雅关闭...", sig)
		logf(LogInfo, "📊 最终统计: %s", r.stats.String())

		r.cancel()
		r.cache.Shutdown()
		close(r.shutdown)

		time.Sleep(2 * time.Second)
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

	logf(LogInfo, "🚀 启动 ZJDNS Server")
	logf(LogInfo, "🌐 监听端口: %s", r.config.Network.Port)

	// 根据配置显示不同模式信息
	if len(r.config.Upstream.Servers) > 0 {
		enabledCount := 0
		recursiveCount := 0
		for _, server := range r.config.Upstream.Servers {
			if server.Enabled {
				enabledCount++
				if server.IsRecursive() {
					recursiveCount++
					logf(LogInfo, "🔗 上游配置: %s (递归解析) - %s", server.Name, server.TrustPolicy)
				} else {
					logf(LogInfo, "🔗 上游服务器: %s (%s) - %s", server.Name, server.Address, server.TrustPolicy)
				}
			}
		}
		logf(LogInfo, "🔗 混合模式: %d个上游 (%d递归), 策略=%s, 过滤=%v",
			enabledCount, recursiveCount, r.config.Upstream.Strategy, r.config.Upstream.FilteringEnabled)
		if r.ipFilter.HasCIDRs() {
			logf(LogInfo, "🌍 IP过滤: 已加载中国CIDR数据")
		}
	} else {
		// 根据缓存类型显示不同的信息
		if r.config.Redis.Address == "" {
			logf(LogInfo, "🚫 缓存模式: 无缓存 (纯递归模式)")
		} else {
			logf(LogInfo, "💾 Redis缓存: %s (DB: %d)", r.config.Redis.Address, r.config.Redis.Database)
		}
	}

	if r.config.Rewrite.Enabled {
		logf(LogInfo, "🔄 DNS重写: 已启用")
	}

	logf(LogInfo, "⚡ 最大并发: %d", r.config.Performance.MaxConcurrency)
	logf(LogInfo, "🏊 连接池大小: %d", r.config.Performance.ConnPoolSize)
	logf(LogInfo, "👷 Worker数量: %d", r.config.Performance.WorkerCount)
	logf(LogInfo, "📦 UDP缓冲区: %d bytes (RFC标准)", DefaultBufferSize)

	if r.config.TTL.MinTTL == 0 && r.config.TTL.MaxTTL == 0 {
		logf(LogInfo, "🕐 TTL策略: 使用上游值 (默认: %ds)", r.config.TTL.DefaultTTL)
	} else {
		logf(LogInfo, "🕐 TTL策略: 限制范围 [%ds, %ds] (默认: %ds)",
			r.config.TTL.MinTTL, r.config.TTL.MaxTTL, r.config.TTL.DefaultTTL)
	}

	if r.config.Network.EnableIPv6 {
		logf(LogInfo, "🔗 IPv6支持: 启用")
	}
	if r.config.Features.ServeStale {
		logf(LogInfo, "⏰ 过期缓存服务: 启用 (TTL: %ds, 最大保留: %ds)",
			r.config.TTL.StaleTTL, r.config.TTL.StaleMaxAge)
	}
	if r.config.Features.DNSSEC {
		logf(LogInfo, "🔐 DNSSEC支持: 启用")
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
			UDPSize: DefaultBufferSize,
		}
		logf(LogInfo, "📡 UDP服务器启动中...")
		if err := server.ListenAndServe(); err != nil {
			errChan <- fmt.Errorf("UDP启动失败: %w", err)
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
			errChan <- fmt.Errorf("TCP启动失败: %w", err)
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

	<-r.shutdown
	return nil
}

func (r *RecursiveDNSServer) handleDNSRequest(w dns.ResponseWriter, req *dns.Msg) {
	start := time.Now()

	select {
	case <-r.ctx.Done():
		return
	default:
	}

	response := r.processDNSQuery(req, getClientIP(w))
	duration := time.Since(start)

	fromCache := response.Rcode == dns.RcodeSuccess && len(response.Answer) > 0
	hasError := response.Rcode != dns.RcodeSuccess
	r.stats.recordQuery(duration, fromCache, hasError)

	w.WriteMsg(response)
}

func (r *RecursiveDNSServer) addEDNS0(msg *dns.Msg, validated bool, ecs *ECSOption) {
	var opt *dns.OPT

	if existingOpt := msg.IsEdns0(); existingOpt != nil {
		opt = existingOpt
	} else {
		opt = new(dns.OPT)
		opt.Hdr.Name = "."
		opt.Hdr.Rrtype = dns.TypeOPT
		opt.Hdr.Class = DefaultBufferSize
		msg.Extra = append(msg.Extra, opt)
	}

	if r.config.Features.DNSSEC {
		opt.SetDo(true)
		if validated {
			msg.AuthenticatedData = true
		}
	}

	// 添加ECS响应
	if ecs != nil {
		hasECS := false
		for _, option := range opt.Option {
			if subnet, ok := option.(*dns.EDNS0_SUBNET); ok {
				subnet.Family = ecs.Family
				subnet.SourceNetmask = ecs.SourcePrefix
				subnet.SourceScope = ecs.ScopePrefix
				subnet.Address = ecs.Address
				hasECS = true
				logf(LogDebug, "🌍 更新ECS响应: %s/%d/%d", ecs.Address, ecs.SourcePrefix, ecs.ScopePrefix)
				break
			}
		}

		if !hasECS {
			ecsOption := &dns.EDNS0_SUBNET{
				Code:          dns.EDNS0SUBNET,
				Family:        ecs.Family,
				SourceNetmask: ecs.SourcePrefix,
				SourceScope:   ecs.ScopePrefix,
				Address:       ecs.Address,
			}
			opt.Option = append(opt.Option, ecsOption)
			logf(LogDebug, "🌍 添加ECS响应: %s/%d/%d", ecs.Address, ecs.SourcePrefix, ecs.ScopePrefix)
		}
	}
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
	originalDomain := question.Name

	// DNS重写处理
	if r.config.Rewrite.Enabled {
		if rewritten, changed := r.dnsRewriter.Rewrite(question.Name); changed {
			question.Name = rewritten
			r.stats.recordRewritten()
			logf(LogDebug, "🔄 域名重写: %s -> %s", originalDomain, rewritten)

			// 检查是否重写为IP地址（简单的A记录响应）
			if ip := net.ParseIP(strings.TrimSuffix(rewritten, ".")); ip != nil {
				if question.Qtype == dns.TypeA && ip.To4() != nil {
					msg.Answer = []dns.RR{&dns.A{
						Hdr: dns.RR_Header{
							Name:   originalDomain,
							Rrtype: dns.TypeA,
							Class:  dns.ClassINET,
							Ttl:    uint32(r.config.TTL.DefaultTTL),
						},
						A: ip,
					}}
					return msg
				} else if question.Qtype == dns.TypeAAAA && ip.To4() == nil {
					msg.Answer = []dns.RR{&dns.AAAA{
						Hdr: dns.RR_Header{
							Name:   originalDomain,
							Rrtype: dns.TypeAAAA,
							Class:  dns.ClassINET,
							Ttl:    uint32(r.config.TTL.DefaultTTL),
						},
						AAAA: ip,
					}}
					return msg
				}
			}
		}
	}

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

		responseTTL := entry.GetRemainingTTL(r.config.TTL.StaleTTL)

		msg.Answer = adjustTTL(filterDNSSECRecords(entry.GetAnswerRRs(), dnssecOK), responseTTL)
		msg.Ns = adjustTTL(filterDNSSECRecords(entry.GetAuthorityRRs(), dnssecOK), responseTTL)
		msg.Extra = adjustTTL(filterDNSSECRecords(entry.GetAdditionalRRs(), dnssecOK), responseTTL)

		cachedECS := entry.GetECSOption()

		if dnssecOK || cachedECS != nil {
			r.addEDNS0(msg, entry.Validated, cachedECS)
		}

		if isExpired && r.config.Features.ServeStale && r.config.Features.PrefetchEnabled && entry.ShouldRefresh() {
			r.cache.RequestRefresh(RefreshRequest{
				Question: question,
				ECS:      ecsOpt,
				CacheKey: cacheKey,
			})
		}

		// 恢复原始域名
		for _, rr := range msg.Answer {
			if strings.EqualFold(rr.Header().Name, question.Name) {
				rr.Header().Name = originalDomain
			}
		}

		return msg
	}

	// 选择查询方式：上游服务器 vs 纯递归解析
	var answer, authority, additional []dns.RR
	var validated bool
	var ecsResponse *ECSOption
	var err error

	if len(r.config.Upstream.Servers) > 0 {
		// 使用混合模式（上游服务器 + 递归解析）
		answer, authority, additional, validated, ecsResponse, err = r.queryUpstreamServers(question, ecsOpt)
	} else {
		// 使用纯递归解析模式
		logf(LogDebug, "🔍 纯递归解析: %s %s", dns.TypeToString[question.Qtype], question.Name)

		ctx, cancel := context.WithTimeout(r.ctx, 30*time.Second)
		defer cancel()

		answer, authority, additional, validated, ecsResponse, err = r.resolveWithCNAME(ctx, question, ecsOpt)
	}

	if err != nil {
		logf(LogDebug, "查询失败: %v", err)

		// Serve-Stale fallback
		if r.config.Features.ServeStale {
			if entry, found, _ := r.cache.Get(cacheKey); found {
				logf(LogDebug, "⏰ 使用过期缓存回退: %s %s", question.Name, dns.TypeToString[question.Qtype])

				responseTTL := uint32(r.config.TTL.StaleTTL)
				msg.Answer = adjustTTL(filterDNSSECRecords(entry.GetAnswerRRs(), dnssecOK), responseTTL)
				msg.Ns = adjustTTL(filterDNSSECRecords(entry.GetAuthorityRRs(), dnssecOK), responseTTL)
				msg.Extra = adjustTTL(filterDNSSECRecords(entry.GetAdditionalRRs(), dnssecOK), responseTTL)

				cachedECS := entry.GetECSOption()
				if dnssecOK || cachedECS != nil {
					r.addEDNS0(msg, entry.Validated, cachedECS)
				}

				// 恢复原始域名
				for _, rr := range msg.Answer {
					if strings.EqualFold(rr.Header().Name, question.Name) {
						rr.Header().Name = originalDomain
					}
				}

				return msg
			}
		}

		msg.Rcode = dns.RcodeServerFailure
		return msg
	}

	// 使用实际响应的ECS信息或请求的ECS信息
	finalECS := ecsResponse
	if finalECS == nil && ecsOpt != nil {
		finalECS = &ECSOption{
			Family:       ecsOpt.Family,
			SourcePrefix: ecsOpt.SourcePrefix,
			ScopePrefix:  ecsOpt.SourcePrefix,
			Address:      ecsOpt.Address,
		}
	}

	r.cache.Set(cacheKey, answer, authority, additional, validated, finalECS)

	msg.Answer = filterDNSSECRecords(answer, dnssecOK)
	msg.Ns = filterDNSSECRecords(authority, dnssecOK)
	msg.Extra = filterDNSSECRecords(additional, dnssecOK)

	if dnssecOK || finalECS != nil {
		r.addEDNS0(msg, validated, finalECS)
	}

	// 恢复原始域名
	for _, rr := range msg.Answer {
		if strings.EqualFold(rr.Header().Name, question.Name) {
			rr.Header().Name = originalDomain
		}
	}

	return msg
}

// 新增：查询上游服务器（包含递归选项）
func (r *RecursiveDNSServer) queryUpstreamServers(question dns.Question, ecs *ECSOption) ([]dns.RR, []dns.RR, []dns.RR, bool, *ECSOption, error) {
	enabledServers := make([]*UpstreamServer, 0)
	for i := range r.config.Upstream.Servers {
		if r.config.Upstream.Servers[i].Enabled {
			enabledServers = append(enabledServers, &r.config.Upstream.Servers[i])
		}
	}

	if len(enabledServers) == 0 {
		return nil, nil, nil, false, nil, errors.New("没有可用的上游服务器")
	}

	// 并发查询所有上游服务器（包括递归）
	resultChan := make(chan UpstreamResult, len(enabledServers))
	ctx, cancel := context.WithTimeout(r.ctx, 15*time.Second)
	defer cancel()

	for _, server := range enabledServers {
		go func(srv *UpstreamServer) {
			var result UpstreamResult
			if srv.IsRecursive() {
				result = r.queryRecursiveAsUpstream(ctx, srv, question, ecs)
			} else {
				result = r.queryUpstreamServer(ctx, srv, question, ecs)
			}
			resultChan <- result
		}(server)
	}

	var results []UpstreamResult
	for i := 0; i < len(enabledServers); i++ {
		select {
		case result := <-resultChan:
			results = append(results, result)
		case <-ctx.Done():
			break
		}
	}

	if len(results) == 0 {
		return nil, nil, nil, false, nil, errors.New("所有上游服务器查询失败")
	}

	// 根据策略选择结果
	return r.selectUpstreamResult(results, question)
}

// 新增：将递归解析作为上游选项处理
func (r *RecursiveDNSServer) queryRecursiveAsUpstream(ctx context.Context, server *UpstreamServer, question dns.Question, ecs *ECSOption) UpstreamResult {
	start := time.Now()
	r.stats.recordUpstreamQuery(server.Name)
	r.stats.recordRecursive()

	answer, authority, additional, validated, ecsResponse, err := r.resolveWithCNAME(ctx, question, ecs)
	duration := time.Since(start)

	result := UpstreamResult{
		Server:   server,
		Error:    err,
		Duration: duration,
	}

	if err != nil {
		logf(LogDebug, "🔗 递归解析失败 %s: %v (%v)", server.Name, err, duration)
		return result
	}

	// 构造响应消息
	response := new(dns.Msg)
	response.Answer = answer
	response.Ns = authority
	response.Extra = additional
	response.Rcode = dns.RcodeSuccess
	result.Response = response

	// 使用 validated 变量 - 设置 DNSSEC 验证标志
	if validated && r.config.Features.DNSSEC {
		response.AuthenticatedData = true
	}

	// 使用 ecsResponse 变量 - 添加到响应中
	if ecsResponse != nil {
		opt := &dns.OPT{
			Hdr: dns.RR_Header{
				Name:   ".",
				Rrtype: dns.TypeOPT,
				Class:  DefaultBufferSize,
			},
		}
		ecsOption := &dns.EDNS0_SUBNET{
			Code:          dns.EDNS0SUBNET,
			Family:        ecsResponse.Family,
			SourceNetmask: ecsResponse.SourcePrefix,
			SourceScope:   ecsResponse.ScopePrefix,
			Address:       ecsResponse.Address,
		}
		opt.Option = append(opt.Option, ecsOption)
		response.Extra = append(response.Extra, opt)
	}

	// 分析响应中的IP地址
	if r.config.Upstream.FilteringEnabled && r.ipFilter.HasCIDRs() {
		result.HasChinaIP = containsChinaIP(answer, r.ipFilter)
		result.HasNonChinaIP = containsNonChinaIP(answer, r.ipFilter)

		// 判断是否可信
		result.Trusted = server.ShouldTrustResult(result.HasChinaIP, result.HasNonChinaIP)

		logf(LogDebug, "🔗 递归解析 %s 成功: 中国IP=%v, 非中国IP=%v, 可信=%v (%v)",
			server.Name, result.HasChinaIP, result.HasNonChinaIP, result.Trusted, duration)

		if !result.Trusted {
			r.stats.recordFiltered()
			logf(LogDebug, "🚫 过滤递归结果: %s (策略: %s)", server.Name, server.TrustPolicy)
		}
	} else {
		result.Trusted = true
		logf(LogDebug, "🔗 递归解析 %s 成功 (%v)", server.Name, duration)
	}

	return result
}

func (r *RecursiveDNSServer) queryUpstreamServer(ctx context.Context, server *UpstreamServer, question dns.Question, ecs *ECSOption) UpstreamResult {
	start := time.Now()
	r.stats.recordUpstreamQuery(server.Name)

	client := r.connPool.Get()
	defer r.connPool.Put(client)

	msg := new(dns.Msg)
	msg.SetQuestion(question.Name, question.Qtype)
	msg.RecursionDesired = true

	// 设置EDNS0选项
	opt := &dns.OPT{
		Hdr: dns.RR_Header{
			Name:   ".",
			Rrtype: dns.TypeOPT,
			Class:  DefaultBufferSize,
		},
	}

	if r.config.Features.DNSSEC {
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

	queryCtx, queryCancel := context.WithTimeout(ctx, time.Duration(server.Timeout)*time.Second)
	defer queryCancel()

	response, _, err := client.ExchangeContext(queryCtx, msg, server.Address)
	duration := time.Since(start)

	result := UpstreamResult{
		Response: response,
		Server:   server,
		Error:    err,
		Duration: duration,
	}

	if err != nil {
		logf(LogDebug, "🔗 上游查询失败 %s: %v (%v)", server.Name, err, duration)
		return result
	}

	if response.Rcode != dns.RcodeSuccess {
		logf(LogDebug, "🔗 上游查询 %s 返回: %s (%v)", server.Name, dns.RcodeToString[response.Rcode], duration)
		return result
	}

	// 分析响应中的IP地址
	if r.config.Upstream.FilteringEnabled && r.ipFilter.HasCIDRs() {
		result.HasChinaIP = containsChinaIP(response.Answer, r.ipFilter)
		result.HasNonChinaIP = containsNonChinaIP(response.Answer, r.ipFilter)

		// 判断是否可信
		result.Trusted = server.ShouldTrustResult(result.HasChinaIP, result.HasNonChinaIP)

		logf(LogDebug, "🔗 上游查询 %s 成功: 中国IP=%v, 非中国IP=%v, 可信=%v (%v)",
			server.Name, result.HasChinaIP, result.HasNonChinaIP, result.Trusted, duration)

		if !result.Trusted {
			r.stats.recordFiltered()
			logf(LogDebug, "🚫 过滤上游结果: %s (策略: %s)", server.Name, server.TrustPolicy)
		}
	} else {
		result.Trusted = true
		logf(LogDebug, "🔗 上游查询 %s 成功 (%v)", server.Name, duration)
	}

	return result
}

func (r *RecursiveDNSServer) selectUpstreamResult(results []UpstreamResult, question dns.Question) ([]dns.RR, []dns.RR, []dns.RR, bool, *ECSOption, error) {
	// 分离成功和可信的结果
	var validResults []UpstreamResult
	var trustedResults []UpstreamResult

	for _, result := range results {
		if result.Error == nil && result.Response != nil && result.Response.Rcode == dns.RcodeSuccess {
			validResults = append(validResults, result)
			if result.Trusted {
				trustedResults = append(trustedResults, result)
			}
		}
	}

	if len(validResults) == 0 {
		return nil, nil, nil, false, nil, errors.New("没有有效的查询结果")
	}

	var selectedResult UpstreamResult

	// 根据策略选择结果
	switch r.config.Upstream.Strategy {
	case "first_valid":
		selectedResult = validResults[0]

	case "prefer_trusted":
		if len(trustedResults) > 0 {
			selectedResult = trustedResults[0]
		} else {
			selectedResult = validResults[0]
		}

	case "round_robin":
		// 简单轮询实现
		selectedResult = validResults[int(time.Now().UnixNano())%len(validResults)]

	default:
		selectedResult = validResults[0]
	}

	sourceType := "上游"
	if selectedResult.Server.IsRecursive() {
		sourceType = "递归"
	}
	logf(LogDebug, "✅ 选择%s结果: %s (策略: %s)", sourceType, selectedResult.Server.Name, r.config.Upstream.Strategy)

	// 提取ECS响应信息
	var ecsResponse *ECSOption
	if opt := selectedResult.Response.IsEdns0(); opt != nil {
		for _, option := range opt.Option {
			if subnet, ok := option.(*dns.EDNS0_SUBNET); ok {
				ecsResponse = &ECSOption{
					Family:       subnet.Family,
					SourcePrefix: subnet.SourceNetmask,
					ScopePrefix:  subnet.SourceScope,
					Address:      subnet.Address,
				}
				break
			}
		}
	}

	validated := r.dnssecVal.HasDNSSECRecords(selectedResult.Response)

	return selectedResult.Response.Answer, selectedResult.Response.Ns, selectedResult.Response.Extra, validated, ecsResponse, nil
}

func (r *RecursiveDNSServer) resolveWithCNAME(ctx context.Context, question dns.Question, ecs *ECSOption) ([]dns.RR, []dns.RR, []dns.RR, bool, *ECSOption, error) {
	var allAnswers []dns.RR
	var finalAuthority, finalAdditional []dns.RR
	var finalECSResponse *ECSOption
	allValidated := true

	currentQuestion := question
	visitedCNAMEs := make(map[string]bool, MaxCNAMEChain)

	for i := 0; i < MaxCNAMEChain; i++ {
		select {
		case <-ctx.Done():
			return nil, nil, nil, false, nil, ctx.Err()
		default:
		}

		currentName := strings.ToLower(currentQuestion.Name)
		if visitedCNAMEs[currentName] {
			return nil, nil, nil, false, nil, fmt.Errorf("CNAME循环检测: %s", currentName)
		}
		visitedCNAMEs[currentName] = true

		answer, authority, additional, validated, ecsResponse, err := r.recursiveQuery(ctx, currentQuestion, ecs, 0)
		if err != nil {
			return nil, nil, nil, false, nil, err
		}

		if !validated {
			allValidated = false
		}

		if ecsResponse != nil {
			finalECSResponse = ecsResponse
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

	return allAnswers, finalAuthority, finalAdditional, allValidated, finalECSResponse, nil
}

func (r *RecursiveDNSServer) recursiveQuery(ctx context.Context, question dns.Question, ecs *ECSOption, depth int) ([]dns.RR, []dns.RR, []dns.RR, bool, *ECSOption, error) {
	if depth > r.config.Performance.MaxRecursion {
		return nil, nil, nil, false, nil, fmt.Errorf("递归深度超限: %d", depth)
	}

	qname := dns.Fqdn(question.Name)
	question.Name = qname
	nameservers := r.getRootServers()
	currentDomain := "."

	for {
		select {
		case <-ctx.Done():
			return nil, nil, nil, false, nil, ctx.Err()
		default:
		}

		logf(LogDebug, "🔍 查询域 %s，使用NS: %v", currentDomain, nameservers[:min(len(nameservers), 3)])

		response, err := r.queryNameserversConcurrent(ctx, nameservers, question, ecs)
		if err != nil {
			return nil, nil, nil, false, nil, fmt.Errorf("查询%s失败: %w", currentDomain, err)
		}

		validated := r.dnssecVal.HasDNSSECRecords(response)

		// 提取ECS响应信息
		var ecsResponse *ECSOption
		if opt := response.IsEdns0(); opt != nil {
			for _, option := range opt.Option {
				if subnet, ok := option.(*dns.EDNS0_SUBNET); ok {
					ecsResponse = &ECSOption{
						Family:       subnet.Family,
						SourcePrefix: subnet.SourceNetmask,
						ScopePrefix:  subnet.SourceScope,
						Address:      subnet.Address,
					}
					logf(LogDebug, "🌍 上游ECS响应: %s/%d/%d", subnet.Address, subnet.SourceNetmask, subnet.SourceScope)
					break
				}
			}
		}

		if len(response.Answer) > 0 {
			logf(LogDebug, "✅ 找到答案: %d条记录", len(response.Answer))
			return response.Answer, response.Ns, response.Extra, validated, ecsResponse, nil
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
			return nil, nil, nil, false, nil, errors.New("未找到适当的NS记录")
		}

		if bestMatch == strings.TrimSuffix(currentDomain, ".") {
			return nil, nil, nil, false, nil, fmt.Errorf("检测到递归循环: %s", bestMatch)
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
			return nil, nil, nil, false, nil, errors.New("无法解析NS地址")
		}

		logf(LogDebug, "🔄 切换到NS: %v", nextNS[:min(len(nextNS), 3)])
		nameservers = nextNS
	}
}

func (r *RecursiveDNSServer) queryNameserversConcurrent(ctx context.Context, nameservers []string, question dns.Question, ecs *ECSOption) (*dns.Msg, error) {
	if len(nameservers) == 0 {
		return nil, errors.New("没有可用的nameserver")
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
					Class:  DefaultBufferSize,
				},
			}
			if r.config.Features.DNSSEC {
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
			return nil, errors.New("查询超时")
		}
	}

	return nil, errors.New("所有nameserver查询失败")
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
			if nsAnswer, _, _, _, _, err := r.recursiveQuery(ctx, nsQuestion, nil, depth+1); err == nil {
				for _, rr := range nsAnswer {
					if a, ok := rr.(*dns.A); ok {
						addresses = append(addresses, net.JoinHostPort(a.A.String(), "53"))
					}
				}
			}

			if r.config.Network.EnableIPv6 && len(addresses) == 0 {
				nsQuestionV6 := dns.Question{Name: dns.Fqdn(ns.Ns), Qtype: dns.TypeAAAA, Qclass: dns.ClassINET}
				if nsAnswerV6, _, _, _, _, err := r.recursiveQuery(ctx, nsQuestionV6, nil, depth+1); err == nil {
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
		switch a := addr.(type) {
		case *net.UDPAddr:
			return a.IP
		case *net.TCPAddr:
			return a.IP
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

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func main() {
	var configFile string
	var generateConfig bool

	flag.StringVar(&configFile, "config", "", "配置文件路径 (JSON格式)")
	flag.BoolVar(&generateConfig, "generate-config", false, "生成示例配置文件")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "🚀 ZJDNS Server\n\n")

		fmt.Fprintf(os.Stderr, "用法:\n")
		fmt.Fprintf(os.Stderr, "  %s -config <配置文件>     # 使用配置文件启动\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -generate-config       # 生成示例配置文件\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s                         # 使用默认配置启动（纯递归模式）\n\n", os.Args[0])

		fmt.Fprintf(os.Stderr, "选项:\n")
		fmt.Fprintf(os.Stderr, "  -config string            配置文件路径 (JSON格式)\n")
		fmt.Fprintf(os.Stderr, "  -generate-config          生成示例配置文件到标准输出\n")
		fmt.Fprintf(os.Stderr, "  -h, -help                 显示此帮助信息\n\n")

		fmt.Fprintf(os.Stderr, "示例:\n")
		fmt.Fprintf(os.Stderr, "  # 直接启动（纯递归模式）\n")
		fmt.Fprintf(os.Stderr, "  %s\n\n", os.Args[0])
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
