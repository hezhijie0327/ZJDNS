package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
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
	"unsafe"

	"github.com/miekg/dns"
	"github.com/redis/go-redis/v9"
)

// ==================== 常量和配置定义 ====================

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

// ==================== 系统常量统一管理 ====================

// 网络协议相关常量
const (
	DNSServerPort            = "53"        // DNS服务器默认端口
	RecursiveServerIndicator = "recursive" // 递归服务器标识符
	UDPClientBufferSize      = 1232        // UDP客户端响应缓冲区大小
	UDPUpstreamBufferSize    = 4096        // UDP上游查询缓冲区大小
	RFCMaxDomainNameLength   = 253         // RFC规定的最大域名长度
)

// 缓存相关常量
const (
	MaxCacheKeyLength     = 512    // 缓存键最大长度限制
	DefaultCacheTTL       = 3600   // 默认缓存TTL (1小时)
	MinCacheTTL           = 0      // 最小缓存TTL
	MaxCacheTTL           = 0      // 最大缓存TTL (0表示不限制)
	StaleCacheTTL         = 30     // 过期缓存服务TTL
	StaleCacheMaxAge      = 604800 // 过期缓存最大保存时间 (7天)
	CacheRefreshThreshold = 300    // 缓存刷新触发阈值 (5分钟)
	CacheAccessThrottleMs = 100    // 缓存访问信息更新节流时间(毫秒)
)

// 并发控制相关常量
const (
	GlobalMaxConcurrentQueries      = 10000 // 全局最大并发查询数
	DefaultServerMaxConcurrency     = 1000  // 服务器默认最大并发数
	DefaultConnectionPoolSize       = 100   // 默认连接池大小
	SingleQueryMaxConcurrency       = 5     // 单个查询的最大并发数
	NameServerResolveMaxConcurrency = 3     // NS解析最大并发数
	BackgroundWorkerMaxCount        = 50    // 后台工作协程最大数量
	BackgroundWorkerQueueSize       = 1000  // 后台工作队列大小
)

// DNS解析相关常量
const (
	MaxCNAMEChainLength       = 16 // CNAME链最大跳转次数
	MaxRecursionDepth         = 16 // 递归解析最大深度
	MaxNameServerResolveCount = 3  // NS解析最大数量限制
)

// 超时时间相关常量
const (
	DefaultQueryTimeout      = 5 * time.Second        // 默认DNS查询超时
	StandardOperationTimeout = 5 * time.Second        // 标准操作超时时间
	RecursiveQueryTimeout    = 30 * time.Second       // 递归查询总超时时间
	ExtendedQueryTimeout     = 25 * time.Second       // 扩展查询超时(用于缓存刷新)
	ServerStartupDelay       = 100 * time.Millisecond // 服务器启动延迟
	GracefulShutdownTimeout  = 10 * time.Second       // 优雅关闭超时
	TLSHandshakeTimeout      = 2 * time.Second        // TLS握手超时
	BackgroundTaskTimeout    = 10 * time.Second       // 后台任务关闭超时
)

// 内存管理相关常量
const (
	SmallSliceInitialCapacity  = 8    // 小切片初始容量
	MediumSliceInitialCapacity = 16   // 中等切片初始容量
	LargeSliceInitialCapacity  = 32   // 大切片初始容量
	SliceCapacity              = 100  // 切片容量限制
	MapInitialCapacity         = 32   // 映射初始容量
	StackTraceBufferSize       = 4096 // panic堆栈跟踪缓冲区大小
)

// 文件处理相关常量
const (
	MaxConfigFileSize       = 1024 * 1024 // 最大配置文件大小 (1MB)
	MaxInputLineLength      = 128         // 文件输入行最大长度
	FileScannerBufferSize   = 64 * 1024   // 文件扫描器缓冲区
	FileScannerMaxTokenSize = 1024 * 1024 // 文件扫描器最大token大小
	MaxRegexPatternLength   = 100         // DNS重写正则表达式最大长度
	MaxDNSRewriteRules      = 100         // DNS重写规则最大数量
)

// Redis缓存相关常量
const (
	RedisConnectionPoolSize    = 50              // Redis连接池大小
	RedisMinIdleConnections    = 10              // Redis最小空闲连接数
	RedisMaxRetryAttempts      = 3               // Redis操作最大重试次数
	RedisConnectionPoolTimeout = 5 * time.Second // Redis连接池获取超时
	RedisReadOperationTimeout  = 3 * time.Second // Redis读操作超时
	RedisWriteOperationTimeout = 3 * time.Second // Redis写操作超时
	RedisDialTimeout           = 5 * time.Second // Redis连接建立超时
	CacheRefreshQueueSize      = 1000            // 缓存刷新队列大小
	CacheRefreshWorkerCount    = 10              // 缓存刷新工作协程数量
	CacheRefreshRetryInterval  = 600             // 缓存刷新重试间隔(秒)
)

// IP检测相关常量
const (
	PublicIPDetectionTimeout = 3 * time.Second // 公网IP检测超时
	HTTPClientRequestTimeout = 5 * time.Second // HTTP客户端请求超时
	IPDetectionCacheExpiry   = 5 * time.Minute // IP检测结果缓存过期时间
	MaxTrustedIPv4CIDRs      = 1024            // 最大可信IPv4 CIDR条目数
	MaxTrustedIPv6CIDRs      = 256             // 最大可信IPv6 CIDR条目数
	DefaultECSIPv4PrefixLen  = 24              // ECS默认IPv4前缀长度
	DefaultECSIPv6PrefixLen  = 64              // ECS默认IPv6前缀长度
)

// 全局日志配置
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

// ==================== 请求追踪器 ====================

// RequestTracker 用于追踪DNS查询的完整链路
type RequestTracker struct {
	ID           string        // 请求唯一标识
	StartTime    time.Time     // 请求开始时间
	Domain       string        // 查询域名
	QueryType    string        // 查询类型
	ClientIP     string        // 客户端IP
	Steps        []string      // 查询步骤记录
	CacheHit     bool          // 是否命中缓存
	Upstream     string        // 使用的上游服务器
	ResponseTime time.Duration // 响应时间
	mu           sync.Mutex    // 保护并发写入
}

// NewRequestTracker 创建新的请求追踪器
func NewRequestTracker(domain, qtype, clientIP string) *RequestTracker {
	return &RequestTracker{
		ID:        generateRequestID(),
		StartTime: time.Now(),
		Domain:    domain,
		QueryType: qtype,
		ClientIP:  clientIP,
		Steps:     make([]string, 0, SmallSliceInitialCapacity),
	}
}

// AddStep 添加查询步骤
func (rt *RequestTracker) AddStep(step string, args ...interface{}) {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	timestamp := time.Since(rt.StartTime).String()
	stepMsg := fmt.Sprintf("[%s] %s", timestamp, fmt.Sprintf(step, args...))
	rt.Steps = append(rt.Steps, stepMsg)

	// 输出debug日志
	logf(LogDebug, "🔍 [%s] %s", rt.ID[:SmallSliceInitialCapacity], stepMsg)
}

// Finish 完成请求追踪
func (rt *RequestTracker) Finish() {
	rt.ResponseTime = time.Since(rt.StartTime)

	// 输出完整的查询链路信息
	if logConfig.level >= LogInfo {
		rt.logSummary()
	}
}

// logSummary 输出查询摘要
func (rt *RequestTracker) logSummary() {
	cacheStatus := "MISS"
	if rt.CacheHit {
		cacheStatus = "HIT"
	}

	logf(LogInfo, "📊 [%s] 查询完成: %s %s | 缓存:%s | 耗时:%v | 上游:%s",
		rt.ID[:SmallSliceInitialCapacity], rt.Domain, rt.QueryType, cacheStatus, rt.ResponseTime, rt.Upstream)
}

// generateRequestID 生成请求ID
func generateRequestID() string {
	return fmt.Sprintf("%d_%d", time.Now().UnixNano(), runtime.NumGoroutine())
}

// ==================== 日志系统 ====================

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

// logf 统一的日志输出函数，支持格式化和日志级别控制
func logf(level LogLevel, format string, args ...interface{}) {
	if level <= logConfig.level {
		timestamp := time.Now().UTC().Format("2006-01-02 15:04:05 UTC")
		message := fmt.Sprintf(format, args...)
		logLine := fmt.Sprintf("%s[%s] %s %s", ColorGray, timestamp, level.String(), message)
		if logConfig.useColor {
			logLine += ColorReset
		}
		customLogger.Println(logLine)
	}
}

// ==================== 错误处理和恢复系统 ====================

// SafeExecutor 安全执行器，统一处理panic恢复
type SafeExecutor struct {
	operation string
}

// NewSafeExecutor 创建安全执行器
func NewSafeExecutor(operation string) *SafeExecutor {
	return &SafeExecutor{operation: operation}
}

// Execute 安全执行函数，自动处理panic
func (se *SafeExecutor) Execute(fn func() error) error {
	defer func() {
		if r := recover(); r != nil {
			// 双重panic保护
			func() {
				defer func() {
					if r2 := recover(); r2 != nil {
						fmt.Fprintf(os.Stderr, "CRITICAL: Double panic in %s: %v (original: %v)\n", se.operation, r2, r)
					}
				}()

				logf(LogError, "🚨 Panic恢复 [%s]: %v", se.operation, r)
				buf := make([]byte, StackTraceBufferSize)
				n := runtime.Stack(buf, false)
				logf(LogError, "调用栈: %s", string(buf[:n]))
			}()
		}
	}()

	return fn()
}

// ExecuteWithResult 安全执行带返回值的函数
func (se *SafeExecutor) ExecuteWithResult(fn func() (interface{}, error)) (interface{}, error) {
	var result interface{}
	var err error

	executeErr := se.Execute(func() error {
		result, err = fn()
		return err
	})

	if executeErr != nil {
		return nil, executeErr
	}
	return result, err
}

// recoverPanic 兼容原有的panic恢复函数
func recoverPanic(operation string) {
	NewSafeExecutor(operation).Execute(func() error { return nil })
}

// ==================== 优化的对象池管理 ====================

// ObjectPoolManager 统一管理所有对象池
type ObjectPoolManager struct {
	stringBuilders sync.Pool
	rrSlices       sync.Pool
	stringSlices   sync.Pool
	stringMaps     sync.Pool
	dnsMessages    sync.Pool
}

// NewObjectPoolManager 创建对象池管理器
func NewObjectPoolManager() *ObjectPoolManager {
	return &ObjectPoolManager{
		stringBuilders: sync.Pool{
			New: func() interface{} {
				return &strings.Builder{}
			},
		},
		rrSlices: sync.Pool{
			New: func() interface{} {
				return make([]*CompactDNSRecord, 0, MediumSliceInitialCapacity)
			},
		},
		stringSlices: sync.Pool{
			New: func() interface{} {
				return make([]string, 0, SmallSliceInitialCapacity)
			},
		},
		stringMaps: sync.Pool{
			New: func() interface{} {
				return make(map[string]bool, MapInitialCapacity)
			},
		},
		dnsMessages: sync.Pool{
			New: func() interface{} {
				return new(dns.Msg)
			},
		},
	}
}

// GetStringBuilder 获取字符串构建器
func (pm *ObjectPoolManager) GetStringBuilder() *strings.Builder {
	builder := pm.stringBuilders.Get().(*strings.Builder)
	builder.Reset()
	return builder
}

// PutStringBuilder 归还字符串构建器
func (pm *ObjectPoolManager) PutStringBuilder(builder *strings.Builder) {
	if builder.Cap() < LargeSliceInitialCapacity*MapInitialCapacity { // 防止内存泄漏
		pm.stringBuilders.Put(builder)
	}
}

// GetRRSlice 获取RR切片
func (pm *ObjectPoolManager) GetRRSlice() []*CompactDNSRecord {
	slice := pm.rrSlices.Get().([]*CompactDNSRecord)
	return slice[:0] // 重置长度但保持容量
}

// PutRRSlice 归还RR切片
func (pm *ObjectPoolManager) PutRRSlice(slice []*CompactDNSRecord) {
	if cap(slice) < SliceCapacity { // 防止内存泄漏
		pm.rrSlices.Put(slice)
	}
}

// GetStringMap 获取字符串映射
func (pm *ObjectPoolManager) GetStringMap() map[string]bool {
	m := pm.stringMaps.Get().(map[string]bool)
	// 清空映射
	for k := range m {
		delete(m, k)
	}
	return m
}

// PutStringMap 归还字符串映射
func (pm *ObjectPoolManager) PutStringMap(m map[string]bool) {
	if len(m) < MaxDNSRewriteRules/2 { // 防止内存泄漏
		pm.stringMaps.Put(m)
	}
}

// GetDNSMessage 获取DNS消息
func (pm *ObjectPoolManager) GetDNSMessage() *dns.Msg {
	msg := pm.dnsMessages.Get().(*dns.Msg)
	*msg = dns.Msg{} // 重置消息
	return msg
}

// PutDNSMessage 归还DNS消息
func (pm *ObjectPoolManager) PutDNSMessage(msg *dns.Msg) {
	pm.dnsMessages.Put(msg)
}

// 全局对象池管理器
var globalPoolManager = NewObjectPoolManager()

// ==================== Goroutine管理器 ====================

// GoroutineManager 统一管理所有goroutine的生命周期
type GoroutineManager struct {
	ctx           context.Context
	cancel        context.CancelFunc
	wg            sync.WaitGroup
	activeCount   int64
	maxGoroutines int64
	semaphore     chan struct{} // 信号量控制并发数
}

// NewGoroutineManager 创建Goroutine管理器
func NewGoroutineManager(maxGoroutines int) *GoroutineManager {
	ctx, cancel := context.WithCancel(context.Background())

	if maxGoroutines <= 0 {
		maxGoroutines = GlobalMaxConcurrentQueries
	}

	return &GoroutineManager{
		ctx:           ctx,
		cancel:        cancel,
		maxGoroutines: int64(maxGoroutines),
		semaphore:     make(chan struct{}, maxGoroutines),
	}
}

// Execute 执行受管理的goroutine
func (gm *GoroutineManager) Execute(name string, fn func(ctx context.Context) error) error {
	// 检查是否已关闭
	select {
	case <-gm.ctx.Done():
		return gm.ctx.Err()
	default:
	}

	// 获取执行许可
	select {
	case gm.semaphore <- struct{}{}:
		defer func() { <-gm.semaphore }()
	case <-gm.ctx.Done():
		return gm.ctx.Err()
	}

	// 增加计数器
	atomic.AddInt64(&gm.activeCount, 1)
	defer atomic.AddInt64(&gm.activeCount, -1)

	gm.wg.Add(1)
	defer gm.wg.Done()

	// 执行函数
	executor := NewSafeExecutor(fmt.Sprintf("Goroutine-%s", name))
	return executor.Execute(func() error {
		return fn(gm.ctx)
	})
}

// ExecuteAsync 异步执行goroutine
func (gm *GoroutineManager) ExecuteAsync(name string, fn func(ctx context.Context) error) {
	go func() {
		if err := gm.Execute(name, fn); err != nil && err != context.Canceled {
			logf(LogError, "异步goroutine执行失败 [%s]: %v", name, err)
		}
	}()
}

// GetActiveCount 获取活跃goroutine数量
func (gm *GoroutineManager) GetActiveCount() int64 {
	return atomic.LoadInt64(&gm.activeCount)
}

// Shutdown 关闭管理器
func (gm *GoroutineManager) Shutdown(timeout time.Duration) error {
	logf(LogInfo, "🛑 正在关闭Goroutine管理器...")

	// 取消所有goroutine
	gm.cancel()

	// 等待所有goroutine完成
	done := make(chan struct{})
	go func() {
		gm.wg.Wait()
		close(done)
	}()

	// 超时控制
	select {
	case <-done:
		logf(LogInfo, "✅ 所有goroutine已安全关闭")
		return nil
	case <-time.After(timeout):
		activeCount := gm.GetActiveCount()
		logf(LogWarn, "⏰ Goroutine关闭超时，仍有 %d 个活跃", activeCount)
		return fmt.Errorf("shutdown timeout, %d goroutines still active", activeCount)
	}
}

// ==================== ECS管理器 ====================

// ECSManager 统一管理EDNS Client Subnet相关操作
type ECSManager struct {
	defaultECS *ECSOption
	detector   *IPDetector
	cache      sync.Map // IP检测结果缓存
}

// ECSOption ECS选项定义
type ECSOption struct {
	Family       uint16
	SourcePrefix uint8
	ScopePrefix  uint8
	Address      net.IP
}

// NewECSManager 创建ECS管理器
func NewECSManager(defaultSubnet string) (*ECSManager, error) {
	manager := &ECSManager{
		detector: NewIPDetector(),
	}

	if defaultSubnet != "" {
		ecs, err := manager.parseECSConfig(defaultSubnet)
		if err != nil {
			return nil, fmt.Errorf("ECS配置解析失败: %w", err)
		}
		manager.defaultECS = ecs

		if ecs != nil {
			logf(LogInfo, "🌍 默认ECS配置: %s/%d", ecs.Address, ecs.SourcePrefix)
		}
	}

	return manager, nil
}

// GetDefaultECS 获取默认ECS选项
func (em *ECSManager) GetDefaultECS() *ECSOption {
	return em.defaultECS
}

// ParseFromDNS 从DNS消息中解析ECS选项
func (em *ECSManager) ParseFromDNS(msg *dns.Msg) *ECSOption {
	if msg == nil {
		return nil
	}

	opt := msg.IsEdns0()
	if opt == nil {
		return nil
	}

	for _, option := range opt.Option {
		if subnet, ok := option.(*dns.EDNS0_SUBNET); ok {
			return &ECSOption{
				Family:       subnet.Family,
				SourcePrefix: subnet.SourceNetmask,
				ScopePrefix:  subnet.SourceScope,
				Address:      subnet.Address,
			}
		}
	}

	return nil
}

// AddToMessage 将ECS选项添加到DNS消息
func (em *ECSManager) AddToMessage(msg *dns.Msg, ecs *ECSOption, dnssecEnabled bool) {
	if msg == nil {
		return
	}

	// 移除现有的OPT记录
	var cleanExtra []dns.RR
	for _, rr := range msg.Extra {
		if rr.Header().Rrtype != dns.TypeOPT {
			cleanExtra = append(cleanExtra, rr)
		}
	}
	msg.Extra = cleanExtra

	// 创建新的OPT记录
	opt := &dns.OPT{
		Hdr: dns.RR_Header{
			Name:   ".",
			Rrtype: dns.TypeOPT,
			Class:  UDPUpstreamBufferSize,
			Ttl:    0,
		},
	}

	// 设置DNSSEC选项
	if dnssecEnabled {
		opt.SetDo(true)
	}

	// 添加ECS选项
	if ecs != nil {
		ecsOption := &dns.EDNS0_SUBNET{
			Code:          dns.EDNS0SUBNET,
			Family:        ecs.Family,
			SourceNetmask: ecs.SourcePrefix,
			SourceScope:   ecs.ScopePrefix,
			Address:       ecs.Address,
		}
		opt.Option = []dns.EDNS0{ecsOption}
	}

	msg.Extra = append(msg.Extra, opt)
}

// parseECSConfig 解析ECS配置
func (em *ECSManager) parseECSConfig(subnet string) (*ECSOption, error) {
	switch strings.ToLower(subnet) {
	case "auto":
		return em.detectPublicIP(false, true)
	case "auto_v4":
		return em.detectPublicIP(false, false)
	case "auto_v6":
		return em.detectPublicIP(true, false)
	default:
		// 手动CIDR配置
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
}

// detectPublicIP 检测公网IP地址（带缓存）
func (em *ECSManager) detectPublicIP(forceIPv6, allowFallback bool) (*ECSOption, error) {
	cacheKey := fmt.Sprintf("ip_detection_%v_%v", forceIPv6, allowFallback)

	// 检查缓存
	if cached, ok := em.cache.Load(cacheKey); ok {
		if cachedECS, ok := cached.(*ECSOption); ok {
			logf(LogDebug, "🌍 使用缓存的IP检测结果: %s", cachedECS.Address)
			return cachedECS, nil
		}
	}

	var ip net.IP
	var ecs *ECSOption

	// 检测IPv4或IPv6
	if ip = em.detector.detectPublicIP(forceIPv6); ip != nil {
		family := uint16(1)
		prefix := uint8(DefaultECSIPv4PrefixLen)

		if forceIPv6 {
			family = 2
			prefix = DefaultECSIPv6PrefixLen
		}

		ecs = &ECSOption{
			Family:       family,
			SourcePrefix: prefix,
			ScopePrefix:  prefix,
			Address:      ip,
		}

		logf(LogDebug, "🌍 检测到IP地址: %s", ip)
	}

	// 如果允许回退且检测失败，尝试另一个版本
	if ecs == nil && allowFallback && !forceIPv6 {
		if ip = em.detector.detectPublicIP(true); ip != nil {
			ecs = &ECSOption{
				Family:       2,
				SourcePrefix: DefaultECSIPv6PrefixLen,
				ScopePrefix:  DefaultECSIPv6PrefixLen,
				Address:      ip,
			}
			logf(LogDebug, "🌍 回退检测到IPv6地址: %s", ip)
		}
	}

	// 缓存结果
	if ecs != nil {
		em.cache.Store(cacheKey, ecs)
		time.AfterFunc(IPDetectionCacheExpiry, func() {
			em.cache.Delete(cacheKey)
		})
	} else {
		logf(LogWarn, "⚠️ IP地址检测失败，ECS功能将禁用")
	}

	return ecs, nil
}

// ==================== DNS消息构建器 ====================

// DNSMessageBuilder 统一构建DNS消息
type DNSMessageBuilder struct {
	poolManager *ObjectPoolManager
	ecsManager  *ECSManager
}

// NewDNSMessageBuilder 创建DNS消息构建器
func NewDNSMessageBuilder(poolManager *ObjectPoolManager, ecsManager *ECSManager) *DNSMessageBuilder {
	return &DNSMessageBuilder{
		poolManager: poolManager,
		ecsManager:  ecsManager,
	}
}

// BuildQuery 构建查询消息
func (dmb *DNSMessageBuilder) BuildQuery(question dns.Question, ecs *ECSOption, dnssecEnabled bool, recursionDesired bool) *dns.Msg {
	msg := dmb.poolManager.GetDNSMessage()

	// 设置基本查询信息
	msg.SetQuestion(question.Name, question.Qtype)
	msg.RecursionDesired = recursionDesired

	// 添加EDNS0选项
	dmb.ecsManager.AddToMessage(msg, ecs, dnssecEnabled)

	return msg
}

// BuildResponse 构建响应消息
func (dmb *DNSMessageBuilder) BuildResponse(request *dns.Msg) *dns.Msg {
	msg := dmb.poolManager.GetDNSMessage()
	msg.SetReply(request)
	msg.Authoritative = false
	msg.RecursionAvailable = true
	return msg
}

// ReleaseMessage 释放消息到对象池
func (dmb *DNSMessageBuilder) ReleaseMessage(msg *dns.Msg) {
	if msg != nil {
		dmb.poolManager.PutDNSMessage(msg)
	}
}

// ==================== 统一查询管理器 ====================

// QueryManager 统一管理所有DNS查询操作
type QueryManager struct {
	connPool         *ConnectionPool
	messageBuilder   *DNSMessageBuilder
	goroutineManager *GoroutineManager
	timeout          time.Duration
}

// NewQueryManager 创建查询管理器
func NewQueryManager(connPool *ConnectionPool, messageBuilder *DNSMessageBuilder,
	goroutineManager *GoroutineManager, timeout time.Duration) *QueryManager {
	return &QueryManager{
		connPool:         connPool,
		messageBuilder:   messageBuilder,
		goroutineManager: goroutineManager,
		timeout:          timeout,
	}
}

// QueryResult 查询结果
type QueryResult struct {
	Response *dns.Msg
	Server   string
	Error    error
	Duration time.Duration
	UsedTCP  bool
}

// ExecuteQuery 执行DNS查询（自动UDP/TCP切换）
func (qm *QueryManager) ExecuteQuery(ctx context.Context, msg *dns.Msg, server string, tracker *RequestTracker) *QueryResult {
	start := time.Now()
	result := &QueryResult{
		Server: server,
	}

	if tracker != nil {
		tracker.AddStep("开始查询服务器: %s", server)
	}

	// 创建查询上下文
	queryCtx, cancel := context.WithTimeout(ctx, qm.timeout)
	defer cancel()

	// 首先尝试UDP查询
	result.Response, result.Error = qm.executeUDPQuery(queryCtx, msg, server, tracker)
	result.Duration = time.Since(start)

	// 检查是否需要TCP回退
	needTCPFallback := false
	if result.Error != nil {
		needTCPFallback = true
		if tracker != nil {
			tracker.AddStep("UDP查询失败，准备TCP回退: %v", result.Error)
		}
	} else if result.Response != nil && result.Response.Truncated {
		needTCPFallback = true
		if tracker != nil {
			tracker.AddStep("UDP响应被截断，进行TCP回退")
		}
	}

	// 执行TCP回退
	if needTCPFallback {
		tcpStart := time.Now()
		tcpResponse, tcpErr := qm.executeTCPQuery(queryCtx, msg, server, tracker)
		tcpDuration := time.Since(tcpStart)

		if tcpErr != nil {
			// 如果TCP也失败，但UDP有非错误响应，使用UDP响应
			if result.Response != nil && result.Response.Rcode != dns.RcodeServerFailure {
				if tracker != nil {
					tracker.AddStep("TCP回退失败，使用UDP响应: %v", tcpErr)
				}
				return result
			}
			// 两者都失败，返回TCP错误
			result.Error = tcpErr
			result.Duration = time.Since(start)
			return result
		}

		// TCP成功
		result.Response = tcpResponse
		result.Error = nil
		result.Duration = time.Since(start)
		result.UsedTCP = true

		if tracker != nil {
			tracker.AddStep("TCP查询成功，耗时: %v", tcpDuration)
		}
	}

	return result
}

// executeUDPQuery 执行UDP查询
func (qm *QueryManager) executeUDPQuery(ctx context.Context, msg *dns.Msg, server string, tracker *RequestTracker) (*dns.Msg, error) {
	client := qm.connPool.Get()
	defer qm.connPool.Put(client)

	response, _, err := client.ExchangeContext(ctx, msg, server)

	if tracker != nil && err == nil {
		tracker.AddStep("UDP查询成功，响应码: %s", dns.RcodeToString[response.Rcode])
	}

	return response, err
}

// executeTCPQuery 执行TCP查询
func (qm *QueryManager) executeTCPQuery(ctx context.Context, msg *dns.Msg, server string, tracker *RequestTracker) (*dns.Msg, error) {
	client := qm.connPool.GetTCP()

	response, _, err := client.ExchangeContext(ctx, msg, server)

	if tracker != nil && err == nil {
		tracker.AddStep("TCP查询成功，响应码: %s", dns.RcodeToString[response.Rcode])
	}

	return response, err
}

// ExecuteConcurrentQuery 执行并发查询
func (qm *QueryManager) ExecuteConcurrentQuery(ctx context.Context, msg *dns.Msg, servers []string,
	maxConcurrency int, tracker *RequestTracker) (*QueryResult, error) {

	if len(servers) == 0 {
		return nil, errors.New("没有可用的服务器")
	}

	if tracker != nil {
		tracker.AddStep("开始并发查询 %d 个服务器", len(servers))
	}

	// 限制并发数
	concurrency := len(servers)
	if maxConcurrency > 0 && concurrency > maxConcurrency {
		concurrency = maxConcurrency
	}

	resultChan := make(chan *QueryResult, concurrency)

	// 启动查询goroutine
	for i := 0; i < concurrency && i < len(servers); i++ {
		server := servers[i]
		qm.goroutineManager.ExecuteAsync(fmt.Sprintf("ConcurrentQuery-%s", server),
			func(ctx context.Context) error {
				result := qm.ExecuteQuery(ctx, msg, server, tracker)
				select {
				case resultChan <- result:
				case <-ctx.Done():
				}
				return nil
			})
	}

	// 等待第一个成功的结果
	for i := 0; i < concurrency; i++ {
		select {
		case result := <-resultChan:
			if result.Error == nil && result.Response != nil {
				rcode := result.Response.Rcode
				if rcode == dns.RcodeSuccess || rcode == dns.RcodeNameError {
					if tracker != nil {
						tracker.AddStep("并发查询成功，选择服务器: %s", result.Server)
					}
					return result, nil
				}
			}
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	return nil, errors.New("所有并发查询均失败")
}

// ==================== IP检测器优化 ====================

type IPDetector struct {
	dnsClient  *dns.Client
	httpClient *http.Client
}

func NewIPDetector() *IPDetector {
	return &IPDetector{
		dnsClient: &dns.Client{
			Timeout: PublicIPDetectionTimeout,
			Net:     "udp",
			UDPSize: UDPUpstreamBufferSize,
		},
		httpClient: &http.Client{
			Timeout: HTTPClientRequestTimeout,
			Transport: &http.Transport{
				DialContext: (&net.Dialer{
					Timeout: PublicIPDetectionTimeout,
				}).DialContext,
				TLSHandshakeTimeout: TLSHandshakeTimeout,
			},
		},
	}
}

// detectPublicIP 检测公网IP地址
func (d *IPDetector) detectPublicIP(forceIPv6 bool) net.IP {
	// 优先尝试Google DNS查询
	if ip := d.tryGoogleDNS(forceIPv6); ip != nil {
		logf(LogDebug, "✅ Google DNS检测成功: %s", ip)
		return ip
	}

	// Fallback到Cloudflare HTTP API
	if ip := d.tryCloudflareHTTP(forceIPv6); ip != nil {
		logf(LogDebug, "✅ Cloudflare HTTP检测成功: %s", ip)
		return ip
	}

	return nil
}

func (d *IPDetector) tryGoogleDNS(forceIPv6 bool) net.IP {
	var server string
	if forceIPv6 {
		server = "[2001:4860:4802:32::a]:" + DNSServerPort
	} else {
		server = "216.239.32.10:" + DNSServerPort
	}

	msg := new(dns.Msg)
	msg.SetQuestion("o-o.myaddr.l.google.com.", dns.TypeTXT)
	msg.RecursionDesired = true

	response, _, err := d.dnsClient.Exchange(msg, server)
	if err != nil || response.Rcode != dns.RcodeSuccess {
		return nil
	}

	for _, rr := range response.Answer {
		if txt, ok := rr.(*dns.TXT); ok {
			for _, record := range txt.Txt {
				record = strings.Trim(record, "\"")
				if ip := net.ParseIP(record); ip != nil {
					if forceIPv6 && ip.To4() != nil {
						continue
					}
					if !forceIPv6 && ip.To4() == nil {
						continue
					}
					return ip
				}
			}
		}
	}
	return nil
}

func (d *IPDetector) tryCloudflareHTTP(forceIPv6 bool) net.IP {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialer := &net.Dialer{Timeout: PublicIPDetectionTimeout}
			if forceIPv6 {
				return dialer.DialContext(ctx, "tcp6", addr)
			}
			return dialer.DialContext(ctx, "tcp4", addr)
		},
		TLSHandshakeTimeout: TLSHandshakeTimeout,
	}

	client := &http.Client{
		Timeout:   HTTPClientRequestTimeout,
		Transport: transport,
	}

	resp, err := client.Get("https://api.cloudflare.com/cdn-cgi/trace")
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	re := regexp.MustCompile(`ip=([^\s\n]+)`)
	matches := re.FindStringSubmatch(string(body))
	if len(matches) < 2 {
		return nil
	}

	ip := net.ParseIP(matches[1])
	if ip == nil {
		return nil
	}

	if forceIPv6 && ip.To4() != nil {
		return nil
	}
	if !forceIPv6 && ip.To4() == nil {
		return nil
	}

	return ip
}

// ==================== 缓存Key构建器优化 ====================

// CacheKeyBuilder 缓存键构建器
type CacheKeyBuilder struct {
	builder *strings.Builder
}

// newCacheKeyBuilder 创建缓存键构建器
func newCacheKeyBuilder() *CacheKeyBuilder {
	builder := globalPoolManager.GetStringBuilder()
	return &CacheKeyBuilder{builder: builder}
}

// AddDomain 添加域名
func (ckb *CacheKeyBuilder) AddDomain(domain string) *CacheKeyBuilder {
	ckb.builder.WriteString(strings.ToLower(domain))
	return ckb
}

// AddType 添加查询类型
func (ckb *CacheKeyBuilder) AddType(qtype uint16) *CacheKeyBuilder {
	ckb.builder.WriteByte(':')
	ckb.builder.WriteString(fmt.Sprintf("%d", qtype))
	return ckb
}

// AddClass 添加查询类
func (ckb *CacheKeyBuilder) AddClass(qclass uint16) *CacheKeyBuilder {
	ckb.builder.WriteByte(':')
	ckb.builder.WriteString(fmt.Sprintf("%d", qclass))
	return ckb
}

// AddECS 添加ECS信息
func (ckb *CacheKeyBuilder) AddECS(ecs *ECSOption) *CacheKeyBuilder {
	if ecs != nil {
		ckb.builder.WriteByte(':')
		ckb.builder.WriteString(ecs.Address.String())
		ckb.builder.WriteByte('/')
		ckb.builder.WriteString(fmt.Sprintf("%d", ecs.SourcePrefix))
	}
	return ckb
}

// AddDNSSEC 添加DNSSEC标记
func (ckb *CacheKeyBuilder) AddDNSSEC(enabled bool) *CacheKeyBuilder {
	if enabled {
		ckb.builder.WriteString(":dnssec")
	}
	return ckb
}

// String 构建最终的缓存键
func (ckb *CacheKeyBuilder) String() string {
	result := ckb.builder.String()
	if len(result) > MaxCacheKeyLength {
		result = fmt.Sprintf("hash:%x", result)[:MaxCacheKeyLength]
	}
	return result
}

// Release 释放构建器到对象池
func (ckb *CacheKeyBuilder) Release() {
	globalPoolManager.PutStringBuilder(ckb.builder)
}

// ==================== 后台任务管理器 ====================

type BackgroundTaskManager struct {
	taskQueue chan func()
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
}

func NewBackgroundTaskManager() *BackgroundTaskManager {
	workers := runtime.NumCPU() // 使用CPU核数
	if workers > BackgroundWorkerMaxCount {
		workers = BackgroundWorkerMaxCount
	}

	ctx, cancel := context.WithCancel(context.Background())
	btm := &BackgroundTaskManager{
		taskQueue: make(chan func(), BackgroundWorkerQueueSize),
		ctx:       ctx,
		cancel:    cancel,
	}

	// 启动worker goroutines
	for i := 0; i < workers; i++ {
		btm.wg.Add(1)
		go func(workerID int) {
			defer btm.wg.Done()
			defer recoverPanic(fmt.Sprintf("BackgroundTaskManager Worker %d", workerID))

			for {
				select {
				case task := <-btm.taskQueue:
					if task != nil {
						func() {
							defer recoverPanic(fmt.Sprintf("BackgroundTask in Worker %d", workerID))
							task()
						}()
					}
				case <-btm.ctx.Done():
					return
				}
			}
		}(i)
	}

	return btm
}

func (btm *BackgroundTaskManager) SubmitTask(task func()) {
	select {
	case btm.taskQueue <- task:
	default:
		logf(LogWarn, "⚠️ 后台任务队列已满，跳过任务")
	}
}

func (btm *BackgroundTaskManager) Shutdown() {
	logf(LogInfo, "🔧 正在关闭后台任务管理器...")
	btm.cancel()
	close(btm.taskQueue)

	done := make(chan struct{})
	go func() {
		btm.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		logf(LogInfo, "✅ 后台任务管理器已安全关闭")
	case <-time.After(BackgroundTaskTimeout):
		logf(LogWarn, "⏰ 后台任务管理器关闭超时")
	}
}

// ==================== IP过滤器 ====================

type IPFilter struct {
	trustedCIDRs   []*net.IPNet
	trustedCIDRsV6 []*net.IPNet
	mu             sync.RWMutex
}

func NewIPFilter() *IPFilter {
	return &IPFilter{
		trustedCIDRs:   make([]*net.IPNet, 0, MaxTrustedIPv4CIDRs),
		trustedCIDRsV6: make([]*net.IPNet, 0, MaxTrustedIPv6CIDRs),
	}
}

func (f *IPFilter) LoadCIDRs(filename string) error {
	if filename == "" {
		logf(LogInfo, "🌍 IP过滤器未配置文件路径")
		return nil
	}

	if !isValidFilePath(filename) {
		return fmt.Errorf("无效的文件路径: %s", filename)
	}

	file, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("打开CIDR文件失败: %w", err)
	}
	defer file.Close()

	f.mu.Lock()
	defer f.mu.Unlock()

	f.trustedCIDRs = make([]*net.IPNet, 0, MaxTrustedIPv4CIDRs)
	f.trustedCIDRsV6 = make([]*net.IPNet, 0, MaxTrustedIPv6CIDRs)

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, FileScannerBufferSize), FileScannerMaxTokenSize)
	var totalV4, totalV6 int

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || len(line) > MaxInputLineLength {
			continue
		}

		_, ipNet, err := net.ParseCIDR(line)
		if err != nil {
			continue
		}

		if ipNet.IP.To4() != nil {
			f.trustedCIDRs = append(f.trustedCIDRs, ipNet)
			totalV4++
		} else {
			f.trustedCIDRsV6 = append(f.trustedCIDRsV6, ipNet)
			totalV6++
		}
	}

	f.optimizeCIDRs()
	logf(LogInfo, "🌍 IP过滤器加载完成: IPv4=%d条, IPv6=%d条", totalV4, totalV6)
	return scanner.Err()
}

func (f *IPFilter) optimizeCIDRs() {
	// 按掩码长度降序排序，更具体的网络优先匹配
	sort.Slice(f.trustedCIDRs, func(i, j int) bool {
		sizeI, _ := f.trustedCIDRs[i].Mask.Size()
		sizeJ, _ := f.trustedCIDRs[j].Mask.Size()
		return sizeI > sizeJ
	})

	sort.Slice(f.trustedCIDRsV6, func(i, j int) bool {
		sizeI, _ := f.trustedCIDRsV6[i].Mask.Size()
		sizeJ, _ := f.trustedCIDRsV6[j].Mask.Size()
		return sizeI > sizeJ
	})
}

func (f *IPFilter) isTrustedIP(ip net.IP) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()

	if ip.To4() != nil {
		for _, cidr := range f.trustedCIDRs {
			if cidr.Contains(ip) {
				return true
			}
		}
	} else {
		for _, cidr := range f.trustedCIDRsV6 {
			if cidr.Contains(ip) {
				return true
			}
		}
	}
	return false
}

func (f *IPFilter) AnalyzeIPs(rrs []dns.RR) (hasTrustedIP, hasUntrustedIP bool) {
	if !f.HasData() {
		return false, true
	}

	for _, rr := range rrs {
		var ip net.IP
		switch record := rr.(type) {
		case *dns.A:
			ip = record.A
		case *dns.AAAA:
			ip = record.AAAA
		default:
			continue
		}

		if f.isTrustedIP(ip) {
			hasTrustedIP = true
		} else {
			hasUntrustedIP = true
		}

		if hasTrustedIP && hasUntrustedIP {
			return
		}
	}
	return
}

func (f *IPFilter) HasData() bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return len(f.trustedCIDRs) > 0 || len(f.trustedCIDRsV6) > 0
}

// ==================== DNS重写器 ====================

type RewriteRuleType int

const (
	RewriteExact RewriteRuleType = iota
	RewriteSuffix
	RewriteRegex
	RewritePrefix
)

// RewriteRule 重写规则
type RewriteRule struct {
	Type        RewriteRuleType `json:"-"`
	TypeString  string          `json:"type"`
	Pattern     string          `json:"pattern"`
	Replacement string          `json:"replacement"`
	regex       *regexp.Regexp  `json:"-"`
}

type DNSRewriter struct {
	rules []RewriteRule
	mu    sync.RWMutex
}

func NewDNSRewriter() *DNSRewriter {
	return &DNSRewriter{
		rules: make([]RewriteRule, 0, LargeSliceInitialCapacity),
	}
}

func (r *DNSRewriter) LoadRules(rules []RewriteRule) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	validRules := make([]RewriteRule, 0, len(rules))
	for i, rule := range rules {
		if len(rule.Pattern) > RFCMaxDomainNameLength || len(rule.Replacement) > RFCMaxDomainNameLength {
			continue
		}

		switch strings.ToLower(rule.TypeString) {
		case "exact":
			rule.Type = RewriteExact
		case "suffix":
			rule.Type = RewriteSuffix
		case "prefix":
			rule.Type = RewritePrefix
		case "regex":
			rule.Type = RewriteRegex
			if len(rule.Pattern) > MaxRegexPatternLength {
				return fmt.Errorf("重写规则 %d 正则表达式过于复杂", i)
			}
			regex, err := regexp.Compile(rule.Pattern)
			if err != nil {
				return fmt.Errorf("重写规则 %d 正则表达式编译失败: %w", i, err)
			}
			rule.regex = regex
		default:
			return fmt.Errorf("重写规则 %d 类型无效: %s", i, rule.TypeString)
		}

		validRules = append(validRules, rule)
	}

	r.rules = validRules
	logf(LogInfo, "🔄 DNS重写器加载完成: %d条规则", len(validRules))
	return nil
}

func (r *DNSRewriter) Rewrite(domain string) (string, bool) {
	if !r.HasRules() || len(domain) > RFCMaxDomainNameLength {
		return domain, false
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	for i := range r.rules {
		rule := &r.rules[i]
		if matched, result := r.matchRule(rule, domain); matched {
			result = dns.Fqdn(result)
			logf(LogDebug, "🔄 域名重写: %s -> %s", domain, result)
			return result, true
		}
	}
	return domain, false
}

func (r *DNSRewriter) matchRule(rule *RewriteRule, domain string) (bool, string) {
	switch rule.Type {
	case RewriteExact:
		if domain == strings.ToLower(rule.Pattern) {
			return true, rule.Replacement
		}
	case RewriteSuffix:
		pattern := strings.ToLower(rule.Pattern)
		if domain == pattern || strings.HasSuffix(domain, "."+pattern) {
			if strings.Contains(rule.Replacement, "$1") {
				if domain == pattern {
					return true, strings.ReplaceAll(rule.Replacement, "$1", "")
				} else {
					prefix := strings.TrimSuffix(domain, "."+pattern)
					return true, strings.TrimSuffix(strings.ReplaceAll(rule.Replacement, "$1", prefix+"."), ".")
				}
			}
			return true, rule.Replacement
		}
	case RewritePrefix:
		pattern := strings.ToLower(rule.Pattern)
		if strings.HasPrefix(domain, pattern) {
			if strings.Contains(rule.Replacement, "$1") {
				suffix := strings.TrimPrefix(domain, pattern)
				return true, strings.ReplaceAll(rule.Replacement, "$1", suffix)
			}
			return true, rule.Replacement
		}
	case RewriteRegex:
		if rule.regex.MatchString(domain) {
			result := rule.regex.ReplaceAllString(domain, rule.Replacement)
			return true, result
		}
	}
	return false, ""
}

// ==================== DNS劫持预防检查器 ====================

type DNSHijackPrevention struct {
	enabled bool
}

func NewDNSHijackPrevention(enabled bool) *DNSHijackPrevention {
	return &DNSHijackPrevention{enabled: enabled}
}

func (shp *DNSHijackPrevention) IsEnabled() bool {
	return shp.enabled
}

func (shp *DNSHijackPrevention) CheckResponse(currentDomain, queryDomain string, response *dns.Msg) (bool, string) {
	if !shp.enabled || response == nil {
		return true, ""
	}

	currentDomain = strings.ToLower(strings.TrimSuffix(currentDomain, "."))
	queryDomain = strings.ToLower(strings.TrimSuffix(queryDomain, "."))

	// 检查根服务器是否越权返回最终记录
	if currentDomain == "" && queryDomain != "" {
		// 添加根服务器查询的例外处理
		isRootServerQuery := strings.HasSuffix(queryDomain, ".root-servers.net") || queryDomain == "root-servers.net"

		for _, rr := range response.Answer {
			answerName := strings.ToLower(strings.TrimSuffix(rr.Header().Name, "."))
			if answerName == queryDomain {
				// 跳过委托记录
				if rr.Header().Rrtype == dns.TypeNS || rr.Header().Rrtype == dns.TypeDS {
					continue
				}

				// 允许根服务器返回自身的A/AAAA记录
				if isRootServerQuery && (rr.Header().Rrtype == dns.TypeA || rr.Header().Rrtype == dns.TypeAAAA) {
					continue
				}

				recordType := dns.TypeToString[rr.Header().Rrtype]
				reason := fmt.Sprintf("根服务器越权返回了 '%s' 的%s记录", queryDomain, recordType)
				logf(LogDebug, "🚨 检测到DNS劫持: %s", reason)
				return false, reason
			}
		}
	}
	return true, ""
}

// ==================== 上游服务器管理 ====================

// UpstreamServer 上游服务器配置
type UpstreamServer struct {
	Address string `json:"address"`
	Policy  string `json:"policy"`
}

func (u *UpstreamServer) IsRecursive() bool {
	return strings.ToLower(u.Address) == RecursiveServerIndicator
}

func (u *UpstreamServer) ShouldTrustResult(hasTrustedIP, hasUntrustedIP bool) bool {
	switch u.Policy {
	case "all":
		return true
	case "trusted_only":
		return hasTrustedIP && !hasUntrustedIP
	case "untrusted_only":
		return !hasTrustedIP
	default:
		return true
	}
}

type UpstreamManager struct {
	servers []*UpstreamServer
	mu      sync.RWMutex
}

func NewUpstreamManager(servers []UpstreamServer) *UpstreamManager {
	activeServers := make([]*UpstreamServer, 0, len(servers))

	for i := range servers {
		server := &servers[i]
		activeServers = append(activeServers, server)
	}

	return &UpstreamManager{
		servers: activeServers,
	}
}

func (um *UpstreamManager) GetServers() []*UpstreamServer {
	um.mu.RLock()
	defer um.mu.RUnlock()
	return um.servers
}

// ==================== 服务器配置 ====================

type ServerConfig struct {
	Server struct {
		Port            string `json:"port"`
		IPv6            bool   `json:"ipv6"`
		DefaultECS      string `json:"default_ecs_subnet"`
		TrustedCIDRFile string `json:"trusted_cidr_file"`
	} `json:"server"`

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
	} `json:"performance"`

	Logging struct {
		Level string `json:"level"`
	} `json:"logging"`

	Features struct {
		ServeStale       bool `json:"serve_stale"`
		Prefetch         bool `json:"prefetch"`
		DNSSEC           bool `json:"dnssec"`
		HijackProtection bool `json:"hijack_protection"`
	} `json:"features"`

	Redis struct {
		Address   string `json:"address"`
		Password  string `json:"password"`
		Database  int    `json:"database"`
		KeyPrefix string `json:"key_prefix"`
	} `json:"redis"`

	Upstream []UpstreamServer `json:"upstream"`
	Rewrite  []RewriteRule    `json:"rewrite"`
}

// 配置管理和验证
func loadConfig(filename string) (*ServerConfig, error) {
	config := getDefaultConfig()

	if filename == "" {
		logf(LogInfo, "📄 使用默认配置")
		return config, nil
	}

	if !isValidFilePath(filename) {
		return nil, fmt.Errorf("无效的配置文件路径: %s", filename)
	}

	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("读取配置文件失败: %w", err)
	}

	if len(data) > MaxConfigFileSize {
		return nil, fmt.Errorf("配置文件过大: %d bytes", len(data))
	}

	if err := json.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("解析配置文件失败: %w", err)
	}

	logf(LogInfo, "📄 配置文件加载成功: %s", filename)
	return config, validateConfig(config)
}

func validateConfig(config *ServerConfig) error {
	// 验证日志级别
	validLevels := map[string]LogLevel{
		"none": LogNone, "error": LogError, "warn": LogWarn,
		"info": LogInfo, "debug": LogDebug,
	}
	if level, ok := validLevels[strings.ToLower(config.Logging.Level)]; ok {
		logConfig.level = level
	} else {
		return fmt.Errorf("无效的日志级别: %s", config.Logging.Level)
	}

	// 验证网络配置
	if config.Server.DefaultECS != "" {
		ecs := strings.ToLower(config.Server.DefaultECS)
		validPresets := []string{"auto", "auto_v4", "auto_v6"}
		isPreset := false
		for _, preset := range validPresets {
			if ecs == preset {
				isPreset = true
				break
			}
		}
		if !isPreset {
			if _, _, err := net.ParseCIDR(config.Server.DefaultECS); err != nil {
				return fmt.Errorf("ECS子网格式错误: %w", err)
			}
		}
	}

	// 验证TTL配置
	if config.TTL.MinTTL > 0 && config.TTL.MaxTTL > 0 && config.TTL.MinTTL > config.TTL.MaxTTL {
		return errors.New("最小TTL不能大于最大TTL")
	}

	// 验证上游服务器配置
	for i, server := range config.Upstream {
		if !server.IsRecursive() {
			if _, _, err := net.SplitHostPort(server.Address); err != nil {
				return fmt.Errorf("上游服务器 %d 地址格式错误: %w", i, err)
			}
		}
		validPolicies := map[string]bool{"all": true, "trusted_only": true, "untrusted_only": true}
		if !validPolicies[server.Policy] {
			return fmt.Errorf("上游服务器 %d 信任策略无效: %s", i, server.Policy)
		}
	}

	// 验证Redis配置
	if config.Redis.Address != "" {
		if _, _, err := net.SplitHostPort(config.Redis.Address); err != nil {
			return fmt.Errorf("Redis地址格式错误: %w", err)
		}
	} else {
		if config.Features.ServeStale {
			logf(LogWarn, "⚠️ 无缓存模式下禁用过期缓存服务功能")
			config.Features.ServeStale = false
		}
		if config.Features.Prefetch {
			logf(LogWarn, "⚠️ 无缓存模式下禁用预取功能")
			config.Features.Prefetch = false
		}
	}

	return nil
}

func getDefaultConfig() *ServerConfig {
	config := &ServerConfig{}

	config.Server.Port = DNSServerPort
	config.Server.IPv6 = true
	config.Server.DefaultECS = "auto"

	config.TTL.DefaultTTL = DefaultCacheTTL
	config.TTL.MinTTL = MinCacheTTL
	config.TTL.MaxTTL = MaxCacheTTL
	config.TTL.StaleTTL = StaleCacheTTL
	config.TTL.StaleMaxAge = StaleCacheMaxAge

	config.Performance.MaxConcurrency = DefaultServerMaxConcurrency
	config.Performance.ConnPoolSize = DefaultConnectionPoolSize
	config.Performance.QueryTimeout = int(DefaultQueryTimeout / time.Second)

	config.Logging.Level = "info"

	config.Features.ServeStale = false
	config.Features.Prefetch = false
	config.Features.DNSSEC = true
	config.Features.HijackProtection = false

	config.Redis.Address = ""
	config.Redis.Password = ""
	config.Redis.Database = 0
	config.Redis.KeyPrefix = "zjdns:"

	config.Upstream = []UpstreamServer{}
	config.Rewrite = []RewriteRule{}

	return config
}

// ==================== 工具函数 ====================

func isValidFilePath(path string) bool {
	if strings.Contains(path, "..") ||
		strings.HasPrefix(path, "/etc/") ||
		strings.HasPrefix(path, "/proc/") ||
		strings.HasPrefix(path, "/sys/") {
		return false
	}

	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.Mode().IsRegular()
}

func generateExampleConfig() string {
	config := getDefaultConfig()
	config.Server.DefaultECS = "auto"
	config.Server.TrustedCIDRFile = "trusted_cidr.txt"
	config.Redis.Address = "127.0.0.1:6379"
	config.Features.ServeStale = true
	config.Features.Prefetch = true
	config.Features.HijackProtection = true

	config.Upstream = []UpstreamServer{
		{
			Address: "8.8.8.8:53",
			Policy:  "all",
		},
		{
			Address: "114.114.114.114:53",
			Policy:  "trusted_only",
		},
		{
			Address: "recursive",
			Policy:  "all",
		},
	}

	config.Rewrite = []RewriteRule{
		{
			TypeString:  "exact",
			Pattern:     "blocked.example.com",
			Replacement: "127.0.0.1",
		},
		{
			TypeString:  "suffix",
			Pattern:     "ads.example.com",
			Replacement: "127.0.0.1",
		},
	}

	data, _ := json.MarshalIndent(config, "", "  ")
	return string(data)
}

// ==================== TTL计算器 ====================

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

// ==================== DNS记录结构 ====================

type CompactDNSRecord struct {
	Text    string `json:"text"`
	OrigTTL uint32 `json:"orig_ttl"`
	Type    uint16 `json:"type"`
}

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

	seen := globalPoolManager.GetStringMap()
	defer globalPoolManager.PutStringMap(seen)

	result := make([]*CompactDNSRecord, 0, len(rrs))
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
	return result
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

// ==================== 缓存条目结构 ====================

type CacheEntry struct {
	Answer          []*CompactDNSRecord `json:"answer"`
	Authority       []*CompactDNSRecord `json:"authority"`
	Additional      []*CompactDNSRecord `json:"additional"`
	TTL             int                 `json:"ttl"`
	Timestamp       int64               `json:"timestamp"`
	Validated       bool                `json:"validated"`
	AccessTime      int64               `json:"access_time"`
	RefreshTime     int64               `json:"refresh_time"`
	ECSFamily       uint16              `json:"ecs_family,omitempty"`
	ECSSourcePrefix uint8               `json:"ecs_source_prefix,omitempty"`
	ECSScopePrefix  uint8               `json:"ecs_scope_prefix,omitempty"`
	ECSAddress      string              `json:"ecs_address,omitempty"`
	LastUpdateTime  int64               `json:"last_update_time,omitempty"`
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
		(now-c.Timestamp) > int64(c.TTL+CacheRefreshThreshold) &&
		(now-c.RefreshTime) > CacheRefreshRetryInterval
}

func (c *CacheEntry) ShouldUpdateAccessInfo() bool {
	now := time.Now().UnixMilli()
	return now-c.LastUpdateTime > CacheAccessThrottleMs
}

func (c *CacheEntry) GetRemainingTTL(staleTTL int) uint32 {
	now := time.Now().Unix()
	elapsed := now - c.Timestamp
	remaining := int64(c.TTL) - elapsed

	if remaining > 0 {
		return uint32(remaining)
	}

	// 计算stale TTL
	staleElapsed := elapsed - int64(c.TTL)
	staleCycle := staleElapsed % int64(staleTTL)
	staleTTLRemaining := int64(staleTTL) - staleCycle

	if staleTTLRemaining <= 0 {
		staleTTLRemaining = int64(staleTTL)
	}

	return uint32(staleTTLRemaining)
}

func (c *CacheEntry) ShouldBeDeleted(maxAge int) bool {
	now := time.Now().Unix()
	totalAge := now - c.Timestamp
	return totalAge > int64(c.TTL+maxAge)
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

// ==================== 刷新请求结构 ====================

type RefreshRequest struct {
	Question            dns.Question
	ECS                 *ECSOption
	CacheKey            string
	ServerDNSSECEnabled bool
}

// ==================== 缓存接口和实现 ====================

type DNSCache interface {
	Get(key string) (*CacheEntry, bool, bool)
	Set(key string, answer, authority, additional []dns.RR, validated bool, ecs *ECSOption)
	RequestRefresh(req RefreshRequest)
	Shutdown()
}

// 空缓存实现
type NullCache struct{}

func NewNullCache() *NullCache {
	logf(LogInfo, "🚫 无缓存模式")
	return &NullCache{}
}

func (nc *NullCache) Get(key string) (*CacheEntry, bool, bool) { return nil, false, false }
func (nc *NullCache) Set(key string, answer, authority, additional []dns.RR, validated bool, ecs *ECSOption) {
}
func (nc *NullCache) RequestRefresh(req RefreshRequest) {}
func (nc *NullCache) Shutdown()                         {}

// ==================== Redis缓存实现 ====================

type RedisDNSCache struct {
	client       *redis.Client
	config       *ServerConfig
	ttlCalc      *TTLCalculator
	keyPrefix    string
	refreshQueue chan RefreshRequest
	ctx          context.Context
	cancel       context.CancelFunc
	wg           sync.WaitGroup
	bgManager    *BackgroundTaskManager
	server       *RecursiveDNSServer // 查询接口
}

func NewRedisDNSCache(config *ServerConfig, server *RecursiveDNSServer) (*RedisDNSCache, error) {
	rdb := redis.NewClient(&redis.Options{
		Addr:         config.Redis.Address,
		Password:     config.Redis.Password,
		DB:           config.Redis.Database,
		PoolSize:     RedisConnectionPoolSize,
		MinIdleConns: RedisMinIdleConnections,
		MaxRetries:   RedisMaxRetryAttempts,
		PoolTimeout:  RedisConnectionPoolTimeout,
		ReadTimeout:  RedisReadOperationTimeout,
		WriteTimeout: RedisWriteOperationTimeout,
		DialTimeout:  RedisDialTimeout,
	})

	ctx, cancel := context.WithTimeout(context.Background(), StandardOperationTimeout)
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
		refreshQueue: make(chan RefreshRequest, CacheRefreshQueueSize),
		ctx:          cacheCtx,
		cancel:       cacheCancel,
		bgManager:    NewBackgroundTaskManager(),
		server:       server,
	}

	if config.Features.ServeStale && config.Features.Prefetch {
		cache.startRefreshProcessor()
	}

	logf(LogInfo, "✅ Redis缓存系统初始化完成")
	return cache, nil
}

func (rc *RedisDNSCache) startRefreshProcessor() {
	workerCount := runtime.NumCPU()
	if workerCount > CacheRefreshWorkerCount {
		workerCount = CacheRefreshWorkerCount
	}

	for i := 0; i < workerCount; i++ {
		rc.wg.Add(1)
		go func(workerID int) {
			defer rc.wg.Done()
			defer recoverPanic(fmt.Sprintf("Redis刷新Worker %d", workerID))

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
	defer recoverPanic("Redis刷新请求处理")

	logf(LogDebug, "🔄 开始处理刷新请求: %s", req.CacheKey)

	// 执行查询
	answer, authority, additional, validated, ecsResponse, err := rc.server.QueryForRefresh(
		req.Question, req.ECS, req.ServerDNSSECEnabled)

	if err != nil {
		logf(LogDebug, "🔄 刷新查询失败: %s - %v", req.CacheKey, err)
		rc.updateRefreshTime(req.CacheKey)
		return
	}

	// 计算新的TTL并更新缓存
	allRRs := make([]dns.RR, 0, len(answer)+len(authority)+len(additional))
	allRRs = append(allRRs, answer...)
	allRRs = append(allRRs, authority...)
	allRRs = append(allRRs, additional...)

	cacheTTL := rc.ttlCalc.CalculateCacheTTL(allRRs)
	now := time.Now().Unix()

	entry := &CacheEntry{
		Answer:         compactRRs(answer),
		Authority:      compactRRs(authority),
		Additional:     compactRRs(additional),
		TTL:            cacheTTL,
		Timestamp:      now,
		Validated:      validated,
		AccessTime:     now,
		RefreshTime:    now,
		LastUpdateTime: time.Now().UnixMilli(),
	}

	if ecsResponse != nil {
		entry.ECSFamily = ecsResponse.Family
		entry.ECSSourcePrefix = ecsResponse.SourcePrefix
		entry.ECSScopePrefix = ecsResponse.ScopePrefix
		entry.ECSAddress = ecsResponse.Address.String()
	}

	// 存储到Redis
	data, err := json.Marshal(entry)
	if err != nil {
		logf(LogWarn, "⚠️ 刷新缓存序列化失败: %v", err)
		return
	}

	fullKey := rc.keyPrefix + req.CacheKey
	expiration := time.Duration(cacheTTL) * time.Second
	if rc.config.Features.ServeStale {
		expiration += time.Duration(rc.config.TTL.StaleMaxAge) * time.Second
	}

	if err := rc.client.Set(rc.ctx, fullKey, data, expiration).Err(); err != nil {
		logf(LogWarn, "⚠️ 刷新缓存存储失败: %v", err)
		return
	}

	logf(LogDebug, "✅ 缓存刷新完成: %s (TTL: %ds, 答案: %d条)", req.CacheKey, cacheTTL, len(answer))
}

func (rc *RedisDNSCache) updateRefreshTime(cacheKey string) {
	defer recoverPanic("更新刷新时间")

	fullKey := rc.keyPrefix + cacheKey
	data, err := rc.client.Get(rc.ctx, fullKey).Result()
	if err != nil {
		return
	}

	var entry CacheEntry
	if err := json.Unmarshal(unsafe.Slice(unsafe.StringData(data), len(data)), &entry); err != nil {
		return
	}

	now := time.Now().Unix()
	entry.RefreshTime = now
	entry.LastUpdateTime = time.Now().UnixMilli()

	updatedData, err := json.Marshal(entry)
	if err != nil {
		return
	}

	rc.client.Set(rc.ctx, fullKey, updatedData, redis.KeepTTL)
}

func (rc *RedisDNSCache) Get(key string) (*CacheEntry, bool, bool) {
	defer recoverPanic("Redis缓存获取")

	fullKey := rc.keyPrefix + key
	data, err := rc.client.Get(rc.ctx, fullKey).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, false, false
		}
		return nil, false, false
	}

	var entry CacheEntry
	if err := json.Unmarshal(unsafe.Slice(unsafe.StringData(data), len(data)), &entry); err != nil {
		return nil, false, false
	}

	// 检查是否应该完全删除
	if entry.ShouldBeDeleted(rc.config.TTL.StaleMaxAge) {
		rc.bgManager.SubmitTask(func() {
			rc.client.Del(rc.ctx, fullKey)
		})
		return nil, false, false
	}

	// 更新访问信息（节流）
	if entry.ShouldUpdateAccessInfo() {
		entry.AccessTime = time.Now().Unix()
		entry.LastUpdateTime = time.Now().UnixMilli()
		rc.bgManager.SubmitTask(func() { rc.updateAccessInfo(fullKey, &entry) })
	}

	isExpired := entry.IsExpired()

	// 如果不支持stale服务且已过期，删除缓存
	if !rc.config.Features.ServeStale && isExpired {
		rc.bgManager.SubmitTask(func() { rc.client.Del(rc.ctx, fullKey) })
		return nil, false, false
	}

	return &entry, true, isExpired
}

func (rc *RedisDNSCache) Set(key string, answer, authority, additional []dns.RR, validated bool, ecs *ECSOption) {
	defer recoverPanic("Redis缓存设置")

	allRRs := make([]dns.RR, 0, len(answer)+len(authority)+len(additional))
	allRRs = append(allRRs, answer...)
	allRRs = append(allRRs, authority...)
	allRRs = append(allRRs, additional...)

	cacheTTL := rc.ttlCalc.CalculateCacheTTL(allRRs)
	now := time.Now().Unix()

	entry := &CacheEntry{
		Answer:         compactRRs(answer),
		Authority:      compactRRs(authority),
		Additional:     compactRRs(additional),
		TTL:            cacheTTL,
		Timestamp:      now,
		Validated:      validated,
		AccessTime:     now,
		RefreshTime:    0,
		LastUpdateTime: time.Now().UnixMilli(),
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
	if rc.config.Features.ServeStale {
		expiration += time.Duration(rc.config.TTL.StaleMaxAge) * time.Second
	}

	rc.client.Set(rc.ctx, fullKey, data, expiration)
	logf(LogDebug, "💾 Redis缓存记录: %s (TTL: %ds)", key, cacheTTL)
}

func (rc *RedisDNSCache) updateAccessInfo(fullKey string, entry *CacheEntry) {
	defer recoverPanic("Redis访问信息更新")
	data, err := json.Marshal(entry)
	if err != nil {
		return
	}
	rc.client.Set(rc.ctx, fullKey, data, redis.KeepTTL)
}

func (rc *RedisDNSCache) RequestRefresh(req RefreshRequest) {
	select {
	case rc.refreshQueue <- req:
	default:
		logf(LogDebug, "刷新队列已满，跳过刷新请求")
	}
}

func (rc *RedisDNSCache) Shutdown() {
	logf(LogInfo, "🛑 正在关闭Redis缓存系统...")
	rc.bgManager.Shutdown()
	rc.cancel()
	close(rc.refreshQueue)

	done := make(chan struct{})
	go func() {
		rc.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(BackgroundTaskTimeout):
		logf(LogWarn, "Redis缓存关闭超时")
	}

	rc.client.Close()
	logf(LogInfo, "✅ Redis缓存系统已安全关闭")
}

// ==================== 连接池 ====================

type ConnectionPool struct {
	clients     chan *dns.Client
	timeout     time.Duration
	currentSize int64
}

func NewConnectionPool(config *ServerConfig) *ConnectionPool {
	poolSize := config.Performance.ConnPoolSize
	timeout := time.Duration(config.Performance.QueryTimeout) * time.Second

	pool := &ConnectionPool{
		clients:     make(chan *dns.Client, poolSize),
		timeout:     timeout,
		currentSize: 0,
	}

	// 使用动态池，初始为空，按需创建
	return pool
}

func (cp *ConnectionPool) createClient() *dns.Client {
	return &dns.Client{
		Timeout: cp.timeout,
		Net:     "udp",
		UDPSize: UDPUpstreamBufferSize,
	}
}

func (cp *ConnectionPool) Get() *dns.Client {
	select {
	case client := <-cp.clients:
		return client
	default:
		return cp.createClient()
	}
}

func (cp *ConnectionPool) GetTCP() *dns.Client {
	return &dns.Client{
		Timeout: cp.timeout,
		Net:     "tcp",
	}
}

func (cp *ConnectionPool) Put(client *dns.Client) {
	select {
	case cp.clients <- client:
	default:
		// 池已满，丢弃客户端
	}
}

// ==================== DNSSEC验证器 ====================

type DNSSECValidator struct{}

func NewDNSSECValidator() *DNSSECValidator {
	return &DNSSECValidator{}
}

func (v *DNSSECValidator) HasDNSSECRecords(response *dns.Msg) bool {
	if response == nil {
		return false
	}

	for _, sections := range [][]dns.RR{response.Answer, response.Ns, response.Extra} {
		for _, rr := range sections {
			switch rr.(type) {
			case *dns.RRSIG, *dns.NSEC, *dns.NSEC3, *dns.DNSKEY, *dns.DS:
				return true
			}
		}
	}
	return false
}

func (v *DNSSECValidator) IsValidated(response *dns.Msg) bool {
	if response == nil {
		return false
	}
	return response.AuthenticatedData || v.HasDNSSECRecords(response)
}

func (v *DNSSECValidator) ValidateResponse(response *dns.Msg, dnssecOK bool) bool {
	if response == nil || !dnssecOK {
		return false
	}
	return v.IsValidated(response)
}

// ==================== 查询结果结构 ====================

type UpstreamResult struct {
	Response       *dns.Msg
	Server         *UpstreamServer
	Error          error
	Duration       time.Duration
	HasTrustedIP   bool
	HasUntrustedIP bool
	Trusted        bool
	Filtered       bool
	Validated      bool
}

// ==================== 主服务器 ====================

type RecursiveDNSServer struct {
	config            *ServerConfig
	cache             DNSCache
	rootServersV4     []string
	rootServersV6     []string
	connPool          *ConnectionPool
	dnssecVal         *DNSSECValidator
	concurrencyLimit  chan struct{}
	ctx               context.Context
	cancel            context.CancelFunc
	shutdown          chan struct{}
	ipFilter          *IPFilter
	dnsRewriter       *DNSRewriter
	upstreamManager   *UpstreamManager
	wg                sync.WaitGroup
	backgroundManager *BackgroundTaskManager
	hijackPrevention  *DNSHijackPrevention

	// 新增的管理器
	ecsManager       *ECSManager
	messageBuilder   *DNSMessageBuilder
	queryManager     *QueryManager
	goroutineManager *GoroutineManager
}

// QueryForRefresh 为缓存刷新提供查询能力
func (r *RecursiveDNSServer) QueryForRefresh(question dns.Question, ecs *ECSOption, serverDNSSECEnabled bool) ([]dns.RR, []dns.RR, []dns.RR, bool, *ECSOption, error) {
	defer recoverPanic("缓存刷新查询")

	refreshCtx, cancel := context.WithTimeout(r.ctx, ExtendedQueryTimeout)
	defer cancel()

	servers := r.upstreamManager.GetServers()
	if len(servers) > 0 {
		return r.queryUpstreamServers(question, ecs, serverDNSSECEnabled, nil)
	} else {
		return r.resolveWithCNAME(refreshCtx, question, ecs, nil)
	}
}

func NewRecursiveDNSServer(config *ServerConfig) (*RecursiveDNSServer, error) {
	// Root servers
	rootServersV4 := []string{
		"198.41.0.4:" + DNSServerPort, "170.247.170.2:" + DNSServerPort, "192.33.4.12:" + DNSServerPort, "199.7.91.13:" + DNSServerPort,
		"192.203.230.10:" + DNSServerPort, "192.5.5.241:" + DNSServerPort, "192.112.36.4:" + DNSServerPort, "198.97.190.53:" + DNSServerPort,
		"192.36.148.17:" + DNSServerPort, "192.58.128.30:" + DNSServerPort, "193.0.14.129:" + DNSServerPort, "199.7.83.42:" + DNSServerPort, "202.12.27.33:" + DNSServerPort,
	}

	rootServersV6 := []string{
		"[2001:503:ba3e::2:30]:" + DNSServerPort, "[2801:1b8:10::b]:" + DNSServerPort, "[2001:500:2::c]:" + DNSServerPort, "[2001:500:2d::d]:" + DNSServerPort,
		"[2001:500:a8::e]:" + DNSServerPort, "[2001:500:2f::f]:" + DNSServerPort, "[2001:500:12::d0d]:" + DNSServerPort, "[2001:500:1::53]:" + DNSServerPort,
		"[2001:7fe::53]:" + DNSServerPort, "[2001:503:c27::2:30]:" + DNSServerPort, "[2001:7fd::1]:" + DNSServerPort, "[2001:500:9f::42]:" + DNSServerPort, "[2001:dc3::35]:" + DNSServerPort,
	}

	ctx, cancel := context.WithCancel(context.Background())

	// 创建ECS管理器
	ecsManager, err := NewECSManager(config.Server.DefaultECS)
	if err != nil {
		return nil, fmt.Errorf("ECS管理器初始化失败: %w", err)
	}

	// 创建IP过滤器
	ipFilter := NewIPFilter()
	if config.Server.TrustedCIDRFile != "" {
		if err := ipFilter.LoadCIDRs(config.Server.TrustedCIDRFile); err != nil {
			return nil, fmt.Errorf("加载可信CIDR文件失败: %w", err)
		}
	}

	// 创建DNS重写器
	dnsRewriter := NewDNSRewriter()
	if len(config.Rewrite) > 0 {
		if err := dnsRewriter.LoadRules(config.Rewrite); err != nil {
			return nil, fmt.Errorf("加载DNS重写规则失败: %w", err)
		}
	}

	// 创建上游管理器
	upstreamManager := NewUpstreamManager(config.Upstream)

	// 创建连接池
	connPool := NewConnectionPool(config)

	// 创建Goroutine管理器
	goroutineManager := NewGoroutineManager(config.Performance.MaxConcurrency)

	// 创建DNS消息构建器
	messageBuilder := NewDNSMessageBuilder(globalPoolManager, ecsManager)

	// 创建查询管理器
	queryManager := NewQueryManager(connPool, messageBuilder, goroutineManager,
		time.Duration(config.Performance.QueryTimeout)*time.Second)

	// 创建DNS劫持预防器
	hijackPrevention := NewDNSHijackPrevention(config.Features.HijackProtection)

	server := &RecursiveDNSServer{
		config:            config,
		rootServersV4:     rootServersV4,
		rootServersV6:     rootServersV6,
		connPool:          connPool,
		dnssecVal:         NewDNSSECValidator(),
		concurrencyLimit:  make(chan struct{}, config.Performance.MaxConcurrency),
		ctx:               ctx,
		cancel:            cancel,
		shutdown:          make(chan struct{}),
		ipFilter:          ipFilter,
		dnsRewriter:       dnsRewriter,
		upstreamManager:   upstreamManager,
		backgroundManager: NewBackgroundTaskManager(),
		hijackPrevention:  hijackPrevention,
		ecsManager:        ecsManager,
		messageBuilder:    messageBuilder,
		queryManager:      queryManager,
		goroutineManager:  goroutineManager,
	}

	// 创建缓存
	var cache DNSCache
	if config.Redis.Address == "" {
		cache = NewNullCache()
	} else {
		redisCache, err := NewRedisDNSCache(config, server)
		if err != nil {
			return nil, fmt.Errorf("Redis缓存初始化失败: %w", err)
		}
		cache = redisCache
	}

	server.cache = cache
	server.setupSignalHandling()
	return server, nil
}

func (r *RecursiveDNSServer) setupSignalHandling() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		defer recoverPanic("信号处理器")

		select {
		case sig := <-sigChan:
			logf(LogInfo, "🛑 收到信号 %v，开始优雅关闭...", sig)
			r.cancel()
			r.cache.Shutdown()
			r.backgroundManager.Shutdown()
			r.goroutineManager.Shutdown(GracefulShutdownTimeout)

			done := make(chan struct{})
			go func() {
				r.wg.Wait()
				close(done)
			}()

			select {
			case <-done:
				logf(LogInfo, "✅ 所有goroutine已安全关闭")
			case <-time.After(GracefulShutdownTimeout):
				logf(LogWarn, "⏰ goroutine关闭超时")
			}

			close(r.shutdown)
			time.Sleep(time.Second)
			os.Exit(0)

		case <-r.ctx.Done():
			return
		}
	}()
}

func (r *RecursiveDNSServer) getRootServers() []string {
	if r.config.Server.IPv6 {
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
	logf(LogInfo, "🌐 监听端口: %s", r.config.Server.Port)

	r.displayInfo()

	wg.Add(2)

	// UDP服务器
	go func() {
		defer wg.Done()
		defer recoverPanic("UDP服务器")

		server := &dns.Server{
			Addr:    ":" + r.config.Server.Port,
			Net:     "udp",
			Handler: dns.HandlerFunc(r.handleDNSRequest),
			UDPSize: UDPClientBufferSize,
		}
		logf(LogInfo, "📡 UDP服务器启动中...")
		if err := server.ListenAndServe(); err != nil {
			errChan <- fmt.Errorf("UDP启动失败: %w", err)
		}
	}()

	// TCP服务器
	go func() {
		defer wg.Done()
		defer recoverPanic("TCP服务器")

		server := &dns.Server{
			Addr:    ":" + r.config.Server.Port,
			Net:     "tcp",
			Handler: dns.HandlerFunc(r.handleDNSRequest),
		}
		logf(LogInfo, "🔌 TCP服务器启动中...")
		if err := server.ListenAndServe(); err != nil {
			errChan <- fmt.Errorf("TCP启动失败: %w", err)
		}
	}()

	time.Sleep(ServerStartupDelay)
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

func (r *RecursiveDNSServer) displayInfo() {
	servers := r.upstreamManager.GetServers()
	if len(servers) > 0 {
		for _, server := range servers {
			if server.IsRecursive() {
				logf(LogInfo, "🔗 上游服务器: 递归解析 - %s", server.Policy)
			} else {
				logf(LogInfo, "🔗 上游服务器: %s - %s", server.Address, server.Policy)
			}
		}
		logf(LogInfo, "🔗 上游模式: %d个服务器, 策略=prefer_trusted", len(servers))
	} else {
		if r.config.Redis.Address == "" {
			logf(LogInfo, "🚫 递归模式 (无缓存)")
		} else {
			logf(LogInfo, "💾 递归模式 + Redis缓存: %s", r.config.Redis.Address)
		}
	}

	if r.ipFilter.HasData() {
		logf(LogInfo, "🌍 IP过滤器: 已启用 (配置文件: %s)", r.config.Server.TrustedCIDRFile)
	}
	if r.dnsRewriter.HasRules() {
		logf(LogInfo, "🔄 DNS重写器: 已启用 (%d条规则)", len(r.config.Rewrite))
	}
	if r.config.Features.HijackProtection {
		logf(LogInfo, "🛡️ DNS劫持预防: 已启用")
	}
	if defaultECS := r.ecsManager.GetDefaultECS(); defaultECS != nil {
		logf(LogInfo, "🌍 默认ECS: %s/%d", defaultECS.Address, defaultECS.SourcePrefix)
	}

	logf(LogInfo, "⚡ 最大并发: %d", r.config.Performance.MaxConcurrency)
	logf(LogInfo, "📦 UDP缓冲区: 客户端=%d, 上游=%d", UDPClientBufferSize, UDPUpstreamBufferSize)
}

// handleDNSRequest 处理DNS请求的入口函数
func (r *RecursiveDNSServer) handleDNSRequest(w dns.ResponseWriter, req *dns.Msg) {
	// 使用安全执行器自动处理panic
	executor := NewSafeExecutor("DNS请求处理")
	executor.Execute(func() error {
		// 检查服务状态
		select {
		case <-r.ctx.Done():
			return nil
		default:
		}

		// 处理请求并写入响应
		response := r.processDNSQuery(req, getClientIP(w))
		return w.WriteMsg(response)
	})
}

// processDNSQuery 处理DNS查询的核心逻辑
func (r *RecursiveDNSServer) processDNSQuery(req *dns.Msg, clientIP net.IP) *dns.Msg {
	// 创建请求追踪器
	var tracker *RequestTracker
	if logConfig.level >= LogDebug {
		if len(req.Question) > 0 {
			question := req.Question[0]
			tracker = NewRequestTracker(
				question.Name,
				dns.TypeToString[question.Qtype],
				clientIP.String(),
			)
			defer tracker.Finish()
		}
	}

	// 构建基础响应
	msg := r.messageBuilder.BuildResponse(req)
	defer r.messageBuilder.ReleaseMessage(msg)

	// 验证请求基本格式
	if len(req.Question) == 0 {
		msg.Rcode = dns.RcodeFormatError
		if tracker != nil {
			tracker.AddStep("请求格式错误: 缺少问题部分")
		}
		return msg
	}

	question := req.Question[0]
	originalDomain := question.Name

	// 验证域名长度
	if len(question.Name) > RFCMaxDomainNameLength {
		logf(LogWarn, "拒绝过长域名查询: %d字符", len(question.Name))
		msg.Rcode = dns.RcodeFormatError
		if tracker != nil {
			tracker.AddStep("域名过长被拒绝: %d字符", len(question.Name))
		}
		return msg
	}

	if tracker != nil {
		tracker.AddStep("开始处理查询: %s %s", question.Name, dns.TypeToString[question.Qtype])
	}

	// DNS重写处理
	if r.dnsRewriter.HasRules() {
		if rewritten, changed := r.dnsRewriter.Rewrite(question.Name); changed {
			question.Name = rewritten
			if tracker != nil {
				tracker.AddStep("域名重写: %s -> %s", originalDomain, rewritten)
			}

			// 检查是否为直接IP重写
			if ip := net.ParseIP(strings.TrimSuffix(rewritten, ".")); ip != nil {
				return r.createDirectIPResponse(msg, originalDomain, question.Qtype, ip, tracker)
			}
		}
	}

	// 解析客户端EDNS0选项
	clientRequestedDNSSEC := false
	var ecsOpt *ECSOption

	if opt := req.IsEdns0(); opt != nil {
		clientRequestedDNSSEC = opt.Do()
		ecsOpt = r.ecsManager.ParseFromDNS(req)
		if tracker != nil && ecsOpt != nil {
			tracker.AddStep("客户端ECS: %s/%d", ecsOpt.Address, ecsOpt.SourcePrefix)
		}
	}

	// 使用默认ECS（如果客户端没有提供）
	if ecsOpt == nil {
		ecsOpt = r.ecsManager.GetDefaultECS()
		if tracker != nil && ecsOpt != nil {
			tracker.AddStep("使用默认ECS: %s/%d", ecsOpt.Address, ecsOpt.SourcePrefix)
		}
	}

	serverDNSSECEnabled := r.config.Features.DNSSEC
	cacheKey := r.buildCacheKey(question, ecsOpt, serverDNSSECEnabled)

	if tracker != nil {
		tracker.AddStep("缓存键: %s", cacheKey)
	}

	// 缓存查找
	if entry, found, isExpired := r.cache.Get(cacheKey); found {
		return r.handleCacheHit(msg, entry, isExpired, question, originalDomain,
			clientRequestedDNSSEC, cacheKey, ecsOpt, tracker)
	}

	// 缓存未命中，进行查询
	if tracker != nil {
		tracker.AddStep("缓存未命中，开始查询")
	}
	return r.handleCacheMiss(msg, question, originalDomain, ecsOpt,
		clientRequestedDNSSEC, serverDNSSECEnabled, cacheKey, tracker)
}

// createDirectIPResponse 创建直接IP响应（用于DNS重写）
func (r *RecursiveDNSServer) createDirectIPResponse(msg *dns.Msg, originalDomain string,
	qtype uint16, ip net.IP, tracker *RequestTracker) *dns.Msg {

	if tracker != nil {
		tracker.AddStep("创建直接IP响应: %s", ip.String())
	}

	if qtype == dns.TypeA && ip.To4() != nil {
		msg.Answer = []dns.RR{&dns.A{
			Hdr: dns.RR_Header{
				Name:   originalDomain,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    uint32(r.config.TTL.DefaultTTL),
			},
			A: ip,
		}}
	} else if qtype == dns.TypeAAAA && ip.To4() == nil {
		msg.Answer = []dns.RR{&dns.AAAA{
			Hdr: dns.RR_Header{
				Name:   originalDomain,
				Rrtype: dns.TypeAAAA,
				Class:  dns.ClassINET,
				Ttl:    uint32(r.config.TTL.DefaultTTL),
			},
			AAAA: ip,
		}}
	}
	return msg
}

// handleCacheHit 处理缓存命中
func (r *RecursiveDNSServer) handleCacheHit(msg *dns.Msg, entry *CacheEntry, isExpired bool,
	question dns.Question, originalDomain string, clientRequestedDNSSEC bool, cacheKey string,
	ecsOpt *ECSOption, tracker *RequestTracker) *dns.Msg {

	responseTTL := entry.GetRemainingTTL(r.config.TTL.StaleTTL)

	if tracker != nil {
		tracker.CacheHit = true
		if isExpired {
			tracker.AddStep("缓存命中(过期): TTL=%ds", responseTTL)
		} else {
			tracker.AddStep("缓存命中: TTL=%ds", responseTTL)
		}
	}

	// 设置响应内容
	msg.Answer = adjustTTL(filterDNSSECRecords(entry.GetAnswerRRs(), clientRequestedDNSSEC), responseTTL)
	msg.Ns = adjustTTL(filterDNSSECRecords(entry.GetAuthorityRRs(), clientRequestedDNSSEC), responseTTL)
	msg.Extra = adjustTTL(filterDNSSECRecords(entry.GetAdditionalRRs(), clientRequestedDNSSEC), responseTTL)

	// 设置EDNS0和ECS
	cachedECS := entry.GetECSOption()
	if clientRequestedDNSSEC || cachedECS != nil {
		r.ecsManager.AddToMessage(msg, cachedECS, entry.Validated && clientRequestedDNSSEC)
	}

	// 预取逻辑
	if isExpired && r.config.Features.ServeStale && r.config.Features.Prefetch && entry.ShouldRefresh() {
		if tracker != nil {
			tracker.AddStep("启动后台预取刷新")
		}
		r.cache.RequestRefresh(RefreshRequest{
			Question:            question,
			ECS:                 ecsOpt,
			CacheKey:            cacheKey,
			ServerDNSSECEnabled: r.config.Features.DNSSEC,
		})
	}

	// 恢复原始域名
	r.restoreOriginalDomain(msg, question.Name, originalDomain)
	return msg
}

// handleCacheMiss 处理缓存未命中
func (r *RecursiveDNSServer) handleCacheMiss(msg *dns.Msg, question dns.Question, originalDomain string,
	ecsOpt *ECSOption, clientRequestedDNSSEC bool, serverDNSSECEnabled bool, cacheKey string,
	tracker *RequestTracker) *dns.Msg {

	var answer, authority, additional []dns.RR
	var validated bool
	var ecsResponse *ECSOption
	var err error

	// 选择查询策略
	servers := r.upstreamManager.GetServers()
	if len(servers) > 0 {
		if tracker != nil {
			tracker.AddStep("使用上游服务器查询 (%d个可用)", len(servers))
		}
		answer, authority, additional, validated, ecsResponse, err = r.queryUpstreamServers(question, ecsOpt, serverDNSSECEnabled, tracker)
	} else {
		if tracker != nil {
			tracker.AddStep("使用递归解析")
		}
		ctx, cancel := context.WithTimeout(r.ctx, RecursiveQueryTimeout)
		defer cancel()
		answer, authority, additional, validated, ecsResponse, err = r.resolveWithCNAME(ctx, question, ecsOpt, tracker)
	}

	// 处理查询结果
	if err != nil {
		return r.handleQueryError(msg, err, cacheKey, originalDomain, question, clientRequestedDNSSEC, tracker)
	}

	return r.handleQuerySuccess(msg, question, originalDomain, ecsOpt, clientRequestedDNSSEC, cacheKey,
		answer, authority, additional, validated, ecsResponse, tracker)
}

// handleQueryError 处理查询错误
func (r *RecursiveDNSServer) handleQueryError(msg *dns.Msg, err error, cacheKey string,
	originalDomain string, question dns.Question, clientRequestedDNSSEC bool, tracker *RequestTracker) *dns.Msg {

	if tracker != nil {
		tracker.AddStep("查询失败: %v", err)
	}

	// 尝试使用过期缓存作为回退
	if r.config.Features.ServeStale {
		if entry, found, _ := r.cache.Get(cacheKey); found {
			if tracker != nil {
				tracker.AddStep("使用过期缓存回退")
			}

			responseTTL := uint32(r.config.TTL.StaleTTL)
			msg.Answer = adjustTTL(filterDNSSECRecords(entry.GetAnswerRRs(), clientRequestedDNSSEC), responseTTL)
			msg.Ns = adjustTTL(filterDNSSECRecords(entry.GetAuthorityRRs(), clientRequestedDNSSEC), responseTTL)
			msg.Extra = adjustTTL(filterDNSSECRecords(entry.GetAdditionalRRs(), clientRequestedDNSSEC), responseTTL)

			cachedECS := entry.GetECSOption()
			if clientRequestedDNSSEC || cachedECS != nil {
				r.ecsManager.AddToMessage(msg, cachedECS, entry.Validated && clientRequestedDNSSEC)
			}

			r.restoreOriginalDomain(msg, question.Name, originalDomain)
			return msg
		}
	}

	msg.Rcode = dns.RcodeServerFailure
	return msg
}

// handleQuerySuccess 处理查询成功
func (r *RecursiveDNSServer) handleQuerySuccess(msg *dns.Msg, question dns.Question, originalDomain string,
	ecsOpt *ECSOption, clientRequestedDNSSEC bool, cacheKey string, answer, authority, additional []dns.RR,
	validated bool, ecsResponse *ECSOption, tracker *RequestTracker) *dns.Msg {

	if tracker != nil {
		tracker.AddStep("查询成功: 答案=%d, 授权=%d, 附加=%d", len(answer), len(authority), len(additional))
		if validated {
			tracker.AddStep("DNSSEC验证通过")
		}
	}

	// 设置DNSSEC认证标志
	if r.config.Features.DNSSEC && validated {
		msg.AuthenticatedData = true
	}

	// 确定最终的ECS选项
	finalECS := ecsResponse
	if finalECS == nil && ecsOpt != nil {
		finalECS = &ECSOption{
			Family:       ecsOpt.Family,
			SourcePrefix: ecsOpt.SourcePrefix,
			ScopePrefix:  ecsOpt.SourcePrefix,
			Address:      ecsOpt.Address,
		}
	}

	// 存储到缓存
	r.cache.Set(cacheKey, answer, authority, additional, validated, finalECS)

	// 设置响应内容
	msg.Answer = filterDNSSECRecords(answer, clientRequestedDNSSEC)
	msg.Ns = filterDNSSECRecords(authority, clientRequestedDNSSEC)
	msg.Extra = filterDNSSECRecords(additional, clientRequestedDNSSEC)

	// 添加EDNS0选项
	if clientRequestedDNSSEC || finalECS != nil {
		r.ecsManager.AddToMessage(msg, finalECS, validated && clientRequestedDNSSEC)
	}

	// 恢复原始域名
	r.restoreOriginalDomain(msg, question.Name, originalDomain)
	return msg
}

// restoreOriginalDomain 恢复原始域名（用于DNS重写后的响应）
func (r *RecursiveDNSServer) restoreOriginalDomain(msg *dns.Msg, questionName, originalDomain string) {
	for _, rr := range msg.Answer {
		if strings.EqualFold(rr.Header().Name, questionName) {
			rr.Header().Name = originalDomain
		}
	}
}

// ==================== DNS查询实现 ====================

// queryUpstreamServers 查询上游服务器
func (r *RecursiveDNSServer) queryUpstreamServers(question dns.Question, ecs *ECSOption,
	serverDNSSECEnabled bool, tracker *RequestTracker) ([]dns.RR, []dns.RR, []dns.RR, bool, *ECSOption, error) {

	servers := r.upstreamManager.GetServers()
	if len(servers) == 0 {
		return nil, nil, nil, false, nil, errors.New("没有可用的上游服务器")
	}

	maxConcurrent := SingleQueryMaxConcurrency
	if maxConcurrent > len(servers) {
		maxConcurrent = len(servers)
	}

	if tracker != nil {
		tracker.AddStep("并发查询 %d 个上游服务器", maxConcurrent)
	}

	resultChan := make(chan UpstreamResult, maxConcurrent)
	ctx, cancel := context.WithTimeout(r.ctx, DefaultQueryTimeout)
	defer cancel()

	// 启动并发查询
	for i := 0; i < maxConcurrent && i < len(servers); i++ {
		server := servers[i]
		r.goroutineManager.ExecuteAsync(fmt.Sprintf("UpstreamQuery-%s", server.Address),
			func(ctx context.Context) error {
				result := r.queryUpstreamServer(ctx, server, question, ecs, serverDNSSECEnabled, tracker)
				select {
				case resultChan <- result:
				case <-ctx.Done():
				}
				return nil
			})
	}

	// 收集结果
	var results []UpstreamResult
	for i := 0; i < maxConcurrent; i++ {
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

	return r.selectUpstreamResult(results, question, tracker)
}

// queryUpstreamServer 查询单个上游服务器
func (r *RecursiveDNSServer) queryUpstreamServer(ctx context.Context, server *UpstreamServer,
	question dns.Question, ecs *ECSOption, serverDNSSECEnabled bool, tracker *RequestTracker) UpstreamResult {

	start := time.Now()
	result := UpstreamResult{
		Server:   server,
		Duration: 0,
	}

	if tracker != nil {
		tracker.AddStep("查询上游服务器: %s", server.Address)
	}

	if server.IsRecursive() {
		// 递归查询
		answer, authority, additional, validated, ecsResponse, err := r.resolveWithCNAME(ctx, question, ecs, tracker)
		result.Duration = time.Since(start)
		result.Error = err

		if err != nil {
			if tracker != nil {
				tracker.AddStep("递归解析失败: %v", err)
			}
			return result
		}

		// 构建响应
		response := globalPoolManager.GetDNSMessage()
		defer globalPoolManager.PutDNSMessage(response)

		response.Answer = answer
		response.Ns = authority
		response.Extra = additional
		response.Rcode = dns.RcodeSuccess

		if serverDNSSECEnabled {
			response.AuthenticatedData = validated
		}

		result.Response = response
		result.Validated = validated

		// 添加ECS选项到响应
		if ecsResponse != nil {
			r.ecsManager.AddToMessage(response, ecsResponse, serverDNSSECEnabled)
		}
	} else {
		// 上游服务器查询
		msg := r.messageBuilder.BuildQuery(question, ecs, serverDNSSECEnabled, true)
		defer r.messageBuilder.ReleaseMessage(msg)

		queryCtx, queryCancel := context.WithTimeout(ctx, StandardOperationTimeout)
		defer queryCancel()

		queryResult := r.queryManager.ExecuteQuery(queryCtx, msg, server.Address, tracker)
		result.Duration = time.Since(start)
		result.Response = queryResult.Response
		result.Error = queryResult.Error

		if result.Error != nil {
			if tracker != nil {
				tracker.AddStep("上游查询失败: %v", result.Error)
			}
			return result
		}

		if result.Response.Rcode != dns.RcodeSuccess {
			if tracker != nil {
				tracker.AddStep("上游返回错误: %s", dns.RcodeToString[result.Response.Rcode])
			}
			return result
		}

		if serverDNSSECEnabled {
			result.Validated = r.dnssecVal.ValidateResponse(result.Response, serverDNSSECEnabled)
		}
	}

	// 分析IP归属
	result.HasTrustedIP, result.HasUntrustedIP = r.ipFilter.AnalyzeIPs(result.Response.Answer)
	result.Trusted = server.ShouldTrustResult(result.HasTrustedIP, result.HasUntrustedIP)

	if r.ipFilter.HasData() {
		if !result.Trusted {
			result.Filtered = true
			if tracker != nil {
				tracker.AddStep("结果被过滤: %s (策略: %s)", server.Address, server.Policy)
			}
		}
	}

	if tracker != nil && result.Trusted {
		tracker.Upstream = server.Address
		tracker.AddStep("选择可信结果: %s (耗时: %v)", server.Address, result.Duration)
	}

	return result
}

// selectUpstreamResult 选择最佳上游查询结果
func (r *RecursiveDNSServer) selectUpstreamResult(results []UpstreamResult, question dns.Question,
	tracker *RequestTracker) ([]dns.RR, []dns.RR, []dns.RR, bool, *ECSOption, error) {

	var validResults []UpstreamResult
	var trustedResults []UpstreamResult

	// 分类结果
	for _, result := range results {
		if result.Error == nil && result.Response != nil && result.Response.Rcode == dns.RcodeSuccess {
			validResults = append(validResults, result)
			if result.Trusted && !result.Filtered {
				trustedResults = append(trustedResults, result)
			}
		}
	}

	if len(validResults) == 0 {
		return nil, nil, nil, false, nil, errors.New("没有有效的查询结果")
	}

	if tracker != nil {
		tracker.AddStep("有效结果: %d, 可信结果: %d", len(validResults), len(trustedResults))
	}

	var selectedResult UpstreamResult

	// 使用prefer_trusted策略
	if len(trustedResults) > 0 {
		selectedResult = trustedResults[0]
	} else {
		selectedResult = validResults[0]
	}

	sourceType := "上游"
	if selectedResult.Server.IsRecursive() {
		sourceType = "递归"
	}

	if tracker != nil {
		tracker.Upstream = selectedResult.Server.Address
		tracker.AddStep("最终选择%s结果: %s (策略: prefer_trusted)", sourceType, selectedResult.Server.Address)
	}

	// 解析ECS响应
	var ecsResponse *ECSOption
	if selectedResult.Response != nil {
		ecsResponse = r.ecsManager.ParseFromDNS(selectedResult.Response)
	}

	return selectedResult.Response.Answer, selectedResult.Response.Ns, selectedResult.Response.Extra,
		selectedResult.Validated, ecsResponse, nil
}

// ==================== 递归解析实现 ====================

// resolveWithCNAME 带CNAME跟踪的递归解析
func (r *RecursiveDNSServer) resolveWithCNAME(ctx context.Context, question dns.Question, ecs *ECSOption,
	tracker *RequestTracker) ([]dns.RR, []dns.RR, []dns.RR, bool, *ECSOption, error) {

	var allAnswers []dns.RR
	var finalAuthority, finalAdditional []dns.RR
	var finalECSResponse *ECSOption
	allValidated := true

	currentQuestion := question
	visitedCNAMEs := globalPoolManager.GetStringMap()
	defer globalPoolManager.PutStringMap(visitedCNAMEs)

	if tracker != nil {
		tracker.AddStep("开始CNAME链解析")
	}

	for i := 0; i < MaxCNAMEChainLength; i++ {
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

		if tracker != nil {
			tracker.AddStep("解析CNAME链第%d步: %s", i+1, currentQuestion.Name)
		}

		answer, authority, additional, validated, ecsResponse, err := r.recursiveQuery(ctx, currentQuestion, ecs, 0, false, tracker)
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

		// 检查CNAME链
		var nextCNAME *dns.CNAME
		hasTargetType := false

		for _, rr := range answer {
			if cname, ok := rr.(*dns.CNAME); ok {
				if strings.EqualFold(rr.Header().Name, currentQuestion.Name) {
					nextCNAME = cname
					if tracker != nil {
						tracker.AddStep("发现CNAME: %s -> %s", currentQuestion.Name, cname.Target)
					}
				}
			} else if rr.Header().Rrtype == currentQuestion.Qtype {
				hasTargetType = true
			}
		}

		// CNAME链结束条件
		if hasTargetType || currentQuestion.Qtype == dns.TypeCNAME || nextCNAME == nil {
			if tracker != nil {
				tracker.AddStep("CNAME链解析完成")
			}
			break
		}

		// 继续跟踪CNAME
		currentQuestion = dns.Question{
			Name:   nextCNAME.Target,
			Qtype:  question.Qtype,
			Qclass: question.Qclass,
		}
	}

	return allAnswers, finalAuthority, finalAdditional, allValidated, finalECSResponse, nil
}

// recursiveQuery 递归查询核心实现
func (r *RecursiveDNSServer) recursiveQuery(ctx context.Context, question dns.Question, ecs *ECSOption,
	depth int, forceTCP bool, tracker *RequestTracker) ([]dns.RR, []dns.RR, []dns.RR, bool, *ECSOption, error) {

	if depth > MaxRecursionDepth {
		return nil, nil, nil, false, nil, fmt.Errorf("递归深度超限: %d", depth)
	}

	qname := dns.Fqdn(question.Name)
	question.Name = qname
	nameservers := r.getRootServers()
	currentDomain := "."

	normalizedQname := strings.ToLower(strings.TrimSuffix(qname, "."))

	if tracker != nil {
		tracker.AddStep("递归查询开始: %s, 深度=%d, TCP=%v", normalizedQname, depth, forceTCP)
	}

	// 特殊处理根域名查询
	if normalizedQname == "" {
		response, err := r.queryNameserversConcurrent(ctx, nameservers, question, ecs, forceTCP, tracker)
		if err != nil {
			return nil, nil, nil, false, nil, fmt.Errorf("查询根域名失败: %w", err)
		}

		// DNS劫持预防检查
		if r.hijackPrevention.IsEnabled() {
			if valid, reason := r.hijackPrevention.CheckResponse(currentDomain, normalizedQname, response); !valid {
				return r.handleSuspiciousResponse(response, reason, forceTCP, tracker)
			}
		}

		validated := false
		if r.config.Features.DNSSEC {
			validated = r.dnssecVal.ValidateResponse(response, true)
		}

		var ecsResponse *ECSOption
		ecsResponse = r.ecsManager.ParseFromDNS(response)

		return response.Answer, response.Ns, response.Extra, validated, ecsResponse, nil
	}

	// 迭代查询循环
	for {
		select {
		case <-ctx.Done():
			return nil, nil, nil, false, nil, ctx.Err()
		default:
		}

		if tracker != nil {
			tracker.AddStep("查询授权服务器: %s (%d个NS)", currentDomain, len(nameservers))
		}

		response, err := r.queryNameserversConcurrent(ctx, nameservers, question, ecs, forceTCP, tracker)
		if err != nil {
			// 检查是否需要TCP重试
			if !forceTCP && strings.HasPrefix(err.Error(), "DNS_HIJACK_DETECTED") {
				if tracker != nil {
					tracker.AddStep("检测到DNS劫持，切换TCP模式重试")
				}
				return r.recursiveQuery(ctx, question, ecs, depth, true, tracker)
			}
			return nil, nil, nil, false, nil, fmt.Errorf("查询%s失败: %w", currentDomain, err)
		}

		// DNS劫持预防检查
		if r.hijackPrevention.IsEnabled() {
			if valid, reason := r.hijackPrevention.CheckResponse(currentDomain, normalizedQname, response); !valid {
				answer, authority, additional, validated, ecsResponse, err := r.handleSuspiciousResponse(response, reason, forceTCP, tracker)
				if err != nil && !forceTCP && strings.HasPrefix(err.Error(), "DNS_HIJACK_DETECTED") {
					if tracker != nil {
						tracker.AddStep("检测到DNS劫持，切换TCP模式重试")
					}
					return r.recursiveQuery(ctx, question, ecs, depth, true, tracker)
				}
				return answer, authority, additional, validated, ecsResponse, err
			}
		}

		validated := false
		if r.config.Features.DNSSEC {
			validated = r.dnssecVal.ValidateResponse(response, true)
		}

		var ecsResponse *ECSOption
		ecsResponse = r.ecsManager.ParseFromDNS(response)

		// 如果有答案，返回结果
		if len(response.Answer) > 0 {
			if tracker != nil {
				tracker.AddStep("获得最终答案: %d条记录", len(response.Answer))
			}
			return response.Answer, response.Ns, response.Extra, validated, ecsResponse, nil
		}

		// 寻找最佳NS记录匹配
		bestMatch := ""
		var bestNSRecords []*dns.NS

		for _, rr := range response.Ns {
			if ns, ok := rr.(*dns.NS); ok {
				nsName := strings.ToLower(strings.TrimSuffix(rr.Header().Name, "."))

				var isMatch bool
				if normalizedQname == nsName {
					isMatch = true
				} else if nsName != "" && strings.HasSuffix(normalizedQname, "."+nsName) {
					isMatch = true
				} else if nsName == "" && normalizedQname != "" {
					isMatch = true
				}

				if isMatch {
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
			if tracker != nil {
				tracker.AddStep("未找到匹配的NS记录，返回授权信息")
			}
			return nil, response.Ns, response.Extra, validated, ecsResponse, nil
		}

		// 循环检测
		currentDomainNormalized := strings.ToLower(strings.TrimSuffix(currentDomain, "."))
		if bestMatch == currentDomainNormalized && currentDomainNormalized != "" {
			if tracker != nil {
				tracker.AddStep("检测到查询循环，停止递归")
			}
			return nil, response.Ns, response.Extra, validated, ecsResponse, nil
		}

		currentDomain = bestMatch + "."
		var nextNS []string

		// 从Additional记录中查找NS地址
		for _, ns := range bestNSRecords {
			for _, rr := range response.Extra {
				switch a := rr.(type) {
				case *dns.A:
					if strings.EqualFold(a.Header().Name, ns.Ns) {
						nextNS = append(nextNS, net.JoinHostPort(a.A.String(), DNSServerPort))
					}
				case *dns.AAAA:
					if r.config.Server.IPv6 && strings.EqualFold(a.Header().Name, ns.Ns) {
						nextNS = append(nextNS, net.JoinHostPort(a.AAAA.String(), DNSServerPort))
					}
				}
			}
		}

		// 如果Additional中没有地址，需要单独解析NS
		if len(nextNS) == 0 {
			if tracker != nil {
				tracker.AddStep("Additional中无NS地址，开始解析NS记录")
			}
			nextNS = r.resolveNSAddressesConcurrent(ctx, bestNSRecords, qname, depth, forceTCP, tracker)
		}

		if len(nextNS) == 0 {
			if tracker != nil {
				tracker.AddStep("无法获取NS地址，返回授权信息")
			}
			return nil, response.Ns, response.Extra, validated, ecsResponse, nil
		}

		nameservers = nextNS
		if tracker != nil {
			tracker.AddStep("下一轮查询，切换到域: %s (%d个NS)", bestMatch, len(nextNS))
		}
	}
}

// handleSuspiciousResponse 处理可疑响应
func (r *RecursiveDNSServer) handleSuspiciousResponse(response *dns.Msg, reason string, currentlyTCP bool,
	tracker *RequestTracker) ([]dns.RR, []dns.RR, []dns.RR, bool, *ECSOption, error) {

	if !currentlyTCP {
		if tracker != nil {
			tracker.AddStep("检测到DNS劫持，将切换到TCP模式: %s", reason)
		}
		return nil, nil, nil, false, nil, fmt.Errorf("DNS_HIJACK_DETECTED: %s", reason)
	} else {
		if tracker != nil {
			tracker.AddStep("TCP模式下仍检测到DNS劫持，拒绝响应: %s", reason)
		}
		return nil, nil, nil, false, nil, fmt.Errorf("检测到DNS劫持(TCP模式): %s", reason)
	}
}

// queryNameserversConcurrent 并发查询nameserver
func (r *RecursiveDNSServer) queryNameserversConcurrent(ctx context.Context, nameservers []string,
	question dns.Question, ecs *ECSOption, forceTCP bool, tracker *RequestTracker) (*dns.Msg, error) {

	if len(nameservers) == 0 {
		return nil, errors.New("没有可用的nameserver")
	}

	// 获取并发控制信号量
	select {
	case r.concurrencyLimit <- struct{}{}:
		defer func() { <-r.concurrencyLimit }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	concurrency := len(nameservers)
	if concurrency > SingleQueryMaxConcurrency {
		concurrency = SingleQueryMaxConcurrency
	}

	if tracker != nil {
		tracker.AddStep("并发查询nameserver: %d个, TCP=%v", concurrency, forceTCP)
	}

	// 构建查询消息
	msg := r.messageBuilder.BuildQuery(question, ecs, r.config.Features.DNSSEC, false)
	defer r.messageBuilder.ReleaseMessage(msg)

	// 使用统一的查询管理器进行并发查询
	queryResult, err := r.queryManager.ExecuteConcurrentQuery(ctx, msg, nameservers[:concurrency],
		concurrency, tracker)

	if err != nil {
		return nil, err
	}

	return queryResult.Response, nil
}

// resolveNSAddressesConcurrent 并发解析NS地址
func (r *RecursiveDNSServer) resolveNSAddressesConcurrent(ctx context.Context, nsRecords []*dns.NS,
	qname string, depth int, forceTCP bool, tracker *RequestTracker) []string {

	resolveCount := len(nsRecords)
	if resolveCount > NameServerResolveMaxConcurrency {
		resolveCount = NameServerResolveMaxConcurrency
	}

	if tracker != nil {
		tracker.AddStep("并发解析%d个NS地址", resolveCount)
	}

	nsChan := make(chan []string, resolveCount)
	resolveCtx, resolveCancel := context.WithTimeout(ctx, StandardOperationTimeout)
	defer resolveCancel()

	// 启动NS解析goroutine
	for i := 0; i < resolveCount; i++ {
		ns := nsRecords[i]
		r.goroutineManager.ExecuteAsync(fmt.Sprintf("NSResolve-%s", ns.Ns),
			func(ctx context.Context) error {
				// 防止循环依赖
				if strings.EqualFold(strings.TrimSuffix(ns.Ns, "."), strings.TrimSuffix(qname, ".")) {
					select {
					case nsChan <- nil:
					case <-ctx.Done():
					}
					return nil
				}

				var addresses []string

				// 解析A记录
				nsQuestion := dns.Question{Name: dns.Fqdn(ns.Ns), Qtype: dns.TypeA, Qclass: dns.ClassINET}
				if nsAnswer, _, _, _, _, err := r.recursiveQuery(resolveCtx, nsQuestion, nil, depth+1, forceTCP, tracker); err == nil {
					for _, rr := range nsAnswer {
						if a, ok := rr.(*dns.A); ok {
							addresses = append(addresses, net.JoinHostPort(a.A.String(), DNSServerPort))
						}
					}
				}

				// 如果需要IPv6且IPv4解析失败，尝试AAAA记录
				if r.config.Server.IPv6 && len(addresses) == 0 {
					nsQuestionV6 := dns.Question{Name: dns.Fqdn(ns.Ns), Qtype: dns.TypeAAAA, Qclass: dns.ClassINET}
					if nsAnswerV6, _, _, _, _, err := r.recursiveQuery(resolveCtx, nsQuestionV6, nil, depth+1, forceTCP, tracker); err == nil {
						for _, rr := range nsAnswerV6 {
							if aaaa, ok := rr.(*dns.AAAA); ok {
								addresses = append(addresses, net.JoinHostPort(aaaa.AAAA.String(), DNSServerPort))
							}
						}
					}
				}

				select {
				case nsChan <- addresses:
				case <-ctx.Done():
				}
				return nil
			})
	}

	// 收集NS地址
	var allAddresses []string
	for i := 0; i < resolveCount; i++ {
		select {
		case addresses := <-nsChan:
			if len(addresses) > 0 {
				allAddresses = append(allAddresses, addresses...)
				if len(allAddresses) >= MaxNameServerResolveCount {
					resolveCancel()
					break
				}
			}
		case <-resolveCtx.Done():
			break
		}
	}

	if tracker != nil {
		tracker.AddStep("NS解析完成: 获得%d个地址", len(allAddresses))
	}

	return allAddresses
}

// ==================== 工具函数 ====================

// HasRules 检查是否有有效的重写规则
func (r *DNSRewriter) HasRules() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.rules) > 0
}

// getClientIP 获取客户端IP地址
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

// buildCacheKey 构建缓存键
func (r *RecursiveDNSServer) buildCacheKey(q dns.Question, ecs *ECSOption, serverDNSSECEnabled bool) string {
	builder := newCacheKeyBuilder()
	defer builder.Release()

	key := builder.AddDomain(q.Name).
		AddType(q.Qtype).
		AddClass(q.Qclass).
		AddECS(ecs).
		AddDNSSEC(serverDNSSECEnabled).
		String()

	return key
}

// adjustTTL 调整DNS记录的TTL
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

// filterDNSSECRecords 过滤DNSSEC记录
func filterDNSSECRecords(rrs []dns.RR, includeDNSSEC bool) []dns.RR {
	if includeDNSSEC || len(rrs) == 0 {
		return rrs
	}

	filtered := make([]dns.RR, 0, len(rrs))
	for _, rr := range rrs {
		switch rr.(type) {
		case *dns.RRSIG, *dns.NSEC, *dns.NSEC3, *dns.DNSKEY, *dns.DS:
			// 过滤DNSSEC记录
		default:
			filtered = append(filtered, rr)
		}
	}
	return filtered
}

// min 返回两个整数中的最小值
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ==================== 主函数 ====================

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
		fmt.Fprintf(os.Stderr, "  %s                         # 使用默认配置启动\n\n", os.Args[0])
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

	server, err := NewRecursiveDNSServer(config)
	if err != nil {
		customLogger.Fatalf("❌ 服务器创建失败: %v", err)
	}

	if err := server.Start(); err != nil {
		customLogger.Fatalf("❌ 服务器启动失败: %v", err)
	}
}
