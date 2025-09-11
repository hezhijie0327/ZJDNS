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

// ==================== 系统常量定义 ====================

// DNS服务相关常量
const (
	DNSServerPort            = "53"                // DNS标准端口
	RecursiveServerIndicator = "buildin_recursive" // 内置递归服务器标识
	UDPClientBufferSize      = 1232                // UDP客户端缓冲区大小
	UDPUpstreamBufferSize    = 4096                // UDP上游缓冲区大小
	RFCMaxDomainNameLength   = 253                 // RFC规定的最大域名长度
)

// 缓存系统常量
const (
	MaxCacheKeyLength         = 512    // 最大缓存键长度
	DefaultCacheTTL           = 3600   // 默认缓存TTL(秒)
	StaleTTL                  = 30     // 过期缓存TTL(秒)
	StaleMaxAge               = 604800 // 过期缓存最大保存时间(7天)
	CacheRefreshThreshold     = 300    // 缓存刷新阈值(秒)
	CacheAccessThrottleMs     = 100    // 缓存访问节流(毫秒)
	CacheRefreshQueueSize     = 1000   // 缓存刷新队列大小
	CacheRefreshWorkerCount   = 10     // 缓存刷新工作线程数
	CacheRefreshRetryInterval = 600    // 缓存刷新重试间隔(秒)
)

// 并发控制常量
const (
	MaxConcurrency                  = 1000 // 最大并发数
	ConnPoolSize                    = 100  // 连接池大小
	SingleQueryMaxConcurrency       = 5    // 单次查询最大并发数
	NameServerResolveMaxConcurrency = 3    // NS解析最大并发数
	TaskWorkerMaxCount              = 50   // 任务工作线程最大数量
	TaskWorkerQueueSize             = 1000 // 任务队列大小
)

// DNS解析常量
const (
	MaxCNAMEChainLength       = 16 // 最大CNAME链长度
	MaxRecursionDepth         = 16 // 最大递归深度
	MaxNameServerResolveCount = 3  // 最大NS解析数量
)

// 超时时间常量
const (
	QueryTimeout             = 5 * time.Second        // 查询超时
	StandardOperationTimeout = 5 * time.Second        // 标准操作超时
	RecursiveQueryTimeout    = 30 * time.Second       // 递归查询超时
	ExtendedQueryTimeout     = 25 * time.Second       // 扩展查询超时
	ServerStartupDelay       = 100 * time.Millisecond // 服务器启动延迟
	GracefulShutdownTimeout  = 10 * time.Second       // 优雅关闭超时
	TLSHandshakeTimeout      = 2 * time.Second        // TLS握手超时
	TaskExecutionTimeout     = 10 * time.Second       // 任务执行超时
)

// 内存管理常量
const (
	SmallSliceInitialCapacity  = 8    // 小切片初始容量
	MediumSliceInitialCapacity = 16   // 中等切片初始容量
	LargeSliceInitialCapacity  = 32   // 大切片初始容量
	SliceCapacity              = 100  // 通用切片容量
	MapInitialCapacity         = 32   // Map初始容量
	StackTraceBufferSize       = 4096 // 堆栈跟踪缓冲区大小
)

// 文件处理常量
const (
	MaxConfigFileSize       = 1024 * 1024 // 最大配置文件大小(1MB)
	MaxInputLineLength      = 128         // 最大输入行长度
	FileScannerBufferSize   = 64 * 1024   // 文件扫描器缓冲区
	FileScannerMaxTokenSize = 1024 * 1024 // 文件扫描器最大令牌大小
	MaxRegexPatternLength   = 100         // 最大正则表达式长度
	MaxDNSRewriteRules      = 100         // 最大DNS重写规则数
)

// Redis配置常量
const (
	RedisConnectionPoolSize    = 50              // Redis连接池大小
	RedisMinIdleConnections    = 10              // Redis最小空闲连接数
	RedisMaxRetryAttempts      = 3               // Redis最大重试次数
	RedisConnectionPoolTimeout = 5 * time.Second // Redis连接池超时
	RedisReadOperationTimeout  = 3 * time.Second // Redis读操作超时
	RedisWriteOperationTimeout = 3 * time.Second // Redis写操作超时
	RedisDialTimeout           = 5 * time.Second // Redis拨号超时
)

// IP检测常量
const (
	PublicIPDetectionTimeout = 3 * time.Second // 公网IP检测超时
	HTTPClientRequestTimeout = 5 * time.Second // HTTP客户端超时
	IPDetectionCacheExpiry   = 5 * time.Minute // IP检测缓存过期时间
	MaxTrustedIPv4CIDRs      = 1024            // 最大可信IPv4 CIDR数量
	MaxTrustedIPv6CIDRs      = 256             // 最大可信IPv6 CIDR数量
	DefaultECSIPv4PrefixLen  = 24              // 默认ECS IPv4前缀长度
	DefaultECSIPv6PrefixLen  = 64              // 默认ECS IPv6前缀长度
)

// ==================== 日志系统 ====================

// LogLevel 定义日志级别
type LogLevel int

const (
	LogNone  LogLevel = iota - 1 // 无日志
	LogError                     // 错误日志
	LogWarn                      // 警告日志
	LogInfo                      // 信息日志
	LogDebug                     // 调试日志
)

// ANSI颜色代码，用于控制台彩色输出
const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorYellow = "\033[33m"
	ColorGreen  = "\033[32m"
	ColorBlue   = "\033[34m"
	ColorGray   = "\033[37m"
)

// LogConfig 全局日志配置
type LogConfig struct {
	level     LogLevel // 当前日志级别
	useColor  bool     // 是否使用颜色
	useEmojis bool     // 是否使用表情符号
}

var (
	// 全局日志配置实例
	logConfig = &LogConfig{
		level:     LogWarn,
		useColor:  true,
		useEmojis: true,
	}
	// 自定义日志记录器
	customLogger = log.New(os.Stdout, "", 0)
)

// String 返回日志级别的字符串表示，支持颜色和表情符号
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

// logf 格式化日志输出函数
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

// recoverPanic 统一的panic恢复处理函数
func recoverPanic(operation string) {
	if r := recover(); r != nil {
		func() {
			defer func() {
				if r2 := recover(); r2 != nil {
					fmt.Fprintf(os.Stderr, "CRITICAL: Double panic in %s: %v (original: %v)\n", operation, r2, r)
				}
			}()

			logf(LogError, "🚨 Panic恢复 [%s]: %v", operation, r)
			buf := make([]byte, StackTraceBufferSize)
			n := runtime.Stack(buf, false)
			logf(LogError, "调用栈: %s", string(buf[:n]))
		}()
	}
}

// safeExecute 安全执行函数，自动处理panic
func safeExecute(operation string, fn func() error) error {
	defer func() {
		if r := recover(); r != nil {
			recoverPanic(operation)
		}
	}()
	return fn()
}

// ==================== 请求追踪系统 ====================

// RequestTracker 用于追踪单个DNS请求的完整处理过程
type RequestTracker struct {
	ID           string        // 请求唯一标识
	StartTime    time.Time     // 请求开始时间
	Domain       string        // 查询域名
	QueryType    string        // 查询类型
	ClientIP     string        // 客户端IP
	Steps        []string      // 处理步骤记录
	CacheHit     bool          // 是否命中缓存
	Upstream     string        // 使用的上游服务器
	ResponseTime time.Duration // 响应时间
	mu           sync.Mutex    // 并发保护
}

// CreateRequestTracker 创建新的请求追踪器
func CreateRequestTracker(domain, qtype, clientIP string) *RequestTracker {
	return &RequestTracker{
		ID:        generateRequestID(),
		StartTime: time.Now(),
		Domain:    domain,
		QueryType: qtype,
		ClientIP:  clientIP,
		Steps:     make([]string, 0, SmallSliceInitialCapacity),
	}
}

// AddStep 添加处理步骤记录
func (rt *RequestTracker) AddStep(step string, args ...interface{}) {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	timestamp := time.Since(rt.StartTime).String()
	stepMsg := fmt.Sprintf("[%s] %s", timestamp, fmt.Sprintf(step, args...))
	rt.Steps = append(rt.Steps, stepMsg)

	logf(LogDebug, "🔍 [%s] %s", rt.ID[:SmallSliceInitialCapacity], stepMsg)
}

// Finish 完成请求追踪并记录摘要
func (rt *RequestTracker) Finish() {
	rt.ResponseTime = time.Since(rt.StartTime)
	if logConfig.level >= LogInfo {
		rt.logSummary()
	}
}

// logSummary 记录请求处理摘要
func (rt *RequestTracker) logSummary() {
	cacheStatus := "MISS"
	if rt.CacheHit {
		cacheStatus = "HIT"
	}
	logf(LogInfo, "📊 [%s] 查询完成: %s %s | 缓存:%s | 耗时:%v | 上游:%s",
		rt.ID[:SmallSliceInitialCapacity], rt.Domain, rt.QueryType, cacheStatus, rt.ResponseTime, rt.Upstream)
}

// generateRequestID 生成唯一的请求ID
func generateRequestID() string {
	return fmt.Sprintf("%d_%d", time.Now().UnixNano(), runtime.NumGoroutine())
}

// ==================== 对象池管理 ====================

// ObjectPoolManager 管理各种对象的复用池，减少GC压力
type ObjectPoolManager struct {
	stringBuilders sync.Pool // 字符串构建器池
	rrSlices       sync.Pool // DNS记录切片池
	stringSlices   sync.Pool // 字符串切片池
	stringMaps     sync.Pool // 字符串映射池
	dnsMessages    sync.Pool // DNS消息池
}

// InitObjectPool 初始化对象池管理器
func InitObjectPool() *ObjectPoolManager {
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
	if builder.Cap() < LargeSliceInitialCapacity*MapInitialCapacity {
		pm.stringBuilders.Put(builder)
	}
}

// GetStringMap 获取字符串映射
func (pm *ObjectPoolManager) GetStringMap() map[string]bool {
	m := pm.stringMaps.Get().(map[string]bool)
	for k := range m {
		delete(m, k)
	}
	return m
}

// PutStringMap 归还字符串映射
func (pm *ObjectPoolManager) PutStringMap(m map[string]bool) {
	if len(m) < MaxDNSRewriteRules/2 {
		pm.stringMaps.Put(m)
	}
}

// GetDNSMessage 获取DNS消息
func (pm *ObjectPoolManager) GetDNSMessage() *dns.Msg {
	msg := pm.dnsMessages.Get().(*dns.Msg)
	*msg = dns.Msg{}
	return msg
}

// PutDNSMessage 归还DNS消息
func (pm *ObjectPoolManager) PutDNSMessage(msg *dns.Msg) {
	pm.dnsMessages.Put(msg)
}

// 全局对象池管理器实例
var globalPoolManager = InitObjectPool()

// ==================== 统一任务管理器 ====================

// TaskManager 统一的任务和协程管理器，替代原来的GoroutineManager和BackgroundTaskManager
type TaskManager struct {
	ctx           context.Context    // 上下文
	cancel        context.CancelFunc // 取消函数
	wg            sync.WaitGroup     // 等待组
	activeCount   int64              // 活跃协程数量
	maxGoroutines int64              // 最大协程数量
	semaphore     chan struct{}      // 信号量控制并发
	taskQueue     chan func()        // 后台任务队列
}

// CreateTaskManager 创建任务管理器
func CreateTaskManager(maxGoroutines int) *TaskManager {
	ctx, cancel := context.WithCancel(context.Background())

	if maxGoroutines <= 0 {
		maxGoroutines = MaxConcurrency
	}

	tm := &TaskManager{
		ctx:           ctx,
		cancel:        cancel,
		maxGoroutines: int64(maxGoroutines),
		semaphore:     make(chan struct{}, maxGoroutines),
		taskQueue:     make(chan func(), TaskWorkerQueueSize),
	}

	// 启动后台任务工作线程
	tm.startBackgroundWorkers()
	return tm
}

// startBackgroundWorkers 启动后台任务处理工作线程
func (tm *TaskManager) startBackgroundWorkers() {
	workers := runtime.NumCPU()
	if workers > TaskWorkerMaxCount {
		workers = TaskWorkerMaxCount
	}

	for i := 0; i < workers; i++ {
		tm.wg.Add(1)
		go func(workerID int) {
			defer tm.wg.Done()
			defer recoverPanic(fmt.Sprintf("TaskManager Worker %d", workerID))

			for {
				select {
				case task := <-tm.taskQueue:
					if task != nil {
						func() {
							defer recoverPanic(fmt.Sprintf("BackgroundTask in Worker %d", workerID))
							task()
						}()
					}
				case <-tm.ctx.Done():
					return
				}
			}
		}(i)
	}
}

// Execute 同步执行任务
func (tm *TaskManager) Execute(name string, fn func(ctx context.Context) error) error {
	select {
	case <-tm.ctx.Done():
		return tm.ctx.Err()
	default:
	}

	select {
	case tm.semaphore <- struct{}{}:
		defer func() { <-tm.semaphore }()
	case <-tm.ctx.Done():
		return tm.ctx.Err()
	}

	atomic.AddInt64(&tm.activeCount, 1)
	defer atomic.AddInt64(&tm.activeCount, -1)

	tm.wg.Add(1)
	defer tm.wg.Done()

	return safeExecute(fmt.Sprintf("Task-%s", name), func() error {
		return fn(tm.ctx)
	})
}

// ExecuteAsync 异步执行任务
func (tm *TaskManager) ExecuteAsync(name string, fn func(ctx context.Context) error) {
	go func() {
		if err := tm.Execute(name, fn); err != nil && err != context.Canceled {
			logf(LogError, "异步任务执行失败 [%s]: %v", name, err)
		}
	}()
}

// SubmitBackgroundTask 提交后台任务
func (tm *TaskManager) SubmitBackgroundTask(task func()) {
	select {
	case tm.taskQueue <- task:
	default:
		logf(LogWarn, "⚠️ 后台任务队列已满，跳过任务")
	}
}

// GetActiveCount 获取活跃协程数量
func (tm *TaskManager) GetActiveCount() int64 {
	return atomic.LoadInt64(&tm.activeCount)
}

// Shutdown 关闭任务管理器
func (tm *TaskManager) Shutdown(timeout time.Duration) error {
	logf(LogInfo, "🛑 正在关闭任务管理器...")

	tm.cancel()
	close(tm.taskQueue)

	done := make(chan struct{})
	go func() {
		tm.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		logf(LogInfo, "✅ 任务管理器已安全关闭")
		return nil
	case <-time.After(timeout):
		activeCount := tm.GetActiveCount()
		logf(LogWarn, "⏰ 任务管理器关闭超时，仍有 %d 个活跃协程", activeCount)
		return fmt.Errorf("shutdown timeout, %d goroutines still active", activeCount)
	}
}

// ==================== ECS管理器 ====================

// ECSOption ECS (EDNS Client Subnet) 选项配置
type ECSOption struct {
	Family       uint16 // 地址族 (1=IPv4, 2=IPv6)
	SourcePrefix uint8  // 源前缀长度
	ScopePrefix  uint8  // 作用域前缀长度
	Address      net.IP // IP地址
}

// ECSManager ECS选项管理器，处理EDNS Client Subnet相关功能
type ECSManager struct {
	defaultECS *ECSOption  // 默认ECS配置
	detector   *IPDetector // IP检测器
	cache      sync.Map    // ECS缓存
}

// InitECSManager 初始化ECS管理器
func InitECSManager(defaultSubnet string) (*ECSManager, error) {
	manager := &ECSManager{
		detector: CreateIPDetector(),
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

// GetDefaultECS 获取默认ECS配置
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

// AddToMessage 向DNS消息添加ECS选项
func (em *ECSManager) AddToMessage(msg *dns.Msg, ecs *ECSOption, dnssecEnabled bool) {
	if msg == nil {
		return
	}

	// 清理现有的OPT记录
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

	if dnssecEnabled {
		opt.SetDo(true)
	}

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

// parseECSConfig 解析ECS配置字符串
func (em *ECSManager) parseECSConfig(subnet string) (*ECSOption, error) {
	switch strings.ToLower(subnet) {
	case "auto":
		return em.detectPublicIP(false, true)
	case "auto_v4":
		return em.detectPublicIP(false, false)
	case "auto_v6":
		return em.detectPublicIP(true, false)
	default:
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

// detectPublicIP 检测公网IP地址
func (em *ECSManager) detectPublicIP(forceIPv6, allowFallback bool) (*ECSOption, error) {
	cacheKey := fmt.Sprintf("ip_detection_%v_%v", forceIPv6, allowFallback)

	if cached, ok := em.cache.Load(cacheKey); ok {
		if cachedECS, ok := cached.(*ECSOption); ok {
			logf(LogDebug, "🌍 使用缓存的IP检测结果: %s", cachedECS.Address)
			return cachedECS, nil
		}
	}

	var ip net.IP
	var ecs *ECSOption

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

// ==================== IP检测器 ====================

// IPDetector 公网IP地址检测器
type IPDetector struct {
	dnsClient  *dns.Client  // DNS客户端
	httpClient *http.Client // HTTP客户端
}

// CreateIPDetector 创建IP检测器
func CreateIPDetector() *IPDetector {
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

// detectPublicIP 检测公网IP地址，优先使用DNS方法，失败后回退到HTTP
func (d *IPDetector) detectPublicIP(forceIPv6 bool) net.IP {
	if ip := d.tryGoogleDNS(forceIPv6); ip != nil {
		logf(LogDebug, "✅ Google DNS检测成功: %s", ip)
		return ip
	}

	if ip := d.tryCloudflareHTTP(forceIPv6); ip != nil {
		logf(LogDebug, "✅ Cloudflare HTTP检测成功: %s", ip)
		return ip
	}

	return nil
}

// tryGoogleDNS 尝试通过Google DNS服务检测IP
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

// tryCloudflareHTTP 尝试通过Cloudflare HTTP服务检测IP
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

// ==================== 查询引擎 (合并原MessageBuilder和QueryManager) ====================

// QueryResult DNS查询结果
type QueryResult struct {
	Response *dns.Msg      // DNS响应消息
	Server   string        // 响应服务器地址
	Error    error         // 错误信息
	Duration time.Duration // 查询耗时
	UsedTCP  bool          // 是否使用TCP
}

// QueryEngine 统一的DNS查询引擎，负责构建查询消息和执行查询
type QueryEngine struct {
	poolManager *ObjectPoolManager // 对象池管理器
	ecsManager  *ECSManager        // ECS管理器
	connPool    *ConnectionPool    // 连接池
	taskManager *TaskManager       // 任务管理器
	timeout     time.Duration      // 查询超时时间
}

// CreateQueryEngine 创建查询引擎
func CreateQueryEngine(poolManager *ObjectPoolManager, ecsManager *ECSManager,
	connPool *ConnectionPool, taskManager *TaskManager, timeout time.Duration) *QueryEngine {
	return &QueryEngine{
		poolManager: poolManager,
		ecsManager:  ecsManager,
		connPool:    connPool,
		taskManager: taskManager,
		timeout:     timeout,
	}
}

// BuildQuery 构建DNS查询消息
func (qe *QueryEngine) BuildQuery(question dns.Question, ecs *ECSOption, dnssecEnabled bool, recursionDesired bool) *dns.Msg {
	msg := qe.poolManager.GetDNSMessage()

	msg.SetQuestion(question.Name, question.Qtype)
	msg.RecursionDesired = recursionDesired

	qe.ecsManager.AddToMessage(msg, ecs, dnssecEnabled)

	return msg
}

// BuildResponse 构建DNS响应消息
func (qe *QueryEngine) BuildResponse(request *dns.Msg) *dns.Msg {
	msg := qe.poolManager.GetDNSMessage()
	msg.SetReply(request)
	msg.Authoritative = false
	msg.RecursionAvailable = true
	return msg
}

// ReleaseMessage 释放DNS消息到对象池
func (qe *QueryEngine) ReleaseMessage(msg *dns.Msg) {
	if msg != nil {
		qe.poolManager.PutDNSMessage(msg)
	}
}

// ExecuteQuery 执行单个DNS查询，支持UDP/TCP自动回退
func (qe *QueryEngine) ExecuteQuery(ctx context.Context, msg *dns.Msg, server string, tracker *RequestTracker) *QueryResult {
	start := time.Now()
	result := &QueryResult{
		Server: server,
	}

	if tracker != nil {
		tracker.AddStep("开始查询服务器: %s", server)
	}

	queryCtx, cancel := context.WithTimeout(ctx, qe.timeout)
	defer cancel()

	// 首先尝试UDP查询
	result.Response, result.Error = qe.executeUDPQuery(queryCtx, msg, server, tracker)
	result.Duration = time.Since(start)

	// 判断是否需要TCP回退
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
		tcpResponse, tcpErr := qe.executeTCPQuery(queryCtx, msg, server, tracker)
		tcpDuration := time.Since(tcpStart)

		if tcpErr != nil {
			if result.Response != nil && result.Response.Rcode != dns.RcodeServerFailure {
				if tracker != nil {
					tracker.AddStep("TCP回退失败，使用UDP响应: %v", tcpErr)
				}
				return result
			}
			result.Error = tcpErr
			result.Duration = time.Since(start)
			return result
		}

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
func (qe *QueryEngine) executeUDPQuery(ctx context.Context, msg *dns.Msg, server string, tracker *RequestTracker) (*dns.Msg, error) {
	client := qe.connPool.Get()
	defer qe.connPool.Put(client)

	response, _, err := client.ExchangeContext(ctx, msg, server)

	if tracker != nil && err == nil {
		tracker.AddStep("UDP查询成功，响应码: %s", dns.RcodeToString[response.Rcode])
	}

	return response, err
}

// executeTCPQuery 执行TCP查询
func (qe *QueryEngine) executeTCPQuery(ctx context.Context, msg *dns.Msg, server string, tracker *RequestTracker) (*dns.Msg, error) {
	client := qe.connPool.GetTCP()

	response, _, err := client.ExchangeContext(ctx, msg, server)

	if tracker != nil && err == nil {
		tracker.AddStep("TCP查询成功，响应码: %s", dns.RcodeToString[response.Rcode])
	}

	return response, err
}

// ExecuteConcurrentQuery 执行并发DNS查询，返回第一个成功的结果
func (qe *QueryEngine) ExecuteConcurrentQuery(ctx context.Context, msg *dns.Msg, servers []string,
	maxConcurrency int, tracker *RequestTracker) (*QueryResult, error) {

	if len(servers) == 0 {
		return nil, errors.New("没有可用的服务器")
	}

	if tracker != nil {
		tracker.AddStep("开始并发查询 %d 个服务器", len(servers))
	}

	concurrency := len(servers)
	if maxConcurrency > 0 && concurrency > maxConcurrency {
		concurrency = maxConcurrency
	}

	resultChan := make(chan *QueryResult, concurrency)

	for i := 0; i < concurrency && i < len(servers); i++ {
		server := servers[i]
		qe.taskManager.ExecuteAsync(fmt.Sprintf("ConcurrentQuery-%s", server),
			func(ctx context.Context) error {
				result := qe.ExecuteQuery(ctx, msg, server, tracker)
				select {
				case resultChan <- result:
				case <-ctx.Done():
				}
				return nil
			})
	}

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

// ==================== 连接池 ====================

// ConnectionPool DNS客户端连接池，复用连接以提高性能
type ConnectionPool struct {
	clients     chan *dns.Client // 客户端池
	timeout     time.Duration    // 超时时间
	currentSize int64            // 当前池大小
}

// InitConnectionPool 初始化连接池
func InitConnectionPool() *ConnectionPool {
	return &ConnectionPool{
		clients:     make(chan *dns.Client, ConnPoolSize),
		timeout:     QueryTimeout,
		currentSize: 0,
	}
}

// createClient 创建新的DNS客户端
func (cp *ConnectionPool) createClient() *dns.Client {
	return &dns.Client{
		Timeout: cp.timeout,
		Net:     "udp",
		UDPSize: UDPUpstreamBufferSize,
	}
}

// Get 获取UDP客户端
func (cp *ConnectionPool) Get() *dns.Client {
	select {
	case client := <-cp.clients:
		return client
	default:
		return cp.createClient()
	}
}

// GetTCP 获取TCP客户端
func (cp *ConnectionPool) GetTCP() *dns.Client {
	return &dns.Client{
		Timeout: cp.timeout,
		Net:     "tcp",
	}
}

// Put 归还客户端到池中
func (cp *ConnectionPool) Put(client *dns.Client) {
	select {
	case cp.clients <- client:
	default:
		// 池已满，丢弃客户端
	}
}

// ==================== 缓存键构建工具 ====================

// buildCacheKey 构建缓存键的工具函数，替代原来的CacheKeyBuilder结构体
func buildCacheKey(question dns.Question, ecs *ECSOption, dnssecEnabled bool) string {
	builder := globalPoolManager.GetStringBuilder()
	defer globalPoolManager.PutStringBuilder(builder)

	// 域名
	builder.WriteString(strings.ToLower(question.Name))

	// 查询类型
	builder.WriteByte(':')
	builder.WriteString(fmt.Sprintf("%d", question.Qtype))

	// 查询类
	builder.WriteByte(':')
	builder.WriteString(fmt.Sprintf("%d", question.Qclass))

	// ECS选项
	if ecs != nil {
		builder.WriteByte(':')
		builder.WriteString(ecs.Address.String())
		builder.WriteByte('/')
		builder.WriteString(fmt.Sprintf("%d", ecs.SourcePrefix))
	}

	// DNSSEC选项
	if dnssecEnabled {
		builder.WriteString(":dnssec")
	}

	result := builder.String()
	if len(result) > MaxCacheKeyLength {
		result = fmt.Sprintf("hash:%x", result)[:MaxCacheKeyLength]
	}
	return result
}

// ==================== TTL计算工具 ====================

// calculateCacheTTL 计算缓存TTL的工具函数，替代原来的TTLCalculator结构体
func calculateCacheTTL(rrs []dns.RR) int {
	if len(rrs) == 0 {
		return DefaultCacheTTL
	}

	minTTL := int(rrs[0].Header().Ttl)
	for _, rr := range rrs {
		if ttl := int(rr.Header().Ttl); ttl > 0 && (minTTL == 0 || ttl < minTTL) {
			minTTL = ttl
		}
	}

	if minTTL <= 0 {
		minTTL = DefaultCacheTTL
	}

	return minTTL
}

// ==================== IP过滤器 ====================

// IPFilter IP地址过滤器，用于判断IP地址是否在可信列表中
type IPFilter struct {
	trustedCIDRs   []*net.IPNet // IPv4可信CIDR列表
	trustedCIDRsV6 []*net.IPNet // IPv6可信CIDR列表
	mu             sync.RWMutex // 读写锁
}

// CreateIPFilter 创建IP过滤器
func CreateIPFilter() *IPFilter {
	return &IPFilter{
		trustedCIDRs:   make([]*net.IPNet, 0, MaxTrustedIPv4CIDRs),
		trustedCIDRsV6: make([]*net.IPNet, 0, MaxTrustedIPv6CIDRs),
	}
}

// LoadCIDRs 从文件加载CIDR列表
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

// optimizeCIDRs 优化CIDR列表，按前缀长度排序以提高匹配效率
func (f *IPFilter) optimizeCIDRs() {
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

// isTrustedIP 判断IP是否为可信IP
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

// AnalyzeIPs 分析DNS记录中的IP地址，返回是否包含可信和不可信IP
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

// HasData 检查是否有可信CIDR数据
func (f *IPFilter) HasData() bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return len(f.trustedCIDRs) > 0 || len(f.trustedCIDRsV6) > 0
}

// ==================== DNS重写器 ====================

// RewriteRuleType DNS重写规则类型
type RewriteRuleType int

const (
	RewriteExact  RewriteRuleType = iota // 精确匹配
	RewriteSuffix                        // 后缀匹配
	RewriteRegex                         // 正则表达式匹配
	RewritePrefix                        // 前缀匹配
)

// RewriteRule DNS重写规则
type RewriteRule struct {
	Type        RewriteRuleType `json:"-"`           // 规则类型
	TypeString  string          `json:"type"`        // 规则类型字符串
	Pattern     string          `json:"pattern"`     // 匹配模式
	Replacement string          `json:"replacement"` // 替换内容
	regex       *regexp.Regexp  `json:"-"`           // 编译后的正则表达式
}

// DNSRewriter DNS域名重写器
type DNSRewriter struct {
	rules []RewriteRule // 重写规则列表
	mu    sync.RWMutex  // 读写锁
}

// CreateDNSRewriter 创建DNS重写器
func CreateDNSRewriter() *DNSRewriter {
	return &DNSRewriter{
		rules: make([]RewriteRule, 0, LargeSliceInitialCapacity),
	}
}

// LoadRules 加载重写规则
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

// Rewrite 重写域名
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

// matchRule 匹配重写规则
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

// HasRules 检查是否有重写规则
func (r *DNSRewriter) HasRules() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.rules) > 0
}

// ==================== DNS劫持预防检查器 ====================

// DNSHijackPrevention DNS劫持预防检查器
type DNSHijackPrevention struct {
	enabled bool // 是否启用检查
}

// CreateDNSHijackPrevention 创建DNS劫持预防检查器
func CreateDNSHijackPrevention(enabled bool) *DNSHijackPrevention {
	return &DNSHijackPrevention{enabled: enabled}
}

// IsEnabled 检查是否启用劫持预防
func (shp *DNSHijackPrevention) IsEnabled() bool {
	return shp.enabled
}

// CheckResponse 检查DNS响应是否存在劫持迹象
func (shp *DNSHijackPrevention) CheckResponse(currentDomain, queryDomain string, response *dns.Msg) (bool, string) {
	if !shp.enabled || response == nil {
		return true, ""
	}

	currentDomain = strings.ToLower(strings.TrimSuffix(currentDomain, "."))
	queryDomain = strings.ToLower(strings.TrimSuffix(queryDomain, "."))

	if currentDomain == "" && queryDomain != "" {
		isRootServerQuery := strings.HasSuffix(queryDomain, ".root-servers.net") || queryDomain == "root-servers.net"

		for _, rr := range response.Answer {
			answerName := strings.ToLower(strings.TrimSuffix(rr.Header().Name, "."))
			if answerName == queryDomain {
				if rr.Header().Rrtype == dns.TypeNS || rr.Header().Rrtype == dns.TypeDS {
					continue
				}

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

// UpstreamServer 上游DNS服务器配置
type UpstreamServer struct {
	Address string `json:"address"` // 服务器地址
	Policy  string `json:"policy"`  // 信任策略 (all/trusted_only/untrusted_only)
}

// IsRecursive 检查是否为内置递归服务器
func (u *UpstreamServer) IsRecursive() bool {
	return strings.ToLower(u.Address) == RecursiveServerIndicator
}

// ShouldTrustResult 根据策略判断是否信任查询结果
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

// UpstreamManager 上游服务器管理器
type UpstreamManager struct {
	servers []*UpstreamServer // 服务器列表
	mu      sync.RWMutex      // 读写锁
}

// InitUpstreamManager 初始化上游服务器管理器
func InitUpstreamManager(servers []UpstreamServer) *UpstreamManager {
	activeServers := make([]*UpstreamServer, 0, len(servers))

	for i := range servers {
		server := &servers[i]
		activeServers = append(activeServers, server)
	}

	return &UpstreamManager{
		servers: activeServers,
	}
}

// GetServers 获取服务器列表
func (um *UpstreamManager) GetServers() []*UpstreamServer {
	um.mu.RLock()
	defer um.mu.RUnlock()
	return um.servers
}

// ==================== 服务器配置 ====================

// ServerConfig 服务器配置结构
type ServerConfig struct {
	Server struct {
		Port            string `json:"port"`               // 监听端口
		IPv6            bool   `json:"ipv6"`               // 是否支持IPv6
		LogLevel        string `json:"log_level"`          // 日志级别
		DefaultECS      string `json:"default_ecs_subnet"` // 默认ECS子网
		TrustedCIDRFile string `json:"trusted_cidr_file"`  // 可信CIDR文件路径
		Features        struct {
			ServeStale       bool `json:"serve_stale"`       // 是否启用过期缓存服务
			Prefetch         bool `json:"prefetch"`          // 是否启用预取
			DNSSEC           bool `json:"dnssec"`            // 是否启用DNSSEC
			HijackProtection bool `json:"hijack_protection"` // 是否启用劫持保护
		} `json:"features"`
	} `json:"server"`

	Redis struct {
		Address   string `json:"address"`    // Redis地址
		Password  string `json:"password"`   // Redis密码
		Database  int    `json:"database"`   // Redis数据库
		KeyPrefix string `json:"key_prefix"` // 缓存键前缀
	} `json:"redis"`

	Upstream []UpstreamServer `json:"upstream"` // 上游服务器列表
	Rewrite  []RewriteRule    `json:"rewrite"`  // DNS重写规则
}

// loadConfig 加载配置文件
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

// validateConfig 验证配置
func validateConfig(config *ServerConfig) error {
	// 验证日志级别
	validLevels := map[string]LogLevel{
		"none": LogNone, "error": LogError, "warn": LogWarn,
		"info": LogInfo, "debug": LogDebug,
	}
	if level, ok := validLevels[strings.ToLower(config.Server.LogLevel)]; ok {
		logConfig.level = level
	} else {
		return fmt.Errorf("无效的日志级别: %s", config.Server.LogLevel)
	}

	// 验证ECS配置
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
		// 无缓存模式下禁用某些功能
		if config.Server.Features.ServeStale {
			logf(LogWarn, "⚠️ 无缓存模式下禁用过期缓存服务功能")
			config.Server.Features.ServeStale = false
		}
		if config.Server.Features.Prefetch {
			logf(LogWarn, "⚠️ 无缓存模式下禁用预取功能")
			config.Server.Features.Prefetch = false
		}
	}

	return nil
}

// getDefaultConfig 获取默认配置
func getDefaultConfig() *ServerConfig {
	config := &ServerConfig{}

	config.Server.Port = DNSServerPort
	config.Server.IPv6 = true
	config.Server.LogLevel = "info"
	config.Server.DefaultECS = "auto"
	config.Server.TrustedCIDRFile = ""

	config.Server.Features.ServeStale = false
	config.Server.Features.Prefetch = false
	config.Server.Features.DNSSEC = true
	config.Server.Features.HijackProtection = false

	config.Redis.Address = ""
	config.Redis.Password = ""
	config.Redis.Database = 0
	config.Redis.KeyPrefix = "zjdns:"

	config.Upstream = []UpstreamServer{}
	config.Rewrite = []RewriteRule{}

	return config
}

// isValidFilePath 验证文件路径是否安全
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

// generateExampleConfig 生成示例配置
func generateExampleConfig() string {
	config := getDefaultConfig()
	config.Server.LogLevel = "info"
	config.Server.DefaultECS = "auto"
	config.Server.TrustedCIDRFile = "trusted_cidr.txt"
	config.Redis.Address = "127.0.0.1:6379"
	config.Server.Features.ServeStale = true
	config.Server.Features.Prefetch = true
	config.Server.Features.HijackProtection = true

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

// ==================== DNS记录结构 ====================

// CompactDNSRecord 紧凑的DNS记录结构，用于缓存存储
type CompactDNSRecord struct {
	Text    string `json:"text"`     // DNS记录文本表示
	OrigTTL uint32 `json:"orig_ttl"` // 原始TTL值
	Type    uint16 `json:"type"`     // 记录类型
}

// compactRR 将DNS记录转换为紧凑格式
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

// expandRR 将紧凑格式转换为DNS记录
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

// compactRRs 批量转换DNS记录为紧凑格式，去重
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

// expandRRs 批量将紧凑格式转换为DNS记录
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

// CacheEntry 缓存条目结构
type CacheEntry struct {
	Answer          []*CompactDNSRecord `json:"answer"`                      // 答案记录
	Authority       []*CompactDNSRecord `json:"authority"`                   // 授权记录
	Additional      []*CompactDNSRecord `json:"additional"`                  // 附加记录
	TTL             int                 `json:"ttl"`                         // 缓存TTL
	Timestamp       int64               `json:"timestamp"`                   // 创建时间戳
	Validated       bool                `json:"validated"`                   // DNSSEC验证状态
	AccessTime      int64               `json:"access_time"`                 // 最后访问时间
	RefreshTime     int64               `json:"refresh_time"`                // 最后刷新时间
	ECSFamily       uint16              `json:"ecs_family,omitempty"`        // ECS地址族
	ECSSourcePrefix uint8               `json:"ecs_source_prefix,omitempty"` // ECS源前缀
	ECSScopePrefix  uint8               `json:"ecs_scope_prefix,omitempty"`  // ECS作用域前缀
	ECSAddress      string              `json:"ecs_address,omitempty"`       // ECS地址
	LastUpdateTime  int64               `json:"last_update_time,omitempty"`  // 最后更新时间
}

// IsExpired 检查缓存是否过期
func (c *CacheEntry) IsExpired() bool {
	return time.Now().Unix()-c.Timestamp > int64(c.TTL)
}

// IsStale 检查缓存是否过期且超过最大保存时间
func (c *CacheEntry) IsStale() bool {
	return time.Now().Unix()-c.Timestamp > int64(c.TTL+StaleMaxAge)
}

// ShouldRefresh 检查是否需要刷新缓存
func (c *CacheEntry) ShouldRefresh() bool {
	now := time.Now().Unix()
	return c.IsExpired() &&
		(now-c.Timestamp) > int64(c.TTL+CacheRefreshThreshold) &&
		(now-c.RefreshTime) > CacheRefreshRetryInterval
}

// ShouldUpdateAccessInfo 检查是否需要更新访问信息
func (c *CacheEntry) ShouldUpdateAccessInfo() bool {
	now := time.Now().UnixMilli()
	return now-c.LastUpdateTime > CacheAccessThrottleMs
}

// GetRemainingTTL 获取剩余TTL
func (c *CacheEntry) GetRemainingTTL() uint32 {
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

// ShouldBeDeleted 检查缓存是否应该被删除
func (c *CacheEntry) ShouldBeDeleted() bool {
	now := time.Now().Unix()
	totalAge := now - c.Timestamp
	return totalAge > int64(c.TTL+StaleMaxAge)
}

// GetAnswerRRs 获取答案DNS记录
func (c *CacheEntry) GetAnswerRRs() []dns.RR { return expandRRs(c.Answer) }

// GetAuthorityRRs 获取授权DNS记录
func (c *CacheEntry) GetAuthorityRRs() []dns.RR { return expandRRs(c.Authority) }

// GetAdditionalRRs 获取附加DNS记录
func (c *CacheEntry) GetAdditionalRRs() []dns.RR { return expandRRs(c.Additional) }

// GetECSOption 获取ECS选项
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

// RefreshRequest 缓存刷新请求
type RefreshRequest struct {
	Question            dns.Question // DNS问题
	ECS                 *ECSOption   // ECS选项
	CacheKey            string       // 缓存键
	ServerDNSSECEnabled bool         // 服务器DNSSEC设置
}

// ==================== 缓存接口 ====================

// DNSCache DNS缓存接口
type DNSCache interface {
	Get(key string) (*CacheEntry, bool, bool)                                               // 获取缓存条目
	Set(key string, answer, authority, additional []dns.RR, validated bool, ecs *ECSOption) // 设置缓存条目
	RequestRefresh(req RefreshRequest)                                                      // 请求刷新
	Shutdown()                                                                              // 关闭缓存
}

// NullCache 空缓存实现，不执行任何缓存操作
type NullCache struct{}

// CreateNullCache 创建空缓存
func CreateNullCache() *NullCache {
	logf(LogInfo, "🚫 无缓存模式")
	return &NullCache{}
}

func (nc *NullCache) Get(key string) (*CacheEntry, bool, bool) { return nil, false, false }
func (nc *NullCache) Set(key string, answer, authority, additional []dns.RR, validated bool, ecs *ECSOption) {
}
func (nc *NullCache) RequestRefresh(req RefreshRequest) {}
func (nc *NullCache) Shutdown()                         {}

// ==================== Redis缓存实现 ====================

// RedisDNSCache Redis缓存实现
type RedisDNSCache struct {
	client       *redis.Client       // Redis客户端
	config       *ServerConfig       // 服务器配置
	keyPrefix    string              // 缓存键前缀
	refreshQueue chan RefreshRequest // 刷新请求队列
	ctx          context.Context     // 上下文
	cancel       context.CancelFunc  // 取消函数
	wg           sync.WaitGroup      // 等待组
	taskManager  *TaskManager        // 任务管理器
	server       *RecursiveDNSServer // DNS服务器引用
}

// CreateRedisDNSCache 创建Redis缓存
func CreateRedisDNSCache(config *ServerConfig, server *RecursiveDNSServer) (*RedisDNSCache, error) {
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
		keyPrefix:    config.Redis.KeyPrefix,
		refreshQueue: make(chan RefreshRequest, CacheRefreshQueueSize),
		ctx:          cacheCtx,
		cancel:       cacheCancel,
		taskManager:  CreateTaskManager(TaskWorkerMaxCount),
		server:       server,
	}

	if config.Server.Features.ServeStale && config.Server.Features.Prefetch {
		cache.startRefreshProcessor()
	}

	logf(LogInfo, "✅ Redis缓存系统初始化完成")
	return cache, nil
}

// startRefreshProcessor 启动刷新处理器
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

// handleRefreshRequest 处理刷新请求
func (rc *RedisDNSCache) handleRefreshRequest(req RefreshRequest) {
	defer recoverPanic("Redis刷新请求处理")

	logf(LogDebug, "🔄 开始处理刷新请求: %s", req.CacheKey)

	answer, authority, additional, validated, ecsResponse, err := rc.server.QueryForRefresh(
		req.Question, req.ECS, req.ServerDNSSECEnabled)

	if err != nil {
		logf(LogDebug, "🔄 刷新查询失败: %s - %v", req.CacheKey, err)
		rc.updateRefreshTime(req.CacheKey)
		return
	}

	allRRs := make([]dns.RR, 0, len(answer)+len(authority)+len(additional))
	allRRs = append(allRRs, answer...)
	allRRs = append(allRRs, authority...)
	allRRs = append(allRRs, additional...)

	cacheTTL := calculateCacheTTL(allRRs)
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

	data, err := json.Marshal(entry)
	if err != nil {
		logf(LogWarn, "⚠️ 刷新缓存序列化失败: %v", err)
		return
	}

	fullKey := rc.keyPrefix + req.CacheKey
	expiration := time.Duration(cacheTTL) * time.Second
	if rc.config.Server.Features.ServeStale {
		expiration += time.Duration(StaleMaxAge) * time.Second
	}

	if err := rc.client.Set(rc.ctx, fullKey, data, expiration).Err(); err != nil {
		logf(LogWarn, "⚠️ 刷新缓存存储失败: %v", err)
		return
	}

	logf(LogDebug, "✅ 缓存刷新完成: %s (TTL: %ds, 答案: %d条)", req.CacheKey, cacheTTL, len(answer))
}

// updateRefreshTime 更新刷新时间
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

// Get 获取缓存条目
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

	if entry.ShouldBeDeleted() {
		rc.taskManager.SubmitBackgroundTask(func() {
			rc.client.Del(rc.ctx, fullKey)
		})
		return nil, false, false
	}

	if entry.ShouldUpdateAccessInfo() {
		entry.AccessTime = time.Now().Unix()
		entry.LastUpdateTime = time.Now().UnixMilli()
		rc.taskManager.SubmitBackgroundTask(func() { rc.updateAccessInfo(fullKey, &entry) })
	}

	isExpired := entry.IsExpired()

	if !rc.config.Server.Features.ServeStale && isExpired {
		rc.taskManager.SubmitBackgroundTask(func() { rc.client.Del(rc.ctx, fullKey) })
		return nil, false, false
	}

	return &entry, true, isExpired
}

// Set 设置缓存条目
func (rc *RedisDNSCache) Set(key string, answer, authority, additional []dns.RR, validated bool, ecs *ECSOption) {
	defer recoverPanic("Redis缓存设置")

	allRRs := make([]dns.RR, 0, len(answer)+len(authority)+len(additional))
	allRRs = append(allRRs, answer...)
	allRRs = append(allRRs, authority...)
	allRRs = append(allRRs, additional...)

	cacheTTL := calculateCacheTTL(allRRs)
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
	if rc.config.Server.Features.ServeStale {
		expiration += time.Duration(StaleMaxAge) * time.Second
	}

	rc.client.Set(rc.ctx, fullKey, data, expiration)
	logf(LogDebug, "💾 Redis缓存记录: %s (TTL: %ds)", key, cacheTTL)
}

// updateAccessInfo 更新访问信息
func (rc *RedisDNSCache) updateAccessInfo(fullKey string, entry *CacheEntry) {
	defer recoverPanic("Redis访问信息更新")
	data, err := json.Marshal(entry)
	if err != nil {
		return
	}
	rc.client.Set(rc.ctx, fullKey, data, redis.KeepTTL)
}

// RequestRefresh 请求刷新缓存
func (rc *RedisDNSCache) RequestRefresh(req RefreshRequest) {
	select {
	case rc.refreshQueue <- req:
	default:
		logf(LogDebug, "刷新队列已满，跳过刷新请求")
	}
}

// Shutdown 关闭Redis缓存
func (rc *RedisDNSCache) Shutdown() {
	logf(LogInfo, "🛑 正在关闭Redis缓存系统...")
	rc.taskManager.Shutdown(TaskExecutionTimeout)
	rc.cancel()
	close(rc.refreshQueue)

	done := make(chan struct{})
	go func() {
		rc.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(TaskExecutionTimeout):
		logf(LogWarn, "Redis缓存关闭超时")
	}

	rc.client.Close()
	logf(LogInfo, "✅ Redis缓存系统已安全关闭")
}

// ==================== DNSSEC验证器 ====================

// DNSSECValidator DNSSEC验证器
type DNSSECValidator struct{}

// CreateDNSSECValidator 创建DNSSEC验证器
func CreateDNSSECValidator() *DNSSECValidator {
	return &DNSSECValidator{}
}

// HasDNSSECRecords 检查响应是否包含DNSSEC记录
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

// IsValidated 检查响应是否已验证
func (v *DNSSECValidator) IsValidated(response *dns.Msg) bool {
	if response == nil {
		return false
	}
	return response.AuthenticatedData || v.HasDNSSECRecords(response)
}

// ValidateResponse 验证DNS响应
func (v *DNSSECValidator) ValidateResponse(response *dns.Msg, dnssecOK bool) bool {
	if response == nil || !dnssecOK {
		return false
	}
	return v.IsValidated(response)
}

// ==================== 查询结果结构 ====================

// UpstreamResult 上游查询结果
type UpstreamResult struct {
	Response       *dns.Msg        // DNS响应
	Server         *UpstreamServer // 上游服务器
	Error          error           // 错误信息
	Duration       time.Duration   // 查询耗时
	HasTrustedIP   bool            // 是否包含可信IP
	HasUntrustedIP bool            // 是否包含不可信IP
	Trusted        bool            // 是否可信
	Filtered       bool            // 是否被过滤
	Validated      bool            // 是否DNSSEC验证
}

// ==================== 主DNS服务器 ====================

// RecursiveDNSServer 递归DNS服务器主结构
type RecursiveDNSServer struct {
	config           *ServerConfig        // 服务器配置
	cache            DNSCache             // DNS缓存
	rootServersV4    []string             // IPv4根服务器列表
	rootServersV6    []string             // IPv6根服务器列表
	connPool         *ConnectionPool      // 连接池
	dnssecVal        *DNSSECValidator     // DNSSEC验证器
	concurrencyLimit chan struct{}        // 并发限制信号量
	ctx              context.Context      // 上下文
	cancel           context.CancelFunc   // 取消函数
	shutdown         chan struct{}        // 关闭信号通道
	ipFilter         *IPFilter            // IP过滤器
	dnsRewriter      *DNSRewriter         // DNS重写器
	upstreamManager  *UpstreamManager     // 上游服务器管理器
	wg               sync.WaitGroup       // 等待组
	taskManager      *TaskManager         // 任务管理器
	hijackPrevention *DNSHijackPrevention // DNS劫持预防
	ecsManager       *ECSManager          // ECS管理器
	queryEngine      *QueryEngine         // 查询引擎
}

// QueryForRefresh 为缓存刷新执行查询，供Redis缓存调用
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

// CreateDNSServer 创建递归DNS服务器
func CreateDNSServer(config *ServerConfig) (*RecursiveDNSServer, error) {
	// 根服务器列表
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

	// 初始化各种组件
	ecsManager, err := InitECSManager(config.Server.DefaultECS)
	if err != nil {
		return nil, fmt.Errorf("ECS管理器初始化失败: %w", err)
	}

	ipFilter := CreateIPFilter()
	if config.Server.TrustedCIDRFile != "" {
		if err := ipFilter.LoadCIDRs(config.Server.TrustedCIDRFile); err != nil {
			return nil, fmt.Errorf("加载可信CIDR文件失败: %w", err)
		}
	}

	dnsRewriter := CreateDNSRewriter()
	if len(config.Rewrite) > 0 {
		if err := dnsRewriter.LoadRules(config.Rewrite); err != nil {
			return nil, fmt.Errorf("加载DNS重写规则失败: %w", err)
		}
	}

	upstreamManager := InitUpstreamManager(config.Upstream)
	connPool := InitConnectionPool()
	taskManager := CreateTaskManager(MaxConcurrency)
	queryEngine := CreateQueryEngine(globalPoolManager, ecsManager, connPool, taskManager, QueryTimeout)
	hijackPrevention := CreateDNSHijackPrevention(config.Server.Features.HijackProtection)

	server := &RecursiveDNSServer{
		config:           config,
		rootServersV4:    rootServersV4,
		rootServersV6:    rootServersV6,
		connPool:         connPool,
		dnssecVal:        CreateDNSSECValidator(),
		concurrencyLimit: make(chan struct{}, MaxConcurrency),
		ctx:              ctx,
		cancel:           cancel,
		shutdown:         make(chan struct{}),
		ipFilter:         ipFilter,
		dnsRewriter:      dnsRewriter,
		upstreamManager:  upstreamManager,
		taskManager:      taskManager,
		hijackPrevention: hijackPrevention,
		ecsManager:       ecsManager,
		queryEngine:      queryEngine,
	}

	// 初始化缓存
	var cache DNSCache
	if config.Redis.Address == "" {
		cache = CreateNullCache()
	} else {
		redisCache, err := CreateRedisDNSCache(config, server)
		if err != nil {
			return nil, fmt.Errorf("Redis缓存初始化失败: %w", err)
		}
		cache = redisCache
	}

	server.cache = cache
	server.setupSignalHandling()
	return server, nil
}

// setupSignalHandling 设置信号处理
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
			r.taskManager.Shutdown(GracefulShutdownTimeout)

			done := make(chan struct{})
			go func() {
				r.wg.Wait()
				close(done)
			}()

			select {
			case <-done:
				logf(LogInfo, "✅ 所有组件已安全关闭")
			case <-time.After(GracefulShutdownTimeout):
				logf(LogWarn, "⏰ 组件关闭超时")
			}

			close(r.shutdown)
			time.Sleep(time.Second)
			os.Exit(0)

		case <-r.ctx.Done():
			return
		}
	}()
}

// getRootServers 获取根服务器列表
func (r *RecursiveDNSServer) getRootServers() []string {
	if r.config.Server.IPv6 {
		mixed := make([]string, 0, len(r.rootServersV4)+len(r.rootServersV6))
		mixed = append(mixed, r.rootServersV4...)
		mixed = append(mixed, r.rootServersV6...)
		return mixed
	}
	return r.rootServersV4
}

// Start 启动DNS服务器
func (r *RecursiveDNSServer) Start() error {
	var wg sync.WaitGroup
	errChan := make(chan error, 2)

	logf(LogInfo, "🚀 启动 ZJDNS Server")
	logf(LogInfo, "🌐 监听端口: %s", r.config.Server.Port)

	r.displayInfo()

	wg.Add(2)

	// 启动UDP服务器
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

	// 启动TCP服务器
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

// displayInfo 显示服务器信息
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
		logf(LogInfo, "🔗 上游模式: 共 %d 个服务器", len(servers))
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
	if r.config.Server.Features.HijackProtection {
		logf(LogInfo, "🛡️ DNS劫持预防: 已启用")
	}
	if defaultECS := r.ecsManager.GetDefaultECS(); defaultECS != nil {
		logf(LogInfo, "🌍 默认ECS: %s/%d", defaultECS.Address, defaultECS.SourcePrefix)
	}

	logf(LogInfo, "⚡ 最大并发: %d", MaxConcurrency)
	logf(LogInfo, "📦 UDP缓冲区: 客户端=%d, 上游=%d", UDPClientBufferSize, UDPUpstreamBufferSize)
}

// handleDNSRequest 处理DNS请求
func (r *RecursiveDNSServer) handleDNSRequest(w dns.ResponseWriter, req *dns.Msg) {
	safeExecute("DNS请求处理", func() error {
		select {
		case <-r.ctx.Done():
			return nil
		default:
		}

		response := r.processDNSQuery(req, getClientIP(w))
		return w.WriteMsg(response)
	})
}

// processDNSQuery 处理DNS查询的核心逻辑
func (r *RecursiveDNSServer) processDNSQuery(req *dns.Msg, clientIP net.IP) *dns.Msg {
	var tracker *RequestTracker
	if logConfig.level >= LogDebug {
		if len(req.Question) > 0 {
			question := req.Question[0]
			tracker = CreateRequestTracker(
				question.Name,
				dns.TypeToString[question.Qtype],
				clientIP.String(),
			)
			defer tracker.Finish()
		}
	}

	msg := r.queryEngine.BuildResponse(req)
	defer r.queryEngine.ReleaseMessage(msg)

	if len(req.Question) == 0 {
		msg.Rcode = dns.RcodeFormatError
		if tracker != nil {
			tracker.AddStep("请求格式错误: 缺少问题部分")
		}
		return msg
	}

	question := req.Question[0]
	originalDomain := question.Name

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

			if ip := net.ParseIP(strings.TrimSuffix(rewritten, ".")); ip != nil {
				return r.createDirectIPResponse(msg, originalDomain, question.Qtype, ip, tracker)
			}
		}
	}

	// 解析客户端EDNS选项
	clientRequestedDNSSEC := false
	var ecsOpt *ECSOption

	if opt := req.IsEdns0(); opt != nil {
		clientRequestedDNSSEC = opt.Do()
		ecsOpt = r.ecsManager.ParseFromDNS(req)
		if tracker != nil && ecsOpt != nil {
			tracker.AddStep("客户端ECS: %s/%d", ecsOpt.Address, ecsOpt.SourcePrefix)
		}
	}

	if ecsOpt == nil {
		ecsOpt = r.ecsManager.GetDefaultECS()
		if tracker != nil && ecsOpt != nil {
			tracker.AddStep("使用默认ECS: %s/%d", ecsOpt.Address, ecsOpt.SourcePrefix)
		}
	}

	serverDNSSECEnabled := r.config.Server.Features.DNSSEC
	cacheKey := buildCacheKey(question, ecsOpt, serverDNSSECEnabled)

	if tracker != nil {
		tracker.AddStep("缓存键: %s", cacheKey)
	}

	// 缓存查找
	if entry, found, isExpired := r.cache.Get(cacheKey); found {
		return r.handleCacheHit(msg, entry, isExpired, question, originalDomain,
			clientRequestedDNSSEC, cacheKey, ecsOpt, tracker)
	}

	if tracker != nil {
		tracker.AddStep("缓存未命中，开始查询")
	}
	return r.handleCacheMiss(msg, question, originalDomain, ecsOpt,
		clientRequestedDNSSEC, serverDNSSECEnabled, cacheKey, tracker)
}

// createDirectIPResponse 创建直接IP响应
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
				Ttl:    uint32(DefaultCacheTTL),
			},
			A: ip,
		}}
	} else if qtype == dns.TypeAAAA && ip.To4() == nil {
		msg.Answer = []dns.RR{&dns.AAAA{
			Hdr: dns.RR_Header{
				Name:   originalDomain,
				Rrtype: dns.TypeAAAA,
				Class:  dns.ClassINET,
				Ttl:    uint32(DefaultCacheTTL),
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

	responseTTL := entry.GetRemainingTTL()

	if tracker != nil {
		tracker.CacheHit = true
		if isExpired {
			tracker.AddStep("缓存命中(过期): TTL=%ds", responseTTL)
		} else {
			tracker.AddStep("缓存命中: TTL=%ds", responseTTL)
		}
	}

	msg.Answer = adjustTTL(filterDNSSECRecords(entry.GetAnswerRRs(), clientRequestedDNSSEC), responseTTL)
	msg.Ns = adjustTTL(filterDNSSECRecords(entry.GetAuthorityRRs(), clientRequestedDNSSEC), responseTTL)
	msg.Extra = adjustTTL(filterDNSSECRecords(entry.GetAdditionalRRs(), clientRequestedDNSSEC), responseTTL)

	cachedECS := entry.GetECSOption()
	if clientRequestedDNSSEC || cachedECS != nil {
		r.ecsManager.AddToMessage(msg, cachedECS, entry.Validated && clientRequestedDNSSEC)
	}

	if isExpired && r.config.Server.Features.ServeStale && r.config.Server.Features.Prefetch && entry.ShouldRefresh() {
		if tracker != nil {
			tracker.AddStep("启动后台预取刷新")
		}
		r.cache.RequestRefresh(RefreshRequest{
			Question:            question,
			ECS:                 ecsOpt,
			CacheKey:            cacheKey,
			ServerDNSSECEnabled: r.config.Server.Features.DNSSEC,
		})
	}

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

	// 尝试使用过期缓存
	if r.config.Server.Features.ServeStale {
		if entry, found, _ := r.cache.Get(cacheKey); found {
			if tracker != nil {
				tracker.AddStep("使用过期缓存回退")
			}

			responseTTL := uint32(StaleTTL)
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

	if r.config.Server.Features.DNSSEC && validated {
		msg.AuthenticatedData = true
	}

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

	msg.Answer = filterDNSSECRecords(answer, clientRequestedDNSSEC)
	msg.Ns = filterDNSSECRecords(authority, clientRequestedDNSSEC)
	msg.Extra = filterDNSSECRecords(additional, clientRequestedDNSSEC)

	if clientRequestedDNSSEC || finalECS != nil {
		r.ecsManager.AddToMessage(msg, finalECS, validated && clientRequestedDNSSEC)
	}

	r.restoreOriginalDomain(msg, question.Name, originalDomain)
	return msg
}

// restoreOriginalDomain 恢复原始域名
func (r *RecursiveDNSServer) restoreOriginalDomain(msg *dns.Msg, questionName, originalDomain string) {
	for _, rr := range msg.Answer {
		if strings.EqualFold(rr.Header().Name, questionName) {
			rr.Header().Name = originalDomain
		}
	}
}

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
	ctx, cancel := context.WithTimeout(r.ctx, QueryTimeout)
	defer cancel()

	for i := 0; i < maxConcurrent && i < len(servers); i++ {
		server := servers[i]
		r.taskManager.ExecuteAsync(fmt.Sprintf("UpstreamQuery-%s", server.Address),
			func(ctx context.Context) error {
				result := r.queryUpstreamServer(ctx, server, question, ecs, serverDNSSECEnabled, tracker)
				select {
				case resultChan <- result:
				case <-ctx.Done():
				}
				return nil
			})
	}

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
		answer, authority, additional, validated, ecsResponse, err := r.resolveWithCNAME(ctx, question, ecs, tracker)
		result.Duration = time.Since(start)
		result.Error = err

		if err != nil {
			if tracker != nil {
				tracker.AddStep("递归解析失败: %v", err)
			}
			return result
		}

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

		if ecsResponse != nil {
			r.ecsManager.AddToMessage(response, ecsResponse, serverDNSSECEnabled)
		}
	} else {
		msg := r.queryEngine.BuildQuery(question, ecs, serverDNSSECEnabled, true)
		defer r.queryEngine.ReleaseMessage(msg)

		queryCtx, queryCancel := context.WithTimeout(ctx, StandardOperationTimeout)
		defer queryCancel()

		queryResult := r.queryEngine.ExecuteQuery(queryCtx, msg, server.Address, tracker)
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

// selectUpstreamResult 选择上游查询结果
func (r *RecursiveDNSServer) selectUpstreamResult(results []UpstreamResult, question dns.Question,
	tracker *RequestTracker) ([]dns.RR, []dns.RR, []dns.RR, bool, *ECSOption, error) {

	var validResults []UpstreamResult
	var trustedResults []UpstreamResult

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

	var ecsResponse *ECSOption
	if selectedResult.Response != nil {
		ecsResponse = r.ecsManager.ParseFromDNS(selectedResult.Response)
	}

	return selectedResult.Response.Answer, selectedResult.Response.Ns, selectedResult.Response.Extra,
		selectedResult.Validated, ecsResponse, nil
}

// resolveWithCNAME 处理CNAME链的递归解析
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

		if hasTargetType || currentQuestion.Qtype == dns.TypeCNAME || nextCNAME == nil {
			if tracker != nil {
				tracker.AddStep("CNAME链解析完成")
			}
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

// recursiveQuery 执行递归DNS查询
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

	if normalizedQname == "" {
		response, err := r.queryNameserversConcurrent(ctx, nameservers, question, ecs, forceTCP, tracker)
		if err != nil {
			return nil, nil, nil, false, nil, fmt.Errorf("查询根域名失败: %w", err)
		}

		if r.hijackPrevention.IsEnabled() {
			if valid, reason := r.hijackPrevention.CheckResponse(currentDomain, normalizedQname, response); !valid {
				return r.handleSuspiciousResponse(response, reason, forceTCP, tracker)
			}
		}

		validated := false
		if r.config.Server.Features.DNSSEC {
			validated = r.dnssecVal.ValidateResponse(response, true)
		}

		var ecsResponse *ECSOption
		ecsResponse = r.ecsManager.ParseFromDNS(response)

		return response.Answer, response.Ns, response.Extra, validated, ecsResponse, nil
	}

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
			if !forceTCP && strings.HasPrefix(err.Error(), "DNS_HIJACK_DETECTED") {
				if tracker != nil {
					tracker.AddStep("检测到DNS劫持，切换TCP模式重试")
				}
				return r.recursiveQuery(ctx, question, ecs, depth, true, tracker)
			}
			return nil, nil, nil, false, nil, fmt.Errorf("查询%s失败: %w", currentDomain, err)
		}

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
		if r.config.Server.Features.DNSSEC {
			validated = r.dnssecVal.ValidateResponse(response, true)
		}

		var ecsResponse *ECSOption
		ecsResponse = r.ecsManager.ParseFromDNS(response)

		if len(response.Answer) > 0 {
			if tracker != nil {
				tracker.AddStep("获得最终答案: %d条记录", len(response.Answer))
			}
			return response.Answer, response.Ns, response.Extra, validated, ecsResponse, nil
		}

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

		currentDomainNormalized := strings.ToLower(strings.TrimSuffix(currentDomain, "."))
		if bestMatch == currentDomainNormalized && currentDomainNormalized != "" {
			if tracker != nil {
				tracker.AddStep("检测到查询循环，停止递归")
			}
			return nil, response.Ns, response.Extra, validated, ecsResponse, nil
		}

		currentDomain = bestMatch + "."
		var nextNS []string

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

	msg := r.queryEngine.BuildQuery(question, ecs, r.config.Server.Features.DNSSEC, false)
	defer r.queryEngine.ReleaseMessage(msg)

	queryResult, err := r.queryEngine.ExecuteConcurrentQuery(ctx, msg, nameservers[:concurrency],
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

	for i := 0; i < resolveCount; i++ {
		ns := nsRecords[i]
		r.taskManager.ExecuteAsync(fmt.Sprintf("NSResolve-%s", ns.Ns),
			func(ctx context.Context) error {
				if strings.EqualFold(strings.TrimSuffix(ns.Ns, "."), strings.TrimSuffix(qname, ".")) {
					select {
					case nsChan <- nil:
					case <-ctx.Done():
					}
					return nil
				}

				var addresses []string

				nsQuestion := dns.Question{Name: dns.Fqdn(ns.Ns), Qtype: dns.TypeA, Qclass: dns.ClassINET}
				if nsAnswer, _, _, _, _, err := r.recursiveQuery(resolveCtx, nsQuestion, nil, depth+1, forceTCP, tracker); err == nil {
					for _, rr := range nsAnswer {
						if a, ok := rr.(*dns.A); ok {
							addresses = append(addresses, net.JoinHostPort(a.A.String(), DNSServerPort))
						}
					}
				}

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
			// 跳过DNSSEC记录
		default:
			filtered = append(filtered, rr)
		}
	}
	return filtered
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

	server, err := CreateDNSServer(config)
	if err != nil {
		customLogger.Fatalf("❌ 服务器创建失败: %v", err)
	}

	if err := server.Start(); err != nil {
		customLogger.Fatalf("❌ 服务器启动失败: %v", err)
	}
}
