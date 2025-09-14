package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/bluele/gcache"
	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/redis/go-redis/v9"
)

// ==================== 系统常量定义 ====================

// DNS服务相关常量
const (
	DNSServerPort            = "53"
	DNSServerSecurePort      = "853"
	RecursiveServerIndicator = "buildin_recursive"
	ClientUDPBufferSize      = 1232
	UpstreamUDPBufferSize    = 4096
	RFCMaxDomainNameLength   = 253
)

// DNS Padding 相关常量 (RFC 7830)
const (
	DNSPaddingBlockSize = 128
	DNSPaddingFillByte  = 0x00
	DNSPaddingMinSize   = 12
	DNSPaddingMaxSize   = 468
)

// 安全连接相关常量
const (
	SecureConnIdleTimeout      = 5 * time.Minute
	SecureConnKeepAlive        = 20 * time.Second
	SecureConnHandshakeTimeout = 2 * time.Second
	SecureConnQueryTimeout     = 5 * time.Second
	SecureConnBufferSize       = 8192
	MinDNSPacketSize           = 12
	SecureConnMaxRetries       = 2
)

// QUIC协议相关常量
const (
	QUICAddrValidatorCacheSize = 1000
	QUICAddrValidatorCacheTTL  = 30 * time.Minute
)

var NextProtoQUIC = []string{"doq", "doq-i02", "doq-i00", "dq"}

const (
	QUICCodeNoError       quic.ApplicationErrorCode = 0
	QUICCodeInternalError quic.ApplicationErrorCode = 1
	QUICCodeProtocolError quic.ApplicationErrorCode = 2
)

// 缓存系统相关常量
const (
	DefaultCacheTTL           = 3600
	StaleTTL                  = 30
	StaleMaxAge               = 259200
	CacheRefreshThreshold     = 300
	CacheRefreshQueueSize     = 500
	CacheRefreshRetryInterval = 600
)

// 并发控制相关常量
const (
	MaxConcurrency                  = 500
	SingleQueryMaxConcurrency       = 3
	NameServerResolveMaxConcurrency = 2
)

// DNS解析相关常量
const (
	MaxCNAMEChainLength       = 16
	MaxRecursionDepth         = 16
	MaxNameServerResolveCount = 3
)

// 超时时间相关常量
const (
	QueryTimeout             = 5 * time.Second
	StandardOperationTimeout = 5 * time.Second
	RecursiveQueryTimeout    = 30 * time.Second
	ExtendedQueryTimeout     = 25 * time.Second
	GracefulShutdownTimeout  = 10 * time.Second
)

// 文件处理相关常量
const (
	MaxConfigFileSize       = 1024 * 1024
	MaxInputLineLength      = 128
	FileScannerBufferSize   = 64 * 1024
	FileScannerMaxTokenSize = 1024 * 1024
	MaxRegexPatternLength   = 100
	MaxDNSRewriteRules      = 100
)

// Redis配置相关常量
const (
	RedisConnectionPoolSize    = 20
	RedisMinIdleConnections    = 5
	RedisMaxRetryAttempts      = 3
	RedisConnectionPoolTimeout = 5 * time.Second
	RedisReadOperationTimeout  = 3 * time.Second
	RedisWriteOperationTimeout = 3 * time.Second
	RedisDialTimeout           = 5 * time.Second
)

// IP检测相关常量
const (
	PublicIPDetectionTimeout = 3 * time.Second
	HTTPClientRequestTimeout = 5 * time.Second
	IPDetectionCacheExpiry   = 5 * time.Minute
	MaxTrustedIPv4CIDRs      = 1024
	MaxTrustedIPv6CIDRs      = 256
	DefaultECSIPv4PrefixLen  = 24
	DefaultECSIPv6PrefixLen  = 64
	DefaultECSClientScope    = 0
)

// ==================== 日志系统 ====================

type LogLevel int

const (
	LogNone LogLevel = iota - 1
	LogError
	LogWarn
	LogInfo
	LogDebug
)

const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorYellow = "\033[33m"
	ColorGreen  = "\033[32m"
	ColorBlue   = "\033[34m"
	ColorGray   = "\033[37m"
)

type LogConfig struct {
	level     LogLevel
	useColor  bool
	useEmojis bool
}

var (
	logConfig = &LogConfig{
		level:     LogInfo,
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

func writeLog(level LogLevel, format string, args ...interface{}) {
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

// ==================== 简化的错误处理和恢复系统 ====================

func handlePanic(operation string) {
	if r := recover(); r != nil {
		writeLog(LogError, "🚨 Panic恢复 [%s]: %v", operation, r)
	}
}

func executeWithRecover(operation string, fn func() error) error {
	defer handlePanic(operation)
	return fn()
}

// ==================== 简化的请求追踪系统 ====================

type RequestTracker struct {
	ID           string
	StartTime    time.Time
	Domain       string
	QueryType    string
	ClientIP     string
	CacheHit     bool
	Upstream     string
	ResponseTime time.Duration
	mutex        sync.Mutex
}

func NewRequestTracker(domain, qtype, clientIP string) *RequestTracker {
	return &RequestTracker{
		ID:        fmt.Sprintf("%d", time.Now().UnixNano()%1000000),
		StartTime: time.Now(),
		Domain:    domain,
		QueryType: qtype,
		ClientIP:  clientIP,
	}
}

func (rt *RequestTracker) AddStep(step string, args ...interface{}) {
	if logConfig.level >= LogDebug {
		rt.mutex.Lock()
		timestamp := time.Since(rt.StartTime).String()
		stepMsg := fmt.Sprintf("[%s] %s", timestamp, fmt.Sprintf(step, args...))
		writeLog(LogDebug, "🔍 [%s] %s", rt.ID, stepMsg)
		rt.mutex.Unlock()
	}
}

func (rt *RequestTracker) Finish() {
	rt.ResponseTime = time.Since(rt.StartTime)
	if logConfig.level >= LogInfo {
		cacheStatus := "MISS"
		if rt.CacheHit {
			cacheStatus = "HIT"
		}
		writeLog(LogInfo, "📊 [%s] 查询完成: %s %s | 缓存:%s | 耗时:%v | 上游:%s",
			rt.ID, rt.Domain, rt.QueryType, cacheStatus, rt.ResponseTime, rt.Upstream)
	}
}

// ==================== 简化的资源管理器 ====================

type ResourceManager struct {
	dnsMessages sync.Pool
}

func NewResourceManager() *ResourceManager {
	return &ResourceManager{
		dnsMessages: sync.Pool{
			New: func() interface{} {
				return new(dns.Msg)
			},
		},
	}
}

func (rm *ResourceManager) GetDNSMessage() *dns.Msg {
	msg := rm.dnsMessages.Get().(*dns.Msg)
	*msg = dns.Msg{}
	return msg
}

func (rm *ResourceManager) PutDNSMessage(msg *dns.Msg) {
	if msg != nil {
		rm.dnsMessages.Put(msg)
	}
}

var globalResourceManager = NewResourceManager()

// ==================== 简化的任务管理器 ====================

type TaskManager struct {
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
	semaphore   chan struct{}
	activeCount int64
}

func NewTaskManager(maxGoroutines int) *TaskManager {
	ctx, cancel := context.WithCancel(context.Background())
	return &TaskManager{
		ctx:       ctx,
		cancel:    cancel,
		semaphore: make(chan struct{}, maxGoroutines),
	}
}

func (tm *TaskManager) Execute(name string, fn func(ctx context.Context) error) error {
	select {
	case <-tm.ctx.Done():
		return tm.ctx.Err()
	case tm.semaphore <- struct{}{}:
		defer func() { <-tm.semaphore }()
	}

	atomic.AddInt64(&tm.activeCount, 1)
	defer atomic.AddInt64(&tm.activeCount, -1)

	tm.wg.Add(1)
	defer tm.wg.Done()

	return executeWithRecover(fmt.Sprintf("Task-%s", name), func() error {
		return fn(tm.ctx)
	})
}

func (tm *TaskManager) ExecuteAsync(name string, fn func(ctx context.Context) error) {
	go func() {
		if err := tm.Execute(name, fn); err != nil && err != context.Canceled {
			writeLog(LogError, "异步任务执行失败 [%s]: %v", name, err)
		}
	}()
}

func (tm *TaskManager) Shutdown(timeout time.Duration) error {
	tm.cancel()
	done := make(chan struct{})
	go func() {
		tm.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-time.After(timeout):
		return fmt.Errorf("shutdown timeout")
	}
}

// ==================== DNS Padding 管理器 ====================

type PaddingManager struct {
	enabled bool
}

func NewPaddingManager(enabled bool) *PaddingManager {
	return &PaddingManager{enabled: enabled}
}

func (pm *PaddingManager) IsEnabled() bool {
	return pm.enabled
}

func (pm *PaddingManager) CalculatePaddingSize(currentSize int) int {
	if !pm.enabled || currentSize <= 0 || currentSize >= DNSPaddingMaxSize {
		return 0
	}

	nextBlockSize := ((currentSize + DNSPaddingBlockSize - 1) / DNSPaddingBlockSize) * DNSPaddingBlockSize
	paddingSize := nextBlockSize - currentSize

	if currentSize+paddingSize > DNSPaddingMaxSize {
		return DNSPaddingMaxSize - currentSize
	}

	return paddingSize
}

func (pm *PaddingManager) CreatePaddingOption(paddingSize int) *dns.EDNS0_PADDING {
	if paddingSize <= 0 {
		return nil
	}
	return &dns.EDNS0_PADDING{
		Padding: make([]byte, paddingSize),
	}
}

// ==================== ECS选项结构 ====================

type ECSOption struct {
	Family       uint16
	SourcePrefix uint8
	ScopePrefix  uint8
	Address      net.IP
}

// ==================== EDNS管理器 ====================

type EDNSManager struct {
	defaultECS     *ECSOption
	detector       *IPDetector
	cache          sync.Map
	paddingManager *PaddingManager
}

func NewEDNSManager(defaultSubnet string, paddingEnabled bool) (*EDNSManager, error) {
	manager := &EDNSManager{
		detector:       NewIPDetector(),
		paddingManager: NewPaddingManager(paddingEnabled),
	}

	if defaultSubnet != "" {
		ecs, err := manager.parseECSConfig(defaultSubnet)
		if err != nil {
			return nil, fmt.Errorf("ECS配置解析失败: %w", err)
		}
		manager.defaultECS = ecs
		if ecs != nil {
			writeLog(LogInfo, "🌍 默认ECS配置: %s/%d", ecs.Address, ecs.SourcePrefix)
		}
	}

	if paddingEnabled {
		writeLog(LogInfo, "🔒 DNS Padding: 已启用 (RFC 7830, 块大小: %d字节, 仅对安全连接生效)", DNSPaddingBlockSize)
	}

	return manager, nil
}

func (em *EDNSManager) GetDefaultECS() *ECSOption {
	return em.defaultECS
}

func (em *EDNSManager) IsPaddingEnabled() bool {
	return em.paddingManager.IsEnabled()
}

func (em *EDNSManager) ParseFromDNS(msg *dns.Msg) *ECSOption {
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

func (em *EDNSManager) AddToMessage(msg *dns.Msg, ecs *ECSOption, dnssecEnabled bool, isSecureConnection bool) {
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
			Class:  ClientUDPBufferSize,
			Ttl:    0,
		},
	}

	if dnssecEnabled {
		opt.SetDo(true)
	}

	var options []dns.EDNS0

	// 添加ECS选项
	if ecs != nil {
		ecsOption := &dns.EDNS0_SUBNET{
			Code:          dns.EDNS0SUBNET,
			Family:        ecs.Family,
			SourceNetmask: ecs.SourcePrefix,
			SourceScope:   DefaultECSClientScope,
			Address:       ecs.Address,
		}
		options = append(options, ecsOption)
		writeLog(LogDebug, "🌍 添加ECS选项: %s/%d (scope=0)", ecs.Address, ecs.SourcePrefix)
	}

	// 添加Padding选项（仅对安全连接）
	if em.paddingManager.IsEnabled() && isSecureConnection {
		tempMsg := msg.Copy()
		opt.Option = options
		tempMsg.Extra = append(tempMsg.Extra, opt)

		currentSize := tempMsg.Len()
		paddingSize := em.paddingManager.CalculatePaddingSize(currentSize)

		if paddingOption := em.paddingManager.CreatePaddingOption(paddingSize); paddingOption != nil {
			options = append(options, paddingOption)
			writeLog(LogDebug, "🔒 DNS Padding: 消息从 %d 字节填充到 %d 字节 (+%d)",
				currentSize, currentSize+paddingSize, paddingSize)
		}
	}

	opt.Option = options
	msg.Extra = append(msg.Extra, opt)
}

func (em *EDNSManager) parseECSConfig(subnet string) (*ECSOption, error) {
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
			ScopePrefix:  DefaultECSClientScope,
			Address:      ipNet.IP,
		}, nil
	}
}

func (em *EDNSManager) detectPublicIP(forceIPv6, allowFallback bool) (*ECSOption, error) {
	cacheKey := fmt.Sprintf("ip_detection_%v_%v", forceIPv6, allowFallback)

	if cached, ok := em.cache.Load(cacheKey); ok {
		if cachedECS, ok := cached.(*ECSOption); ok {
			return cachedECS, nil
		}
	}

	var ecs *ECSOption
	if ip := em.detector.DetectPublicIP(forceIPv6); ip != nil {
		family := uint16(1)
		prefix := uint8(DefaultECSIPv4PrefixLen)

		if forceIPv6 {
			family = 2
			prefix = DefaultECSIPv6PrefixLen
		}

		ecs = &ECSOption{
			Family:       family,
			SourcePrefix: prefix,
			ScopePrefix:  DefaultECSClientScope,
			Address:      ip,
		}
	}

	// 回退处理
	if ecs == nil && allowFallback && !forceIPv6 {
		if ip := em.detector.DetectPublicIP(true); ip != nil {
			ecs = &ECSOption{
				Family:       2,
				SourcePrefix: DefaultECSIPv6PrefixLen,
				ScopePrefix:  DefaultECSClientScope,
				Address:      ip,
			}
		}
	}

	// 缓存结果
	if ecs != nil {
		em.cache.Store(cacheKey, ecs)
		time.AfterFunc(IPDetectionCacheExpiry, func() {
			em.cache.Delete(cacheKey)
		})
	}

	return ecs, nil
}

// ==================== 简化的IP检测器 ====================

type IPDetector struct {
	dnsClient  *dns.Client
	httpClient *http.Client
}

func NewIPDetector() *IPDetector {
	return &IPDetector{
		dnsClient: &dns.Client{
			Timeout: PublicIPDetectionTimeout,
			Net:     "udp",
			UDPSize: UpstreamUDPBufferSize,
		},
		httpClient: &http.Client{
			Timeout: HTTPClientRequestTimeout,
		},
	}
}

func (d *IPDetector) DetectPublicIP(forceIPv6 bool) net.IP {
	// 简化：只使用Cloudflare HTTP检测
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialer := &net.Dialer{Timeout: PublicIPDetectionTimeout}
			if forceIPv6 {
				return dialer.DialContext(ctx, "tcp6", addr)
			}
			return dialer.DialContext(ctx, "tcp4", addr)
		},
		TLSHandshakeTimeout: SecureConnHandshakeTimeout,
	}

	client := &http.Client{
		Timeout:   HTTPClientRequestTimeout,
		Transport: transport,
	}
	defer transport.CloseIdleConnections()

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

	// 检查IP版本匹配
	if forceIPv6 && ip.To4() != nil {
		return nil
	}
	if !forceIPv6 && ip.To4() == nil {
		return nil
	}

	return ip
}

// ==================== DNS记录转换和处理工具 ====================

type CompactDNSRecord struct {
	Text    string `json:"text"`
	OrigTTL uint32 `json:"orig_ttl"`
	Type    uint16 `json:"type"`
}

type DNSRecordHandler struct{}

func NewDNSRecordHandler() *DNSRecordHandler {
	return &DNSRecordHandler{}
}

func (drh *DNSRecordHandler) CompactRecord(rr dns.RR) *CompactDNSRecord {
	if rr == nil {
		return nil
	}
	return &CompactDNSRecord{
		Text:    rr.String(),
		OrigTTL: rr.Header().Ttl,
		Type:    rr.Header().Rrtype,
	}
}

func (drh *DNSRecordHandler) ExpandRecord(cr *CompactDNSRecord) dns.RR {
	if cr == nil || cr.Text == "" {
		return nil
	}
	rr, err := dns.NewRR(cr.Text)
	if err != nil {
		return nil
	}
	return rr
}

func (drh *DNSRecordHandler) CompactRecords(rrs []dns.RR) []*CompactDNSRecord {
	if len(rrs) == 0 {
		return nil
	}

	seen := make(map[string]bool)
	result := make([]*CompactDNSRecord, 0, len(rrs))

	for _, rr := range rrs {
		if rr == nil || rr.Header().Rrtype == dns.TypeOPT {
			continue
		}

		rrText := rr.String()
		if !seen[rrText] {
			seen[rrText] = true
			if cr := drh.CompactRecord(rr); cr != nil {
				result = append(result, cr)
			}
		}
	}
	return result
}

func (drh *DNSRecordHandler) ExpandRecords(crs []*CompactDNSRecord) []dns.RR {
	if len(crs) == 0 {
		return nil
	}
	result := make([]dns.RR, 0, len(crs))
	for _, cr := range crs {
		if rr := drh.ExpandRecord(cr); rr != nil {
			result = append(result, rr)
		}
	}
	return result
}

func (drh *DNSRecordHandler) AdjustTTL(rrs []dns.RR, ttl uint32) []dns.RR {
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

func (drh *DNSRecordHandler) FilterDNSSEC(rrs []dns.RR, includeDNSSEC bool) []dns.RR {
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

func (drh *DNSRecordHandler) ProcessRecords(rrs []dns.RR, ttl uint32, includeDNSSEC bool) []dns.RR {
	filtered := drh.FilterDNSSEC(rrs, includeDNSSEC)
	return drh.AdjustTTL(filtered, ttl)
}

var globalRecordHandler = NewDNSRecordHandler()

// ==================== 缓存工具 ====================

type CacheUtils struct{}

func NewCacheUtils() *CacheUtils {
	return &CacheUtils{}
}

func (cu *CacheUtils) BuildKey(question dns.Question, ecs *ECSOption, dnssecEnabled bool) string {
	var parts []string
	parts = append(parts, strings.ToLower(question.Name))
	parts = append(parts, fmt.Sprintf("%d", question.Qtype))
	parts = append(parts, fmt.Sprintf("%d", question.Qclass))

	if ecs != nil {
		parts = append(parts, fmt.Sprintf("%s/%d", ecs.Address.String(), ecs.SourcePrefix))
	}

	if dnssecEnabled {
		parts = append(parts, "dnssec")
	}

	result := strings.Join(parts, ":")
	if len(result) > 512 {
		result = fmt.Sprintf("hash:%x", result)[:512]
	}
	return result
}

func (cu *CacheUtils) CalculateTTL(rrs []dns.RR) int {
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

var globalCacheUtils = NewCacheUtils()

// ==================== 统一安全连接错误处理器 ====================

type SecureConnErrorHandler struct{}

func NewSecureConnErrorHandler() *SecureConnErrorHandler {
	return &SecureConnErrorHandler{}
}

func (h *SecureConnErrorHandler) IsRetryableError(protocol string, err error) bool {
	if err == nil {
		return false
	}

	switch strings.ToLower(protocol) {
	case "quic":
		return h.isQUICRetryableError(err)
	case "tls":
		return h.isTLSRetryableError(err)
	default:
		return false
	}
}

func (h *SecureConnErrorHandler) isQUICRetryableError(err error) bool {
	// 应用层错误
	var qAppErr *quic.ApplicationError
	if errors.As(err, &qAppErr) {
		return qAppErr.ErrorCode == 0 || qAppErr.ErrorCode == quic.ApplicationErrorCode(0x100)
	}

	// 空闲超时错误
	var qIdleErr *quic.IdleTimeoutError
	if errors.As(err, &qIdleErr) {
		return true
	}

	// 无状态重置错误
	var resetErr *quic.StatelessResetError
	if errors.As(err, &resetErr) {
		return true
	}

	// 传输错误
	var qTransportError *quic.TransportError
	if errors.As(err, &qTransportError) && qTransportError.ErrorCode == quic.NoError {
		return true
	}

	// 0-RTT被拒绝
	if errors.Is(err, quic.Err0RTTRejected) {
		return true
	}

	// 超时错误
	return errors.Is(err, os.ErrDeadlineExceeded)
}

func (h *SecureConnErrorHandler) isTLSRetryableError(err error) bool {
	if err == nil {
		return false
	}

	errStr := err.Error()
	connectionErrors := []string{
		"broken pipe",
		"connection reset",
		"use of closed network connection",
		"connection refused",
		"no route to host",
		"network is unreachable",
	}

	for _, connErr := range connectionErrors {
		if strings.Contains(errStr, connErr) {
			return true
		}
	}

	if errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}

	return errors.Is(err, io.EOF)
}

var globalSecureConnErrorHandler = NewSecureConnErrorHandler()

// ==================== 统一安全连接客户端 ====================

type SecureClient interface {
	Exchange(msg *dns.Msg, addr string) (*dns.Msg, error)
	Close() error
}

type UnifiedSecureClient struct {
	protocol        string
	serverName      string
	skipVerify      bool
	timeout         time.Duration
	tlsConn         *tls.Conn
	quicConn        *quic.Conn
	isQUICConnected bool
	lastActivity    time.Time
	mutex           sync.Mutex
}

func NewUnifiedSecureClient(protocol, addr, serverName string, skipVerify bool) (*UnifiedSecureClient, error) {
	client := &UnifiedSecureClient{
		protocol:     strings.ToLower(protocol),
		serverName:   serverName,
		skipVerify:   skipVerify,
		timeout:      SecureConnQueryTimeout,
		lastActivity: time.Now(),
	}

	if err := client.connect(addr); err != nil {
		return nil, err
	}

	return client, nil
}

func (c *UnifiedSecureClient) connect(addr string) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("解析地址失败: %w", err)
	}

	switch c.protocol {
	case "tls":
		return c.connectTLS(host, port)
	case "quic":
		return c.connectQUIC(net.JoinHostPort(host, port))
	default:
		return fmt.Errorf("不支持的协议: %s", c.protocol)
	}
}

func (c *UnifiedSecureClient) connectTLS(host, port string) error {
	tlsConfig := &tls.Config{
		ServerName:         c.serverName,
		InsecureSkipVerify: c.skipVerify,
	}

	dialer := &net.Dialer{
		Timeout:   SecureConnHandshakeTimeout,
		KeepAlive: SecureConnKeepAlive,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(host, port), tlsConfig)
	if err != nil {
		return fmt.Errorf("TLS连接失败: %w", err)
	}

	// 设置TCP keep-alive
	if tcpConn, ok := conn.NetConn().(*net.TCPConn); ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(SecureConnKeepAlive)
	}

	c.tlsConn = conn
	c.lastActivity = time.Now()
	return nil
}

func (c *UnifiedSecureClient) connectQUIC(addr string) error {
	tlsConfig := &tls.Config{
		ServerName:         c.serverName,
		InsecureSkipVerify: c.skipVerify,
		NextProtos:         NextProtoQUIC,
	}

	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()

	conn, err := quic.DialAddr(ctx, addr, tlsConfig, &quic.Config{
		MaxIdleTimeout:        SecureConnIdleTimeout,
		MaxIncomingStreams:    math.MaxUint16,
		MaxIncomingUniStreams: math.MaxUint16,
		KeepAlivePeriod:       SecureConnKeepAlive,
		Allow0RTT:             true,
	})
	if err != nil {
		return fmt.Errorf("QUIC连接失败: %w", err)
	}

	c.quicConn = conn
	c.isQUICConnected = true
	c.lastActivity = time.Now()
	return nil
}

func (c *UnifiedSecureClient) isConnectionAlive() bool {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	switch c.protocol {
	case "tls":
		if c.tlsConn == nil {
			return false
		}
		return time.Since(c.lastActivity) <= SecureConnIdleTimeout
	case "quic":
		return c.quicConn != nil && c.isQUICConnected &&
			time.Since(c.lastActivity) <= SecureConnIdleTimeout
	}
	return false
}

func (c *UnifiedSecureClient) reconnectIfNeeded(addr string) error {
	if c.isConnectionAlive() {
		return nil
	}

	writeLog(LogDebug, "检测到%s连接断开，重新建立连接", strings.ToUpper(c.protocol))

	// 清理旧连接
	c.closeConnection()

	// 重新建立连接
	return c.connect(addr)
}

func (c *UnifiedSecureClient) Exchange(msg *dns.Msg, addr string) (*dns.Msg, error) {
	// 检查并重连（如果需要）
	if err := c.reconnectIfNeeded(addr); err != nil {
		return nil, fmt.Errorf("重连失败: %w", err)
	}

	switch c.protocol {
	case "tls":
		resp, err := c.exchangeTLS(msg)
		// 如果是连接错误，尝试重连一次
		if err != nil && globalSecureConnErrorHandler.isTLSRetryableError(err) {
			writeLog(LogDebug, "TLS连接错误，尝试重连: %v", err)
			if c.connect(addr) == nil {
				return c.exchangeTLS(msg)
			}
		}
		return resp, err
	case "quic":
		return c.exchangeQUIC(msg)
	default:
		return nil, fmt.Errorf("不支持的协议: %s", c.protocol)
	}
}

func (c *UnifiedSecureClient) exchangeTLS(msg *dns.Msg) (*dns.Msg, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if c.tlsConn == nil {
		return nil, errors.New("TLS连接未建立")
	}

	deadline := time.Now().Add(c.timeout)
	c.tlsConn.SetDeadline(deadline)
	defer c.tlsConn.SetDeadline(time.Time{})

	msgData, err := msg.Pack()
	if err != nil {
		return nil, fmt.Errorf("消息打包失败: %w", err)
	}

	buf := make([]byte, 2+len(msgData))
	binary.BigEndian.PutUint16(buf[:2], uint16(len(msgData)))
	copy(buf[2:], msgData)

	if _, err := c.tlsConn.Write(buf); err != nil {
		return nil, fmt.Errorf("发送TLS查询失败: %w", err)
	}

	lengthBuf := make([]byte, 2)
	if _, err := io.ReadFull(c.tlsConn, lengthBuf); err != nil {
		return nil, fmt.Errorf("读取响应长度失败: %w", err)
	}

	respLength := binary.BigEndian.Uint16(lengthBuf)
	if respLength == 0 || respLength > UpstreamUDPBufferSize {
		return nil, fmt.Errorf("响应长度异常: %d", respLength)
	}

	respBuf := make([]byte, respLength)
	if _, err := io.ReadFull(c.tlsConn, respBuf); err != nil {
		return nil, fmt.Errorf("读取响应内容失败: %w", err)
	}

	response := new(dns.Msg)
	if err := response.Unpack(respBuf); err != nil {
		return nil, fmt.Errorf("响应解析失败: %w", err)
	}

	c.lastActivity = time.Now()
	return response, nil
}

func (c *UnifiedSecureClient) exchangeQUIC(msg *dns.Msg) (*dns.Msg, error) {
	originalID := msg.Id
	msg.Id = 0
	defer func() {
		msg.Id = originalID
	}()

	resp, err := c.exchangeQUICWithRetry(msg)
	if resp != nil {
		resp.Id = originalID
	}
	return resp, err
}

func (c *UnifiedSecureClient) exchangeQUICWithRetry(msg *dns.Msg) (*dns.Msg, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if c.quicConn == nil || !c.isQUICConnected {
		return nil, errors.New("QUIC连接未建立")
	}

	// 第一次尝试
	resp, err := c.exchangeQUICDirect(msg)

	// 如果失败且可重试，重新连接并重试
	if err != nil && globalSecureConnErrorHandler.IsRetryableError("quic", err) {
		writeLog(LogDebug, "QUIC连接失败，重新建立连接: %v", err)

		// 关闭旧连接
		c.closeQUICConn()

		return nil, fmt.Errorf("QUIC连接失败需要重新建立: %w", err)
	}

	return resp, err
}

func (c *UnifiedSecureClient) exchangeQUICDirect(msg *dns.Msg) (*dns.Msg, error) {
	msgData, err := msg.Pack()
	if err != nil {
		return nil, fmt.Errorf("消息打包失败: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()

	stream, err := c.quicConn.OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("创建QUIC流失败: %w", err)
	}
	defer stream.Close()

	if c.timeout > 0 {
		if err := stream.SetDeadline(time.Now().Add(c.timeout)); err != nil {
			return nil, fmt.Errorf("设置流超时失败: %w", err)
		}
	}

	// QUIC格式：2字节长度前缀 + DNS消息
	buf := make([]byte, 2+len(msgData))
	binary.BigEndian.PutUint16(buf[:2], uint16(len(msgData)))
	copy(buf[2:], msgData)

	if _, err = stream.Write(buf); err != nil {
		return nil, fmt.Errorf("发送QUIC查询失败: %w", err)
	}

	// 关闭写方向（QUIC协议要求）
	if err := stream.Close(); err != nil {
		writeLog(LogDebug, "关闭QUIC流写方向失败: %v", err)
	}

	// 读取响应
	resp, err := c.readQUICMsg(stream)
	if err == nil {
		c.lastActivity = time.Now()
	}
	return resp, err
}

func (c *UnifiedSecureClient) readQUICMsg(stream *quic.Stream) (*dns.Msg, error) {
	respBuf := make([]byte, SecureConnBufferSize)

	// 读取响应数据
	n, err := stream.Read(respBuf)
	if err != nil && n == 0 {
		return nil, fmt.Errorf("读取QUIC响应失败: %w", err)
	}

	// 取消读取（防止阻塞）
	stream.CancelRead(0)

	// 检查最小长度
	if n < 2 {
		return nil, fmt.Errorf("QUIC响应太短: %d字节", n)
	}

	// 验证长度前缀
	msgLen := binary.BigEndian.Uint16(respBuf[:2])
	if int(msgLen) != n-2 {
		writeLog(LogDebug, "QUIC响应长度不匹配: 声明=%d, 实际=%d", msgLen, n-2)
	}

	// 解析DNS消息（跳过2字节长度前缀）
	response := new(dns.Msg)
	if err := response.Unpack(respBuf[2:n]); err != nil {
		return nil, fmt.Errorf("QUIC响应解析失败: %w", err)
	}

	return response, nil
}

func (c *UnifiedSecureClient) closeConnection() {
	switch c.protocol {
	case "tls":
		if c.tlsConn != nil {
			c.tlsConn.Close()
			c.tlsConn = nil
		}
	case "quic":
		c.closeQUICConn()
	}
}

func (c *UnifiedSecureClient) closeQUICConn() {
	if c.quicConn != nil {
		c.quicConn.CloseWithError(QUICCodeNoError, "")
		c.quicConn = nil
		c.isQUICConnected = false
	}
}

func (c *UnifiedSecureClient) Close() error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.closeConnection()
	return nil
}

// ==================== 连接池管理器 ====================

type ConnectionPoolManager struct {
	clients       chan *dns.Client
	secureClients map[string]SecureClient
	timeout       time.Duration
	mutex         sync.RWMutex
}

func NewConnectionPoolManager() *ConnectionPoolManager {
	return &ConnectionPoolManager{
		clients:       make(chan *dns.Client, 50),
		secureClients: make(map[string]SecureClient),
		timeout:       QueryTimeout,
	}
}

func (cpm *ConnectionPoolManager) createClient() *dns.Client {
	return &dns.Client{
		Timeout: cpm.timeout,
		Net:     "udp",
		UDPSize: UpstreamUDPBufferSize,
	}
}

func (cpm *ConnectionPoolManager) GetUDPClient() *dns.Client {
	select {
	case client := <-cpm.clients:
		return client
	default:
		return cpm.createClient()
	}
}

func (cpm *ConnectionPoolManager) GetTCPClient() *dns.Client {
	return &dns.Client{
		Timeout: cpm.timeout,
		Net:     "tcp",
	}
}

func (cpm *ConnectionPoolManager) GetSecureClient(protocol, addr, serverName string, skipVerify bool) (SecureClient, error) {
	cacheKey := fmt.Sprintf("%s:%s:%s:%v", protocol, addr, serverName, skipVerify)

	cpm.mutex.RLock()
	if client, exists := cpm.secureClients[cacheKey]; exists {
		cpm.mutex.RUnlock()

		// 检查连接是否仍然有效
		if unifiedClient, ok := client.(*UnifiedSecureClient); ok {
			if unifiedClient.isConnectionAlive() {
				return client, nil
			} else {
				// 连接失效，从缓存中移除
				cpm.mutex.Lock()
				delete(cpm.secureClients, cacheKey)
				cpm.mutex.Unlock()
				client.Close()
			}
		}
	} else {
		cpm.mutex.RUnlock()
	}

	// 创建新的安全客户端
	client, err := NewUnifiedSecureClient(protocol, addr, serverName, skipVerify)
	if err != nil {
		return nil, err
	}

	// 缓存客户端
	cpm.mutex.Lock()
	cpm.secureClients[cacheKey] = client
	cpm.mutex.Unlock()

	return client, nil
}

func (cpm *ConnectionPoolManager) PutUDPClient(client *dns.Client) {
	if client == nil {
		return
	}
	select {
	case cpm.clients <- client:
	default:
	}
}

func (cpm *ConnectionPoolManager) Close() error {
	cpm.mutex.Lock()
	defer cpm.mutex.Unlock()

	for key, client := range cpm.secureClients {
		if err := client.Close(); err != nil {
			writeLog(LogWarn, "关闭安全客户端失败 [%s]: %v", key, err)
		}
	}
	cpm.secureClients = make(map[string]SecureClient)

	close(cpm.clients)
	for range cpm.clients {
	}

	return nil
}

// ==================== 统一安全DNS服务器管理器 ====================

type SecureDNSManager struct {
	server        *RecursiveDNSServer
	tlsConfig     *tls.Config
	ctx           context.Context
	cancel        context.CancelFunc
	wg            sync.WaitGroup
	tlsListener   net.Listener
	quicConn      *net.UDPConn
	quicListener  *quic.EarlyListener
	quicTransport *quic.Transport
	validator     gcache.Cache
}

func NewSecureDNSManager(server *RecursiveDNSServer, config *ServerConfig) (*SecureDNSManager, error) {
	cert, err := tls.LoadX509KeyPair(config.Server.TLS.CertFile, config.Server.TLS.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("加载证书失败: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &SecureDNSManager{
		server:    server,
		tlsConfig: tlsConfig,
		ctx:       ctx,
		cancel:    cancel,
		validator: gcache.New(QUICAddrValidatorCacheSize).LRU().Build(),
	}, nil
}

func (sm *SecureDNSManager) Start() error {
	var wg sync.WaitGroup
	errChan := make(chan error, 2)

	wg.Add(2)

	// 启动 TLS 服务器
	go func() {
		defer wg.Done()
		defer handlePanic("TLS服务器")

		if err := sm.startTLSServer(); err != nil {
			errChan <- fmt.Errorf("TLS启动失败: %w", err)
		}
	}()

	// 启动 QUIC 服务器
	go func() {
		defer wg.Done()
		defer handlePanic("QUIC服务器")

		if err := sm.startQUICServer(); err != nil {
			errChan <- fmt.Errorf("QUIC启动失败: %w", err)
		}
	}()

	// 等待启动完成或错误
	go func() {
		wg.Wait()
		close(errChan)
	}()

	for err := range errChan {
		if err != nil {
			return err
		}
	}

	return nil
}

func (sm *SecureDNSManager) startTLSServer() error {
	listener, err := net.Listen("tcp", ":"+sm.server.config.Server.TLS.Port)
	if err != nil {
		return fmt.Errorf("TLS监听失败: %w", err)
	}

	sm.tlsListener = tls.NewListener(listener, sm.tlsConfig)
	writeLog(LogInfo, "🔐 TLS服务器启动: %s", sm.tlsListener.Addr())

	sm.wg.Add(1)
	go func() {
		defer sm.wg.Done()
		defer handlePanic("TLS服务器")
		sm.handleTLSConnections()
	}()

	return nil
}

func (sm *SecureDNSManager) startQUICServer() error {
	addr := ":" + sm.server.config.Server.TLS.Port

	// 创建 UDP 连接
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return fmt.Errorf("解析UDP地址失败: %w", err)
	}

	sm.quicConn, err = net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("UDP监听失败: %w", err)
	}

	// 创建 QUIC Transport
	sm.quicTransport = &quic.Transport{
		Conn:                sm.quicConn,
		VerifySourceAddress: sm.requiresValidation,
	}

	// 创建 QUIC TLS 配置
	quicTLSConfig := sm.tlsConfig.Clone()
	quicTLSConfig.NextProtos = NextProtoQUIC

	// 创建 QUIC 监听器
	quicConfig := &quic.Config{
		MaxIdleTimeout:        SecureConnIdleTimeout,
		MaxIncomingStreams:    math.MaxUint16,
		MaxIncomingUniStreams: math.MaxUint16,
		Allow0RTT:             true,
	}

	sm.quicListener, err = sm.quicTransport.ListenEarly(quicTLSConfig, quicConfig)
	if err != nil {
		sm.quicConn.Close()
		return fmt.Errorf("QUIC监听失败: %w", err)
	}

	writeLog(LogInfo, "🚀 QUIC服务器启动: %s", sm.quicListener.Addr())

	sm.wg.Add(1)
	go func() {
		defer sm.wg.Done()
		defer handlePanic("QUIC服务器")
		sm.handleQUICConnections()
	}()

	return nil
}

// requiresValidation QUIC地址验证
func (sm *SecureDNSManager) requiresValidation(addr net.Addr) bool {
	key := addr.(*net.UDPAddr).IP.String()
	if sm.validator.Has(key) {
		return false
	}

	if err := sm.validator.SetWithExpire(key, true, QUICAddrValidatorCacheTTL); err != nil {
		writeLog(LogWarn, "QUIC验证器缓存设置失败: %v", err)
	}

	return true
}

func (sm *SecureDNSManager) handleTLSConnections() {
	for {
		select {
		case <-sm.ctx.Done():
			return
		default:
		}

		conn, err := sm.tlsListener.Accept()
		if err != nil {
			if sm.ctx.Err() != nil {
				return
			}
			writeLog(LogError, "TLS连接接受失败: %v", err)
			continue
		}

		sm.wg.Add(1)
		go func() {
			defer sm.wg.Done()
			defer handlePanic("TLS连接处理")
			defer conn.Close()
			sm.handleSecureDNSConnection(conn, "TLS")
		}()
	}
}

func (sm *SecureDNSManager) handleQUICConnections() {
	for {
		select {
		case <-sm.ctx.Done():
			return
		default:
		}

		conn, err := sm.quicListener.Accept(sm.ctx)
		if err != nil {
			if sm.ctx.Err() != nil {
				return
			}
			sm.logQUICError("accepting quic conn", err)
			continue
		}

		sm.wg.Add(1)
		go func() {
			defer sm.wg.Done()
			defer handlePanic("QUIC连接处理")
			sm.handleQUICConnection(conn)
		}()
	}
}

func (sm *SecureDNSManager) handleQUICConnection(conn *quic.Conn) {
	defer func() {
		conn.CloseWithError(QUICCodeNoError, "")
	}()

	for {
		select {
		case <-sm.ctx.Done():
			return
		default:
		}

		stream, err := conn.AcceptStream(sm.ctx)
		if err != nil {
			sm.logQUICError("accepting quic stream", err)
			return
		}

		sm.wg.Add(1)
		go func() {
			defer sm.wg.Done()
			defer handlePanic("QUIC流处理")
			defer stream.Close()
			sm.handleQUICStream(stream, conn)
		}()
	}
}

func (sm *SecureDNSManager) handleQUICStream(stream *quic.Stream, conn *quic.Conn) {
	// 读取DNS消息
	buf := make([]byte, SecureConnBufferSize)
	n, err := sm.readAll(stream, buf)

	if err != nil && err != io.EOF {
		writeLog(LogDebug, "QUIC流读取失败: %v", err)
		return
	}

	if n < MinDNSPacketSize {
		writeLog(LogDebug, "QUIC消息太短: %d字节", n)
		return
	}

	// 解析DNS消息 (QUIC格式，带长度前缀)
	req := new(dns.Msg)
	var msgData []byte

	// 检查是否有长度前缀
	packetLen := binary.BigEndian.Uint16(buf[:2])
	if packetLen == uint16(n-2) {
		// 有长度前缀，使用标准格式
		msgData = buf[2:n]
	} else {
		// 无长度前缀，不支持旧版本
		writeLog(LogDebug, "QUIC不支持的消息格式")
		conn.CloseWithError(QUICCodeProtocolError, "")
		return
	}

	if err := req.Unpack(msgData); err != nil {
		writeLog(LogDebug, "QUIC消息解析失败: %v", err)
		conn.CloseWithError(QUICCodeProtocolError, "")
		return
	}

	// 验证DNS消息
	if !sm.validQUICMsg(req) {
		conn.CloseWithError(QUICCodeProtocolError, "")
		return
	}

	// 处理DNS查询
	clientIP := sm.getSecureClientIP(conn, "QUIC")
	response := sm.server.ProcessDNSQuery(req, clientIP, true)

	// 发送响应
	if err := sm.respondQUIC(stream, response); err != nil {
		writeLog(LogDebug, "QUIC响应发送失败: %v", err)
	}
}

func (sm *SecureDNSManager) handleSecureDNSConnection(conn net.Conn, protocol string) {
	tlsConn := conn.(*tls.Conn)
	tlsConn.SetReadDeadline(time.Now().Add(SecureConnQueryTimeout))

	for {
		select {
		case <-sm.ctx.Done():
			return
		default:
		}

		lengthBuf := make([]byte, 2)
		if _, err := io.ReadFull(tlsConn, lengthBuf); err != nil {
			if err != io.EOF {
				writeLog(LogDebug, "%s长度读取失败: %v", protocol, err)
			}
			return
		}

		msgLength := binary.BigEndian.Uint16(lengthBuf)
		if msgLength == 0 || msgLength > UpstreamUDPBufferSize {
			writeLog(LogWarn, "%s消息长度异常: %d", protocol, msgLength)
			return
		}

		msgBuf := make([]byte, msgLength)
		if _, err := io.ReadFull(tlsConn, msgBuf); err != nil {
			writeLog(LogDebug, "%s消息读取失败: %v", protocol, err)
			return
		}

		req := new(dns.Msg)
		if err := req.Unpack(msgBuf); err != nil {
			writeLog(LogDebug, "%s消息解析失败: %v", protocol, err)
			return
		}

		clientIP := sm.getSecureClientIP(tlsConn, protocol)
		response := sm.server.ProcessDNSQuery(req, clientIP, true)

		respBuf, err := response.Pack()
		if err != nil {
			writeLog(LogError, "%s响应打包失败: %v", protocol, err)
			return
		}

		lengthPrefix := make([]byte, 2)
		binary.BigEndian.PutUint16(lengthPrefix, uint16(len(respBuf)))

		if _, err := tlsConn.Write(lengthPrefix); err != nil {
			writeLog(LogDebug, "%s响应长度写入失败: %v", protocol, err)
			return
		}

		if _, err := tlsConn.Write(respBuf); err != nil {
			writeLog(LogDebug, "%s响应写入失败: %v", protocol, err)
			return
		}

		tlsConn.SetReadDeadline(time.Now().Add(SecureConnQueryTimeout))
	}
}

func (sm *SecureDNSManager) getSecureClientIP(conn interface{}, protocol string) net.IP {
	switch c := conn.(type) {
	case *tls.Conn:
		if addr, ok := c.RemoteAddr().(*net.TCPAddr); ok {
			return addr.IP
		}
	case *quic.Conn:
		if addr, ok := c.RemoteAddr().(*net.UDPAddr); ok {
			return addr.IP
		}
	}
	return nil
}

// validQUICMsg 验证 QUIC DNS 消息
func (sm *SecureDNSManager) validQUICMsg(req *dns.Msg) bool {
	// 检查 EDNS TCP keepalive 选项（QUIC 中不允许）
	if opt := req.IsEdns0(); opt != nil {
		for _, option := range opt.Option {
			if option.Option() == dns.EDNS0TCPKEEPALIVE {
				writeLog(LogDebug, "QUIC客户端发送了不允许的TCP keepalive选项")
				return false
			}
		}
	}
	return true
}

// respondQUIC 发送 QUIC DNS 响应
func (sm *SecureDNSManager) respondQUIC(stream *quic.Stream, response *dns.Msg) error {
	if response == nil {
		return errors.New("响应消息为空")
	}

	// 打包DNS响应
	respBuf, err := response.Pack()
	if err != nil {
		return fmt.Errorf("响应打包失败: %w", err)
	}

	// QUIC格式：2字节长度前缀 + DNS消息
	buf := make([]byte, 2+len(respBuf))
	binary.BigEndian.PutUint16(buf[:2], uint16(len(respBuf)))
	copy(buf[2:], respBuf)

	// 写入流
	n, err := stream.Write(buf)
	if err != nil {
		return fmt.Errorf("流写入失败: %w", err)
	}

	if n != len(buf) {
		return fmt.Errorf("写入长度不匹配: %d != %d", n, len(buf))
	}

	return nil
}

// logQUICError 记录 QUIC 错误
func (sm *SecureDNSManager) logQUICError(prefix string, err error) {
	if sm.isQUICErrorForDebugLog(err) {
		writeLog(LogDebug, "QUIC连接关闭: %s - %v", prefix, err)
	} else {
		writeLog(LogError, "QUIC错误: %s - %v", prefix, err)
	}
}

// isQUICErrorForDebugLog 判断是否为调试级别的 QUIC 错误
func (sm *SecureDNSManager) isQUICErrorForDebugLog(err error) bool {
	if errors.Is(err, quic.ErrServerClosed) {
		return true
	}

	var qAppErr *quic.ApplicationError
	if errors.As(err, &qAppErr) &&
		(qAppErr.ErrorCode == quic.ApplicationErrorCode(quic.NoError) ||
			qAppErr.ErrorCode == quic.ApplicationErrorCode(quic.ApplicationErrorErrorCode)) {
		return true
	}

	if errors.Is(err, quic.Err0RTTRejected) {
		return true
	}

	var qIdleErr *quic.IdleTimeoutError
	return errors.As(err, &qIdleErr)
}

// readAll 从 reader 读取所有数据到缓冲区
func (sm *SecureDNSManager) readAll(r io.Reader, buf []byte) (int, error) {
	var n int
	for n < len(buf) {
		read, err := r.Read(buf[n:])
		n += read

		if err != nil {
			if err == io.EOF {
				return n, nil
			}
			return n, err
		}

		if n == len(buf) {
			return n, io.ErrShortBuffer
		}
	}
	return n, nil
}

func (sm *SecureDNSManager) Shutdown() error {
	writeLog(LogInfo, "🛑 正在关闭安全DNS服务器...")

	sm.cancel()

	// 关闭监听器
	if sm.tlsListener != nil {
		sm.tlsListener.Close()
	}
	if sm.quicListener != nil {
		sm.quicListener.Close()
	}
	if sm.quicConn != nil {
		sm.quicConn.Close()
	}

	// 等待连接处理完成
	done := make(chan struct{})
	go func() {
		sm.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		writeLog(LogInfo, "✅ 安全DNS服务器已安全关闭")
		return nil
	case <-time.After(GracefulShutdownTimeout):
		writeLog(LogWarn, "⏰ 安全DNS服务器关闭超时")
		return fmt.Errorf("安全DNS服务器关闭超时")
	}
}

// ==================== 查询引擎 ====================

type QueryResult struct {
	Response *dns.Msg
	Server   string
	Error    error
	Duration time.Duration
	UsedTCP  bool
	Protocol string
}

type QueryEngine struct {
	resourceManager *ResourceManager
	ednsManager     *EDNSManager
	connPool        *ConnectionPoolManager
	taskManager     *TaskManager
	timeout         time.Duration
}

func NewQueryEngine(resourceManager *ResourceManager, ednsManager *EDNSManager,
	connPool *ConnectionPoolManager, taskManager *TaskManager, timeout time.Duration) *QueryEngine {
	return &QueryEngine{
		resourceManager: resourceManager,
		ednsManager:     ednsManager,
		connPool:        connPool,
		taskManager:     taskManager,
		timeout:         timeout,
	}
}

func (qe *QueryEngine) BuildQuery(question dns.Question, ecs *ECSOption, dnssecEnabled bool, recursionDesired bool, isSecureConnection bool) *dns.Msg {
	msg := qe.resourceManager.GetDNSMessage()
	msg.SetQuestion(question.Name, question.Qtype)
	msg.RecursionDesired = recursionDesired
	qe.ednsManager.AddToMessage(msg, ecs, dnssecEnabled, isSecureConnection)
	return msg
}

func (qe *QueryEngine) BuildResponse(request *dns.Msg) *dns.Msg {
	msg := qe.resourceManager.GetDNSMessage()
	msg.SetReply(request)
	msg.Authoritative = false
	msg.RecursionAvailable = true
	return msg
}

func (qe *QueryEngine) ReleaseMessage(msg *dns.Msg) {
	if msg != nil {
		qe.resourceManager.PutDNSMessage(msg)
	}
}

func (qe *QueryEngine) executeQuery(ctx context.Context, msg *dns.Msg, server *UpstreamServer, useTCP bool, tracker *RequestTracker) (*dns.Msg, error) {
	protocol := strings.ToLower(server.Protocol)

	switch protocol {
	case "tls", "quic":
		client, err := qe.connPool.GetSecureClient(protocol, server.Address, server.ServerName, server.SkipTLSVerify)
		if err != nil {
			return nil, fmt.Errorf("获取%s客户端失败: %w", strings.ToUpper(protocol), err)
		}

		response, err := client.Exchange(msg, server.Address)
		if err != nil {
			return nil, err
		}

		if tracker != nil {
			tracker.AddStep("%s查询成功，响应码: %s", strings.ToUpper(protocol), dns.RcodeToString[response.Rcode])
		}

		return response, nil

	default:
		var client *dns.Client
		if useTCP || protocol == "tcp" {
			client = qe.connPool.GetTCPClient()
		} else {
			client = qe.connPool.GetUDPClient()
			defer qe.connPool.PutUDPClient(client)
		}

		response, _, err := client.ExchangeContext(ctx, msg, server.Address)

		if tracker != nil && err == nil {
			protocolName := "UDP"
			if useTCP || protocol == "tcp" {
				protocolName = "TCP"
			}
			tracker.AddStep("%s查询成功，响应码: %s", protocolName, dns.RcodeToString[response.Rcode])
		}

		return response, err
	}
}

func (qe *QueryEngine) ExecuteQuery(ctx context.Context, msg *dns.Msg, server *UpstreamServer, tracker *RequestTracker) *QueryResult {
	start := time.Now()
	result := &QueryResult{
		Server:   server.Address,
		Protocol: server.Protocol,
	}

	if tracker != nil {
		tracker.AddStep("开始查询服务器: %s (%s)", server.Address, server.Protocol)
	}

	queryCtx, cancel := context.WithTimeout(ctx, qe.timeout)
	defer cancel()

	protocol := strings.ToLower(server.Protocol)

	// 对于安全协议，直接查询不需要TCP回退
	if protocol == "tls" || protocol == "quic" {
		result.Response, result.Error = qe.executeQuery(queryCtx, msg, server, false, tracker)
		result.Duration = time.Since(start)
		result.Protocol = strings.ToUpper(protocol)
		return result
	}

	// 首先尝试UDP查询（仅对标准DNS）
	result.Response, result.Error = qe.executeQuery(queryCtx, msg, server, false, tracker)
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
	if needTCPFallback && protocol != "tcp" {
		tcpServer := *server
		tcpServer.Protocol = "tcp"
		tcpResponse, tcpErr := qe.executeQuery(queryCtx, msg, &tcpServer, true, tracker)

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
		result.Protocol = "TCP"

		if tracker != nil {
			tracker.AddStep("TCP查询成功")
		}
	}

	return result
}

func (qe *QueryEngine) ExecuteConcurrentQuery(ctx context.Context, msg *dns.Msg, servers []*UpstreamServer,
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

	// 启动并发查询
	for i := 0; i < concurrency && i < len(servers); i++ {
		server := servers[i]
		qe.taskManager.ExecuteAsync(fmt.Sprintf("ConcurrentQuery-%s", server.Address),
			func(ctx context.Context) error {
				result := qe.ExecuteQuery(ctx, msg, server, tracker)
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
						tracker.AddStep("并发查询成功，选择服务器: %s (%s)", result.Server, result.Protocol)
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

// ==================== IP过滤器 ====================

type IPFilter struct {
	trustedCIDRs   []*net.IPNet
	trustedCIDRsV6 []*net.IPNet
	mutex          sync.RWMutex
}

func NewIPFilter() *IPFilter {
	return &IPFilter{
		trustedCIDRs:   make([]*net.IPNet, 0, MaxTrustedIPv4CIDRs),
		trustedCIDRsV6: make([]*net.IPNet, 0, MaxTrustedIPv6CIDRs),
	}
}

func (f *IPFilter) LoadCIDRs(filename string) error {
	if filename == "" {
		writeLog(LogInfo, "🌍 IP过滤器未配置文件路径")
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

	f.mutex.Lock()
	defer f.mutex.Unlock()

	f.trustedCIDRs = make([]*net.IPNet, 0, MaxTrustedIPv4CIDRs)
	f.trustedCIDRsV6 = make([]*net.IPNet, 0, MaxTrustedIPv6CIDRs)

	scanner := bufio.NewScanner(file)
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
	writeLog(LogInfo, "🌍 IP过滤器加载完成: IPv4=%d条, IPv6=%d条", totalV4, totalV6)
	return scanner.Err()
}

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

func (f *IPFilter) IsTrustedIP(ip net.IP) bool {
	f.mutex.RLock()
	defer f.mutex.RUnlock()

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

		if f.IsTrustedIP(ip) {
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
	f.mutex.RLock()
	defer f.mutex.RUnlock()
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

type RewriteRule struct {
	Type        RewriteRuleType `json:"-"`
	TypeString  string          `json:"type"`
	Pattern     string          `json:"pattern"`
	Replacement string          `json:"replacement"`
	regex       *regexp.Regexp  `json:"-"`
}

type DNSRewriter struct {
	rules []RewriteRule
	mutex sync.RWMutex
}

func NewDNSRewriter() *DNSRewriter {
	return &DNSRewriter{
		rules: make([]RewriteRule, 0, 32),
	}
}

func (r *DNSRewriter) LoadRules(rules []RewriteRule) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

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
	writeLog(LogInfo, "🔄 DNS重写器加载完成: %d条规则", len(validRules))
	return nil
}

func (r *DNSRewriter) Rewrite(domain string) (string, bool) {
	if !r.HasRules() || len(domain) > RFCMaxDomainNameLength {
		return domain, false
	}

	r.mutex.RLock()
	defer r.mutex.RUnlock()

	domain = strings.ToLower(strings.TrimSuffix(domain, "."))

	for i := range r.rules {
		rule := &r.rules[i]
		if matched, result := r.matchRule(rule, domain); matched {
			result = dns.Fqdn(result)
			writeLog(LogDebug, "🔄 域名重写: %s -> %s", domain, result)
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

func (r *DNSRewriter) HasRules() bool {
	r.mutex.RLock()
	defer r.mutex.RUnlock()
	return len(r.rules) > 0
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
				return false, reason
			}
		}
	}
	return true, ""
}

// ==================== 扩展上游服务器管理 ====================

type UpstreamServer struct {
	Address       string `json:"address"`
	Policy        string `json:"policy"`
	Protocol      string `json:"protocol"`
	ServerName    string `json:"server_name"`
	SkipTLSVerify bool   `json:"skip_tls_verify"`
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
	mutex   sync.RWMutex
}

func NewUpstreamManager(servers []UpstreamServer) *UpstreamManager {
	activeServers := make([]*UpstreamServer, 0, len(servers))

	for i := range servers {
		server := &servers[i]
		if server.Protocol == "" {
			server.Protocol = "udp"
		}
		activeServers = append(activeServers, server)
	}

	return &UpstreamManager{
		servers: activeServers,
	}
}

func (um *UpstreamManager) GetServers() []*UpstreamServer {
	um.mutex.RLock()
	defer um.mutex.RUnlock()
	return um.servers
}

// ==================== 服务器配置 ====================

type ServerConfig struct {
	Server struct {
		Port            string `json:"port"`
		IPv6            bool   `json:"ipv6"`
		LogLevel        string `json:"log_level"`
		DefaultECS      string `json:"default_ecs_subnet"`
		TrustedCIDRFile string `json:"trusted_cidr_file"`

		TLS struct {
			Port     string `json:"port"`
			CertFile string `json:"cert_file"`
			KeyFile  string `json:"key_file"`
		} `json:"tls"`

		Features struct {
			ServeStale       bool `json:"serve_stale"`
			Prefetch         bool `json:"prefetch"`
			DNSSEC           bool `json:"dnssec"`
			HijackProtection bool `json:"hijack_protection"`
			Padding          bool `json:"padding"`
		} `json:"features"`
	} `json:"server"`

	Redis struct {
		Address   string `json:"address"`
		Password  string `json:"password"`
		Database  int    `json:"database"`
		KeyPrefix string `json:"key_prefix"`
	} `json:"redis"`

	Upstream []UpstreamServer `json:"upstream"`
	Rewrite  []RewriteRule    `json:"rewrite"`
}

type ConfigManager struct{}

func NewConfigManager() *ConfigManager {
	return &ConfigManager{}
}

func (cm *ConfigManager) LoadConfig(filename string) (*ServerConfig, error) {
	config := cm.getDefaultConfig()

	if filename == "" {
		writeLog(LogInfo, "📄 使用默认配置")
		return config, nil
	}

	if !cm.isValidFilePath(filename) {
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

	writeLog(LogInfo, "📄 配置文件加载成功: %s", filename)
	return config, cm.ValidateConfig(config)
}

func (cm *ConfigManager) ValidateConfig(config *ServerConfig) error {
	// 验证日志级别
	if err := cm.validateLogLevel(config.Server.LogLevel); err != nil {
		return err
	}

	// 验证ECS配置
	if err := cm.validateECSConfig(config.Server.DefaultECS); err != nil {
		return err
	}

	// 验证上游服务器配置
	if err := cm.validateUpstreamServers(config.Upstream); err != nil {
		return err
	}

	// 验证Redis配置
	if err := cm.validateRedisConfig(config); err != nil {
		return err
	}

	// 验证TLS配置
	if err := cm.validateTLSConfig(config); err != nil {
		return err
	}

	return nil
}

func (cm *ConfigManager) validateLogLevel(logLevel string) error {
	validLevels := map[string]LogLevel{
		"none": LogNone, "error": LogError, "warn": LogWarn,
		"info": LogInfo, "debug": LogDebug,
	}
	if level, ok := validLevels[strings.ToLower(logLevel)]; ok {
		logConfig.level = level
		return nil
	}
	return fmt.Errorf("无效的日志级别: %s", logLevel)
}

func (cm *ConfigManager) validateECSConfig(ecsConfig string) error {
	if ecsConfig == "" {
		return nil
	}

	ecs := strings.ToLower(ecsConfig)
	validPresets := []string{"auto", "auto_v4", "auto_v6"}
	for _, preset := range validPresets {
		if ecs == preset {
			return nil
		}
	}

	if _, _, err := net.ParseCIDR(ecsConfig); err != nil {
		return fmt.Errorf("ECS子网格式错误: %w", err)
	}
	return nil
}

func (cm *ConfigManager) validateUpstreamServers(servers []UpstreamServer) error {
	for i, server := range servers {
		if !server.IsRecursive() {
			if _, _, err := net.SplitHostPort(server.Address); err != nil {
				return fmt.Errorf("上游服务器 %d 地址格式错误: %w", i, err)
			}
		}

		validPolicies := map[string]bool{"all": true, "trusted_only": true, "untrusted_only": true}
		if !validPolicies[server.Policy] {
			return fmt.Errorf("上游服务器 %d 信任策略无效: %s", i, server.Policy)
		}

		validProtocols := map[string]bool{"udp": true, "tcp": true, "tls": true, "quic": true}
		if server.Protocol != "" && !validProtocols[strings.ToLower(server.Protocol)] {
			return fmt.Errorf("上游服务器 %d 协议无效: %s", i, server.Protocol)
		}

		if (strings.ToLower(server.Protocol) == "tls" || strings.ToLower(server.Protocol) == "quic") && server.ServerName == "" {
			return fmt.Errorf("上游服务器 %d 使用 %s 协议需要配置 server_name", i, server.Protocol)
		}
	}
	return nil
}

func (cm *ConfigManager) validateRedisConfig(config *ServerConfig) error {
	if config.Redis.Address != "" {
		if _, _, err := net.SplitHostPort(config.Redis.Address); err != nil {
			return fmt.Errorf("Redis地址格式错误: %w", err)
		}
	} else {
		if config.Server.Features.ServeStale {
			writeLog(LogWarn, "⚠️ 无缓存模式下禁用过期缓存服务功能")
			config.Server.Features.ServeStale = false
		}
		if config.Server.Features.Prefetch {
			writeLog(LogWarn, "⚠️ 无缓存模式下禁用预取功能")
			config.Server.Features.Prefetch = false
		}
	}
	return nil
}

func (cm *ConfigManager) validateTLSConfig(config *ServerConfig) error {
	if config.Server.TLS.CertFile != "" || config.Server.TLS.KeyFile != "" {
		if config.Server.TLS.CertFile == "" || config.Server.TLS.KeyFile == "" {
			return fmt.Errorf("证书和私钥文件必须同时配置")
		}

		if !cm.isValidFilePath(config.Server.TLS.CertFile) {
			return fmt.Errorf("证书文件不存在: %s", config.Server.TLS.CertFile)
		}
		if !cm.isValidFilePath(config.Server.TLS.KeyFile) {
			return fmt.Errorf("私钥文件不存在: %s", config.Server.TLS.KeyFile)
		}

		if _, err := tls.LoadX509KeyPair(config.Server.TLS.CertFile, config.Server.TLS.KeyFile); err != nil {
			return fmt.Errorf("证书加载失败: %w", err)
		}

		writeLog(LogInfo, "✅ TLS证书验证通过")
	}

	return nil
}

func (cm *ConfigManager) getDefaultConfig() *ServerConfig {
	config := &ServerConfig{}

	config.Server.Port = DNSServerPort
	config.Server.IPv6 = true
	config.Server.LogLevel = "info"
	config.Server.DefaultECS = "auto"
	config.Server.TrustedCIDRFile = ""

	config.Server.TLS.Port = DNSServerSecurePort
	config.Server.TLS.CertFile = ""
	config.Server.TLS.KeyFile = ""

	config.Server.Features.ServeStale = false
	config.Server.Features.Prefetch = false
	config.Server.Features.DNSSEC = true
	config.Server.Features.HijackProtection = false
	config.Server.Features.Padding = false

	config.Redis.Address = ""
	config.Redis.Password = ""
	config.Redis.Database = 0
	config.Redis.KeyPrefix = "zjdns:"

	config.Upstream = []UpstreamServer{}
	config.Rewrite = []RewriteRule{}

	return config
}

func (cm *ConfigManager) isValidFilePath(path string) bool {
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

func (cm *ConfigManager) GenerateExampleConfig() string {
	config := cm.getDefaultConfig()

	config.Server.LogLevel = "info"
	config.Server.DefaultECS = "auto"
	config.Server.TrustedCIDRFile = "trusted_cidr.txt"

	config.Server.TLS.CertFile = "/path/to/cert.pem"
	config.Server.TLS.KeyFile = "/path/to/key.pem"

	config.Redis.Address = "127.0.0.1:6379"
	config.Server.Features.ServeStale = true
	config.Server.Features.Prefetch = true
	config.Server.Features.HijackProtection = true
	config.Server.Features.Padding = false

	config.Upstream = []UpstreamServer{
		{
			Address:  "223.5.5.5:53",
			Policy:   "all",
			Protocol: "tcp",
		},
		{
			Address:  "223.6.6.6:53",
			Policy:   "all",
			Protocol: "udp",
		},
		{
			Address:       "223.5.5.5:853",
			Policy:        "trusted_only",
			Protocol:      "tls",
			ServerName:    "dns.alidns.com",
			SkipTLSVerify: false,
		},
		{
			Address:       "223.6.6.6:853",
			Policy:        "all",
			Protocol:      "quic",
			ServerName:    "dns.alidns.com",
			SkipTLSVerify: true,
		},
		{
			Address: RecursiveServerIndicator,
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

var globalConfigManager = NewConfigManager()

func LoadConfig(filename string) (*ServerConfig, error) {
	return globalConfigManager.LoadConfig(filename)
}

func isValidFilePath(path string) bool {
	return globalConfigManager.isValidFilePath(path)
}

func GenerateExampleConfig() string {
	return globalConfigManager.GenerateExampleConfig()
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
	RefreshTime     int64               `json:"refresh_time,omitempty"`
	ECSFamily       uint16              `json:"ecs_family,omitempty"`
	ECSSourcePrefix uint8               `json:"ecs_source_prefix,omitempty"`
	ECSScopePrefix  uint8               `json:"ecs_scope_prefix,omitempty"`
	ECSAddress      string              `json:"ecs_address,omitempty"`
}

func (c *CacheEntry) IsExpired() bool {
	return time.Now().Unix()-c.Timestamp > int64(c.TTL)
}

func (c *CacheEntry) IsStale() bool {
	return time.Now().Unix()-c.Timestamp > int64(c.TTL+StaleMaxAge)
}

func (c *CacheEntry) ShouldRefresh() bool {
	now := time.Now().Unix()
	return c.IsExpired() &&
		(now-c.Timestamp) > int64(c.TTL+CacheRefreshThreshold) &&
		(now-c.RefreshTime) > CacheRefreshRetryInterval
}

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

func (c *CacheEntry) ShouldBeDeleted() bool {
	now := time.Now().Unix()
	totalAge := now - c.Timestamp
	return totalAge > int64(c.TTL+StaleMaxAge)
}

func (c *CacheEntry) GetAnswerRRs() []dns.RR {
	return globalRecordHandler.ExpandRecords(c.Answer)
}

func (c *CacheEntry) GetAuthorityRRs() []dns.RR {
	return globalRecordHandler.ExpandRecords(c.Authority)
}

func (c *CacheEntry) GetAdditionalRRs() []dns.RR {
	return globalRecordHandler.ExpandRecords(c.Additional)
}

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

// ==================== 缓存接口 ====================

type DNSCache interface {
	Get(key string) (*CacheEntry, bool, bool)
	Set(key string, answer, authority, additional []dns.RR, validated bool, ecs *ECSOption)
	RequestRefresh(req RefreshRequest)
	Shutdown()
}

type NullCache struct{}

func NewNullCache() *NullCache {
	writeLog(LogInfo, "🚫 无缓存模式")
	return &NullCache{}
}

func (nc *NullCache) Get(key string) (*CacheEntry, bool, bool) { return nil, false, false }
func (nc *NullCache) Set(key string, answer, authority, additional []dns.RR, validated bool, ecs *ECSOption) {
}
func (nc *NullCache) RequestRefresh(req RefreshRequest) {}
func (nc *NullCache) Shutdown()                         {}

// ==================== 简化的Redis缓存实现 ====================

type RedisDNSCache struct {
	client       *redis.Client
	config       *ServerConfig
	keyPrefix    string
	refreshQueue chan RefreshRequest
	ctx          context.Context
	cancel       context.CancelFunc
	wg           sync.WaitGroup
	taskManager  *TaskManager
	server       *RecursiveDNSServer
	closed       int32
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
			defer handlePanic(fmt.Sprintf("Redis刷新Worker %d", workerID))

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
	defer handlePanic("Redis刷新请求处理")

	if atomic.LoadInt32(&rc.closed) != 0 {
		return
	}

	answer, authority, additional, validated, ecsResponse, err := rc.server.QueryForRefresh(
		req.Question, req.ECS, req.ServerDNSSECEnabled)

	if err != nil {
		rc.updateRefreshTime(req.CacheKey)
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
		expiration += time.Duration(StaleMaxAge) * time.Second
	}

	rc.client.Set(rc.ctx, fullKey, data, expiration)
}

func (rc *RedisDNSCache) updateRefreshTime(cacheKey string) {
	defer handlePanic("更新刷新时间")

	if atomic.LoadInt32(&rc.closed) != 0 {
		return
	}

	fullKey := rc.keyPrefix + cacheKey
	data, err := rc.client.Get(rc.ctx, fullKey).Result()
	if err != nil {
		return
	}

	var entry CacheEntry
	if err := json.Unmarshal(unsafe.Slice(unsafe.StringData(data), len(data)), &entry); err != nil {
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
	defer handlePanic("Redis缓存获取")

	if atomic.LoadInt32(&rc.closed) != 0 {
		return nil, false, false
	}

	fullKey := rc.keyPrefix + key
	data, err := rc.client.Get(rc.ctx, fullKey).Result()
	if err != nil {
		return nil, false, false
	}

	var entry CacheEntry
	if err := json.Unmarshal(unsafe.Slice(unsafe.StringData(data), len(data)), &entry); err != nil {
		return nil, false, false
	}

	if entry.ShouldBeDeleted() {
		go func() {
			rc.client.Del(rc.ctx, fullKey)
		}()
		return nil, false, false
	}

	entry.AccessTime = time.Now().Unix()
	go func() {
		rc.updateAccessInfo(fullKey, &entry)
	}()

	isExpired := entry.IsExpired()

	if !rc.config.Server.Features.ServeStale && isExpired {
		go func() {
			rc.client.Del(rc.ctx, fullKey)
		}()
		return nil, false, false
	}

	return &entry, true, isExpired
}

func (rc *RedisDNSCache) Set(key string, answer, authority, additional []dns.RR, validated bool, ecs *ECSOption) {
	defer handlePanic("Redis缓存设置")

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
		expiration += time.Duration(StaleMaxAge) * time.Second
	}

	rc.client.Set(rc.ctx, fullKey, data, expiration)
}

func (rc *RedisDNSCache) updateAccessInfo(fullKey string, entry *CacheEntry) {
	defer handlePanic("Redis访问信息更新")

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

	rc.taskManager.Shutdown(5 * time.Second)
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

	rc.client.Close()
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
	if response.AuthenticatedData {
		return true
	}
	return v.HasDNSSECRecords(response)
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
	Protocol       string
}

// ==================== 主DNS服务器 ====================

type RecursiveDNSServer struct {
	config           *ServerConfig
	cache            DNSCache
	rootServersV4    []string
	rootServersV6    []string
	connPool         *ConnectionPoolManager
	dnssecVal        *DNSSECValidator
	concurrencyLimit chan struct{}
	ctx              context.Context
	cancel           context.CancelFunc
	shutdown         chan struct{}
	ipFilter         *IPFilter
	dnsRewriter      *DNSRewriter
	upstreamManager  *UpstreamManager
	wg               sync.WaitGroup
	taskManager      *TaskManager
	hijackPrevention *DNSHijackPrevention
	ednsManager      *EDNSManager
	queryEngine      *QueryEngine
	secureDNSManager *SecureDNSManager
	closed           int32
}

func (r *RecursiveDNSServer) QueryForRefresh(question dns.Question, ecs *ECSOption, serverDNSSECEnabled bool) ([]dns.RR, []dns.RR, []dns.RR, bool, *ECSOption, error) {
	defer handlePanic("缓存刷新查询")

	if atomic.LoadInt32(&r.closed) != 0 {
		return nil, nil, nil, false, nil, errors.New("server is closed")
	}

	refreshCtx, cancel := context.WithTimeout(r.ctx, ExtendedQueryTimeout)
	defer cancel()

	servers := r.upstreamManager.GetServers()
	if len(servers) > 0 {
		return r.queryUpstreamServers(question, ecs, serverDNSSECEnabled, nil)
	} else {
		return r.resolveWithCNAME(refreshCtx, question, ecs, nil)
	}
}

func NewDNSServer(config *ServerConfig) (*RecursiveDNSServer, error) {
	rootServersV4 := []string{
		"198.41.0.4:53", "170.247.170.2:53", "192.33.4.12:53", "199.7.91.13:53",
		"192.203.230.10:53", "192.5.5.241:53", "192.112.36.4:53", "198.97.190.53:53",
		"192.36.148.17:53", "192.58.128.30:53", "193.0.14.129:53", "199.7.83.42:53", "202.12.27.33:53",
	}

	rootServersV6 := []string{
		"[2001:503:ba3e::2:30]:53", "[2801:1b8:10::b]:53", "[2001:500:2::c]:53", "[2001:500:2d::d]:53",
		"[2001:500:a8::e]:53", "[2001:500:2f::f]:53", "[2001:500:12::d0d]:53", "[2001:500:1::53]:53",
		"[2001:7fe::53]:53", "[2001:503:c27::2:30]:53", "[2001:7fd::1]:53", "[2001:500:9f::42]:53", "[2001:dc3::35]:53",
	}

	ctx, cancel := context.WithCancel(context.Background())

	ednsManager, err := NewEDNSManager(config.Server.DefaultECS, config.Server.Features.Padding)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("EDNS管理器初始化失败: %w", err)
	}

	ipFilter := NewIPFilter()
	if config.Server.TrustedCIDRFile != "" {
		if err := ipFilter.LoadCIDRs(config.Server.TrustedCIDRFile); err != nil {
			cancel()
			return nil, fmt.Errorf("加载可信CIDR文件失败: %w", err)
		}
	}

	dnsRewriter := NewDNSRewriter()
	if len(config.Rewrite) > 0 {
		if err := dnsRewriter.LoadRules(config.Rewrite); err != nil {
			cancel()
			return nil, fmt.Errorf("加载DNS重写规则失败: %w", err)
		}
	}

	upstreamManager := NewUpstreamManager(config.Upstream)
	connPool := NewConnectionPoolManager()
	taskManager := NewTaskManager(MaxConcurrency)
	queryEngine := NewQueryEngine(globalResourceManager, ednsManager, connPool, taskManager, QueryTimeout)
	hijackPrevention := NewDNSHijackPrevention(config.Server.Features.HijackProtection)

	server := &RecursiveDNSServer{
		config:           config,
		rootServersV4:    rootServersV4,
		rootServersV6:    rootServersV6,
		connPool:         connPool,
		dnssecVal:        NewDNSSECValidator(),
		concurrencyLimit: make(chan struct{}, MaxConcurrency),
		ctx:              ctx,
		cancel:           cancel,
		shutdown:         make(chan struct{}),
		ipFilter:         ipFilter,
		dnsRewriter:      dnsRewriter,
		upstreamManager:  upstreamManager,
		taskManager:      taskManager,
		hijackPrevention: hijackPrevention,
		ednsManager:      ednsManager,
		queryEngine:      queryEngine,
	}

	if config.Server.TLS.CertFile != "" && config.Server.TLS.KeyFile != "" {
		secureDNSManager, err := NewSecureDNSManager(server, config)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("安全DNS管理器初始化失败: %w", err)
		}
		server.secureDNSManager = secureDNSManager
	}

	var cache DNSCache
	if config.Redis.Address == "" {
		cache = NewNullCache()
	} else {
		redisCache, err := NewRedisDNSCache(config, server)
		if err != nil {
			cancel()
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
		defer handlePanic("信号处理器")

		select {
		case sig := <-sigChan:
			writeLog(LogInfo, "🛑 收到信号 %v，开始优雅关闭...", sig)
			r.shutdownServer()
		case <-r.ctx.Done():
			return
		}
	}()
}

func (r *RecursiveDNSServer) shutdownServer() {
	if !atomic.CompareAndSwapInt32(&r.closed, 0, 1) {
		return
	}

	r.cancel()
	r.cache.Shutdown()

	if r.secureDNSManager != nil {
		r.secureDNSManager.Shutdown()
	}

	r.connPool.Close()
	r.taskManager.Shutdown(GracefulShutdownTimeout)

	done := make(chan struct{})
	go func() {
		r.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		writeLog(LogInfo, "✅ 所有组件已安全关闭")
	case <-time.After(GracefulShutdownTimeout):
		writeLog(LogWarn, "⏰ 组件关闭超时")
	}

	close(r.shutdown)
	time.Sleep(time.Second)
	os.Exit(0)
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
	if atomic.LoadInt32(&r.closed) != 0 {
		return errors.New("server is closed")
	}

	var wg sync.WaitGroup
	serverCount := 2

	if r.secureDNSManager != nil {
		serverCount += 1
	}

	errChan := make(chan error, serverCount)

	writeLog(LogInfo, "🚀 启动 ZJDNS Server")
	writeLog(LogInfo, "🌐 监听端口: %s", r.config.Server.Port)

	r.displayInfo()

	wg.Add(serverCount)

	// 启动 UDP 服务器
	go func() {
		defer wg.Done()
		defer handlePanic("UDP服务器")

		server := &dns.Server{
			Addr:    ":" + r.config.Server.Port,
			Net:     "udp",
			Handler: dns.HandlerFunc(r.handleDNSRequest),
			UDPSize: ClientUDPBufferSize,
		}
		writeLog(LogInfo, "📡 UDP服务器启动: [::]:"+r.config.Server.Port)
		if err := server.ListenAndServe(); err != nil {
			errChan <- fmt.Errorf("UDP启动失败: %w", err)
		}
	}()

	// 启动 TCP 服务器
	go func() {
		defer wg.Done()
		defer handlePanic("TCP服务器")

		server := &dns.Server{
			Addr:    ":" + r.config.Server.Port,
			Net:     "tcp",
			Handler: dns.HandlerFunc(r.handleDNSRequest),
		}
		writeLog(LogInfo, "🔌 TCP服务器启动: [::]:"+r.config.Server.Port)
		if err := server.ListenAndServe(); err != nil {
			errChan <- fmt.Errorf("TCP启动失败: %w", err)
		}
	}()

	// 启动安全DNS服务器（如果已配置）
	if r.secureDNSManager != nil {
		go func() {
			defer wg.Done()
			defer handlePanic("安全DNS服务器")

			if err := r.secureDNSManager.Start(); err != nil {
				errChan <- fmt.Errorf("安全DNS启动失败: %w", err)
			}
		}()
	}

	// 等待错误或正常结束
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
				writeLog(LogInfo, "🔗 上游服务器: 递归解析 - %s", server.Policy)
			} else {
				protocol := strings.ToUpper(server.Protocol)
				if protocol == "" {
					protocol = "UDP"
				}
				serverInfo := fmt.Sprintf("%s (%s) - %s", server.Address, protocol, server.Policy)
				if server.SkipTLSVerify && (protocol == "TLS" || protocol == "QUIC") {
					serverInfo += " [跳过TLS验证]"
				}
				writeLog(LogInfo, "🔗 上游服务器: %s", serverInfo)
			}
		}
		writeLog(LogInfo, "🔗 上游模式: 共 %d 个服务器", len(servers))
	} else {
		if r.config.Redis.Address == "" {
			writeLog(LogInfo, "🚫 递归模式 (无缓存)")
		} else {
			writeLog(LogInfo, "💾 递归模式 + Redis缓存: %s", r.config.Redis.Address)
		}
	}

	if r.secureDNSManager != nil {
		writeLog(LogInfo, "🔐 监听加密端口: %s", r.config.Server.TLS.Port)
	}

	if r.ipFilter.HasData() {
		writeLog(LogInfo, "🌍 IP过滤器: 已启用 (配置文件: %s)", r.config.Server.TrustedCIDRFile)
	}
	if r.dnsRewriter.HasRules() {
		writeLog(LogInfo, "🔄 DNS重写器: 已启用 (%d条规则)", len(r.config.Rewrite))
	}
	if r.config.Server.Features.HijackProtection {
		writeLog(LogInfo, "🛡️ DNS劫持预防: 已启用")
	}
	if defaultECS := r.ednsManager.GetDefaultECS(); defaultECS != nil {
		writeLog(LogInfo, "🌍 默认ECS: %s/%d", defaultECS.Address, defaultECS.SourcePrefix)
	}
	if r.ednsManager.IsPaddingEnabled() {
		writeLog(LogInfo, "🔒 DNS Padding: 已启用")
	}

	writeLog(LogInfo, "⚡ 最大并发: %d", MaxConcurrency)
}

func (r *RecursiveDNSServer) handleDNSRequest(w dns.ResponseWriter, req *dns.Msg) {
	if atomic.LoadInt32(&r.closed) != 0 {
		return
	}

	executeWithRecover("DNS请求处理", func() error {
		select {
		case <-r.ctx.Done():
			return nil
		default:
		}

		response := r.ProcessDNSQuery(req, GetClientIP(w), false)
		return w.WriteMsg(response)
	})
}

func (r *RecursiveDNSServer) ProcessDNSQuery(req *dns.Msg, clientIP net.IP, isSecureConnection bool) *dns.Msg {
	if atomic.LoadInt32(&r.closed) != 0 {
		msg := r.queryEngine.BuildResponse(req)
		msg.Rcode = dns.RcodeServerFailure
		return msg
	}

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
		msg.Rcode = dns.RcodeFormatError
		if tracker != nil {
			tracker.AddStep("域名过长被拒绝: %d字符", len(question.Name))
		}
		return msg
	}

	if tracker != nil {
		tracker.AddStep("开始处理查询: %s %s", question.Name, dns.TypeToString[question.Qtype])
		if isSecureConnection {
			tracker.AddStep("安全连接查询，将启用DNS Padding")
		}
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

	// 解析EDNS选项
	clientRequestedDNSSEC := false
	clientHasEDNS := false
	var ecsOpt *ECSOption

	if opt := req.IsEdns0(); opt != nil {
		clientHasEDNS = true
		clientRequestedDNSSEC = opt.Do()
		ecsOpt = r.ednsManager.ParseFromDNS(req)
		if tracker != nil && ecsOpt != nil {
			tracker.AddStep("客户端ECS: %s/%d", ecsOpt.Address, ecsOpt.SourcePrefix)
		}
	}

	if ecsOpt == nil {
		ecsOpt = r.ednsManager.GetDefaultECS()
		if tracker != nil && ecsOpt != nil {
			tracker.AddStep("使用默认ECS: %s/%d", ecsOpt.Address, ecsOpt.SourcePrefix)
		}
	}

	serverDNSSECEnabled := r.config.Server.Features.DNSSEC
	cacheKey := globalCacheUtils.BuildKey(question, ecsOpt, serverDNSSECEnabled)

	if tracker != nil {
		tracker.AddStep("缓存键: %s", cacheKey)
	}

	// 缓存查找
	if entry, found, isExpired := r.cache.Get(cacheKey); found {
		return r.handleCacheHit(msg, entry, isExpired, question, originalDomain,
			clientRequestedDNSSEC, clientHasEDNS, ecsOpt, cacheKey, tracker, isSecureConnection)
	}

	if tracker != nil {
		tracker.AddStep("缓存未命中，开始查询")
	}
	return r.handleCacheMiss(msg, question, originalDomain, ecsOpt,
		clientRequestedDNSSEC, clientHasEDNS, serverDNSSECEnabled, cacheKey, tracker, isSecureConnection)
}

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

func (r *RecursiveDNSServer) handleCacheHit(msg *dns.Msg, entry *CacheEntry, isExpired bool,
	question dns.Question, originalDomain string, clientRequestedDNSSEC bool, clientHasEDNS bool,
	ecsOpt *ECSOption, cacheKey string, tracker *RequestTracker, isSecureConnection bool) *dns.Msg {

	responseTTL := entry.GetRemainingTTL()

	if tracker != nil {
		tracker.CacheHit = true
		if isExpired {
			tracker.AddStep("缓存命中(过期): TTL=%ds", responseTTL)
		} else {
			tracker.AddStep("缓存命中: TTL=%ds", responseTTL)
		}
	}

	msg.Answer = globalRecordHandler.ProcessRecords(entry.GetAnswerRRs(), responseTTL, clientRequestedDNSSEC)
	msg.Ns = globalRecordHandler.ProcessRecords(entry.GetAuthorityRRs(), responseTTL, clientRequestedDNSSEC)
	msg.Extra = globalRecordHandler.ProcessRecords(entry.GetAdditionalRRs(), responseTTL, clientRequestedDNSSEC)

	if r.config.Server.Features.DNSSEC && entry.Validated {
		msg.AuthenticatedData = true
		if tracker != nil {
			tracker.AddStep("设置AD标志: 缓存记录已验证")
		}
	}

	responseECS := entry.GetECSOption()
	if responseECS == nil {
		responseECS = ecsOpt
	}

	shouldAddEDNS := clientHasEDNS || responseECS != nil || r.ednsManager.IsPaddingEnabled() ||
		(clientRequestedDNSSEC && r.config.Server.Features.DNSSEC)

	if shouldAddEDNS {
		r.ednsManager.AddToMessage(msg, responseECS, clientRequestedDNSSEC && r.config.Server.Features.DNSSEC, isSecureConnection)
		if tracker != nil && responseECS != nil {
			tracker.AddStep("添加响应ECS: %s/%d", responseECS.Address, responseECS.SourcePrefix)
		}
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

func (r *RecursiveDNSServer) handleCacheMiss(msg *dns.Msg, question dns.Question, originalDomain string,
	ecsOpt *ECSOption, clientRequestedDNSSEC bool, clientHasEDNS bool, serverDNSSECEnabled bool,
	cacheKey string, tracker *RequestTracker, isSecureConnection bool) *dns.Msg {

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
		return r.handleQueryError(msg, err, cacheKey, originalDomain, question,
			clientRequestedDNSSEC, clientHasEDNS, ecsOpt, tracker, isSecureConnection)
	}

	return r.handleQuerySuccess(msg, question, originalDomain, ecsOpt, clientRequestedDNSSEC,
		clientHasEDNS, cacheKey, answer, authority, additional, validated, ecsResponse, tracker, isSecureConnection)
}

func (r *RecursiveDNSServer) handleQueryError(msg *dns.Msg, err error, cacheKey string,
	originalDomain string, question dns.Question, clientRequestedDNSSEC bool, clientHasEDNS bool,
	ecsOpt *ECSOption, tracker *RequestTracker, isSecureConnection bool) *dns.Msg {

	if tracker != nil {
		tracker.AddStep("查询失败: %v", err)
	}

	if r.config.Server.Features.ServeStale {
		if entry, found, _ := r.cache.Get(cacheKey); found {
			if tracker != nil {
				tracker.AddStep("使用过期缓存回退")
			}

			responseTTL := uint32(StaleTTL)
			msg.Answer = globalRecordHandler.ProcessRecords(entry.GetAnswerRRs(), responseTTL, clientRequestedDNSSEC)
			msg.Ns = globalRecordHandler.ProcessRecords(entry.GetAuthorityRRs(), responseTTL, clientRequestedDNSSEC)
			msg.Extra = globalRecordHandler.ProcessRecords(entry.GetAdditionalRRs(), responseTTL, clientRequestedDNSSEC)

			if r.config.Server.Features.DNSSEC && entry.Validated {
				msg.AuthenticatedData = true
			}

			responseECS := entry.GetECSOption()
			if responseECS == nil {
				responseECS = ecsOpt
			}

			shouldAddEDNS := clientHasEDNS || responseECS != nil || r.ednsManager.IsPaddingEnabled() ||
				(clientRequestedDNSSEC && r.config.Server.Features.DNSSEC)

			if shouldAddEDNS {
				r.ednsManager.AddToMessage(msg, responseECS, clientRequestedDNSSEC && r.config.Server.Features.DNSSEC, isSecureConnection)
			}

			r.restoreOriginalDomain(msg, question.Name, originalDomain)
			return msg
		}
	}

	msg.Rcode = dns.RcodeServerFailure
	return msg
}

func (r *RecursiveDNSServer) handleQuerySuccess(msg *dns.Msg, question dns.Question, originalDomain string,
	ecsOpt *ECSOption, clientRequestedDNSSEC bool, clientHasEDNS bool, cacheKey string,
	answer, authority, additional []dns.RR, validated bool, ecsResponse *ECSOption, tracker *RequestTracker, isSecureConnection bool) *dns.Msg {

	if tracker != nil {
		tracker.AddStep("查询成功: 答案=%d, 授权=%d, 附加=%d", len(answer), len(authority), len(additional))
		if validated {
			tracker.AddStep("DNSSEC验证通过")
		}
	}

	if r.config.Server.Features.DNSSEC && validated {
		msg.AuthenticatedData = true
		if tracker != nil {
			tracker.AddStep("设置AD标志: 查询结果已验证")
		}
	}

	responseECS := ecsResponse
	if responseECS == nil && ecsOpt != nil {
		responseECS = &ECSOption{
			Family:       ecsOpt.Family,
			SourcePrefix: ecsOpt.SourcePrefix,
			ScopePrefix:  ecsOpt.SourcePrefix,
			Address:      ecsOpt.Address,
		}
	}

	r.cache.Set(cacheKey, answer, authority, additional, validated, responseECS)

	msg.Answer = globalRecordHandler.FilterDNSSEC(answer, clientRequestedDNSSEC)
	msg.Ns = globalRecordHandler.FilterDNSSEC(authority, clientRequestedDNSSEC)
	msg.Extra = globalRecordHandler.FilterDNSSEC(additional, clientRequestedDNSSEC)

	shouldAddEDNS := clientHasEDNS || responseECS != nil || r.ednsManager.IsPaddingEnabled() ||
		(clientRequestedDNSSEC && r.config.Server.Features.DNSSEC)

	if shouldAddEDNS {
		r.ednsManager.AddToMessage(msg, responseECS, clientRequestedDNSSEC && r.config.Server.Features.DNSSEC, isSecureConnection)
		if tracker != nil && responseECS != nil {
			tracker.AddStep("添加响应ECS: %s/%d", responseECS.Address, responseECS.SourcePrefix)
		}
	}

	r.restoreOriginalDomain(msg, question.Name, originalDomain)
	return msg
}

func (r *RecursiveDNSServer) restoreOriginalDomain(msg *dns.Msg, questionName, originalDomain string) {
	for _, rr := range msg.Answer {
		if strings.EqualFold(rr.Header().Name, questionName) {
			rr.Header().Name = originalDomain
		}
	}
}

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

func (r *RecursiveDNSServer) queryUpstreamServer(ctx context.Context, server *UpstreamServer,
	question dns.Question, ecs *ECSOption, serverDNSSECEnabled bool, tracker *RequestTracker) UpstreamResult {

	start := time.Now()
	result := UpstreamResult{
		Server:   server,
		Duration: 0,
		Protocol: strings.ToUpper(server.Protocol),
	}

	if tracker != nil {
		tracker.AddStep("查询上游服务器: %s (%s)", server.Address, result.Protocol)
	}

	if server.IsRecursive() {
		answer, authority, additional, validated, ecsResponse, err := r.resolveWithCNAME(ctx, question, ecs, tracker)
		result.Duration = time.Since(start)
		result.Error = err
		result.Protocol = "递归"

		if err != nil {
			if tracker != nil {
				tracker.AddStep("递归解析失败: %v", err)
			}
			return result
		}

		response := globalResourceManager.GetDNSMessage()
		defer globalResourceManager.PutDNSMessage(response)

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
			r.ednsManager.AddToMessage(response, ecsResponse, serverDNSSECEnabled, false)
		}
	} else {
		protocol := strings.ToLower(server.Protocol)
		isSecureConnection := (protocol == "tls" || protocol == "quic")

		msg := r.queryEngine.BuildQuery(question, ecs, serverDNSSECEnabled, true, isSecureConnection)
		defer r.queryEngine.ReleaseMessage(msg)

		queryCtx, queryCancel := context.WithTimeout(ctx, StandardOperationTimeout)
		defer queryCancel()

		queryResult := r.queryEngine.ExecuteQuery(queryCtx, msg, server, tracker)
		result.Duration = time.Since(start)
		result.Response = queryResult.Response
		result.Error = queryResult.Error
		result.Protocol = queryResult.Protocol

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
		tracker.AddStep("选择可信结果: %s (%s, 耗时: %v)", server.Address, result.Protocol, result.Duration)
	}

	return result
}

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

	sourceType := selectedResult.Protocol
	if selectedResult.Server.IsRecursive() {
		sourceType = "递归"
	}

	if tracker != nil {
		tracker.Upstream = selectedResult.Server.Address
		tracker.AddStep("最终选择%s结果: %s", sourceType, selectedResult.Server.Address)
	}

	var ecsResponse *ECSOption
	if selectedResult.Response != nil {
		ecsResponse = r.ednsManager.ParseFromDNS(selectedResult.Response)
	}

	return selectedResult.Response.Answer, selectedResult.Response.Ns, selectedResult.Response.Extra,
		selectedResult.Validated, ecsResponse, nil
}

func (r *RecursiveDNSServer) resolveWithCNAME(ctx context.Context, question dns.Question, ecs *ECSOption,
	tracker *RequestTracker) ([]dns.RR, []dns.RR, []dns.RR, bool, *ECSOption, error) {

	var allAnswers []dns.RR
	var finalAuthority, finalAdditional []dns.RR
	var finalECSResponse *ECSOption
	allValidated := true

	currentQuestion := question
	visitedCNAMEs := make(map[string]bool)

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
		ecsResponse = r.ednsManager.ParseFromDNS(response)

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
		ecsResponse = r.ednsManager.ParseFromDNS(response)

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

	msg := r.queryEngine.BuildQuery(question, ecs, r.config.Server.Features.DNSSEC, false, false)
	defer r.queryEngine.ReleaseMessage(msg)

	tempServers := make([]*UpstreamServer, concurrency)
	for i := 0; i < concurrency && i < len(nameservers); i++ {
		protocol := "udp"
		if forceTCP {
			protocol = "tcp"
		}
		tempServers[i] = &UpstreamServer{
			Address:  nameservers[i],
			Protocol: protocol,
			Policy:   "all",
		}
	}

	queryResult, err := r.queryEngine.ExecuteConcurrentQuery(ctx, msg, tempServers, concurrency, tracker)

	if err != nil {
		return nil, err
	}

	return queryResult.Response, nil
}

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

func GetClientIP(w dns.ResponseWriter) net.IP {
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
		fmt.Println(GenerateExampleConfig())
		return
	}

	config, err := LoadConfig(configFile)
	if err != nil {
		customLogger.Fatalf("❌ 配置加载失败: %v", err)
	}

	server, err := NewDNSServer(config)
	if err != nil {
		customLogger.Fatalf("❌ 服务器创建失败: %v", err)
	}

	if err := server.Start(); err != nil {
		customLogger.Fatalf("❌ 服务器启动失败: %v", err)
	}
}
