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

// 系统常量
const (
	DefaultQueryTimeout  = 5 * time.Second
	MaxRetries           = 3
	ClientBufferSize     = 1232 // 响应给客户端的buffer size
	UpstreamBufferSize   = 4096 // 向上游查询的buffer size
	MaxCNAMEChain        = 10
	RecursiveAddress     = "recursive"
	MaxCacheKeySize      = 512
	MaxDomainLength      = 253
	MaxConcurrentQueries = 10000
	MaxBackgroundWorkers = 50
	WorkerQueueSize      = 1000
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

// Panic恢复中间件
func recoverPanic(operation string) {
	if r := recover(); r != nil {
		func() {
			defer func() {
				if r2 := recover(); r2 != nil {
					fmt.Fprintf(os.Stderr, "CRITICAL: Double panic in %s: %v (original: %v)\n", operation, r2, r)
				}
			}()
			logf(LogError, "🚨 Panic恢复 [%s]: %v", operation, r)
			buf := make([]byte, 4096)
			n := runtime.Stack(buf, false)
			logf(LogError, "调用栈: %s", string(buf[:n]))
		}()
	}
}

// ==================== 对象池管理 ====================

var (
	stringBuilderPool = sync.Pool{
		New: func() interface{} {
			return &strings.Builder{}
		},
	}
	rrSlicePool = sync.Pool{
		New: func() interface{} {
			return make([]*CompactDNSRecord, 0, 16)
		},
	}
	stringSetPool = sync.Pool{
		New: func() interface{} {
			return make(map[string]bool, 32)
		},
	}
)

// ==================== 缓存Key构建器 ====================

type CacheKeyBuilder struct {
	builder *strings.Builder
}

func newCacheKeyBuilder() *CacheKeyBuilder {
	builder := stringBuilderPool.Get().(*strings.Builder)
	builder.Reset()
	return &CacheKeyBuilder{builder: builder}
}

func (ckb *CacheKeyBuilder) AddDomain(domain string) *CacheKeyBuilder {
	ckb.builder.WriteString(strings.ToLower(domain))
	return ckb
}

func (ckb *CacheKeyBuilder) AddType(qtype uint16) *CacheKeyBuilder {
	ckb.builder.WriteByte(':')
	ckb.builder.WriteString(fmt.Sprintf("%d", qtype))
	return ckb
}

func (ckb *CacheKeyBuilder) AddClass(qclass uint16) *CacheKeyBuilder {
	ckb.builder.WriteByte(':')
	ckb.builder.WriteString(fmt.Sprintf("%d", qclass))
	return ckb
}

func (ckb *CacheKeyBuilder) AddECS(ecs *ECSOption) *CacheKeyBuilder {
	if ecs != nil {
		ckb.builder.WriteByte(':')
		ckb.builder.WriteString(ecs.Address.String())
		ckb.builder.WriteByte('/')
		ckb.builder.WriteString(fmt.Sprintf("%d", ecs.SourcePrefix))
	}
	return ckb
}

func (ckb *CacheKeyBuilder) AddDNSSEC(enabled bool) *CacheKeyBuilder {
	if enabled {
		ckb.builder.WriteString(":dnssec")
	}
	return ckb
}

func (ckb *CacheKeyBuilder) String() string {
	result := ckb.builder.String()
	if len(result) > MaxCacheKeySize {
		result = fmt.Sprintf("hash:%x", result)[:MaxCacheKeySize]
	}
	return result
}

func (ckb *CacheKeyBuilder) Release() {
	stringBuilderPool.Put(ckb.builder)
}

// ==================== 后台任务管理器 ====================

type BackgroundTaskManager struct {
	taskQueue chan func()
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
}

func NewBackgroundTaskManager(workers int) *BackgroundTaskManager {
	if workers <= 0 {
		workers = runtime.NumCPU()
	}
	if workers > MaxBackgroundWorkers {
		workers = MaxBackgroundWorkers
	}

	ctx, cancel := context.WithCancel(context.Background())
	btm := &BackgroundTaskManager{
		taskQueue: make(chan func(), WorkerQueueSize),
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
	case <-time.After(10 * time.Second):
		logf(LogWarn, "⏰ 后台任务管理器关闭超时")
	}
}

// ==================== IP检测器 ====================

type IPDetector struct {
	dnsClient  *dns.Client
	httpClient *http.Client
}

func NewIPDetector() *IPDetector {
	return &IPDetector{
		dnsClient: &dns.Client{
			Timeout: 3 * time.Second,
			Net:     "udp",
			UDPSize: UpstreamBufferSize,
		},
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				DialContext: (&net.Dialer{
					Timeout: 3 * time.Second,
				}).DialContext,
				TLSHandshakeTimeout: 2 * time.Second,
			},
		},
	}
}

// 检测公网IP地址
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
		server = "[2001:4860:4802:32::a]:53"
	} else {
		server = "216.239.32.10:53"
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
			dialer := &net.Dialer{Timeout: 3 * time.Second}
			if forceIPv6 {
				return dialer.DialContext(ctx, "tcp6", addr)
			}
			return dialer.DialContext(ctx, "tcp4", addr)
		},
		TLSHandshakeTimeout: 2 * time.Second,
	}

	client := &http.Client{
		Timeout:   5 * time.Second,
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

// ==================== IP过滤器 ====================

type IPFilter struct {
	cnCIDRs   []*net.IPNet
	cnCIDRsV6 []*net.IPNet
	mu        sync.RWMutex
}

func NewIPFilter() *IPFilter {
	return &IPFilter{
		cnCIDRs:   make([]*net.IPNet, 0, 1024),
		cnCIDRsV6: make([]*net.IPNet, 0, 256),
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

	f.cnCIDRs = make([]*net.IPNet, 0, 1024)
	f.cnCIDRsV6 = make([]*net.IPNet, 0, 256)

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var totalV4, totalV6 int

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || len(line) > 128 {
			continue
		}

		_, ipNet, err := net.ParseCIDR(line)
		if err != nil {
			continue
		}

		if ipNet.IP.To4() != nil {
			f.cnCIDRs = append(f.cnCIDRs, ipNet)
			totalV4++
		} else {
			f.cnCIDRsV6 = append(f.cnCIDRsV6, ipNet)
			totalV6++
		}
	}

	f.optimizeCIDRs()
	logf(LogInfo, "🌍 IP过滤器加载完成: IPv4=%d条, IPv6=%d条", totalV4, totalV6)
	return scanner.Err()
}

func (f *IPFilter) optimizeCIDRs() {
	// 按掩码长度降序排序，更具体的网络优先匹配
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
}

func (f *IPFilter) isChinaIP(ip net.IP) bool {
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

func (f *IPFilter) AnalyzeIPs(rrs []dns.RR) (hasChinaIP, hasNonChinaIP bool) {
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

		if f.isChinaIP(ip) {
			hasChinaIP = true
		} else {
			hasNonChinaIP = true
		}

		if hasChinaIP && hasNonChinaIP {
			return
		}
	}
	return
}

func (f *IPFilter) HasData() bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return len(f.cnCIDRs) > 0 || len(f.cnCIDRsV6) > 0
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
	Enabled     bool            `json:"enabled"`
	Priority    int             `json:"priority"`
	regex       *regexp.Regexp  `json:"-"`
}

type DNSRewriter struct {
	rules []RewriteRule
	mu    sync.RWMutex
}

func NewDNSRewriter() *DNSRewriter {
	return &DNSRewriter{
		rules: make([]RewriteRule, 0, 32),
	}
}

func (r *DNSRewriter) LoadRules(rules []RewriteRule) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	validRules := make([]RewriteRule, 0, len(rules))
	for i, rule := range rules {
		if !rule.Enabled || len(rule.Pattern) > MaxDomainLength || len(rule.Replacement) > MaxDomainLength {
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
			if len(rule.Pattern) > 100 {
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

		if rule.Priority == 0 {
			rule.Priority = 100
		}
		validRules = append(validRules, rule)
	}

	sort.Slice(validRules, func(i, j int) bool {
		return validRules[i].Priority < validRules[j].Priority
	})

	r.rules = validRules
	logf(LogInfo, "🔄 DNS重写器加载完成: %d条规则", len(validRules))
	return nil
}

func (r *DNSRewriter) Rewrite(domain string) (string, bool) {
	if len(r.rules) == 0 || len(domain) > MaxDomainLength {
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
		for _, rr := range response.Answer {
			answerName := strings.ToLower(strings.TrimSuffix(rr.Header().Name, "."))
			if answerName == queryDomain {
				// 跳过委托记录
				if rr.Header().Rrtype == dns.TypeNS || rr.Header().Rrtype == dns.TypeDS {
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

type UpstreamServer struct {
	Address     string `json:"address"`
	Name        string `json:"name"`
	TrustPolicy string `json:"trust_policy"`
	Weight      int    `json:"weight"`
	Timeout     int    `json:"timeout"`
	Enabled     bool   `json:"enabled"`
	Priority    int    `json:"priority"`
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

type UpstreamManager struct {
	servers       []*UpstreamServer
	strategy      string
	roundRobinIdx int64
	mu            sync.RWMutex
}

func NewUpstreamManager(servers []UpstreamServer, strategy string) *UpstreamManager {
	activeServers := make([]*UpstreamServer, 0, len(servers))

	for i := range servers {
		if servers[i].Enabled {
			if servers[i].Weight <= 0 {
				servers[i].Weight = 1
			}
			if servers[i].Timeout <= 0 {
				servers[i].Timeout = 5
			}
			if servers[i].Priority == 0 {
				servers[i].Priority = 100
			}
			activeServers = append(activeServers, &servers[i])
		}
	}

	sort.Slice(activeServers, func(i, j int) bool {
		return activeServers[i].Priority < activeServers[j].Priority
	})

	return &UpstreamManager{
		servers:  activeServers,
		strategy: strategy,
	}
}

func (um *UpstreamManager) GetServers() []*UpstreamServer {
	um.mu.RLock()
	defer um.mu.RUnlock()
	return um.servers
}

func (um *UpstreamManager) SelectServer() *UpstreamServer {
	um.mu.RLock()
	defer um.mu.RUnlock()

	if len(um.servers) == 0 {
		return nil
	}

	switch um.strategy {
	case "round_robin":
		idx := atomic.AddInt64(&um.roundRobinIdx, 1) % int64(len(um.servers))
		return um.servers[idx]
	case "weighted":
		return um.selectWeighted()
	default:
		return um.servers[0]
	}
}

func (um *UpstreamManager) selectWeighted() *UpstreamServer {
	totalWeight := 0
	for _, server := range um.servers {
		totalWeight += server.Weight
	}

	if totalWeight == 0 {
		return um.servers[0]
	}

	target := int(time.Now().UnixNano()) % totalWeight
	current := 0

	for _, server := range um.servers {
		current += server.Weight
		if current > target {
			return server
		}
	}
	return um.servers[0]
}

// ==================== ECS选项 ====================

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

	detector := NewIPDetector()

	switch strings.ToLower(subnet) {
	case "auto":
		logf(LogInfo, "🌍 自动检测ECS地址 (优先IPv4)...")
		if ip := detector.detectPublicIP(false); ip != nil {
			logf(LogInfo, "🌍 检测到IPv4地址: %s", ip)
			return &ECSOption{
				Family:       1,
				SourcePrefix: 24,
				ScopePrefix:  24,
				Address:      ip,
			}, nil
		}
		if ip := detector.detectPublicIP(true); ip != nil {
			logf(LogInfo, "🌍 检测到IPv6地址: %s", ip)
			return &ECSOption{
				Family:       2,
				SourcePrefix: 64,
				ScopePrefix:  64,
				Address:      ip,
			}, nil
		}
		logf(LogWarn, "⚠️ 自动检测失败，ECS功能将禁用")
		return nil, nil

	case "auto_v4":
		if ip := detector.detectPublicIP(false); ip != nil {
			return &ECSOption{
				Family:       1,
				SourcePrefix: 24,
				ScopePrefix:  24,
				Address:      ip,
			}, nil
		}
		return nil, nil

	case "auto_v6":
		if ip := detector.detectPublicIP(true); ip != nil {
			return &ECSOption{
				Family:       2,
				SourcePrefix: 64,
				ScopePrefix:  64,
				Address:      ip,
			}, nil
		}
		return nil, nil
	}

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

// ==================== 服务器配置 ====================

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
		MaxConcurrency    int  `json:"max_concurrency"`
		ConnPoolSize      int  `json:"conn_pool_size"`
		QueryTimeout      int  `json:"query_timeout"`
		MaxRecursion      int  `json:"max_recursion"`
		WorkerCount       int  `json:"worker_count"`
		EnableDynamicPool bool `json:"enable_dynamic_pool"`
		MaxPoolSize       int  `json:"max_pool_size"`
		MinPoolSize       int  `json:"min_pool_size"`
		BackgroundWorkers int  `json:"background_workers"`
	} `json:"performance"`

	Logging struct {
		Level string `json:"level"`
	} `json:"logging"`

	Features struct {
		ServeStale       bool `json:"serve_stale"`
		PrefetchEnabled  bool `json:"prefetch_enabled"`
		DNSSEC           bool `json:"dnssec"`
		PreventDNSHijack bool `json:"prevent_dns_hijack"`
	} `json:"features"`

	Redis struct {
		Address          string `json:"address"`
		Password         string `json:"password"`
		Database         int    `json:"database"`
		PoolSize         int    `json:"pool_size"`
		KeyPrefix        string `json:"key_prefix"`
		MaxRetries       int    `json:"max_retries"`
		MinIdleConns     int    `json:"min_idle_conns"`
		PoolTimeout      int    `json:"pool_timeout"`
		UpdateThrottleMs int    `json:"update_throttle_ms"`
	} `json:"redis"`

	Upstream struct {
		Servers          []UpstreamServer `json:"servers"`
		ChinaCIDRFile    string           `json:"china_cidr_file"`
		FilteringEnabled bool             `json:"filtering_enabled"`
		Strategy         string           `json:"strategy"`
		MaxConcurrent    int              `json:"max_concurrent"`
		QueryTimeout     int              `json:"query_timeout"`
	} `json:"upstream"`

	Rewrite struct {
		Enabled bool          `json:"enabled"`
		Rules   []RewriteRule `json:"rules"`
	} `json:"rewrite"`
}

// 配置管理和验证
func loadConfig(filename string) (*ServerConfig, error) {
	config := getDefaultConfig()

	if filename == "" {
		logf(LogInfo, "📄 使用默认配置（纯递归模式）")
		return config, nil
	}

	if !isValidFilePath(filename) {
		return nil, fmt.Errorf("无效的配置文件路径: %s", filename)
	}

	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("读取配置文件失败: %w", err)
	}

	if len(data) > 1024*1024 {
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
	if config.Network.DefaultECS != "" {
		ecs := strings.ToLower(config.Network.DefaultECS)
		validPresets := []string{"auto", "auto_v4", "auto_v6"}
		isPreset := false
		for _, preset := range validPresets {
			if ecs == preset {
				isPreset = true
				break
			}
		}
		if !isPreset {
			if _, _, err := net.ParseCIDR(config.Network.DefaultECS); err != nil {
				return fmt.Errorf("ECS子网格式错误: %w", err)
			}
		}
	}

	// 验证TTL配置
	if config.TTL.MinTTL > 0 && config.TTL.MaxTTL > 0 && config.TTL.MinTTL > config.TTL.MaxTTL {
		return errors.New("最小TTL不能大于最大TTL")
	}

	// 验证上游服务器配置
	for i, server := range config.Upstream.Servers {
		if !server.Enabled {
			continue
		}
		if !server.IsRecursive() {
			if _, _, err := net.SplitHostPort(server.Address); err != nil {
				return fmt.Errorf("上游服务器 %d 地址格式错误: %w", i, err)
			}
		}
		validPolicies := map[string]bool{"all": true, "cn_only": true, "non_cn_only": true}
		if !validPolicies[server.TrustPolicy] {
			return fmt.Errorf("上游服务器 %d 信任策略无效: %s", i, server.TrustPolicy)
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
		if config.Features.PrefetchEnabled {
			logf(LogWarn, "⚠️ 无缓存模式下禁用预取功能")
			config.Features.PrefetchEnabled = false
		}
	}

	// 调整性能参数
	if config.Performance.BackgroundWorkers <= 0 {
		config.Performance.BackgroundWorkers = runtime.NumCPU()
	}
	if config.Performance.BackgroundWorkers > MaxBackgroundWorkers {
		config.Performance.BackgroundWorkers = MaxBackgroundWorkers
	}

	if config.Redis.UpdateThrottleMs <= 0 {
		config.Redis.UpdateThrottleMs = 100
	}

	return nil
}

func getDefaultConfig() *ServerConfig {
	config := &ServerConfig{}

	config.Network.Port = "53"
	config.Network.EnableIPv6 = true
	config.Network.DefaultECS = "auto"

	config.TTL.DefaultTTL = 3600
	config.TTL.MinTTL = 0
	config.TTL.MaxTTL = 0
	config.TTL.StaleTTL = 30
	config.TTL.StaleMaxAge = 604800

	config.Performance.MaxConcurrency = 1000
	config.Performance.ConnPoolSize = 100
	config.Performance.QueryTimeout = 5
	config.Performance.MaxRecursion = 10
	config.Performance.WorkerCount = runtime.NumCPU()
	config.Performance.EnableDynamicPool = true
	config.Performance.MaxPoolSize = 500
	config.Performance.MinPoolSize = 50
	config.Performance.BackgroundWorkers = runtime.NumCPU()

	config.Logging.Level = "info"

	config.Features.ServeStale = false
	config.Features.PrefetchEnabled = false
	config.Features.DNSSEC = true
	config.Features.PreventDNSHijack = false

	config.Redis.Address = ""
	config.Redis.Password = ""
	config.Redis.Database = 0
	config.Redis.PoolSize = 50
	config.Redis.KeyPrefix = "zjdns:"
	config.Redis.MaxRetries = 3
	config.Redis.MinIdleConns = 10
	config.Redis.PoolTimeout = 5
	config.Redis.UpdateThrottleMs = 100

	config.Upstream.Servers = []UpstreamServer{}
	config.Upstream.ChinaCIDRFile = ""
	config.Upstream.FilteringEnabled = false
	config.Upstream.Strategy = "first_valid"
	config.Upstream.MaxConcurrent = 5
	config.Upstream.QueryTimeout = 10

	config.Rewrite.Enabled = false
	config.Rewrite.Rules = []RewriteRule{}

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
	config.Network.DefaultECS = "auto"
	config.Redis.Address = "127.0.0.1:6379"
	config.Features.ServeStale = true
	config.Features.PrefetchEnabled = true
	config.Features.PreventDNSHijack = true

	config.Upstream.Servers = []UpstreamServer{
		{
			Address:     "8.8.8.8:53",
			Name:        "Google DNS (海外可信)",
			TrustPolicy: "all",
			Weight:      10,
			Timeout:     5,
			Priority:    1,
			Enabled:     true,
		},
		{
			Address:     "114.114.114.114:53",
			Name:        "114 DNS (仅信任中国IP)",
			TrustPolicy: "cn_only",
			Weight:      8,
			Timeout:     3,
			Priority:    2,
			Enabled:     true,
		},
		{
			Address:     "recursive",
			Name:        "递归解析 (回退选项)",
			TrustPolicy: "all",
			Weight:      5,
			Timeout:     10,
			Priority:    3,
			Enabled:     true,
		},
	}
	config.Upstream.ChinaCIDRFile = "china_cidr.txt"
	config.Upstream.FilteringEnabled = true
	config.Upstream.Strategy = "prefer_trusted"

	config.Rewrite.Enabled = true
	config.Rewrite.Rules = []RewriteRule{
		{
			TypeString:  "exact",
			Pattern:     "blocked.example.com",
			Replacement: "127.0.0.1",
			Priority:    1,
			Enabled:     true,
		},
		{
			TypeString:  "suffix",
			Pattern:     "ads.example.com",
			Replacement: "127.0.0.1",
			Priority:    2,
			Enabled:     true,
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

	seen := stringSetPool.Get().(map[string]bool)
	defer func() {
		for k := range seen {
			delete(seen, k)
		}
		stringSetPool.Put(seen)
	}()

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
		(now-c.Timestamp) > int64(c.TTL+300) &&
		(now-c.RefreshTime) > 600
}

func (c *CacheEntry) ShouldUpdateAccessInfo(throttleMs int) bool {
	now := time.Now().UnixMilli()
	return now-c.LastUpdateTime > int64(throttleMs)
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
	logf(LogInfo, "🚫 启用无缓存模式")
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
		PoolSize:     config.Redis.PoolSize,
		MinIdleConns: config.Redis.MinIdleConns,
		MaxRetries:   config.Redis.MaxRetries,
		PoolTimeout:  time.Duration(config.Redis.PoolTimeout) * time.Second,
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
		ctx:          cacheCtx,
		cancel:       cacheCancel,
		bgManager:    NewBackgroundTaskManager(config.Performance.BackgroundWorkers),
		server:       server,
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
	if entry.ShouldUpdateAccessInfo(rc.config.Redis.UpdateThrottleMs) {
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
	case <-time.After(10 * time.Second):
		logf(LogWarn, "Redis缓存关闭超时")
	}

	rc.client.Close()
	logf(LogInfo, "✅ Redis缓存系统已安全关闭")
}

// ==================== 连接池 ====================

type ConnectionPool struct {
	clients     chan *dns.Client
	timeout     time.Duration
	maxSize     int
	minSize     int
	currentSize int64
}

func NewConnectionPool(minSize, maxSize int, timeout time.Duration) *ConnectionPool {
	pool := &ConnectionPool{
		clients:     make(chan *dns.Client, maxSize),
		timeout:     timeout,
		maxSize:     maxSize,
		minSize:     minSize,
		currentSize: 0,
	}

	for i := 0; i < minSize; i++ {
		client := pool.createClient()
		pool.clients <- client
		atomic.AddInt64(&pool.currentSize, 1)
	}

	return pool
}

func (cp *ConnectionPool) createClient() *dns.Client {
	return &dns.Client{
		Timeout: cp.timeout,
		Net:     "udp",
		UDPSize: UpstreamBufferSize,
	}
}

func (cp *ConnectionPool) Get() *dns.Client {
	select {
	case client := <-cp.clients:
		return client
	default:
		currentSize := atomic.LoadInt64(&cp.currentSize)
		if int(currentSize) < cp.maxSize {
			if atomic.CompareAndSwapInt64(&cp.currentSize, currentSize, currentSize+1) {
				return cp.createClient()
			}
		}
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
		currentSize := atomic.LoadInt64(&cp.currentSize)
		if int(currentSize) > cp.minSize {
			atomic.AddInt64(&cp.currentSize, -1)
		}
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

type QueryResult struct {
	Response *dns.Msg
	Server   string
	Error    error
	Duration time.Duration
}

type UpstreamResult struct {
	Response      *dns.Msg
	Server        *UpstreamServer
	Error         error
	Duration      time.Duration
	HasChinaIP    bool
	HasNonChinaIP bool
	Trusted       bool
	Filtered      bool
	Validated     bool
}

// ==================== 主服务器 ====================

type RecursiveDNSServer struct {
	config            *ServerConfig
	cache             DNSCache
	rootServersV4     []string
	rootServersV6     []string
	connPool          *ConnectionPool
	dnssecVal         *DNSSECValidator
	defaultECS        *ECSOption
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
}

// QueryForRefresh 为缓存刷新提供查询能力
func (r *RecursiveDNSServer) QueryForRefresh(question dns.Question, ecs *ECSOption, serverDNSSECEnabled bool) ([]dns.RR, []dns.RR, []dns.RR, bool, *ECSOption, error) {
	defer recoverPanic("缓存刷新查询")

	refreshCtx, cancel := context.WithTimeout(r.ctx, 25*time.Second)
	defer cancel()

	servers := r.upstreamManager.GetServers()
	if len(servers) > 0 {
		return r.queryUpstreamServers(question, ecs, serverDNSSECEnabled)
	} else {
		return r.resolveWithCNAME(refreshCtx, question, ecs)
	}
}

func NewRecursiveDNSServer(config *ServerConfig) (*RecursiveDNSServer, error) {
	// Root servers
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

	defaultECS, err := parseDefaultECS(config.Network.DefaultECS)
	if err != nil {
		return nil, fmt.Errorf("ECS配置错误: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	ipFilter := NewIPFilter()
	if config.Upstream.FilteringEnabled {
		if err := ipFilter.LoadCIDRs(config.Upstream.ChinaCIDRFile); err != nil {
			return nil, fmt.Errorf("加载中国CIDR文件失败: %w", err)
		}
	}

	dnsRewriter := NewDNSRewriter()
	if config.Rewrite.Enabled {
		if err := dnsRewriter.LoadRules(config.Rewrite.Rules); err != nil {
			return nil, fmt.Errorf("加载DNS重写规则失败: %w", err)
		}
	}

	upstreamManager := NewUpstreamManager(config.Upstream.Servers, config.Upstream.Strategy)

	var connPool *ConnectionPool
	if config.Performance.EnableDynamicPool {
		connPool = NewConnectionPool(
			config.Performance.MinPoolSize,
			config.Performance.MaxPoolSize,
			DefaultQueryTimeout,
		)
	} else {
		connPool = NewConnectionPool(
			config.Performance.ConnPoolSize,
			config.Performance.ConnPoolSize,
			DefaultQueryTimeout,
		)
	}

	hijackPrevention := NewDNSHijackPrevention(config.Features.PreventDNSHijack)

	server := &RecursiveDNSServer{
		config:            config,
		rootServersV4:     rootServersV4,
		rootServersV6:     rootServersV6,
		connPool:          connPool,
		dnssecVal:         NewDNSSECValidator(),
		defaultECS:        defaultECS,
		concurrencyLimit:  make(chan struct{}, config.Performance.MaxConcurrency),
		ctx:               ctx,
		cancel:            cancel,
		shutdown:          make(chan struct{}),
		ipFilter:          ipFilter,
		dnsRewriter:       dnsRewriter,
		upstreamManager:   upstreamManager,
		backgroundManager: NewBackgroundTaskManager(config.Performance.BackgroundWorkers),
		hijackPrevention:  hijackPrevention,
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

			done := make(chan struct{})
			go func() {
				r.wg.Wait()
				close(done)
			}()

			select {
			case <-done:
				logf(LogInfo, "✅ 所有goroutine已安全关闭")
			case <-time.After(10 * time.Second):
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

	r.displayInfo()

	wg.Add(2)

	// UDP服务器
	go func() {
		defer wg.Done()
		defer recoverPanic("UDP服务器")

		server := &dns.Server{
			Addr:    ":" + r.config.Network.Port,
			Net:     "udp",
			Handler: dns.HandlerFunc(r.handleDNSRequest),
			UDPSize: ClientBufferSize,
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

func (r *RecursiveDNSServer) displayInfo() {
	servers := r.upstreamManager.GetServers()
	if len(servers) > 0 {
		for _, server := range servers {
			if server.IsRecursive() {
				logf(LogInfo, "🔗 上游配置: %s (递归解析) - %s", server.Name, server.TrustPolicy)
			} else {
				logf(LogInfo, "🔗 上游服务器: %s (%s) - %s", server.Name, server.Address, server.TrustPolicy)
			}
		}
		logf(LogInfo, "🔗 混合模式: %d个上游, 策略=%s", len(servers), r.config.Upstream.Strategy)
	} else {
		if r.config.Redis.Address == "" {
			logf(LogInfo, "🚫 纯递归模式 (无缓存)")
		} else {
			logf(LogInfo, "💾 递归模式 + Redis缓存: %s", r.config.Redis.Address)
		}
	}

	if r.ipFilter.HasData() {
		logf(LogInfo, "🌍 IP过滤器: 已加载")
	}
	if r.config.Rewrite.Enabled {
		logf(LogInfo, "🔄 DNS重写器: 已启用")
	}
	if r.config.Features.PreventDNSHijack {
		logf(LogInfo, "🛡️ DNS劫持预防: 启用")
	}
	if r.defaultECS != nil {
		logf(LogInfo, "🌍 默认ECS: %s/%d", r.defaultECS.Address, r.defaultECS.SourcePrefix)
	}

	logf(LogInfo, "⚡ 最大并发: %d", r.config.Performance.MaxConcurrency)
	logf(LogInfo, "📦 UDP缓冲区: 客户端=%d, 上游=%d", ClientBufferSize, UpstreamBufferSize)
}

func (r *RecursiveDNSServer) handleDNSRequest(w dns.ResponseWriter, req *dns.Msg) {
	defer func() {
		if rec := recover(); rec != nil {
			logf(LogError, "🚨 DNS请求处理Panic: %v", rec)
			response := new(dns.Msg)
			response.SetReply(req)
			response.Rcode = dns.RcodeServerFailure
			w.WriteMsg(response)
		}
	}()

	select {
	case <-r.ctx.Done():
		return
	default:
	}

	response := r.processDNSQuery(req, getClientIP(w))
	w.WriteMsg(response)
}

func (r *RecursiveDNSServer) processDNSQuery(req *dns.Msg, clientIP net.IP) *dns.Msg {
	defer recoverPanic("DNS查询处理")

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

	if len(question.Name) > MaxDomainLength {
		logf(LogWarn, "拒绝过长域名查询: %d字符", len(question.Name))
		msg.Rcode = dns.RcodeFormatError
		return msg
	}

	// DNS重写处理
	if r.config.Rewrite.Enabled {
		if rewritten, changed := r.dnsRewriter.Rewrite(question.Name); changed {
			question.Name = rewritten
			logf(LogDebug, "🔄 域名重写: %s -> %s", originalDomain, rewritten)

			if ip := net.ParseIP(strings.TrimSuffix(rewritten, ".")); ip != nil {
				return r.createDirectIPResponse(msg, originalDomain, question.Qtype, ip)
			}
		}
	}

	// 解析客户端EDNS0选项
	clientRequestedDNSSEC := false
	var ecsOpt *ECSOption

	if opt := req.IsEdns0(); opt != nil {
		clientRequestedDNSSEC = opt.Do()
		for _, option := range opt.Option {
			if subnet, ok := option.(*dns.EDNS0_SUBNET); ok {
				ecsOpt = ParseECS(subnet)
				break
			}
		}
	}

	if ecsOpt == nil && r.defaultECS != nil {
		ecsOpt = r.defaultECS
	}

	serverDNSSECEnabled := r.config.Features.DNSSEC
	cacheKey := r.buildCacheKey(question, ecsOpt, serverDNSSECEnabled)

	// 缓存查找
	if entry, found, isExpired := r.cache.Get(cacheKey); found {
		return r.handleCacheHit(msg, entry, isExpired, question, originalDomain,
			clientRequestedDNSSEC, cacheKey, ecsOpt)
	}

	// 缓存未命中，进行查询
	return r.handleCacheMiss(msg, question, originalDomain, ecsOpt,
		clientRequestedDNSSEC, serverDNSSECEnabled, cacheKey)
}

func (r *RecursiveDNSServer) createDirectIPResponse(msg *dns.Msg, originalDomain string, qtype uint16, ip net.IP) *dns.Msg {
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

func (r *RecursiveDNSServer) handleCacheHit(msg *dns.Msg, entry *CacheEntry, isExpired bool,
	question dns.Question, originalDomain string, clientRequestedDNSSEC bool, cacheKey string, ecsOpt *ECSOption) *dns.Msg {

	responseTTL := entry.GetRemainingTTL(r.config.TTL.StaleTTL)

	if isExpired {
		logf(LogDebug, "💾 缓存命中(过期): %s %s (TTL: %ds)", question.Name, dns.TypeToString[question.Qtype], responseTTL)
	} else {
		logf(LogDebug, "💾 缓存命中: %s %s (TTL: %ds)", question.Name, dns.TypeToString[question.Qtype], responseTTL)
	}

	msg.Answer = adjustTTL(filterDNSSECRecords(entry.GetAnswerRRs(), clientRequestedDNSSEC), responseTTL)
	msg.Ns = adjustTTL(filterDNSSECRecords(entry.GetAuthorityRRs(), clientRequestedDNSSEC), responseTTL)
	msg.Extra = adjustTTL(filterDNSSECRecords(entry.GetAdditionalRRs(), clientRequestedDNSSEC), responseTTL)

	cachedECS := entry.GetECSOption()
	if clientRequestedDNSSEC || cachedECS != nil {
		r.addEDNS0(msg, entry.Validated, cachedECS, clientRequestedDNSSEC)
	}

	// 预取逻辑
	if isExpired && r.config.Features.ServeStale && r.config.Features.PrefetchEnabled && entry.ShouldRefresh() {
		r.cache.RequestRefresh(RefreshRequest{
			Question:            question,
			ECS:                 ecsOpt,
			CacheKey:            cacheKey,
			ServerDNSSECEnabled: r.config.Features.DNSSEC,
		})
	}

	r.restoreOriginalDomain(msg, question.Name, originalDomain)
	return msg
}

func (r *RecursiveDNSServer) handleCacheMiss(msg *dns.Msg, question dns.Question, originalDomain string,
	ecsOpt *ECSOption, clientRequestedDNSSEC bool, serverDNSSECEnabled bool, cacheKey string) *dns.Msg {

	var answer, authority, additional []dns.RR
	var validated bool
	var ecsResponse *ECSOption
	var err error

	servers := r.upstreamManager.GetServers()
	if len(servers) > 0 {
		answer, authority, additional, validated, ecsResponse, err = r.queryUpstreamServers(question, ecsOpt, serverDNSSECEnabled)
	} else {
		logf(LogDebug, "🔍 纯递归解析: %s %s", dns.TypeToString[question.Qtype], question.Name)
		ctx, cancel := context.WithTimeout(r.ctx, 30*time.Second)
		defer cancel()
		answer, authority, additional, validated, ecsResponse, err = r.resolveWithCNAME(ctx, question, ecsOpt)
	}

	if err != nil {
		return r.handleQueryError(msg, err, cacheKey, originalDomain, question, clientRequestedDNSSEC)
	}

	return r.handleQuerySuccess(msg, question, originalDomain, ecsOpt, clientRequestedDNSSEC, cacheKey,
		answer, authority, additional, validated, ecsResponse)
}

func (r *RecursiveDNSServer) handleQueryError(msg *dns.Msg, err error, cacheKey string,
	originalDomain string, question dns.Question, clientRequestedDNSSEC bool) *dns.Msg {

	logf(LogDebug, "查询失败: %v", err)

	if r.config.Features.ServeStale {
		if entry, found, _ := r.cache.Get(cacheKey); found {
			logf(LogDebug, "⏰ 使用过期缓存回退: %s %s", question.Name, dns.TypeToString[question.Qtype])

			responseTTL := uint32(r.config.TTL.StaleTTL)
			msg.Answer = adjustTTL(filterDNSSECRecords(entry.GetAnswerRRs(), clientRequestedDNSSEC), responseTTL)
			msg.Ns = adjustTTL(filterDNSSECRecords(entry.GetAuthorityRRs(), clientRequestedDNSSEC), responseTTL)
			msg.Extra = adjustTTL(filterDNSSECRecords(entry.GetAdditionalRRs(), clientRequestedDNSSEC), responseTTL)

			cachedECS := entry.GetECSOption()
			if clientRequestedDNSSEC || cachedECS != nil {
				r.addEDNS0(msg, entry.Validated, cachedECS, clientRequestedDNSSEC)
			}

			r.restoreOriginalDomain(msg, question.Name, originalDomain)
			return msg
		}
	}

	msg.Rcode = dns.RcodeServerFailure
	return msg
}

func (r *RecursiveDNSServer) handleQuerySuccess(msg *dns.Msg, question dns.Question, originalDomain string,
	ecsOpt *ECSOption, clientRequestedDNSSEC bool, cacheKey string, answer, authority, additional []dns.RR,
	validated bool, ecsResponse *ECSOption) *dns.Msg {

	if r.config.Features.DNSSEC && validated {
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
		r.addEDNS0(msg, validated, finalECS, clientRequestedDNSSEC)
	}

	r.restoreOriginalDomain(msg, question.Name, originalDomain)
	return msg
}

func (r *RecursiveDNSServer) addEDNS0(msg *dns.Msg, validated bool, ecs *ECSOption, clientRequestedDNSSEC bool) {
	var cleanExtra []dns.RR
	for _, rr := range msg.Extra {
		if rr.Header().Rrtype != dns.TypeOPT {
			cleanExtra = append(cleanExtra, rr)
		}
	}
	msg.Extra = cleanExtra

	opt := &dns.OPT{
		Hdr: dns.RR_Header{
			Name:   ".",
			Rrtype: dns.TypeOPT,
			Class:  ClientBufferSize,
			Ttl:    0,
		},
	}

	if r.config.Features.DNSSEC {
		if validated {
			msg.AuthenticatedData = true
		}
		if clientRequestedDNSSEC {
			opt.SetDo(true)
		}
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

func (r *RecursiveDNSServer) restoreOriginalDomain(msg *dns.Msg, questionName, originalDomain string) {
	for _, rr := range msg.Answer {
		if strings.EqualFold(rr.Header().Name, questionName) {
			rr.Header().Name = originalDomain
		}
	}
}

// ==================== DNS查询实现 ====================

func (r *RecursiveDNSServer) queryWithFallback(ctx context.Context, msg *dns.Msg, server string) (*dns.Msg, error) {
	defer recoverPanic(fmt.Sprintf("DNS查询fallback %s", server))

	// 首先尝试UDP查询
	udpClient := r.connPool.Get()
	defer r.connPool.Put(udpClient)

	response, _, err := udpClient.ExchangeContext(ctx, msg, server)

	needTCPFallback := false
	if err != nil {
		needTCPFallback = true
	} else if response != nil && response.Truncated {
		needTCPFallback = true
	}

	// 执行TCP fallback
	if needTCPFallback {
		tcpClient := r.connPool.GetTCP()
		logf(LogDebug, "🔌 执行TCP查询: %s", server)
		tcpResponse, _, tcpErr := tcpClient.ExchangeContext(ctx, msg, server)

		if tcpErr != nil {
			if response != nil && response.Rcode != dns.RcodeServerFailure {
				return response, nil
			}
			return nil, tcpErr
		}
		return tcpResponse, nil
	}

	return response, nil
}

func (r *RecursiveDNSServer) queryUpstreamServers(question dns.Question, ecs *ECSOption, serverDNSSECEnabled bool) ([]dns.RR, []dns.RR, []dns.RR, bool, *ECSOption, error) {
	defer recoverPanic("上游服务器查询")

	servers := r.upstreamManager.GetServers()
	if len(servers) == 0 {
		return nil, nil, nil, false, nil, errors.New("没有可用的上游服务器")
	}

	maxConcurrent := r.config.Upstream.MaxConcurrent
	if maxConcurrent > len(servers) {
		maxConcurrent = len(servers)
	}

	resultChan := make(chan UpstreamResult, maxConcurrent)
	ctx, cancel := context.WithTimeout(r.ctx, time.Duration(r.config.Upstream.QueryTimeout)*time.Second)
	defer cancel()

	for i := 0; i < maxConcurrent && i < len(servers); i++ {
		r.wg.Add(1)
		go func(srv *UpstreamServer) {
			defer r.wg.Done()
			defer recoverPanic(fmt.Sprintf("上游查询worker %s", srv.Name))

			result := r.queryUpstreamServer(ctx, srv, question, ecs, serverDNSSECEnabled)
			select {
			case resultChan <- result:
			case <-ctx.Done():
			}
		}(servers[i])
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

	return r.selectUpstreamResult(results, question)
}

func (r *RecursiveDNSServer) queryUpstreamServer(ctx context.Context, server *UpstreamServer,
	question dns.Question, ecs *ECSOption, serverDNSSECEnabled bool) UpstreamResult {

	start := time.Now()
	result := UpstreamResult{
		Server:   server,
		Duration: 0,
	}

	if server.IsRecursive() {
		// 递归查询
		answer, authority, additional, validated, ecsResponse, err := r.resolveWithCNAME(ctx, question, ecs)
		result.Duration = time.Since(start)
		result.Error = err

		if err != nil {
			logf(LogDebug, "🔗 递归解析失败 %s: %v", server.Name, err)
			return result
		}

		response := new(dns.Msg)
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
			opt := &dns.OPT{
				Hdr: dns.RR_Header{
					Name:   ".",
					Rrtype: dns.TypeOPT,
					Class:  UpstreamBufferSize,
				},
			}
			if serverDNSSECEnabled {
				opt.SetDo(true)
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
	} else {
		// 上游服务器查询
		msg := new(dns.Msg)
		msg.SetQuestion(question.Name, question.Qtype)
		msg.RecursionDesired = true

		opt := &dns.OPT{
			Hdr: dns.RR_Header{
				Name:   ".",
				Rrtype: dns.TypeOPT,
				Class:  UpstreamBufferSize,
			},
		}

		if serverDNSSECEnabled {
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

		response, err := r.queryWithFallback(queryCtx, msg, server.Address)
		result.Duration = time.Since(start)
		result.Response = response
		result.Error = err

		if err != nil {
			logf(LogDebug, "🔗 上游查询失败 %s: %v", server.Name, err)
			return result
		}

		if response.Rcode != dns.RcodeSuccess {
			logf(LogDebug, "🔗 上游查询 %s 返回: %s", server.Name, dns.RcodeToString[response.Rcode])
			return result
		}

		if serverDNSSECEnabled {
			result.Validated = r.dnssecVal.ValidateResponse(response, serverDNSSECEnabled)
		}
	}

	// 分析IP
	result.HasChinaIP, result.HasNonChinaIP = r.ipFilter.AnalyzeIPs(result.Response.Answer)
	result.Trusted = server.ShouldTrustResult(result.HasChinaIP, result.HasNonChinaIP)

	if r.config.Upstream.FilteringEnabled && r.ipFilter.HasData() {
		if !result.Trusted {
			result.Filtered = true
			logf(LogDebug, "🚫 过滤结果: %s (策略: %s)", server.Name, server.TrustPolicy)
		}
	}

	return result
}

func (r *RecursiveDNSServer) selectUpstreamResult(results []UpstreamResult, question dns.Question) ([]dns.RR, []dns.RR, []dns.RR, bool, *ECSOption, error) {
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

	var selectedResult UpstreamResult

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
		selectedResult = validResults[int(time.Now().UnixNano())%len(validResults)]
	case "weighted":
		selectedResult = r.selectWeightedResult(validResults)
	default:
		selectedResult = validResults[0]
	}

	sourceType := "上游"
	if selectedResult.Server.IsRecursive() {
		sourceType = "递归"
	}
	logf(LogDebug, "✅ 选择%s结果: %s (策略: %s)", sourceType, selectedResult.Server.Name, r.config.Upstream.Strategy)

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

	return selectedResult.Response.Answer, selectedResult.Response.Ns, selectedResult.Response.Extra, selectedResult.Validated, ecsResponse, nil
}

func (r *RecursiveDNSServer) selectWeightedResult(results []UpstreamResult) UpstreamResult {
	totalWeight := 0
	for _, result := range results {
		totalWeight += result.Server.Weight
	}

	if totalWeight == 0 {
		return results[0]
	}

	target := int(time.Now().UnixNano()) % totalWeight
	current := 0

	for _, result := range results {
		current += result.Server.Weight
		if current > target {
			return result
		}
	}
	return results[0]
}

// ==================== 递归解析实现 ====================

func (r *RecursiveDNSServer) resolveWithCNAME(ctx context.Context, question dns.Question, ecs *ECSOption) ([]dns.RR, []dns.RR, []dns.RR, bool, *ECSOption, error) {
	defer recoverPanic("CNAME解析")

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

		answer, authority, additional, validated, ecsResponse, err := r.recursiveQuery(ctx, currentQuestion, ecs, 0, false)
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

func (r *RecursiveDNSServer) recursiveQuery(ctx context.Context, question dns.Question, ecs *ECSOption, depth int, forceTCP bool) ([]dns.RR, []dns.RR, []dns.RR, bool, *ECSOption, error) {
	if depth > r.config.Performance.MaxRecursion {
		return nil, nil, nil, false, nil, fmt.Errorf("递归深度超限: %d", depth)
	}

	qname := dns.Fqdn(question.Name)
	question.Name = qname
	nameservers := r.getRootServers()
	currentDomain := "."

	normalizedQname := strings.ToLower(strings.TrimSuffix(qname, "."))

	// 特殊处理根域名查询
	if normalizedQname == "" {
		response, err := r.queryNameserversConcurrent(ctx, nameservers, question, ecs, forceTCP)
		if err != nil {
			return nil, nil, nil, false, nil, fmt.Errorf("查询根域名失败: %w", err)
		}

		// DNS劫持预防检查
		if r.hijackPrevention.IsEnabled() {
			if valid, reason := r.hijackPrevention.CheckResponse(currentDomain, normalizedQname, response); !valid {
				return r.handleSuspiciousResponse(response, reason, forceTCP)
			}
		}

		validated := false
		if r.config.Features.DNSSEC {
			validated = r.dnssecVal.ValidateResponse(response, true)
		}

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
					break
				}
			}
		}

		return response.Answer, response.Ns, response.Extra, validated, ecsResponse, nil
	}

	for {
		select {
		case <-ctx.Done():
			return nil, nil, nil, false, nil, ctx.Err()
		default:
		}

		response, err := r.queryNameserversConcurrent(ctx, nameservers, question, ecs, forceTCP)
		if err != nil {
			// 检查是否需要TCP重试
			if !forceTCP && strings.HasPrefix(err.Error(), "DNS_HIJACK_DETECTED") {
				logf(LogInfo, "🔄 检测到DNS劫持，自动切换到TCP模式重试: %s", currentDomain)
				return r.recursiveQuery(ctx, question, ecs, depth, true)
			}
			return nil, nil, nil, false, nil, fmt.Errorf("查询%s失败: %w", currentDomain, err)
		}

		// DNS劫持预防检查
		if r.hijackPrevention.IsEnabled() {
			if valid, reason := r.hijackPrevention.CheckResponse(currentDomain, normalizedQname, response); !valid {
				answer, authority, additional, validated, ecsResponse, err := r.handleSuspiciousResponse(response, reason, forceTCP)
				if err != nil && !forceTCP && strings.HasPrefix(err.Error(), "DNS_HIJACK_DETECTED") {
					logf(LogInfo, "🔄 检测到DNS劫持，自动切换到TCP模式重试: %s", currentDomain)
					return r.recursiveQuery(ctx, question, ecs, depth, true)
				}
				return answer, authority, additional, validated, ecsResponse, err
			}
		}

		validated := false
		if r.config.Features.DNSSEC {
			validated = r.dnssecVal.ValidateResponse(response, true)
		}

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
					break
				}
			}
		}

		if len(response.Answer) > 0 {
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
			return nil, response.Ns, response.Extra, validated, ecsResponse, nil
		}

		// 循环检测
		currentDomainNormalized := strings.ToLower(strings.TrimSuffix(currentDomain, "."))
		if bestMatch == currentDomainNormalized && currentDomainNormalized != "" {
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
						nextNS = append(nextNS, net.JoinHostPort(a.A.String(), "53"))
					}
				case *dns.AAAA:
					if r.config.Network.EnableIPv6 && strings.EqualFold(a.Header().Name, ns.Ns) {
						nextNS = append(nextNS, net.JoinHostPort(a.AAAA.String(), "53"))
					}
				}
			}
		}

		// 如果Additional中没有地址，需要单独解析NS
		if len(nextNS) == 0 {
			nextNS = r.resolveNSAddressesConcurrent(ctx, bestNSRecords, qname, depth, forceTCP)
		}

		if len(nextNS) == 0 {
			return nil, response.Ns, response.Extra, validated, ecsResponse, nil
		}

		nameservers = nextNS
	}
}

func (r *RecursiveDNSServer) handleSuspiciousResponse(response *dns.Msg, reason string, currentlyTCP bool) ([]dns.RR, []dns.RR, []dns.RR, bool, *ECSOption, error) {
	if !currentlyTCP {
		logf(LogWarn, "🛡️ 检测到DNS劫持，将切换到TCP模式重试: %s", reason)
		return nil, nil, nil, false, nil, fmt.Errorf("DNS_HIJACK_DETECTED: %s", reason)
	} else {
		logf(LogError, "🚫 TCP模式下仍检测到DNS劫持，拒绝响应: %s", reason)
		return nil, nil, nil, false, nil, fmt.Errorf("检测到DNS劫持(TCP模式): %s", reason)
	}
}

func (r *RecursiveDNSServer) queryNameserversConcurrent(ctx context.Context, nameservers []string, question dns.Question, ecs *ECSOption, forceTCP bool) (*dns.Msg, error) {
	defer recoverPanic("nameserver并发查询")

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
		r.wg.Add(1)
		go func(ns string) {
			defer r.wg.Done()
			defer recoverPanic(fmt.Sprintf("nameserver查询 %s", ns))

			start := time.Now()

			msg := new(dns.Msg)
			msg.SetQuestion(question.Name, question.Qtype)
			msg.RecursionDesired = false

			opt := &dns.OPT{
				Hdr: dns.RR_Header{
					Name:   ".",
					Rrtype: dns.TypeOPT,
					Class:  UpstreamBufferSize,
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

			var response *dns.Msg
			var err error

			if forceTCP {
				tcpClient := r.connPool.GetTCP()
				response, _, err = tcpClient.ExchangeContext(queryCtx, msg, ns)
			} else {
				response, err = r.queryWithFallback(queryCtx, msg, ns)
			}

			duration := time.Since(start)

			result := QueryResult{
				Response: response,
				Server:   ns,
				Error:    err,
				Duration: duration,
			}

			select {
			case resultChan <- result:
			case <-queryCtx.Done():
			}
		}(nameservers[i])
	}

	for i := 0; i < concurrency; i++ {
		select {
		case result := <-resultChan:
			if result.Error != nil {
				continue
			}

			if result.Response.Rcode == dns.RcodeSuccess || result.Response.Rcode == dns.RcodeNameError {
				return result.Response, nil
			}

		case <-queryCtx.Done():
			return nil, errors.New("查询超时")
		}
	}

	return nil, errors.New("所有nameserver查询失败")
}

func (r *RecursiveDNSServer) resolveNSAddressesConcurrent(ctx context.Context, nsRecords []*dns.NS, qname string, depth int, forceTCP bool) []string {
	defer recoverPanic("NS地址并发解析")

	resolveCount := len(nsRecords)
	if resolveCount > 3 {
		resolveCount = 3
	}

	nsChan := make(chan []string, resolveCount)
	resolveCtx, resolveCancel := context.WithTimeout(ctx, 5*time.Second)
	defer resolveCancel()

	for i := 0; i < resolveCount; i++ {
		r.wg.Add(1)
		go func(ns *dns.NS) {
			defer r.wg.Done()
			defer recoverPanic(fmt.Sprintf("NS解析 %s", ns.Ns))

			if strings.EqualFold(strings.TrimSuffix(ns.Ns, "."), strings.TrimSuffix(qname, ".")) {
				select {
				case nsChan <- nil:
				case <-resolveCtx.Done():
				}
				return
			}

			var addresses []string

			nsQuestion := dns.Question{Name: dns.Fqdn(ns.Ns), Qtype: dns.TypeA, Qclass: dns.ClassINET}
			if nsAnswer, _, _, _, _, err := r.recursiveQuery(resolveCtx, nsQuestion, nil, depth+1, forceTCP); err == nil {
				for _, rr := range nsAnswer {
					if a, ok := rr.(*dns.A); ok {
						addresses = append(addresses, net.JoinHostPort(a.A.String(), "53"))
					}
				}
			}

			if r.config.Network.EnableIPv6 && len(addresses) == 0 {
				nsQuestionV6 := dns.Question{Name: dns.Fqdn(ns.Ns), Qtype: dns.TypeAAAA, Qclass: dns.ClassINET}
				if nsAnswerV6, _, _, _, _, err := r.recursiveQuery(resolveCtx, nsQuestionV6, nil, depth+1, forceTCP); err == nil {
					for _, rr := range nsAnswerV6 {
						if aaaa, ok := rr.(*dns.AAAA); ok {
							addresses = append(addresses, net.JoinHostPort(aaaa.AAAA.String(), "53"))
						}
					}
				}
			}

			select {
			case nsChan <- addresses:
			case <-resolveCtx.Done():
			}
		}(nsRecords[i])
	}

	var allAddresses []string
	for i := 0; i < resolveCount; i++ {
		select {
		case addresses := <-nsChan:
			if len(addresses) > 0 {
				allAddresses = append(allAddresses, addresses...)
				if len(allAddresses) >= 3 {
					resolveCancel()
					break
				}
			}
		case <-resolveCtx.Done():
			break
		}
	}

	return allAddresses
}

// ==================== 工具函数 ====================

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
			// 过滤DNSSEC记录
		default:
			filtered = append(filtered, rr)
		}
	}
	return filtered
}

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
		fmt.Fprintf(os.Stderr, "  %s                         # 使用默认配置启动（纯递归模式）\n\n", os.Args[0])
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
