package main

import (
	"compress/gzip"
	"context"
	"encoding/gob"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/miekg/dns"
)

type LogLevel int

const (
	LogError LogLevel = iota
	LogWarn
	LogInfo
	LogDebug
)

func (l LogLevel) String() string {
	levels := []string{"ERROR", "WARN", "INFO", "DEBUG"}
	if int(l) < len(levels) {
		return levels[l]
	}
	return "UNKNOWN"
}

var currentLogLevel = LogError

func logf(level LogLevel, format string, args ...interface{}) {
	if level <= currentLogLevel {
		log.Printf("[%s] %s", level.String(), fmt.Sprintf(format, args...))
	}
}

type ServerConfig struct {
	Port             string
	CacheSize        int
	CacheFile        string
	DefaultECSSubnet string
	SaveInterval     int
	ServeExpired     bool
	ExpiredTTL       int
	StaleMaxAge      int
	LogLevel         string
	EnableIPv6       bool
	MaxConcurrency   int // 新增：最大并发查询数
	ConnPoolSize     int // 新增：连接池大小
}

func parseFlags() *ServerConfig {
	config := &ServerConfig{}
	flag.StringVar(&config.Port, "port", "53", "DNS服务器端口")
	flag.IntVar(&config.CacheSize, "cache-size", 10000, "DNS缓存条目数量限制")
	flag.StringVar(&config.CacheFile, "cache-file", "dns_cache.gob.gz", "缓存持久化文件路径")
	flag.StringVar(&config.DefaultECSSubnet, "default-ecs", "", "默认ECS子网地址")
	flag.IntVar(&config.SaveInterval, "save-interval", 600, "缓存保存间隔（秒）")
	flag.BoolVar(&config.ServeExpired, "serve-expired", true, "启用过期缓存服务")
	flag.IntVar(&config.ExpiredTTL, "expired-ttl", 30, "过期缓存响应的TTL（秒）")
	flag.IntVar(&config.StaleMaxAge, "stale-max-age", 86400, "过期缓存最大保留时间（秒）")
	flag.StringVar(&config.LogLevel, "log-level", "error", "日志级别 (error,warn,info,debug)")
	flag.BoolVar(&config.EnableIPv6, "enable-ipv6", false, "启用IPv6根服务器支持")
	flag.IntVar(&config.MaxConcurrency, "max-concurrency", 10, "最大并发查询数")
	flag.IntVar(&config.ConnPoolSize, "conn-pool-size", 20, "连接池大小")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "高性能DNS递归解析服务器\n\n用法: %s [选项]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "选项:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\n特性:\n")
		fmt.Fprintf(os.Stderr, "  • 高性能并发递归解析\n  • DNSSEC验证\n  • ECS支持\n  • 连接池优化\n  • 缓存持久化\n")
	}

	flag.Parse()
	return config
}

var validLogLevels = map[string]LogLevel{
	"error": LogError, "warn": LogWarn, "info": LogInfo, "debug": LogDebug,
}

func validateConfig(config *ServerConfig) error {
	if config.CacheSize < 100 || config.CacheSize > 1000000 {
		return fmt.Errorf("缓存大小必须在100-1000000之间")
	}

	if config.DefaultECSSubnet != "" {
		if _, _, err := net.ParseCIDR(config.DefaultECSSubnet); err != nil {
			return fmt.Errorf("ECS子网格式错误: %v", err)
		}
	}

	if config.ExpiredTTL < 1 || config.ExpiredTTL > 300 {
		return fmt.Errorf("过期TTL必须在1-300秒之间")
	}

	if config.MaxConcurrency < 1 || config.MaxConcurrency > 100 {
		return fmt.Errorf("并发数必须在1-100之间")
	}

	if config.ConnPoolSize < 5 || config.ConnPoolSize > 200 {
		return fmt.Errorf("连接池大小必须在5-200之间")
	}

	if level, ok := validLogLevels[strings.ToLower(config.LogLevel)]; ok {
		currentLogLevel = level
	} else {
		return fmt.Errorf("无效的日志级别: %s", config.LogLevel)
	}

	return nil
}

// 优化的紧凑DNS记录结构
type CompactDNSRecord struct {
	Text    string `gob:"t"`
	OrigTTL uint32 `gob:"o"`
	Type    uint16 `gob:"y"`
}

var rrPool = sync.Pool{
	New: func() interface{} {
		return make([]*CompactDNSRecord, 0, 16)
	},
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
		logf(LogWarn, "解析DNS记录失败: %v", err)
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

	seen := make(map[string]bool, len(rrs))

	for _, rr := range rrs {
		if rr == nil {
			continue
		}

		if _, ok := rr.(*dns.OPT); ok {
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

type CacheEntry struct {
	Answer      []*CompactDNSRecord `gob:"a"`
	Authority   []*CompactDNSRecord `gob:"u"`
	Additional  []*CompactDNSRecord `gob:"d"`
	TTL         int                 `gob:"t"`
	Timestamp   int64               `gob:"s"`
	Validated   bool                `gob:"v"`
	AccessTime  int64               `gob:"c"`
	RefreshTime int64               `gob:"r"`
}

func (c *CacheEntry) IsExpired() bool {
	return time.Now().Unix()-c.Timestamp > int64(c.TTL)
}

func (c *CacheEntry) IsStale(maxAge int) bool {
	return time.Now().Unix()-c.Timestamp > int64(c.TTL+maxAge)
}

func (c *CacheEntry) NeedsRefresh() bool {
	now := time.Now().Unix()
	return c.IsExpired() &&
		   (now-c.Timestamp) > int64(c.TTL+300) &&
		   (now-c.RefreshTime) > 600
}

func (c *CacheEntry) GetRemainingTTL(expiredTTL int) uint32 {
	remaining := int64(c.TTL) - (time.Now().Unix() - c.Timestamp)
	if remaining <= 0 {
		return uint32(expiredTTL)
	}
	return uint32(remaining)
}

func (c *CacheEntry) GetAnswerRRs() []dns.RR     { return expandRRs(c.Answer) }
func (c *CacheEntry) GetAuthorityRRs() []dns.RR  { return expandRRs(c.Authority) }
func (c *CacheEntry) GetAdditionalRRs() []dns.RR { return expandRRs(c.Additional) }

type RefreshRequest struct {
	Question dns.Question
	ECS      *ECSOption
	CacheKey string
}

// 高性能DNS缓存
type DNSCache struct {
	cache        map[string]*CacheEntry
	mutex        sync.RWMutex
	maxSize      int
	accessed     map[string]int64
	cacheFile    string
	saveTimer    *time.Timer
	saveInterval time.Duration
	serveExpired bool
	expiredTTL   int
	staleMaxAge  int
	refreshQueue chan RefreshRequest
	cleanupList  []string
}

func NewDNSCache(maxSize int, cacheFile string, saveInterval, expiredTTL, staleMaxAge int, serveExpired bool) *DNSCache {
	dc := &DNSCache{
		cache:        make(map[string]*CacheEntry, maxSize),
		maxSize:      maxSize,
		accessed:     make(map[string]int64, maxSize),
		cacheFile:    cacheFile,
		saveInterval: time.Duration(saveInterval) * time.Second,
		serveExpired: serveExpired,
		expiredTTL:   expiredTTL,
		staleMaxAge:  staleMaxAge,
		refreshQueue: make(chan RefreshRequest, 100),
		cleanupList:  make([]string, 0, 1000),
	}

	if err := dc.loadFromFile(); err != nil {
		logf(LogWarn, "加载缓存失败: %v", err)
	}

	if saveInterval > 0 {
		dc.startPeriodicSave()
	}

	if serveExpired {
		dc.startStaleCleanup()
	}

	return dc
}

// 修复：移除未使用的 maxAge 变量
func (dc *DNSCache) loadFromFile() error {
	if dc.cacheFile == "" {
		return nil
	}

	file, err := os.Open(dc.cacheFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer file.Close()

	var reader io.Reader = file
	if strings.HasSuffix(dc.cacheFile, ".gz") {
		gzReader, err := gzip.NewReader(file)
		if err != nil {
			return err
		}
		defer gzReader.Close()
		reader = gzReader
	}

	var data struct {
		Cache    map[string]*CacheEntry `gob:"c"`
		Accessed map[string]int64       `gob:"a"`
		Version  int                    `gob:"v"`
	}

	if err := gob.NewDecoder(reader).Decode(&data); err != nil {
		logf(LogWarn, "缓存文件格式不兼容，从空缓存开始: %v", err)
		return nil
	}

	dc.mutex.Lock()
	defer dc.mutex.Unlock()

	validCount, expiredCount, errorCount := 0, 0, 0
	now := time.Now().Unix()

	for key, entry := range data.Cache {
		if entry == nil {
			errorCount++
			continue
		}

		if entry.Timestamp <= 0 || entry.Timestamp > now+3600 {
			errorCount++
			continue
		}

		// 修复：直接使用条件判断，不定义unused变量
		var shouldKeep bool
		if dc.serveExpired {
			shouldKeep = now-entry.Timestamp <= int64(entry.TTL+dc.staleMaxAge)
		} else {
			shouldKeep = now-entry.Timestamp <= int64(entry.TTL)
		}

		if shouldKeep {
			dc.cache[key] = entry
			if accessTime, exists := data.Accessed[key]; exists {
				dc.accessed[key] = accessTime
			} else {
				dc.accessed[key] = entry.Timestamp
			}

			if entry.IsExpired() {
				expiredCount++
			} else {
				validCount++
			}
		}
	}

	logMsg := fmt.Sprintf("加载缓存: %d条有效", validCount)
	if dc.serveExpired && expiredCount > 0 {
		logMsg += fmt.Sprintf(", %d条过期", expiredCount)
	}
	if errorCount > 0 {
		logMsg += fmt.Sprintf(", %d条损坏已跳过", errorCount)
	}
	logf(LogInfo, logMsg)

	return nil
}

func (dc *DNSCache) saveToFile() error {
	if dc.cacheFile == "" {
		return nil
	}

	if err := os.MkdirAll(filepath.Dir(dc.cacheFile), 0755); err != nil {
		return err
	}

	tempFile := dc.cacheFile + ".tmp"
	file, err := os.Create(tempFile)
	if err != nil {
		return err
	}

	var writer io.Writer = file
	var gzWriter *gzip.Writer
	if strings.HasSuffix(dc.cacheFile, ".gz") {
		gzWriter = gzip.NewWriter(file)
		writer = gzWriter
	}

	dc.mutex.RLock()

	validEntries := 0
	now := time.Now().Unix()

	// 预计算有效条目数
	for _, entry := range dc.cache {
		var shouldSave bool
		if dc.serveExpired {
			shouldSave = now-entry.Timestamp <= int64(entry.TTL+dc.staleMaxAge)
		} else {
			shouldSave = now-entry.Timestamp <= int64(entry.TTL)
		}
		if shouldSave {
			validEntries++
		}
	}

	data := struct {
		Cache    map[string]*CacheEntry `gob:"c"`
		Accessed map[string]int64       `gob:"a"`
		Version  int                    `gob:"v"`
	}{
		Cache:    make(map[string]*CacheEntry, validEntries),
		Accessed: make(map[string]int64, validEntries),
		Version:  1,
	}

	savedCount := 0
	for key, entry := range dc.cache {
		var shouldSave bool
		if dc.serveExpired {
			shouldSave = now-entry.Timestamp <= int64(entry.TTL+dc.staleMaxAge)
		} else {
			shouldSave = now-entry.Timestamp <= int64(entry.TTL)
		}

		if shouldSave {
			data.Cache[key] = entry
			data.Accessed[key] = dc.accessed[key]
			savedCount++
		}
	}
	dc.mutex.RUnlock()

	err = gob.NewEncoder(writer).Encode(data)

	if gzWriter != nil {
		gzWriter.Close()
	}
	file.Close()

	if err != nil {
		os.Remove(tempFile)
		return err
	}

	if err := os.Rename(tempFile, dc.cacheFile); err != nil {
		os.Remove(tempFile)
		return err
	}

	logf(LogInfo, "保存缓存: %d条", savedCount)
	return nil
}

func (dc *DNSCache) startPeriodicSave() {
	dc.saveTimer = time.NewTimer(dc.saveInterval)
	go func() {
		for range dc.saveTimer.C {
			if err := dc.saveToFile(); err != nil {
				logf(LogWarn, "保存缓存失败: %v", err)
			}
			dc.saveTimer.Reset(dc.saveInterval)
		}
	}()
}

func (dc *DNSCache) startStaleCleanup() {
	go func() {
		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()

		for range ticker.C {
			dc.cleanupStaleEntries()
		}
	}()
}

func (dc *DNSCache) cleanupStaleEntries() {
	dc.mutex.Lock()
	defer dc.mutex.Unlock()

	dc.cleanupList = dc.cleanupList[:0]
	now := time.Now().Unix()

	for key, entry := range dc.cache {
		if now-entry.Timestamp > int64(entry.TTL+dc.staleMaxAge) {
			dc.cleanupList = append(dc.cleanupList, key)
		}
	}

	for _, key := range dc.cleanupList {
		delete(dc.cache, key)
		delete(dc.accessed, key)
	}

	if len(dc.cleanupList) > 0 {
		logf(LogInfo, "清理过期缓存: %d条", len(dc.cleanupList))
	}
}

func (dc *DNSCache) RequestRefresh(req RefreshRequest) {
	select {
	case dc.refreshQueue <- req:
	default:
	}
}

func (dc *DNSCache) Shutdown() {
	if dc.saveTimer != nil {
		dc.saveTimer.Stop()
	}
	close(dc.refreshQueue)
	dc.saveToFile()
}

func (dc *DNSCache) Get(key string) (*CacheEntry, bool, bool) {
	dc.mutex.RLock()
	entry, exists := dc.cache[key]
	if !exists {
		dc.mutex.RUnlock()
		return nil, false, false
	}

	now := time.Now().Unix()
	if dc.serveExpired && now-entry.Timestamp > int64(entry.TTL+dc.staleMaxAge) {
		dc.mutex.RUnlock()
		go dc.removeStaleEntry(key)
		return nil, false, false
	}

	dc.mutex.RUnlock()

	dc.mutex.Lock()
	dc.accessed[key] = now
	entry.AccessTime = now
	dc.mutex.Unlock()

	isExpired := entry.IsExpired()
	if !dc.serveExpired && isExpired {
		go dc.removeStaleEntry(key)
		return nil, false, false
	}

	return entry, true, isExpired
}

func (dc *DNSCache) removeStaleEntry(key string) {
	dc.mutex.Lock()
	delete(dc.cache, key)
	delete(dc.accessed, key)
	dc.mutex.Unlock()
}

func (dc *DNSCache) Set(key string, answer, authority, additional []dns.RR, validated bool) {
	minTTL := 3600
	for _, rrs := range [][]dns.RR{answer, authority, additional} {
		for _, rr := range rrs {
			if ttl := int(rr.Header().Ttl); ttl > 0 && ttl < minTTL {
				minTTL = ttl
			}
		}
	}

	if minTTL < 300 {
		minTTL = 300
	} else if minTTL > 86400 {
		minTTL = 86400
	}

	now := time.Now().Unix()
	entry := &CacheEntry{
		Answer:      compactRRs(answer),
		Authority:   compactRRs(authority),
		Additional:  compactRRs(additional),
		TTL:         minTTL,
		Timestamp:   now,
		Validated:   validated,
		AccessTime:  now,
		RefreshTime: 0,
	}

	dc.mutex.Lock()
	if len(dc.cache) >= dc.maxSize {
		dc.evictLRU()
	}
	dc.cache[key] = entry
	dc.accessed[key] = now
	dc.mutex.Unlock()

	validatedStr := ""
	if validated {
		validatedStr = " [DNSSEC]"
	}
	logf(LogDebug, "缓存: %s (TTL: %ds, 答案: %d条)%s", key, minTTL, len(answer), validatedStr)
}

func (dc *DNSCache) UpdateRefreshTime(key string) {
	dc.mutex.Lock()
	if entry, exists := dc.cache[key]; exists {
		entry.RefreshTime = time.Now().Unix()
	}
	dc.mutex.Unlock()
}

func (dc *DNSCache) evictLRU() {
	var oldestKey string
	var oldestTime int64 = time.Now().Unix()

	for key, accessTime := range dc.accessed {
		if accessTime < oldestTime {
			oldestTime = accessTime
			oldestKey = key
		}
	}

	if oldestKey != "" {
		delete(dc.cache, oldestKey)
		delete(dc.accessed, oldestKey)
	}
}

func copyRRs(rrs []dns.RR) []dns.RR {
	if len(rrs) == 0 {
		return nil
	}
	result := make([]dns.RR, len(rrs))
	for i, rr := range rrs {
		result[i] = dns.Copy(rr)
	}
	return result
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
		return nil, err
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
			case *dns.RRSIG:
				logf(LogDebug, "DNSSEC: 发现RRSIG记录")
				return true
			case *dns.NSEC, *dns.NSEC3:
				logf(LogDebug, "DNSSEC: 发现NSEC记录")
				return true
			}
		}
	}
	return false
}

// 新增：连接池管理器
type ConnectionPool struct {
	clients      []*dns.Client
	pool         chan *dns.Client
	maxSize      int
	timeout      time.Duration
}

func NewConnectionPool(size int, timeout time.Duration) *ConnectionPool {
	pool := &ConnectionPool{
		clients: make([]*dns.Client, 0, size),
		pool:    make(chan *dns.Client, size),
		maxSize: size,
		timeout: timeout,
	}

	// 预创建连接
	for i := 0; i < size; i++ {
		client := &dns.Client{
			Timeout: timeout,
			Net:     "udp",
		}
		pool.clients = append(pool.clients, client)
		pool.pool <- client
	}

	return pool
}

func (cp *ConnectionPool) Get() *dns.Client {
	select {
	case client := <-cp.pool:
		return client
	default:
		// 如果池为空，创建临时客户端
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

// 新增：并发查询结果
type QueryResult struct {
	Response *dns.Msg
	Server   string
	Error    error
	Duration time.Duration
}

// 高性能递归DNS服务器
type RecursiveDNSServer struct {
	config        *ServerConfig
	cache         *DNSCache
	rootServersV4 []string
	rootServersV6 []string
	connPool      *ConnectionPool
	dnssecVal     *DNSSECValidator
	defaultECS    *ECSOption

	// 新增：并发控制
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

	defaultECS, err := parseDefaultECS(config.DefaultECSSubnet)
	if err != nil {
		return nil, fmt.Errorf("ECS配置错误: %v", err)
	}

	server := &RecursiveDNSServer{
		config:           config,
		cache:            NewDNSCache(config.CacheSize, config.CacheFile, config.SaveInterval, config.ExpiredTTL, config.StaleMaxAge, config.ServeExpired),
		rootServersV4:    rootServersV4,
		rootServersV6:    rootServersV6,
		connPool:         NewConnectionPool(config.ConnPoolSize, 3*time.Second),
		dnssecVal:        NewDNSSECValidator(),
		defaultECS:       defaultECS,
		concurrencyLimit: make(chan struct{}, config.MaxConcurrency),
	}

	if config.ServeExpired {
		server.startRefreshProcessor()
	}

	server.setupSignalHandling()
	return server, nil
}

func (r *RecursiveDNSServer) startRefreshProcessor() {
	// 启动多个worker处理刷新请求
	for i := 0; i < 3; i++ {
		go func() {
			for req := range r.cache.refreshQueue {
				r.handleRefreshRequest(req)
			}
		}()
	}
}

func (r *RecursiveDNSServer) handleRefreshRequest(req RefreshRequest) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	logf(LogDebug, "后台刷新: %s %s", dns.TypeToString[req.Question.Qtype], req.Question.Name)

	r.cache.UpdateRefreshTime(req.CacheKey)

	answer, authority, additional, validated, err := r.resolveWithCNAME(ctx, req.Question, req.ECS)
	if err != nil {
		logf(LogWarn, "后台刷新失败: %v", err)
		return
	}

	r.cache.Set(req.CacheKey, answer, authority, additional, validated)
	logf(LogDebug, "后台刷新成功: %s", req.CacheKey)
}

func (r *RecursiveDNSServer) setupSignalHandling() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		logf(LogInfo, "收到关闭信号，保存缓存...")
		r.cache.Shutdown()
		os.Exit(0)
	}()
}

func (r *RecursiveDNSServer) getRootServers() []string {
	if r.config.EnableIPv6 {
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

	logf(LogInfo, "启动高性能DNS服务器...")
	logf(LogInfo, "端口: %s, 缓存: %d条, 并发: %d, 连接池: %d",
		r.config.Port, r.config.CacheSize, r.config.MaxConcurrency, r.config.ConnPoolSize)
	if r.config.EnableIPv6 {
		logf(LogInfo, "IPv6支持: 启用")
	}
	if r.config.ServeExpired {
		logf(LogInfo, "Serve-Expired: 启用 (过期TTL: %ds)", r.config.ExpiredTTL)
	}
	if r.defaultECS != nil {
		logf(LogInfo, "默认ECS: %s/%d", r.defaultECS.Address, r.defaultECS.SourcePrefix)
	}

	wg.Add(2)

	go func() {
		defer wg.Done()
		server := &dns.Server{
			Addr: ":" + r.config.Port,
			Net:  "udp",
			Handler: dns.HandlerFunc(r.handleDNSRequest),
		}
		if err := server.ListenAndServe(); err != nil {
			errChan <- fmt.Errorf("UDP启动失败: %v", err)
		}
	}()

	go func() {
		defer wg.Done()
		server := &dns.Server{
			Addr: ":" + r.config.Port,
			Net:  "tcp",
			Handler: dns.HandlerFunc(r.handleDNSRequest),
		}
		if err := server.ListenAndServe(); err != nil {
			errChan <- fmt.Errorf("TCP启动失败: %v", err)
		}
	}()

	logf(LogInfo, "服务器启动完成")

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
	response := r.processDNSQuery(req, getClientIP(w))
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
				logf(LogDebug, "客户端ECS: %s/%d", ecsOpt.Address, ecsOpt.SourcePrefix)
				break
			}
		}
	}

	if ecsOpt == nil && r.defaultECS != nil {
		ecsOpt = r.defaultECS
		logf(LogDebug, "使用默认ECS: %s/%d", ecsOpt.Address, ecsOpt.SourcePrefix)
	}

	cacheKey := r.buildCacheKey(question, ecsOpt, dnssecOK)

	if entry, found, isExpired := r.cache.Get(cacheKey); found {
		if isExpired {
			logf(LogDebug, "缓存命中(过期): %s %s", question.Name, dns.TypeToString[question.Qtype])
		} else {
			logf(LogDebug, "缓存命中: %s %s", question.Name, dns.TypeToString[question.Qtype])
		}

		responseTTL := entry.GetRemainingTTL(r.config.ExpiredTTL)

		msg.Answer = adjustTTL(filterDNSSECRecords(entry.GetAnswerRRs(), dnssecOK), responseTTL)
		msg.Ns = adjustTTL(filterDNSSECRecords(entry.GetAuthorityRRs(), dnssecOK), responseTTL)
		msg.Extra = adjustTTL(filterDNSSECRecords(entry.GetAdditionalRRs(), dnssecOK), responseTTL)

		if isExpired && r.config.ServeExpired && entry.NeedsRefresh() {
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

	logf(LogInfo, "递归解析: %s %s", dns.TypeToString[question.Qtype], question.Name)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	answer, authority, additional, validated, err := r.resolveWithCNAME(ctx, question, ecsOpt)
	if err != nil {
		logf(LogError, "查询失败: %v", err)

		if r.config.ServeExpired {
			if entry, found, _ := r.cache.Get(cacheKey); found {
				logf(LogInfo, "使用过期缓存: %s %s", question.Name, dns.TypeToString[question.Qtype])

				responseTTL := uint32(r.config.ExpiredTTL)
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
			return nil, nil, nil, false, fmt.Errorf("CNAME循环: %s", currentName)
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
	if depth > 10 {
		return nil, nil, nil, false, fmt.Errorf("递归深度超限")
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

		// 核心优化：并发查询nameservers
		response, err := r.queryNameserversConcurrent(ctx, nameservers, question, ecs)
		if err != nil {
			return nil, nil, nil, false, fmt.Errorf("查询%s失败: %v", currentDomain, err)
		}

		validated := r.dnssecVal.HasDNSSECRecords(response)

		if len(response.Answer) > 0 {
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
			return nil, nil, nil, false, fmt.Errorf("未找到NS记录")
		}

		if bestMatch == strings.TrimSuffix(currentDomain, ".") {
			return nil, nil, nil, false, fmt.Errorf("递归循环: %s", bestMatch)
		}

		currentDomain = bestMatch + "."
		var nextNS []string

		// 从Extra记录中快速查找NS地址
		for _, ns := range bestNSRecords {
			for _, rr := range response.Extra {
				switch a := rr.(type) {
				case *dns.A:
					if strings.EqualFold(a.Header().Name, ns.Ns) {
						nextNS = append(nextNS, net.JoinHostPort(a.A.String(), "53"))
					}
				case *dns.AAAA:
					if r.config.EnableIPv6 && strings.EqualFold(a.Header().Name, ns.Ns) {
						nextNS = append(nextNS, net.JoinHostPort(a.AAAA.String(), "53"))
					}
				}
			}
		}

		// 如果需要递归解析NS，使用并发方式
		if len(nextNS) == 0 {
			nextNS = r.resolveNSAddressesConcurrent(ctx, bestNSRecords, qname, depth)
		}

		if len(nextNS) == 0 {
			return nil, nil, nil, false, fmt.Errorf("无法解析NS地址")
		}

		nameservers = nextNS
	}
}

// 新增：并发查询nameservers
func (r *RecursiveDNSServer) queryNameserversConcurrent(ctx context.Context, nameservers []string, question dns.Question, ecs *ECSOption) (*dns.Msg, error) {
	if len(nameservers) == 0 {
		return nil, fmt.Errorf("没有可用的nameserver")
	}

	// 并发控制
	select {
	case r.concurrencyLimit <- struct{}{}:
		defer func() { <-r.concurrencyLimit }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	// 限制并发查询数量
	concurrency := len(nameservers)
	if concurrency > 5 {
		concurrency = 5
	}

	resultChan := make(chan QueryResult, concurrency)
	queryCtx, queryCancel := context.WithTimeout(ctx, 5*time.Second)
	defer queryCancel()

	// 启动并发查询
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
			opt.SetDo(true)

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

	// 等待第一个成功响应
	for i := 0; i < concurrency; i++ {
		select {
		case result := <-resultChan:
			if result.Error != nil {
				logf(LogDebug, "查询%s失败: %v (%v)", result.Server, result.Error, result.Duration)
				continue
			}

			if result.Response.Rcode == dns.RcodeSuccess || result.Response.Rcode == dns.RcodeNameError {
				logf(LogDebug, "查询%s成功 (%v)", result.Server, result.Duration)
				return result.Response, nil
			}

			logf(LogDebug, "查询%s返回: %s (%v)", result.Server, dns.RcodeToString[result.Response.Rcode], result.Duration)

		case <-queryCtx.Done():
			return nil, fmt.Errorf("查询超时")
		}
	}

	return nil, fmt.Errorf("所有nameserver查询失败")
}

// 新增：并发解析NS地址
func (r *RecursiveDNSServer) resolveNSAddressesConcurrent(ctx context.Context, nsRecords []*dns.NS, qname string, depth int) []string {
	var nextNS []string
	nsChan := make(chan []string, len(nsRecords))

	// 并发解析前几个NS记录
	resolveCount := len(nsRecords)
	if resolveCount > 3 {
		resolveCount = 3 // 最多并发解析3个NS
	}

	for i := 0; i < resolveCount; i++ {
		go func(ns *dns.NS) {
			defer func() { nsChan <- nil }()

			if strings.EqualFold(strings.TrimSuffix(ns.Ns, "."), strings.TrimSuffix(qname, ".")) {
				return
			}

			var addresses []string

			// A记录查询
			nsQuestion := dns.Question{Name: dns.Fqdn(ns.Ns), Qtype: dns.TypeA, Qclass: dns.ClassINET}
			if nsAnswer, _, _, _, err := r.recursiveQuery(ctx, nsQuestion, nil, depth+1); err == nil {
				for _, rr := range nsAnswer {
					if a, ok := rr.(*dns.A); ok {
						addresses = append(addresses, net.JoinHostPort(a.A.String(), "53"))
					}
				}
			}

			// IPv6支持
			if r.config.EnableIPv6 && len(addresses) == 0 {
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

	// 收集结果
	for i := 0; i < resolveCount; i++ {
		select {
		case addresses := <-nsChan:
			if len(addresses) > 0 {
				nextNS = append(nextNS, addresses...)
				if len(nextNS) >= 3 {
					return nextNS // 有足够的NS地址就返回
				}
			}
		case <-ctx.Done():
			return nextNS
		case <-time.After(3 * time.Second):
			logf(LogDebug, "NS解析超时")
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
	config := parseFlags()

	if err := validateConfig(config); err != nil {
		log.Fatalf("配置错误: %v", err)
	}

	server, err := NewRecursiveDNSServer(config)
	if err != nil {
		log.Fatalf("创建服务器失败: %v", err)
	}

	if err := server.Start(); err != nil {
		log.Fatalf("启动失败: %v", err)
	}
}
