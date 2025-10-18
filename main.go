// Package main implements a high-performance DNS server supporting
// recursive resolution, caching, and secure DNS protocols (DoT/DoH/DoQ).
package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
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

	_ "net/http/pprof"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/redis/go-redis/v9"
	"github.com/redis/go-redis/v9/logging"
	"golang.org/x/net/http2"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// =============================================================================
// Constants
// =============================================================================

const (
	// Version info
	Version    = "1.1.0"
	CommitHash = "dirty"
	BuildTime  = "dev"

	// Network ports
	DefaultDNSPort   = "53"
	DefaultTLSPort   = "853"
	DefaultHTTPSPort = "443"
	DefaultPprofPort = "6060"

	// Protocol
	RecursiveIndicator = "builtin_recursive"
	DefaultQueryPath   = "/dns-query"
	PprofPath          = "/debug/pprof/"

	// Buffer sizes
	UDPBufferSize    = 1232
	TCPBufferSize    = 4096
	SecureBufferSize = 8192
	MinDNSPacketSize = 12

	// Limits
	MaxDomainLength   = 253
	MaxCNAMEChain     = 16
	MaxRecursionDepth = 16
	MaxConcurrency    = 1000
	MaxSingleQuery    = 5
	MaxNSResolve      = 5
	MaxMessageCap     = 100

	// Timeouts
	QueryTimeout           = 5 * time.Second
	RecursiveTimeout       = 10 * time.Second
	ConnTimeout            = 5 * time.Second
	TLSHandshakeTimeout    = 3 * time.Second
	PublicIPTimeout        = 3 * time.Second
	HTTPClientTimeout      = 5 * time.Second
	ShutdownTimeout        = 3 * time.Second
	DoHReadHeaderTimeout   = 5 * time.Second
	DoHWriteTimeout        = 5 * time.Second
	SecureIdleTimeout      = 300 * time.Second
	PprofReadHeaderTimeout = 10 * time.Second
	PprofReadTimeout       = 30 * time.Second
	PprofIdleTimeout       = 120 * time.Second
	PprofShutdownTimeout   = 5 * time.Second
	ConnectionCloseTimeout = 1 * time.Second

	// Cache TTL settings
	DefaultCacheTTL = 10
	StaleTTL        = 30
	StaleMaxAge     = 86400 * 7

	// Redis
	RedisPoolSize     = 20
	RedisMinIdle      = 5
	RedisMaxRetries   = 3
	RedisPoolTimeout  = 5 * time.Second
	RedisReadTimeout  = 3 * time.Second
	RedisWriteTimeout = 3 * time.Second
	RedisDialTimeout  = 5 * time.Second

	// Redis key prefixes
	RedisPrefixDNS               = "dns:"
	RedisPrefixSpeedTestDomain   = "speedtest:domain:"
	RedisPrefixSpeedTestRoot     = "speedtest:rootserver:"
	RedisPrefixSpeedTestDebounce = "speedtest:debounce:"
	RedisPrefixQUICValidator     = "quic:validator:"
	RedisPrefixRefreshLock       = "refresh:lock:"

	// ECS
	DefaultECSv4Len = 24
	DefaultECSv6Len = 64
	DefaultECSScope = 0

	// Padding
	PaddingBlockSize = 468

	// DoH
	DoHMaxRequestSize = 8192

	// QUIC
	MaxIncomingStreams   = 2048
	QUICAddrValidatorTTL = 300 * time.Second

	// SpeedTest
	DefaultSpeedTimeout     = 250 * time.Millisecond
	DefaultSpeedConcurrency = 5
	UnreachableLatency      = 10 * time.Second
	DefaultSpeedCacheTTL    = 900 * time.Second
	SpeedDebounceInterval   = 10 * time.Second
	RootServerSortInterval  = 900 * time.Second

	// TLS
	CertValidityDuration = 90 * 24 * time.Hour

	// Defaults
	DefaultLogLevel = "info"

	// ANSI colors
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorYellow = "\033[33m"
	ColorGreen  = "\033[32m"
	ColorCyan   = "\033[36m"
	ColorBold   = "\033[1m"

	// QUIC error codes
	QUICCodeNoError       quic.ApplicationErrorCode = 0
	QUICCodeInternalError quic.ApplicationErrorCode = 1
	QUICCodeProtocolError quic.ApplicationErrorCode = 2
)

var (
	NextProtoQUIC  = []string{"doq", "doq-i00", "doq-i02", "doq-i03", "dq"}
	NextProtoHTTP3 = []string{"h3"}
	NextProtoHTTP2 = []string{http2.NextProtoTLS, "http/1.1"}

	// Maximum worker count
	MaxWorkerCount = runtime.NumCPU()
)

// =============================================================================
// Core Interfaces
// =============================================================================

// Closeable defines resource cleanup interface
type Closeable interface {
	Close() error
}

// =============================================================================
// Logging System
// =============================================================================

type LogLevel int

const (
	Error LogLevel = iota
	Warn
	Info
	Debug
)

type LogManager struct {
	level    LogLevel
	writer   io.Writer
	mu       sync.Mutex
	colorMap map[LogLevel]string
}

func NewLogManager() *LogManager {
	return &LogManager{
		level:  Info,
		writer: os.Stdout,
		colorMap: map[LogLevel]string{
			Error: ColorRed,
			Warn:  ColorYellow,
			Info:  ColorGreen,
			Debug: ColorCyan,
		},
	}
}

func (lm *LogManager) SetLevel(level LogLevel) {
	lm.mu.Lock()
	defer lm.mu.Unlock()
	lm.level = level
}

func (lm *LogManager) GetLevel() LogLevel {
	lm.mu.Lock()
	defer lm.mu.Unlock()
	return lm.level
}

func (lm *LogManager) Log(level LogLevel, format string, args ...interface{}) {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	if level > lm.level {
		return
	}

	levelStr := [...]string{"ERROR", "WARN", "INFO", "DEBUG"}[level]
	color := lm.colorMap[level]
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	message := fmt.Sprintf(format, args...)

	logLine := fmt.Sprintf("%s[%s]%s %s%-5s%s %s\n",
		ColorBold, timestamp, ColorReset,
		color, levelStr, ColorReset,
		message)

	_, _ = fmt.Fprint(lm.writer, logLine)
}

func (lm *LogManager) Error(format string, args ...interface{}) { lm.Log(Error, format, args...) }
func (lm *LogManager) Warn(format string, args ...interface{})  { lm.Log(Warn, format, args...) }
func (lm *LogManager) Info(format string, args ...interface{})  { lm.Log(Info, format, args...) }
func (lm *LogManager) Debug(format string, args ...interface{}) { lm.Log(Debug, format, args...) }

var globalLog = NewLogManager()

func LogError(format string, args ...interface{}) { globalLog.Error(format, args...) }
func LogWarn(format string, args ...interface{})  { globalLog.Warn(format, args...) }
func LogInfo(format string, args ...interface{})  { globalLog.Info(format, args...) }
func LogDebug(format string, args ...interface{}) { globalLog.Debug(format, args...) }

// =============================================================================
// Configuration Types
// =============================================================================

type ServerConfig struct {
	Server    ServerSettings    `json:"server"`
	Redis     RedisSettings     `json:"redis"`
	SpeedTest []SpeedTestMethod `json:"speedtest"`
	Upstream  []UpstreamServer  `json:"upstream"`
	Rewrite   []RewriteRule     `json:"rewrite"`
	CIDR      []CIDRConfig      `json:"cidr"`
}

type ServerSettings struct {
	Port       string       `json:"port"`
	Pprof      string       `json:"pprof"`
	LogLevel   string       `json:"log_level"`
	DefaultECS string       `json:"default_ecs_subnet"`
	DDR        DDRSettings  `json:"ddr"`
	TLS        TLSSettings  `json:"tls"`
	Features   FeatureFlags `json:"features"`
}

type DDRSettings struct {
	Domain string `json:"domain"`
	IPv4   string `json:"ipv4"`
	IPv6   string `json:"ipv6"`
}

type TLSSettings struct {
	Port       string        `json:"port"`
	CertFile   string        `json:"cert_file"`
	KeyFile    string        `json:"key_file"`
	SelfSigned bool          `json:"self_signed"`
	HTTPS      HTTPSSettings `json:"https"`
}

type HTTPSSettings struct {
	Port     string `json:"port"`
	Endpoint string `json:"endpoint"`
}

type FeatureFlags struct {
	HijackProtection bool `json:"hijack_protection"`
}

type RedisSettings struct {
	Address   string `json:"address"`
	Password  string `json:"password"`
	Database  int    `json:"database"`
	KeyPrefix string `json:"key_prefix"`
}

type UpstreamServer struct {
	Address       string   `json:"address"`
	Protocol      string   `json:"protocol"`
	ServerName    string   `json:"server_name"`
	SkipTLSVerify bool     `json:"skip_tls_verify"`
	Match         []string `json:"match,omitempty"`
}

func (u *UpstreamServer) IsRecursive() bool {
	return strings.ToLower(u.Address) == RecursiveIndicator
}

type RewriteRule struct {
	Name         string            `json:"name"`
	ResponseCode *int              `json:"response_code,omitempty"`
	Records      []DNSRecordConfig `json:"records,omitempty"`
	Additional   []DNSRecordConfig `json:"additional,omitempty"`
}

type DNSRecordConfig struct {
	Name         string `json:"name,omitempty"`
	Type         string `json:"type"`
	TTL          uint32 `json:"ttl,omitempty"`
	Content      string `json:"content"`
	ResponseCode *int   `json:"response_code,omitempty"`
}

type SpeedTestMethod struct {
	Type    string `json:"type"`
	Port    string `json:"port,omitempty"`
	Timeout int    `json:"timeout"`
}

type CIDRConfig struct {
	File  string   `json:"file,omitempty"`
	Rules []string `json:"rules,omitempty"`
	Tag   string   `json:"tag"`
}

// =============================================================================
// Configuration Manager
// =============================================================================

type ConfigManager struct{}

func (cm *ConfigManager) LoadConfig(configFile string) (*ServerConfig, error) {
	if configFile == "" {
		return cm.getDefaultConfig(), nil
	}

	data, err := os.ReadFile(configFile)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	config := &ServerConfig{}
	if err := json.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	if err := cm.validateConfig(config); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}

	if cm.shouldEnableDDR(config) {
		cm.addDDRRecords(config)
	}

	LogInfo("CONFIG: Configuration loaded successfully: %s", configFile)
	return config, nil
}

func (cm *ConfigManager) validateConfig(config *ServerConfig) error {
	// Validate log level
	validLevels := map[string]LogLevel{
		"error": Error, "warn": Warn, "info": Info, "debug": Debug,
	}
	if level, ok := validLevels[strings.ToLower(config.Server.LogLevel)]; ok {
		globalLog.SetLevel(level)
	} else {
		return fmt.Errorf("invalid log level: %s", config.Server.LogLevel)
	}

	// Validate ECS
	if config.Server.DefaultECS != "" {
		ecs := strings.ToLower(config.Server.DefaultECS)
		validPresets := []string{"auto", "auto_v4", "auto_v6"}
		isValidPreset := false
		for _, preset := range validPresets {
			if ecs == preset {
				isValidPreset = true
				break
			}
		}
		if !isValidPreset {
			if _, _, err := net.ParseCIDR(config.Server.DefaultECS); err != nil {
				return fmt.Errorf("invalid ECS subnet: %w", err)
			}
		}
	}

	// Validate CIDR
	cidrTags := make(map[string]bool)
	for i, cidrConfig := range config.CIDR {
		if cidrConfig.Tag == "" {
			return fmt.Errorf("CIDR config %d: tag cannot be empty", i)
		}
		if cidrTags[cidrConfig.Tag] {
			return fmt.Errorf("CIDR config %d: duplicate tag '%s'", i, cidrConfig.Tag)
		}
		cidrTags[cidrConfig.Tag] = true

		if cidrConfig.File == "" && len(cidrConfig.Rules) == 0 {
			return fmt.Errorf("CIDR config %d (tag '%s'): either 'file' or 'rules' must be specified", i, cidrConfig.Tag)
		}
		if cidrConfig.File != "" && !isValidFilePath(cidrConfig.File) {
			return fmt.Errorf("CIDR config %d (tag '%s'): file not found: %s", i, cidrConfig.Tag, cidrConfig.File)
		}
	}

	// Validate upstream
	for i, server := range config.Upstream {
		if !server.IsRecursive() {
			if _, _, err := net.SplitHostPort(server.Address); err != nil {
				if server.Protocol == "https" || server.Protocol == "http3" {
					if _, err := url.Parse(server.Address); err != nil {
						return fmt.Errorf("upstream server %d address invalid: %w", i, err)
					}
				} else {
					return fmt.Errorf("upstream server %d address invalid: %w", i, err)
				}
			}
		}

		validProtocols := map[string]bool{
			"udp": true, "tcp": true, "tls": true,
			"quic": true, "https": true, "http3": true,
		}
		if server.Protocol != "" && !validProtocols[strings.ToLower(server.Protocol)] {
			return fmt.Errorf("upstream server %d protocol invalid: %s", i, server.Protocol)
		}

		protocol := strings.ToLower(server.Protocol)
		if isSecureProtocol(protocol) && server.ServerName == "" {
			return fmt.Errorf("upstream server %d using %s requires server_name", i, server.Protocol)
		}

		for _, matchTag := range server.Match {
			cleanTag := strings.TrimPrefix(matchTag, "!")
			if !cidrTags[cleanTag] {
				return fmt.Errorf("upstream server %d: match tag '%s' not found in CIDR config", i, cleanTag)
			}
		}
	}

	// Validate Redis
	if config.Redis.Address != "" {
		if _, _, err := net.SplitHostPort(config.Redis.Address); err != nil {
			return fmt.Errorf("redis address invalid: %w", err)
		}
	}

	// Validate TLS
	if config.Server.TLS.SelfSigned && (config.Server.TLS.CertFile != "" || config.Server.TLS.KeyFile != "") {
		LogWarn("TLS: Self-signed certificate enabled, ignoring cert and key files")
	}

	if !config.Server.TLS.SelfSigned && (config.Server.TLS.CertFile != "" || config.Server.TLS.KeyFile != "") {
		if config.Server.TLS.CertFile == "" || config.Server.TLS.KeyFile == "" {
			return errors.New("cert and key files must be configured together")
		}
		if !isValidFilePath(config.Server.TLS.CertFile) {
			return fmt.Errorf("cert file not found: %s", config.Server.TLS.CertFile)
		}
		if !isValidFilePath(config.Server.TLS.KeyFile) {
			return fmt.Errorf("key file not found: %s", config.Server.TLS.KeyFile)
		}
		if _, err := tls.LoadX509KeyPair(config.Server.TLS.CertFile, config.Server.TLS.KeyFile); err != nil {
			return fmt.Errorf("load certificate: %w", err)
		}
	}

	return nil
}

func (cm *ConfigManager) getDefaultConfig() *ServerConfig {
	config := &ServerConfig{}
	config.Server.Port = DefaultDNSPort
	config.Server.LogLevel = DefaultLogLevel
	config.Server.DefaultECS = "auto"
	config.Server.DDR.Domain = "dns.example.com"
	config.Server.DDR.IPv4 = "127.0.0.1"
	config.Server.DDR.IPv6 = "::1"
	config.Server.TLS.Port = DefaultTLSPort
	config.Server.TLS.HTTPS.Port = DefaultHTTPSPort
	config.Server.TLS.HTTPS.Endpoint = DefaultQueryPath
	config.Server.Features.HijackProtection = true
	config.Redis.KeyPrefix = "zjdns:"
	return config
}

func (cm *ConfigManager) shouldEnableDDR(config *ServerConfig) bool {
	return config.Server.DDR.Domain != "" &&
		(config.Server.DDR.IPv4 != "" || config.Server.DDR.IPv6 != "")
}

func (cm *ConfigManager) addDDRRecords(config *ServerConfig) {
	domain := strings.TrimSuffix(config.Server.DDR.Domain, ".")

	svcbRecords := []DNSRecordConfig{
		{Type: "SVCB", Content: "1 . alpn=h3,h2 port=" + config.Server.TLS.HTTPS.Port},
		{Type: "SVCB", Content: "2 . alpn=doq,dot port=" + config.Server.TLS.Port},
	}

	var additionalRecords []DNSRecordConfig
	var directQueryRecords []DNSRecordConfig
	nxdomainCode := dns.RcodeNameError

	if config.Server.DDR.IPv4 != "" {
		svcbRecords[0].Content += " ipv4hint=" + config.Server.DDR.IPv4
		svcbRecords[1].Content += " ipv4hint=" + config.Server.DDR.IPv4
		ipv4Record := DNSRecordConfig{Type: "A", Content: config.Server.DDR.IPv4}
		additionalRecords = append(additionalRecords, DNSRecordConfig{
			Name: domain, Type: ipv4Record.Type, Content: ipv4Record.Content,
		})
		directQueryRecords = append(directQueryRecords, ipv4Record)
	} else {
		config.Rewrite = append(config.Rewrite, RewriteRule{
			Name:    domain,
			Records: []DNSRecordConfig{{Type: "A", ResponseCode: &nxdomainCode}},
		})
	}

	if config.Server.DDR.IPv6 != "" {
		svcbRecords[0].Content += " ipv6hint=" + config.Server.DDR.IPv6
		svcbRecords[1].Content += " ipv6hint=" + config.Server.DDR.IPv6
		ipv6Record := DNSRecordConfig{Type: "AAAA", Content: config.Server.DDR.IPv6}
		additionalRecords = append(additionalRecords, DNSRecordConfig{
			Name: domain, Type: ipv6Record.Type, Content: ipv6Record.Content,
		})
		directQueryRecords = append(directQueryRecords, ipv6Record)
	} else {
		config.Rewrite = append(config.Rewrite, RewriteRule{
			Name:    domain,
			Records: []DNSRecordConfig{{Type: "AAAA", ResponseCode: &nxdomainCode}},
		})
	}

	if config.Server.DDR.IPv4 != "" || config.Server.DDR.IPv6 != "" {
		ddrRuleNames := []string{"_dns.resolver.arpa", "_dns." + domain}
		if config.Server.Port != "" && config.Server.Port != DefaultDNSPort {
			ddrRuleNames = append(ddrRuleNames, "_"+config.Server.Port+"._dns."+domain)
		}

		for _, ruleName := range ddrRuleNames {
			config.Rewrite = append(config.Rewrite, RewriteRule{
				Name:       ruleName,
				Records:    svcbRecords,
				Additional: additionalRecords,
			})
		}

		if len(directQueryRecords) > 0 {
			config.Rewrite = append(config.Rewrite, RewriteRule{
				Name:    domain,
				Records: directQueryRecords,
			})
		}
	}
}

func GenerateExampleConfig() string {
	cm := &ConfigManager{}
	config := cm.getDefaultConfig()

	config.Server.Pprof = DefaultPprofPort
	config.Server.LogLevel = DefaultLogLevel
	config.Server.DefaultECS = "auto"
	config.Redis.Address = "127.0.0.1:6379"
	config.Server.TLS.CertFile = "/path/to/cert.pem"
	config.Server.TLS.KeyFile = "/path/to/key.pem"

	config.CIDR = []CIDRConfig{
		{File: "whitelist.txt", Tag: "file"},
		{Rules: []string{"192.168.0.0/16", "10.0.0.0/8", "2001:db8::/32"}, Tag: "rules"},
		{File: "blacklist.txt", Rules: []string{"127.0.0.1/32"}, Tag: "mixed"},
	}

	config.Upstream = []UpstreamServer{
		{Address: "223.5.5.5:53", Protocol: "tcp"},
		{Address: "223.6.6.6:53", Protocol: "udp"},
		{Address: "223.5.5.5:853", Protocol: "tls", ServerName: "dns.alidns.com"},
		{Address: "223.6.6.6:853", Protocol: "quic", ServerName: "dns.alidns.com", SkipTLSVerify: true},
		{Address: "https://223.5.5.5:443/dns-query", Protocol: "https", ServerName: "dns.alidns.com", Match: []string{"mixed"}},
		{Address: "https://223.6.6.6:443/dns-query", Protocol: "http3", ServerName: "dns.alidns.com", Match: []string{"!mixed"}},
		{Address: RecursiveIndicator},
	}

	config.Rewrite = []RewriteRule{
		{Name: "blocked.example.com", Records: []DNSRecordConfig{{Type: "A", Content: "127.0.0.1", TTL: DefaultCacheTTL}}},
		{Name: "ipv6.blocked.example.com", Records: []DNSRecordConfig{{Type: "AAAA", Content: "::1", TTL: DefaultCacheTTL}}},
	}

	config.SpeedTest = []SpeedTestMethod{
		{Type: "icmp", Timeout: int(DefaultSpeedTimeout.Milliseconds())},
		{Type: "tcp", Port: "443", Timeout: int(DefaultSpeedTimeout.Milliseconds())},
		{Type: "tcp", Port: "80", Timeout: int(DefaultSpeedTimeout.Milliseconds())},
		{Type: "udp", Port: "53", Timeout: int(DefaultSpeedTimeout.Milliseconds())},
	}

	data, _ := json.MarshalIndent(config, "", "  ")
	return string(data)
}

// =============================================================================
// Cache Types
// =============================================================================

type CacheEntry struct {
	Answer          []*CompactRecord `json:"answer"`
	Authority       []*CompactRecord `json:"authority"`
	Additional      []*CompactRecord `json:"additional"`
	ECSAddress      string           `json:"ecs_address,omitempty"`
	Timestamp       int64            `json:"timestamp"`
	AccessTime      int64            `json:"access_time"`
	RefreshTime     int64            `json:"refresh_time,omitempty"`
	TTL             int              `json:"ttl"`
	OriginalTTL     int              `json:"original_ttl"`
	ECSFamily       uint16           `json:"ecs_family,omitempty"`
	ECSSourcePrefix uint8            `json:"ecs_source_prefix,omitempty"`
	ECSScopePrefix  uint8            `json:"ecs_scope_prefix,omitempty"`
	Validated       bool             `json:"validated"`
}

type CompactRecord struct {
	Text    string `json:"text"`
	OrigTTL uint32 `json:"orig_ttl"`
	Type    uint16 `json:"type"`
}

func (c *CacheEntry) IsExpired() bool {
	return c != nil && time.Now().Unix()-c.Timestamp > int64(c.TTL)
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
	return c.IsExpired() && (now-c.Timestamp) > refreshInterval && (now-c.RefreshTime) > refreshInterval
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
	// Return short TTL for stale data
	staleElapsed := elapsed - int64(c.TTL)
	staleCycle := staleElapsed % int64(StaleTTL)
	staleTTLRemaining := int64(StaleTTL) - staleCycle
	if staleTTLRemaining <= 0 {
		staleTTLRemaining = int64(StaleTTL)
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

type CacheManager interface {
	Get(key string) (*CacheEntry, bool, bool)
	Set(key string, answer, authority, additional []dns.RR, validated bool, ecs *ECSOption)
	Closeable
}

type NullCache struct{}

func NewNullCache() *NullCache {
	LogInfo("CACHE: No cache mode (stale cache disabled)")
	return &NullCache{}
}

func (nc *NullCache) Get(key string) (*CacheEntry, bool, bool) { return nil, false, false }
func (nc *NullCache) Set(key string, answer, authority, additional []dns.RR, validated bool, ecs *ECSOption) {
}
func (nc *NullCache) Close() error { return nil }

type RedisCache struct {
	client         *redis.Client
	config         *ServerConfig
	ctx            context.Context
	cancel         context.CancelFunc
	taskMgr        *TaskManager
	server         *DNSServer
	refreshTracker *RefreshTracker
	closed         int32
}

// RefreshTracker 用于防止重复的缓存刷新任务
type RefreshTracker struct {
	mu      sync.Mutex
	pending map[string]time.Time
}

func NewRefreshTracker() *RefreshTracker {
	return &RefreshTracker{
		pending: make(map[string]time.Time),
	}
}

func (rt *RefreshTracker) TryStartRefresh(key string, ttl time.Duration) bool {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	if lastRefresh, exists := rt.pending[key]; exists {
		if time.Since(lastRefresh) < ttl {
			return false // 最近已经刷新过
		}
	}

	rt.pending[key] = time.Now()
	return true
}

func (rt *RefreshTracker) EndRefresh(key string) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	delete(rt.pending, key)
}

func NewRedisCache(config *ServerConfig, server *DNSServer) (*RedisCache, error) {
	logging.Disable()

	rdb := redis.NewClient(&redis.Options{
		Addr:         config.Redis.Address,
		Password:     config.Redis.Password,
		DB:           config.Redis.Database,
		PoolSize:     RedisPoolSize,
		MinIdleConns: RedisMinIdle,
		MaxRetries:   RedisMaxRetries,
		PoolTimeout:  RedisPoolTimeout,
		ReadTimeout:  RedisReadTimeout,
		WriteTimeout: RedisWriteTimeout,
		DialTimeout:  RedisDialTimeout,
	})

	ctx, cancel := context.WithTimeout(context.Background(), ConnTimeout)
	defer cancel()

	if err := rdb.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("redis connection: %w", err)
	}

	cacheCtx, cacheCancel := context.WithCancel(context.Background())
	cache := &RedisCache{
		client:         rdb,
		config:         config,
		ctx:            cacheCtx,
		cancel:         cacheCancel,
		taskMgr:        NewTaskManager(MaxWorkerCount),
		server:         server,
		refreshTracker: NewRefreshTracker(),
	}

	LogInfo("CACHE: Redis cache initialized (stale cache enabled)")
	return cache, nil
}

func (rc *RedisCache) Get(key string) (*CacheEntry, bool, bool) {
	defer handlePanic("Redis cache get")

	if atomic.LoadInt32(&rc.closed) != 0 {
		LogDebug("CACHE: Redis cache is closed")
		return nil, false, false
	}

	LogDebug("CACHE: Getting key: %s", key)
	data, err := rc.client.Get(rc.ctx, key).Result()
	if err != nil {
		LogDebug("CACHE: Cache miss for key: %s", key)
		return nil, false, false
	}

	var entry CacheEntry
	if err := json.Unmarshal([]byte(data), &entry); err != nil {
		LogDebug("CACHE: Corrupted cache entry for key: %s, removing", key)
		go func() {
			defer handlePanic("Clean corrupted cache")
			rc.client.Del(context.Background(), key)
		}()
		return nil, false, false
	}

	isExpired := entry.IsExpired()
	LogDebug("CACHE: Cache hit for key: %s (expired: %v, TTL: %d, age: %ds)",
		key, isExpired, entry.TTL, time.Now().Unix()-entry.Timestamp)

	// Update access time asynchronously
	entry.AccessTime = time.Now().Unix()
	go func() {
		defer handlePanic("Update access time")
		if atomic.LoadInt32(&rc.closed) == 0 {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			data, _ := json.Marshal(entry)
			rc.client.Set(ctx, key, data, redis.KeepTTL)
		}
	}()

	return &entry, true, isExpired
}

func (rc *RedisCache) Set(key string, answer, authority, additional []dns.RR, validated bool, ecs *ECSOption) {
	defer handlePanic("Redis cache set")

	if atomic.LoadInt32(&rc.closed) != 0 {
		LogDebug("CACHE: Redis cache is closed, not setting key: %s", key)
		return
	}

	allRRs := make([]dns.RR, 0, len(answer)+len(authority)+len(additional))
	allRRs = append(append(append(allRRs, answer...), authority...), additional...)
	cacheTTL := calculateTTL(allRRs)
	now := time.Now().Unix()

	LogDebug("CACHE: Setting key: %s (TTL: %d, answer: %d, authority: %d, additional: %d, validated: %v)",
		key, cacheTTL, len(answer), len(authority), len(additional), validated)

	entry := &CacheEntry{
		Answer:      compactRecords(answer),
		Authority:   compactRecords(authority),
		Additional:  compactRecords(additional),
		TTL:         cacheTTL,
		OriginalTTL: cacheTTL,
		Timestamp:   now,
		Validated:   validated,
		AccessTime:  now,
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

	ctx, cancel := context.WithTimeout(rc.ctx, RedisWriteTimeout)
	defer cancel()

	// Cache TTL = original TTL + stale max-age
	expiration := time.Duration(cacheTTL)*time.Second + time.Duration(StaleMaxAge)*time.Second
	rc.client.Set(ctx, key, data, expiration)
}

func (rc *RedisCache) Close() error {
	if !atomic.CompareAndSwapInt32(&rc.closed, 0, 1) {
		return nil
	}

	LogInfo("CACHE: Shutting down Redis cache...")

	if err := rc.taskMgr.Shutdown(ShutdownTimeout); err != nil {
		LogError("TASK: Task manager shutdown failed: %v", err)
	}

	rc.cancel()

	if err := rc.client.Close(); err != nil {
		LogError("CACHE: Redis client shutdown failed: %v", err)
	}

	LogInfo("CACHE: Redis cache shut down")
	return nil
}

// =============================================================================
// CIDR Management
// =============================================================================

type CIDRManager struct {
	rules map[string]*CIDRRule
	mu    sync.RWMutex
}

type CIDRRule struct {
	tag  string
	nets []*net.IPNet
}

func NewCIDRManager(configs []CIDRConfig) (*CIDRManager, error) {
	cm := &CIDRManager{rules: make(map[string]*CIDRRule)}

	for _, config := range configs {
		if config.Tag == "" {
			return nil, errors.New("CIDR tag cannot be empty")
		}
		if _, exists := cm.rules[config.Tag]; exists {
			return nil, fmt.Errorf("duplicate CIDR tag: %s", config.Tag)
		}

		rule, err := cm.loadCIDRConfig(config)
		if err != nil {
			return nil, fmt.Errorf("load CIDR config for tag '%s': %w", config.Tag, err)
		}
		cm.rules[config.Tag] = rule

		sourceInfo := ""
		if config.File != "" && len(config.Rules) > 0 {
			sourceInfo = fmt.Sprintf("%s + %d inline rules", config.File, len(config.Rules))
		} else if config.File != "" {
			sourceInfo = config.File
		} else {
			sourceInfo = fmt.Sprintf("%d inline rules", len(config.Rules))
		}
		LogInfo("CIDR: loaded: tag=%s, source=%s, total=%d", config.Tag, sourceInfo, len(rule.nets))
	}

	return cm, nil
}

func (cm *CIDRManager) loadCIDRConfig(config CIDRConfig) (*CIDRRule, error) {
	rule := &CIDRRule{tag: config.Tag, nets: make([]*net.IPNet, 0)}
	validCount := 0

	// Load inline rules
	for i, cidr := range config.Rules {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" || strings.HasPrefix(cidr, "#") {
			continue
		}
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			LogWarn("CIDR: Invalid CIDR in rules[%d] for tag '%s': %s - %v", i, config.Tag, cidr, err)
			continue
		}
		rule.nets = append(rule.nets, ipNet)
		validCount++
	}

	// Load from file
	if config.File != "" {
		if !isValidFilePath(config.File) {
			return nil, fmt.Errorf("invalid file path: %s", config.File)
		}
		f, err := os.Open(config.File)
		if err != nil {
			return nil, fmt.Errorf("open CIDR file: %w", err)
		}
		defer func() { _ = f.Close() }()

		scanner := bufio.NewScanner(f)
		lineNum := 0
		for scanner.Scan() {
			lineNum++
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			_, ipNet, err := net.ParseCIDR(line)
			if err != nil {
				LogWarn("CIDR: Invalid CIDR at %s:%d: %s - %v", config.File, lineNum, line, err)
				continue
			}
			rule.nets = append(rule.nets, ipNet)
			validCount++
		}
		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("scan CIDR file: %w", err)
		}
	}

	if validCount == 0 {
		return nil, fmt.Errorf("no valid CIDR entries for tag '%s'", config.Tag)
	}

	return rule, nil
}

func (cm *CIDRManager) MatchIP(ip net.IP, matchTag string) (matched bool, exists bool) {
	if cm == nil || matchTag == "" {
		return true, true
	}

	negate := strings.HasPrefix(matchTag, "!")
	tag := strings.TrimPrefix(matchTag, "!")

	cm.mu.RLock()
	rule, exists := cm.rules[tag]
	cm.mu.RUnlock()

	if !exists {
		return false, false
	}

	inList := rule.contains(ip)
	if negate {
		return !inList, true
	}
	return inList, true
}

func (r *CIDRRule) contains(ip net.IP) bool {
	if r == nil || ip == nil {
		return false
	}
	for _, ipNet := range r.nets {
		if ipNet.Contains(ip) {
			return true
		}
	}
	return false
}

// =============================================================================
// EDNS Management
// =============================================================================

type ECSOption struct {
	Address      net.IP
	Family       uint16
	SourcePrefix uint8
	ScopePrefix  uint8
}

type EDNSManager struct {
	defaultECS *ECSOption
	detector   *IPDetector
}

func NewEDNSManager(defaultSubnet string) (*EDNSManager, error) {
	manager := &EDNSManager{
		detector: newIPDetector(),
	}

	if defaultSubnet != "" {
		ecs, err := manager.parseECSConfig(defaultSubnet)
		if err != nil {
			return nil, fmt.Errorf("parse ECS config: %w", err)
		}
		manager.defaultECS = ecs
		if ecs != nil {
			LogInfo("EDNS: Default ECS: %s/%d", ecs.Address, ecs.SourcePrefix)
		}
	}

	return manager, nil
}

func (em *EDNSManager) GetDefaultECS() *ECSOption {
	if em == nil {
		return nil
	}
	return em.defaultECS
}

func (em *EDNSManager) ParseFromDNS(msg *dns.Msg) *ECSOption {
	if em == nil || msg == nil || msg.Extra == nil {
		return nil
	}

	opt := msg.IsEdns0()
	if opt == nil {
		return nil
	}

	for _, option := range opt.Option {
		if subnet, ok := option.(*dns.EDNS0_SUBNET); ok {
			ecs := &ECSOption{
				Family:       subnet.Family,
				SourcePrefix: subnet.SourceNetmask,
				ScopePrefix:  subnet.SourceScope,
				Address:      subnet.Address,
			}
			LogDebug("EDNS: Parsed ECS option: %s/%d", ecs.Address.String(), ecs.SourcePrefix)
			return ecs
		}
	}
	return nil
}

func (em *EDNSManager) AddToMessage(msg *dns.Msg, ecs *ECSOption, clientRequestedDNSSEC bool, isSecureConnection bool) {
	if em == nil || msg == nil {
		return
	}

	LogDebug("EDNS: Adding EDNS to message (DNSSEC: %v, ECS: %v)", clientRequestedDNSSEC, ecs != nil)

	// Initialize message sections
	if msg.Question == nil {
		msg.Question = []dns.Question{}
	}
	if msg.Answer == nil {
		msg.Answer = []dns.RR{}
	}
	if msg.Ns == nil {
		msg.Ns = []dns.RR{}
	}
	if msg.Extra == nil {
		msg.Extra = []dns.RR{}
	}

	// Remove existing OPT records
	cleanExtra := make([]dns.RR, 0, len(msg.Extra))
	for _, rr := range msg.Extra {
		if rr != nil && rr.Header().Rrtype != dns.TypeOPT {
			cleanExtra = append(cleanExtra, rr)
		}
	}
	msg.Extra = cleanExtra

	// Create OPT record
	opt := &dns.OPT{
		Hdr: dns.RR_Header{
			Name:   ".",
			Rrtype: dns.TypeOPT,
			Class:  UDPBufferSize,
		},
	}

	// DNSSEC is always enabled
	opt.SetDo()

	var options []dns.EDNS0

	// Add ECS
	if ecs != nil {
		options = append(options, &dns.EDNS0_SUBNET{
			Code:          dns.EDNS0SUBNET,
			Family:        ecs.Family,
			SourceNetmask: ecs.SourcePrefix,
			SourceScope:   DefaultECSScope,
			Address:       ecs.Address,
		})
	}

	// Add padding for secure connections
	if isSecureConnection {
		LogDebug("PADDING: Adding padding for secure connection")
		opt.Option = options
		msg.Extra = append(msg.Extra, opt)
		if wireData, err := msg.Pack(); err == nil {
			currentSize := len(wireData)
			LogDebug("PADDING: Current message size: %d bytes", currentSize)
			if currentSize < PaddingBlockSize {
				paddingDataSize := PaddingBlockSize - currentSize - 4
				LogDebug("PADDING: Adding %d bytes of padding (target: %d bytes)",
					paddingDataSize, PaddingBlockSize)
				if paddingDataSize > 0 {
					options = append(options, &dns.EDNS0_PADDING{
						Padding: make([]byte, paddingDataSize),
					})
					LogDebug("PADDING: Padding added successfully")
				} else {
					LogDebug("PADDING: No padding needed (size already optimal)")
				}
			} else {
				LogDebug("PADDING: Message size %d exceeds padding target %d, no padding",
					currentSize, PaddingBlockSize)
			}
		} else {
			LogDebug("PADDING: Failed to pack message for padding calculation: %v", err)
		}
		msg.Extra = msg.Extra[:len(msg.Extra)-1]
	} else {
		LogDebug("PADDING: Connection is not secure, skipping padding")
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
			return nil, fmt.Errorf("parse CIDR: %w", err)
		}
		prefix, _ := ipNet.Mask.Size()
		family := uint16(1)
		if ipNet.IP.To4() == nil {
			family = 2
		}
		return &ECSOption{
			Family:       family,
			SourcePrefix: uint8(prefix),
			ScopePrefix:  DefaultECSScope,
			Address:      ipNet.IP,
		}, nil
	}
}

func (em *EDNSManager) detectPublicIP(forceIPv6, allowFallback bool) (*ECSOption, error) {
	var ecs *ECSOption
	if ip := em.detector.detectPublicIP(forceIPv6); ip != nil {
		family := uint16(1)
		prefix := uint8(DefaultECSv4Len)
		if forceIPv6 {
			family = 2
			prefix = DefaultECSv6Len
		}
		ecs = &ECSOption{
			Family:       family,
			SourcePrefix: prefix,
			ScopePrefix:  DefaultECSScope,
			Address:      ip,
		}
	}

	if ecs == nil && allowFallback && !forceIPv6 {
		if ip := em.detector.detectPublicIP(true); ip != nil {
			ecs = &ECSOption{
				Family:       2,
				SourcePrefix: DefaultECSv6Len,
				ScopePrefix:  DefaultECSScope,
				Address:      ip,
			}
		}
	}

	return ecs, nil
}

type IPDetector struct {
	httpClient *http.Client
}

func newIPDetector() *IPDetector {
	return &IPDetector{
		httpClient: &http.Client{Timeout: HTTPClientTimeout},
	}
}

func (d *IPDetector) detectPublicIP(forceIPv6 bool) net.IP {
	if d == nil {
		return nil
	}

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialer := &net.Dialer{Timeout: PublicIPTimeout}
			if forceIPv6 {
				return dialer.DialContext(ctx, "tcp6", addr)
			}
			return dialer.DialContext(ctx, "tcp4", addr)
		},
		TLSHandshakeTimeout: TLSHandshakeTimeout,
	}

	client := &http.Client{Timeout: HTTPClientTimeout, Transport: transport}
	defer transport.CloseIdleConnections()

	resp, err := client.Get("https://api.cloudflare.com/cdn-cgi/trace")
	if err != nil {
		return nil
	}
	defer func() { _ = resp.Body.Close() }()

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

// =============================================================================
// Rewrite Management
// =============================================================================

type RewriteManager struct {
	rules []RewriteRule
	mu    sync.RWMutex
}

type DNSRewriteResult struct {
	Domain        string
	ShouldRewrite bool
	ResponseCode  int
	Records       []dns.RR
	Additional    []dns.RR
}

func NewRewriteManager() *RewriteManager {
	return &RewriteManager{rules: make([]RewriteRule, 0, 32)}
}

func (rm *RewriteManager) LoadRules(rules []RewriteRule) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	validRules := make([]RewriteRule, 0, len(rules))
	for _, rule := range rules {
		if len(rule.Name) <= MaxDomainLength {
			validRules = append(validRules, rule)
		}
	}

	rm.rules = validRules
	LogInfo("REWRITE: DNS rewriter loaded: %d rules", len(validRules))
	return nil
}

func (rm *RewriteManager) RewriteWithDetails(domain string, qtype uint16) DNSRewriteResult {
	result := DNSRewriteResult{
		Domain:        domain,
		ResponseCode:  dns.RcodeSuccess,
		ShouldRewrite: false,
	}

	if !rm.hasRules() || len(domain) > MaxDomainLength {
		return result
	}

	LogDebug("REWRITE: Checking domain %s for rewrite rules", domain)

	rm.mu.RLock()
	defer rm.mu.RUnlock()

	domain = normalizeDomain(domain)

	for i := range rm.rules {
		rule := &rm.rules[i]
		if domain != normalizeDomain(rule.Name) {
			continue
		}

		LogDebug("REWRITE: Found matching rule for domain %s", domain)
		if rule.ResponseCode != nil {
			result.ResponseCode = *rule.ResponseCode
			result.ShouldRewrite = true
			LogDebug("REWRITE: Applied response code rewrite for %s: %d", domain, *rule.ResponseCode)
			return result
		}

		if len(rule.Records) > 0 || len(rule.Additional) > 0 {
			result.Records = make([]dns.RR, 0)
			result.Additional = make([]dns.RR, 0)

			for _, record := range rule.Records {
				recordType := dns.StringToType[record.Type]
				if record.ResponseCode != nil {
					if record.Type == "" || recordType == qtype {
						result.ResponseCode = *record.ResponseCode
						result.ShouldRewrite = true
						result.Records = nil
						result.Additional = nil
						return result
					}
					continue
				}
				if record.Type != "" && recordType != qtype {
					continue
				}
				if rr := rm.buildDNSRecord(domain, record); rr != nil {
					result.Records = append(result.Records, rr)
				}
			}

			for _, record := range rule.Additional {
				if rr := rm.buildDNSRecord(domain, record); rr != nil {
					result.Additional = append(result.Additional, rr)
				}
			}

			result.ShouldRewrite = true
			LogDebug("REWRITE: Applied record rewrite for %s with %d records and %d additional", domain, len(result.Records), len(result.Additional))
			return result
		}
	}

	return result
}

func (rm *RewriteManager) buildDNSRecord(domain string, record DNSRecordConfig) dns.RR {
	ttl := record.TTL
	if ttl == 0 {
		ttl = DefaultCacheTTL
	}

	name := dns.Fqdn(domain)
	if record.Name != "" {
		name = dns.Fqdn(record.Name)
	}

	rrStr := fmt.Sprintf("%s %d IN %s %s", name, ttl, record.Type, record.Content)
	if rr, err := dns.NewRR(rrStr); err == nil {
		return rr
	}

	rrType, exists := dns.StringToType[record.Type]
	if !exists {
		rrType = 0
	}

	return &dns.RFC3597{
		Hdr:   dns.RR_Header{Name: name, Rrtype: rrType, Class: dns.ClassINET, Ttl: ttl},
		Rdata: record.Content,
	}
}

func (rm *RewriteManager) hasRules() bool {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	return len(rm.rules) > 0
}

// =============================================================================
// SpeedTest Management
// =============================================================================

type SpeedTestManager struct {
	timeout     time.Duration
	concurrency int
	redis       *redis.Client
	cacheTTL    time.Duration
	keyPrefix   string
	icmpConn4   *icmp.PacketConn
	icmpConn6   *icmp.PacketConn
	methods     []SpeedTestMethod
}

type SpeedResult struct {
	IP        string        `json:"ip"`
	Latency   time.Duration `json:"latency"`
	Reachable bool          `json:"reachable"`
	Timestamp time.Time     `json:"timestamp"`
}

func NewSpeedTestManager(config ServerConfig, redisClient *redis.Client, keyPrefix string) *SpeedTestManager {
	if keyPrefix == "" {
		keyPrefix = config.Redis.KeyPrefix + RedisPrefixSpeedTestDomain
	}

	st := &SpeedTestManager{
		timeout:     DefaultSpeedTimeout,
		concurrency: DefaultSpeedConcurrency,
		redis:       redisClient,
		cacheTTL:    DefaultSpeedCacheTTL,
		keyPrefix:   keyPrefix,
		methods:     config.SpeedTest,
	}
	st.initICMP()
	return st
}

func (st *SpeedTestManager) initICMP() {
	if conn4, err := icmp.ListenPacket("ip4:icmp", ""); err == nil {
		st.icmpConn4 = conn4
	}
	if conn6, err := icmp.ListenPacket("ip6:ipv6-icmp", ""); err == nil {
		st.icmpConn6 = conn6
	}
}

func (st *SpeedTestManager) Close() error {
	if st.icmpConn4 != nil {
		_ = st.icmpConn4.Close()
	}
	if st.icmpConn6 != nil {
		_ = st.icmpConn6.Close()
	}
	return nil
}

func (st *SpeedTestManager) performSpeedTestAndSort(response *dns.Msg) *dns.Msg {
	if response == nil {
		return response
	}

	LogDebug("SPEEDTEST: Starting speed test and sort for %d records", len(response.Answer))
	var aRecords []*dns.A
	var aaaaRecords []*dns.AAAA
	var cnameRecords []dns.RR
	var otherRecords []dns.RR

	for _, answer := range response.Answer {
		switch record := answer.(type) {
		case *dns.A:
			aRecords = append(aRecords, record)
		case *dns.AAAA:
			aaaaRecords = append(aaaaRecords, record)
		case *dns.CNAME:
			cnameRecords = append(cnameRecords, record)
		default:
			otherRecords = append(otherRecords, answer)
		}
	}

	if len(aRecords) > 1 {
		aRecords = st.sortARecords(aRecords)
	}
	if len(aaaaRecords) > 1 {
		aaaaRecords = st.sortAAAARecords(aaaaRecords)
	}

	response.Answer = append(append(append(cnameRecords, toRRSlice(aRecords)...), toRRSlice(aaaaRecords)...), otherRecords...)
	return response
}

func (st *SpeedTestManager) sortARecords(records []*dns.A) []*dns.A {
	if len(records) <= 1 {
		return records
	}

	ips := make([]string, len(records))
	for i, record := range records {
		ips[i] = record.A.String()
	}

	results := st.speedTest(ips)

	sort.Slice(records, func(i, j int) bool {
		ipI, ipJ := records[i].A.String(), records[j].A.String()
		resultI, okI := results[ipI]
		resultJ, okJ := results[ipJ]
		if !okI || !okJ {
			return i < j
		}
		if resultI.Reachable != resultJ.Reachable {
			return resultI.Reachable
		}
		return resultI.Latency < resultJ.Latency
	})

	return records
}

func (st *SpeedTestManager) sortAAAARecords(records []*dns.AAAA) []*dns.AAAA {
	if len(records) <= 1 {
		return records
	}

	ips := make([]string, len(records))
	for i, record := range records {
		ips[i] = record.AAAA.String()
	}

	results := st.speedTest(ips)

	sort.Slice(records, func(i, j int) bool {
		ipI, ipJ := records[i].AAAA.String(), records[j].AAAA.String()
		resultI, okI := results[ipI]
		resultJ, okJ := results[ipJ]
		if !okI || !okJ {
			return i < j
		}
		if resultI.Reachable != resultJ.Reachable {
			return resultI.Reachable
		}
		return resultI.Latency < resultJ.Latency
	})

	return records
}

func (st *SpeedTestManager) speedTest(ips []string) map[string]*SpeedResult {
	results := make(map[string]*SpeedResult)
	remainingIPs := []string{}

	LogDebug("SPEEDTEST: Testing %d IPs for speed", len(ips))

	// Try to get cached results from Redis
	if st.redis != nil {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
		defer cancel()

		for _, ip := range ips {
			key := st.keyPrefix + ip
			data, err := st.redis.Get(ctx, key).Result()
			if err == nil {
				var result SpeedResult
				if json.Unmarshal([]byte(data), &result) == nil {
					// Check if cache is still valid
					if time.Since(result.Timestamp) < st.cacheTTL {
						results[ip] = &result
						LogDebug("SPEEDTEST: Cache hit for IP %s (latency: %v)", ip, result.Latency)
						continue
					}
				}
			}
			remainingIPs = append(remainingIPs, ip)
		}
	} else {
		remainingIPs = ips
	}

	LogDebug("SPEEDTEST: Found %d cached results, testing %d remaining IPs",
		len(results), len(remainingIPs))

	if len(remainingIPs) == 0 {
		return results
	}

	// Test remaining IPs
	newResults := st.performSpeedTest(remainingIPs)

	// Store new results in Redis
	if st.redis != nil {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
		defer cancel()

		for ip, result := range newResults {
			key := st.keyPrefix + ip
			data, err := json.Marshal(result)
			if err == nil {
				st.redis.Set(ctx, key, data, st.cacheTTL)
				LogDebug("SPEEDTEST: Cached result for IP %s (latency: %v)", ip, result.Latency)
			}
		}
	}

	// Merge results
	for ip, result := range newResults {
		results[ip] = result
	}

	return results
}

func (st *SpeedTestManager) performSpeedTest(ips []string) map[string]*SpeedResult {
	LogDebug("SPEEDTEST: Starting concurrent speed test for %d IPs with concurrency %d", len(ips), st.concurrency)
	semaphore := make(chan struct{}, st.concurrency)
	resultChan := make(chan *SpeedResult, len(ips))

	var wg sync.WaitGroup
	for _, ip := range ips {
		wg.Add(1)
		go func(testIP string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()
			if result := st.testSingleIP(testIP); result != nil {
				select {
				case resultChan <- result:
				default:
				}
			}
		}(ip)
	}

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	results := make(map[string]*SpeedResult)
	for result := range resultChan {
		if result != nil {
			results[result.IP] = result
		}
	}

	return results
}

func (st *SpeedTestManager) testSingleIP(ip string) *SpeedResult {
	LogDebug("SPEEDTEST: Testing IP %s", ip)
	result := &SpeedResult{IP: ip, Timestamp: time.Now()}

	for _, method := range st.methods {
		var latency time.Duration
		switch method.Type {
		case "icmp":
			latency = st.pingWithICMP(ip, time.Duration(method.Timeout)*time.Millisecond)
		case "tcp":
			latency = st.pingWithTCP(ip, method.Port, time.Duration(method.Timeout)*time.Millisecond)
		case "udp":
			latency = st.pingWithUDP(ip, method.Port, time.Duration(method.Timeout)*time.Millisecond)
		default:
			continue
		}

		if latency >= 0 {
			result.Reachable = true
			result.Latency = latency
			LogDebug("SPEEDTEST: IP %s reachable with latency %v", ip, latency)
			return result
		}
	}

	result.Reachable = false
	result.Latency = st.timeout
	LogDebug("SPEEDTEST: IP %s unreachable", ip)
	return result
}

func (st *SpeedTestManager) pingWithICMP(ip string, timeout time.Duration) time.Duration {
	dst, err := net.ResolveIPAddr("ip", ip)
	if err != nil {
		return -1
	}

	var conn *icmp.PacketConn
	var icmpType icmp.Type
	var protocol int

	if dst.IP.To4() != nil {
		conn = st.icmpConn4
		icmpType = ipv4.ICMPTypeEcho
		protocol = 1
	} else {
		conn = st.icmpConn6
		icmpType = ipv6.ICMPTypeEchoRequest
		protocol = 58
	}

	if conn == nil {
		return -1
	}

	wm := icmp.Message{
		Type: icmpType,
		Code: 0,
		Body: &icmp.Echo{ID: os.Getpid() & 0xffff, Seq: 1, Data: []byte("ZJDNS")},
	}

	wb, err := wm.Marshal(nil)
	if err != nil {
		return -1
	}

	_ = conn.SetWriteDeadline(time.Now().Add(timeout))
	start := time.Now()

	if _, err := conn.WriteTo(wb, dst); err != nil {
		return -1
	}

	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	rb := make([]byte, 1500)
	n, _, err := conn.ReadFrom(rb)
	if err != nil {
		return -1
	}

	rm, err := icmp.ParseMessage(protocol, rb[:n])
	if err != nil {
		return -1
	}

	switch rm.Type {
	case ipv4.ICMPTypeEchoReply, ipv6.ICMPTypeEchoReply:
		return time.Since(start)
	default:
		return -1
	}
}

func (st *SpeedTestManager) pingWithTCP(ip, port string, timeout time.Duration) time.Duration {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	start := time.Now()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(ip, port))
	if err != nil {
		return -1
	}
	latency := time.Since(start)
	_ = conn.Close()
	return latency
}

func (st *SpeedTestManager) pingWithUDP(ip, port string, timeout time.Duration) time.Duration {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	start := time.Now()
	conn, err := (&net.Dialer{}).DialContext(ctx, "udp", net.JoinHostPort(ip, port))
	if err != nil {
		return -1
	}

	if _, err := conn.Write([]byte{}); err != nil {
		_ = conn.Close()
		return -1
	}

	latency := time.Since(start)
	_ = conn.Close()
	return latency
}

// =============================================================================
// Root Server Management
// =============================================================================

type RootServerManager struct {
	servers      []string
	speedTester  *SpeedTestManager
	sorted       []RootServerWithLatency
	lastSortTime time.Time
	mu           sync.RWMutex
	needsSpeed   bool
}

type RootServerWithLatency struct {
	Server    string        `json:"server"`
	Latency   time.Duration `json:"latency"`
	Reachable bool          `json:"reachable"`
}

func NewRootServerManager(config ServerConfig, redisClient *redis.Client) *RootServerManager {
	needsRecursive := len(config.Upstream) == 0
	if !needsRecursive {
		for _, upstream := range config.Upstream {
			if upstream.IsRecursive() {
				needsRecursive = true
				break
			}
		}
	}

	rsm := &RootServerManager{
		servers: []string{
			"198.41.0.4:53", "[2001:503:ba3e::2:30]:53",
			"170.247.170.2:53", "[2801:1b8:10::b]:53",
			"192.33.4.12:53", "[2001:500:2::c]:53",
			"199.7.91.13:53", "[2001:500:2d::d]:53",
			"192.203.230.10:53", "[2001:500:a8::e]:53",
			"192.5.5.241:53", "[2001:500:2f::f]:53",
			"192.112.36.4:53", "[2001:500:12::d0d]:53",
			"198.97.190.53:53", "[2001:500:1::53]:53",
			"192.36.148.17:53", "[2001:7fe::53]:53",
			"192.58.128.30:53", "[2001:503:c27::2:30]:53",
			"193.0.14.129:53", "[2001:7fd::1]:53",
			"199.7.83.42:53", "[2001:500:9f::42]:53",
			"202.12.27.33:53", "[2001:dc3::35]:53",
		},
		needsSpeed: needsRecursive,
	}

	rsm.sorted = make([]RootServerWithLatency, len(rsm.servers))
	for i, server := range rsm.servers {
		rsm.sorted[i] = RootServerWithLatency{
			Server:    server,
			Latency:   UnreachableLatency,
			Reachable: false,
		}
	}

	if needsRecursive {
		dnsSpeedTestConfig := config
		dnsSpeedTestConfig.SpeedTest = []SpeedTestMethod{
			{Type: "icmp", Timeout: int(DefaultSpeedTimeout.Milliseconds())},
			{Type: "tcp", Port: DefaultDNSPort, Timeout: int(DefaultSpeedTimeout.Milliseconds())},
			{Type: "udp", Port: DefaultDNSPort, Timeout: int(DefaultSpeedTimeout.Milliseconds())},
		}

		rootServerPrefix := config.Redis.KeyPrefix + RedisPrefixSpeedTestRoot
		rsm.speedTester = NewSpeedTestManager(dnsSpeedTestConfig, redisClient, rootServerPrefix)
		rsm.speedTester.cacheTTL = DefaultSpeedCacheTTL

		go rsm.sortServersBySpeed()
		LogInfo("SPEEDTEST: Root server speed testing enabled")
	} else {
		LogInfo("SPEEDTEST: Root server speed testing disabled (using upstream servers)")
	}

	return rsm
}

func (rsm *RootServerManager) GetOptimalRootServers() []RootServerWithLatency {
	rsm.mu.RLock()
	defer rsm.mu.RUnlock()
	result := make([]RootServerWithLatency, len(rsm.sorted))
	copy(result, rsm.sorted)
	return result
}

func (rsm *RootServerManager) sortServersBySpeed() {
	defer handlePanic("Root server speed sorting")

	if !rsm.needsSpeed || rsm.speedTester == nil {
		return
	}

	ips := extractIPsFromServers(rsm.servers)
	results := rsm.speedTester.speedTest(ips)
	sortedWithLatency := sortBySpeedResultWithLatency(rsm.servers, results)

	rsm.mu.Lock()
	rsm.sorted = sortedWithLatency
	rsm.lastSortTime = time.Now()
	rsm.mu.Unlock()
}

func (rsm *RootServerManager) StartPeriodicSorting(ctx context.Context) {
	if !rsm.needsSpeed {
		return
	}

	ticker := time.NewTicker(RootServerSortInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			rsm.sortServersBySpeed()
		case <-ctx.Done():
			return
		}
	}
}

// =============================================================================
// Security Management
// =============================================================================

type SecurityManager struct {
	tls    *TLSManager
	dnssec *DNSSECValidator
	hijack *HijackPrevention
}

func NewSecurityManager(config *ServerConfig, server *DNSServer) (*SecurityManager, error) {
	sm := &SecurityManager{
		dnssec: &DNSSECValidator{},
		hijack: &HijackPrevention{enabled: config.Server.Features.HijackProtection},
	}

	if config.Server.TLS.SelfSigned || (config.Server.TLS.CertFile != "" && config.Server.TLS.KeyFile != "") {
		tlsMgr, err := NewTLSManager(server, config)
		if err != nil {
			return nil, fmt.Errorf("create TLS manager: %w", err)
		}
		sm.tls = tlsMgr
	}

	return sm, nil
}

func (sm *SecurityManager) Shutdown(timeout time.Duration) error {
	if sm.tls != nil {
		return sm.tls.shutdown()
	}
	return nil
}

type DNSSECValidator struct{}

func (v *DNSSECValidator) ValidateResponse(response *dns.Msg, dnssecOK bool) bool {
	if !dnssecOK || response == nil {
		return false
	}
	if response.AuthenticatedData {
		return true
	}
	return v.hasDNSSECRecords(response)
}

func (v *DNSSECValidator) hasDNSSECRecords(response *dns.Msg) bool {
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

type HijackPrevention struct {
	enabled bool
}

func (hp *HijackPrevention) IsEnabled() bool {
	return hp.enabled
}

func (hp *HijackPrevention) CheckResponse(currentDomain, queryDomain string, response *dns.Msg) (bool, string) {
	if !hp.enabled || response == nil {
		return true, ""
	}

	LogDebug("HIJACK: Checking response for domain %s (query: %s)", currentDomain, queryDomain)
	currentDomain = normalizeDomain(currentDomain)
	queryDomain = normalizeDomain(queryDomain)

	for _, rr := range response.Answer {
		answerName := normalizeDomain(rr.Header().Name)
		rrType := rr.Header().Rrtype

		if answerName != queryDomain {
			continue
		}

		if rrType == dns.TypeNS || rrType == dns.TypeDS {
			continue
		}

		if valid, reason := hp.validateAnswer(currentDomain, queryDomain, rrType); !valid {
			LogDebug("HIJACK: Detected potential hijacking for %s: %s", queryDomain, reason)
			return false, reason
		}
	}

	return true, ""
}

func (hp *HijackPrevention) validateAnswer(authorityDomain, queryDomain string, rrType uint16) (bool, string) {
	if !hp.isInAuthority(queryDomain, authorityDomain) {
		return false, fmt.Sprintf("Server '%s' returned out-of-authority %s record for '%s'",
			authorityDomain, dns.TypeToString[rrType], queryDomain)
	}

	if authorityDomain == "" {
		return hp.validateRootServer(queryDomain, rrType)
	}

	if hp.isTLD(authorityDomain) {
		return hp.validateTLDServer(authorityDomain, queryDomain, rrType)
	}

	return true, ""
}

func (hp *HijackPrevention) validateRootServer(queryDomain string, rrType uint16) (bool, string) {
	if hp.isRootServerGlue(queryDomain, rrType) {
		return true, ""
	}
	if queryDomain != "" {
		return false, fmt.Sprintf("Root server returned unauthorized %s record for '%s'",
			dns.TypeToString[rrType], queryDomain)
	}
	return true, ""
}

func (hp *HijackPrevention) validateTLDServer(tldDomain, queryDomain string, rrType uint16) (bool, string) {
	if queryDomain != tldDomain {
		return false, fmt.Sprintf("TLD '%s' returned %s record in Answer for subdomain '%s'",
			tldDomain, dns.TypeToString[rrType], queryDomain)
	}
	return true, ""
}

func (hp *HijackPrevention) isRootServerGlue(domain string, rrType uint16) bool {
	if rrType != dns.TypeA && rrType != dns.TypeAAAA {
		return false
	}
	return strings.HasSuffix(domain, ".root-servers.net") || domain == "root-servers.net"
}

func (hp *HijackPrevention) isTLD(domain string) bool {
	return domain != "" && !strings.Contains(domain, ".")
}

func (hp *HijackPrevention) isInAuthority(queryDomain, authorityDomain string) bool {
	if queryDomain == authorityDomain || authorityDomain == "" {
		return true
	}
	return strings.HasSuffix(queryDomain, "."+authorityDomain)
}

// =============================================================================
// TLS Management
// =============================================================================

func generateSelfSignedCert(domain string) (tls.Certificate, error) {
	caPrivKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate CA EC key: %w", err)
	}

	serverPrivKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate server EC key: %w", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	caSerialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate CA serial number: %w", err)
	}

	serverSerialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate server serial number: %w", err)
	}

	caTemplate := x509.Certificate{
		SerialNumber: caSerialNumber,
		Subject: pkix.Name{
			CommonName:   "ZJDNS ECC Domain Secure Site CA",
			Organization: []string{"ZJDNS"},
			Country:      []string{"CN"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(CertValidityDuration),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	serverTemplate := x509.Certificate{
		SerialNumber: serverSerialNumber,
		Subject: pkix.Name{
			CommonName: domain,
		},
		DNSNames:    []string{domain},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(CertValidityDuration),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create CA certificate: %w", err)
	}

	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("parse CA certificate: %w", err)
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &serverTemplate, caCert, &serverPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create server certificate: %w", err)
	}

	cert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  serverPrivKey,
	}

	caPrivKeyBytes, err := x509.MarshalECPrivateKey(caPrivKey)
	if err != nil {
		LogWarn("TLS: Failed to marshal CA private key: %v", err)
		return cert, nil
	}

	serverPrivKeyBytes, err := x509.MarshalECPrivateKey(serverPrivKey)
	if err != nil {
		LogWarn("TLS: Failed to marshal server private key: %v", err)
		return cert, nil
	}

	fullchain := fmt.Sprintf("TLS: Certificate Full Chain:\n%s\n%s",
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertDER}))
	LogWarn("%s", fullchain)

	privkey := fmt.Sprintf("TLS: Certificate Private Key:\n%s",
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: serverPrivKeyBytes}))
	LogWarn("%s", privkey)

	caPrivkey := fmt.Sprintf("TLS: CA Private key:\n%s",
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: caPrivKeyBytes}))
	LogDebug("%s", caPrivkey)

	return cert, nil
}

func (tm *TLSManager) displayCertificateInfo(cert tls.Certificate) {
	if len(cert.Certificate) == 0 {
		LogError("TLS: No certificate found")
		return
	}

	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		LogError("TLS: Failed to parse certificate: %v", err)
		return
	}

	LogInfo("TLS: Certificate: Subject: %s | Issuer: %s | Valid: %s -> %s | Algorithm: %s",
		x509Cert.Subject.CommonName,
		x509Cert.Issuer.String(),
		x509Cert.NotBefore.Format("2006-01-02"),
		x509Cert.NotAfter.Format("2006-01-02"),
		x509Cert.SignatureAlgorithm.String())

	daysUntilExpiry := int(time.Until(x509Cert.NotAfter).Hours() / 24)
	if daysUntilExpiry < 0 {
		LogError("TLS: Certificate has EXPIRED for %d days!", -daysUntilExpiry)
	} else if daysUntilExpiry <= 30 {
		LogWarn("TLS: Certificate expires in %d days!", daysUntilExpiry)
	}
}

type TLSManager struct {
	server            *DNSServer
	tlsConfig         *tls.Config
	ctx               context.Context
	cancel            context.CancelFunc
	wg                sync.WaitGroup
	tlsListener       net.Listener
	quicConn          *net.UDPConn
	quicListener      *quic.EarlyListener
	quicTransport     *quic.Transport
	quicAddrValidator *QUICAddrValidator
	httpsServer       *http.Server
	h3Server          *http3.Server
	httpsListener     net.Listener
	h3Listener        *quic.EarlyListener
}

func NewTLSManager(server *DNSServer, config *ServerConfig) (*TLSManager, error) {
	var cert tls.Certificate
	var err error

	if config.Server.TLS.SelfSigned {
		cert, err = generateSelfSignedCert(config.Server.DDR.Domain)
		if err != nil {
			return nil, fmt.Errorf("generate self-signed certificate: %w", err)
		}
		LogInfo("TLS: Using self-signed certificate for domain: %s", config.Server.DDR.Domain)
	} else {
		cert, err = tls.LoadX509KeyPair(config.Server.TLS.CertFile, config.Server.TLS.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("load certificate: %w", err)
		}
		LogInfo("TLS: Using certificate from files: %s, %s", config.Server.TLS.CertFile, config.Server.TLS.KeyFile)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Create QUIC address validator with Redis support
	var quicAddrValidator *QUICAddrValidator
	if server.redisClient != nil {
		quicPrefix := config.Redis.KeyPrefix + RedisPrefixQUICValidator
		quicAddrValidator = newQUICAddrValidator(server.redisClient, quicPrefix, QUICAddrValidatorTTL)
		LogInfo("QUIC: Using Redis cache for address validation")
	} else {
		LogInfo("QUIC: No cache for address validation (Redis not configured)")
	}

	tm := &TLSManager{
		server:            server,
		tlsConfig:         tlsConfig,
		ctx:               ctx,
		cancel:            cancel,
		quicAddrValidator: quicAddrValidator,
	}

	tm.displayCertificateInfo(cert)

	return tm, nil
}

func (tm *TLSManager) Start(httpsPort string) error {
	serverCount := 2
	if httpsPort != "" {
		serverCount += 2
	}

	errChan := make(chan error, serverCount)
	wg := sync.WaitGroup{}
	wg.Add(serverCount)

	go func() {
		defer wg.Done()
		defer handlePanic("Critical-DoT server")
		if err := tm.startTLSServer(); err != nil {
			errChan <- fmt.Errorf("DoT startup: %w", err)
		}
	}()

	go func() {
		defer wg.Done()
		defer handlePanic("Critical-DoQ server")
		if err := tm.startQUICServer(); err != nil {
			errChan <- fmt.Errorf("DoQ startup: %w", err)
		}
	}()

	if httpsPort != "" {
		go func() {
			defer wg.Done()
			defer handlePanic("Critical-DoH server")
			if err := tm.startDoHServer(httpsPort); err != nil {
				errChan <- fmt.Errorf("DoH startup: %w", err)
			}
		}()

		go func() {
			defer wg.Done()
			defer handlePanic("Critical-DoH3 server")
			if err := tm.startDoH3Server(httpsPort); err != nil {
				errChan <- fmt.Errorf("DoH3 startup: %w", err)
			}
		}()
	}

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

func (tm *TLSManager) startTLSServer() error {
	listener, err := net.Listen("tcp", ":"+tm.server.config.Server.TLS.Port)
	if err != nil {
		return fmt.Errorf("DoT listen: %w", err)
	}

	tm.tlsListener = tls.NewListener(listener, tm.tlsConfig)
	LogInfo("DOT: DoT server started: %s", tm.tlsListener.Addr())

	tm.wg.Add(1)
	go func() {
		defer tm.wg.Done()
		defer handlePanic("DoT server")
		tm.handleTLSConnections()
	}()

	return nil
}

func (tm *TLSManager) startQUICServer() error {
	addr := ":" + tm.server.config.Server.TLS.Port

	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return fmt.Errorf("resolve UDP address: %w", err)
	}

	tm.quicConn, err = net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("UDP listen: %w", err)
	}

	tm.quicTransport = &quic.Transport{
		Conn:                tm.quicConn,
		VerifySourceAddress: tm.quicAddrValidator.requiresValidation,
	}

	quicTLSConfig := tm.tlsConfig.Clone()
	quicTLSConfig.NextProtos = NextProtoQUIC

	quicConfig := &quic.Config{
		MaxIdleTimeout:        SecureIdleTimeout,
		MaxIncomingStreams:    MaxIncomingStreams,
		MaxIncomingUniStreams: MaxIncomingStreams,
		Allow0RTT:             true,
	}

	tm.quicListener, err = tm.quicTransport.ListenEarly(quicTLSConfig, quicConfig)
	if err != nil {
		_ = tm.quicConn.Close()
		return fmt.Errorf("DoQ listen: %w", err)
	}

	LogInfo("DOQ: DoQ server started: %s", tm.quicListener.Addr())

	tm.wg.Add(1)
	go func() {
		defer tm.wg.Done()
		defer handlePanic("DoQ server")
		tm.handleQUICConnections()
	}()

	return nil
}

func (tm *TLSManager) startDoHServer(port string) error {
	listener, err := net.Listen("tcp", ":"+port)
	if err != nil {
		return fmt.Errorf("DoH listen: %w", err)
	}

	tlsConfig := tm.tlsConfig.Clone()
	tlsConfig.NextProtos = NextProtoHTTP2

	tm.httpsListener = tls.NewListener(listener, tlsConfig)
	LogInfo("DOH: DoH server started: %s", tm.httpsListener.Addr())

	tm.httpsServer = &http.Server{
		Handler:           tm,
		ReadHeaderTimeout: DoHReadHeaderTimeout,
		WriteTimeout:      DoHWriteTimeout,
	}

	tm.wg.Add(1)
	go func() {
		defer tm.wg.Done()
		defer handlePanic("DoH server")
		if err := tm.httpsServer.Serve(tm.httpsListener); err != nil && err != http.ErrServerClosed {
			LogError("DOH: DoH server error: %v", err)
		}
	}()

	return nil
}

func (tm *TLSManager) startDoH3Server(port string) error {
	addr := ":" + port

	tlsConfig := tm.tlsConfig.Clone()
	tlsConfig.NextProtos = NextProtoHTTP3

	quicConfig := &quic.Config{
		MaxIdleTimeout:        SecureIdleTimeout,
		MaxIncomingStreams:    MaxIncomingStreams,
		MaxIncomingUniStreams: MaxIncomingStreams,
		Allow0RTT:             true,
	}

	quicListener, err := quic.ListenAddrEarly(addr, tlsConfig, quicConfig)
	if err != nil {
		return fmt.Errorf("DoH3 listen: %w", err)
	}

	tm.h3Listener = quicListener
	LogInfo("DOH3: DoH3 server started: %s", tm.h3Listener.Addr())

	tm.h3Server = &http3.Server{Handler: tm}

	tm.wg.Add(1)
	go func() {
		defer tm.wg.Done()
		defer handlePanic("DoH3 server")
		if err := tm.h3Server.ServeListener(tm.h3Listener); err != nil && err != http.ErrServerClosed {
			LogError("DOH3: DoH3 server error: %v", err)
		}
	}()

	return nil
}

func (tm *TLSManager) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if tm == nil || tm.server == nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	expectedPath := tm.server.config.Server.TLS.HTTPS.Endpoint
	if expectedPath == "" {
		expectedPath = DefaultQueryPath
	}
	if !strings.HasPrefix(expectedPath, "/") {
		expectedPath = "/" + expectedPath
	}

	if r.URL.Path != expectedPath {
		http.NotFound(w, r)
		return
	}

	req, statusCode := tm.parseDoHRequest(r)
	if req == nil {
		http.Error(w, http.StatusText(statusCode), statusCode)
		return
	}

	response := tm.server.processDNSQuery(req, nil, true)
	if err := tm.respondDoH(w, response); err != nil {
		LogError("DOH: DoH response failed: %v", err)
	}
}

func (tm *TLSManager) parseDoHRequest(r *http.Request) (*dns.Msg, int) {
	var buf []byte
	var err error

	switch r.Method {
	case http.MethodGet:
		dnsParam := r.URL.Query().Get("dns")
		if dnsParam == "" {
			return nil, http.StatusBadRequest
		}
		buf, err = base64.RawURLEncoding.DecodeString(dnsParam)
		if err != nil {
			return nil, http.StatusBadRequest
		}

	case http.MethodPost:
		if r.Header.Get("Content-Type") != "application/dns-message" {
			return nil, http.StatusUnsupportedMediaType
		}
		r.Body = http.MaxBytesReader(nil, r.Body, DoHMaxRequestSize)
		buf, err = io.ReadAll(r.Body)
		defer func() { _ = r.Body.Close() }()
		if err != nil {
			return nil, http.StatusBadRequest
		}

	default:
		return nil, http.StatusMethodNotAllowed
	}

	if len(buf) == 0 {
		return nil, http.StatusBadRequest
	}

	req := new(dns.Msg)
	if err := req.Unpack(buf); err != nil {
		return nil, http.StatusBadRequest
	}

	return req, http.StatusOK
}

func (tm *TLSManager) respondDoH(w http.ResponseWriter, response *dns.Msg) error {
	if response == nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return nil
	}

	bytes, err := response.Pack()
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return fmt.Errorf("pack response: %w", err)
	}

	w.Header().Set("Content-Type", "application/dns-message")
	w.Header().Set("Cache-Control", "max-age=0")
	_, err = w.Write(bytes)
	return err
}

func (tm *TLSManager) handleTLSConnections() {
	for {
		select {
		case <-tm.ctx.Done():
			return
		default:
		}

		conn, err := tm.tlsListener.Accept()
		if err != nil {
			if tm.ctx.Err() != nil {
				return
			}
			LogError("DOT: DoT accept failed: %v", err)
			continue
		}

		tm.wg.Add(1)
		go func(c net.Conn) {
			defer tm.wg.Done()
			defer handlePanic("DoT connection")
			defer func() { _ = c.Close() }()
			tm.handleSecureDNSConnection(c, "DoT")
		}(conn)
	}
}

func (tm *TLSManager) handleQUICConnections() {
	for {
		select {
		case <-tm.ctx.Done():
			return
		default:
		}

		conn, err := tm.quicListener.Accept(tm.ctx)
		if err != nil {
			if tm.ctx.Err() != nil {
				return
			}
			continue
		}

		if conn == nil {
			continue
		}

		tm.wg.Add(1)
		go func(quicConn *quic.Conn) {
			defer tm.wg.Done()
			defer handlePanic("DoQ connection")
			defer tm.forceCloseQUICConnection(quicConn)
			tm.handleQUICConnection(quicConn)
		}(conn)
	}
}

func (tm *TLSManager) forceCloseQUICConnection(conn *quic.Conn) {
	if conn == nil {
		return
	}

	// 关闭连接
	_ = conn.CloseWithError(QUICCodeNoError, "")

	// 等待一小段时间确保关闭帧发送
	ctx, cancel := context.WithTimeout(context.Background(), ConnectionCloseTimeout)
	defer cancel()

	done := make(chan struct{})
	go func() {
		<-conn.Context().Done()
		close(done)
	}()

	select {
	case <-done:
		// 连接已完全关闭
	case <-ctx.Done():
		// 超时，强制返回
		LogDebug("QUIC: Connection close timeout, forcing shutdown")
	}
}

func (tm *TLSManager) handleQUICConnection(conn *quic.Conn) {
	if conn == nil {
		return
	}

	for {
		select {
		case <-tm.ctx.Done():
			return
		case <-conn.Context().Done():
			return
		default:
		}

		stream, err := conn.AcceptStream(tm.ctx)
		if err != nil {
			return // 任何错误都退出
		}

		if stream == nil {
			continue
		}

		tm.wg.Add(1)
		go func(s *quic.Stream) {
			defer tm.wg.Done()
			defer handlePanic("DoQ stream")
			if s != nil {
				defer func() { _ = s.Close() }()
				tm.handleQUICStream(s, conn)
			}
		}(stream)
	}
}

func (tm *TLSManager) handleQUICStream(stream *quic.Stream, conn *quic.Conn) {
	buf := make([]byte, SecureBufferSize)
	n, err := io.ReadFull(stream, buf[:2])
	if err != nil || n < 2 {
		return
	}

	msgLen := binary.BigEndian.Uint16(buf[:2])
	if msgLen == 0 || msgLen > SecureBufferSize-2 {
		_ = conn.CloseWithError(QUICCodeProtocolError, "")
		return
	}

	n, err = io.ReadFull(stream, buf[2:2+msgLen])
	if err != nil || n != int(msgLen) {
		return
	}

	req := new(dns.Msg)
	if err := req.Unpack(buf[2 : 2+msgLen]); err != nil {
		_ = conn.CloseWithError(QUICCodeProtocolError, "")
		return
	}

	clientIP := getSecureClientIP(conn)
	response := tm.server.processDNSQuery(req, clientIP, true)

	if err := tm.respondQUIC(stream, response); err != nil {
		LogDebug("PROTOCOL: DoQ response failed: %v", err)
	}
}

func (tm *TLSManager) handleSecureDNSConnection(conn net.Conn, _ string) {
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return
	}

	// 创建 context 用于连接级别的取消
	connCtx, connCancel := context.WithCancel(tm.ctx)
	defer connCancel()

	// 在单独的 goroutine 中监听 context 取消
	go func() {
		<-connCtx.Done()
		_ = tlsConn.Close()
	}()

	_ = tlsConn.SetReadDeadline(time.Now().Add(QueryTimeout))

	for {
		select {
		case <-connCtx.Done():
			return
		default:
		}

		lengthBuf := make([]byte, 2)
		if _, err := io.ReadFull(tlsConn, lengthBuf); err != nil {
			return
		}

		msgLength := binary.BigEndian.Uint16(lengthBuf)
		if msgLength == 0 || msgLength > TCPBufferSize {
			return
		}

		msgBuf := make([]byte, msgLength)
		if _, err := io.ReadFull(tlsConn, msgBuf); err != nil {
			return
		}

		req := new(dns.Msg)
		if err := req.Unpack(msgBuf); err != nil {
			return
		}

		clientIP := getSecureClientIP(tlsConn)
		response := tm.server.processDNSQuery(req, clientIP, true)

		respBuf, err := response.Pack()
		if err != nil {
			return
		}

		lengthPrefix := make([]byte, 2)
		binary.BigEndian.PutUint16(lengthPrefix, uint16(len(respBuf)))

		if _, err := tlsConn.Write(lengthPrefix); err != nil {
			return
		}
		if _, err := tlsConn.Write(respBuf); err != nil {
			return
		}

		_ = tlsConn.SetReadDeadline(time.Now().Add(QueryTimeout))
	}
}

func (tm *TLSManager) respondQUIC(stream *quic.Stream, response *dns.Msg) error {
	if response == nil {
		return errors.New("response is nil")
	}

	respBuf, err := response.Pack()
	if err != nil {
		return fmt.Errorf("pack response: %w", err)
	}

	buf := make([]byte, 2+len(respBuf))
	binary.BigEndian.PutUint16(buf[:2], uint16(len(respBuf)))
	copy(buf[2:], respBuf)

	n, err := stream.Write(buf)
	if err != nil {
		return fmt.Errorf("stream write: %w", err)
	}
	if n != len(buf) {
		return fmt.Errorf("write length mismatch: %d != %d", n, len(buf))
	}

	return nil
}

func (tm *TLSManager) shutdown() error {
	LogInfo("TLS: Shutting down secure DNS server...")

	tm.cancel()

	if tm.tlsListener != nil {
		closeWithLog(tm.tlsListener, "TLS listener")
	}
	if tm.quicListener != nil {
		closeWithLog(tm.quicListener, "QUIC listener")
	}
	if tm.quicConn != nil {
		closeWithLog(tm.quicConn, "QUIC connection")
	}

	if tm.httpsServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), ShutdownTimeout)
		defer cancel()
		_ = tm.httpsServer.Shutdown(ctx)
	}

	if tm.h3Server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), ShutdownTimeout)
		defer cancel()
		_ = tm.h3Server.Shutdown(ctx)
	}

	if tm.httpsListener != nil {
		closeWithLog(tm.httpsListener, "HTTPS listener")
	}
	if tm.h3Listener != nil {
		closeWithLog(tm.h3Listener, "HTTP/3 listener")
	}

	tm.wg.Wait()
	LogInfo("TLS: Secure DNS server shut down")
	return nil
}

type QUICAddrValidator struct {
	redis  *redis.Client
	ttl    time.Duration
	prefix string
}

func newQUICAddrValidator(redisClient *redis.Client, keyPrefix string, ttl time.Duration) *QUICAddrValidator {
	return &QUICAddrValidator{
		redis:  redisClient,
		ttl:    ttl,
		prefix: keyPrefix,
	}
}

func (v *QUICAddrValidator) requiresValidation(addr net.Addr) bool {
	if v == nil || v.redis == nil {
		return true
	}

	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return true
	}

	key := v.prefix + udpAddr.IP.String()

	// Check if already validated
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	exists, err := v.redis.Exists(ctx, key).Result()
	if err != nil || exists == 1 {
		// If error or exists, don't require validation
		return err != nil
	}

	// Set validation flag with TTL
	err = v.redis.Set(ctx, key, "1", v.ttl).Err()
	if err != nil {
		LogDebug("QUIC: Failed to set validation cache for %s: %v", key, err)
	}

	return true
}

// =============================================================================
// Connection & Query Management
// =============================================================================

type ConnectionManager struct {
	timeout     time.Duration
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
	closed      int32
	queryClient *QueryClient
}

func NewConnectionManager() *ConnectionManager {
	ctx, cancel := context.WithCancel(context.Background())
	cm := &ConnectionManager{
		timeout: QueryTimeout,
		ctx:     ctx,
		cancel:  cancel,
	}
	cm.queryClient = &QueryClient{connMgr: cm, timeout: QueryTimeout}
	return cm
}

func (cm *ConnectionManager) Close() error {
	if !atomic.CompareAndSwapInt32(&cm.closed, 0, 1) {
		return nil
	}
	LogInfo("CONN: Shutting down connection manager...")
	cm.cancel()
	cm.wg.Wait()
	LogInfo("CONN: Connection manager shut down")
	return nil
}

type QueryClient struct {
	connMgr *ConnectionManager
	timeout time.Duration
}

type QueryResult struct {
	Response   *dns.Msg
	Answer     []dns.RR
	Authority  []dns.RR
	Additional []dns.RR
	Server     string
	Error      error
	Duration   time.Duration
	Protocol   string
	Validated  bool
	ECS        *ECSOption
}

func (qc *QueryClient) ExecuteQuery(ctx context.Context, msg *dns.Msg, server *UpstreamServer, tracker *RequestTracker) *QueryResult {
	start := time.Now()
	result := &QueryResult{Server: server.Address, Protocol: server.Protocol}

	queryCtx, cancel := context.WithTimeout(ctx, qc.timeout)
	defer cancel()

	protocol := strings.ToLower(server.Protocol)
	LogDebug("PROTOCOL: Selected protocol %s for query to %s (question: %s)",
		strings.ToUpper(protocol), server.Address, msg.Question[0].Name)

	if isSecureProtocol(protocol) {
		LogDebug("PROTOCOL: Using secure protocol %s", strings.ToUpper(protocol))
		result.Response, result.Error = qc.executeSecureQuery(queryCtx, msg, server, protocol, tracker)
	} else {
		LogDebug("PROTOCOL: Using traditional protocol %s", strings.ToUpper(protocol))
		result.Response, result.Error = qc.executeTraditionalQuery(queryCtx, msg, server, tracker)
		if qc.needsTCPFallback(result, protocol) {
			LogDebug("PROTOCOL: UDP query failed/truncated, falling back to TCP for %s", server.Address)
			tcpServer := *server
			tcpServer.Protocol = "tcp"
			tcpResponse, tcpErr := qc.executeTraditionalQuery(queryCtx, msg, &tcpServer, tracker)
			if tcpErr == nil {
				LogDebug("PROTOCOL: TCP fallback successful for %s", server.Address)
				result.Response = tcpResponse
				result.Error = nil
				result.Protocol = "TCP"
			} else {
				LogDebug("PROTOCOL: TCP fallback failed for %s: %v", server.Address, tcpErr)
				if result.Response == nil || result.Response.Rcode == dns.RcodeServerFailure {
					result.Error = tcpErr
				}
			}
		} else {
			LogDebug("PROTOCOL: No TCP fallback needed for %s", server.Address)
		}
	}

	result.Duration = time.Since(start)
	result.Protocol = strings.ToUpper(protocol)

	if result.Error != nil {
		LogDebug("PROTOCOL: Query to %s failed in %v: %v", server.Address, result.Duration, result.Error)
	} else {
		rcode := "UNKNOWN"
		if result.Response != nil {
			rcode = dns.RcodeToString[result.Response.Rcode]
		}
		LogDebug("PROTOCOL: Query to %s completed in %v with rcode %s",
			server.Address, result.Duration, rcode)
	}

	return result
}

func (qc *QueryClient) executeSecureQuery(ctx context.Context, msg *dns.Msg, server *UpstreamServer, protocol string, _ *RequestTracker) (*dns.Msg, error) {
	tlsConfig := &tls.Config{
		ServerName:         server.ServerName,
		InsecureSkipVerify: server.SkipTLSVerify,
		MinVersion:         tls.VersionTLS12,
	}

	switch protocol {
	case "tls":
		return qc.executeTLSQuery(ctx, msg, server, tlsConfig)
	case "quic":
		return qc.executeQUICQuery(ctx, msg, server, tlsConfig)
	case "https", "http3":
		return qc.executeDoHQuery(ctx, msg, server, protocol)
	default:
		return nil, fmt.Errorf("unsupported protocol: %s", protocol)
	}
}

func (qc *QueryClient) executeTLSQuery(ctx context.Context, msg *dns.Msg, server *UpstreamServer, tlsConfig *tls.Config) (*dns.Msg, error) {
	host, port, err := net.SplitHostPort(server.Address)
	if err != nil {
		return nil, fmt.Errorf("parse TLS address: %w", err)
	}

	// 使用 DialContext 以支持 context 取消
	dialer := &net.Dialer{Timeout: TLSHandshakeTimeout}
	netConn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}

	// 在单独的 goroutine 中监听 context 取消
	go func() {
		<-ctx.Done()
		_ = netConn.Close()
	}()

	// 手动进行 TLS 握手
	tlsConn := tls.Client(netConn, tlsConfig)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = netConn.Close()
		return nil, fmt.Errorf("TLS handshake: %w", err)
	}
	defer func() { _ = tlsConn.Close() }()

	_ = tlsConn.SetDeadline(time.Now().Add(qc.timeout))

	msgData, err := msg.Pack()
	if err != nil {
		return nil, fmt.Errorf("pack message: %w", err)
	}

	buf := make([]byte, 2+len(msgData))
	binary.BigEndian.PutUint16(buf[:2], uint16(len(msgData)))
	copy(buf[2:], msgData)

	if _, err := tlsConn.Write(buf); err != nil {
		return nil, fmt.Errorf("send TLS query: %w", err)
	}

	lengthBuf := make([]byte, 2)
	if _, err := io.ReadFull(tlsConn, lengthBuf); err != nil {
		return nil, fmt.Errorf("read response length: %w", err)
	}

	respLength := binary.BigEndian.Uint16(lengthBuf)
	if respLength == 0 || respLength > TCPBufferSize {
		return nil, fmt.Errorf("invalid response length: %d", respLength)
	}

	respBuf := make([]byte, respLength)
	if _, err := io.ReadFull(tlsConn, respBuf); err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	response := new(dns.Msg)
	if err := response.Unpack(respBuf); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	return response, nil
}

func (qc *QueryClient) executeQUICQuery(ctx context.Context, msg *dns.Msg, server *UpstreamServer, tlsConfig *tls.Config) (*dns.Msg, error) {
	tlsConfig.NextProtos = NextProtoQUIC
	quicConfig := &quic.Config{
		MaxIdleTimeout:     SecureIdleTimeout,
		MaxIncomingStreams: MaxIncomingStreams,
	}

	conn, err := quic.DialAddr(ctx, server.Address, tlsConfig, quicConfig)
	if err != nil {
		return nil, fmt.Errorf("QUIC dial: %w", err)
	}

	// 确保连接关闭
	defer func() {
		_ = conn.CloseWithError(QUICCodeNoError, "")
		// 等待关闭完成
		closeCtx, closeCancel := context.WithTimeout(context.Background(), ConnectionCloseTimeout)
		defer closeCancel()
		<-closeCtx.Done()
	}()

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("create QUIC stream: %w", err)
	}
	defer func() { _ = stream.Close() }()

	_ = stream.SetDeadline(time.Now().Add(qc.timeout))

	originalID := msg.Id
	msg.Id = 0

	msgData, err := msg.Pack()
	if err != nil {
		msg.Id = originalID
		return nil, fmt.Errorf("pack message: %w", err)
	}

	buf := make([]byte, 2+len(msgData))
	binary.BigEndian.PutUint16(buf[:2], uint16(len(msgData)))
	copy(buf[2:], msgData)

	if _, err := stream.Write(buf); err != nil {
		msg.Id = originalID
		return nil, fmt.Errorf("send QUIC query: %w", err)
	}

	_ = stream.Close()

	respBuf := make([]byte, SecureBufferSize)
	n, err := stream.Read(respBuf)
	if err != nil && n == 0 {
		msg.Id = originalID
		return nil, fmt.Errorf("read QUIC response: %w", err)
	}

	stream.CancelRead(0)

	if n < 2 {
		msg.Id = originalID
		return nil, fmt.Errorf("QUIC response too short: %d bytes", n)
	}

	response := new(dns.Msg)
	if err := response.Unpack(respBuf[2:n]); err != nil {
		msg.Id = originalID
		return nil, fmt.Errorf("parse QUIC response: %w", err)
	}

	msg.Id = originalID
	response.Id = originalID

	return response, nil
}

func (qc *QueryClient) executeDoHQuery(ctx context.Context, msg *dns.Msg, server *UpstreamServer, protocol string) (*dns.Msg, error) {
	parsedURL, err := url.Parse(server.Address)
	if err != nil {
		return nil, fmt.Errorf("parse DoH address: %w", err)
	}

	if parsedURL.Port() == "" {
		parsedURL.Host = net.JoinHostPort(parsedURL.Host, DefaultHTTPSPort)
	}

	tlsConfig := &tls.Config{
		ServerName:         server.ServerName,
		InsecureSkipVerify: server.SkipTLSVerify,
		MinVersion:         tls.VersionTLS12,
	}

	var transport http.RoundTripper

	if protocol == "http3" {
		tlsConfig.NextProtos = NextProtoHTTP3
		quicConfig := &quic.Config{
			MaxIdleTimeout:     SecureIdleTimeout,
			MaxIncomingStreams: MaxIncomingStreams,
		}
		transport = &http3.Transport{TLSClientConfig: tlsConfig, QUICConfig: quicConfig}
		defer func() { _ = transport.(*http3.Transport).Close() }()
	} else {
		tlsConfig.NextProtos = NextProtoHTTP2
		transport = &http.Transport{
			TLSClientConfig:    tlsConfig,
			DisableCompression: true,
			DisableKeepAlives:  true,
			MaxIdleConns:       0,
			IdleConnTimeout:    0,
			ForceAttemptHTTP2:  true,
		}
		// ✅ 修复：确保 transport 在函数返回时关闭
		defer transport.(*http.Transport).CloseIdleConnections()
		_, _ = http2.ConfigureTransports(transport.(*http.Transport))
	}

	httpClient := &http.Client{Transport: transport, Timeout: qc.timeout}

	originalID := msg.Id
	msg.Id = 0

	buf, err := msg.Pack()
	if err != nil {
		msg.Id = originalID
		return nil, fmt.Errorf("pack DNS message: %w", err)
	}

	q := url.Values{"dns": []string{base64.RawURLEncoding.EncodeToString(buf)}}
	u := url.URL{Scheme: parsedURL.Scheme, Host: parsedURL.Host, Path: parsedURL.Path, RawQuery: q.Encode()}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		msg.Id = originalID
		return nil, fmt.Errorf("create HTTP request: %w", err)
	}

	httpReq.Header.Set("Accept", "application/dns-message")
	httpReq.Close = true

	httpResp, err := httpClient.Do(httpReq)
	if err != nil {
		msg.Id = originalID
		return nil, fmt.Errorf("send HTTP request: %w", err)
	}
	defer func() { _ = httpResp.Body.Close() }()

	if httpResp.StatusCode != http.StatusOK {
		msg.Id = originalID
		return nil, fmt.Errorf("HTTP error: %d", httpResp.StatusCode)
	}

	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		msg.Id = originalID
		return nil, fmt.Errorf("read response: %w", err)
	}

	response := &dns.Msg{}
	if err := response.Unpack(body); err != nil {
		msg.Id = originalID
		return nil, fmt.Errorf("parse DNS response: %w", err)
	}

	msg.Id = originalID
	response.Id = originalID

	return response, nil
}

func (qc *QueryClient) executeTraditionalQuery(ctx context.Context, msg *dns.Msg, server *UpstreamServer, _ *RequestTracker) (*dns.Msg, error) {
	client := &dns.Client{Timeout: qc.timeout, Net: server.Protocol}
	if server.Protocol == "udp" {
		client.UDPSize = UDPBufferSize
	}

	response, _, err := client.ExchangeContext(ctx, msg, server.Address)
	return response, err
}

func (qc *QueryClient) needsTCPFallback(result *QueryResult, protocol string) bool {
	if protocol == "tcp" {
		return false
	}
	if result.Error != nil || (result.Response != nil && result.Response.Truncated) {
		return true
	}
	return false
}

// =============================================================================
// Query Manager
// =============================================================================

type QueryManager struct {
	upstream  *UpstreamHandler
	recursive *RecursiveResolver
	cname     *CNAMEHandler
	validator *ResponseValidator
	server    *DNSServer
}

func NewQueryManager(server *DNSServer) *QueryManager {
	return &QueryManager{
		upstream: &UpstreamHandler{servers: make([]*UpstreamServer, 0)},
		recursive: &RecursiveResolver{
			server:          server,
			rootServerMgr:   server.rootServerMgr,
			concurrencyLock: make(chan struct{}, MaxConcurrency),
		},
		cname: &CNAMEHandler{server: server},
		validator: &ResponseValidator{
			hijackPrevention: server.securityMgr.hijack,
			dnssecValidator:  server.securityMgr.dnssec,
		},
		server: server,
	}
}

func (qm *QueryManager) Initialize(servers []UpstreamServer) error {
	activeServers := make([]*UpstreamServer, 0, len(servers))
	for i := range servers {
		server := &servers[i]
		if server.Protocol == "" {
			server.Protocol = "udp"
		}
		activeServers = append(activeServers, server)
	}

	qm.upstream.mu.Lock()
	qm.upstream.servers = activeServers
	qm.upstream.mu.Unlock()

	return nil
}

func (qm *QueryManager) Query(question dns.Question, ecs *ECSOption, tracker *RequestTracker) ([]dns.RR, []dns.RR, []dns.RR, bool, *ECSOption, error) {
	servers := qm.upstream.getServers()
	if len(servers) > 0 {
		return qm.queryUpstream(question, ecs, tracker)
	}
	ctx, cancel := context.WithTimeout(qm.server.ctx, RecursiveTimeout)
	defer cancel()
	return qm.cname.resolveWithCNAME(ctx, question, ecs, tracker)
}

func (qm *QueryManager) queryUpstream(question dns.Question, ecs *ECSOption, tracker *RequestTracker) ([]dns.RR, []dns.RR, []dns.RR, bool, *ECSOption, error) {
	servers := qm.upstream.getServers()
	if len(servers) == 0 {
		return nil, nil, nil, false, nil, errors.New("no upstream servers")
	}

	resultChan := make(chan *QueryResult, len(servers))
	ctx, cancel := context.WithTimeout(qm.server.ctx, QueryTimeout)
	defer cancel()

	// ✅ 修复：创建一个可取消的子 context 用于所有查询
	queryCtx, cancelQueries := context.WithCancel(ctx)
	defer cancelQueries() // 确保所有查询都会被取消

	var wg sync.WaitGroup

	for _, server := range servers {
		srv := server

		if srv.IsRecursive() {
			wg.Add(1)
			qm.server.taskMgr.ExecuteAsync("Query-Recursive", func(taskCtx context.Context) error {
				defer wg.Done()

				// ✅ 使用可取消的 context
				recursiveCtx, recursiveCancel := context.WithTimeout(queryCtx, RecursiveTimeout)
				defer recursiveCancel()

				answer, authority, additional, validated, ecsResponse, err := qm.cname.resolveWithCNAME(recursiveCtx, question, ecs, tracker)

				if err == nil && len(answer) > 0 {
					if len(srv.Match) > 0 {
						filteredAnswer, shouldRefuse := qm.filterRecordsByCIDR(answer, srv.Match, tracker)
						if shouldRefuse {
							select {
							case resultChan <- &QueryResult{Error: fmt.Errorf("CIDR filter refused"), Server: srv.Address}:
							case <-queryCtx.Done():
							}
							return nil
						}
						answer = filteredAnswer
					}

					select {
					case resultChan <- &QueryResult{
						Answer:     answer,
						Authority:  authority,
						Additional: additional,
						Validated:  validated,
						ECS:        ecsResponse,
						Server:     srv.Address,
					}:
					case <-queryCtx.Done():
					}
				} else if err != nil {
					select {
					case resultChan <- &QueryResult{Error: err, Server: srv.Address}:
					case <-queryCtx.Done():
					}
				}
				return nil
			})
		} else {
			wg.Add(1)
			msg := qm.server.buildQueryMessage(question, ecs, true, false)
			qm.server.taskMgr.ExecuteAsync(fmt.Sprintf("Query-%s", srv.Address), func(taskCtx context.Context) error {
				defer wg.Done()
				defer releaseMessage(msg)

				// ✅ 使用可取消的 context
				result := qm.server.connMgr.queryClient.ExecuteQuery(queryCtx, msg, srv, tracker)

				if result.Error != nil {
					select {
					case resultChan <- &QueryResult{Error: result.Error, Server: srv.Address}:
					case <-queryCtx.Done():
					}
					return nil
				}

				if result.Response != nil {
					rcode := result.Response.Rcode

					if rcode == dns.RcodeSuccess || rcode == dns.RcodeNameError {
						if len(srv.Match) > 0 {
							filteredAnswer, shouldRefuse := qm.filterRecordsByCIDR(result.Response.Answer, srv.Match, tracker)
							if shouldRefuse {
								select {
								case resultChan <- &QueryResult{Error: fmt.Errorf("CIDR filter refused"), Server: srv.Address}:
								case <-queryCtx.Done():
								}
								return nil
							}
							result.Response.Answer = filteredAnswer
						}

						result.Validated = qm.validator.dnssecValidator.ValidateResponse(result.Response, true)

						ecsResponse := qm.server.ednsMgr.ParseFromDNS(result.Response)

						select {
						case resultChan <- &QueryResult{
							Answer:     result.Response.Answer,
							Authority:  result.Response.Ns,
							Additional: result.Response.Extra,
							Validated:  result.Validated,
							ECS:        ecsResponse,
							Server:     srv.Address,
						}:
						case <-queryCtx.Done():
						}
					} else {
						select {
						case resultChan <- &QueryResult{Error: fmt.Errorf("upstream error: %s", dns.RcodeToString[rcode]), Server: srv.Address}:
						case <-queryCtx.Done():
						}
					}
				}
				return nil
			})
		}
	}

	// ✅ 在单独的 goroutine 中等待所有任务完成并关闭 channel
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	var lastError error
	var successfulResults []*QueryResult

	// ✅ 修复：接收第一个成功结果后立即取消其他查询
	for result := range resultChan {
		if result.Error != nil {
			lastError = result.Error
			continue
		}

		if len(result.Answer) > 0 {
			// ✅ 找到成功结果，取消所有其他查询
			cancelQueries()
			// 等待 wg 完成以确保所有 goroutine 退出
			go func() {
				wg.Wait()
			}()
			return result.Answer, result.Authority, result.Additional, result.Validated, result.ECS, nil
		}

		successfulResults = append(successfulResults, result)
	}

	if len(successfulResults) > 0 {
		result := successfulResults[0]
		return result.Answer, result.Authority, result.Additional, result.Validated, result.ECS, nil
	}

	if lastError != nil {
		return nil, nil, nil, false, nil, lastError
	}
	return nil, nil, nil, false, nil, errors.New("all upstream queries returned no valid records")
}

func (qm *QueryManager) filterRecordsByCIDR(records []dns.RR, matchTags []string, _ *RequestTracker) ([]dns.RR, bool) {
	if qm.server.cidrMgr == nil || len(matchTags) == 0 {
		return records, false
	}

	filtered := make([]dns.RR, 0, len(records))
	refusedCount := 0

	for _, rr := range records {
		var ip net.IP
		switch record := rr.(type) {
		case *dns.A:
			ip = record.A
		case *dns.AAAA:
			ip = record.AAAA
		default:
			filtered = append(filtered, rr)
			continue
		}

		accepted := false
		for _, matchTag := range matchTags {
			matched, exists := qm.server.cidrMgr.MatchIP(ip, matchTag)
			if !exists {
				return nil, true
			}
			if matched {
				accepted = true
				break
			}
		}

		if accepted {
			filtered = append(filtered, rr)
		} else {
			refusedCount++
		}
	}

	if refusedCount > 0 {
		return nil, true
	}

	return filtered, false
}

type UpstreamHandler struct {
	servers []*UpstreamServer
	mu      sync.RWMutex
}

func (uh *UpstreamHandler) getServers() []*UpstreamServer {
	uh.mu.RLock()
	defer uh.mu.RUnlock()
	return uh.servers
}

type CNAMEHandler struct {
	server *DNSServer
}

func (ch *CNAMEHandler) resolveWithCNAME(ctx context.Context, question dns.Question, ecs *ECSOption, tracker *RequestTracker) ([]dns.RR, []dns.RR, []dns.RR, bool, *ECSOption, error) {
	var allAnswers []dns.RR
	var finalAuthority, finalAdditional []dns.RR
	var finalECSResponse *ECSOption
	allValidated := true

	currentQuestion := question
	visitedCNAMEs := make(map[string]bool)

	for i := 0; i < MaxCNAMEChain; i++ {
		select {
		case <-ctx.Done():
			return nil, nil, nil, false, nil, ctx.Err()
		default:
		}

		currentName := normalizeDomain(currentQuestion.Name)
		if visitedCNAMEs[currentName] {
			return nil, nil, nil, false, nil, fmt.Errorf("CNAME loop detected: %s", currentName)
		}
		visitedCNAMEs[currentName] = true

		answer, authority, additional, validated, ecsResponse, err := ch.server.queryMgr.recursive.recursiveQuery(ctx, currentQuestion, ecs, 0, false, tracker)
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

type RecursiveResolver struct {
	server          *DNSServer
	rootServerMgr   *RootServerManager
	concurrencyLock chan struct{}
}

func (rr *RecursiveResolver) recursiveQuery(ctx context.Context, question dns.Question, ecs *ECSOption, depth int, forceTCP bool, tracker *RequestTracker) ([]dns.RR, []dns.RR, []dns.RR, bool, *ECSOption, error) {
	if depth > MaxRecursionDepth {
		LogDebug("RECURSION: Maximum depth exceeded for %s (depth: %d)", question.Name, depth)
		return nil, nil, nil, false, nil, fmt.Errorf("recursion depth exceeded: %d", depth)
	}

	qname := dns.Fqdn(question.Name)
	question.Name = qname
	nameservers := rr.getRootServers()
	currentDomain := "."
	normalizedQname := normalizeDomain(qname)

	LogDebug("RECURSION: Starting resolution for %s (type: %d, depth: %d, forceTCP: %v)",
		qname, question.Qtype, depth, forceTCP)
	LogDebug("RECURSION: Using %d root servers: %v", len(nameservers), nameservers)

	if normalizedQname == "" {
		response, err := rr.queryNameserversConcurrent(ctx, nameservers, question, ecs, forceTCP, tracker)
		if err != nil {
			return nil, nil, nil, false, nil, fmt.Errorf("root domain query: %w", err)
		}

		if rr.server.securityMgr.hijack.IsEnabled() {
			if valid, reason := rr.server.securityMgr.hijack.CheckResponse(currentDomain, normalizedQname, response); !valid {
				return rr.handleSuspiciousResponse(reason, forceTCP, ctx, question, ecs, depth, tracker)
			}
		}

		validated := rr.server.securityMgr.dnssec.ValidateResponse(response, true)
		ecsResponse := rr.server.ednsMgr.ParseFromDNS(response)
		return response.Answer, response.Ns, response.Extra, validated, ecsResponse, nil
	}

	for {
		select {
		case <-ctx.Done():
			LogDebug("RECURSION: Context cancelled for %s", question.Name)
			return nil, nil, nil, false, nil, ctx.Err()
		default:
		}

		LogDebug("RECURSION: Querying %d nameservers for domain %s", len(nameservers), currentDomain)
		response, err := rr.queryNameserversConcurrent(ctx, nameservers, question, ecs, forceTCP, tracker)
		if err != nil {
			LogDebug("RECURSION: Query failed for %s: %v (forceTCP: %v)", currentDomain, err, forceTCP)
			if !forceTCP && strings.HasPrefix(err.Error(), "DNS_HIJACK_DETECTED") {
				LogDebug("RECURSION: DNS hijack detected, retrying with TCP for %s", question.Name)
				return rr.recursiveQuery(ctx, question, ecs, depth, true, tracker)
			}
			return nil, nil, nil, false, nil, fmt.Errorf("query %s: %w", currentDomain, err)
		}

		if rr.server.securityMgr.hijack.IsEnabled() {
			if valid, reason := rr.server.securityMgr.hijack.CheckResponse(currentDomain, normalizedQname, response); !valid {
				answer, authority, additional, validated, ecsResponse, err := rr.handleSuspiciousResponse(reason, forceTCP, ctx, question, ecs, depth, tracker)
				if err != nil && !forceTCP && strings.HasPrefix(err.Error(), "DNS_HIJACK_DETECTED") {
					return rr.recursiveQuery(ctx, question, ecs, depth, true, tracker)
				}
				return answer, authority, additional, validated, ecsResponse, err
			}
		}

		validated := rr.server.securityMgr.dnssec.ValidateResponse(response, true)
		LogDebug("RECURSION: DNSSEC validation result for %s: %v", currentDomain, validated)

		ecsResponse := rr.server.ednsMgr.ParseFromDNS(response)
		if ecsResponse != nil {
			LogDebug("RECURSION: ECS response received for %s: %s/%d",
				currentDomain, ecsResponse.Address, ecsResponse.SourcePrefix)
		}

		if len(response.Answer) > 0 {
			LogDebug("RECURSION: Found answer for %s - %d records, returning result",
				question.Name, len(response.Answer))
			return response.Answer, response.Ns, response.Extra, validated, ecsResponse, nil
		}

		bestMatch := ""
		var bestNSRecords []*dns.NS

		LogDebug("RECURSION: Processing %d NS records from response for %s", len(response.Ns), currentDomain)

		for _, rrec := range response.Ns {
			if ns, ok := rrec.(*dns.NS); ok {
				nsName := normalizeDomain(rrec.Header().Name)

				isMatch := normalizedQname == nsName ||
					(nsName != "" && strings.HasSuffix(normalizedQname, "."+nsName)) ||
					(nsName == "" && normalizedQname != "")

				if isMatch && len(nsName) >= len(bestMatch) {
					if len(nsName) > len(bestMatch) {
						bestMatch = nsName
						bestNSRecords = []*dns.NS{ns}
					} else {
						bestNSRecords = append(bestNSRecords, ns)
					}
				}
			}
		}

		LogDebug("RECURSION: Best NS match for %s: %s (%d records)", question.Name, bestMatch, len(bestNSRecords))
		if len(bestNSRecords) == 0 {
			LogDebug("RECURSION: No matching NS records found, returning delegation")
			return nil, response.Ns, response.Extra, validated, ecsResponse, nil
		}

		currentDomainNormalized := normalizeDomain(currentDomain)
		if bestMatch == currentDomainNormalized && currentDomainNormalized != "" {
			LogDebug("RECURSION: NS delegation loop detected for %s, returning delegation", currentDomain)
			return nil, response.Ns, response.Extra, validated, ecsResponse, nil
		}

		currentDomain = bestMatch + "."
		LogDebug("RECURSION: Continuing to next level: %s", currentDomain)

		var nextNS []string
		LogDebug("RECURSION: Resolving glue records for %d NS servers", len(bestNSRecords))
		for _, ns := range bestNSRecords {
			for _, rrec := range response.Extra {
				switch a := rrec.(type) {
				case *dns.A:
					if strings.EqualFold(a.Header().Name, ns.Ns) {
						nextNS = append(nextNS, net.JoinHostPort(a.A.String(), DefaultDNSPort))
						LogDebug("RECURSION: Found glue A record: %s -> %s", ns.Ns, a.A.String())
					}
				case *dns.AAAA:
					if strings.EqualFold(a.Header().Name, ns.Ns) {
						nextNS = append(nextNS, net.JoinHostPort(a.AAAA.String(), DefaultDNSPort))
						LogDebug("RECURSION: Found glue AAAA record: %s -> %s", ns.Ns, a.AAAA.String())
					}
				}
			}
		}

		if len(nextNS) == 0 {
			LogDebug("RECURSION: No glue records found, resolving NS addresses recursively")
			nextNS = rr.resolveNSAddressesConcurrent(ctx, bestNSRecords, qname, depth, forceTCP, tracker)
		}

		LogDebug("RECURSION: Resolved %d nameserver addresses for next level", len(nextNS))
		if len(nextNS) == 0 {
			LogDebug("RECURSION: Failed to resolve any nameserver addresses, returning delegation")
			return nil, response.Ns, response.Extra, validated, ecsResponse, nil
		}

		LogDebug("RECURSION: Using nameservers for next query: %v", nextNS)
		nameservers = nextNS
	}
}

func (rr *RecursiveResolver) handleSuspiciousResponse(reason string, currentlyTCP bool, _ context.Context, _ dns.Question, _ *ECSOption, _ int, _ *RequestTracker) ([]dns.RR, []dns.RR, []dns.RR, bool, *ECSOption, error) {
	if !currentlyTCP {
		return nil, nil, nil, false, nil, fmt.Errorf("DNS_HIJACK_DETECTED: %s", reason)
	}
	return nil, nil, nil, false, nil, fmt.Errorf("DNS hijacking detected (TCP): %s", reason)
}

func (rr *RecursiveResolver) queryNameserversConcurrent(ctx context.Context, nameservers []string, question dns.Question, ecs *ECSOption, forceTCP bool, tracker *RequestTracker) (*dns.Msg, error) {
	if len(nameservers) == 0 {
		LogDebug("UPSTREAM: No nameservers provided for query %s", question.Name)
		return nil, errors.New("no nameservers")
	}

	LogDebug("UPSTREAM: Starting concurrent query for %s (type: %d) to %d servers, forceTCP: %v",
		question.Name, question.Qtype, len(nameservers), forceTCP)

	select {
	case rr.concurrencyLock <- struct{}{}:
		defer func() { <-rr.concurrencyLock }()
	case <-ctx.Done():
		LogDebug("UPSTREAM: Context cancelled while waiting for concurrency lock")
		return nil, ctx.Err()
	}

	concurrency := len(nameservers)
	if concurrency > MaxSingleQuery {
		concurrency = MaxSingleQuery
		LogDebug("UPSTREAM: Limiting concurrency to %d (was %d)", MaxSingleQuery, len(nameservers))
	}

	tempServers := make([]*UpstreamServer, concurrency)
	for i := 0; i < concurrency && i < len(nameservers); i++ {
		protocol := "udp"
		if forceTCP {
			protocol = "tcp"
		}
		tempServers[i] = &UpstreamServer{Address: nameservers[i], Protocol: protocol}
		LogDebug("UPSTREAM: Server %d: %s (%s)", i+1, nameservers[i], protocol)
	}

	// ✅ 修复：使用 buffered channel 防止 goroutine 泄漏
	resultChan := make(chan *QueryResult, concurrency)

	// ✅ 创建可取消的 context
	queryCtx, cancelQueries := context.WithCancel(ctx)
	defer cancelQueries()

	LogDebug("UPSTREAM: Launching %d concurrent queries", concurrency)

	for _, server := range tempServers {
		srv := server
		msg := rr.server.buildQueryMessage(question, ecs, true, false)
		rr.server.taskMgr.ExecuteAsync(fmt.Sprintf("Query-%s", srv.Address), func(taskCtx context.Context) error {
			defer releaseMessage(msg)
			LogDebug("UPSTREAM: Executing query to %s", srv.Address)

			// ✅ 使用可取消的 context
			result := rr.server.connMgr.queryClient.ExecuteQuery(queryCtx, msg, srv, tracker)

			if result.Error == nil && result.Response != nil {
				rcode := result.Response.Rcode
				LogDebug("UPSTREAM: Response from %s: rcode=%d, answer=%d, ns=%d, additional=%d",
					srv.Address, rcode, len(result.Response.Answer), len(result.Response.Ns), len(result.Response.Extra))

				if rcode == dns.RcodeSuccess || rcode == dns.RcodeNameError {
					result.Validated = rr.server.securityMgr.dnssec.ValidateResponse(result.Response, true)
					LogDebug("UPSTREAM: DNSSEC validation for %s: %v", srv.Address, result.Validated)
					LogDebug("UPSTREAM: Successful response from %s, returning result", srv.Address)
					select {
					case resultChan <- result:
					case <-queryCtx.Done():
						LogDebug("UPSTREAM: Context cancelled while sending result from %s", srv.Address)
					}
				} else {
					LogDebug("UPSTREAM: Response from %s has non-success rcode %d, ignoring", srv.Address, rcode)
				}
			} else {
				LogDebug("UPSTREAM: Query to %s failed: %v", srv.Address, result.Error)
			}
			return nil
		})
	}

	LogDebug("UPSTREAM: Waiting for first successful response")
	select {
	case result := <-resultChan:
		// ✅ 收到第一个成功响应，立即取消其他查询
		cancelQueries()
		LogDebug("UPSTREAM: Received successful response (rcode: %d)", result.Response.Rcode)
		return result.Response, nil
	case <-ctx.Done():
		LogDebug("UPSTREAM: Context cancelled while waiting for response")
		return nil, ctx.Err()
	}
}

func (rr *RecursiveResolver) resolveNSAddressesConcurrent(ctx context.Context, nsRecords []*dns.NS, qname string, depth int, forceTCP bool, tracker *RequestTracker) []string {
	resolveCount := len(nsRecords)
	if resolveCount > MaxNSResolve {
		resolveCount = MaxNSResolve
	}

	// ✅ 修复：使用 buffered channel
	nsChan := make(chan []string, resolveCount)
	resolveCtx, resolveCancel := context.WithTimeout(ctx, ConnTimeout)
	defer resolveCancel()

	for i := 0; i < resolveCount; i++ {
		ns := nsRecords[i]
		rr.server.taskMgr.ExecuteAsync(fmt.Sprintf("NSResolve-%s", ns.Ns), func(taskCtx context.Context) error {
			if strings.EqualFold(strings.TrimSuffix(ns.Ns, "."), strings.TrimSuffix(qname, ".")) {
				select {
				case nsChan <- nil:
				case <-resolveCtx.Done():
				}
				return nil
			}

			var addresses []string

			nsQuestion := dns.Question{Name: dns.Fqdn(ns.Ns), Qtype: dns.TypeA, Qclass: dns.ClassINET}
			if nsAnswer, _, _, _, _, err := rr.recursiveQuery(resolveCtx, nsQuestion, nil, depth+1, forceTCP, tracker); err == nil {
				for _, rrec := range nsAnswer {
					if a, ok := rrec.(*dns.A); ok {
						addresses = append(addresses, net.JoinHostPort(a.A.String(), DefaultDNSPort))
					}
				}
			}

			if len(addresses) == 0 {
				nsQuestionV6 := dns.Question{Name: dns.Fqdn(ns.Ns), Qtype: dns.TypeAAAA, Qclass: dns.ClassINET}
				if nsAnswerV6, _, _, _, _, err := rr.recursiveQuery(resolveCtx, nsQuestionV6, nil, depth+1, forceTCP, tracker); err == nil {
					for _, rrec := range nsAnswerV6 {
						if aaaa, ok := rrec.(*dns.AAAA); ok {
							addresses = append(addresses, net.JoinHostPort(aaaa.AAAA.String(), DefaultDNSPort))
						}
					}
				}
			}

			// ✅ 修复：检查 context 是否已取消
			select {
			case nsChan <- addresses:
			case <-resolveCtx.Done():
				// Context 已取消，不发送
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
				if len(allAddresses) >= MaxNSResolve {
					resolveCancel() // ✅ 取消剩余任务
					// ✅ 清空 channel 以防止 goroutine 阻塞
					go func() {
						for i < resolveCount {
							select {
							case <-nsChan:
								i++
							case <-time.After(time.Second):
								return
							}
						}
					}()
					return allAddresses
				}
			}
		case <-resolveCtx.Done():
			return allAddresses
		}
	}

	return allAddresses
}

func (rr *RecursiveResolver) getRootServers() []string {
	serversWithLatency := rr.rootServerMgr.GetOptimalRootServers()
	servers := make([]string, len(serversWithLatency))
	for i, server := range serversWithLatency {
		servers[i] = server.Server
	}
	return servers
}

type ResponseValidator struct {
	hijackPrevention *HijackPrevention
	dnssecValidator  *DNSSECValidator
}

// =============================================================================
// Resource Management
// =============================================================================

type TaskManager struct {
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
	semaphore   chan struct{}
	activeCount int64
	closed      int32
	stats       struct {
		executed int64
		failed   int64
		timeout  int64
	}
}

func NewTaskManager(maxGoroutines int) *TaskManager {
	ctx, cancel := context.WithCancel(context.Background())
	return &TaskManager{
		ctx:       ctx,
		cancel:    cancel,
		semaphore: make(chan struct{}, maxGoroutines),
	}
}

func (tm *TaskManager) ExecuteAsync(name string, fn func(ctx context.Context) error) {
	// ✅ 修复：提前检查，避免创建 goroutine
	if tm == nil || atomic.LoadInt32(&tm.closed) != 0 {
		return
	}

	// ✅ 在创建 goroutine 前增加计数
	tm.wg.Add(1)

	LogDebug("TASK: Starting async task %s", name)
	go func() {
		defer tm.wg.Done()
		defer handlePanic(fmt.Sprintf("AsyncTask-%s", name))

		// ✅ 再次检查关闭状态
		if atomic.LoadInt32(&tm.closed) != 0 {
			return
		}

		atomic.AddInt64(&tm.activeCount, 1)
		defer atomic.AddInt64(&tm.activeCount, -1)

		atomic.AddInt64(&tm.stats.executed, 1)

		if err := fn(tm.ctx); err != nil && err != context.Canceled {
			atomic.AddInt64(&tm.stats.failed, 1)
			LogDebug("TASK: Async task %s failed: %v", name, err)
		} else {
			LogDebug("TASK: Async task %s completed successfully", name)
		}
	}()
}

func (tm *TaskManager) Shutdown(timeout time.Duration) error {
	if tm == nil || !atomic.CompareAndSwapInt32(&tm.closed, 0, 1) {
		return nil
	}

	LogInfo("TASK: Shutting down task manager...")
	tm.cancel()

	done := make(chan struct{})
	go func() {
		tm.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		LogInfo("TASK: Task manager shut down")
	case <-time.After(timeout):
		LogWarn("TASK: Task manager shutdown timeout")
		return fmt.Errorf("shutdown timeout")
	}

	close(tm.semaphore)
	return nil
}

type RequestTracker struct {
	ID           string
	StartTime    time.Time
	Domain       string
	QueryType    string
	ClientIP     string
	Steps        []string
	Upstream     string
	ResponseTime time.Duration
	mu           sync.Mutex
}

func NewRequestTracker(domain, qtype, clientIP string) *RequestTracker {
	return &RequestTracker{
		ID:        fmt.Sprintf("%x", time.Now().UnixNano()&0xFFFFFF),
		StartTime: time.Now(),
		Domain:    domain,
		QueryType: qtype,
		ClientIP:  clientIP,
		Steps:     make([]string, 0, 8),
	}
}

func (rt *RequestTracker) AddStep(step string, args ...interface{}) {
	if rt == nil || globalLog.GetLevel() < Debug {
		return
	}

	rt.mu.Lock()
	defer rt.mu.Unlock()

	timestamp := time.Since(rt.StartTime)
	stepMsg := fmt.Sprintf("[%v] %s", timestamp.Truncate(time.Microsecond), fmt.Sprintf(step, args...))
	rt.Steps = append(rt.Steps, stepMsg)
	LogDebug("[%s] %s", rt.ID, stepMsg)
}

func (rt *RequestTracker) Finish() {
	if rt == nil {
		return
	}
	rt.ResponseTime = time.Since(rt.StartTime)
	if globalLog.GetLevel() >= Info {
		upstream := rt.Upstream
		if upstream == "" {
			upstream = RecursiveIndicator
		}
		LogDebug("FINISH [%s]: Query completed: %s %s | Time:%v | Upstream:%s",
			rt.ID, rt.Domain, rt.QueryType, rt.ResponseTime.Truncate(time.Microsecond), upstream)
	}
}

// =============================================================================
// DNS Server
// =============================================================================

type DNSServer struct {
	config        *ServerConfig
	cacheMgr      CacheManager
	connMgr       *ConnectionManager
	queryMgr      *QueryManager
	securityMgr   *SecurityManager
	ednsMgr       *EDNSManager
	rewriteMgr    *RewriteManager
	speedTestMgr  *SpeedTestManager
	rootServerMgr *RootServerManager
	taskMgr       *TaskManager
	cidrMgr       *CIDRManager
	pprofServer   *http.Server
	speedInterval time.Duration
	redisClient   *redis.Client
	ctx           context.Context
	cancel        context.CancelFunc
	shutdown      chan struct{}
	wg            sync.WaitGroup
	closed        int32
}

func NewDNSServer(config *ServerConfig) (*DNSServer, error) {
	ctx, cancel := context.WithCancel(context.Background())

	ednsManager, err := NewEDNSManager(config.Server.DefaultECS)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("EDNS manager init: %w", err)
	}

	rewriteManager := NewRewriteManager()
	if len(config.Rewrite) > 0 {
		if err := rewriteManager.LoadRules(config.Rewrite); err != nil {
			cancel()
			return nil, fmt.Errorf("load rewrite rules: %w", err)
		}
	}

	var cidrManager *CIDRManager
	if len(config.CIDR) > 0 {
		cidrManager, err = NewCIDRManager(config.CIDR)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("CIDR manager init: %w", err)
		}
	}

	connectionManager := NewConnectionManager()
	taskManager := NewTaskManager(MaxConcurrency)

	// Create Redis client
	var redisClient *redis.Client
	var cache CacheManager
	if config.Redis.Address == "" {
		cache = NewNullCache()
	} else {
		redisCache, err := NewRedisCache(config, nil)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("redis cache init: %w", err)
		}
		cache = redisCache
		redisClient = redisCache.client
	}

	// Create RootServerManager with Redis client
	rootServerManager := NewRootServerManager(*config, redisClient)

	server := &DNSServer{
		config:        config,
		rootServerMgr: rootServerManager,
		connMgr:       connectionManager,
		taskMgr:       taskManager,
		ednsMgr:       ednsManager,
		rewriteMgr:    rewriteManager,
		cidrMgr:       cidrManager,
		speedInterval: SpeedDebounceInterval,
		redisClient:   redisClient,
		ctx:           ctx,
		cancel:        cancel,
		shutdown:      make(chan struct{}),
	}

	// Set server reference in RedisCache
	if redisCache, ok := cache.(*RedisCache); ok {
		redisCache.server = server
	}

	server.cacheMgr = cache

	securityManager, err := NewSecurityManager(config, server)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("security manager init: %w", err)
	}
	server.securityMgr = securityManager

	queryManager := NewQueryManager(server)
	if err := queryManager.Initialize(config.Upstream); err != nil {
		cancel()
		return nil, fmt.Errorf("query manager init: %w", err)
	}
	server.queryMgr = queryManager

	// Create domain SpeedTestManager
	if len(config.SpeedTest) > 0 {
		domainSpeedPrefix := config.Redis.KeyPrefix + RedisPrefixSpeedTestDomain
		server.speedTestMgr = NewSpeedTestManager(*config, redisClient, domainSpeedPrefix)
		if redisClient != nil {
			LogInfo("SPEEDTEST: Using Redis cache for domain speed test results")
		} else {
			LogInfo("SPEEDTEST: No cache for domain speed test (Redis not configured)")
		}
	}

	// Initialize pprof server if configured
	if config.Server.Pprof != "" {
		server.pprofServer = &http.Server{
			Addr:              ":" + config.Server.Pprof,
			ReadHeaderTimeout: PprofReadHeaderTimeout,
			ReadTimeout:       PprofReadTimeout,
			IdleTimeout:       PprofIdleTimeout,
		}

		// Configure TLS for pprof if TLS manager is available
		if server.securityMgr != nil && server.securityMgr.tls != nil {
			server.pprofServer.TLSConfig = server.securityMgr.tls.tlsConfig
		}
	}

	server.setupSignalHandling()

	return server, nil
}

func (s *DNSServer) setupSignalHandling() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer handlePanic("Root server periodic sorting")
		s.rootServerMgr.StartPeriodicSorting(s.ctx)
	}()

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer handlePanic("Signal handler")
		select {
		case sig := <-sigChan:
			LogInfo("SIGNAL: Received signal %v, starting graceful shutdown...", sig)
			s.shutdownServer()
		case <-s.ctx.Done():
			return
		}
	}()
}

func (s *DNSServer) shutdownServer() {
	if !atomic.CompareAndSwapInt32(&s.closed, 0, 1) {
		return
	}

	LogInfo("SERVER: Starting DNS server shutdown...")

	if s.cancel != nil {
		s.cancel()
	}

	if s.cacheMgr != nil {
		closeWithLog(s.cacheMgr, "Cache manager")
	}

	if s.securityMgr != nil {
		if err := s.securityMgr.Shutdown(ShutdownTimeout); err != nil {
			LogError("SECURITY: Security manager shutdown failed: %v", err)
		}
	}

	if s.connMgr != nil {
		closeWithLog(s.connMgr, "Connection manager")
	}

	if s.taskMgr != nil {
		if err := s.taskMgr.Shutdown(ShutdownTimeout); err != nil {
			LogError("TASK: Task manager shutdown failed: %v", err)
		}
	}

	if s.speedTestMgr != nil {
		closeWithLog(s.speedTestMgr, "SpeedTest manager")
	}

	if s.pprofServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), PprofShutdownTimeout)
		if err := s.pprofServer.Shutdown(ctx); err != nil {
			LogError("PPROF: pprof server shutdown failed: %v", err)
		} else {
			LogInfo("PPROF: pprof server shut down successfully")
		}
		cancel()
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		s.wg.Wait()
	}()

	select {
	case <-done:
		LogInfo("SERVER: All components shut down")
	case <-time.After(ShutdownTimeout):
		LogWarn("SERVER: Component shutdown timeout")
	}

	if s.shutdown != nil {
		close(s.shutdown)
	}

	time.Sleep(100 * time.Millisecond)
	os.Exit(0)
}

func (s *DNSServer) Start() error {
	if atomic.LoadInt32(&s.closed) != 0 {
		return errors.New("server is closed")
	}

	var wg sync.WaitGroup
	serverCount := 2
	if s.securityMgr.tls != nil {
		serverCount++
	}
	if s.pprofServer != nil {
		serverCount++
	}

	errChan := make(chan error, serverCount)

	LogInfo("SERVER: Starting ZJDNS Server %s", getVersion())
	LogInfo("SERVER: Listening port: %s", s.config.Server.Port)

	s.displayInfo()

	wg.Add(serverCount)

	go func() {
		defer wg.Done()
		defer handlePanic("Critical-UDP server")
		server := &dns.Server{
			Addr:    ":" + s.config.Server.Port,
			Net:     "udp",
			Handler: dns.HandlerFunc(s.handleDNSRequest),
			UDPSize: UDPBufferSize,
		}
		LogInfo("DNS: UDP server started: [::]:%s", s.config.Server.Port)
		if err := server.ListenAndServe(); err != nil {
			errChan <- fmt.Errorf("UDP startup: %w", err)
		}
	}()

	// Start pprof server if configured
	if s.pprofServer != nil {
		go func() {
			defer wg.Done()
			defer handlePanic("Critical-pprof server")
			LogInfo("PPROF: pprof server started: [::]:%s", s.config.Server.Pprof)
			var err error
			if s.pprofServer.TLSConfig != nil {
				// Start HTTPS server using existing TLS config
				err = s.pprofServer.ListenAndServeTLS("", "") // Cert and key are in TLSConfig
			} else {
				// Start HTTP server
				err = s.pprofServer.ListenAndServe()
			}

			if err != nil && err != http.ErrServerClosed {
				errChan <- fmt.Errorf("pprof startup: %w", err)
			}
		}()
	}

	go func() {
		defer wg.Done()
		defer handlePanic("Critical-TCP server")
		server := &dns.Server{
			Addr:    ":" + s.config.Server.Port,
			Net:     "tcp",
			Handler: dns.HandlerFunc(s.handleDNSRequest),
		}
		LogInfo("DNS: TCP server started: [::]:%s", s.config.Server.Port)
		if err := server.ListenAndServe(); err != nil {
			errChan <- fmt.Errorf("TCP startup: %w", err)
		}
	}()

	if s.securityMgr.tls != nil {
		go func() {
			defer wg.Done()
			defer handlePanic("Critical-Secure DNS server")
			httpsPort := s.config.Server.TLS.HTTPS.Port
			if err := s.securityMgr.tls.Start(httpsPort); err != nil {
				errChan <- fmt.Errorf("secure DNS startup: %w", err)
			}
		}()
	}

	go func() {
		wg.Wait()
		close(errChan)
	}()

	for err := range errChan {
		if err != nil {
			return err
		}
	}

	<-s.shutdown
	return nil
}

func (s *DNSServer) displayInfo() {
	servers := s.queryMgr.upstream.getServers()
	if len(servers) > 0 {
		for _, server := range servers {
			if server.IsRecursive() {
				info := "Upstream server: recursive resolution"
				if len(server.Match) > 0 {
					info += fmt.Sprintf(" [CIDR match: %v]", server.Match)
				}
				LogInfo("UPSTREAM: %s", info)
			} else {
				protocol := strings.ToUpper(server.Protocol)
				if protocol == "" {
					protocol = "UDP"
				}
				serverInfo := fmt.Sprintf("%s (%s)", server.Address, protocol)
				if server.SkipTLSVerify && isSecureProtocol(strings.ToLower(server.Protocol)) {
					serverInfo += " [Skip TLS verification]"
				}
				if len(server.Match) > 0 {
					serverInfo += fmt.Sprintf(" [CIDR match: %v]", server.Match)
				}
				LogInfo("UPSTREAM: Upstream server: %s", serverInfo)
			}
		}
		LogInfo("UPSTREAM: Upstream mode: total %d servers", len(servers))
	} else {
		if s.config.Redis.Address == "" {
			LogInfo("RECURSION: Recursive mode (no cache)")
		} else {
			LogInfo("RECURSION: Recursive mode + Redis cache: %s", s.config.Redis.Address)
		}
	}

	if s.cidrMgr != nil && len(s.config.CIDR) > 0 {
		LogInfo("CIDR: CIDR Manager: enabled (%d rules)", len(s.config.CIDR))
	}

	if s.pprofServer != nil {
		LogInfo("PPROF: pprof server enabled on: %s, via: %s, tls: %t", s.config.Server.Pprof, PprofPath, s.pprofServer.TLSConfig != nil)
	}

	if s.securityMgr.tls != nil {
		LogInfo("TLS: Listening secure DNS port: %s (DoT/DoQ)", s.config.Server.TLS.Port)
		httpsPort := s.config.Server.TLS.HTTPS.Port
		if httpsPort != "" {
			endpoint := s.config.Server.TLS.HTTPS.Endpoint
			if endpoint == "" {
				endpoint = strings.TrimPrefix(DefaultQueryPath, "/")
			}
			LogInfo("TLS: Listening secure DNS port: %s (DoH/DoH3, endpoint: %s)", httpsPort, endpoint)
		}
	}

	if s.rewriteMgr.hasRules() {
		LogInfo("REWRITE: DNS rewriter: enabled (%d rules)", len(s.config.Rewrite))
	}
	if s.config.Server.Features.HijackProtection {
		LogInfo("HIJACK: DNS hijacking prevention: enabled")
	}
	if defaultECS := s.ednsMgr.GetDefaultECS(); defaultECS != nil {
		LogInfo("EDNS: Default ECS: %s/%d", defaultECS.Address, defaultECS.SourcePrefix)
	}

	if len(s.config.SpeedTest) > 0 {
		if s.redisClient != nil {
			LogInfo("SPEEDTEST: SpeedTest: enabled (with Redis debouncing)")
		} else {
			LogInfo("SPEEDTEST: SpeedTest: enabled (no debouncing)")
		}
	}

	if s.rootServerMgr.needsSpeed {
		LogInfo("SPEEDTEST: Root server speed testing: enabled")
	}
}

func (s *DNSServer) handleDNSRequest(w dns.ResponseWriter, req *dns.Msg) {
	defer handlePanic("DNS request processing")

	select {
	case <-s.ctx.Done():
		return
	default:
	}

	response := s.processDNSQuery(req, getClientIP(w), false)
	if response != nil {
		response.Compress = true
		_ = w.WriteMsg(response)
	}
}

func (s *DNSServer) processDNSQuery(req *dns.Msg, clientIP net.IP, isSecureConnection bool) *dns.Msg {
	if atomic.LoadInt32(&s.closed) != 0 {
		msg := s.buildResponse(req)
		if msg != nil {
			msg.Rcode = dns.RcodeServerFailure
		}
		return msg
	}

	if req == nil || len(req.Question) == 0 {
		msg := &dns.Msg{}
		if req != nil && len(req.Question) > 0 {
			msg.SetReply(req)
		} else {
			msg.Response = true
		}
		msg.Rcode = dns.RcodeFormatError
		return msg
	}

	question := req.Question[0]

	if len(question.Name) > MaxDomainLength || question.Qtype == dns.TypeANY {
		msg := &dns.Msg{}
		msg.SetReply(req)
		msg.Rcode = dns.RcodeRefused
		return msg
	}

	var tracker *RequestTracker
	if globalLog.GetLevel() >= Debug {
		clientIPStr := "unknown"
		if clientIP != nil {
			clientIPStr = clientIP.String()
		}
		tracker = NewRequestTracker(question.Name, dns.TypeToString[question.Qtype], clientIPStr)
		if tracker != nil {
			defer tracker.Finish()
		}
	}

	// Check rewrite rules
	if s.rewriteMgr.hasRules() {
		rewriteResult := s.rewriteMgr.RewriteWithDetails(question.Name, question.Qtype)
		if rewriteResult.ShouldRewrite {
			if rewriteResult.ResponseCode != dns.RcodeSuccess {
				response := s.buildResponse(req)
				response.Rcode = rewriteResult.ResponseCode
				s.addEDNS(response, req, isSecureConnection)
				return response
			}

			if len(rewriteResult.Records) > 0 {
				response := s.buildResponse(req)
				response.Answer = rewriteResult.Records
				response.Rcode = dns.RcodeSuccess
				if len(rewriteResult.Additional) > 0 {
					response.Extra = rewriteResult.Additional
				}
				s.addEDNS(response, req, isSecureConnection)
				return response
			}

			if rewriteResult.Domain != question.Name {
				question.Name = rewriteResult.Domain
			}
		}
	}

	clientRequestedDNSSEC := false
	clientHasEDNS := false
	var ecsOpt *ECSOption

	if opt := req.IsEdns0(); opt != nil {
		clientHasEDNS = true
		clientRequestedDNSSEC = opt.Do()
		ecsOpt = s.ednsMgr.ParseFromDNS(req)
	}

	if ecsOpt == nil {
		ecsOpt = s.ednsMgr.GetDefaultECS()
	}

	cacheKey := buildCacheKey(question, ecsOpt, s.config.Redis.KeyPrefix)

	if entry, found, isExpired := s.cacheMgr.Get(cacheKey); found {
		return s.processCacheHit(req, entry, isExpired, question, clientRequestedDNSSEC, clientHasEDNS, ecsOpt, cacheKey, tracker, isSecureConnection)
	}

	return s.processCacheMiss(req, question, ecsOpt, clientRequestedDNSSEC, clientHasEDNS, cacheKey, tracker, isSecureConnection)
}

func (s *DNSServer) processCacheHit(req *dns.Msg, entry *CacheEntry, isExpired bool, question dns.Question, clientRequestedDNSSEC bool, _ bool, ecsOpt *ECSOption, cacheKey string, _ *RequestTracker, isSecureConnection bool) *dns.Msg {
	// Calculate response TTL
	responseTTL := entry.GetRemainingTTL()

	msg := s.buildResponse(req)
	if msg == nil {
		msg = &dns.Msg{}
		msg.SetReply(req)
		msg.Rcode = dns.RcodeServerFailure
		return msg
	}

	msg.Answer = processRecords(expandRecords(entry.Answer), responseTTL, clientRequestedDNSSEC)
	msg.Ns = processRecords(expandRecords(entry.Authority), responseTTL, clientRequestedDNSSEC)
	msg.Extra = processRecords(expandRecords(entry.Additional), responseTTL, clientRequestedDNSSEC)

	if entry.Validated {
		msg.AuthenticatedData = true
	}

	s.addEDNS(msg, req, isSecureConnection)

	// ✅ 修复：使用 RefreshTracker 防止重复刷新
	if isExpired && entry.ShouldRefresh() {
		refreshInterval := time.Duration(entry.OriginalTTL) * time.Second
		if s.cacheMgr.(*RedisCache).refreshTracker.TryStartRefresh(cacheKey, refreshInterval) {
			s.taskMgr.ExecuteAsync(
				fmt.Sprintf("refresh-%s", cacheKey),
				func(ctx context.Context) error {
					defer s.cacheMgr.(*RedisCache).refreshTracker.EndRefresh(cacheKey)
					return s.refreshCacheEntry(ctx, question, ecsOpt, cacheKey, entry)
				},
			)
		}
	}

	s.restoreOriginalDomain(msg, req.Question[0].Name, question.Name)

	if isExpired {
		LogDebug("CACHE: Returned stale cache for %s (TTL: %d)", question.Name, responseTTL)
	}

	return msg
}

func (s *DNSServer) processCacheMiss(req *dns.Msg, question dns.Question, ecsOpt *ECSOption, clientRequestedDNSSEC bool, clientHasEDNS bool, cacheKey string, tracker *RequestTracker, isSecureConnection bool) *dns.Msg {
	// Execute query directly
	answer, authority, additional, validated, ecsResponse, err := s.queryMgr.Query(
		question, ecsOpt, tracker)

	if err != nil {
		return s.processQueryError(req, err, cacheKey, question,
			clientRequestedDNSSEC, clientHasEDNS, ecsOpt, tracker, isSecureConnection)
	}

	return s.processQuerySuccess(req, question, ecsOpt, clientRequestedDNSSEC,
		clientHasEDNS, cacheKey, answer, authority, additional,
		validated, ecsResponse, tracker, isSecureConnection)
}

func (s *DNSServer) refreshCacheEntry(ctx context.Context, question dns.Question,
	ecs *ECSOption, cacheKey string, oldEntry *CacheEntry) error {

	defer handlePanic("cache refresh")

	if atomic.LoadInt32(&s.closed) != 0 {
		return errors.New("server closed")
	}

	LogDebug("CACHE: Starting background refresh for %s", cacheKey)

	// Execute query with timeout
	_, cancel := context.WithTimeout(ctx, QueryTimeout)
	defer cancel()

	answer, authority, additional, validated, ecsResponse, err := s.queryMgr.Query(
		question, ecs, nil)

	if err != nil {
		LogDebug("CACHE: Refresh failed for %s: %v", cacheKey, err)
		s.updateCacheRefreshTime(cacheKey, oldEntry)
		return err
	}

	LogDebug("CACHE: Refresh succeeded for %s", cacheKey)

	// Speed test if configured
	if len(s.config.SpeedTest) > 0 &&
		(question.Qtype == dns.TypeA || question.Qtype == dns.TypeAAAA) {
		tempMsg := &dns.Msg{Answer: answer, Ns: authority, Extra: additional}
		domainSpeedPrefix := s.config.Redis.KeyPrefix + RedisPrefixSpeedTestDomain
		speedTester := NewSpeedTestManager(*s.config, s.redisClient, domainSpeedPrefix)
		speedTester.performSpeedTestAndSort(tempMsg)
		_ = speedTester.Close()
		answer, authority, additional = tempMsg.Answer, tempMsg.Ns, tempMsg.Extra
	}

	// Update cache
	s.cacheMgr.Set(cacheKey, answer, authority, additional, validated, ecsResponse)

	return nil
}

func (s *DNSServer) updateCacheRefreshTime(cacheKey string, _ *CacheEntry) {
	defer handlePanic("Update refresh time")

	redisCache, ok := s.cacheMgr.(*RedisCache)
	if !ok || atomic.LoadInt32(&redisCache.closed) != 0 {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), RedisReadTimeout)
	defer cancel()

	data, err := redisCache.client.Get(ctx, cacheKey).Result()
	if err != nil {
		return
	}

	var currentEntry CacheEntry
	if err := json.Unmarshal([]byte(data), &currentEntry); err != nil {
		return
	}

	currentEntry.RefreshTime = time.Now().Unix()

	updatedData, err := json.Marshal(currentEntry)
	if err != nil {
		return
	}

	writeCtx, writeCancel := context.WithTimeout(context.Background(), RedisWriteTimeout)
	defer writeCancel()

	redisCache.client.Set(writeCtx, cacheKey, updatedData, redis.KeepTTL)
	LogDebug("CACHE: Updated refresh time for %s (keeping stale data)", cacheKey)
}

func (s *DNSServer) processQueryError(req *dns.Msg, _ error, cacheKey string,
	question dns.Question, clientRequestedDNSSEC bool, _ bool,
	_ *ECSOption, _ *RequestTracker, isSecureConnection bool) *dns.Msg {

	// Try to return stale cache on query error
	if entry, found, _ := s.cacheMgr.Get(cacheKey); found {
		LogDebug("CACHE: Query failed, returning stale cache for %s", question.Name)

		msg := s.buildResponse(req)
		if msg == nil {
			msg = &dns.Msg{}
			msg.SetReply(req)
			msg.Rcode = dns.RcodeServerFailure
			return msg
		}

		responseTTL := uint32(StaleTTL)
		msg.Answer = processRecords(expandRecords(entry.Answer), responseTTL, clientRequestedDNSSEC)
		msg.Ns = processRecords(expandRecords(entry.Authority), responseTTL, clientRequestedDNSSEC)
		msg.Extra = processRecords(expandRecords(entry.Additional), responseTTL, clientRequestedDNSSEC)

		if entry.Validated {
			msg.AuthenticatedData = true
		}

		s.addEDNS(msg, req, isSecureConnection)
		s.restoreOriginalDomain(msg, req.Question[0].Name, question.Name)
		return msg
	}

	// No stale cache available
	LogDebug("CACHE: No stale cache available after query error for %s", question.Name)
	msg := s.buildResponse(req)
	if msg == nil {
		msg = &dns.Msg{}
		msg.SetReply(req)
	}
	msg.Rcode = dns.RcodeServerFailure
	return msg
}

func (s *DNSServer) processQuerySuccess(req *dns.Msg, question dns.Question, ecsOpt *ECSOption, clientRequestedDNSSEC bool, _ bool, cacheKey string, answer, authority, additional []dns.RR, validated bool, ecsResponse *ECSOption, _ *RequestTracker, isSecureConnection bool) *dns.Msg {
	msg := s.buildResponse(req)
	if msg == nil {
		msg = &dns.Msg{}
		msg.SetReply(req)
	}

	if validated {
		msg.AuthenticatedData = true
	}

	responseECS := ecsResponse
	if responseECS == nil && ecsOpt != nil {
		responseECS = &ECSOption{
			Family:       ecsOpt.Family,
			SourcePrefix: ecsOpt.SourcePrefix,
			ScopePrefix:  ecsOpt.ScopePrefix,
			Address:      ecsOpt.Address,
		}
	}

	s.cacheMgr.Set(cacheKey, answer, authority, additional, validated, responseECS)

	msg.Answer = processRecords(answer, 0, clientRequestedDNSSEC)
	msg.Ns = processRecords(authority, 0, clientRequestedDNSSEC)
	msg.Extra = processRecords(additional, 0, clientRequestedDNSSEC)

	if len(s.config.SpeedTest) > 0 {
		shouldPerformSpeedTest := s.shouldPerformSpeedTest(question.Name)
		if shouldPerformSpeedTest {
			msgCopy := copyMessage(msg)
			if msgCopy != nil {
				s.taskMgr.ExecuteAsync(fmt.Sprintf("speed-test-%s", question.Name), func(ctx context.Context) error {
					defer releaseMessage(msgCopy)

					domainSpeedPrefix := s.config.Redis.KeyPrefix + RedisPrefixSpeedTestDomain
					speedTester := NewSpeedTestManager(*s.config, s.redisClient, domainSpeedPrefix)
					defer func() { _ = speedTester.Close() }()

					speedTester.performSpeedTestAndSort(msgCopy)

					s.cacheMgr.Set(cacheKey, msgCopy.Answer, msgCopy.Ns, msgCopy.Extra, validated, responseECS)
					return nil
				})
			}
		}
	}

	s.addEDNS(msg, req, isSecureConnection)
	s.restoreOriginalDomain(msg, req.Question[0].Name, question.Name)
	return msg
}

func (s *DNSServer) addEDNS(msg *dns.Msg, req *dns.Msg, isSecureConnection bool) {
	if msg == nil || req == nil {
		return
	}

	clientRequestedDNSSEC := false
	var ecsOpt *ECSOption

	if opt := req.IsEdns0(); opt != nil {
		clientRequestedDNSSEC = opt.Do()
		ecsOpt = s.ednsMgr.ParseFromDNS(req)
	}

	if ecsOpt == nil {
		ecsOpt = s.ednsMgr.GetDefaultECS()
	}

	shouldAddEDNS := ecsOpt != nil || clientRequestedDNSSEC || true // padding always enabled

	if shouldAddEDNS {
		s.ednsMgr.AddToMessage(msg, ecsOpt, clientRequestedDNSSEC, isSecureConnection)
	}
}

func (s *DNSServer) buildResponse(req *dns.Msg) *dns.Msg {
	msg := acquireMessage()
	if msg == nil {
		msg = &dns.Msg{}
	}

	if req != nil && len(req.Question) > 0 {
		msg.SetReply(req)
	} else if req != nil {
		msg.Response = true
		msg.Rcode = dns.RcodeFormatError
	}

	msg.Authoritative = false
	msg.RecursionAvailable = true
	msg.Compress = true
	return msg
}

func (s *DNSServer) restoreOriginalDomain(msg *dns.Msg, currentName, originalName string) {
	if msg == nil {
		return
	}
	for _, rr := range msg.Answer {
		if rr != nil && strings.EqualFold(rr.Header().Name, currentName) {
			rr.Header().Name = originalName
		}
	}
}

func (s *DNSServer) shouldPerformSpeedTest(domain string) bool {
	if len(s.config.SpeedTest) == 0 {
		return false
	}

	if s.redisClient == nil {
		LogDebug("SPEEDTEST: No Redis, performing speed test for %s", domain)
		return true
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	debounceKey := s.config.Redis.KeyPrefix + RedisPrefixSpeedTestDebounce + domain

	success, err := s.redisClient.SetNX(ctx, debounceKey, "1", s.speedInterval).Result()
	if err != nil {
		LogDebug("SPEEDTEST: Redis debounce check failed for %s: %v, performing test", domain, err)
		return true
	}

	if success {
		LogDebug("SPEEDTEST: Debounce passed for %s, performing speed test", domain)
		return true
	}

	LogDebug("SPEEDTEST: Domain %s in debounce period, skipping speed test", domain)
	return false
}

func (s *DNSServer) buildQueryMessage(question dns.Question, ecs *ECSOption, recursionDesired bool, isSecureConnection bool) *dns.Msg {
	msg := acquireMessage()
	if msg == nil {
		msg = &dns.Msg{}
	}

	msg.SetQuestion(dns.Fqdn(question.Name), question.Qtype)
	msg.RecursionDesired = recursionDesired

	if s.ednsMgr != nil {
		s.ednsMgr.AddToMessage(msg, ecs, true, isSecureConnection) // DNSSEC always enabled
	}

	return msg
}

// =============================================================================
// Utility Functions
// =============================================================================

func getVersion() string {
	return fmt.Sprintf("v%s-ZHIJIE-%s@%s", Version, CommitHash, BuildTime)
}

func normalizeDomain(domain string) string {
	return strings.ToLower(strings.TrimSuffix(domain, "."))
}

func isSecureProtocol(protocol string) bool {
	switch protocol {
	case "tls", "quic", "https", "http3":
		return true
	default:
		return false
	}
}

func isValidFilePath(path string) bool {
	if strings.Contains(path, "..") ||
		strings.HasPrefix(path, "/etc/") ||
		strings.HasPrefix(path, "/proc/") ||
		strings.HasPrefix(path, "/sys/") {
		return false
	}

	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

func handlePanic(operation string) {
	if r := recover(); r != nil {
		buf := make([]byte, 2048)
		n := runtime.Stack(buf, false)
		stackTrace := string(buf[:n])
		LogError("PANIC: Panic [%s]: %v\nStack:\n%s\nExiting due to panic", operation, r, stackTrace)
		os.Exit(1)
	}
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

func getSecureClientIP(conn any) net.IP {
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

func closeWithLog(c Closeable, name string) {
	if c == nil {
		return
	}
	if err := c.Close(); err != nil {
		LogWarn("SERVER: Close %s failed: %v", name, err)
	}
}

func createCompactRecord(rr dns.RR) *CompactRecord {
	if rr == nil {
		return nil
	}
	return &CompactRecord{
		Text:    rr.String(),
		OrigTTL: rr.Header().Ttl,
		Type:    rr.Header().Rrtype,
	}
}

func expandRecord(cr *CompactRecord) dns.RR {
	if cr == nil || cr.Text == "" {
		return nil
	}
	rr, _ := dns.NewRR(cr.Text)
	return rr
}

func compactRecords(rrs []dns.RR) []*CompactRecord {
	if len(rrs) == 0 {
		return nil
	}

	seen := make(map[string]bool, len(rrs))
	result := make([]*CompactRecord, 0, len(rrs))

	for _, rr := range rrs {
		if rr == nil || rr.Header().Rrtype == dns.TypeOPT {
			continue
		}

		rrText := rr.String()
		if !seen[rrText] {
			seen[rrText] = true
			if cr := createCompactRecord(rr); cr != nil {
				result = append(result, cr)
			}
		}
	}
	return result
}

func expandRecords(crs []*CompactRecord) []dns.RR {
	if len(crs) == 0 {
		return nil
	}
	result := make([]dns.RR, 0, len(crs))
	for _, cr := range crs {
		if rr := expandRecord(cr); rr != nil {
			result = append(result, rr)
		}
	}
	return result
}

func processRecords(rrs []dns.RR, ttl uint32, includeDNSSEC bool) []dns.RR {
	if len(rrs) == 0 {
		return nil
	}

	result := make([]dns.RR, 0, len(rrs))
	for _, rr := range rrs {
		if rr == nil {
			continue
		}

		if !includeDNSSEC {
			switch rr.(type) {
			case *dns.RRSIG, *dns.NSEC, *dns.NSEC3, *dns.DNSKEY, *dns.DS:
				continue
			}
		}

		newRR := dns.Copy(rr)
		if newRR != nil {
			if ttl > 0 {
				newRR.Header().Ttl = ttl
			}
			result = append(result, newRR)
		}
	}
	return result
}

func buildCacheKey(question dns.Question, ecs *ECSOption, globalPrefix string) string {
	key := globalPrefix + RedisPrefixDNS +
		fmt.Sprintf("%s:%d:%d", normalizeDomain(question.Name), question.Qtype, question.Qclass)

	if ecs != nil {
		key += fmt.Sprintf(":%s/%d", ecs.Address.String(), ecs.SourcePrefix)
	}

	// DNSSEC is always enabled
	key += ":dnssec"

	if len(key) > 512 {
		key = fmt.Sprintf("hash:%x", key)[:512]
	}
	return key
}

func calculateTTL(rrs []dns.RR) int {
	if len(rrs) == 0 {
		return DefaultCacheTTL
	}

	minTTL := int(rrs[0].Header().Ttl)
	for _, rr := range rrs {
		if rr == nil {
			continue
		}
		if ttl := int(rr.Header().Ttl); ttl > 0 && (minTTL == 0 || ttl < minTTL) {
			minTTL = ttl
		}
	}

	if minTTL <= 0 {
		minTTL = DefaultCacheTTL
	}

	return minTTL
}

func extractIPsFromServers(servers []string) []string {
	ips := make([]string, len(servers))
	for i, server := range servers {
		host, _, err := net.SplitHostPort(server)
		if err != nil {
			ips[i] = server
		} else {
			ips[i] = host
		}
	}
	return ips
}

func sortBySpeedResultWithLatency(servers []string, results map[string]*SpeedResult) []RootServerWithLatency {
	serverList := make([]RootServerWithLatency, len(servers))

	for i, server := range servers {
		host, _, _ := net.SplitHostPort(server)
		if result, exists := results[host]; exists && result.Reachable {
			serverList[i] = RootServerWithLatency{
				Server:    server,
				Latency:   result.Latency,
				Reachable: true,
			}
		} else {
			serverList[i] = RootServerWithLatency{
				Server:    server,
				Latency:   UnreachableLatency,
				Reachable: false,
			}
		}
	}

	sort.Slice(serverList, func(i, j int) bool {
		if serverList[i].Reachable != serverList[j].Reachable {
			return serverList[i].Reachable
		}
		return serverList[i].Latency < serverList[j].Latency
	})

	return serverList
}

func toRRSlice[T dns.RR](records []T) []dns.RR {
	result := make([]dns.RR, len(records))
	for i, r := range records {
		result[i] = r
	}
	return result
}

var messagePool = sync.Pool{
	New: func() any {
		return &dns.Msg{}
	},
}

func acquireMessage() *dns.Msg {
	msg := messagePool.Get().(*dns.Msg)
	msg.Question = msg.Question[:0]
	msg.Answer = msg.Answer[:0]
	msg.Ns = msg.Ns[:0]
	msg.Extra = msg.Extra[:0]
	return msg
}

func releaseMessage(msg *dns.Msg) {
	if msg != nil {
		// ✅ 修复：限制 slice 容量，防止大对象占用内存
		if cap(msg.Question) > MaxMessageCap {
			msg.Question = make([]dns.Question, 0, 10)
		} else {
			msg.Question = msg.Question[:0]
		}

		if cap(msg.Answer) > MaxMessageCap {
			msg.Answer = make([]dns.RR, 0, 10)
		} else {
			msg.Answer = msg.Answer[:0]
		}

		if cap(msg.Ns) > MaxMessageCap {
			msg.Ns = make([]dns.RR, 0, 10)
		} else {
			msg.Ns = msg.Ns[:0]
		}

		if cap(msg.Extra) > MaxMessageCap {
			msg.Extra = make([]dns.RR, 0, 10)
		} else {
			msg.Extra = msg.Extra[:0]
		}

		messagePool.Put(msg)
	}
}

func copyMessage(msg *dns.Msg) *dns.Msg {
	if msg == nil {
		return nil
	}

	msgCopy := acquireMessage()
	msgCopy.MsgHdr = msg.MsgHdr
	msgCopy.Compress = msg.Compress

	if msg.Question != nil {
		msgCopy.Question = append(msgCopy.Question[:0], msg.Question...)
	}

	for _, rr := range msg.Answer {
		if rr != nil {
			msgCopy.Answer = append(msgCopy.Answer, dns.Copy(rr))
		}
	}

	for _, rr := range msg.Ns {
		if rr != nil {
			msgCopy.Ns = append(msgCopy.Ns, dns.Copy(rr))
		}
	}

	for _, rr := range msg.Extra {
		if rr != nil {
			msgCopy.Extra = append(msgCopy.Extra, dns.Copy(rr))
		}
	}

	return msgCopy
}

// =============================================================================
// Main Function
// =============================================================================

func main() {
	var configFile string
	var generateConfig bool
	var showVersion bool

	flag.StringVar(&configFile, "config", "", "Configuration file path (JSON format)")
	flag.BoolVar(&generateConfig, "generate-config", false, "Generate example configuration file")
	flag.BoolVar(&showVersion, "version", false, "Show version information and exit")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "ZJDNS Server - High Performance Recursive DNS Server\n\n")
		fmt.Fprintf(os.Stderr, "Version: %s\n\n", getVersion())
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  %s -config <config file>     # Start with config file\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -generate-config          # Generate example config\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -version                  # Show version information\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s                            # Start with default config\n\n", os.Args[0])
	}

	flag.Parse()

	if showVersion {
		fmt.Printf("ZJDNS Server\n")
		fmt.Printf("Version: %s\n", getVersion())
		return
	}

	if generateConfig {
		fmt.Println(GenerateExampleConfig())
		return
	}

	cm := &ConfigManager{}
	config, err := cm.LoadConfig(configFile)
	if err != nil {
		log.Fatalf("Config load failed: %v", err)
	}

	server, err := NewDNSServer(config)
	if err != nil {
		log.Fatalf("Server creation failed: %v", err)
	}

	LogInfo("SERVER: ZJDNS Server started successfully!")

	if err := server.Start(); err != nil {
		log.Fatalf("Server startup failed: %v", err)
	}
}
