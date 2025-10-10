// Package main implements a high-performance DNS server supporting
// recursive resolution, caching, and secure DNS protocols (DoT/DoH/DoQ).
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
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

	"github.com/dgraph-io/ristretto/v2"
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
	Version    = "1.0.0"
	CommitHash = "dirty"
	BuildTime  = "dev"

	// Network
	DefaultDNSPort   = "53"
	DefaultTLSPort   = "853"
	DefaultHTTPSPort = "443"

	// Protocol
	RecursiveIndicator = "builtin_recursive"
	DefaultQueryPath   = "/dns-query"

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

	// Timeouts
	QueryTimeout         = 5 * time.Second
	RecursiveTimeout     = 10 * time.Second
	ConnTimeout          = 5 * time.Second
	TLSHandshakeTimeout  = 3 * time.Second
	PublicIPTimeout      = 3 * time.Second
	HTTPClientTimeout    = 5 * time.Second
	ShutdownTimeout      = 3 * time.Second
	DoHReadHeaderTimeout = 5 * time.Second
	DoHWriteTimeout      = 5 * time.Second
	SecureIdleTimeout    = 300 * time.Second
	DoHIdleConnTimeout   = 300 * time.Second

	// Cache
	DefaultCacheTTL = 10
	StaleTTL        = 30
	StaleMaxAge     = 86400 * 30
	CacheQueueSize  = 500
	IPCacheExpiry   = 300 * time.Second

	// Redis
	RedisPoolSize     = 20
	RedisMinIdle      = 5
	RedisMaxRetries   = 3
	RedisPoolTimeout  = 5 * time.Second
	RedisReadTimeout  = 3 * time.Second
	RedisWriteTimeout = 3 * time.Second
	RedisDialTimeout  = 5 * time.Second

	// ECS
	DefaultECSv4Len = 24
	DefaultECSv6Len = 64
	DefaultECSScope = 0

	// Padding
	PaddingBlockSize = 468

	// DoH
	DoHMaxRequestSize  = 8192
	DoHMaxConnsPerHost = 5
	DoHMaxIdleConns    = 5

	// QUIC
	MaxIncomingStreams         = 2048
	QUICAddrValidatorCacheSize = 16 * 1024
	QUICAddrValidatorTTL       = 300 * time.Second

	// SpeedTest
	DefaultSpeedTimeout     = 250 * time.Millisecond
	DefaultSpeedConcurrency = 5
	UnreachableLatency      = 10 * time.Second
	DefaultSpeedCacheTTL    = 900 * time.Second
	SpeedDebounceInterval   = 10 * time.Second

	// Root Server
	RootServerSortInterval = 900 * time.Second

	// Defaults
	DefaultLogLevel = "info"

	// ANSI Colors
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorYellow = "\033[33m"
	ColorGreen  = "\033[32m"
	ColorCyan   = "\033[36m"
	ColorBold   = "\033[1m"
)

// QUIC Error Codes
const (
	QUICCodeNoError       quic.ApplicationErrorCode = 0
	QUICCodeInternalError quic.ApplicationErrorCode = 1
	QUICCodeProtocolError quic.ApplicationErrorCode = 2
)

var (
	NextProtoQUIC  = []string{"doq", "doq-i00", "doq-i02", "doq-i03", "dq"}
	NextProtoHTTP3 = []string{"h3"}
	NextProtoHTTP2 = []string{http2.NextProtoTLS, "http/1.1"}
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

// NewLogManager creates a new log manager
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

// SetLevel sets the logging level
func (lm *LogManager) SetLevel(level LogLevel) {
	lm.mu.Lock()
	defer lm.mu.Unlock()
	lm.level = level
}

// GetLevel returns current logging level
func (lm *LogManager) GetLevel() LogLevel {
	lm.mu.Lock()
	defer lm.mu.Unlock()
	return lm.level
}

// Log outputs a log message at the specified level
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
	Port     string        `json:"port"`
	CertFile string        `json:"cert_file"`
	KeyFile  string        `json:"key_file"`
	HTTPS    HTTPSSettings `json:"https"`
}

type HTTPSSettings struct {
	Port     string `json:"port"`
	Endpoint string `json:"endpoint"`
}

type FeatureFlags struct {
	ServeStale       bool `json:"serve_stale"`
	Prefetch         bool `json:"prefetch"`
	DNSSEC           bool `json:"dnssec"`
	HijackProtection bool `json:"hijack_protection"`
	Padding          bool `json:"padding"`
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

// IsRecursive checks if this server is configured for recursive resolution
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

// LoadConfig loads configuration from file or returns default config
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

	LogInfo("Configuration loaded successfully: %s", configFile)
	return config, nil
}

// validateConfig validates the configuration
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

	// Validate CIDR configs
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

	// Validate upstream servers
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
	} else {
		if config.Server.Features.ServeStale {
			LogWarn("No cache mode: serve stale disabled")
			config.Server.Features.ServeStale = false
		}
		if config.Server.Features.Prefetch {
			LogWarn("No cache mode: prefetch disabled")
			config.Server.Features.Prefetch = false
		}
	}

	// Validate TLS
	if config.Server.TLS.CertFile != "" || config.Server.TLS.KeyFile != "" {
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
		LogInfo("TLS certificate verified")
	}

	return nil
}

// getDefaultConfig returns default configuration
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
	config.Server.Features.DNSSEC = true
	config.Server.Features.HijackProtection = true
	config.Server.Features.Padding = true
	config.Redis.KeyPrefix = "zjdns:"
	return config
}

// shouldEnableDDR checks if DDR should be enabled
func (cm *ConfigManager) shouldEnableDDR(config *ServerConfig) bool {
	return config.Server.DDR.Domain != "" &&
		(config.Server.DDR.IPv4 != "" || config.Server.DDR.IPv6 != "")
}

// addDDRRecords adds DDR records to rewrite rules
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

// GenerateExampleConfig generates example configuration
func GenerateExampleConfig() string {
	cm := &ConfigManager{}
	config := cm.getDefaultConfig()

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

// CacheEntry represents a cached DNS response
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

// CompactRecord represents a compact DNS record
type CompactRecord struct {
	Text    string `json:"text"`
	OrigTTL uint32 `json:"orig_ttl"`
	Type    uint16 `json:"type"`
}

// RefreshRequest represents a cache refresh request
type RefreshRequest struct {
	Question            dns.Question
	ECS                 *ECSOption
	CacheKey            string
	ServerDNSSECEnabled bool
}

// IsExpired checks if cache entry is expired
func (c *CacheEntry) IsExpired() bool {
	return c != nil && time.Now().Unix()-c.Timestamp > int64(c.TTL)
}

// IsStale checks if cache entry is stale
func (c *CacheEntry) IsStale() bool {
	return c != nil && time.Now().Unix()-c.Timestamp > int64(c.TTL+StaleMaxAge)
}

// ShouldRefresh checks if cache entry should be refreshed
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

// GetRemainingTTL returns remaining TTL for cache entry
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
	staleCycle := staleElapsed % int64(StaleTTL)
	staleTTLRemaining := int64(StaleTTL) - staleCycle
	if staleTTLRemaining <= 0 {
		staleTTLRemaining = int64(StaleTTL)
	}
	return uint32(staleTTLRemaining)
}

// GetECSOption returns ECS option from cache entry
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

// CacheManager defines cache interface
type CacheManager interface {
	Get(key string) (*CacheEntry, bool, bool)
	Set(key string, answer, authority, additional []dns.RR, validated bool, ecs *ECSOption)
	RequestRefresh(req RefreshRequest)
	Closeable
}

// NullCache implements a no-op cache
type NullCache struct{}

// NewNullCache creates a new null cache
func NewNullCache() *NullCache {
	LogInfo("No cache mode")
	return &NullCache{}
}

func (nc *NullCache) Get(key string) (*CacheEntry, bool, bool) { return nil, false, false }
func (nc *NullCache) Set(key string, answer, authority, additional []dns.RR, validated bool, ecs *ECSOption) {
}
func (nc *NullCache) RequestRefresh(req RefreshRequest) {}
func (nc *NullCache) Close() error                      { return nil }

// RedisCache implements Redis-based cache
type RedisCache struct {
	client       *redis.Client
	config       *ServerConfig
	keyPrefix    string
	refreshQueue chan RefreshRequest
	ctx          context.Context
	cancel       context.CancelFunc
	taskMgr      *TaskManager
	server       *DNSServer
	wg           sync.WaitGroup
	closed       int32
}

// NewRedisCache creates a new Redis cache
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
		client:       rdb,
		config:       config,
		keyPrefix:    config.Redis.KeyPrefix,
		refreshQueue: make(chan RefreshRequest, CacheQueueSize),
		ctx:          cacheCtx,
		cancel:       cacheCancel,
		taskMgr:      NewTaskManager(10),
		server:       server,
	}

	if config.Server.Features.ServeStale && config.Server.Features.Prefetch {
		cache.startRefreshProcessor()
	}

	LogInfo("Redis cache initialized")
	return cache, nil
}

// startRefreshProcessor starts background refresh workers
func (rc *RedisCache) startRefreshProcessor() {
	for i := 0; i < 2; i++ {
		rc.wg.Add(1)
		go func(workerID int) {
			defer rc.wg.Done()
			defer handlePanic(fmt.Sprintf("Redis refresh worker %d", workerID))
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

// handleRefreshRequest handles a cache refresh request
func (rc *RedisCache) handleRefreshRequest(req RefreshRequest) {
	defer handlePanic("Redis refresh request")

	if atomic.LoadInt32(&rc.closed) != 0 {
		return
	}

	answer, authority, additional, validated, ecsResponse, err := rc.server.queryForRefresh(
		req.Question, req.ECS, req.ServerDNSSECEnabled)

	if err != nil {
		rc.updateRefreshTime(req.CacheKey)
		return
	}

	if len(rc.server.config.SpeedTest) > 0 &&
		(req.Question.Qtype == dns.TypeA || req.Question.Qtype == dns.TypeAAAA) {
		tempMsg := &dns.Msg{Answer: answer, Ns: authority, Extra: additional}
		speedTester := NewSpeedTestManager(*rc.server.config)
		speedTester.performSpeedTestAndSort(tempMsg)
		_ = speedTester.Close()
		answer, authority, additional = tempMsg.Answer, tempMsg.Ns, tempMsg.Extra
	}

	allRRs := make([]dns.RR, 0, len(answer)+len(authority)+len(additional))
	allRRs = append(append(append(allRRs, answer...), authority...), additional...)
	cacheTTL := calculateTTL(allRRs)
	now := time.Now().Unix()

	entry := &CacheEntry{
		Answer:      compactRecords(answer),
		Authority:   compactRecords(authority),
		Additional:  compactRecords(additional),
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
		expiration += time.Duration(StaleMaxAge) * time.Second
	}
	rc.client.Set(rc.ctx, fullKey, data, expiration)
}

// updateRefreshTime updates the refresh timestamp of a cache entry
func (rc *RedisCache) updateRefreshTime(cacheKey string) {
	defer handlePanic("Update refresh time")

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

// Get retrieves an entry from cache
func (rc *RedisCache) Get(key string) (*CacheEntry, bool, bool) {
	defer handlePanic("Redis cache get")

	if atomic.LoadInt32(&rc.closed) != 0 {
		LogDebug("CACHE: Redis cache is closed")
		return nil, false, false
	}

	fullKey := rc.keyPrefix + key
	LogDebug("CACHE: Getting key: %s", fullKey)
	data, err := rc.client.Get(rc.ctx, fullKey).Result()
	if err != nil {
		LogDebug("CACHE: Cache miss for key: %s (error: %v)", fullKey, err)
		return nil, false, false
	}

	var entry CacheEntry
	if err := json.Unmarshal([]byte(data), &entry); err != nil {
		LogDebug("CACHE: Corrupted cache entry for key: %s, deleting", fullKey)
		go func() {
			defer handlePanic("Clean corrupted cache")
			rc.client.Del(context.Background(), fullKey)
		}()
		return nil, false, false
	}

	LogDebug("CACHE: Cache hit for key: %s (expired: %v, TTL: %d, age: %ds)",
		fullKey, entry.IsExpired(), entry.TTL, time.Now().Unix()-entry.Timestamp)

	if entry.IsStale() {
		LogDebug("CACHE: Stale cache entry for key: %s, deleting", fullKey)
		go func() {
			defer handlePanic("Clean stale cache")
			rc.client.Del(context.Background(), fullKey)
		}()
		return nil, false, false
	}

	entry.AccessTime = time.Now().Unix()
	go func() {
		defer handlePanic("Update access time")
		rc.updateAccessInfo(fullKey, &entry)
	}()

	isExpired := entry.IsExpired()
	if !rc.config.Server.Features.ServeStale && isExpired {
		go func() {
			defer handlePanic("Clean expired cache")
			rc.client.Del(context.Background(), fullKey)
		}()
		return nil, false, false
	}

	return &entry, true, isExpired
}

// Set stores an entry in cache
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

	fullKey := rc.keyPrefix + key
	expiration := time.Duration(cacheTTL) * time.Second
	if rc.config.Server.Features.ServeStale {
		expiration += time.Duration(StaleMaxAge) * time.Second
	}
	rc.client.Set(rc.ctx, fullKey, data, expiration)
}

// updateAccessInfo updates access information in cache
func (rc *RedisCache) updateAccessInfo(fullKey string, entry *CacheEntry) {
	defer handlePanic("Redis access info update")

	if atomic.LoadInt32(&rc.closed) != 0 {
		return
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return
	}
	rc.client.Set(rc.ctx, fullKey, data, redis.KeepTTL)
}

// RequestRefresh requests a cache refresh
func (rc *RedisCache) RequestRefresh(req RefreshRequest) {
	if atomic.LoadInt32(&rc.closed) != 0 {
		return
	}
	select {
	case rc.refreshQueue <- req:
	default:
	}
}

// Close closes the Redis cache
func (rc *RedisCache) Close() error {
	if !atomic.CompareAndSwapInt32(&rc.closed, 0, 1) {
		return nil
	}

	LogInfo("Shutting down Redis cache...")

	if err := rc.taskMgr.Shutdown(ShutdownTimeout); err != nil {
		LogError("Task manager shutdown failed: %v", err)
	}

	rc.cancel()
	close(rc.refreshQueue)

	// Drain queue
	for {
		select {
		case <-rc.refreshQueue:
		default:
			goto drained
		}
	}

drained:
	done := make(chan struct{})
	go func() {
		rc.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(ShutdownTimeout):
	}

	if err := rc.client.Close(); err != nil {
		LogError("Redis client shutdown failed: %v", err)
	}

	LogInfo("Redis cache shut down")
	return nil
}

// =============================================================================
// CIDR Management
// =============================================================================

// CIDRManager manages CIDR-based filtering
type CIDRManager struct {
	rules map[string]*CIDRRule
	mu    sync.RWMutex
}

// CIDRRule represents a CIDR filtering rule
type CIDRRule struct {
	tag  string
	nets []*net.IPNet
}

// NewCIDRManager creates a new CIDR manager
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
		LogInfo("CIDR loaded: tag=%s, source=%s, total=%d", config.Tag, sourceInfo, len(rule.nets))
	}

	return cm, nil
}

// loadCIDRConfig loads CIDR configuration
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
			LogWarn("Invalid CIDR in rules[%d] for tag '%s': %s - %v", i, config.Tag, cidr, err)
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
				LogWarn("Invalid CIDR at %s:%d: %s - %v", config.File, lineNum, line, err)
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

// MatchIP checks if an IP matches a CIDR rule
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

// contains checks if IP is in rule's CIDR list
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

// ECSOption represents EDNS Client Subnet option
type ECSOption struct {
	Address      net.IP
	Family       uint16
	SourcePrefix uint8
	ScopePrefix  uint8
}

// EDNSManager manages EDNS options
type EDNSManager struct {
	defaultECS     *ECSOption
	detector       *IPDetector
	cache          sync.Map
	paddingEnabled bool
}

// NewEDNSManager creates a new EDNS manager
func NewEDNSManager(defaultSubnet string, paddingEnabled bool) (*EDNSManager, error) {
	manager := &EDNSManager{
		detector:       newIPDetector(),
		paddingEnabled: paddingEnabled,
	}

	if defaultSubnet != "" {
		ecs, err := manager.parseECSConfig(defaultSubnet)
		if err != nil {
			return nil, fmt.Errorf("parse ECS config: %w", err)
		}
		manager.defaultECS = ecs
		if ecs != nil {
			LogInfo("Default ECS: %s/%d", ecs.Address, ecs.SourcePrefix)
		}
	}

	if paddingEnabled {
		LogInfo("DNS Padding enabled (block size: %d bytes)", PaddingBlockSize)
	}

	return manager, nil
}

// GetDefaultECS returns default ECS option
func (em *EDNSManager) GetDefaultECS() *ECSOption {
	if em == nil {
		return nil
	}
	return em.defaultECS
}

// ParseFromDNS parses ECS from DNS message
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

// AddToMessage adds EDNS options to DNS message
func (em *EDNSManager) AddToMessage(msg *dns.Msg, ecs *ECSOption, dnssecEnabled bool, isSecureConnection bool) {
	if em == nil || msg == nil {
		return
	}

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

	if dnssecEnabled {
		opt.SetDo(true)
	}

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
	if em.paddingEnabled && isSecureConnection {
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
	} else if em.paddingEnabled {
		LogDebug("PADDING: Padding enabled but connection is not secure, skipping padding")
	} else {
		LogDebug("PADDING: Padding disabled")
	}

	opt.Option = options
	msg.Extra = append(msg.Extra, opt)
}

// parseECSConfig parses ECS configuration
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

// detectPublicIP detects public IP address
func (em *EDNSManager) detectPublicIP(forceIPv6, allowFallback bool) (*ECSOption, error) {
	cacheKey := fmt.Sprintf("ip_detection_%v_%v", forceIPv6, allowFallback)

	if cached, ok := em.cache.Load(cacheKey); ok {
		if cachedECS, ok := cached.(*ECSOption); ok {
			return cachedECS, nil
		}
	}

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

	if ecs != nil {
		em.cache.Store(cacheKey, ecs)
		time.AfterFunc(IPCacheExpiry, func() { em.cache.Delete(cacheKey) })
	}

	return ecs, nil
}

// IPDetector detects public IP
type IPDetector struct {
	httpClient *http.Client
}

// newIPDetector creates a new IP detector
func newIPDetector() *IPDetector {
	return &IPDetector{
		httpClient: &http.Client{Timeout: HTTPClientTimeout},
	}
}

// detectPublicIP detects public IP address
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

// RewriteManager manages DNS rewrite rules
type RewriteManager struct {
	rules []RewriteRule
	mu    sync.RWMutex
}

// DNSRewriteResult represents result of rewrite operation
type DNSRewriteResult struct {
	Domain        string
	ShouldRewrite bool
	ResponseCode  int
	Records       []dns.RR
	Additional    []dns.RR
}

// NewRewriteManager creates a new rewrite manager
func NewRewriteManager() *RewriteManager {
	return &RewriteManager{rules: make([]RewriteRule, 0, 32)}
}

// LoadRules loads rewrite rules
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
	LogInfo("DNS rewriter loaded: %d rules", len(validRules))
	return nil
}

// RewriteWithDetails performs rewrite with detailed result
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

// buildDNSRecord builds a DNS record from configuration
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

// hasRules checks if rewrite rules exist
func (rm *RewriteManager) hasRules() bool {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	return len(rm.rules) > 0
}

// =============================================================================
// SpeedTest Management
// =============================================================================

// SpeedTestManager manages speed testing
type SpeedTestManager struct {
	timeout     time.Duration
	concurrency int
	cache       map[string]*SpeedResult
	cacheMutex  sync.RWMutex
	cacheTTL    time.Duration
	icmpConn4   *icmp.PacketConn
	icmpConn6   *icmp.PacketConn
	methods     []SpeedTestMethod
}

// SpeedResult represents speed test result
type SpeedResult struct {
	IP        string
	Latency   time.Duration
	Reachable bool
	Timestamp time.Time
}

// NewSpeedTestManager creates a new speed test manager
func NewSpeedTestManager(config ServerConfig) *SpeedTestManager {
	st := &SpeedTestManager{
		timeout:     DefaultSpeedTimeout,
		concurrency: DefaultSpeedConcurrency,
		cache:       make(map[string]*SpeedResult),
		cacheTTL:    DefaultSpeedCacheTTL,
		methods:     config.SpeedTest,
	}
	st.initICMP()
	return st
}

// initICMP initializes ICMP connections
func (st *SpeedTestManager) initICMP() {
	if conn4, err := icmp.ListenPacket("ip4:icmp", ""); err == nil {
		st.icmpConn4 = conn4
	}
	if conn6, err := icmp.ListenPacket("ip6:ipv6-icmp", ""); err == nil {
		st.icmpConn6 = conn6
	}
}

// Close closes speed test resources
func (st *SpeedTestManager) Close() error {
	if st.icmpConn4 != nil {
		_ = st.icmpConn4.Close()
	}
	if st.icmpConn6 != nil {
		_ = st.icmpConn6.Close()
	}
	return nil
}

// performSpeedTestAndSort performs speed test and sorts records
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

// sortARecords sorts A records by latency
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

// sortAAAARecords sorts AAAA records by latency
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

// speedTest performs speed test on IPs
func (st *SpeedTestManager) speedTest(ips []string) map[string]*SpeedResult {
	cachedResults := make(map[string]*SpeedResult)
	remainingIPs := []string{}

	LogDebug("SPEEDTEST: Testing %d IPs for speed", len(ips))
	st.cacheMutex.RLock()
	now := time.Now()
	for _, ip := range ips {
		if result, exists := st.cache[ip]; exists && now.Sub(result.Timestamp) < st.cacheTTL {
			cachedResults[ip] = result
		} else {
			remainingIPs = append(remainingIPs, ip)
		}
	}
	st.cacheMutex.RUnlock()

	LogDebug("SPEEDTEST: Found %d cached results, testing %d remaining IPs", len(cachedResults), len(remainingIPs))
	if len(remainingIPs) == 0 {
		return cachedResults
	}

	newResults := st.performSpeedTest(remainingIPs)

	results := make(map[string]*SpeedResult)
	for ip, result := range cachedResults {
		results[ip] = result
	}
	for ip, result := range newResults {
		results[ip] = result
	}

	st.cacheMutex.Lock()
	for ip, result := range newResults {
		st.cache[ip] = result
	}
	st.cacheMutex.Unlock()

	return results
}

// performSpeedTest performs concurrent speed test
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

// testSingleIP tests a single IP
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

// pingWithICMP performs ICMP ping
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

// pingWithTCP performs TCP ping
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

// pingWithUDP performs UDP ping
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

// RootServerManager manages root DNS servers
type RootServerManager struct {
	servers      []string
	speedTester  *SpeedTestManager
	sorted       []RootServerWithLatency
	lastSortTime time.Time
	mu           sync.RWMutex
	needsSpeed   bool
}

// RootServerWithLatency represents root server with latency info
type RootServerWithLatency struct {
	Server    string        `json:"server"`
	Latency   time.Duration `json:"latency"`
	Reachable bool          `json:"reachable"`
}

// NewRootServerManager creates a new root server manager
func NewRootServerManager(config ServerConfig) *RootServerManager {
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
		rsm.speedTester = NewSpeedTestManager(dnsSpeedTestConfig)
		go rsm.sortServersBySpeed()
		LogInfo("Root server speed testing enabled")
	} else {
		LogInfo("Root server speed testing disabled (using upstream servers)")
	}

	return rsm
}

// GetOptimalRootServers returns sorted root servers
func (rsm *RootServerManager) GetOptimalRootServers() []RootServerWithLatency {
	rsm.mu.RLock()
	defer rsm.mu.RUnlock()
	result := make([]RootServerWithLatency, len(rsm.sorted))
	copy(result, rsm.sorted)
	return result
}

// sortServersBySpeed sorts root servers by speed
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

// StartPeriodicSorting starts periodic root server sorting
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

// SecurityManager manages security features
type SecurityManager struct {
	tls    *TLSManager
	dnssec *DNSSECValidator
	hijack *HijackPrevention
}

// NewSecurityManager creates a new security manager
func NewSecurityManager(config *ServerConfig, server *DNSServer) (*SecurityManager, error) {
	sm := &SecurityManager{
		dnssec: &DNSSECValidator{},
		hijack: &HijackPrevention{enabled: config.Server.Features.HijackProtection},
	}

	if config.Server.TLS.CertFile != "" && config.Server.TLS.KeyFile != "" {
		tlsMgr, err := NewTLSManager(server, config)
		if err != nil {
			return nil, fmt.Errorf("create TLS manager: %w", err)
		}
		sm.tls = tlsMgr
	}

	return sm, nil
}

// Shutdown shuts down security manager
func (sm *SecurityManager) Shutdown(timeout time.Duration) error {
	if sm.tls != nil {
		return sm.tls.shutdown()
	}
	return nil
}

// DNSSECValidator validates DNSSEC
type DNSSECValidator struct{}

// ValidateResponse validates DNSSEC in response
func (v *DNSSECValidator) ValidateResponse(response *dns.Msg, dnssecOK bool) bool {
	if !dnssecOK || response == nil {
		return false
	}
	if response.AuthenticatedData {
		return true
	}
	return v.hasDNSSECRecords(response)
}

// hasDNSSECRecords checks if response has DNSSEC records
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

// HijackPrevention prevents DNS hijacking
type HijackPrevention struct {
	enabled bool
}

// IsEnabled checks if hijack prevention is enabled
func (hp *HijackPrevention) IsEnabled() bool {
	return hp.enabled
}

// CheckResponse checks if response is potentially hijacked
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

// validateAnswer validates answer record
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

// validateRootServer validates root server response
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

// validateTLDServer validates TLD server response
func (hp *HijackPrevention) validateTLDServer(tldDomain, queryDomain string, rrType uint16) (bool, string) {
	if queryDomain != tldDomain {
		return false, fmt.Sprintf("TLD '%s' returned %s record in Answer for subdomain '%s'",
			tldDomain, dns.TypeToString[rrType], queryDomain)
	}
	return true, ""
}

// isRootServerGlue checks if record is root server glue record
func (hp *HijackPrevention) isRootServerGlue(domain string, rrType uint16) bool {
	if rrType != dns.TypeA && rrType != dns.TypeAAAA {
		return false
	}
	return strings.HasSuffix(domain, ".root-servers.net") || domain == "root-servers.net"
}

// isTLD checks if domain is TLD
func (hp *HijackPrevention) isTLD(domain string) bool {
	return domain != "" && !strings.Contains(domain, ".")
}

// isInAuthority checks if query domain is in authority
func (hp *HijackPrevention) isInAuthority(queryDomain, authorityDomain string) bool {
	if queryDomain == authorityDomain || authorityDomain == "" {
		return true
	}
	return strings.HasSuffix(queryDomain, "."+authorityDomain)
}

// =============================================================================
// TLS Management
// =============================================================================

// TLSManager manages TLS/QUIC/DoH servers
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

// NewTLSManager creates a new TLS manager
func NewTLSManager(server *DNSServer, config *ServerConfig) (*TLSManager, error) {
	cert, err := tls.LoadX509KeyPair(config.Server.TLS.CertFile, config.Server.TLS.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("load certificate: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	ctx, cancel := context.WithCancel(context.Background())

	quicAddrValidator, err := newQUICAddrValidator(QUICAddrValidatorCacheSize, QUICAddrValidatorTTL)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("create QUIC validator: %w", err)
	}

	return &TLSManager{
		server:            server,
		tlsConfig:         tlsConfig,
		ctx:               ctx,
		cancel:            cancel,
		quicAddrValidator: quicAddrValidator,
	}, nil
}

// Start starts all secure DNS servers
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

// startTLSServer starts DoT server
func (tm *TLSManager) startTLSServer() error {
	listener, err := net.Listen("tcp", ":"+tm.server.config.Server.TLS.Port)
	if err != nil {
		return fmt.Errorf("DoT listen: %w", err)
	}

	tm.tlsListener = tls.NewListener(listener, tm.tlsConfig)
	LogInfo("DoT server started: %s", tm.tlsListener.Addr())

	tm.wg.Add(1)
	go func() {
		defer tm.wg.Done()
		defer handlePanic("DoT server")
		tm.handleTLSConnections()
	}()

	return nil
}

// startQUICServer starts DoQ server
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

	LogInfo("DoQ server started: %s", tm.quicListener.Addr())

	tm.wg.Add(1)
	go func() {
		defer tm.wg.Done()
		defer handlePanic("DoQ server")
		tm.handleQUICConnections()
	}()

	return nil
}

// startDoHServer starts DoH server
func (tm *TLSManager) startDoHServer(port string) error {
	listener, err := net.Listen("tcp", ":"+port)
	if err != nil {
		return fmt.Errorf("DoH listen: %w", err)
	}

	tlsConfig := tm.tlsConfig.Clone()
	tlsConfig.NextProtos = NextProtoHTTP2

	tm.httpsListener = tls.NewListener(listener, tlsConfig)
	LogInfo("DoH server started: %s", tm.httpsListener.Addr())

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
			LogError("DoH server error: %v", err)
		}
	}()

	return nil
}

// startDoH3Server starts DoH3 server
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
	LogInfo("DoH3 server started: %s", tm.h3Listener.Addr())

	tm.h3Server = &http3.Server{Handler: tm}

	tm.wg.Add(1)
	go func() {
		defer tm.wg.Done()
		defer handlePanic("DoH3 server")
		if err := tm.h3Server.ServeListener(tm.h3Listener); err != nil && err != http.ErrServerClosed {
			LogError("DoH3 server error: %v", err)
		}
	}()

	return nil
}

// ServeHTTP implements http.Handler for DoH/DoH3
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
		LogError("DoH response failed: %v", err)
	}
}

// parseDoHRequest parses DoH request
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

// respondDoH sends DoH response
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

// handleTLSConnections handles DoT connections
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
			LogError("DoT accept failed: %v", err)
			continue
		}

		tm.wg.Add(1)
		go func() {
			defer tm.wg.Done()
			defer handlePanic("DoT connection")
			defer func() { _ = conn.Close() }()
			tm.handleSecureDNSConnection(conn, "DoT")
		}()
	}
}

// handleQUICConnections handles DoQ connections
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
			defer func() { _ = quicConn.CloseWithError(QUICCodeNoError, "") }()
			tm.handleQUICConnection(quicConn)
		}(conn)
	}
}

// handleQUICConnection handles a QUIC connection
func (tm *TLSManager) handleQUICConnection(conn *quic.Conn) {
	if conn == nil {
		return
	}

	for {
		select {
		case <-tm.ctx.Done():
			return
		default:
		}

		stream, err := conn.AcceptStream(tm.ctx)
		if err != nil {
			return
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

// handleQUICStream handles a QUIC stream
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

// handleSecureDNSConnection handles secure DNS connection (DoT)
func (tm *TLSManager) handleSecureDNSConnection(conn net.Conn, _ string) {
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return
	}

	_ = tlsConn.SetReadDeadline(time.Now().Add(QueryTimeout))

	for {
		select {
		case <-tm.ctx.Done():
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

// respondQUIC sends QUIC response
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

// shutdown shuts down TLS manager
func (tm *TLSManager) shutdown() error {
	LogInfo("Shutting down secure DNS server...")

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
	if tm.quicAddrValidator != nil {
		tm.quicAddrValidator.close()
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
	LogInfo("Secure DNS server shut down")
	return nil
}

// QUICAddrValidator validates QUIC addresses
type QUICAddrValidator struct {
	cache *ristretto.Cache[string, struct{}]
	ttl   time.Duration
}

// newQUICAddrValidator creates a new QUIC address validator
func newQUICAddrValidator(cacheSize int, ttl time.Duration) (*QUICAddrValidator, error) {
	cache, err := ristretto.NewCache(&ristretto.Config[string, struct{}]{
		NumCounters: int64(cacheSize * 10),
		MaxCost:     int64(cacheSize),
		BufferItems: 64,
	})
	if err != nil {
		return nil, fmt.Errorf("create ristretto cache: %w", err)
	}

	return &QUICAddrValidator{cache: cache, ttl: ttl}, nil
}

// requiresValidation checks if address requires validation
func (v *QUICAddrValidator) requiresValidation(addr net.Addr) bool {
	if v == nil || v.cache == nil {
		return true
	}

	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return true
	}

	key := udpAddr.IP.String()
	if _, found := v.cache.Get(key); found {
		return false
	}

	v.cache.SetWithTTL(key, struct{}{}, 1, v.ttl)
	return true
}

// close closes the validator
func (v *QUICAddrValidator) close() {
	if v != nil && v.cache != nil {
		v.cache.Close()
	}
}

// =============================================================================
// Connection & Query Management
// =============================================================================

// ConnectionManager manages DNS connections
type ConnectionManager struct {
	timeout     time.Duration
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
	closed      int32
	queryClient *QueryClient
}

// NewConnectionManager creates a new connection manager
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

// Close closes connection manager
func (cm *ConnectionManager) Close() error {
	if !atomic.CompareAndSwapInt32(&cm.closed, 0, 1) {
		return nil
	}
	LogInfo("Shutting down connection manager...")
	cm.cancel()
	cm.wg.Wait()
	LogInfo("Connection manager shut down")
	return nil
}

// QueryClient executes DNS queries
type QueryClient struct {
	connMgr *ConnectionManager
	timeout time.Duration
}

// QueryResult represents query result
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

// ExecuteQuery executes a DNS query
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

// executeSecureQuery executes secure query (TLS/QUIC/DoH)
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

// executeTLSQuery executes TLS query
func (qc *QueryClient) executeTLSQuery(_ context.Context, msg *dns.Msg, server *UpstreamServer, tlsConfig *tls.Config) (*dns.Msg, error) {
	host, port, err := net.SplitHostPort(server.Address)
	if err != nil {
		return nil, fmt.Errorf("parse TLS address: %w", err)
	}

	dialer := &net.Dialer{Timeout: TLSHandshakeTimeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(host, port), tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("TLS dial: %w", err)
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(qc.timeout))

	msgData, err := msg.Pack()
	if err != nil {
		return nil, fmt.Errorf("pack message: %w", err)
	}

	buf := make([]byte, 2+len(msgData))
	binary.BigEndian.PutUint16(buf[:2], uint16(len(msgData)))
	copy(buf[2:], msgData)

	if _, err := conn.Write(buf); err != nil {
		return nil, fmt.Errorf("send TLS query: %w", err)
	}

	lengthBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, lengthBuf); err != nil {
		return nil, fmt.Errorf("read response length: %w", err)
	}

	respLength := binary.BigEndian.Uint16(lengthBuf)
	if respLength == 0 || respLength > TCPBufferSize {
		return nil, fmt.Errorf("invalid response length: %d", respLength)
	}

	respBuf := make([]byte, respLength)
	if _, err := io.ReadFull(conn, respBuf); err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	response := new(dns.Msg)
	if err := response.Unpack(respBuf); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	return response, nil
}

// executeQUICQuery executes QUIC query
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
	defer func() { _ = conn.CloseWithError(QUICCodeNoError, "") }()

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

// executeDoHQuery executes DoH/DoH3 query
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
			IdleConnTimeout:    DoHIdleConnTimeout,
			ForceAttemptHTTP2:  true,
		}
		_, _ = http2.ConfigureTransports(transport.(*http.Transport))
		defer transport.(*http.Transport).CloseIdleConnections()
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

// executeTraditionalQuery executes traditional UDP/TCP query
func (qc *QueryClient) executeTraditionalQuery(ctx context.Context, msg *dns.Msg, server *UpstreamServer, _ *RequestTracker) (*dns.Msg, error) {
	client := &dns.Client{Timeout: qc.timeout, Net: server.Protocol}
	if server.Protocol == "udp" {
		client.UDPSize = UDPBufferSize
	}

	response, _, err := client.ExchangeContext(ctx, msg, server.Address)
	return response, err
}

// needsTCPFallback checks if TCP fallback is needed
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

// QueryManager manages DNS queries
type QueryManager struct {
	upstream  *UpstreamHandler
	recursive *RecursiveResolver
	cname     *CNAMEHandler
	validator *ResponseValidator
	server    *DNSServer
}

// NewQueryManager creates a new query manager
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

// Initialize initializes query manager
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

// Query executes a DNS query
func (qm *QueryManager) Query(question dns.Question, ecs *ECSOption, serverDNSSECEnabled bool, tracker *RequestTracker) ([]dns.RR, []dns.RR, []dns.RR, bool, *ECSOption, error) {
	servers := qm.upstream.getServers()
	if len(servers) > 0 {
		return qm.queryUpstream(question, ecs, serverDNSSECEnabled, tracker)
	}
	ctx, cancel := context.WithTimeout(qm.server.ctx, RecursiveTimeout)
	defer cancel()
	return qm.cname.resolveWithCNAME(ctx, question, ecs, tracker)
}

// queryUpstream queries upstream servers
func (qm *QueryManager) queryUpstream(question dns.Question, ecs *ECSOption, serverDNSSECEnabled bool, tracker *RequestTracker) ([]dns.RR, []dns.RR, []dns.RR, bool, *ECSOption, error) {
	servers := qm.upstream.getServers()
	if len(servers) == 0 {
		return nil, nil, nil, false, nil, errors.New("no upstream servers")
	}

	resultChan := make(chan *QueryResult, len(servers))
	ctx, cancel := context.WithTimeout(qm.server.ctx, QueryTimeout)
	defer cancel()

	var wg sync.WaitGroup

	for _, server := range servers {
		srv := server

		if srv.IsRecursive() {
			wg.Add(1)
			qm.server.taskMgr.ExecuteAsync("Query-Recursive", func(taskCtx context.Context) error {
				defer wg.Done()

				recursiveCtx, recursiveCancel := context.WithTimeout(taskCtx, RecursiveTimeout)
				defer recursiveCancel()

				answer, authority, additional, validated, ecsResponse, err := qm.cname.resolveWithCNAME(recursiveCtx, question, ecs, tracker)

				if err == nil && len(answer) > 0 {
					if len(srv.Match) > 0 {
						filteredAnswer, shouldRefuse := qm.filterRecordsByCIDR(answer, srv.Match, tracker)
						if shouldRefuse {
							select {
							case resultChan <- &QueryResult{Error: fmt.Errorf("CIDR filter refused"), Server: srv.Address}:
							case <-ctx.Done():
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
					case <-ctx.Done():
					}
				} else if err != nil {
					select {
					case resultChan <- &QueryResult{Error: err, Server: srv.Address}:
					case <-ctx.Done():
					}
				}
				return nil
			})
		} else {
			wg.Add(1)
			msg := qm.server.buildQueryMessage(question, ecs, serverDNSSECEnabled, true, false)
			qm.server.taskMgr.ExecuteAsync(fmt.Sprintf("Query-%s", srv.Address), func(taskCtx context.Context) error {
				defer wg.Done()
				defer releaseMessage(msg)

				result := qm.server.connMgr.queryClient.ExecuteQuery(taskCtx, msg, srv, tracker)

				if result.Error != nil {
					select {
					case resultChan <- &QueryResult{Error: result.Error, Server: srv.Address}:
					case <-ctx.Done():
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
								case <-ctx.Done():
								}
								return nil
							}
							result.Response.Answer = filteredAnswer
						}

						if serverDNSSECEnabled && qm.server.config.Server.Features.DNSSEC {
							result.Validated = qm.validator.dnssecValidator.ValidateResponse(result.Response, true)
						}

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
						case <-ctx.Done():
						}
					} else {
						select {
						case resultChan <- &QueryResult{Error: fmt.Errorf("upstream error: %s", dns.RcodeToString[rcode]), Server: srv.Address}:
						case <-ctx.Done():
						}
					}
				}
				return nil
			})
		}
	}

	var lastError error
	var successfulResults []*QueryResult
	receivedCount := 0
	serverCount := len(servers)

	for receivedCount < serverCount {
		select {
		case result := <-resultChan:
			receivedCount++

			if result.Error != nil {
				lastError = result.Error
				continue
			}

			if len(result.Answer) > 0 {
				go func() {
					for receivedCount < serverCount {
						select {
						case <-resultChan:
							receivedCount++
						default:
							return
						}
					}
				}()
				return result.Answer, result.Authority, result.Additional, result.Validated, result.ECS, nil
			}

			successfulResults = append(successfulResults, result)

		case <-ctx.Done():
			if len(successfulResults) > 0 {
				result := successfulResults[0]
				return result.Answer, result.Authority, result.Additional, result.Validated, result.ECS, nil
			}
			if lastError != nil {
				return nil, nil, nil, false, nil, lastError
			}
			return nil, nil, nil, false, nil, errors.New("all upstream queries failed or timed out")
		}
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

// filterRecordsByCIDR filters DNS records by CIDR rules
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

// UpstreamHandler handles upstream servers
type UpstreamHandler struct {
	servers []*UpstreamServer
	mu      sync.RWMutex
}

// getServers returns upstream servers
func (uh *UpstreamHandler) getServers() []*UpstreamServer {
	uh.mu.RLock()
	defer uh.mu.RUnlock()
	return uh.servers
}

// CNAMEHandler resolves CNAME chains
type CNAMEHandler struct {
	server *DNSServer
}

// resolveWithCNAME resolves query with CNAME chain
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

// RecursiveResolver performs recursive resolution
type RecursiveResolver struct {
	server          *DNSServer
	rootServerMgr   *RootServerManager
	concurrencyLock chan struct{}
}

// recursiveQuery performs recursive DNS query
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

		validated := false
		if rr.server.config.Server.Features.DNSSEC {
			validated = rr.server.securityMgr.dnssec.ValidateResponse(response, true)
		}

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

		validated := false
		if rr.server.config.Server.Features.DNSSEC {
			LogDebug("RECURSION: Validating DNSSEC for %s", currentDomain)
			validated = rr.server.securityMgr.dnssec.ValidateResponse(response, true)
			LogDebug("RECURSION: DNSSEC validation result for %s: %v", currentDomain, validated)
		}

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

// handleSuspiciousResponse handles suspicious DNS response
func (rr *RecursiveResolver) handleSuspiciousResponse(reason string, currentlyTCP bool, _ context.Context, _ dns.Question, _ *ECSOption, _ int, _ *RequestTracker) ([]dns.RR, []dns.RR, []dns.RR, bool, *ECSOption, error) {
	if !currentlyTCP {
		return nil, nil, nil, false, nil, fmt.Errorf("DNS_HIJACK_DETECTED: %s", reason)
	}
	return nil, nil, nil, false, nil, fmt.Errorf("DNS hijacking detected (TCP): %s", reason)
}

// queryNameserversConcurrent queries nameservers concurrently
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

	resultChan := make(chan *QueryResult, concurrency)
	LogDebug("UPSTREAM: Launching %d concurrent queries", concurrency)

	for _, server := range tempServers {
		srv := server
		msg := rr.server.buildQueryMessage(question, ecs, rr.server.config.Server.Features.DNSSEC, true, false)
		rr.server.taskMgr.ExecuteAsync(fmt.Sprintf("Query-%s", srv.Address), func(ctx context.Context) error {
			defer releaseMessage(msg)
			LogDebug("UPSTREAM: Executing query to %s", srv.Address)
			result := rr.server.connMgr.queryClient.ExecuteQuery(ctx, msg, srv, tracker)

			if result.Error == nil && result.Response != nil {
				rcode := result.Response.Rcode
				LogDebug("UPSTREAM: Response from %s: rcode=%d, answer=%d, ns=%d, additional=%d",
					srv.Address, rcode, len(result.Response.Answer), len(result.Response.Ns), len(result.Response.Extra))

				if rcode == dns.RcodeSuccess || rcode == dns.RcodeNameError {
					if rr.server.config.Server.Features.DNSSEC {
						result.Validated = rr.server.securityMgr.dnssec.ValidateResponse(result.Response, true)
						LogDebug("UPSTREAM: DNSSEC validation for %s: %v", srv.Address, result.Validated)
					}
					LogDebug("UPSTREAM: Successful response from %s, returning result", srv.Address)
					select {
					case resultChan <- result:
					case <-ctx.Done():
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
		LogDebug("UPSTREAM: Received successful response (rcode: %d)", result.Response.Rcode)
		return result.Response, nil
	case <-ctx.Done():
		LogDebug("UPSTREAM: Context cancelled while waiting for response")
		return nil, ctx.Err()
	}
}

// resolveNSAddressesConcurrent resolves NS addresses concurrently
func (rr *RecursiveResolver) resolveNSAddressesConcurrent(ctx context.Context, nsRecords []*dns.NS, qname string, depth int, forceTCP bool, tracker *RequestTracker) []string {
	resolveCount := len(nsRecords)
	if resolveCount > MaxNSResolve {
		resolveCount = MaxNSResolve
	}

	nsChan := make(chan []string, resolveCount)
	resolveCtx, resolveCancel := context.WithTimeout(ctx, ConnTimeout)
	defer resolveCancel()

	for i := 0; i < resolveCount; i++ {
		ns := nsRecords[i]
		rr.server.taskMgr.ExecuteAsync(fmt.Sprintf("NSResolve-%s", ns.Ns), func(ctx context.Context) error {
			if strings.EqualFold(strings.TrimSuffix(ns.Ns, "."), strings.TrimSuffix(qname, ".")) {
				select {
				case nsChan <- nil:
				case <-ctx.Done():
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
				if len(allAddresses) >= MaxNSResolve {
					resolveCancel()
					return allAddresses
				}
			}
		case <-resolveCtx.Done():
			return allAddresses
		}
	}

	return allAddresses
}

// getRootServers returns root servers
func (rr *RecursiveResolver) getRootServers() []string {
	serversWithLatency := rr.rootServerMgr.GetOptimalRootServers()
	servers := make([]string, len(serversWithLatency))
	for i, server := range serversWithLatency {
		servers[i] = server.Server
	}
	return servers
}

// ResponseValidator validates DNS responses
type ResponseValidator struct {
	hijackPrevention *HijackPrevention
	dnssecValidator  *DNSSECValidator
}

// =============================================================================
// Resource Management
// =============================================================================

// TaskManager manages concurrent tasks
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

// NewTaskManager creates a new task manager
func NewTaskManager(maxGoroutines int) *TaskManager {
	ctx, cancel := context.WithCancel(context.Background())
	return &TaskManager{
		ctx:       ctx,
		cancel:    cancel,
		semaphore: make(chan struct{}, maxGoroutines),
	}
}

// ExecuteAsync executes task asynchronously
func (tm *TaskManager) ExecuteAsync(name string, fn func(ctx context.Context) error) {
	if tm == nil || atomic.LoadInt32(&tm.closed) != 0 {
		return
	}

	go func() {
		defer handlePanic(fmt.Sprintf("AsyncTask-%s", name))

		atomic.AddInt64(&tm.activeCount, 1)
		defer atomic.AddInt64(&tm.activeCount, -1)

		tm.wg.Add(1)
		defer tm.wg.Done()

		atomic.AddInt64(&tm.stats.executed, 1)

		if err := fn(tm.ctx); err != nil && err != context.Canceled {
			atomic.AddInt64(&tm.stats.failed, 1)
		}
	}()
}

// Shutdown shuts down task manager
func (tm *TaskManager) Shutdown(timeout time.Duration) error {
	if tm == nil || !atomic.CompareAndSwapInt32(&tm.closed, 0, 1) {
		return nil
	}

	LogInfo("Shutting down task manager...")
	tm.cancel()

	done := make(chan struct{})
	go func() {
		tm.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		LogInfo("Task manager shut down")
	case <-time.After(timeout):
		LogWarn("Task manager shutdown timeout")
		return fmt.Errorf("shutdown timeout")
	}

	close(tm.semaphore)
	return nil
}

// RequestTracker tracks DNS request
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

// NewRequestTracker creates a new request tracker
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

// AddStep adds a tracking step
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

// Finish finishes tracking
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

// DNSServer is the main DNS server
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
	speedDebounce map[string]time.Time
	speedMutex    sync.Mutex
	speedInterval time.Duration
	ctx           context.Context
	cancel        context.CancelFunc
	shutdown      chan struct{}
	wg            sync.WaitGroup
	closed        int32
}

// NewDNSServer creates a new DNS server
func NewDNSServer(config *ServerConfig) (*DNSServer, error) {
	ctx, cancel := context.WithCancel(context.Background())

	rootServerManager := NewRootServerManager(*config)

	ednsManager, err := NewEDNSManager(config.Server.DefaultECS, config.Server.Features.Padding)
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

	server := &DNSServer{
		config:        config,
		rootServerMgr: rootServerManager,
		connMgr:       connectionManager,
		taskMgr:       taskManager,
		ednsMgr:       ednsManager,
		rewriteMgr:    rewriteManager,
		cidrMgr:       cidrManager,
		speedDebounce: make(map[string]time.Time),
		speedInterval: SpeedDebounceInterval,
		ctx:           ctx,
		cancel:        cancel,
		shutdown:      make(chan struct{}),
	}

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

	if len(config.SpeedTest) > 0 {
		server.speedTestMgr = NewSpeedTestManager(*config)
	}

	var cache CacheManager
	if config.Redis.Address == "" {
		cache = NewNullCache()
	} else {
		redisCache, err := NewRedisCache(config, server)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("redis cache init: %w", err)
		}
		cache = redisCache
	}

	server.cacheMgr = cache
	server.setupSignalHandling()
	return server, nil
}

// setupSignalHandling sets up signal handling
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
			LogInfo("Received signal %v, starting graceful shutdown...", sig)
			s.shutdownServer()
		case <-s.ctx.Done():
			return
		}
	}()
}

// shutdownServer shuts down the server
func (s *DNSServer) shutdownServer() {
	if !atomic.CompareAndSwapInt32(&s.closed, 0, 1) {
		return
	}

	LogInfo("Starting DNS server shutdown...")

	s.cleanupSpeedDebounce()

	if s.cancel != nil {
		s.cancel()
	}

	if s.cacheMgr != nil {
		closeWithLog(s.cacheMgr, "Cache manager")
	}

	if s.securityMgr != nil {
		if err := s.securityMgr.Shutdown(ShutdownTimeout); err != nil {
			LogError("Security manager shutdown failed: %v", err)
		}
	}

	if s.connMgr != nil {
		closeWithLog(s.connMgr, "Connection manager")
	}

	if s.taskMgr != nil {
		if err := s.taskMgr.Shutdown(ShutdownTimeout); err != nil {
			LogError("Task manager shutdown failed: %v", err)
		}
	}

	if s.speedTestMgr != nil {
		closeWithLog(s.speedTestMgr, "SpeedTest manager")
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		s.wg.Wait()
	}()

	select {
	case <-done:
		LogInfo("All components shut down")
	case <-time.After(ShutdownTimeout):
		LogWarn("Component shutdown timeout")
	}

	if s.shutdown != nil {
		close(s.shutdown)
	}

	time.Sleep(100 * time.Millisecond)
	os.Exit(0)
}

// cleanupSpeedDebounce cleans up speed debounce map
func (s *DNSServer) cleanupSpeedDebounce() {
	s.speedMutex.Lock()
	defer s.speedMutex.Unlock()

	now := time.Now()
	for domain, lastCheck := range s.speedDebounce {
		if now.Sub(lastCheck) >= s.speedInterval {
			delete(s.speedDebounce, domain)
		}
	}
}

// Start starts the DNS server
func (s *DNSServer) Start() error {
	if atomic.LoadInt32(&s.closed) != 0 {
		return errors.New("server is closed")
	}

	var wg sync.WaitGroup
	serverCount := 2
	if s.securityMgr.tls != nil {
		serverCount++
	}

	errChan := make(chan error, serverCount)

	LogInfo("Starting ZJDNS Server %s", getVersion())
	LogInfo("Listening port: %s", s.config.Server.Port)

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
		LogInfo("UDP server started: [::]:%s", s.config.Server.Port)
		if err := server.ListenAndServe(); err != nil {
			errChan <- fmt.Errorf("UDP startup: %w", err)
		}
	}()

	go func() {
		defer wg.Done()
		defer handlePanic("Critical-TCP server")
		server := &dns.Server{
			Addr:    ":" + s.config.Server.Port,
			Net:     "tcp",
			Handler: dns.HandlerFunc(s.handleDNSRequest),
		}
		LogInfo("TCP server started: [::]:%s", s.config.Server.Port)
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

// displayInfo displays server information
func (s *DNSServer) displayInfo() {
	servers := s.queryMgr.upstream.getServers()
	if len(servers) > 0 {
		for _, server := range servers {
			if server.IsRecursive() {
				info := "Upstream server: recursive resolution"
				if len(server.Match) > 0 {
					info += fmt.Sprintf(" [CIDR match: %v]", server.Match)
				}
				LogInfo("%s", info)
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
				LogInfo("Upstream server: %s", serverInfo)
			}
		}
		LogInfo("Upstream mode: total %d servers", len(servers))
	} else {
		if s.config.Redis.Address == "" {
			LogInfo("Recursive mode (no cache)")
		} else {
			LogInfo("Recursive mode + Redis cache: %s", s.config.Redis.Address)
		}
	}

	if s.cidrMgr != nil && len(s.config.CIDR) > 0 {
		LogInfo("CIDR Manager: enabled (%d rules)", len(s.config.CIDR))
	}

	if s.securityMgr.tls != nil {
		LogInfo("Listening secure DNS port: %s (DoT/DoQ)", s.config.Server.TLS.Port)
		httpsPort := s.config.Server.TLS.HTTPS.Port
		if httpsPort != "" {
			endpoint := s.config.Server.TLS.HTTPS.Endpoint
			if endpoint == "" {
				endpoint = strings.TrimPrefix(DefaultQueryPath, "/")
			}
			LogInfo("Listening secure DNS port: %s (DoH/DoH3, endpoint: %s)", httpsPort, endpoint)
		}
	}

	if s.rewriteMgr.hasRules() {
		LogInfo("DNS rewriter: enabled (%d rules)", len(s.config.Rewrite))
	}
	if s.config.Server.Features.HijackProtection {
		LogInfo("DNS hijacking prevention: enabled")
	}
	if defaultECS := s.ednsMgr.GetDefaultECS(); defaultECS != nil {
		LogInfo("Default ECS: %s/%d", defaultECS.Address, defaultECS.SourcePrefix)
	}
	if s.ednsMgr.paddingEnabled {
		LogInfo("DNS Padding: enabled")
	}

	if len(s.config.SpeedTest) > 0 {
		LogInfo("SpeedTest: enabled")
	}

	if s.rootServerMgr.needsSpeed {
		LogInfo("Root server speed testing: enabled")
	}

	LogInfo("Max concurrency: %d", MaxConcurrency)
}

// handleDNSRequest handles DNS request
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

// processDNSQuery processes DNS query
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

	serverDNSSECEnabled := s.config.Server.Features.DNSSEC
	cacheKey := buildCacheKey(question, ecsOpt, serverDNSSECEnabled)

	if entry, found, isExpired := s.cacheMgr.Get(cacheKey); found {
		return s.processCacheHit(req, entry, isExpired, question, clientRequestedDNSSEC, clientHasEDNS, ecsOpt, cacheKey, tracker, isSecureConnection)
	}

	return s.processCacheMiss(req, question, ecsOpt, clientRequestedDNSSEC, clientHasEDNS, serverDNSSECEnabled, cacheKey, tracker, isSecureConnection)
}

// processCacheHit processes cache hit
func (s *DNSServer) processCacheHit(req *dns.Msg, entry *CacheEntry, isExpired bool, question dns.Question, clientRequestedDNSSEC bool, _ bool, ecsOpt *ECSOption, cacheKey string, _ *RequestTracker, isSecureConnection bool) *dns.Msg {
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

	if s.config.Server.Features.DNSSEC && entry.Validated {
		msg.AuthenticatedData = true
	}

	_ = entry.GetECSOption()

	s.addEDNS(msg, req, isSecureConnection)

	if isExpired && s.config.Server.Features.ServeStale && s.config.Server.Features.Prefetch && entry.ShouldRefresh() {
		s.cacheMgr.RequestRefresh(RefreshRequest{
			Question:            question,
			ECS:                 ecsOpt,
			CacheKey:            cacheKey,
			ServerDNSSECEnabled: s.config.Server.Features.DNSSEC,
		})
	}

	s.restoreOriginalDomain(msg, req.Question[0].Name, question.Name)
	return msg
}

// processCacheMiss processes cache miss
func (s *DNSServer) processCacheMiss(req *dns.Msg, question dns.Question, ecsOpt *ECSOption, clientRequestedDNSSEC bool, clientHasEDNS bool, serverDNSSECEnabled bool, cacheKey string, tracker *RequestTracker, isSecureConnection bool) *dns.Msg {
	answer, authority, additional, validated, ecsResponse, err := s.queryMgr.Query(question, ecsOpt, serverDNSSECEnabled, tracker)

	if err != nil {
		return s.processQueryError(req, err, cacheKey, question, clientRequestedDNSSEC, clientHasEDNS, ecsOpt, tracker, isSecureConnection)
	}

	return s.processQuerySuccess(req, question, ecsOpt, clientRequestedDNSSEC, clientHasEDNS, cacheKey, answer, authority, additional, validated, ecsResponse, tracker, isSecureConnection)
}

// processQueryError processes query error
func (s *DNSServer) processQueryError(req *dns.Msg, _ error, cacheKey string, question dns.Question, clientRequestedDNSSEC bool, _ bool, _ *ECSOption, _ *RequestTracker, isSecureConnection bool) *dns.Msg {
	if s.config.Server.Features.ServeStale {
		if entry, found, _ := s.cacheMgr.Get(cacheKey); found {
			responseTTL := uint32(StaleTTL)
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

			if s.config.Server.Features.DNSSEC && entry.Validated {
				msg.AuthenticatedData = true
			}

			s.addEDNS(msg, req, isSecureConnection)
			s.restoreOriginalDomain(msg, req.Question[0].Name, question.Name)
			return msg
		}
	}

	msg := s.buildResponse(req)
	if msg == nil {
		msg = &dns.Msg{}
		msg.SetReply(req)
	}
	msg.Rcode = dns.RcodeServerFailure
	return msg
}

// processQuerySuccess processes successful query
func (s *DNSServer) processQuerySuccess(req *dns.Msg, question dns.Question, ecsOpt *ECSOption, clientRequestedDNSSEC bool, _ bool, cacheKey string, answer, authority, additional []dns.RR, validated bool, ecsResponse *ECSOption, _ *RequestTracker, isSecureConnection bool) *dns.Msg {
	msg := s.buildResponse(req)
	if msg == nil {
		msg = &dns.Msg{}
		msg.SetReply(req)
	}

	if s.config.Server.Features.DNSSEC && validated {
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

					speedTester := NewSpeedTestManager(*s.config)
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

// addEDNS adds EDNS to message
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

	shouldAddEDNS := ecsOpt != nil || s.ednsMgr.paddingEnabled || (clientRequestedDNSSEC && s.config.Server.Features.DNSSEC)

	if shouldAddEDNS {
		s.ednsMgr.AddToMessage(msg, ecsOpt, clientRequestedDNSSEC && s.config.Server.Features.DNSSEC, isSecureConnection)
	}
}

// buildResponse builds DNS response
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

// restoreOriginalDomain restores original domain in response
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

// shouldPerformSpeedTest checks if speed test should be performed
func (s *DNSServer) shouldPerformSpeedTest(domain string) bool {
	if len(s.config.SpeedTest) == 0 {
		return false
	}

	s.speedMutex.Lock()
	defer s.speedMutex.Unlock()

	now := time.Now()
	lastCheck, exists := s.speedDebounce[domain]
	if !exists || now.Sub(lastCheck) >= s.speedInterval {
		s.speedDebounce[domain] = now
		return true
	}

	return false
}

// queryForRefresh queries for cache refresh
func (s *DNSServer) queryForRefresh(question dns.Question, ecs *ECSOption, serverDNSSECEnabled bool) ([]dns.RR, []dns.RR, []dns.RR, bool, *ECSOption, error) {
	defer handlePanic("Cache refresh query")

	if atomic.LoadInt32(&s.closed) != 0 {
		return nil, nil, nil, false, nil, errors.New("server is closed")
	}

	_, cancel := context.WithTimeout(s.ctx, QueryTimeout)
	defer cancel()

	return s.queryMgr.Query(question, ecs, serverDNSSECEnabled, nil)
}

// buildQueryMessage builds query message
func (s *DNSServer) buildQueryMessage(question dns.Question, ecs *ECSOption, dnssecEnabled bool, recursionDesired bool, isSecureConnection bool) *dns.Msg {
	msg := acquireMessage()
	if msg == nil {
		msg = &dns.Msg{}
	}

	msg.SetQuestion(dns.Fqdn(question.Name), question.Qtype)
	msg.RecursionDesired = recursionDesired

	if s.ednsMgr != nil {
		s.ednsMgr.AddToMessage(msg, ecs, dnssecEnabled, isSecureConnection)
	}

	return msg
}

// =============================================================================
// Utility Functions
// =============================================================================

// getVersion returns version string
func getVersion() string {
	return fmt.Sprintf("v%s-ZHIJIE-%s@%s", Version, CommitHash, BuildTime)
}

// normalizeDomain normalizes domain name
func normalizeDomain(domain string) string {
	return strings.ToLower(strings.TrimSuffix(domain, "."))
}

// isSecureProtocol checks if protocol is secure
func isSecureProtocol(protocol string) bool {
	switch protocol {
	case "tls", "quic", "https", "http3":
		return true
	default:
		return false
	}
}

// isValidFilePath validates file path
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

// handlePanic handles panic
func handlePanic(operation string) {
	if r := recover(); r != nil {
		buf := make([]byte, 2048)
		n := runtime.Stack(buf, false)
		stackTrace := string(buf[:n])
		LogError("Panic [%s]: %v\nStack:\n%s\nExiting due to panic", operation, r, stackTrace)
		os.Exit(1)
	}
}

// getClientIP gets client IP from DNS writer
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

// getSecureClientIP gets client IP from secure connection
func getSecureClientIP(conn interface{}) net.IP {
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

// closeWithLog closes resource with logging
func closeWithLog(c Closeable, name string) {
	if c == nil {
		return
	}
	if err := c.Close(); err != nil {
		LogWarn("Close %s failed: %v", name, err)
	}
}

// createCompactRecord creates compact DNS record
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

// expandRecord expands compact record
func expandRecord(cr *CompactRecord) dns.RR {
	if cr == nil || cr.Text == "" {
		return nil
	}
	rr, _ := dns.NewRR(cr.Text)
	return rr
}

// compactRecords compacts DNS records
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

// expandRecords expands compact records
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

// processRecords processes DNS records
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

// buildCacheKey builds cache key
func buildCacheKey(question dns.Question, ecs *ECSOption, dnssecEnabled bool) string {
	key := fmt.Sprintf("%s:%d:%d", normalizeDomain(question.Name), question.Qtype, question.Qclass)

	if ecs != nil {
		key += fmt.Sprintf(":%s/%d", ecs.Address.String(), ecs.SourcePrefix)
	}

	if dnssecEnabled {
		key += ":dnssec"
	}

	if len(key) > 512 {
		key = fmt.Sprintf("hash:%x", key)[:512]
	}
	return key
}

// calculateTTL calculates TTL from records
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

// extractIPsFromServers extracts IPs from server addresses
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

// sortBySpeedResultWithLatency sorts servers by speed test result
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

// toRRSlice converts typed records to RR slice
func toRRSlice[T dns.RR](records []T) []dns.RR {
	result := make([]dns.RR, len(records))
	for i, r := range records {
		result[i] = r
	}
	return result
}

// Message pool for resource management
var messagePool = sync.Pool{
	New: func() interface{} {
		return &dns.Msg{}
	},
}

// acquireMessage acquires a message from pool
func acquireMessage() *dns.Msg {
	msg := messagePool.Get().(*dns.Msg)
	msg.Question = msg.Question[:0]
	msg.Answer = msg.Answer[:0]
	msg.Ns = msg.Ns[:0]
	msg.Extra = msg.Extra[:0]
	return msg
}

// releaseMessage releases message to pool
func releaseMessage(msg *dns.Msg) {
	if msg != nil {
		msg.Question = msg.Question[:0]
		msg.Answer = msg.Answer[:0]
		msg.Ns = msg.Ns[:0]
		msg.Extra = msg.Extra[:0]
		messagePool.Put(msg)
	}
}

// copyMessage creates a deep copy of DNS message
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

	LogInfo("ZJDNS Server started successfully!")

	if err := server.Start(); err != nil {
		log.Fatalf("Server startup failed: %v", err)
	}
}
