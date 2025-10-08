// Package main implements a high-performance DNS server supporting
// recursive resolution, caching, and secure DNS protocols (DoT/DoH/DoQ).
package main

import (
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
// Version Information
// =============================================================================

// These variables are set at build time using ldflags
var (
	Version    = "1.0.0" // Default version for development
	CommitHash = "dirty" // Git commit hash
	BuildTime  = "dev"   // Build timestamp
)

// GetVersion returns the full version string in format: {Version}-ZHIJIE-{CommitHash}@{BuildTime}
func GetVersion() string {
	return fmt.Sprintf("%s-ZHIJIE-%s@%s", Version, CommitHash, BuildTime)
}

// =============================================================================
// Constants - Network & Protocol
// =============================================================================

const (
	// Ports
	DefaultDNSPort   = "53"
	DefaultTLSPort   = "853"
	DefaultHTTPSPort = "443"

	// Protocol
	RecursiveIndicator = "builtin_recursive"
	DefaultQueryPath   = "/dns-query"

	// Buffer Sizes
	UDPBufferSize    = 1232
	TCPBufferSize    = 4096
	SecureBufferSize = 8192
	MinDNSPacketSize = 12

	// Limits
	MaxDomainLength   = 253
	MaxCNAMEChain     = 16
	MaxRecursionDepth = 16
	MaxConcurrency    = 1000
	MaxSingleQuery    = 3
	MaxNSResolve      = 3

	// Timeouts - Query
	QueryTimeout     = 5 * time.Second
	RecursiveTimeout = 15 * time.Second
	ExtendedTimeout  = 30 * time.Second

	// Timeouts - Connection
	ConnTimeout           = 5 * time.Second
	TLSHandshakeTimeout   = 3 * time.Second
	ConnectionTestTimeout = 100 * time.Millisecond
	PublicIPTimeout       = 3 * time.Second
	HTTPClientTimeout     = 5 * time.Second

	// Timeouts - Server
	ShutdownTimeout      = 5 * time.Second
	DoHReadHeaderTimeout = 5 * time.Second
	DoHWriteTimeout      = 5 * time.Second

	// Connection Lifecycle
	SecureIdleTimeout  = 300 * time.Second
	DoHIdleConnTimeout = 300 * time.Second

	// Cache
	DefaultCacheTTL = 300
	StaleTTL        = 30
	StaleMaxAge     = 259200
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
	DoHMaxConnsPerHost = 3
	DoHMaxIdleConns    = 3

	// TLS/QUIC
	TLSSessionCacheSize  = 256
	QUICSessionCacheSize = 128
	MaxIncomingStreams   = 2048
	InitialPacketSize    = 1200
	H3MaxResponseHeader  = 8192

	// TCP Optimization
	TCPReadBufferSize  = 128 * 1024
	TCPWriteBufferSize = 128 * 1024
	TCPNoDelay         = 1
	TCPQuickAck        = 0x0c

	// QUIC Validator
	QUICAddrValidatorCacheSize = 16 * 1024
	QUICAddrValidatorTTL       = 300 * time.Second

	// SpeedTest
	DefaultSpeedTimeout     = 250 * time.Millisecond
	DefaultSpeedConcurrency = 4
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

// =============================================================================
// Types - Core Interfaces
// =============================================================================

// Manager defines lifecycle interface for all managers
type Manager interface {
	Initialize() error
	Shutdown(timeout time.Duration) error
}

// Closeable defines resource cleanup interface
type Closeable interface {
	Close() error
}

// =============================================================================
// Types - Logging
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

// =============================================================================
// Types - Configuration
// =============================================================================

type ServerConfig struct {
	Server    ServerSettings    `json:"server"`
	Redis     RedisSettings     `json:"redis"`
	SpeedTest []SpeedTestMethod `json:"speedtest"`
	Upstream  []UpstreamServer  `json:"upstream"`
	Rewrite   []RewriteRule     `json:"rewrite"`
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
	Address       string `json:"address"`
	Protocol      string `json:"protocol"`
	ServerName    string `json:"server_name"`
	SkipTLSVerify bool   `json:"skip_tls_verify"`
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

type ConfigManager struct{}

// =============================================================================
// Types - Cache
// =============================================================================

type CacheManager interface {
	Get(key string) (*CacheEntry, bool, bool)
	Set(key string, answer, authority, additional []dns.RR, validated bool, ecs *ECSOption)
	RequestRefresh(req RefreshRequest)
	Closeable
}

type CacheEntry struct {
	Answer          []*CompactRecord `json:"answer"`
	Authority       []*CompactRecord `json:"authority"`
	Additional      []*CompactRecord `json:"additional"`
	TTL             int              `json:"ttl"`
	OriginalTTL     int              `json:"original_ttl"`
	Timestamp       int64            `json:"timestamp"`
	Validated       bool             `json:"validated"`
	AccessTime      int64            `json:"access_time"`
	RefreshTime     int64            `json:"refresh_time,omitempty"`
	ECSFamily       uint16           `json:"ecs_family,omitempty"`
	ECSSourcePrefix uint8            `json:"ecs_source_prefix,omitempty"`
	ECSScopePrefix  uint8            `json:"ecs_scope_prefix,omitempty"`
	ECSAddress      string           `json:"ecs_address,omitempty"`
}

type CompactRecord struct {
	Text    string `json:"text"`
	OrigTTL uint32 `json:"orig_ttl"`
	Type    uint16 `json:"type"`
}

type RefreshRequest struct {
	Question            dns.Question
	ECS                 *ECSOption
	CacheKey            string
	ServerDNSSECEnabled bool
}

type NullCache struct{}

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

// =============================================================================
// Types - Connection
// =============================================================================

type ConnectionManager struct {
	timeout     time.Duration
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
	closed      int32
	queryClient *QueryClient
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
	UsedTCP    bool
	Protocol   string
	Validated  bool
	ECS        *ECSOption
}

// =============================================================================
// Types - Query Processing
// =============================================================================

type QueryManager struct {
	upstream  *UpstreamHandler
	recursive *RecursiveResolver
	cname     *CNAMEHandler
	validator *ResponseValidator
	server    *DNSServer
}

type UpstreamHandler struct {
	servers []*UpstreamServer
	mu      sync.RWMutex
}

type RecursiveResolver struct {
	server          *DNSServer
	rootServerMgr   *RootServerManager
	concurrencyLock chan struct{}
}

type CNAMEHandler struct {
	server *DNSServer
}

type ResponseValidator struct {
	hijackPrevention *HijackPrevention
	dnssecValidator  *DNSSECValidator
}

// =============================================================================
// Types - Security
// =============================================================================

type SecurityManager struct {
	tls    *TLSManager
	dnssec *DNSSECValidator
	hijack *HijackPrevention
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

type DNSSECValidator struct{}

type HijackPrevention struct {
	enabled bool
}

type QUICAddrValidator struct {
	cache *ristretto.Cache[string, struct{}]
	ttl   time.Duration
}

// =============================================================================
// Types - EDNS
// =============================================================================

type EDNSManager struct {
	defaultECS     *ECSOption
	detector       *IPDetector
	cache          sync.Map
	paddingEnabled bool
}

type ECSOption struct {
	Family       uint16 `json:"family"`
	SourcePrefix uint8  `json:"source_prefix"`
	ScopePrefix  uint8  `json:"scope_prefix"`
	Address      net.IP `json:"address"`
}

type IPDetector struct {
	httpClient *http.Client
}

// =============================================================================
// Types - Rewrite
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

// =============================================================================
// Types - SpeedTest
// =============================================================================

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

type SpeedResult struct {
	IP        string
	Latency   time.Duration
	Reachable bool
	Timestamp time.Time
}

// =============================================================================
// Types - Root Server
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

// =============================================================================
// Types - Resource Management
// =============================================================================

type ResourceManager struct {
	dnsMessages    sync.Pool
	buffers        sync.Pool
	stringBuilders sync.Pool
	stats          struct {
		gets int64
		puts int64
		news int64
	}
}

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

type RequestTracker struct {
	ID           string
	StartTime    time.Time
	Domain       string
	QueryType    string
	ClientIP     string
	Steps        []string
	CacheHit     bool
	Upstream     string
	ResponseTime time.Duration
	mu           sync.Mutex
}

// =============================================================================
// Types - DNS Server
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
	resourceMgr   *ResourceManager
	speedDebounce map[string]time.Time
	speedMutex    sync.Mutex
	speedInterval time.Duration
	ctx           context.Context
	cancel        context.CancelFunc
	shutdown      chan struct{}
	wg            sync.WaitGroup
	closed        int32
}

// =============================================================================
// Global Variables
// =============================================================================

var (
	NextProtoQUIC  = []string{"doq", "doq-i00", "doq-i02", "doq-i03", "dq"}
	NextProtoHTTP3 = []string{"h3"}
	NextProtoHTTP2 = []string{http2.NextProtoTLS, "http/1.1"}
)

var (
	GlobalLog      *LogManager
	GlobalConfig   *ConfigManager
	GlobalResource *ResourceManager
)

func init() {
	GlobalLog = NewLogManager()
	GlobalConfig = NewConfigManager()
	GlobalResource = NewResourceManager()
}

// =============================================================================
// Logging System
// =============================================================================

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

	levelStr := lm.GetLevelString(level)
	color := lm.colorMap[level]
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	message := fmt.Sprintf(format, args...)

	logLine := fmt.Sprintf("%s[%s]%s %s%-5s%s %s\n",
		ColorBold, timestamp, ColorReset,
		color, levelStr, ColorReset,
		message)

	_, _ = fmt.Fprint(lm.writer, logLine)
}

func (lm *LogManager) GetLevelString(level LogLevel) string {
	switch level {
	case Error:
		return "ERROR"
	case Warn:
		return "WARN"
	case Info:
		return "INFO"
	case Debug:
		return "DEBUG"
	default:
		return "UNKNOWN"
	}
}

func (lm *LogManager) Error(format string, args ...interface{}) { lm.Log(Error, format, args...) }
func (lm *LogManager) Warn(format string, args ...interface{})  { lm.Log(Warn, format, args...) }
func (lm *LogManager) Info(format string, args ...interface{})  { lm.Log(Info, format, args...) }
func (lm *LogManager) Debug(format string, args ...interface{}) { lm.Log(Debug, format, args...) }

// Helper functions for global logging
func LogError(format string, args ...interface{}) { GlobalLog.Error(format, args...) }
func LogWarn(format string, args ...interface{})  { GlobalLog.Warn(format, args...) }
func LogInfo(format string, args ...interface{})  { GlobalLog.Info(format, args...) }
func LogDebug(format string, args ...interface{}) { GlobalLog.Debug(format, args...) }

// =============================================================================
// Configuration Management
// =============================================================================

func NewConfigManager() *ConfigManager {
	return &ConfigManager{}
}

func (cm *ConfigManager) LoadConfig(configFile string) (*ServerConfig, error) {
	if configFile == "" {
		return cm.GetDefaultConfig(), nil
	}

	data, err := os.ReadFile(configFile)
	if err != nil {
		return nil, WrapError("read config file", err)
	}

	config := &ServerConfig{}
	if err := json.Unmarshal(data, config); err != nil {
		return nil, WrapError("parse config file", err)
	}

	if err := cm.ValidateConfig(config); err != nil {
		return nil, WrapError("validate config", err)
	}

	if cm.ShouldEnableDDR(config) {
		cm.AddDDRRecords(config)
	}

	LogInfo("Configuration loaded successfully: %s", configFile)
	return config, nil
}

func (cm *ConfigManager) ValidateConfig(config *ServerConfig) error {
	// Validate log level
	validLevels := map[string]LogLevel{
		"error": Error, "warn": Warn,
		"info": Info, "debug": Debug,
	}

	if level, ok := validLevels[strings.ToLower(config.Server.LogLevel)]; ok {
		GlobalLog.SetLevel(level)
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
				return WrapError("invalid ECS subnet", err)
			}
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
		if IsSecureProtocol(protocol) && server.ServerName == "" {
			return fmt.Errorf("upstream server %d using %s requires server_name", i, server.Protocol)
		}
	}

	// Validate Redis
	if config.Redis.Address != "" {
		if _, _, err := net.SplitHostPort(config.Redis.Address); err != nil {
			return WrapError("redis address invalid", err)
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

		if !IsValidFilePath(config.Server.TLS.CertFile) {
			return fmt.Errorf("cert file not found: %s", config.Server.TLS.CertFile)
		}

		if !IsValidFilePath(config.Server.TLS.KeyFile) {
			return fmt.Errorf("key file not found: %s", config.Server.TLS.KeyFile)
		}

		if _, err := tls.LoadX509KeyPair(config.Server.TLS.CertFile, config.Server.TLS.KeyFile); err != nil {
			return WrapError("load certificate", err)
		}

		LogInfo("TLS certificate verified")
	}

	return nil
}

func (cm *ConfigManager) GetDefaultConfig() *ServerConfig {
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
	config.Server.TLS.CertFile = ""
	config.Server.TLS.KeyFile = ""

	config.Server.Features.ServeStale = false
	config.Server.Features.Prefetch = false
	config.Server.Features.DNSSEC = true
	config.Server.Features.HijackProtection = true
	config.Server.Features.Padding = true

	config.Redis.Address = ""
	config.Redis.Password = ""
	config.Redis.Database = 0
	config.Redis.KeyPrefix = "zjdns:"

	config.Upstream = []UpstreamServer{}
	config.Rewrite = []RewriteRule{}
	config.SpeedTest = []SpeedTestMethod{}

	return config
}

func (cm *ConfigManager) ShouldEnableDDR(config *ServerConfig) bool {
	return config.Server.DDR.Domain != "" &&
		(config.Server.DDR.IPv4 != "" || config.Server.DDR.IPv6 != "")
}

func (cm *ConfigManager) AddDDRRecords(config *ServerConfig) {
	domain := strings.TrimSuffix(config.Server.DDR.Domain, ".")

	svcbRecords := []DNSRecordConfig{
		{
			Type:    "SVCB",
			Content: "1 . alpn=h3,h2 port=" + config.Server.TLS.HTTPS.Port,
		},
		{
			Type:    "SVCB",
			Content: "2 . alpn=doq,dot port=" + config.Server.TLS.Port,
		},
	}

	var additionalRecords []DNSRecordConfig
	var directQueryRecords []DNSRecordConfig

	nxdomainCode := dns.RcodeNameError

	if config.Server.DDR.IPv4 != "" {
		svcbRecords[0].Content += " ipv4hint=" + config.Server.DDR.IPv4
		svcbRecords[1].Content += " ipv4hint=" + config.Server.DDR.IPv4

		ipv4Record := DNSRecordConfig{
			Type:    "A",
			Content: config.Server.DDR.IPv4,
		}

		additionalRecords = append(additionalRecords, DNSRecordConfig{
			Name:    domain,
			Type:    ipv4Record.Type,
			Content: ipv4Record.Content,
		})

		directQueryRecords = append(directQueryRecords, ipv4Record)
	} else {
		nxdomainARecord := DNSRecordConfig{
			Type:         "A",
			ResponseCode: &nxdomainCode,
		}
		config.Rewrite = append(config.Rewrite, RewriteRule{
			Name:    domain,
			Records: []DNSRecordConfig{nxdomainARecord},
		})
		LogDebug("Adding DDR NXDOMAIN rule for A record: %s", domain)
	}

	if config.Server.DDR.IPv6 != "" {
		svcbRecords[0].Content += " ipv6hint=" + config.Server.DDR.IPv6
		svcbRecords[1].Content += " ipv6hint=" + config.Server.DDR.IPv6

		ipv6Record := DNSRecordConfig{
			Type:    "AAAA",
			Content: config.Server.DDR.IPv6,
		}

		additionalRecords = append(additionalRecords, DNSRecordConfig{
			Name:    domain,
			Type:    ipv6Record.Type,
			Content: ipv6Record.Content,
		})

		directQueryRecords = append(directQueryRecords, ipv6Record)
	} else {
		nxdomainAAAARecord := DNSRecordConfig{
			Type:         "AAAA",
			ResponseCode: &nxdomainCode,
		}
		config.Rewrite = append(config.Rewrite, RewriteRule{
			Name:    domain,
			Records: []DNSRecordConfig{nxdomainAAAARecord},
		})
		LogDebug("Adding DDR NXDOMAIN rule for AAAA record: %s", domain)
	}

	if config.Server.DDR.IPv4 != "" || config.Server.DDR.IPv6 != "" {
		ddrRuleNames := []string{
			"_dns.resolver.arpa",
			"_dns." + domain,
		}

		if config.Server.Port != "" && config.Server.Port != DefaultDNSPort {
			ddrRuleNames = append(ddrRuleNames, "_"+config.Server.Port+"._dns."+domain)
		}

		for _, ruleName := range ddrRuleNames {
			ddrRule := RewriteRule{
				Name:       ruleName,
				Records:    svcbRecords,
				Additional: additionalRecords,
			}
			config.Rewrite = append(config.Rewrite, ddrRule)
			LogDebug("Adding DDR SVCB rewrite rule: %s", ruleName)
		}

		if len(directQueryRecords) > 0 {
			directRule := RewriteRule{
				Name:    domain,
				Records: directQueryRecords,
			}
			config.Rewrite = append(config.Rewrite, directRule)
			LogDebug("Adding DDR direct query rewrite rule: %s (%d records)", domain, len(directQueryRecords))
		}
	}
}

func GenerateExampleConfig() string {
	config := GlobalConfig.GetDefaultConfig()

	config.Server.LogLevel = DefaultLogLevel
	config.Server.DefaultECS = "auto"

	config.Redis.Address = "127.0.0.1:6379"

	config.Server.TLS.CertFile = "/path/to/cert.pem"
	config.Server.TLS.KeyFile = "/path/to/key.pem"
	config.Server.TLS.HTTPS.Port = DefaultHTTPSPort
	config.Server.TLS.HTTPS.Endpoint = DefaultQueryPath

	config.Upstream = []UpstreamServer{
		{
			Address:  "223.5.5.5:53",
			Protocol: "tcp",
		},
		{
			Address:  "223.6.6.6:53",
			Protocol: "udp",
		},
		{
			Address:       "223.5.5.5:853",
			Protocol:      "tls",
			ServerName:    "dns.alidns.com",
			SkipTLSVerify: false,
		},
		{
			Address:       "223.6.6.6:853",
			Protocol:      "quic",
			ServerName:    "dns.alidns.com",
			SkipTLSVerify: true,
		},
		{
			Address:       "https://dns.alidns.com/dns-query",
			Protocol:      "https",
			ServerName:    "dns.alidns.com",
			SkipTLSVerify: false,
		},
		{
			Address:       "https://dns.alidns.com/dns-query",
			Protocol:      "http3",
			ServerName:    "dns.alidns.com",
			SkipTLSVerify: false,
		},
		{
			Address: RecursiveIndicator,
		},
	}

	config.Rewrite = []RewriteRule{
		{
			Name: "blocked.example.com",
			Records: []DNSRecordConfig{
				{
					Type:    "A",
					Content: "127.0.0.1",
					TTL:     DefaultCacheTTL,
				},
			},
		},
		{
			Name: "ipv6.blocked.example.com",
			Records: []DNSRecordConfig{
				{
					Type:    "AAAA",
					Content: "::1",
					TTL:     DefaultCacheTTL,
				},
			},
		},
	}

	config.SpeedTest = []SpeedTestMethod{
		{
			Type:    "icmp",
			Timeout: int(DefaultSpeedTimeout.Milliseconds()),
		},
		{
			Type:    "tcp",
			Port:    "443",
			Timeout: int(DefaultSpeedTimeout.Milliseconds()),
		},
		{
			Type:    "tcp",
			Port:    "80",
			Timeout: int(DefaultSpeedTimeout.Milliseconds()),
		},
		{
			Type:    "udp",
			Port:    "53",
			Timeout: int(DefaultSpeedTimeout.Milliseconds()),
		},
	}

	data, _ := json.MarshalIndent(config, "", "  ")
	return string(data)
}

// =============================================================================
// Cache System
// =============================================================================

func NewNullCache() *NullCache {
	LogInfo("No cache mode")
	return &NullCache{}
}

func (nc *NullCache) Get(key string) (*CacheEntry, bool, bool) { return nil, false, false }
func (nc *NullCache) Set(key string, answer, authority, additional []dns.RR, validated bool, ecs *ECSOption) {
}
func (nc *NullCache) RequestRefresh(req RefreshRequest) {}
func (nc *NullCache) Close() error                      { return nil }

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
		return nil, WrapError("redis connection", err)
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
		cache.StartRefreshProcessor()
	}

	LogInfo("Redis cache initialized")
	return cache, nil
}

func (rc *RedisCache) StartRefreshProcessor() {
	workerCount := 2

	for i := 0; i < workerCount; i++ {
		rc.wg.Add(1)
		go func(workerID int) {
			defer rc.wg.Done()
			defer HandlePanic(fmt.Sprintf("Redis refresh worker %d", workerID))

			for {
				select {
				case req := <-rc.refreshQueue:
					rc.HandleRefreshRequest(req)
				case <-rc.ctx.Done():
					return
				}
			}
		}(i)
	}
}

func (rc *RedisCache) HandleRefreshRequest(req RefreshRequest) {
	defer HandlePanic("Redis refresh request")

	if atomic.LoadInt32(&rc.closed) != 0 {
		return
	}

	answer, authority, additional, validated, ecsResponse, err := rc.server.QueryForRefresh(
		req.Question, req.ECS, req.ServerDNSSECEnabled)

	if err != nil {
		rc.UpdateRefreshTime(req.CacheKey)
		return
	}

	if len(rc.server.config.SpeedTest) > 0 && (req.Question.Qtype == dns.TypeA || req.Question.Qtype == dns.TypeAAAA) {
		tempMsg := &dns.Msg{
			Answer: answer,
			Ns:     authority,
			Extra:  additional,
		}

		speedTester := NewSpeedTestManager(*rc.server.config)
		speedTester.PerformSpeedTestAndSort(tempMsg)
		CloseWithLog(speedTester, "SpeedTester")

		answer = tempMsg.Answer
		authority = tempMsg.Ns
		additional = tempMsg.Extra
	}

	allRRs := make([]dns.RR, 0, len(answer)+len(authority)+len(additional))
	allRRs = append(allRRs, answer...)
	allRRs = append(allRRs, authority...)
	allRRs = append(allRRs, additional...)

	cacheTTL := CalculateTTL(allRRs)
	now := time.Now().Unix()

	entry := &CacheEntry{
		Answer:      CompactRecords(answer),
		Authority:   CompactRecords(authority),
		Additional:  CompactRecords(additional),
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

func (rc *RedisCache) UpdateRefreshTime(cacheKey string) {
	defer HandlePanic("Update refresh time")

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

func (rc *RedisCache) Get(key string) (*CacheEntry, bool, bool) {
	defer HandlePanic("Redis cache get")

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
		LogDebug("Cache entry parse failed: %v", err)
		go func() {
			defer HandlePanic("Clean corrupted cache")
			rc.client.Del(context.Background(), fullKey)
		}()
		return nil, false, false
	}

	if entry.IsStale() {
		go func() {
			defer HandlePanic("Clean stale cache")
			rc.client.Del(context.Background(), fullKey)
		}()
		return nil, false, false
	}

	entry.AccessTime = time.Now().Unix()
	go func() {
		defer HandlePanic("Update access time")
		rc.UpdateAccessInfo(fullKey, &entry)
	}()

	isExpired := entry.IsExpired()

	if !rc.config.Server.Features.ServeStale && isExpired {
		go func() {
			defer HandlePanic("Clean expired cache")
			rc.client.Del(context.Background(), fullKey)
		}()
		return nil, false, false
	}

	return &entry, true, isExpired
}

func (rc *RedisCache) Set(key string, answer, authority, additional []dns.RR, validated bool, ecs *ECSOption) {
	defer HandlePanic("Redis cache set")

	if atomic.LoadInt32(&rc.closed) != 0 {
		return
	}

	allRRs := make([]dns.RR, 0, len(answer)+len(authority)+len(additional))
	allRRs = append(allRRs, answer...)
	allRRs = append(allRRs, authority...)
	allRRs = append(allRRs, additional...)

	cacheTTL := CalculateTTL(allRRs)
	now := time.Now().Unix()

	entry := &CacheEntry{
		Answer:      CompactRecords(answer),
		Authority:   CompactRecords(authority),
		Additional:  CompactRecords(additional),
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
		expiration += time.Duration(StaleMaxAge) * time.Second
	}

	rc.client.Set(rc.ctx, fullKey, data, expiration)
}

func (rc *RedisCache) UpdateAccessInfo(fullKey string, entry *CacheEntry) {
	defer HandlePanic("Redis access info update")

	if atomic.LoadInt32(&rc.closed) != 0 {
		return
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return
	}
	rc.client.Set(rc.ctx, fullKey, data, redis.KeepTTL)
}

func (rc *RedisCache) RequestRefresh(req RefreshRequest) {
	if atomic.LoadInt32(&rc.closed) != 0 {
		return
	}

	select {
	case rc.refreshQueue <- req:
	default:
	}
}

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

func (c *CacheEntry) IsExpired() bool {
	if c == nil {
		return true
	}
	return time.Now().Unix()-c.Timestamp > int64(c.TTL)
}

func (c *CacheEntry) IsStale() bool {
	if c == nil {
		return true
	}
	return time.Now().Unix()-c.Timestamp > int64(c.TTL+StaleMaxAge)
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

	return c.IsExpired() &&
		(now-c.Timestamp) > refreshInterval &&
		(now-c.RefreshTime) > refreshInterval
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

// =============================================================================
// Connection Management
// =============================================================================

func NewConnectionManager() *ConnectionManager {
	ctx, cancel := context.WithCancel(context.Background())
	return &ConnectionManager{
		timeout: QueryTimeout,
		ctx:     ctx,
		cancel:  cancel,
	}
}

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

// =============================================================================
// Query Client
// =============================================================================

func NewQueryClient(connMgr *ConnectionManager) *QueryClient {
	return &QueryClient{
		connMgr: connMgr,
		timeout: QueryTimeout,
	}
}

func (qc *QueryClient) ExecuteQuery(ctx context.Context, msg *dns.Msg, server *UpstreamServer, tracker *RequestTracker) *QueryResult {
	start := time.Now()
	result := &QueryResult{
		Server:   server.Address,
		Protocol: server.Protocol,
	}

	if tracker != nil {
		tracker.AddStep("Starting query: %s (%s)", server.Address, server.Protocol)
	}

	queryCtx, cancel := context.WithTimeout(ctx, qc.timeout)
	defer cancel()

	protocol := strings.ToLower(server.Protocol)

	if IsSecureProtocol(protocol) {
		result.Response, result.Error = qc.ExecuteSecureQuery(queryCtx, msg, server, tracker)
		result.Duration = time.Since(start)
		result.Protocol = strings.ToUpper(protocol)
		return result
	}

	result.Response, result.Error = qc.ExecuteTraditionalQuery(queryCtx, msg, server, tracker)
	result.Duration = time.Since(start)

	if qc.NeedsTCPFallback(result, protocol) {
		if tracker != nil {
			tracker.AddStep("TCP fallback required")
		}

		tcpServer := *server
		tcpServer.Protocol = "tcp"
		tcpResponse, tcpErr := qc.ExecuteTraditionalQuery(queryCtx, msg, &tcpServer, tracker)

		if tcpErr != nil {
			if result.Response != nil && result.Response.Rcode != dns.RcodeServerFailure {
				if tracker != nil {
					tracker.AddStep("TCP fallback failed, using UDP response")
				}
				return result
			}
			result.Error = tcpErr
		} else {
			result.Response = tcpResponse
			result.Error = nil
			result.UsedTCP = true
			result.Protocol = "TCP"
			if tracker != nil {
				tracker.AddStep("TCP fallback successful")
			}
		}
		result.Duration = time.Since(start)
	}

	return result
}

func (qc *QueryClient) ExecuteSecureQuery(ctx context.Context, msg *dns.Msg, server *UpstreamServer, tracker *RequestTracker) (*dns.Msg, error) {
	protocol := strings.ToLower(server.Protocol)

	switch protocol {
	case "tls":
		return qc.ExecuteTLSQuery(ctx, msg, server, tracker)
	case "quic":
		return qc.ExecuteQUICQuery(ctx, msg, server, tracker)
	case "https", "http3":
		return qc.ExecuteDoHQuery(ctx, msg, server, tracker)
	default:
		return nil, fmt.Errorf("unsupported protocol: %s", protocol)
	}
}

func (qc *QueryClient) ExecuteTLSQuery(ctx context.Context, msg *dns.Msg, server *UpstreamServer, tracker *RequestTracker) (*dns.Msg, error) {
	host, port, err := net.SplitHostPort(server.Address)
	if err != nil {
		return nil, WrapError("parse TLS address", err)
	}

	tlsConfig := &tls.Config{
		ServerName:         server.ServerName,
		InsecureSkipVerify: server.SkipTLSVerify,
		MinVersion:         tls.VersionTLS12,
	}

	dialer := &net.Dialer{
		Timeout: TLSHandshakeTimeout,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(host, port), tlsConfig)
	if err != nil {
		return nil, WrapError("TLS dial", err)
	}
	defer func() { _ = conn.Close() }()

	if err := conn.SetDeadline(time.Now().Add(qc.timeout)); err != nil {
		return nil, WrapError("set TLS deadline", err)
	}

	msgData, err := msg.Pack()
	if err != nil {
		return nil, WrapError("pack message", err)
	}

	buf := make([]byte, 2+len(msgData))
	binary.BigEndian.PutUint16(buf[:2], uint16(len(msgData)))
	copy(buf[2:], msgData)

	if _, err := conn.Write(buf); err != nil {
		return nil, WrapError("send TLS query", err)
	}

	lengthBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, lengthBuf); err != nil {
		return nil, WrapError("read response length", err)
	}

	respLength := binary.BigEndian.Uint16(lengthBuf)
	if respLength == 0 || respLength > TCPBufferSize {
		return nil, fmt.Errorf("invalid response length: %d", respLength)
	}

	respBuf := make([]byte, respLength)
	if _, err := io.ReadFull(conn, respBuf); err != nil {
		return nil, WrapError("read response", err)
	}

	response := new(dns.Msg)
	if err := response.Unpack(respBuf); err != nil {
		return nil, WrapError("parse response", err)
	}

	if tracker != nil {
		tracker.AddStep("TLS query successful, rcode: %s", dns.RcodeToString[response.Rcode])
	}

	return response, nil
}

func (qc *QueryClient) ExecuteQUICQuery(ctx context.Context, msg *dns.Msg, server *UpstreamServer, tracker *RequestTracker) (*dns.Msg, error) {
	tlsConfig := &tls.Config{
		ServerName:         server.ServerName,
		InsecureSkipVerify: server.SkipTLSVerify,
		NextProtos:         NextProtoQUIC,
	}

	quicConfig := &quic.Config{
		MaxIdleTimeout:     SecureIdleTimeout,
		MaxIncomingStreams: MaxIncomingStreams,
	}

	conn, err := quic.DialAddr(ctx, server.Address, tlsConfig, quicConfig)
	if err != nil {
		return nil, WrapError("QUIC dial", err)
	}
	defer func() { _ = conn.CloseWithError(QUICCodeNoError, "") }()

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, WrapError("create QUIC stream", err)
	}
	defer func() { _ = stream.Close() }()

	if err := stream.SetDeadline(time.Now().Add(qc.timeout)); err != nil {
		return nil, WrapError("set stream timeout", err)
	}

	// 保存原始 ID
	originalID := msg.Id
	msg.Id = 0

	msgData, err := msg.Pack()
	if err != nil {
		msg.Id = originalID
		return nil, WrapError("pack message", err)
	}

	buf := make([]byte, 2+len(msgData))
	binary.BigEndian.PutUint16(buf[:2], uint16(len(msgData)))
	copy(buf[2:], msgData)

	if _, err := stream.Write(buf); err != nil {
		msg.Id = originalID
		return nil, WrapError("send QUIC query", err)
	}

	if err := stream.Close(); err != nil {
		LogDebug("Close QUIC stream write failed: %v", err)
	}

	respBuf := make([]byte, SecureBufferSize)
	n, err := stream.Read(respBuf)
	if err != nil && n == 0 {
		msg.Id = originalID
		return nil, WrapError("read QUIC response", err)
	}

	stream.CancelRead(0)

	if n < 2 {
		msg.Id = originalID
		return nil, fmt.Errorf("QUIC response too short: %d bytes", n)
	}

	response := new(dns.Msg)
	if err := response.Unpack(respBuf[2:n]); err != nil {
		msg.Id = originalID
		return nil, WrapError("parse QUIC response", err)
	}

	// 恢复原始 ID
	msg.Id = originalID
	response.Id = originalID

	if tracker != nil {
		tracker.AddStep("QUIC query successful, rcode: %s", dns.RcodeToString[response.Rcode])
	}

	return response, nil
}

func (qc *QueryClient) ExecuteDoHQuery(ctx context.Context, msg *dns.Msg, server *UpstreamServer, tracker *RequestTracker) (*dns.Msg, error) {
	parsedURL, err := url.Parse(server.Address)
	if err != nil {
		return nil, WrapError("parse DoH address", err)
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
	protocol := strings.ToLower(server.Protocol)

	if protocol == "http3" {
		tlsConfig.NextProtos = NextProtoHTTP3
		quicConfig := &quic.Config{
			MaxIdleTimeout:     SecureIdleTimeout,
			MaxIncomingStreams: MaxIncomingStreams,
		}
		transport = &http3.Transport{
			TLSClientConfig: tlsConfig,
			QUICConfig:      quicConfig,
		}
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

	httpClient := &http.Client{
		Transport: transport,
		Timeout:   qc.timeout,
	}

	// 保存原始 ID
	originalID := msg.Id
	msg.Id = 0

	buf, err := msg.Pack()
	if err != nil {
		msg.Id = originalID
		return nil, WrapError("pack DNS message", err)
	}

	q := url.Values{
		"dns": []string{base64.RawURLEncoding.EncodeToString(buf)},
	}

	u := url.URL{
		Scheme:   parsedURL.Scheme,
		Host:     parsedURL.Host,
		Path:     parsedURL.Path,
		RawQuery: q.Encode(),
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		msg.Id = originalID
		return nil, WrapError("create HTTP request", err)
	}

	httpReq.Header.Set("Accept", "application/dns-message")
	httpReq.Header.Set("User-Agent", "")

	httpResp, err := httpClient.Do(httpReq)
	if err != nil {
		msg.Id = originalID
		return nil, WrapError("send HTTP request", err)
	}
	defer func() { _ = httpResp.Body.Close() }()

	if httpResp.StatusCode != http.StatusOK {
		msg.Id = originalID
		return nil, fmt.Errorf("HTTP error: %d", httpResp.StatusCode)
	}

	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		msg.Id = originalID
		return nil, WrapError("read response", err)
	}

	response := &dns.Msg{}
	if err := response.Unpack(body); err != nil {
		msg.Id = originalID
		return nil, WrapError("parse DNS response", err)
	}

	// 恢复原始 ID
	msg.Id = originalID
	response.Id = originalID

	if tracker != nil {
		tracker.AddStep("DoH query successful, rcode: %s", dns.RcodeToString[response.Rcode])
	}

	return response, nil
}

func (qc *QueryClient) ExecuteTraditionalQuery(ctx context.Context, msg *dns.Msg, server *UpstreamServer, tracker *RequestTracker) (*dns.Msg, error) {
	msgCopy := SafeCopyMessage(msg)
	defer GlobalResource.PutDNSMessage(msgCopy)

	client := &dns.Client{
		Timeout: qc.timeout,
		Net:     server.Protocol,
	}

	if server.Protocol == "udp" {
		client.UDPSize = UDPBufferSize
	}

	response, _, err := client.ExchangeContext(ctx, msgCopy, server.Address)

	if tracker != nil && err == nil && response != nil {
		protocolName := strings.ToUpper(server.Protocol)
		tracker.AddStep("%s query successful, rcode: %s", protocolName, dns.RcodeToString[response.Rcode])
	}

	return response, err
}

func (qc *QueryClient) NeedsTCPFallback(result *QueryResult, protocol string) bool {
	if protocol == "tcp" {
		return false
	}

	if result.Error != nil {
		return true
	}

	if result.Response != nil && result.Response.Truncated {
		return true
	}

	return false
}

// =============================================================================
// Query Management
// =============================================================================

func NewQueryManager(server *DNSServer) *QueryManager {
	return &QueryManager{
		upstream: &UpstreamHandler{
			servers: make([]*UpstreamServer, 0),
		},
		recursive: &RecursiveResolver{
			server:          server,
			rootServerMgr:   server.rootServerMgr,
			concurrencyLock: make(chan struct{}, MaxConcurrency),
		},
		cname: &CNAMEHandler{
			server: server,
		},
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

func (qm *QueryManager) Query(question dns.Question, ecs *ECSOption, serverDNSSECEnabled bool, tracker *RequestTracker) ([]dns.RR, []dns.RR, []dns.RR, bool, *ECSOption, error) {
	servers := qm.upstream.GetServers()
	if len(servers) > 0 {
		if tracker != nil {
			tracker.AddStep("Using upstream query (%d servers)", len(servers))
		}
		return qm.QueryUpstream(question, ecs, serverDNSSECEnabled, tracker)
	} else {
		if tracker != nil {
			tracker.AddStep("Using recursive resolution")
		}
		ctx, cancel := context.WithTimeout(qm.server.ctx, RecursiveTimeout)
		defer cancel()
		return qm.cname.ResolveWithCNAME(ctx, question, ecs, tracker)
	}
}

func (qm *QueryManager) QueryUpstream(question dns.Question, ecs *ECSOption, serverDNSSECEnabled bool, tracker *RequestTracker) ([]dns.RR, []dns.RR, []dns.RR, bool, *ECSOption, error) {
	servers := qm.upstream.GetServers()
	if len(servers) == 0 {
		return nil, nil, nil, false, nil, errors.New("no upstream servers")
	}

	if tracker != nil {
		tracker.AddStep("Starting concurrent query of %d servers", len(servers))
	}

	resultChan := make(chan *QueryResult, len(servers))
	ctx, cancel := context.WithTimeout(qm.server.ctx, QueryTimeout)
	defer cancel()

	for _, server := range servers {
		srv := server

		if srv.IsRecursive() {
			qm.server.taskMgr.ExecuteAsync("Query-Recursive", func(taskCtx context.Context) error {
				recursiveCtx, recursiveCancel := context.WithTimeout(taskCtx, RecursiveTimeout)
				defer recursiveCancel()

				answer, authority, additional, validated, ecsResponse, err := qm.cname.ResolveWithCNAME(
					recursiveCtx, question, ecs, tracker)

				if err == nil && len(answer) > 0 {
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
				}
				return nil
			})

		} else {
			originalMsg := qm.server.BuildQueryMessage(question, ecs, serverDNSSECEnabled, true, false)
			msg := SafeCopyMessage(originalMsg)
			GlobalResource.PutDNSMessage(originalMsg)

			qm.server.taskMgr.ExecuteAsync(fmt.Sprintf("Query-%s", srv.Address), func(taskCtx context.Context) error {
				result := qm.server.connMgr.queryClient.ExecuteQuery(taskCtx, msg, srv, tracker)

				if result.Error == nil && result.Response != nil {
					rcode := result.Response.Rcode
					if rcode == dns.RcodeSuccess || rcode == dns.RcodeNameError {
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
					}
				}
				return nil
			})
		}
	}

	var lastError error
	receivedCount := 0
	serversCount := len(servers)

	for receivedCount < serversCount {
		select {
		case result := <-resultChan:
			receivedCount++

			if result.Error != nil {
				lastError = result.Error
				if tracker != nil {
					tracker.AddStep("Server %s error: %v", result.Server, result.Error)
				}
				continue
			}

			if len(result.Answer) > 0 {
				if tracker != nil {
					tracker.AddStep("Using result from: %s", result.Server)
				}
				return result.Answer, result.Authority, result.Additional, result.Validated, result.ECS, nil
			}

			continue

		case <-ctx.Done():
			if tracker != nil {
				tracker.AddStep("Query cancelled after %d/%d responses", receivedCount, serversCount)
			}
			if lastError != nil {
				return nil, nil, nil, false, nil, lastError
			}
			return nil, nil, nil, false, nil, errors.New("all upstream queries failed or timed out")
		}
	}

	if tracker != nil {
		tracker.AddStep("All %d upstream servers returned no valid records", serversCount)
	}
	if lastError != nil {
		return nil, nil, nil, false, nil, lastError
	}
	return nil, nil, nil, false, nil, errors.New("all upstream queries returned no valid records")
}

func (uh *UpstreamHandler) GetServers() []*UpstreamServer {
	uh.mu.RLock()
	defer uh.mu.RUnlock()
	return uh.servers
}

func (u *UpstreamServer) IsRecursive() bool {
	return strings.ToLower(u.Address) == RecursiveIndicator
}

// =============================================================================
// CNAME Handler
// =============================================================================

func (ch *CNAMEHandler) ResolveWithCNAME(ctx context.Context, question dns.Question, ecs *ECSOption, tracker *RequestTracker) ([]dns.RR, []dns.RR, []dns.RR, bool, *ECSOption, error) {
	var allAnswers []dns.RR
	var finalAuthority, finalAdditional []dns.RR
	var finalECSResponse *ECSOption
	allValidated := true

	currentQuestion := question
	visitedCNAMEs := make(map[string]bool)

	if tracker != nil {
		tracker.AddStep("Starting CNAME chain resolution")
	}

	for i := 0; i < MaxCNAMEChain; i++ {
		select {
		case <-ctx.Done():
			return nil, nil, nil, false, nil, ctx.Err()
		default:
		}

		currentName := strings.ToLower(currentQuestion.Name)
		if visitedCNAMEs[currentName] {
			return nil, nil, nil, false, nil, fmt.Errorf("CNAME loop detected: %s", currentName)
		}
		visitedCNAMEs[currentName] = true

		if tracker != nil {
			tracker.AddStep("Resolving CNAME step %d: %s", i+1, currentQuestion.Name)
		}

		answer, authority, additional, validated, ecsResponse, err := ch.server.queryMgr.recursive.RecursiveQuery(ctx, currentQuestion, ecs, 0, false, tracker)
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
						tracker.AddStep("CNAME found: %s -> %s", currentQuestion.Name, cname.Target)
					}
				}
			} else if rr.Header().Rrtype == currentQuestion.Qtype {
				hasTargetType = true
			}
		}

		if hasTargetType || currentQuestion.Qtype == dns.TypeCNAME || nextCNAME == nil {
			if tracker != nil {
				tracker.AddStep("CNAME chain resolution completed")
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

// =============================================================================
// Recursive Resolver
// =============================================================================

func (rr *RecursiveResolver) RecursiveQuery(ctx context.Context, question dns.Question, ecs *ECSOption, depth int, forceTCP bool, tracker *RequestTracker) ([]dns.RR, []dns.RR, []dns.RR, bool, *ECSOption, error) {
	if depth > MaxRecursionDepth {
		return nil, nil, nil, false, nil, fmt.Errorf("recursion depth exceeded: %d", depth)
	}

	qname := dns.Fqdn(question.Name)
	question.Name = qname
	nameservers := rr.GetRootServers()
	currentDomain := "."

	normalizedQname := strings.ToLower(strings.TrimSuffix(qname, "."))

	if tracker != nil {
		tracker.AddStep("Starting recursive query: %s, depth=%d, TCP=%v", normalizedQname, depth, forceTCP)
	}

	if normalizedQname == "" {
		response, err := rr.QueryNameserversConcurrent(ctx, nameservers, question, ecs, forceTCP, tracker)
		if err != nil {
			return nil, nil, nil, false, nil, WrapError("root domain query", err)
		}

		if rr.server.securityMgr.hijack.IsEnabled() {
			if valid, reason := rr.server.securityMgr.hijack.CheckResponse(currentDomain, normalizedQname, response); !valid {
				return rr.HandleSuspiciousResponse(reason, forceTCP, ctx, question, ecs, depth, tracker)
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
			return nil, nil, nil, false, nil, ctx.Err()
		default:
		}

		if tracker != nil {
			tracker.AddStep("Querying authoritative: %s (%d NS)", currentDomain, len(nameservers))
		}

		response, err := rr.QueryNameserversConcurrent(ctx, nameservers, question, ecs, forceTCP, tracker)
		if err != nil {
			if !forceTCP && strings.HasPrefix(err.Error(), "DNS_HIJACK_DETECTED") {
				if tracker != nil {
					tracker.AddStep("DNS hijacking detected, switching to TCP")
				}
				return rr.RecursiveQuery(ctx, question, ecs, depth, true, tracker)
			}
			return nil, nil, nil, false, nil, WrapError(fmt.Sprintf("query %s", currentDomain), err)
		}

		if rr.server.securityMgr.hijack.IsEnabled() {
			if valid, reason := rr.server.securityMgr.hijack.CheckResponse(currentDomain, normalizedQname, response); !valid {
				answer, authority, additional, validated, ecsResponse, err := rr.HandleSuspiciousResponse(reason, forceTCP, ctx, question, ecs, depth, tracker)
				if err != nil && !forceTCP && strings.HasPrefix(err.Error(), "DNS_HIJACK_DETECTED") {
					if tracker != nil {
						tracker.AddStep("DNS hijacking detected, switching to TCP")
					}
					return rr.RecursiveQuery(ctx, question, ecs, depth, true, tracker)
				}
				return answer, authority, additional, validated, ecsResponse, err
			}
		}

		validated := false
		if rr.server.config.Server.Features.DNSSEC {
			validated = rr.server.securityMgr.dnssec.ValidateResponse(response, true)
		}

		ecsResponse := rr.server.ednsMgr.ParseFromDNS(response)

		if len(response.Answer) > 0 {
			if tracker != nil {
				tracker.AddStep("Got final answer: %d records", len(response.Answer))
			}
			return response.Answer, response.Ns, response.Extra, validated, ecsResponse, nil
		}

		bestMatch := ""
		var bestNSRecords []*dns.NS

		for _, rrec := range response.Ns {
			if ns, ok := rrec.(*dns.NS); ok {
				nsName := strings.ToLower(strings.TrimSuffix(rrec.Header().Name, "."))

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
				tracker.AddStep("No matching NS records, returning authority")
			}
			return nil, response.Ns, response.Extra, validated, ecsResponse, nil
		}

		currentDomainNormalized := strings.ToLower(strings.TrimSuffix(currentDomain, "."))
		if bestMatch == currentDomainNormalized && currentDomainNormalized != "" {
			if tracker != nil {
				tracker.AddStep("Query loop detected, stopping")
			}
			return nil, response.Ns, response.Extra, validated, ecsResponse, nil
		}

		currentDomain = bestMatch + "."

		var nextNS []string
		for _, ns := range bestNSRecords {
			for _, rrec := range response.Extra {
				switch a := rrec.(type) {
				case *dns.A:
					if strings.EqualFold(a.Header().Name, ns.Ns) {
						nextNS = append(nextNS, net.JoinHostPort(a.A.String(), DefaultDNSPort))
					}
				case *dns.AAAA:
					// 移除 IPv6 判断，总是尝试解析 IPv6
					if strings.EqualFold(a.Header().Name, ns.Ns) {
						nextNS = append(nextNS, net.JoinHostPort(a.AAAA.String(), DefaultDNSPort))
					}
				}
			}
		}

		if len(nextNS) == 0 {
			if tracker != nil {
				tracker.AddStep("No NS addresses in Additional, resolving NS")
			}
			nextNS = rr.ResolveNSAddressesConcurrent(ctx, bestNSRecords, qname, depth, forceTCP, tracker)
		}

		if len(nextNS) == 0 {
			if tracker != nil {
				tracker.AddStep("Cannot get NS addresses, returning authority")
			}
			return nil, response.Ns, response.Extra, validated, ecsResponse, nil
		}

		nameservers = nextNS
		if tracker != nil {
			tracker.AddStep("Next round, switching to: %s (%d NS)", bestMatch, len(nextNS))
		}
	}
}

func (rr *RecursiveResolver) HandleSuspiciousResponse(reason string, currentlyTCP bool, ctx context.Context, question dns.Question, ecs *ECSOption, depth int, tracker *RequestTracker) ([]dns.RR, []dns.RR, []dns.RR, bool, *ECSOption, error) {
	if !currentlyTCP {
		if tracker != nil {
			tracker.AddStep("DNS hijacking detected, switching to TCP: %s", reason)
		}
		return nil, nil, nil, false, nil, fmt.Errorf("DNS_HIJACK_DETECTED: %s", reason)
	} else {
		if tracker != nil {
			tracker.AddStep("DNS hijacking still detected in TCP, rejecting: %s", reason)
		}
		return nil, nil, nil, false, nil, fmt.Errorf("DNS hijacking detected (TCP): %s", reason)
	}
}

func (rr *RecursiveResolver) QueryNameserversConcurrent(ctx context.Context, nameservers []string, question dns.Question, ecs *ECSOption, forceTCP bool, tracker *RequestTracker) (*dns.Msg, error) {
	if len(nameservers) == 0 {
		return nil, errors.New("no nameservers")
	}

	select {
	case rr.concurrencyLock <- struct{}{}:
		defer func() { <-rr.concurrencyLock }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	concurrency := len(nameservers)
	if concurrency > MaxSingleQuery {
		concurrency = MaxSingleQuery
	}

	if tracker != nil {
		tracker.AddStep("Concurrent query nameserver: %d, TCP=%v", concurrency, forceTCP)
	}

	tempServers := make([]*UpstreamServer, concurrency)
	for i := 0; i < concurrency && i < len(nameservers); i++ {
		protocol := "udp"
		if forceTCP {
			protocol = "tcp"
		}
		tempServers[i] = &UpstreamServer{
			Address:  nameservers[i],
			Protocol: protocol,
		}
	}

	resultChan := make(chan *QueryResult, concurrency)

	for _, server := range tempServers {
		srv := server
		originalMsg := rr.server.BuildQueryMessage(question, ecs, rr.server.config.Server.Features.DNSSEC, true, false)
		msg := SafeCopyMessage(originalMsg)
		GlobalResource.PutDNSMessage(originalMsg)

		rr.server.taskMgr.ExecuteAsync(fmt.Sprintf("Query-%s", srv.Address),
			func(ctx context.Context) error {
				result := rr.server.connMgr.queryClient.ExecuteQuery(ctx, msg, srv, tracker)

				if result.Error == nil && result.Response != nil {
					rcode := result.Response.Rcode
					if rcode == dns.RcodeSuccess || rcode == dns.RcodeNameError {
						if rr.server.config.Server.Features.DNSSEC {
							result.Validated = rr.server.securityMgr.dnssec.ValidateResponse(result.Response, true)
							if tracker != nil && result.Validated {
								tracker.AddStep("DNSSEC validated")
							}
						}

						select {
						case resultChan <- result:
						case <-ctx.Done():
						}
					}
				}
				return nil
			})
	}

	select {
	case result := <-resultChan:
		if tracker != nil {
			tracker.AddStep("Query successful, selected: %s", result.Server)
		}
		return result.Response, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (rr *RecursiveResolver) ResolveNSAddressesConcurrent(ctx context.Context, nsRecords []*dns.NS, qname string, depth int, forceTCP bool, tracker *RequestTracker) []string {
	resolveCount := len(nsRecords)
	if resolveCount > MaxNSResolve {
		resolveCount = MaxNSResolve
	}

	if tracker != nil {
		tracker.AddStep("Concurrently resolving %d NS addresses", resolveCount)
	}

	nsChan := make(chan []string, resolveCount)
	resolveCtx, resolveCancel := context.WithTimeout(ctx, ConnTimeout)
	defer resolveCancel()

	for i := 0; i < resolveCount; i++ {
		ns := nsRecords[i]
		rr.server.taskMgr.ExecuteAsync(fmt.Sprintf("NSResolve-%s", ns.Ns),
			func(ctx context.Context) error {
				if strings.EqualFold(strings.TrimSuffix(ns.Ns, "."), strings.TrimSuffix(qname, ".")) {
					select {
					case nsChan <- nil:
					case <-ctx.Done():
					}
					return nil
				}

				var addresses []string

				// 优先解析 A 记录
				nsQuestion := dns.Question{Name: dns.Fqdn(ns.Ns), Qtype: dns.TypeA, Qclass: dns.ClassINET}
				if nsAnswer, _, _, _, _, err := rr.RecursiveQuery(resolveCtx, nsQuestion, nil, depth+1, forceTCP, tracker); err == nil {
					for _, rrec := range nsAnswer {
						if a, ok := rrec.(*dns.A); ok {
							addresses = append(addresses, net.JoinHostPort(a.A.String(), DefaultDNSPort))
						}
					}
				}

				// 移除 IPv6 判断，总是尝试解析 AAAA
				// 如果 IPv4 解析失败或没有结果，尝试 IPv6
				if len(addresses) == 0 {
					nsQuestionV6 := dns.Question{Name: dns.Fqdn(ns.Ns), Qtype: dns.TypeAAAA, Qclass: dns.ClassINET}
					if nsAnswerV6, _, _, _, _, err := rr.RecursiveQuery(resolveCtx, nsQuestionV6, nil, depth+1, forceTCP, tracker); err == nil {
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

	if tracker != nil {
		tracker.AddStep("NS resolution completed: %d addresses", len(allAddresses))
	}

	return allAddresses
}

func (rr *RecursiveResolver) GetRootServers() []string {
	serversWithLatency := rr.rootServerMgr.GetOptimalRootServers()
	servers := make([]string, len(serversWithLatency))
	for i, server := range serversWithLatency {
		servers[i] = server.Server
	}
	return servers
}

// =============================================================================
// Security Management
// =============================================================================

func NewSecurityManager(config *ServerConfig, server *DNSServer) (*SecurityManager, error) {
	sm := &SecurityManager{
		dnssec: NewDNSSECValidator(),
		hijack: NewHijackPrevention(config.Server.Features.HijackProtection),
	}

	if config.Server.TLS.CertFile != "" && config.Server.TLS.KeyFile != "" {
		tlsMgr, err := NewTLSManager(server, config)
		if err != nil {
			return nil, WrapError("create TLS manager", err)
		}
		sm.tls = tlsMgr
	}

	return sm, nil
}

func (sm *SecurityManager) Shutdown(timeout time.Duration) error {
	if sm.tls != nil {
		return sm.tls.Shutdown()
	}
	return nil
}

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
	if !dnssecOK || response == nil {
		return false
	}
	return v.IsValidated(response)
}

func NewHijackPrevention(enabled bool) *HijackPrevention {
	return &HijackPrevention{enabled: enabled}
}

func (hp *HijackPrevention) IsEnabled() bool {
	return hp.enabled
}

func (hp *HijackPrevention) CheckResponse(currentDomain, queryDomain string, response *dns.Msg) (bool, string) {
	if !hp.enabled || response == nil {
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
				reason := fmt.Sprintf("Root server overstepped authority: %s record for '%s'", recordType, queryDomain)
				return false, reason
			}
		}
	}
	return true, ""
}

// =============================================================================
// TLS Management (服务端保持不变，客户端无需连接复用)
// =============================================================================

func NewTLSManager(server *DNSServer, config *ServerConfig) (*TLSManager, error) {
	cert, err := tls.LoadX509KeyPair(config.Server.TLS.CertFile, config.Server.TLS.KeyFile)
	if err != nil {
		return nil, WrapError("load certificate", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	ctx, cancel := context.WithCancel(context.Background())

	quicAddrValidator, err := NewQUICAddrValidator(QUICAddrValidatorCacheSize, QUICAddrValidatorTTL)
	if err != nil {
		cancel()
		return nil, WrapError("create QUIC validator", err)
	}

	return &TLSManager{
		server:            server,
		tlsConfig:         tlsConfig,
		ctx:               ctx,
		cancel:            cancel,
		quicAddrValidator: quicAddrValidator,
	}, nil
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
		defer HandlePanic("Critical-DoT server")
		if err := tm.StartTLSServer(); err != nil {
			errChan <- WrapError("DoT startup", err)
		}
	}()

	go func() {
		defer wg.Done()
		defer HandlePanic("Critical-DoQ server")
		if err := tm.StartQUICServer(); err != nil {
			errChan <- WrapError("DoQ startup", err)
		}
	}()

	if httpsPort != "" {
		go func() {
			defer wg.Done()
			defer HandlePanic("Critical-DoH server")
			if err := tm.StartDoHServer(httpsPort); err != nil {
				errChan <- WrapError("DoH startup", err)
			}
		}()

		go func() {
			defer wg.Done()
			defer HandlePanic("Critical-DoH3 server")
			if err := tm.StartDoH3Server(httpsPort); err != nil {
				errChan <- WrapError("DoH3 startup", err)
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

func (tm *TLSManager) StartTLSServer() error {
	listener, err := net.Listen("tcp", ":"+tm.server.config.Server.TLS.Port)
	if err != nil {
		return WrapError("DoT listen", err)
	}

	tm.tlsListener = tls.NewListener(listener, tm.tlsConfig)
	LogInfo("DoT server started: %s", tm.tlsListener.Addr())

	tm.wg.Add(1)
	go func() {
		defer tm.wg.Done()
		defer HandlePanic("DoT server")
		tm.HandleTLSConnections()
	}()

	return nil
}

func (tm *TLSManager) StartQUICServer() error {
	addr := ":" + tm.server.config.Server.TLS.Port

	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return WrapError("resolve UDP address", err)
	}

	tm.quicConn, err = net.ListenUDP("udp", udpAddr)
	if err != nil {
		return WrapError("UDP listen", err)
	}

	tm.quicTransport = &quic.Transport{
		Conn:                tm.quicConn,
		VerifySourceAddress: tm.quicAddrValidator.RequiresValidation,
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
		return WrapError("DoQ listen", err)
	}

	LogInfo("DoQ server started: %s", tm.quicListener.Addr())

	tm.wg.Add(1)
	go func() {
		defer tm.wg.Done()
		defer HandlePanic("DoQ server")
		tm.HandleQUICConnections()
	}()

	return nil
}

func (tm *TLSManager) StartDoHServer(port string) error {
	listener, err := net.Listen("tcp", ":"+port)
	if err != nil {
		return WrapError("DoH listen", err)
	}

	tlsConfig := tm.tlsConfig.Clone()
	tlsConfig.NextProtos = []string{http2.NextProtoTLS, "http/1.1"}

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
		defer HandlePanic("DoH server")
		if err := tm.httpsServer.Serve(tm.httpsListener); err != nil && err != http.ErrServerClosed {
			LogError("DoH server error: %v", err)
		}
	}()

	return nil
}

func (tm *TLSManager) StartDoH3Server(port string) error {
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
		return WrapError("DoH3 listen", err)
	}

	tm.h3Listener = quicListener
	LogInfo("DoH3 server started: %s", tm.h3Listener.Addr())

	tm.h3Server = &http3.Server{
		Handler: tm,
	}

	tm.wg.Add(1)
	go func() {
		defer tm.wg.Done()
		defer HandlePanic("DoH3 server")
		if err := tm.h3Server.ServeListener(tm.h3Listener); err != nil && err != http.ErrServerClosed {
			LogError("DoH3 server error: %v", err)
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

	if GlobalLog.GetLevel() >= Debug {
		LogDebug("Received DoH request: %s %s", r.Method, r.URL.Path)
	}

	req, statusCode := tm.ParseDoHRequest(r)
	if req == nil {
		http.Error(w, http.StatusText(statusCode), statusCode)
		return
	}

	response := tm.server.ProcessDNSQuery(req, nil, true)
	if err := tm.RespondDoH(w, response); err != nil {
		LogError("DoH response failed: %v", err)
	}
}

func (tm *TLSManager) ParseDoHRequest(r *http.Request) (*dns.Msg, int) {
	var buf []byte
	var err error

	switch r.Method {
	case http.MethodGet:
		dnsParam := r.URL.Query().Get("dns")
		if dnsParam == "" {
			LogDebug("DoH GET missing dns parameter")
			return nil, http.StatusBadRequest
		}
		buf, err = base64.RawURLEncoding.DecodeString(dnsParam)
		if err != nil {
			LogDebug("DoH GET dns parameter decode failed: %v", err)
			return nil, http.StatusBadRequest
		}

	case http.MethodPost:
		contentType := r.Header.Get("Content-Type")
		if contentType != "application/dns-message" {
			LogDebug("DoH POST unsupported Content-Type: %s", contentType)
			return nil, http.StatusUnsupportedMediaType
		}

		r.Body = http.MaxBytesReader(nil, r.Body, DoHMaxRequestSize)
		buf, err = io.ReadAll(r.Body)
		if err != nil {
			LogDebug("DoH POST body read failed: %v", err)
			return nil, http.StatusBadRequest
		}
		defer func() { _ = r.Body.Close() }()

	default:
		LogDebug("DoH unsupported method: %s", r.Method)
		return nil, http.StatusMethodNotAllowed
	}

	if len(buf) == 0 {
		LogDebug("DoH request data empty")
		return nil, http.StatusBadRequest
	}

	req := new(dns.Msg)
	if err := req.Unpack(buf); err != nil {
		LogDebug("DoH DNS message parse failed: %v", err)
		return nil, http.StatusBadRequest
	}

	return req, http.StatusOK
}

func (tm *TLSManager) RespondDoH(w http.ResponseWriter, response *dns.Msg) error {
	if response == nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return nil
	}

	bytes, err := response.Pack()
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return WrapError("pack response", err)
	}

	w.Header().Set("Content-Type", "application/dns-message")
	w.Header().Set("Cache-Control", "max-age=0")

	_, err = w.Write(bytes)
	return err
}

func (tm *TLSManager) HandleTLSConnections() {
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
			defer HandlePanic("DoT connection")
			defer func() { _ = conn.Close() }()
			tm.HandleSecureDNSConnection(conn, "DoT")
		}()
	}
}

func (tm *TLSManager) HandleQUICConnections() {
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
			tm.LogQUICError("accept quic conn", err)
			continue
		}

		tm.wg.Add(1)
		go func() {
			defer tm.wg.Done()
			defer HandlePanic("DoQ connection")
			tm.HandleQUICConnection(conn)
		}()
	}
}

func (tm *TLSManager) HandleQUICConnection(conn *quic.Conn) {
	defer func() {
		if conn != nil {
			_ = conn.CloseWithError(QUICCodeNoError, "")
		}
	}()

	for {
		select {
		case <-tm.ctx.Done():
			return
		default:
		}

		stream, err := conn.AcceptStream(tm.ctx)
		if err != nil {
			if conn != nil {
				tm.LogQUICError("accept quic stream", err)
			}
			return
		}

		if stream == nil {
			continue
		}

		tm.wg.Add(1)
		go func(s *quic.Stream) {
			defer tm.wg.Done()
			defer HandlePanic("DoQ stream")
			if s != nil {
				defer func() { _ = s.Close() }()
				tm.HandleQUICStream(s, conn)
			}
		}(stream)
	}
}

func (tm *TLSManager) HandleQUICStream(stream *quic.Stream, conn *quic.Conn) {
	buf := make([]byte, SecureBufferSize)
	n, err := tm.ReadAll(stream, buf)

	if err != nil && err != io.EOF {
		LogDebug("DoQ stream read failed: %v", err)
		return
	}

	if n < MinDNSPacketSize {
		LogDebug("DoQ message too short: %d bytes", n)
		return
	}

	req := new(dns.Msg)
	var msgData []byte

	packetLen := binary.BigEndian.Uint16(buf[:2])
	if packetLen == uint16(n-2) {
		msgData = buf[2:n]
	} else {
		LogDebug("DoQ unsupported message format")
		_ = conn.CloseWithError(QUICCodeProtocolError, "")
		return
	}

	if err := req.Unpack(msgData); err != nil {
		LogDebug("DoQ message parse failed: %v", err)
		_ = conn.CloseWithError(QUICCodeProtocolError, "")
		return
	}

	if !tm.ValidQUICMsg(req) {
		_ = conn.CloseWithError(QUICCodeProtocolError, "")
		return
	}

	clientIP := tm.GetSecureClientIP(conn)
	response := tm.server.ProcessDNSQuery(req, clientIP, true)

	if err := tm.RespondQUIC(stream, response); err != nil {
		LogDebug("DoQ response failed: %v", err)
	}
}

func (tm *TLSManager) HandleSecureDNSConnection(conn net.Conn, protocol string) {
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return
	}

	if err := tlsConn.SetReadDeadline(time.Now().Add(QueryTimeout)); err != nil {
		LogDebug("Set TLS read deadline failed: %v", err)
	}

	for {
		select {
		case <-tm.ctx.Done():
			return
		default:
		}

		lengthBuf := make([]byte, 2)
		if _, err := io.ReadFull(tlsConn, lengthBuf); err != nil {
			if err != io.EOF {
				LogDebug("%s length read failed: %v", protocol, err)
			}
			return
		}

		msgLength := binary.BigEndian.Uint16(lengthBuf)
		if msgLength == 0 || msgLength > TCPBufferSize {
			LogWarn("%s invalid message length: %d", protocol, msgLength)
			return
		}

		msgBuf := make([]byte, msgLength)
		if _, err := io.ReadFull(tlsConn, msgBuf); err != nil {
			LogDebug("%s message read failed: %v", protocol, err)
			return
		}

		req := new(dns.Msg)
		if err := req.Unpack(msgBuf); err != nil {
			LogDebug("%s message parse failed: %v", protocol, err)
			return
		}

		clientIP := tm.GetSecureClientIP(tlsConn)
		response := tm.server.ProcessDNSQuery(req, clientIP, true)

		respBuf, err := response.Pack()
		if err != nil {
			LogError("%s response pack failed: %v", protocol, err)
			return
		}

		lengthPrefix := make([]byte, 2)
		binary.BigEndian.PutUint16(lengthPrefix, uint16(len(respBuf)))

		if _, err := tlsConn.Write(lengthPrefix); err != nil {
			LogDebug("%s response length write failed: %v", protocol, err)
			return
		}

		if _, err := tlsConn.Write(respBuf); err != nil {
			LogDebug("%s response write failed: %v", protocol, err)
			return
		}

		if err := tlsConn.SetReadDeadline(time.Now().Add(QueryTimeout)); err != nil {
			LogDebug("Update TLS read deadline failed: %v", err)
		}
	}
}

func (tm *TLSManager) GetSecureClientIP(conn interface{}) net.IP {
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

func (tm *TLSManager) ValidQUICMsg(req *dns.Msg) bool {
	if req == nil {
		return false
	}

	if opt := req.IsEdns0(); opt != nil {
		for _, option := range opt.Option {
			if option.Option() == dns.EDNS0TCPKEEPALIVE {
				LogDebug("DoQ client sent disallowed TCP keepalive")
				return false
			}
		}
	}
	return true
}

func (tm *TLSManager) RespondQUIC(stream *quic.Stream, response *dns.Msg) error {
	if response == nil {
		return errors.New("response is nil")
	}

	respBuf, err := response.Pack()
	if err != nil {
		return WrapError("pack response", err)
	}

	buf := make([]byte, 2+len(respBuf))
	binary.BigEndian.PutUint16(buf[:2], uint16(len(respBuf)))
	copy(buf[2:], respBuf)

	n, err := stream.Write(buf)
	if err != nil {
		return WrapError("stream write", err)
	}

	if n != len(buf) {
		return fmt.Errorf("write length mismatch: %d != %d", n, len(buf))
	}

	return nil
}

func (tm *TLSManager) LogQUICError(prefix string, err error) {
	if tm.IsQUICErrorForDebugLog(err) {
		LogDebug("DoQ connection closed: %s - %v", prefix, err)
	} else {
		LogError("DoQ error: %s - %v", prefix, err)
	}
}

func (tm *TLSManager) IsQUICErrorForDebugLog(err error) bool {
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

func (tm *TLSManager) ReadAll(r io.Reader, buf []byte) (int, error) {
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

func (tm *TLSManager) Shutdown() error {
	LogInfo("Shutting down secure DNS server...")

	tm.cancel()

	if tm.tlsListener != nil {
		CloseWithLog(tm.tlsListener, "TLS listener")
	}
	if tm.quicListener != nil {
		CloseWithLog(tm.quicListener, "QUIC listener")
	}
	if tm.quicConn != nil {
		CloseWithLog(tm.quicConn, "QUIC connection")
	}
	if tm.quicAddrValidator != nil {
		tm.quicAddrValidator.Close()
		LogDebug("QUIC address validator closed")
	}

	if tm.httpsServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), ShutdownTimeout)
		defer cancel()
		if err := tm.httpsServer.Shutdown(ctx); err != nil {
			LogDebug("HTTPS server shutdown failed: %v", err)
		}
	}

	if tm.h3Server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), ShutdownTimeout)
		defer cancel()
		if err := tm.h3Server.Shutdown(ctx); err != nil {
			LogDebug("HTTP/3 server shutdown failed: %v", err)
		}
	}

	if tm.httpsListener != nil {
		CloseWithLog(tm.httpsListener, "HTTPS listener")
	}

	if tm.h3Listener != nil {
		CloseWithLog(tm.h3Listener, "HTTP/3 listener")
	}

	tm.wg.Wait()
	LogInfo("Secure DNS server shut down")
	return nil
}

func NewQUICAddrValidator(cacheSize int, ttl time.Duration) (*QUICAddrValidator, error) {
	cache, err := ristretto.NewCache(&ristretto.Config[string, struct{}]{
		NumCounters: int64(cacheSize * 10),
		MaxCost:     int64(cacheSize),
		BufferItems: 64,
	})
	if err != nil {
		return nil, WrapError("create ristretto cache", err)
	}

	LogDebug("QUIC address validator initialized: cacheSize=%d, ttl=%v", cacheSize, ttl)

	return &QUICAddrValidator{
		cache: cache,
		ttl:   ttl,
	}, nil
}

func (v *QUICAddrValidator) RequiresValidation(addr net.Addr) bool {
	if v == nil || v.cache == nil {
		LogDebug("QUIC address validation: validator not initialized")
		return true
	}

	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		LogDebug("QUIC address validation: unexpected type %T", addr)
		return true
	}

	key := udpAddr.IP.String()

	if _, found := v.cache.Get(key); found {
		LogDebug("QUIC address validation: %s cached, skip", key)
		return false
	}

	v.cache.SetWithTTL(key, struct{}{}, 1, v.ttl)
	LogDebug("QUIC address validation: %s not cached, require validation", key)

	return true
}

func (v *QUICAddrValidator) Close() {
	if v != nil && v.cache != nil {
		v.cache.Close()
		LogDebug("QUIC address validator closed")
	}
}

// =============================================================================
// EDNS Management
// =============================================================================

func NewEDNSManager(defaultSubnet string, paddingEnabled bool) (*EDNSManager, error) {
	manager := &EDNSManager{
		detector:       NewIPDetector(),
		paddingEnabled: paddingEnabled,
	}

	if defaultSubnet != "" {
		ecs, err := manager.ParseECSConfig(defaultSubnet)
		if err != nil {
			return nil, WrapError("parse ECS config", err)
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

func (em *EDNSManager) GetDefaultECS() *ECSOption {
	if em == nil {
		return nil
	}
	return em.defaultECS
}

func (em *EDNSManager) IsPaddingEnabled() bool {
	return em != nil && em.paddingEnabled
}

func (em *EDNSManager) ParseFromDNS(msg *dns.Msg) *ECSOption {
	if em == nil || msg == nil {
		return nil
	}

	if msg.Extra == nil {
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
	if em == nil || msg == nil {
		return
	}

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

	cleanExtra := make([]dns.RR, 0, len(msg.Extra))
	for _, rr := range msg.Extra {
		if rr != nil && rr.Header().Rrtype != dns.TypeOPT {
			cleanExtra = append(cleanExtra, rr)
		}
	}
	msg.Extra = cleanExtra

	opt := &dns.OPT{
		Hdr: dns.RR_Header{
			Name:   ".",
			Rrtype: dns.TypeOPT,
			Class:  UDPBufferSize,
			Ttl:    0,
		},
	}

	if dnssecEnabled {
		opt.SetDo(true)
	}

	var options []dns.EDNS0

	if ecs != nil {
		ecsOption := &dns.EDNS0_SUBNET{
			Code:          dns.EDNS0SUBNET,
			Family:        ecs.Family,
			SourceNetmask: ecs.SourcePrefix,
			SourceScope:   DefaultECSScope,
			Address:       ecs.Address,
		}
		options = append(options, ecsOption)
		LogDebug("Adding ECS: %s/%d", ecs.Address, ecs.SourcePrefix)
	}

	if em.paddingEnabled && isSecureConnection {
		opt.Option = options
		msg.Extra = append(msg.Extra, opt)

		if wireData, err := msg.Pack(); err == nil {
			currentSize := len(wireData)
			if currentSize < PaddingBlockSize {
				paddingDataSize := PaddingBlockSize - currentSize - 4
				if paddingDataSize > 0 {
					options = append(options, &dns.EDNS0_PADDING{
						Padding: make([]byte, paddingDataSize),
					})
					LogDebug("DNS Padding: %d -> %d bytes (+%d)", currentSize, PaddingBlockSize, paddingDataSize)
				}
			}
		} else {
			LogDebug("Calculate padding failed: %v", err)
		}

		msg.Extra = msg.Extra[:len(msg.Extra)-1]
	}

	opt.Option = options
	msg.Extra = append(msg.Extra, opt)
}

func (em *EDNSManager) ParseECSConfig(subnet string) (*ECSOption, error) {
	switch strings.ToLower(subnet) {
	case "auto":
		return em.DetectPublicIP(false, true)
	case "auto_v4":
		return em.DetectPublicIP(false, false)
	case "auto_v6":
		return em.DetectPublicIP(true, false)
	default:
		_, ipNet, err := net.ParseCIDR(subnet)
		if err != nil {
			return nil, WrapError("parse CIDR", err)
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

func (em *EDNSManager) DetectPublicIP(forceIPv6, allowFallback bool) (*ECSOption, error) {
	cacheKey := fmt.Sprintf("ip_detection_%v_%v", forceIPv6, allowFallback)

	if cached, ok := em.cache.Load(cacheKey); ok {
		if cachedECS, ok := cached.(*ECSOption); ok {
			return cachedECS, nil
		}
	}

	var ecs *ECSOption
	if ip := em.detector.DetectPublicIP(forceIPv6); ip != nil {
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
		if ip := em.detector.DetectPublicIP(true); ip != nil {
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
		time.AfterFunc(IPCacheExpiry, func() {
			em.cache.Delete(cacheKey)
		})
	}

	return ecs, nil
}

func NewIPDetector() *IPDetector {
	return &IPDetector{
		httpClient: &http.Client{
			Timeout: HTTPClientTimeout,
		},
	}
}

func (d *IPDetector) DetectPublicIP(forceIPv6 bool) net.IP {
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

	client := &http.Client{
		Timeout:   HTTPClientTimeout,
		Transport: transport,
	}
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

func NewRewriteManager() *RewriteManager {
	return &RewriteManager{
		rules: make([]RewriteRule, 0, 32),
	}
}

func (rm *RewriteManager) LoadRules(rules []RewriteRule) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	validRules := make([]RewriteRule, 0, len(rules))
	for _, rule := range rules {
		if len(rule.Name) > MaxDomainLength {
			continue
		}
		validRules = append(validRules, rule)
	}

	rm.rules = validRules
	LogInfo("DNS rewriter loaded: %d rules", len(validRules))
	return nil
}

func (rm *RewriteManager) RewriteWithDetails(domain string, qtype uint16) DNSRewriteResult {
	result := DNSRewriteResult{
		Domain:        domain,
		ShouldRewrite: false,
		ResponseCode:  dns.RcodeSuccess,
		Records:       nil,
		Additional:    nil,
	}

	if !rm.HasRules() || len(domain) > MaxDomainLength {
		return result
	}

	rm.mu.RLock()
	defer rm.mu.RUnlock()

	domain = strings.ToLower(strings.TrimSuffix(domain, "."))

	for i := range rm.rules {
		rule := &rm.rules[i]

		if domain == strings.ToLower(rule.Name) {
			if rule.ResponseCode != nil {
				result.ResponseCode = *rule.ResponseCode
				result.ShouldRewrite = true
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

					rr := rm.BuildDNSRecord(domain, record)
					if rr != nil {
						result.Records = append(result.Records, rr)
					}
				}

				for _, record := range rule.Additional {
					rr := rm.BuildDNSRecord(domain, record)
					if rr != nil {
						result.Additional = append(result.Additional, rr)
					}
				}

				result.ShouldRewrite = true
				return result
			}
		}
	}

	return result
}

func (rm *RewriteManager) BuildDNSRecord(domain string, record DNSRecordConfig) dns.RR {
	ttl := record.TTL
	if ttl == 0 {
		ttl = DefaultCacheTTL
	}

	name := dns.Fqdn(domain)
	if record.Name != "" {
		name = dns.Fqdn(record.Name)
	}

	rrStr := fmt.Sprintf("%s %d IN %s %s", name, ttl, record.Type, record.Content)

	rr, err := dns.NewRR(rrStr)
	if err == nil {
		return rr
	}

	rrType, exists := dns.StringToType[record.Type]
	if !exists {
		rrType = 0
	}

	rfc3597 := &dns.RFC3597{
		Hdr: dns.RR_Header{
			Name:   name,
			Rrtype: rrType,
			Class:  dns.ClassINET,
			Ttl:    ttl,
		},
	}
	rfc3597.Rdata = record.Content
	return rfc3597
}

func (rm *RewriteManager) HasRules() bool {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	return len(rm.rules) > 0
}

// =============================================================================
// SpeedTest Management
// =============================================================================

func NewSpeedTestManager(config ServerConfig) *SpeedTestManager {
	st := &SpeedTestManager{
		timeout:     DefaultSpeedTimeout,
		concurrency: DefaultSpeedConcurrency,
		cache:       make(map[string]*SpeedResult),
		cacheTTL:    DefaultSpeedCacheTTL,
		methods:     config.SpeedTest,
	}

	st.InitICMP()

	return st
}

func (st *SpeedTestManager) InitICMP() {
	conn4, err := icmp.ListenPacket("ip4:icmp", "")
	if err == nil {
		st.icmpConn4 = conn4
	} else {
		if strings.Contains(err.Error(), "operation not permitted") {
			LogDebug("SpeedTest: no permission for IPv4 ICMP")
		} else {
			LogDebug("SpeedTest: cannot create IPv4 ICMP: %v", err)
		}
	}

	conn6, err := icmp.ListenPacket("ip6:ipv6-icmp", "")
	if err == nil {
		st.icmpConn6 = conn6
	} else {
		if strings.Contains(err.Error(), "operation not permitted") {
			LogDebug("SpeedTest: no permission for IPv6 ICMP")
		} else {
			LogDebug("SpeedTest: cannot create IPv6 ICMP: %v", err)
		}
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

func (st *SpeedTestManager) PerformSpeedTestAndSort(response *dns.Msg) *dns.Msg {
	if response == nil {
		LogDebug("SpeedTest: response is nil")
		return response
	}

	LogDebug("SpeedTest: processing response, answer count: %d", len(response.Answer))

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
			otherRecords = append(otherRecords, record)
		}
	}

	LogDebug("SpeedTest: A=%d, AAAA=%d, CNAME=%d", len(aRecords), len(aaaaRecords), len(cnameRecords))

	if len(aRecords) > 1 {
		LogDebug("SpeedTest: sorting %d A records", len(aRecords))
		aRecords = st.SortARecords(aRecords)
	} else {
		LogDebug("SpeedTest: A records insufficient, skip")
	}

	if len(aaaaRecords) > 1 {
		LogDebug("SpeedTest: sorting %d AAAA records", len(aaaaRecords))
		aaaaRecords = st.SortAAAARecords(aaaaRecords)
	} else {
		LogDebug("SpeedTest: AAAA records insufficient, skip")
	}

	response.Answer = []dns.RR{}

	response.Answer = append(response.Answer, cnameRecords...)

	for _, record := range aRecords {
		response.Answer = append(response.Answer, record)
	}

	for _, record := range aaaaRecords {
		response.Answer = append(response.Answer, record)
	}

	response.Answer = append(response.Answer, otherRecords...)

	LogDebug("SpeedTest: processing completed, answer count: %d", len(response.Answer))

	return response
}

func (st *SpeedTestManager) SortARecords(records []*dns.A) []*dns.A {
	if len(records) <= 1 {
		return records
	}

	ips := make([]string, len(records))
	for i, record := range records {
		ips[i] = record.A.String()
	}

	results := st.SpeedTest(ips)

	sort.Slice(records, func(i, j int) bool {
		ipI := records[i].A.String()
		ipJ := records[j].A.String()

		resultI, okI := results[ipI]
		resultJ, okJ := results[ipJ]

		if !okI || !okJ {
			return i < j
		}

		if !resultI.Reachable && resultJ.Reachable {
			return false
		}
		if resultI.Reachable && !resultJ.Reachable {
			return true
		}

		return resultI.Latency < resultJ.Latency
	})

	return records
}

func (st *SpeedTestManager) SortAAAARecords(records []*dns.AAAA) []*dns.AAAA {
	if len(records) <= 1 {
		return records
	}

	ips := make([]string, len(records))
	for i, record := range records {
		ips[i] = record.AAAA.String()
	}

	results := st.SpeedTest(ips)

	sort.Slice(records, func(i, j int) bool {
		ipI := records[i].AAAA.String()
		ipJ := records[j].AAAA.String()

		resultI, okI := results[ipI]
		resultJ, okJ := results[ipJ]

		if !okI || !okJ {
			return i < j
		}

		if !resultI.Reachable && resultJ.Reachable {
			return false
		}
		if resultI.Reachable && !resultJ.Reachable {
			return true
		}

		return resultI.Latency < resultJ.Latency
	})

	return records
}

func (st *SpeedTestManager) SpeedTest(ips []string) map[string]*SpeedResult {
	cachedResults := make(map[string]*SpeedResult)
	remainingIPs := []string{}

	st.cacheMutex.RLock()
	now := time.Now()
	for _, ip := range ips {
		if result, exists := st.cache[ip]; exists {
			if now.Sub(result.Timestamp) < st.cacheTTL {
				cachedResults[ip] = result
			} else {
				remainingIPs = append(remainingIPs, ip)
			}
		} else {
			remainingIPs = append(remainingIPs, ip)
		}
	}
	st.cacheMutex.RUnlock()

	if len(remainingIPs) == 0 {
		LogDebug("SpeedTest: all IPs cached")
		return cachedResults
	}

	LogDebug("SpeedTest: testing %d IPs, %d cached", len(remainingIPs), len(cachedResults))

	newResults := st.PerformSpeedTest(remainingIPs)

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

func (st *SpeedTestManager) PerformSpeedTest(ips []string) map[string]*SpeedResult {
	LogDebug("SpeedTest: starting concurrent test for %d IPs", len(ips))

	semaphore := make(chan struct{}, st.concurrency)
	resultChan := make(chan *SpeedResult, len(ips))

	var wg sync.WaitGroup
	for _, ip := range ips {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			result := st.TestSingleIP(ip)
			resultChan <- result
		}(ip)
	}

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	results := make(map[string]*SpeedResult)
	for result := range resultChan {
		results[result.IP] = result
	}

	LogDebug("SpeedTest: concurrent test completed, got %d results", len(results))

	return results
}

func (st *SpeedTestManager) TestSingleIP(ip string) *SpeedResult {
	LogDebug("SpeedTest: testing IP %s", ip)

	result := &SpeedResult{
		IP:        ip,
		Timestamp: time.Now(),
	}

	totalTimeout := time.Duration(st.timeout)
	totalTimeoutCtx, totalCancel := context.WithTimeout(context.Background(), totalTimeout)
	defer totalCancel()

	for _, method := range st.methods {
		select {
		case <-totalTimeoutCtx.Done():
			result.Reachable = false
			result.Latency = st.timeout
			LogDebug("SpeedTest: IP %s total timeout", ip)
			return result
		default:
		}

		var latency time.Duration
		switch method.Type {
		case "icmp":
			latency = st.PingWithICMP(ip, time.Duration(method.Timeout)*time.Millisecond)
		case "tcp":
			latency = st.PingWithTCP(ip, method.Port, time.Duration(method.Timeout)*time.Millisecond)
		case "udp":
			latency = st.PingWithUDP(ip, method.Port, time.Duration(method.Timeout)*time.Millisecond)
		default:
			continue
		}

		if latency >= 0 {
			result.Reachable = true
			result.Latency = latency
			LogDebug("SpeedTest: IP %s %s successful, latency: %v", ip, method.Type, result.Latency)
			return result
		}
	}

	result.Reachable = false
	result.Latency = st.timeout
	LogDebug("SpeedTest: IP %s all attempts failed", ip)
	return result
}

func (st *SpeedTestManager) PingWithICMP(ip string, timeout time.Duration) time.Duration {
	LogDebug("SpeedTest: ICMP ping %s", ip)

	dst, err := net.ResolveIPAddr("ip", ip)
	if err != nil {
		LogDebug("SpeedTest: cannot parse IP %s: %v", ip, err)
		return -1
	}

	var conn *icmp.PacketConn
	if dst.IP.To4() != nil {
		conn = st.icmpConn4
	} else {
		conn = st.icmpConn6
	}

	if conn == nil {
		LogDebug("SpeedTest: no ICMP connection for %s", ip)
		return -1
	}

	var icmpType icmp.Type
	var protocol int
	if dst.IP.To4() != nil {
		icmpType = ipv4.ICMPTypeEcho
		protocol = 1
	} else {
		icmpType = ipv6.ICMPTypeEchoRequest
		protocol = 58
	}

	wm := icmp.Message{
		Type: icmpType,
		Code: 0,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Seq:  1,
			Data: []byte("ZJDNS SpeedTest"),
		},
	}

	wb, err := wm.Marshal(nil)
	if err != nil {
		LogDebug("SpeedTest: cannot marshal ICMP %s: %v", ip, err)
		return -1
	}

	_ = conn.SetWriteDeadline(time.Now().Add(timeout))

	start := time.Now()

	_, err = conn.WriteTo(wb, dst)
	if err != nil {
		LogDebug("SpeedTest: ICMP send failed %s: %v", ip, err)
		return -1
	}

	_ = conn.SetReadDeadline(time.Now().Add(timeout))

	rb := make([]byte, 1500)
	n, peer, err := conn.ReadFrom(rb)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			LogDebug("SpeedTest: ICMP timeout %s", ip)
		} else {
			LogDebug("SpeedTest: ICMP read failed %s: %v", ip, err)
		}
		return -1
	}

	LogDebug("SpeedTest: received reply from %v, size %d bytes", peer, n)

	rm, err := icmp.ParseMessage(protocol, rb[:n])
	if err != nil {
		LogDebug("SpeedTest: cannot parse ICMP reply %s: %v", ip, err)
		return -1
	}

	switch rm.Type {
	case ipv4.ICMPTypeEchoReply, ipv6.ICMPTypeEchoReply:
		latency := time.Since(start)
		LogDebug("SpeedTest: ICMP ping successful %s, latency: %v", ip, latency)
		return latency
	default:
		LogDebug("SpeedTest: unexpected ICMP type %s: %v", ip, rm.Type)
		return -1
	}
}

func (st *SpeedTestManager) PingWithTCP(ip, port string, timeout time.Duration) time.Duration {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	start := time.Now()

	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(ip, port))
	if err != nil {
		LogDebug("SpeedTest: TCP failed %s:%s - %v", ip, port, err)
		return -1
	}

	latency := time.Since(start)
	_ = conn.Close()

	LogDebug("SpeedTest: TCP successful %s:%s, latency: %v", ip, port, latency)

	return latency
}

func (st *SpeedTestManager) PingWithUDP(ip, port string, timeout time.Duration) time.Duration {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	start := time.Now()

	conn, err := (&net.Dialer{}).DialContext(ctx, "udp", net.JoinHostPort(ip, port))
	if err != nil {
		LogDebug("SpeedTest: UDP failed %s:%s - %v", ip, port, err)
		return -1
	}

	_, writeErr := conn.Write([]byte{})
	if writeErr != nil {
		LogDebug("SpeedTest: UDP send failed %s:%s - %v", ip, port, writeErr)
		_ = conn.Close()
		return -1
	}

	latency := time.Since(start)
	_ = conn.Close()

	LogDebug("SpeedTest: UDP successful %s:%s, latency: %v", ip, port, latency)

	return latency
}

// =============================================================================
// Root Server Management
// =============================================================================

func NewRootServerManager(config ServerConfig) *RootServerManager {
	// 判断是否需要递归解析
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
			// IPv4 根服务器
			"198.41.0.4:53", "170.247.170.2:53", "192.33.4.12:53", "199.7.91.13:53",
			"192.203.230.10:53", "192.5.5.241:53", "192.112.36.4:53", "198.97.190.53:53",
			"192.36.148.17:53", "192.58.128.30:53", "193.0.14.129:53", "199.7.83.42:53", "202.12.27.33:53",
			// IPv6 根服务器
			"[2001:503:ba3e::2:30]:53", "[2801:1b8:10::b]:53", "[2001:500:2::c]:53", "[2001:500:2d::d]:53",
			"[2001:500:a8::e]:53", "[2001:500:2f::f]:53", "[2001:500:12::d0d]:53", "[2001:500:1::53]:53",
			"[2001:7fe::53]:53", "[2001:503:c27::2:30]:53", "[2001:7fd::1]:53", "[2001:500:9f::42]:53", "[2001:dc3::35]:53",
		},
		needsSpeed: needsRecursive,
	}

	// 初始化排序列表
	rsm.sorted = make([]RootServerWithLatency, len(rsm.servers))
	for i, server := range rsm.servers {
		rsm.sorted[i] = RootServerWithLatency{
			Server:    server,
			Latency:   UnreachableLatency,
			Reachable: false,
		}
	}

	// 仅在需要递归解析时初始化测速
	if needsRecursive {
		dnsSpeedTestConfig := config
		dnsSpeedTestConfig.SpeedTest = []SpeedTestMethod{
			{
				Type:    "icmp",
				Timeout: int(DefaultSpeedTimeout.Milliseconds()),
			},
			{
				Type:    "udp",
				Port:    DefaultDNSPort,
				Timeout: int(DefaultSpeedTimeout.Milliseconds()),
			},
			{
				Type:    "tcp",
				Port:    DefaultDNSPort,
				Timeout: int(DefaultSpeedTimeout.Milliseconds()),
			},
		}
		rsm.speedTester = NewSpeedTestManager(dnsSpeedTestConfig)

		// 立即执行一次测速
		go rsm.SortServersBySpeed()

		LogInfo("Root server speed testing enabled")
	} else {
		LogInfo("Root server speed testing disabled (using upstream servers)")
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

func (rsm *RootServerManager) SortServersBySpeed() {
	defer HandlePanic("Root server speed sorting")

	if !rsm.needsSpeed || rsm.speedTester == nil {
		LogDebug("Root server speed testing skipped")
		return
	}

	if len(rsm.servers) == 0 {
		return
	}

	// 提取所有 IP
	ips := ExtractIPsFromServers(rsm.servers)

	// 执行测速
	results := rsm.speedTester.SpeedTest(ips)

	// 排序
	sortedWithLatency := SortBySpeedResultWithLatency(rsm.servers, results)

	rsm.mu.Lock()
	rsm.sorted = sortedWithLatency
	rsm.lastSortTime = time.Now()
	rsm.mu.Unlock()

	LogDebug("Root server speed test completed: %d servers tested", len(rsm.servers))
}

func SortBySpeedResultWithLatency(servers []string, results map[string]*SpeedResult) []RootServerWithLatency {
	serverList := make([]RootServerWithLatency, len(servers))

	for i, server := range servers {
		ip := ExtractIPFromServer(server)
		if result, exists := results[ip]; exists && result.Reachable {
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

func ExtractIPsFromServers(servers []string) []string {
	ips := make([]string, len(servers))
	for i, server := range servers {
		ips[i] = ExtractIPFromServer(server)
	}
	return ips
}

func (rsm *RootServerManager) StartPeriodicSorting(ctx context.Context) {
	if !rsm.needsSpeed {
		LogDebug("RootServer: periodic sorting disabled")
		return
	}

	LogDebug("RootServer: starting periodic sorting (%v interval)", RootServerSortInterval)
	ticker := time.NewTicker(RootServerSortInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			LogDebug("RootServer: triggering periodic speed test")
			rsm.SortServersBySpeed()
		case <-ctx.Done():
			LogDebug("RootServer: stopping periodic sorting")
			return
		}
	}
}

func ExtractIPFromServer(server string) string {
	host, _, err := net.SplitHostPort(server)
	if err != nil {
		return server
	}
	return host
}

// =============================================================================
// Resource Management
// =============================================================================

func NewResourceManager() *ResourceManager {
	rm := &ResourceManager{}

	rm.dnsMessages = sync.Pool{
		New: func() interface{} {
			atomic.AddInt64(&rm.stats.news, 1)
			msg := &dns.Msg{}
			msg.Question = make([]dns.Question, 0)
			msg.Answer = make([]dns.RR, 0)
			msg.Ns = make([]dns.RR, 0)
			msg.Extra = make([]dns.RR, 0)
			return msg
		},
	}

	rm.buffers = sync.Pool{
		New: func() interface{} {
			buf := make([]byte, 0, 1024)
			return &buf
		},
	}

	rm.stringBuilders = sync.Pool{
		New: func() interface{} {
			return &strings.Builder{}
		},
	}

	return rm
}

func (rm *ResourceManager) GetDNSMessage() *dns.Msg {
	if rm == nil {
		msg := &dns.Msg{}
		msg.Question = make([]dns.Question, 0)
		msg.Answer = make([]dns.RR, 0)
		msg.Ns = make([]dns.RR, 0)
		msg.Extra = make([]dns.RR, 0)
		return msg
	}

	atomic.AddInt64(&rm.stats.gets, 1)
	obj := rm.dnsMessages.Get()
	msg, ok := obj.(*dns.Msg)
	if !ok {
		msg = &dns.Msg{}
		msg.Question = make([]dns.Question, 0)
		msg.Answer = make([]dns.RR, 0)
		msg.Ns = make([]dns.RR, 0)
		msg.Extra = make([]dns.RR, 0)
	}

	rm.ResetDNSMessageSafe(msg)
	return msg
}

func (rm *ResourceManager) ResetDNSMessageSafe(msg *dns.Msg) {
	if msg == nil {
		return
	}

	*msg = dns.Msg{
		Question: msg.Question[:0],
		Answer:   msg.Answer[:0],
		Ns:       msg.Ns[:0],
		Extra:    msg.Extra[:0],
	}

	if msg.Question == nil {
		msg.Question = make([]dns.Question, 0)
	}
	if msg.Answer == nil {
		msg.Answer = make([]dns.RR, 0)
	}
	if msg.Ns == nil {
		msg.Ns = make([]dns.RR, 0)
	}
	if msg.Extra == nil {
		msg.Extra = make([]dns.RR, 0)
	}
}

func (rm *ResourceManager) PutDNSMessage(msg *dns.Msg) {
	if rm == nil || msg == nil {
		return
	}

	atomic.AddInt64(&rm.stats.puts, 1)
	rm.ResetDNSMessageSafe(msg)
	rm.dnsMessages.Put(msg)
}

func (rm *ResourceManager) GetBuffer() []byte {
	if rm == nil {
		return make([]byte, 0, 1024)
	}
	return (rm.buffers.Get().([]byte))[:0]
}

func (rm *ResourceManager) PutBuffer(buf []byte) {
	if rm == nil || buf == nil {
		return
	}
	if cap(buf) <= 8192 {
		rm.buffers.Put(&buf)
	}
}

func (rm *ResourceManager) GetStringBuilder() *strings.Builder {
	if rm == nil {
		return &strings.Builder{}
	}
	sb := rm.stringBuilders.Get().(*strings.Builder)
	sb.Reset()
	return sb
}

func (rm *ResourceManager) PutStringBuilder(sb *strings.Builder) {
	if rm == nil || sb == nil {
		return
	}
	if sb.Cap() <= 4096 {
		rm.stringBuilders.Put(sb)
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

func (tm *TaskManager) ExecuteTask(name string, fn func(ctx context.Context) error) error {
	if tm == nil || atomic.LoadInt32(&tm.closed) != 0 {
		return nil
	}

	atomic.AddInt64(&tm.activeCount, 1)
	defer atomic.AddInt64(&tm.activeCount, -1)

	tm.wg.Add(1)
	defer tm.wg.Done()

	atomic.AddInt64(&tm.stats.executed, 1)

	defer HandlePanic(fmt.Sprintf("Task-%s", name))
	return fn(tm.ctx)
}

func (tm *TaskManager) Execute(name string, fn func(ctx context.Context) error) error {
	return tm.ExecuteTask(name, fn)
}

func (tm *TaskManager) ExecuteAsync(name string, fn func(ctx context.Context) error) {
	if tm == nil || atomic.LoadInt32(&tm.closed) != 0 {
		return
	}

	go func() {
		defer HandlePanic(fmt.Sprintf("AsyncTask-%s", name))

		if err := tm.ExecuteTask(name, fn); err != nil {
			if err != context.Canceled {
				atomic.AddInt64(&tm.stats.failed, 1)
				LogError("Async task failed [%s]: %v", name, err)
			}
		}
	}()
}

func (tm *TaskManager) GetStats() (executed, failed, timeout int64) {
	return atomic.LoadInt64(&tm.stats.executed),
		atomic.LoadInt64(&tm.stats.failed),
		atomic.LoadInt64(&tm.stats.timeout)
}

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
		return nil
	case <-time.After(timeout):
		LogWarn("Task manager shutdown timeout")
		return fmt.Errorf("shutdown timeout")
	}
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
	if rt == nil || GlobalLog.GetLevel() < Debug {
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
	if GlobalLog.GetLevel() >= Info {
		LogInfo("[%s] Query completed: %s %s | Time:%v | Upstream:%s",
			rt.ID, rt.Domain, rt.QueryType, rt.ResponseTime.Truncate(time.Microsecond), rt.Upstream)
	}
}

// =============================================================================
// DNS Record Utilities
// =============================================================================

func CreateCompactRecord(rr dns.RR) *CompactRecord {
	if rr == nil {
		return nil
	}
	return &CompactRecord{
		Text:    rr.String(),
		OrigTTL: rr.Header().Ttl,
		Type:    rr.Header().Rrtype,
	}
}

func ExpandRecord(cr *CompactRecord) dns.RR {
	if cr == nil || cr.Text == "" {
		return nil
	}
	rr, err := dns.NewRR(cr.Text)
	if err != nil {
		return nil
	}
	return rr
}

func CompactRecords(rrs []dns.RR) []*CompactRecord {
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
			if cr := CreateCompactRecord(rr); cr != nil {
				result = append(result, cr)
			}
		}
	}
	return result
}

func ExpandRecords(crs []*CompactRecord) []dns.RR {
	if len(crs) == 0 {
		return nil
	}
	result := make([]dns.RR, 0, len(crs))
	for _, cr := range crs {
		if rr := ExpandRecord(cr); rr != nil {
			result = append(result, rr)
		}
	}
	return result
}

func ProcessRecords(rrs []dns.RR, ttl uint32, includeDNSSEC bool) []dns.RR {
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

func BuildCacheKey(question dns.Question, ecs *ECSOption, dnssecEnabled bool) string {
	sb := GlobalResource.GetStringBuilder()
	defer GlobalResource.PutStringBuilder(sb)

	sb.WriteString(strings.ToLower(question.Name))
	sb.WriteByte(':')
	fmt.Fprintf(sb, "%d", question.Qtype)
	sb.WriteByte(':')
	fmt.Fprintf(sb, "%d", question.Qclass)

	if ecs != nil {
		sb.WriteByte(':')
		sb.WriteString(ecs.Address.String())
		sb.WriteByte('/')
		fmt.Fprintf(sb, "%d", ecs.SourcePrefix)
	}

	if dnssecEnabled {
		sb.WriteString(":dnssec")
	}

	result := sb.String()
	if len(result) > 512 {
		result = fmt.Sprintf("hash:%x", result)[:512]
	}
	return result
}

func CalculateTTL(rrs []dns.RR) int {
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

// =============================================================================
// DNS Server Core
// =============================================================================

func NewDNSServer(config *ServerConfig) (*DNSServer, error) {
	ctx, cancel := context.WithCancel(context.Background())

	rootServerManager := NewRootServerManager(*config)

	ednsManager, err := NewEDNSManager(config.Server.DefaultECS, config.Server.Features.Padding)
	if err != nil {
		cancel()
		return nil, WrapError("EDNS manager init", err)
	}

	rewriteManager := NewRewriteManager()
	if len(config.Rewrite) > 0 {
		if err := rewriteManager.LoadRules(config.Rewrite); err != nil {
			cancel()
			return nil, WrapError("load rewrite rules", err)
		}
	}

	connectionManager := NewConnectionManager()
	connectionManager.queryClient = NewQueryClient(connectionManager)

	taskManager := NewTaskManager(MaxConcurrency)

	server := &DNSServer{
		config:        config,
		rootServerMgr: rootServerManager,
		connMgr:       connectionManager,
		taskMgr:       taskManager,
		ednsMgr:       ednsManager,
		rewriteMgr:    rewriteManager,
		resourceMgr:   GlobalResource,
		speedDebounce: make(map[string]time.Time),
		speedInterval: SpeedDebounceInterval,
		ctx:           ctx,
		cancel:        cancel,
		shutdown:      make(chan struct{}),
	}

	securityManager, err := NewSecurityManager(config, server)
	if err != nil {
		cancel()
		return nil, WrapError("security manager init", err)
	}
	server.securityMgr = securityManager

	queryManager := NewQueryManager(server)
	if err := queryManager.Initialize(config.Upstream); err != nil {
		cancel()
		return nil, WrapError("query manager init", err)
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
			return nil, WrapError("redis cache init", err)
		}
		cache = redisCache
	}

	server.cacheMgr = cache
	server.SetupSignalHandling()
	return server, nil
}

func (s *DNSServer) SetupSignalHandling() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer HandlePanic("Root server periodic sorting")
		s.rootServerMgr.StartPeriodicSorting(s.ctx)
	}()

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer HandlePanic("Signal handler")

		select {
		case sig := <-sigChan:
			LogInfo("Received signal %v, starting graceful shutdown...", sig)
			s.ShutdownServer()
		case <-s.ctx.Done():
			return
		}
	}()
}

func (s *DNSServer) CleanupSpeedDebounce() {
	s.speedMutex.Lock()
	defer s.speedMutex.Unlock()

	now := time.Now()
	for domain, lastCheck := range s.speedDebounce {
		if now.Sub(lastCheck) >= s.speedInterval {
			delete(s.speedDebounce, domain)
		}
	}
}

func (s *DNSServer) ShutdownServer() {
	if !atomic.CompareAndSwapInt32(&s.closed, 0, 1) {
		return
	}

	LogInfo("Starting DNS server shutdown...")

	s.CleanupSpeedDebounce()

	if s.cancel != nil {
		s.cancel()
	}

	if s.cacheMgr != nil {
		CloseWithLog(s.cacheMgr, "Cache manager")
	}

	if s.securityMgr != nil {
		if err := s.securityMgr.Shutdown(ShutdownTimeout); err != nil {
			LogError("Security manager shutdown failed: %v", err)
		}
	}

	if s.connMgr != nil {
		CloseWithLog(s.connMgr, "Connection manager")
	}

	if s.taskMgr != nil {
		if err := s.taskMgr.Shutdown(ShutdownTimeout); err != nil {
			LogError("Task manager shutdown failed: %v", err)
		}
	}

	if s.speedTestMgr != nil {
		CloseWithLog(s.speedTestMgr, "SpeedTest manager")
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

func (s *DNSServer) Start() error {
	if atomic.LoadInt32(&s.closed) != 0 {
		return errors.New("server is closed")
	}

	var wg sync.WaitGroup
	serverCount := 2

	if s.securityMgr.tls != nil {
		serverCount += 1
	}

	errChan := make(chan error, serverCount)

	LogInfo("Starting ZJDNS Server v%s", GetVersion())
	LogInfo("Listening port: %s", s.config.Server.Port)

	s.DisplayInfo()

	wg.Add(serverCount)

	go func() {
		defer wg.Done()
		defer HandlePanic("Critical-UDP server")
		server := &dns.Server{
			Addr:    ":" + s.config.Server.Port,
			Net:     "udp",
			Handler: dns.HandlerFunc(s.HandleDNSRequest),
			UDPSize: UDPBufferSize,
		}
		LogInfo("UDP server started: [::]:%s", s.config.Server.Port)
		if err := server.ListenAndServe(); err != nil {
			errChan <- WrapError("UDP startup", err)
		}
	}()

	go func() {
		defer wg.Done()
		defer HandlePanic("Critical-TCP server")
		server := &dns.Server{
			Addr:    ":" + s.config.Server.Port,
			Net:     "tcp",
			Handler: dns.HandlerFunc(s.HandleDNSRequest),
		}
		LogInfo("TCP server started: [::]:%s", s.config.Server.Port)
		if err := server.ListenAndServe(); err != nil {
			errChan <- WrapError("TCP startup", err)
		}
	}()

	if s.securityMgr.tls != nil {
		go func() {
			defer wg.Done()
			defer HandlePanic("Critical-Secure DNS server")
			httpsPort := s.config.Server.TLS.HTTPS.Port
			if err := s.securityMgr.tls.Start(httpsPort); err != nil {
				errChan <- WrapError("secure DNS startup", err)
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

func (s *DNSServer) DisplayInfo() {
	servers := s.queryMgr.upstream.GetServers()
	if len(servers) > 0 {
		for _, server := range servers {
			if server.IsRecursive() {
				LogInfo("Upstream server: recursive resolution")
			} else {
				protocol := strings.ToUpper(server.Protocol)
				if protocol == "" {
					protocol = "UDP"
				}
				serverInfo := fmt.Sprintf("%s (%s)", server.Address, protocol)
				if server.SkipTLSVerify && IsSecureProtocol(strings.ToLower(server.Protocol)) {
					serverInfo += " [Skip TLS verification]"
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

	if s.rewriteMgr.HasRules() {
		LogInfo("DNS rewriter: enabled (%d rules)", len(s.config.Rewrite))
	}
	if s.config.Server.Features.HijackProtection {
		LogInfo("DNS hijacking prevention: enabled")
	}
	if defaultECS := s.ednsMgr.GetDefaultECS(); defaultECS != nil {
		LogInfo("Default ECS: %s/%d", defaultECS.Address, defaultECS.SourcePrefix)
	}
	if s.ednsMgr.IsPaddingEnabled() {
		LogInfo("DNS Padding: enabled")
	}

	if len(s.config.SpeedTest) > 0 {
		LogInfo("SpeedTest: enabled")
	} else {
		LogInfo("SpeedTest: not enabled")
	}

	// 新增：显示 Root Server 测速状态
	if s.rootServerMgr.needsSpeed {
		LogInfo("Root server speed testing: enabled")
	}

	LogInfo("Max concurrency: %d", MaxConcurrency)
}

func (s *DNSServer) HandleDNSRequest(w dns.ResponseWriter, req *dns.Msg) {
	defer HandlePanic("DNS request processing")

	select {
	case <-s.ctx.Done():
		return
	default:
	}

	response := s.ProcessDNSQuery(req, GetClientIP(w), false)
	if response != nil {
		response.Compress = true
		_ = w.WriteMsg(response)
	}
}

func (s *DNSServer) ProcessDNSQuery(req *dns.Msg, clientIP net.IP, isSecureConnection bool) *dns.Msg {
	if atomic.LoadInt32(&s.closed) != 0 {
		msg := s.BuildResponse(req)
		if msg != nil {
			msg.Rcode = dns.RcodeServerFailure
		}
		return msg
	}

	if req == nil {
		msg := &dns.Msg{}
		msg.SetReply(&dns.Msg{})
		msg.Rcode = dns.RcodeFormatError
		return msg
	}

	if len(req.Question) == 0 {
		msg := &dns.Msg{}
		if len(req.Question) > 0 {
			msg.SetReply(req)
		} else {
			msg.Response = true
		}
		msg.Rcode = dns.RcodeFormatError
		return msg
	}

	question := req.Question[0]

	if len(question.Name) > MaxDomainLength {
		msg := &dns.Msg{}
		msg.SetReply(req)
		msg.Rcode = dns.RcodeFormatError
		return msg
	}

	if question.Qtype == dns.TypeANY {
		msg := &dns.Msg{}
		msg.SetReply(req)
		msg.Rcode = dns.RcodeRefused
		return msg
	}

	var tracker *RequestTracker
	if GlobalLog.GetLevel() >= Debug {
		clientIPStr := "unknown"
		if clientIP != nil {
			clientIPStr = clientIP.String()
		}
		tracker = NewRequestTracker(
			question.Name,
			dns.TypeToString[question.Qtype],
			clientIPStr,
		)
		if tracker != nil {
			defer tracker.Finish()
		}
	}

	if tracker != nil {
		tracker.AddStep("Starting query: %s %s", question.Name, dns.TypeToString[question.Qtype])
		if isSecureConnection {
			tracker.AddStep("Secure connection, DNS Padding enabled")
		}
	}

	if s.rewriteMgr.HasRules() {
		rewriteResult := s.rewriteMgr.RewriteWithDetails(question.Name, question.Qtype)
		if rewriteResult.ShouldRewrite {
			if tracker != nil {
				tracker.AddStep("Domain rewrite: %s (QType: %s)", question.Name, dns.TypeToString[question.Qtype])
			}

			if rewriteResult.ResponseCode != dns.RcodeSuccess {
				response := s.BuildResponse(req)
				response.Rcode = rewriteResult.ResponseCode

				if tracker != nil {
					tracker.AddStep("Response code rewrite: %d", rewriteResult.ResponseCode)
				}

				response = s.AddEDNStoRewriteResponse(response, req, tracker, isSecureConnection)
				return response
			}

			if len(rewriteResult.Records) > 0 {
				response := s.BuildResponse(req)
				response.Answer = rewriteResult.Records
				response.Rcode = dns.RcodeSuccess

				if len(rewriteResult.Additional) > 0 {
					response.Extra = rewriteResult.Additional
				}

				if tracker != nil {
					tracker.AddStep("Returning custom records: %d (Answer), %d (Additional)",
						len(rewriteResult.Records), len(rewriteResult.Additional))
				}

				response = s.AddEDNStoRewriteResponse(response, req, tracker, isSecureConnection)
				return response
			}

			if rewriteResult.Domain != question.Name {
				if tracker != nil {
					tracker.AddStep("Domain rewrite: %s -> %s", question.Name, rewriteResult.Domain)
				}
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
		if tracker != nil && ecsOpt != nil {
			tracker.AddStep("Client ECS: %s/%d", ecsOpt.Address, ecsOpt.SourcePrefix)
		}
	}

	if ecsOpt == nil {
		ecsOpt = s.ednsMgr.GetDefaultECS()
		if tracker != nil && ecsOpt != nil {
			tracker.AddStep("Using default ECS: %s/%d", ecsOpt.Address, ecsOpt.SourcePrefix)
		}
	}

	serverDNSSECEnabled := s.config.Server.Features.DNSSEC
	cacheKey := BuildCacheKey(question, ecsOpt, serverDNSSECEnabled)

	if tracker != nil {
		tracker.AddStep("Cache key: %s", cacheKey)
	}

	if entry, found, isExpired := s.cacheMgr.Get(cacheKey); found {
		return s.ProcessCacheHit(req, entry, isExpired, question, clientRequestedDNSSEC, clientHasEDNS, ecsOpt, cacheKey, tracker, isSecureConnection)
	}

	if tracker != nil {
		tracker.AddStep("Cache miss, starting query")
	}
	return s.ProcessCacheMiss(req, question, ecsOpt, clientRequestedDNSSEC, clientHasEDNS, serverDNSSECEnabled, cacheKey, tracker, isSecureConnection)
}

func (s *DNSServer) AddEDNStoRewriteResponse(response *dns.Msg, req *dns.Msg, tracker *RequestTracker, isSecureConnection bool) *dns.Msg {
	if response == nil {
		return response
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

	shouldAddEDNS := clientHasEDNS || ecsOpt != nil || s.ednsMgr.IsPaddingEnabled() ||
		(clientRequestedDNSSEC && s.config.Server.Features.DNSSEC)

	if shouldAddEDNS {
		s.ednsMgr.AddToMessage(response, ecsOpt, clientRequestedDNSSEC && s.config.Server.Features.DNSSEC, isSecureConnection)
		if tracker != nil && ecsOpt != nil {
			tracker.AddStep("Adding response ECS: %s/%d", ecsOpt.Address, ecsOpt.SourcePrefix)
		}
	}

	return response
}

func (s *DNSServer) BuildResponse(req *dns.Msg) *dns.Msg {
	msg := GlobalResource.GetDNSMessage()
	if msg == nil {
		msg = &dns.Msg{}
	}

	if req != nil {
		if len(req.Question) > 0 {
			if msg.Question == nil {
				msg.Question = make([]dns.Question, 0, len(req.Question))
			}
			msg.SetReply(req)
		} else {
			msg.Response = true
			msg.Rcode = dns.RcodeFormatError
		}
	}

	msg.Authoritative = false
	msg.RecursionAvailable = true
	msg.Compress = true
	return msg
}

func (s *DNSServer) ProcessCacheHit(req *dns.Msg, entry *CacheEntry, isExpired bool,
	question dns.Question, clientRequestedDNSSEC bool, clientHasEDNS bool, ecsOpt *ECSOption,
	cacheKey string, tracker *RequestTracker, isSecureConnection bool) *dns.Msg {

	responseTTL := entry.GetRemainingTTL()

	if tracker != nil {
		tracker.CacheHit = true
		if isExpired {
			tracker.AddStep("Cache hit (expired): TTL=%ds", responseTTL)
		} else {
			tracker.AddStep("Cache hit: TTL=%ds", responseTTL)
		}
	}

	msg := s.BuildResponse(req)
	if msg == nil {
		msg = &dns.Msg{}
		msg.SetReply(req)
		msg.Rcode = dns.RcodeServerFailure
		return msg
	}

	msg.Answer = ProcessRecords(ExpandRecords(entry.Answer), responseTTL, clientRequestedDNSSEC)
	msg.Ns = ProcessRecords(ExpandRecords(entry.Authority), responseTTL, clientRequestedDNSSEC)
	msg.Extra = ProcessRecords(ExpandRecords(entry.Additional), responseTTL, clientRequestedDNSSEC)

	if s.config.Server.Features.DNSSEC && entry.Validated {
		msg.AuthenticatedData = true
		if tracker != nil {
			tracker.AddStep("Setting AD flag: cached records verified")
		}
	}

	responseECS := entry.GetECSOption()
	if responseECS == nil {
		responseECS = ecsOpt
	}

	shouldAddEDNS := clientHasEDNS || responseECS != nil || s.ednsMgr.IsPaddingEnabled() ||
		(clientRequestedDNSSEC && s.config.Server.Features.DNSSEC)

	if shouldAddEDNS {
		s.ednsMgr.AddToMessage(msg, responseECS, clientRequestedDNSSEC && s.config.Server.Features.DNSSEC, isSecureConnection)
		if tracker != nil && responseECS != nil {
			tracker.AddStep("Adding response ECS: %s/%d", responseECS.Address, responseECS.SourcePrefix)
		}
	}

	if isExpired && s.config.Server.Features.ServeStale && s.config.Server.Features.Prefetch && entry.ShouldRefresh() {
		if tracker != nil {
			tracker.AddStep("Starting background prefetch")
		}
		s.cacheMgr.RequestRefresh(RefreshRequest{
			Question:            question,
			ECS:                 ecsOpt,
			CacheKey:            cacheKey,
			ServerDNSSECEnabled: s.config.Server.Features.DNSSEC,
		})
	}

	s.RestoreOriginalDomain(msg, req.Question[0].Name, question.Name)
	return msg
}

func (s *DNSServer) ProcessCacheMiss(req *dns.Msg, question dns.Question, ecsOpt *ECSOption,
	clientRequestedDNSSEC bool, clientHasEDNS bool, serverDNSSECEnabled bool, cacheKey string,
	tracker *RequestTracker, isSecureConnection bool) *dns.Msg {

	var answer, authority, additional []dns.RR
	var validated bool
	var ecsResponse *ECSOption
	var err error

	answer, authority, additional, validated, ecsResponse, err = s.queryMgr.Query(question, ecsOpt, serverDNSSECEnabled, tracker)

	if err != nil {
		return s.ProcessQueryError(req, err, cacheKey, question, clientRequestedDNSSEC,
			clientHasEDNS, ecsOpt, tracker, isSecureConnection)
	}

	return s.ProcessQuerySuccess(req, question, ecsOpt, clientRequestedDNSSEC, clientHasEDNS, cacheKey,
		answer, authority, additional, validated, ecsResponse, tracker, isSecureConnection)
}

func (s *DNSServer) ProcessQueryError(req *dns.Msg, err error, cacheKey string,
	question dns.Question, clientRequestedDNSSEC bool, clientHasEDNS bool, ecsOpt *ECSOption,
	tracker *RequestTracker, isSecureConnection bool) *dns.Msg {

	if tracker != nil {
		tracker.AddStep("Query failed: %v", err)
	}

	if s.config.Server.Features.ServeStale {
		if entry, found, _ := s.cacheMgr.Get(cacheKey); found {
			if tracker != nil {
				tracker.AddStep("Using expired cache fallback")
			}

			responseTTL := uint32(StaleTTL)
			msg := s.BuildResponse(req)
			if msg == nil {
				msg = &dns.Msg{}
				msg.SetReply(req)
				msg.Rcode = dns.RcodeServerFailure
				return msg
			}

			msg.Answer = ProcessRecords(ExpandRecords(entry.Answer), responseTTL, clientRequestedDNSSEC)
			msg.Ns = ProcessRecords(ExpandRecords(entry.Authority), responseTTL, clientRequestedDNSSEC)
			msg.Extra = ProcessRecords(ExpandRecords(entry.Additional), responseTTL, clientRequestedDNSSEC)

			if s.config.Server.Features.DNSSEC && entry.Validated {
				msg.AuthenticatedData = true
			}

			responseECS := entry.GetECSOption()
			if responseECS == nil {
				responseECS = ecsOpt
			}

			shouldAddEDNS := clientHasEDNS || responseECS != nil || s.ednsMgr.IsPaddingEnabled() ||
				(clientRequestedDNSSEC && s.config.Server.Features.DNSSEC)

			if shouldAddEDNS {
				s.ednsMgr.AddToMessage(msg, responseECS, clientRequestedDNSSEC && s.config.Server.Features.DNSSEC, isSecureConnection)
			}

			s.RestoreOriginalDomain(msg, req.Question[0].Name, question.Name)
			return msg
		}
	}

	msg := s.BuildResponse(req)
	if msg == nil {
		msg = &dns.Msg{}
		msg.SetReply(req)
	}
	msg.Rcode = dns.RcodeServerFailure
	return msg
}

func (s *DNSServer) ProcessQuerySuccess(req *dns.Msg, question dns.Question, ecsOpt *ECSOption,
	clientRequestedDNSSEC bool, clientHasEDNS bool, cacheKey string,
	answer, authority, additional []dns.RR, validated bool, ecsResponse *ECSOption,
	tracker *RequestTracker, isSecureConnection bool) *dns.Msg {

	if tracker != nil {
		tracker.AddStep("Query successful: answers=%d, authority=%d, additional=%d", len(answer), len(authority), len(additional))
		if validated {
			tracker.AddStep("DNSSEC validated")
		}
	}

	msg := s.BuildResponse(req)
	if msg == nil {
		msg = &dns.Msg{}
		msg.SetReply(req)
	}

	if s.config.Server.Features.DNSSEC && validated {
		msg.AuthenticatedData = true
		if tracker != nil {
			tracker.AddStep("Setting AD flag: query results verified")
		}
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

	msg.Answer = ProcessRecords(answer, 0, clientRequestedDNSSEC)
	msg.Ns = ProcessRecords(authority, 0, clientRequestedDNSSEC)
	msg.Extra = ProcessRecords(additional, 0, clientRequestedDNSSEC)

	if len(s.config.SpeedTest) > 0 {
		LogDebug("SpeedTest enabled")
		if tracker != nil {
			tracker.AddStep("SpeedTest enabled")
		}

		shouldPerformSpeedTest := s.ShouldPerformSpeedTest(question.Name)
		if shouldPerformSpeedTest {
			LogDebug("SpeedTest: triggering background test for %s", question.Name)
			msgCopy := msg.Copy()
			s.taskMgr.ExecuteAsync(fmt.Sprintf("speed-test-%s", question.Name), func(ctx context.Context) error {
				LogDebug("SpeedTest: starting background test for %s", question.Name)
				speedTester := NewSpeedTestManager(*s.config)
				defer CloseWithLog(speedTester, "SpeedTester")
				speedTester.PerformSpeedTestAndSort(msgCopy)

				s.cacheMgr.Set(cacheKey,
					msgCopy.Answer,
					msgCopy.Ns,
					msgCopy.Extra,
					validated, responseECS)
				LogDebug("SpeedTest: background test completed for %s", question.Name)

				return nil
			})

			if tracker != nil {
				tracker.AddStep("First response not sorted, background SpeedTest in progress")
			}
		} else {
			LogDebug("SpeedTest: domain %s skipped by debounce", question.Name)
			if tracker != nil {
				tracker.AddStep("SpeedTest skipped (debounce)")
			}
		}
	} else {
		LogDebug("SpeedTest not enabled")
	}

	shouldAddEDNS := clientHasEDNS || responseECS != nil || s.ednsMgr.IsPaddingEnabled() ||
		(clientRequestedDNSSEC && s.config.Server.Features.DNSSEC)

	if shouldAddEDNS {
		s.ednsMgr.AddToMessage(msg, responseECS, clientRequestedDNSSEC && s.config.Server.Features.DNSSEC, isSecureConnection)
		if tracker != nil && responseECS != nil {
			tracker.AddStep("Adding response ECS: %s/%d", responseECS.Address, responseECS.SourcePrefix)
		}
	}

	s.RestoreOriginalDomain(msg, req.Question[0].Name, question.Name)
	return msg
}

func (s *DNSServer) RestoreOriginalDomain(msg *dns.Msg, currentName, originalName string) {
	if msg == nil {
		return
	}

	for _, rr := range msg.Answer {
		if rr != nil && strings.EqualFold(rr.Header().Name, currentName) {
			rr.Header().Name = originalName
		}
	}
}

func (s *DNSServer) ShouldPerformSpeedTest(domain string) bool {
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

func (s *DNSServer) QueryForRefresh(question dns.Question, ecs *ECSOption, serverDNSSECEnabled bool) ([]dns.RR, []dns.RR, []dns.RR, bool, *ECSOption, error) {
	defer HandlePanic("Cache refresh query")

	if atomic.LoadInt32(&s.closed) != 0 {
		return nil, nil, nil, false, nil, errors.New("server is closed")
	}

	_, cancel := context.WithTimeout(s.ctx, ExtendedTimeout)
	defer cancel()

	return s.queryMgr.Query(question, ecs, serverDNSSECEnabled, nil)
}

func (s *DNSServer) BuildQueryMessage(question dns.Question, ecs *ECSOption, dnssecEnabled bool, recursionDesired bool, isSecureConnection bool) *dns.Msg {
	msg := GlobalResource.GetDNSMessage()

	if msg == nil {
		msg = &dns.Msg{}
	}

	if err := s.SafeSetQuestion(msg, question.Name, question.Qtype); err != nil {
		LogDebug("Set DNS question failed: %v", err)
		msg = &dns.Msg{}
		msg.SetQuestion(dns.Fqdn(question.Name), question.Qtype)
	}

	msg.RecursionDesired = recursionDesired

	if s.ednsMgr != nil {
		s.ednsMgr.AddToMessage(msg, ecs, dnssecEnabled, isSecureConnection)
	}

	return msg
}

func (s *DNSServer) SafeSetQuestion(msg *dns.Msg, name string, qtype uint16) error {
	if msg == nil {
		return errors.New("message is nil")
	}

	if name == "" {
		return errors.New("domain is empty")
	}

	if len(name) > MaxDomainLength {
		return errors.New("domain too long")
	}

	if msg.Question == nil {
		msg.Question = make([]dns.Question, 0, 1)
	}

	defer HandlePanic("Set DNS question")

	msg.SetQuestion(dns.Fqdn(name), qtype)
	return nil
}

// =============================================================================
// Utility Functions
// =============================================================================

func SafeCopyMessage(msg *dns.Msg) *dns.Msg {
	if msg == nil {
		newMsg := GlobalResource.GetDNSMessage()
		return newMsg
	}

	msgCopy := GlobalResource.GetDNSMessage()

	msgCopy.MsgHdr = msg.MsgHdr
	msgCopy.Compress = msg.Compress

	if msg.Question != nil {
		msgCopy.Question = append(msgCopy.Question[:0], msg.Question...)
	} else {
		msgCopy.Question = msgCopy.Question[:0]
	}

	if msg.Answer != nil {
		msgCopy.Answer = msgCopy.Answer[:0]
		for _, rr := range msg.Answer {
			if rr != nil {
				msgCopy.Answer = append(msgCopy.Answer, dns.Copy(rr))
			}
		}
	} else {
		msgCopy.Answer = msgCopy.Answer[:0]
	}

	if msg.Ns != nil {
		msgCopy.Ns = msgCopy.Ns[:0]
		for _, rr := range msg.Ns {
			if rr != nil {
				msgCopy.Ns = append(msgCopy.Ns, dns.Copy(rr))
			}
		}
	} else {
		msgCopy.Ns = msgCopy.Ns[:0]
	}

	if msg.Extra != nil {
		msgCopy.Extra = msgCopy.Extra[:0]
		for _, rr := range msg.Extra {
			if rr != nil {
				msgCopy.Extra = append(msgCopy.Extra, dns.Copy(rr))
			}
		}
	} else {
		msgCopy.Extra = msgCopy.Extra[:0]
	}

	return msgCopy
}

func HandlePanic(operation string) {
	if r := recover(); r != nil {
		buf := make([]byte, 2048)
		n := runtime.Stack(buf, false)
		stackTrace := string(buf[:n])

		LogError("Panic [%s]: %v\nStack:\n%s\nExiting due to panic",
			operation, r, stackTrace)

		os.Exit(1)
	}
}

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

func IsSecureProtocol(protocol string) bool {
	switch protocol {
	case "tls", "quic", "https", "http3":
		return true
	default:
		return false
	}
}

func IsValidFilePath(path string) bool {
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

func WrapError(op string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", op, err)
}

func CloseWithLog(c Closeable, name string) {
	if c == nil {
		return
	}
	if err := c.Close(); err != nil {
		LogWarn("Close %s failed: %v", name, err)
	}
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
		fmt.Fprintf(os.Stderr, "Version: %s\n\n", GetVersion())
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  %s -config <config file>     # Start with config file\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -generate-config          # Generate example config\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -version                  # Show version information\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s                            # Start with default config\n\n", os.Args[0])
	}

	flag.Parse()

	if showVersion {
		fmt.Printf("ZJDNS Server\n")
		fmt.Printf("Version: %s\n", GetVersion())
		if BuildTime != "" {
			fmt.Printf("Built: %s\n", BuildTime)
		}
		return
	}

	if generateConfig {
		fmt.Println(GenerateExampleConfig())
		return
	}

	config, err := GlobalConfig.LoadConfig(configFile)
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
