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
	// Network Configuration
	DefaultDNSPort     = "53"
	DefaultTLSPort     = "853"
	DefaultHTTPSPort   = "443"
	DefaultQueryPath   = "/dns-query"
	RecursiveIndicator = "builtin_recursive"

	// Buffer & Size Limits
	UDPBufferSize      = 1232
	TCPBufferSize      = 4096
	SecureBufferSize   = 8192
	MinDNSPacketSize   = 12
	MaxDomainLength    = 253
	MaxInputLineLength = 128

	// DNS Query Timeouts
	QueryTimeout     = 5 * time.Second
	RecursiveTimeout = 15 * time.Second
	ExtendedTimeout  = 30 * time.Second

	// Connection Timeouts
	ConnTimeout           = 5 * time.Second
	TLSHandshakeTimeout   = 3 * time.Second
	ConnectionTestTimeout = 100 * time.Millisecond
	PublicIPTimeout       = 3 * time.Second
	HTTPClientTimeout     = 5 * time.Second

	// Server Timeouts
	ShutdownTimeout       = 5 * time.Second
	CleanupInterval       = 30 * time.Second
	DoHReadHeaderTimeout  = 5 * time.Second
	DoHWriteTimeout       = 5 * time.Second
	DefaultSpeedTimeout   = 250 * time.Millisecond
	SpeedDebounceInterval = 10 * time.Second

	// Root Server Management
	RootServerSortInterval = 900 * time.Second

	// Connection Lifecycle
	SecureIdleTimeout  = 300 * time.Second
	SecureKeepAlive    = 15 * time.Second
	DoHIdleConnTimeout = 300 * time.Second

	// Cache Configuration
	DefaultCacheTTL      = 300
	StaleTTL             = 30
	StaleMaxAge          = 259200
	CacheQueueSize       = 500
	IPCacheExpiry        = 300 * time.Second
	DefaultSpeedCacheTTL = 900 * time.Second

	// Performance Limits
	MaxConcurrency     = 1000
	MaxSingleQuery     = 3
	MaxNSResolve       = 3
	MaxCNAMEChain      = 16
	MaxRecursionDepth  = 16
	ConnectionPoolSize = 50

	// Redis Configuration
	RedisPoolSize     = 20
	RedisMinIdle      = 5
	RedisMaxRetries   = 3
	RedisPoolTimeout  = 5 * time.Second
	RedisReadTimeout  = 3 * time.Second
	RedisWriteTimeout = 3 * time.Second
	RedisDialTimeout  = 5 * time.Second

	// ECS Configuration
	MaxTrustedIPv4  = 1024
	MaxTrustedIPv6  = 256
	DefaultECSv4Len = 24
	DefaultECSv6Len = 64
	DefaultECSScope = 0

	// DNS Padding
	PaddingBlockSize = 468

	// DoH Configuration
	DoHMaxRequestSize  = 8192
	DoHMaxConnsPerHost = 3
	DoHMaxIdleConns    = 3

	// Connection Pool Configuration
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

	// QUIC Address Validator
	QUICAddrValidatorCacheSize = 16 * 1024
	QUICAddrValidatorTTL       = 300 * time.Second

	// SpeedTest Configuration
	DefaultSpeedConcurrency = 4

	// Default Values
	DefaultLogLevel = "info"

	// ANSI Color Codes
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

// Log Levels
const (
	LogError LogLevel = iota
	LogWarn
	LogInfo
	LogDebug
)

// =============================================================================
// Types - Logging
// =============================================================================

type LogLevel int

type Logger struct {
	level    LogLevel
	writer   io.Writer
	mu       sync.Mutex
	colorMap map[LogLevel]string
}

// =============================================================================
// Types - Core Server
// =============================================================================

type DNSServer struct {
	config            *ServerConfig
	cache             CacheManager
	connPool          *ConnectionPool
	tlsManager        *TLSManager
	upstreamManager   *UpstreamManager
	queryClient       *QueryClient
	taskManager       *TaskManager
	ednsManager       *EDNSManager
	dnsRewriter       *DNSRewriter
	ipFilter          *IPFilter
	hijackPrevention  *HijackPrevention
	dnssecValidator   *DNSSECValidator
	rootServerManager *RootServerManager
	concurrencyLimit  chan struct{}
	speedDebounce     map[string]time.Time
	speedMutex        sync.Mutex
	speedInterval     time.Duration
	ctx               context.Context
	cancel            context.CancelFunc
	shutdown          chan struct{}
	wg                sync.WaitGroup
	closed            int32
}

type QueryClient struct {
	connPool     *ConnectionPool
	errorHandler *SecureErrorHandler
	timeout      time.Duration
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
	Port            string       `json:"port"`
	LogLevel        string       `json:"log_level"`
	DefaultECS      string       `json:"default_ecs_subnet"`
	TrustedCIDRFile string       `json:"trusted_cidr_file"`
	DDR             DDRSettings  `json:"ddr"`
	TLS             TLSSettings  `json:"tls"`
	Features        FeatureFlags `json:"features"`
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
	IPv6             bool `json:"ipv6"`
}

type RedisSettings struct {
	Address   string `json:"address"`
	Password  string `json:"password"`
	Database  int    `json:"database"`
	KeyPrefix string `json:"key_prefix"`
}

type UpstreamServer struct {
	Address       string `json:"address"`
	Policy        string `json:"policy"`
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

// =============================================================================
// Types - Cache
// =============================================================================

type CacheManager interface {
	Get(key string) (*CacheEntry, bool, bool)
	Set(key string, answer, authority, additional []dns.RR, validated bool, ecs *ECSOption)
	RequestRefresh(req RefreshRequest)
	Close() error
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
	taskManager  *TaskManager
	server       *DNSServer
	wg           sync.WaitGroup
	closed       int32
}

// =============================================================================
// Types - Network
// =============================================================================

type ConnectionPool struct {
	clients       chan *dns.Client
	secureClients map[string]SecureClient
	tlsConns      map[string]*tls.Conn
	tlsMu         sync.RWMutex
	quicConns     map[string]*quic.Conn
	quicMu        sync.RWMutex
	timeout       time.Duration
	mu            sync.RWMutex
	ctx           context.Context
	cancel        context.CancelFunc
	wg            sync.WaitGroup
	closed        int32
}

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
	dohClient       *DoHClient
	isQUICConnected bool
	lastActivity    time.Time
	mu              sync.Mutex
	connPool        *ConnectionPool
	addr            string
}

type DoHClient struct {
	addr         *url.URL
	tlsConfig    *tls.Config
	client       *http.Client
	clientMu     sync.Mutex
	quicConfig   *quic.Config
	timeout      time.Duration
	skipVerify   bool
	serverName   string
	addrRedacted string
	httpVersions []string
	closed       int32
}

type HTTP3Transport struct {
	baseTransport *http3.Transport
	closed        bool
	mu            sync.RWMutex
}

// =============================================================================
// Types - Security & Management
// =============================================================================

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
	quicAddrValidator *QuicAddrValidator
	httpsServer       *http.Server
	h3Server          *http3.Server
	httpsListener     net.Listener
	h3Listener        *quic.EarlyListener
}

type UpstreamManager struct {
	servers []*UpstreamServer
	mu      sync.RWMutex
}

type SecureErrorHandler struct{}

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

type QuicAddrValidator struct {
	cache *ristretto.Cache[string, struct{}]
	ttl   time.Duration
}

// =============================================================================
// Types - DNS Processing
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

type DNSRewriter struct {
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

type IPFilter struct {
	trustedCIDRs   []*net.IPNet
	trustedCIDRsV6 []*net.IPNet
	mu             sync.RWMutex
}

type FilterContext struct {
	Policy       string
	IsGlueRecord bool
}

type HijackPrevention struct {
	enabled bool
}

type DNSSECValidator struct{}

type RecordHandler struct{}

type CacheUtils struct{}

type IPDetector struct {
	httpClient *http.Client
}

// =============================================================================
// Types - SpeedTesting
// =============================================================================

type SpeedTester struct {
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

type ConfigManager struct{}

type RootServerManager struct {
	serversV4    []string
	serversV6    []string
	speedTester  *SpeedTester
	sortedV4     []string
	sortedV6     []string
	lastSortTime time.Time
	mu           sync.RWMutex
}

// =============================================================================
// Variables
// =============================================================================

// Protocol Identifiers
var (
	NextProtoQUIC  = []string{"doq", "doq-i00", "doq-i02", "doq-i03", "dq"}
	NextProtoHTTP3 = []string{"h3"}
	NextProtoHTTP2 = []string{http2.NextProtoTLS, "http/1.1"}
)

// Global Variables
var (
	globalResourceManager = NewResourceManager()
	globalRecordHandler   = NewRecordHandler()
	globalCacheUtils      = NewCacheUtils()
	globalErrorHandler    = NewSecureErrorHandler()
	globalConfigManager   = NewConfigManager()
	globalLogger          = NewLogger()
)

// =============================================================================
// Logging System
// =============================================================================

func NewLogger() *Logger {
	return &Logger{
		level:  LogInfo,
		writer: os.Stdout,
		colorMap: map[LogLevel]string{
			LogError: ColorRed,
			LogWarn:  ColorYellow,
			LogInfo:  ColorGreen,
			LogDebug: ColorCyan,
		},
	}
}

func (l *Logger) SetLevel(level LogLevel) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.level = level
}

func (l *Logger) GetLevel() LogLevel {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.level
}

func (l *Logger) GetLevelString(level LogLevel) string {
	switch level {
	case LogError:
		return "ERROR"
	case LogWarn:
		return "WARN"
	case LogInfo:
		return "INFO"
	case LogDebug:
		return "DEBUG"
	default:
		return "UNKNOWN"
	}
}

func (l *Logger) Log(level LogLevel, format string, args ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if level > l.level {
		return
	}

	levelStr := l.GetLevelString(level)
	color := l.colorMap[level]
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	message := fmt.Sprintf(format, args...)

	logLine := fmt.Sprintf("%s[%s]%s %s%-5s%s %s\n",
		ColorBold, timestamp, ColorReset,
		color, levelStr, ColorReset,
		message)

	if _, err := fmt.Fprint(l.writer, logLine); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Failed to write log: %v\n", err)
	}
}

func (l *Logger) Error(format string, args ...interface{}) { l.Log(LogError, format, args...) }
func (l *Logger) Warn(format string, args ...interface{})  { l.Log(LogWarn, format, args...) }
func (l *Logger) Info(format string, args ...interface{})  { l.Log(LogInfo, format, args...) }
func (l *Logger) Debug(format string, args ...interface{}) { l.Log(LogDebug, format, args...) }

func Error(format string, args ...interface{}) { globalLogger.Error(format, args...) }
func Warn(format string, args ...interface{})  { globalLogger.Warn(format, args...) }
func Info(format string, args ...interface{})  { globalLogger.Info(format, args...) }
func Debug(format string, args ...interface{}) { globalLogger.Debug(format, args...) }

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
		return nil, fmt.Errorf("failed to read configuration file: %w", err)
	}

	config := &ServerConfig{}
	if err := json.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("failed to parse configuration file: %w", err)
	}

	if err := cm.ValidateConfig(config); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	if cm.ShouldEnableDDR(config) {
		cm.AddDDRRecords(config)
	}

	Info("Configuration loaded successfully: %s", configFile)
	return config, nil
}

func (cm *ConfigManager) ValidateConfig(config *ServerConfig) error {
	validLevels := map[string]LogLevel{
		"error": LogError, "warn": LogWarn,
		"info": LogInfo, "debug": LogDebug,
	}

	if level, ok := validLevels[strings.ToLower(config.Server.LogLevel)]; ok {
		globalLogger.SetLevel(level)
	} else {
		return fmt.Errorf("invalid log level: %s", config.Server.LogLevel)
	}

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
				return fmt.Errorf("invalid ECS subnet format: %w", err)
			}
		}
	}

	for i, server := range config.Upstream {
		if !server.IsRecursive() {
			if _, _, err := net.SplitHostPort(server.Address); err != nil {
				if server.Protocol == "https" || server.Protocol == "http3" {
					if _, err := url.Parse(server.Address); err != nil {
						return fmt.Errorf("upstream server %d address format error: %w", i, err)
					}
				} else {
					return fmt.Errorf("upstream server %d address format error: %w", i, err)
				}
			}
		}

		validPolicies := map[string]bool{"all": true, "trusted_only": true, "untrusted_only": true}
		if !validPolicies[server.Policy] {
			return fmt.Errorf("upstream server %d trust policy invalid: %s", i, server.Policy)
		}

		validProtocols := map[string]bool{"udp": true, "tcp": true, "tls": true, "quic": true, "https": true, "http3": true}
		if server.Protocol != "" && !validProtocols[strings.ToLower(server.Protocol)] {
			return fmt.Errorf("upstream server %d protocol invalid: %s", i, server.Protocol)
		}

		protocol := strings.ToLower(server.Protocol)
		if IsSecureProtocol(protocol) && server.ServerName == "" {
			return fmt.Errorf("upstream server %d using %s protocol requires server_name configuration", i, server.Protocol)
		}
	}

	if config.Redis.Address != "" {
		if _, _, err := net.SplitHostPort(config.Redis.Address); err != nil {
			return fmt.Errorf("redis address format error: %w", err)
		}
	} else {
		if config.Server.Features.ServeStale {
			Warn("No cache mode: expired cache service disabled")
			config.Server.Features.ServeStale = false
		}
		if config.Server.Features.Prefetch {
			Warn("No cache mode: prefetch function disabled")
			config.Server.Features.Prefetch = false
		}
	}

	if config.Server.TLS.CertFile != "" || config.Server.TLS.KeyFile != "" {
		if config.Server.TLS.CertFile == "" || config.Server.TLS.KeyFile == "" {
			return fmt.Errorf("certificate and private key files must be configured together")
		}

		if !IsValidFilePath(config.Server.TLS.CertFile) {
			return fmt.Errorf("certificate file does not exist: %s", config.Server.TLS.CertFile)
		}

		if !IsValidFilePath(config.Server.TLS.KeyFile) {
			return fmt.Errorf("private key file does not exist: %s", config.Server.TLS.KeyFile)
		}

		if _, err := tls.LoadX509KeyPair(config.Server.TLS.CertFile, config.Server.TLS.KeyFile); err != nil {
			return fmt.Errorf("certificate loading failed: %w", err)
		}

		Info("TLS certificate verification passed")
	}

	return nil
}

func (cm *ConfigManager) GetDefaultConfig() *ServerConfig {
	config := &ServerConfig{}

	config.Server.Port = DefaultDNSPort
	config.Server.LogLevel = DefaultLogLevel
	config.Server.DefaultECS = "auto"
	config.Server.TrustedCIDRFile = ""
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
	config.Server.Features.IPv6 = true

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
		Debug("Adding DDR NXDOMAIN rule for A record: %s", domain)
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
		Debug("Adding DDR NXDOMAIN rule for AAAA record: %s", domain)
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
			Debug("Adding DDR SVCB rewrite rule: %s", ruleName)
		}

		if len(directQueryRecords) > 0 {
			directRule := RewriteRule{
				Name:    domain,
				Records: directQueryRecords,
			}
			config.Rewrite = append(config.Rewrite, directRule)
			Debug("Adding DDR direct query rewrite rule: %s (%d records)", domain, len(directQueryRecords))
		}
	}
}

func GenerateExampleConfig() string {
	config := globalConfigManager.GetDefaultConfig()

	config.Server.LogLevel = DefaultLogLevel
	config.Server.DefaultECS = "auto"
	config.Server.TrustedCIDRFile = "trusted_cidr.txt"

	config.Redis.Address = "127.0.0.1:6379"

	config.Server.TLS.CertFile = "/path/to/cert.pem"
	config.Server.TLS.KeyFile = "/path/to/key.pem"
	config.Server.TLS.HTTPS.Port = DefaultHTTPSPort
	config.Server.TLS.HTTPS.Endpoint = DefaultQueryPath

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
			Address:       "https://dns.alidns.com/dns-query",
			Policy:        "all",
			Protocol:      "https",
			ServerName:    "dns.alidns.com",
			SkipTLSVerify: false,
		},
		{
			Address:       "https://dns.alidns.com/dns-query",
			Policy:        "trusted_only",
			Protocol:      "http3",
			ServerName:    "dns.alidns.com",
			SkipTLSVerify: false,
		},
		{
			Address: RecursiveIndicator,
			Policy:  "all",
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

func LoadConfig(filename string) (*ServerConfig, error) {
	return globalConfigManager.LoadConfig(filename)
}

// =============================================================================
// Cache System
// =============================================================================

func NewNullCache() *NullCache {
	Info("No cache mode")
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
		return nil, fmt.Errorf("redis connection failed: %w", err)
	}

	cacheCtx, cacheCancel := context.WithCancel(context.Background())
	cache := &RedisCache{
		client:       rdb,
		config:       config,
		keyPrefix:    config.Redis.KeyPrefix,
		refreshQueue: make(chan RefreshRequest, CacheQueueSize),
		ctx:          cacheCtx,
		cancel:       cacheCancel,
		taskManager:  NewTaskManager(10),
		server:       server,
	}

	if config.Server.Features.ServeStale && config.Server.Features.Prefetch {
		cache.StartRefreshProcessor()
	}

	Info("Redis cache system initialization completed")
	return cache, nil
}

func (rc *RedisCache) StartRefreshProcessor() {
	workerCount := 2

	for i := 0; i < workerCount; i++ {
		rc.wg.Add(1)
		go func(workerID int) {
			defer rc.wg.Done()
			defer func() { RecoverPanic(fmt.Sprintf("Redis refresh worker %d", workerID)) }()

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
	defer func() { RecoverPanic("Redis refresh request processing") }()

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

		speedTester := NewSpeedTester(*rc.server.config)
		speedTester.PerformSpeedTestAndSort(tempMsg)
		_ = speedTester.Close()

		answer = tempMsg.Answer
		authority = tempMsg.Ns
		additional = tempMsg.Extra
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
	defer func() { RecoverPanic("Update refresh time") }()

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
	defer func() { RecoverPanic("Redis cache retrieval") }()

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
		Debug("Cache entry parsing failed: %v", err)
		go func() {
			defer func() { RecoverPanic("Clean corrupted cache") }()
			rc.client.Del(context.Background(), fullKey)
		}()
		return nil, false, false
	}

	if entry.IsStale() {
		go func() {
			defer func() { RecoverPanic("Clean expired cache") }()
			rc.client.Del(context.Background(), fullKey)
		}()
		return nil, false, false
	}

	entry.AccessTime = time.Now().Unix()
	go func() {
		defer func() { RecoverPanic("Update access time") }()
		rc.UpdateAccessInfo(fullKey, &entry)
	}()

	isExpired := entry.IsExpired()

	if !rc.config.Server.Features.ServeStale && isExpired {
		go func() {
			defer func() { RecoverPanic("Clean expired cache") }()
			rc.client.Del(context.Background(), fullKey)
		}()
		return nil, false, false
	}

	return &entry, true, isExpired
}

func (rc *RedisCache) Set(key string, answer, authority, additional []dns.RR, validated bool, ecs *ECSOption) {
	defer func() { RecoverPanic("Redis cache setting") }()

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
	defer func() { RecoverPanic("Redis access info update") }()

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

	Info("Shutting down Redis cache...")

	if err := rc.taskManager.Shutdown(ShutdownTimeout); err != nil {
		Error("Task manager shutdown failed: %v", err)
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
		Error("Redis client shutdown failed: %v", err)
	}

	Info("Redis cache has been shut down")
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
// Connection & Network Management
// =============================================================================

func NewConnectionPool() *ConnectionPool {
	ctx, cancel := context.WithCancel(context.Background())
	cp := &ConnectionPool{
		clients:       make(chan *dns.Client, ConnectionPoolSize),
		secureClients: make(map[string]SecureClient),
		tlsConns:      make(map[string]*tls.Conn),
		quicConns:     make(map[string]*quic.Conn),
		timeout:       QueryTimeout,
		ctx:           ctx,
		cancel:        cancel,
	}

	cp.wg.Add(1)
	go func() {
		defer cp.wg.Done()
		cp.StartCleanupRoutine()
	}()

	return cp
}

func (cp *ConnectionPool) StartCleanupRoutine() {
	ticker := time.NewTicker(CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-cp.ctx.Done():
			return
		case <-ticker.C:
			cp.CleanupIdleConnections()
		}
	}
}

func (cp *ConnectionPool) CleanupIdleConnections() {
	if atomic.LoadInt32(&cp.closed) != 0 {
		return
	}

	cp.tlsMu.Lock()
	for key, conn := range cp.tlsConns {
		if err := conn.SetReadDeadline(time.Now().Add(ConnectionTestTimeout)); err != nil {
			delete(cp.tlsConns, key)
			go func(c *tls.Conn) {
				_ = c.Close()
			}(conn)
			Debug("Cleaned up idle TLS connection: %s", key)
		} else {
			_ = conn.SetReadDeadline(time.Time{})
		}
	}
	cp.tlsMu.Unlock()

	cp.quicMu.Lock()
	for key, conn := range cp.quicConns {
		if conn.Context().Err() != nil {
			delete(cp.quicConns, key)
			go func(c *quic.Conn) {
				_ = c.CloseWithError(QUICCodeNoError, "idle-cleanup")
			}(conn)
			Debug("Cleaned up idle QUIC connection: %s", key)
		}
	}
	cp.quicMu.Unlock()
}

func (cp *ConnectionPool) CreateClient() *dns.Client {
	return &dns.Client{
		Timeout:        cp.timeout,
		Net:            "udp",
		UDPSize:        UDPBufferSize,
		SingleInflight: false,
	}
}

func (cp *ConnectionPool) GetUDPClient() *dns.Client {
	if atomic.LoadInt32(&cp.closed) != 0 {
		return cp.CreateClient()
	}

	select {
	case client := <-cp.clients:
		return client
	default:
		return cp.CreateClient()
	}
}

func (cp *ConnectionPool) GetTCPClient() *dns.Client {
	return &dns.Client{
		Timeout:        cp.timeout,
		Net:            "tcp",
		SingleInflight: false,
	}
}

func (cp *ConnectionPool) GetTLSConn(host, port string, tlsConfig *tls.Config) (*tls.Conn, error) {
	cacheKey := fmt.Sprintf("%s:%s", host, port)

	cp.tlsMu.RLock()
	if conn, exists := cp.tlsConns[cacheKey]; exists {
		cp.tlsMu.RUnlock()

		if err := conn.SetReadDeadline(time.Now().Add(ConnectionTestTimeout)); err == nil {
			var buf [1]byte
			if _, err := conn.Read(buf[:]); err == nil || err == io.EOF {
				_ = conn.SetReadDeadline(time.Time{})
				Debug("Reusing existing TLS connection: %s", cacheKey)
				return conn, nil
			}
		}

		cp.RemoveTLSConn(cacheKey, conn)
	} else {
		cp.tlsMu.RUnlock()
	}

	dialer := &net.Dialer{
		Timeout:   TLSHandshakeTimeout,
		KeepAlive: SecureKeepAlive,
	}

	if runtime.GOOS == "linux" {
		dialer.Control = func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_NODELAY, TCPNoDelay)
				_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, TCPQuickAck, 1)
			})
		}
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(host, port), tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("TLS dial failed: %w", err)
	}

	if tcpConn, ok := conn.NetConn().(*net.TCPConn); ok {
		_ = tcpConn.SetKeepAlive(true)
		_ = tcpConn.SetKeepAlivePeriod(SecureKeepAlive)
		_ = tcpConn.SetNoDelay(true)
		_ = tcpConn.SetReadBuffer(TCPReadBufferSize)
		_ = tcpConn.SetWriteBuffer(TCPWriteBufferSize)
	}

	connState := conn.ConnectionState()
	if connState.DidResume {
		Debug("TLS session resumed for %s:%s", host, port)
	} else {
		Debug("TLS full handshake for %s:%s", host, port)
	}

	cp.tlsMu.Lock()
	cp.tlsConns[cacheKey] = conn
	cp.tlsMu.Unlock()

	Debug("Created new TLS connection: %s", cacheKey)
	return conn, nil
}

func (cp *ConnectionPool) RemoveTLSConn(key string, conn *tls.Conn) {
	cp.tlsMu.Lock()
	defer cp.tlsMu.Unlock()

	if currentConn, exists := cp.tlsConns[key]; exists && currentConn == conn {
		delete(cp.tlsConns, key)
		go func() {
			_ = conn.Close()
		}()
	}
}

func (cp *ConnectionPool) GetQUICConn(addr string, tlsConfig *tls.Config, quicConfig *quic.Config) (*quic.Conn, error) {
	cacheKey := addr

	cp.quicMu.RLock()
	if conn, exists := cp.quicConns[cacheKey]; exists {
		cp.quicMu.RUnlock()

		if conn.Context().Err() == nil {
			ctx, cancel := context.WithTimeout(context.Background(), ConnectionTestTimeout)
			defer cancel()

			stream, err := conn.OpenStreamSync(ctx)
			if err == nil {
				_ = stream.Close()
				Debug("Reusing existing QUIC connection: %s", addr)
				return conn, nil
			}
		}

		cp.RemoveQUICConn(cacheKey, conn)
	} else {
		cp.quicMu.RUnlock()
	}

	ctx, cancel := context.WithTimeout(context.Background(), ConnTimeout)
	defer cancel()

	conn, err := quic.DialAddr(ctx, addr, tlsConfig, quicConfig)
	if err != nil {
		return nil, fmt.Errorf("QUIC dial failed: %w", err)
	}

	cp.quicMu.Lock()
	cp.quicConns[cacheKey] = conn
	cp.quicMu.Unlock()

	Debug("Created new QUIC connection: %s", addr)
	return conn, nil
}

func (cp *ConnectionPool) RemoveQUICConn(key string, conn *quic.Conn) {
	cp.quicMu.Lock()
	defer cp.quicMu.Unlock()

	if currentConn, exists := cp.quicConns[key]; exists && currentConn == conn {
		delete(cp.quicConns, key)
		go func() {
			_ = conn.CloseWithError(QUICCodeNoError, "cleanup")
		}()
	}
}

func (cp *ConnectionPool) GetSecureClient(protocol, addr, serverName string, skipVerify bool) (SecureClient, error) {
	if atomic.LoadInt32(&cp.closed) != 0 {
		return nil, errors.New("connection pool closed")
	}

	cacheKey := fmt.Sprintf("%s:%s:%s:%v", protocol, addr, serverName, skipVerify)

	cp.mu.RLock()
	if client, exists := cp.secureClients[cacheKey]; exists {
		cp.mu.RUnlock()

		if unifiedClient, ok := client.(*UnifiedSecureClient); ok && unifiedClient != nil {
			if unifiedClient.IsConnectionHealthy() {
				Debug("Reusing secure client: %s", protocol)
				return client, nil
			} else {
				cp.CleanupClient(cacheKey, client)
			}
		}
	} else {
		cp.mu.RUnlock()
	}

	client, err := NewUnifiedSecureClient(cp, protocol, addr, serverName, skipVerify)
	if err != nil {
		return nil, err
	}

	cp.mu.Lock()
	if atomic.LoadInt32(&cp.closed) == 0 {
		cp.secureClients[cacheKey] = client
	}
	cp.mu.Unlock()

	return client, nil
}

func (cp *ConnectionPool) CleanupClient(key string, client SecureClient) {
	cp.mu.Lock()
	defer cp.mu.Unlock()

	if currentClient, exists := cp.secureClients[key]; exists && currentClient == client {
		delete(cp.secureClients, key)
		go func() {
			defer func() { RecoverPanic("Connection cleanup") }()
			if err := client.Close(); err != nil {
				Warn("Secure client shutdown failed: %v", err)
			}
		}()
	}
}

func (cp *ConnectionPool) PutUDPClient(client *dns.Client) {
	if client == nil || atomic.LoadInt32(&cp.closed) != 0 {
		return
	}
	select {
	case cp.clients <- client:
	default:
	}
}

func (cp *ConnectionPool) Close() error {
	if !atomic.CompareAndSwapInt32(&cp.closed, 0, 1) {
		return nil
	}

	Info("Shutting down connection pool...")

	cp.cancel()

	cp.mu.Lock()
	for key, client := range cp.secureClients {
		if err := client.Close(); err != nil {
			Warn("Secure client shutdown failed [%s]: %v", key, err)
		}
	}
	cp.secureClients = make(map[string]SecureClient)
	cp.mu.Unlock()

	cp.tlsMu.Lock()
	for key, conn := range cp.tlsConns {
		_ = conn.Close()
		Debug("Closed TLS connection: %s", key)
	}
	cp.tlsConns = make(map[string]*tls.Conn)
	cp.tlsMu.Unlock()

	cp.quicMu.Lock()
	for key, conn := range cp.quicConns {
		_ = conn.CloseWithError(QUICCodeNoError, "shutdown")
		Debug("Closed QUIC connection: %s", key)
	}
	cp.quicConns = make(map[string]*quic.Conn)
	cp.quicMu.Unlock()

	close(cp.clients)
	for range cp.clients {
	}

	cp.wg.Wait()

	Info("Connection pool has been shut down")
	return nil
}

func NewQueryClient(connectionPool *ConnectionPool, timeout time.Duration) *QueryClient {
	return &QueryClient{
		connPool:     connectionPool,
		errorHandler: globalErrorHandler,
		timeout:      timeout,
	}
}

func (qc *QueryClient) ExecuteQuery(ctx context.Context, msg *dns.Msg, server *UpstreamServer, tracker *RequestTracker) *QueryResult {
	start := time.Now()
	result := &QueryResult{
		Server:   server.Address,
		Protocol: server.Protocol,
	}

	if tracker != nil {
		tracker.AddStep("Starting query server: %s (%s)", server.Address, server.Protocol)
	}

	queryCtx, cancel := context.WithTimeout(ctx, qc.timeout)
	defer cancel()

	protocol := strings.ToLower(server.Protocol)

	if IsSecureProtocol(protocol) {
		result.Response, result.Error = qc.ExecuteSecureQuery(msg, server, tracker)
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

func (qc *QueryClient) ExecuteSecureQuery(msg *dns.Msg, server *UpstreamServer, tracker *RequestTracker) (*dns.Msg, error) {
	client, err := qc.connPool.GetSecureClient(server.Protocol, server.Address, server.ServerName, server.SkipTLSVerify)
	if err != nil {
		return nil, fmt.Errorf("failed to get %s client: %w", strings.ToUpper(server.Protocol), err)
	}

	response, err := client.Exchange(msg, server.Address)
	if err != nil {
		return nil, err
	}

	if tracker != nil && response != nil {
		tracker.AddStep("%s query successful, response code: %s", strings.ToUpper(server.Protocol), dns.RcodeToString[response.Rcode])
	}

	return response, nil
}

func (qc *QueryClient) ExecuteTraditionalQuery(ctx context.Context, msg *dns.Msg, server *UpstreamServer, tracker *RequestTracker) (*dns.Msg, error) {
	msgCopy := SafeCopyMessage(msg)

	var client *dns.Client
	if server.Protocol == "tcp" {
		client = qc.connPool.GetTCPClient()
	} else {
		client = qc.connPool.GetUDPClient()
		defer qc.connPool.PutUDPClient(client)
	}

	response, _, err := client.ExchangeContext(ctx, msgCopy, server.Address)

	if tracker != nil && err == nil && response != nil {
		protocolName := "UDP"
		if server.Protocol == "tcp" {
			protocolName = "TCP"
		}
		tracker.AddStep("%s query successful, response code: %s", protocolName, dns.RcodeToString[response.Rcode])
	}

	if msgCopy != nil {
		globalResourceManager.PutDNSMessage(msgCopy)
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

func NewUnifiedSecureClient(pool *ConnectionPool, protocol, addr, serverName string, skipVerify bool) (*UnifiedSecureClient, error) {
	client := &UnifiedSecureClient{
		protocol:     strings.ToLower(protocol),
		serverName:   serverName,
		skipVerify:   skipVerify,
		timeout:      QueryTimeout,
		lastActivity: time.Now(),
		connPool:     pool,
		addr:         addr,
	}

	switch client.protocol {
	case "https", "http3":
		var err error
		client.dohClient, err = NewDoHClient(addr, serverName, skipVerify, QueryTimeout)
		if err != nil {
			return nil, fmt.Errorf("failed to create DoH client: %w", err)
		}
	case "tls", "quic":
	default:
		return nil, fmt.Errorf("unsupported protocol: %s", protocol)
	}

	return client, nil
}

func (c *UnifiedSecureClient) IsConnectionHealthy() bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	if time.Since(c.lastActivity) > SecureIdleTimeout {
		return false
	}

	switch c.protocol {
	case "tls":
		return c.tlsConn != nil
	case "quic":
		return c.quicConn != nil && c.isQUICConnected && c.quicConn.Context().Err() == nil
	case "https", "http3":
		return c.dohClient != nil
	}
	return false
}

func (c *UnifiedSecureClient) Connect(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("address parsing failed: %w", err)
	}

	switch c.protocol {
	case "tls":
		return c.ConnectTLS(host, port)
	case "quic":
		return c.ConnectQUIC(net.JoinHostPort(host, port))
	default:
		return fmt.Errorf("unsupported protocol: %s", c.protocol)
	}
}

func (c *UnifiedSecureClient) ConnectTLS(host, port string) error {
	tlsConfig := &tls.Config{
		ServerName:             c.serverName,
		InsecureSkipVerify:     c.skipVerify,
		ClientSessionCache:     tls.NewLRUClientSessionCache(TLSSessionCacheSize),
		MinVersion:             tls.VersionTLS12,
		SessionTicketsDisabled: false,
	}

	if c.connPool != nil {
		conn, err := c.connPool.GetTLSConn(host, port, tlsConfig)
		if err != nil {
			return err
		}
		c.tlsConn = conn
		c.lastActivity = time.Now()
		return nil
	}

	dialer := &net.Dialer{
		Timeout:   TLSHandshakeTimeout,
		KeepAlive: SecureKeepAlive,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(host, port), tlsConfig)
	if err != nil {
		return fmt.Errorf("TLS connection failed: %w", err)
	}

	if tcpConn, ok := conn.NetConn().(*net.TCPConn); ok {
		_ = tcpConn.SetKeepAlive(true)
		_ = tcpConn.SetKeepAlivePeriod(SecureKeepAlive)
		_ = tcpConn.SetNoDelay(true)
		_ = tcpConn.SetReadBuffer(TCPReadBufferSize)
		_ = tcpConn.SetWriteBuffer(TCPWriteBufferSize)
	}

	c.tlsConn = conn
	c.lastActivity = time.Now()
	return nil
}

func (c *UnifiedSecureClient) ConnectQUIC(addr string) error {
	tlsConfig := &tls.Config{
		ServerName:         c.serverName,
		InsecureSkipVerify: c.skipVerify,
		NextProtos:         NextProtoQUIC,
		ClientSessionCache: tls.NewLRUClientSessionCache(QUICSessionCacheSize),
	}

	quicConfig := &quic.Config{
		MaxIdleTimeout:        SecureIdleTimeout,
		MaxIncomingStreams:    MaxIncomingStreams,
		MaxIncomingUniStreams: MaxIncomingStreams,
		KeepAlivePeriod:       SecureKeepAlive,
		Allow0RTT:             true,
		EnableDatagrams:       false,
		InitialPacketSize:     InitialPacketSize,
	}

	if c.connPool != nil {
		conn, err := c.connPool.GetQUICConn(addr, tlsConfig, quicConfig)
		if err != nil {
			return err
		}
		c.quicConn = conn
		c.isQUICConnected = true
		c.lastActivity = time.Now()
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()

	conn, err := quic.DialAddr(ctx, addr, tlsConfig, quicConfig)
	if err != nil {
		return fmt.Errorf("QUIC connection failed: %w", err)
	}

	c.quicConn = conn
	c.isQUICConnected = true
	c.lastActivity = time.Now()
	return nil
}

func (c *UnifiedSecureClient) Exchange(msg *dns.Msg, addr string) (*dns.Msg, error) {
	switch c.protocol {
	case "https", "http3":
		return c.dohClient.Exchange(msg)
	case "tls":
		if !c.IsConnectionHealthy() {
			if err := c.Connect(addr); err != nil {
				return nil, fmt.Errorf("reconnection failed: %w", err)
			}
		}
		resp, err := c.ExchangeTLS(msg)
		if err != nil && globalErrorHandler.IsRetryableError("tls", err) {
			Debug("TLS connection error, attempting reconnect: %v", err)
			if c.Connect(addr) == nil {
				return c.ExchangeTLS(msg)
			}
		}
		return resp, err
	case "quic":
		if !c.IsConnectionHealthy() {
			if err := c.Connect(addr); err != nil {
				return nil, fmt.Errorf("reconnection failed: %w", err)
			}
		}
		return c.ExchangeQUIC(msg)
	default:
		return nil, fmt.Errorf("unsupported protocol: %s", c.protocol)
	}
}

func (c *UnifiedSecureClient) ExchangeTLS(msg *dns.Msg) (*dns.Msg, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.tlsConn == nil {
		return nil, errors.New("TLS connection not established")
	}

	deadline := time.Now().Add(c.timeout)
	if deadlineErr := c.tlsConn.SetDeadline(deadline); deadlineErr != nil {
		Debug("Setting TLS connection deadline failed: %v", deadlineErr)
	}
	defer func() {
		if deadlineErr := c.tlsConn.SetDeadline(time.Time{}); deadlineErr != nil {
			Debug("Resetting TLS connection deadline failed: %v", deadlineErr)
		}
	}()

	msgData, err := msg.Pack()
	if err != nil {
		return nil, fmt.Errorf("message packing failed: %w", err)
	}

	buf := make([]byte, 2+len(msgData))
	binary.BigEndian.PutUint16(buf[:2], uint16(len(msgData)))
	copy(buf[2:], msgData)

	if _, err := c.tlsConn.Write(buf); err != nil {
		return nil, fmt.Errorf("failed to send TLS query: %w", err)
	}

	lengthBuf := make([]byte, 2)
	if _, err := io.ReadFull(c.tlsConn, lengthBuf); err != nil {
		return nil, fmt.Errorf("failed to read response length: %w", err)
	}

	respLength := binary.BigEndian.Uint16(lengthBuf)
	if respLength == 0 || respLength > TCPBufferSize {
		return nil, fmt.Errorf("abnormal response length: %d", respLength)
	}

	respBuf := make([]byte, respLength)
	if _, err := io.ReadFull(c.tlsConn, respBuf); err != nil {
		return nil, fmt.Errorf("failed to read response content: %w", err)
	}

	response := new(dns.Msg)
	if err := response.Unpack(respBuf); err != nil {
		return nil, fmt.Errorf("response parsing failed: %w", err)
	}

	c.lastActivity = time.Now()
	return response, nil
}

func (c *UnifiedSecureClient) ExchangeQUIC(msg *dns.Msg) (*dns.Msg, error) {
	originalID := msg.Id
	msg.Id = 0
	defer func() {
		msg.Id = originalID
	}()

	resp, err := c.ExchangeQUICDirect(msg)

	if errors.Is(err, quic.Err0RTTRejected) {
		Debug("0-RTT rejected, retrying with 1-RTT")

		c.mu.Lock()
		if c.quicConn != nil {
			_ = c.quicConn.CloseWithError(QUICCodeNoError, "0rtt-rejected")
			c.quicConn = nil
			c.isQUICConnected = false
		}
		c.mu.Unlock()

		resp, err = c.ExchangeQUICDirect(msg)
	}

	if resp != nil {
		resp.Id = originalID
	}
	return resp, err
}

func (c *UnifiedSecureClient) ExchangeQUICDirect(msg *dns.Msg) (*dns.Msg, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.quicConn == nil || !c.isQUICConnected {
		return nil, errors.New("QUIC connection not established")
	}

	msgData, err := msg.Pack()
	if err != nil {
		return nil, fmt.Errorf("message packing failed: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()

	stream, err := c.quicConn.OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create QUIC stream: %w", err)
	}
	defer func() {
		if closeErr := stream.Close(); closeErr != nil {
			Debug("Closing QUIC stream failed: %v", closeErr)
		}
	}()

	if c.timeout > 0 {
		if err := stream.SetDeadline(time.Now().Add(c.timeout)); err != nil {
			return nil, fmt.Errorf("failed to set stream timeout: %w", err)
		}
	}

	buf := make([]byte, 2+len(msgData))
	binary.BigEndian.PutUint16(buf[:2], uint16(len(msgData)))
	copy(buf[2:], msgData)

	if _, err = stream.Write(buf); err != nil {
		return nil, fmt.Errorf("failed to send QUIC query: %w", err)
	}

	if err := stream.Close(); err != nil {
		Debug("Closing QUIC stream write direction failed: %v", err)
	}

	resp, err := c.ReadQUICMsg(stream)
	if err == nil {
		c.lastActivity = time.Now()
	}
	return resp, err
}

func (c *UnifiedSecureClient) ReadQUICMsg(stream *quic.Stream) (*dns.Msg, error) {
	respBuf := make([]byte, SecureBufferSize)

	n, err := stream.Read(respBuf)
	if err != nil && n == 0 {
		return nil, fmt.Errorf("failed to read QUIC response: %w", err)
	}

	stream.CancelRead(0)

	if n < 2 {
		return nil, fmt.Errorf("QUIC response too short: %d bytes", n)
	}

	msgLen := binary.BigEndian.Uint16(respBuf[:2])
	if int(msgLen) != n-2 {
		Debug("QUIC response length mismatch: declared=%d, actual=%d", msgLen, n-2)
	}

	response := new(dns.Msg)
	if err := response.Unpack(respBuf[2:n]); err != nil {
		return nil, fmt.Errorf("QUIC response parsing failed: %w", err)
	}

	return response, nil
}

func (c *UnifiedSecureClient) Close() error {
	if c == nil {
		return nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	switch c.protocol {
	case "tls":
		if c.tlsConn != nil {
			if c.connPool == nil {
				if closeErr := c.tlsConn.Close(); closeErr != nil {
					Debug("Closing TLS connection failed: %v", closeErr)
				}
			}
			c.tlsConn = nil
		}
	case "quic":
		if c.quicConn != nil {
			if c.connPool == nil {
				if closeErr := c.quicConn.CloseWithError(QUICCodeNoError, ""); closeErr != nil {
					Debug("Closing QUIC connection failed: %v", closeErr)
				}
			}
			c.quicConn = nil
			c.isQUICConnected = false
		}
	case "https", "http3":
		if c.dohClient != nil {
			if closeErr := c.dohClient.Close(); closeErr != nil {
				Debug("Closing DoH client failed: %v", closeErr)
			}
			c.dohClient = nil
		}
	}

	return nil
}

func NewDoHClient(addr, serverName string, skipVerify bool, timeout time.Duration) (*DoHClient, error) {
	parsedURL, err := url.Parse(addr)
	if err != nil {
		return nil, fmt.Errorf("DoH address parsing failed: %w", err)
	}

	if parsedURL.Port() == "" {
		if parsedURL.Scheme == "https" || parsedURL.Scheme == "h3" {
			parsedURL.Host = net.JoinHostPort(parsedURL.Host, DefaultHTTPSPort)
		}
	}

	var httpVersions []string
	if parsedURL.Scheme == "h3" {
		parsedURL.Scheme = "https"
		httpVersions = NextProtoHTTP3
	} else {
		httpVersions = append(NextProtoHTTP2, NextProtoHTTP3...)
	}

	if serverName == "" {
		serverName = parsedURL.Hostname()
	}

	tlsConfig := &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: skipVerify,
		NextProtos:         httpVersions,
		MinVersion:         tls.VersionTLS12,
		ClientSessionCache: tls.NewLRUClientSessionCache(TLSSessionCacheSize),
	}

	client := &DoHClient{
		addr:      parsedURL,
		tlsConfig: tlsConfig,
		quicConfig: &quic.Config{
			MaxIdleTimeout:     SecureIdleTimeout,
			MaxIncomingStreams: MaxIncomingStreams,
			KeepAlivePeriod:    SecureKeepAlive,
			Allow0RTT:          true,
			InitialPacketSize:  InitialPacketSize,
		},
		timeout:      timeout,
		skipVerify:   skipVerify,
		serverName:   serverName,
		addrRedacted: parsedURL.Redacted(),
		httpVersions: httpVersions,
	}

	runtime.SetFinalizer(client, (*DoHClient).Close)
	return client, nil
}

func (c *DoHClient) Exchange(msg *dns.Msg) (*dns.Msg, error) {
	if c == nil || msg == nil {
		return nil, errors.New("DoH client or message is empty")
	}

	originalID := msg.Id
	msg.Id = 0
	defer func() {
		msg.Id = originalID
	}()

	httpClient, isCached, err := c.GetClient()
	if err != nil {
		return nil, fmt.Errorf("failed to get HTTP client: %w", err)
	}

	resp, err := c.ExchangeHTTPS(httpClient, msg)

	for i := 0; isCached && c.ShouldRetry(err) && i < 2; i++ {
		httpClient, err = c.ResetClient(err)
		if err != nil {
			return nil, fmt.Errorf("failed to reset HTTP client: %w", err)
		}
		resp, err = c.ExchangeHTTPS(httpClient, msg)
	}

	if err != nil {
		if _, resetErr := c.ResetClient(err); resetErr != nil {
			Debug("Resetting client failed: %v", resetErr)
		}
		return nil, err
	}

	if resp != nil {
		resp.Id = originalID
	}

	return resp, nil
}

func (c *DoHClient) ExchangeHTTPS(client *http.Client, req *dns.Msg) (*dns.Msg, error) {
	if client == nil || req == nil {
		return nil, errors.New("HTTP client or request is empty")
	}

	buf, err := req.Pack()
	if err != nil {
		return nil, fmt.Errorf("failed to pack DNS message: %w", err)
	}

	method := http.MethodGet
	if c.IsHTTP3(client) {
		method = http3.MethodGet0RTT
	}

	q := url.Values{
		"dns": []string{base64.RawURLEncoding.EncodeToString(buf)},
	}

	u := url.URL{
		Scheme:   c.addr.Scheme,
		Host:     c.addr.Host,
		Path:     c.addr.Path,
		RawQuery: q.Encode(),
	}

	httpReq, err := http.NewRequest(method, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	httpReq.Header.Set("Accept", "application/dns-message")
	httpReq.Header.Set("User-Agent", "")

	httpResp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send HTTP request: %w", err)
	}
	defer func() {
		if closeErr := httpResp.Body.Close(); closeErr != nil {
			Debug("Closing HTTP response body failed: %v", closeErr)
		}
	}()

	if httpResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP response error: %d", httpResp.StatusCode)
	}

	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	resp := &dns.Msg{}
	if err := resp.Unpack(body); err != nil {
		return nil, fmt.Errorf("failed to parse DNS response: %w", err)
	}

	return resp, nil
}

func (c *DoHClient) GetClient() (*http.Client, bool, error) {
	if c == nil {
		return nil, false, errors.New("DoH client is empty")
	}

	if atomic.LoadInt32(&c.closed) != 0 {
		return nil, false, errors.New("DoH client is closed")
	}

	c.clientMu.Lock()
	defer c.clientMu.Unlock()

	if c.client != nil {
		return c.client, true, nil
	}

	var err error
	c.client, err = c.CreateClient()
	return c.client, false, err
}

func (c *DoHClient) CreateClient() (*http.Client, error) {
	transport, err := c.CreateTransport()
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP transport: %w", err)
	}

	return &http.Client{
		Transport: transport,
		Timeout:   c.timeout,
	}, nil
}

func (c *DoHClient) CreateTransport() (http.RoundTripper, error) {
	if c.SupportsHTTP3() {
		if transport, err := c.CreateTransportH3(); err == nil {
			Debug("DoH client using HTTP/3: %s", c.addrRedacted)
			return transport, nil
		} else {
			Debug("HTTP/3 connection failed, falling back to HTTP/2: %v", err)
		}
	}

	if !c.SupportsHTTP() {
		return nil, errors.New("HTTP/1.1 or HTTP/2 not supported")
	}

	transport := &http.Transport{
		TLSClientConfig:    c.tlsConfig.Clone(),
		DisableCompression: true,
		IdleConnTimeout:    DoHIdleConnTimeout,
		MaxConnsPerHost:    DoHMaxConnsPerHost,
		MaxIdleConns:       DoHMaxIdleConns,
		ForceAttemptHTTP2:  true,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialer := &net.Dialer{Timeout: c.timeout}
			return dialer.DialContext(ctx, network, addr)
		},
	}

	_, err := http2.ConfigureTransports(transport)
	if err != nil {
		return nil, err
	}

	return transport, nil
}

func (c *DoHClient) CreateTransportH3() (http.RoundTripper, error) {
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()

	tlsConfig := c.tlsConfig.Clone()
	tlsConfig.NextProtos = NextProtoHTTP3

	conn, err := quic.DialAddr(ctx, c.addr.Host, tlsConfig, c.quicConfig)
	if err != nil {
		return nil, fmt.Errorf("QUIC connection failed: %w", err)
	}

	if closeErr := conn.CloseWithError(QUICCodeNoError, ""); closeErr != nil {
		Debug("Closing QUIC test connection failed: %v", closeErr)
	}

	transport := &http3.Transport{
		TLSClientConfig: tlsConfig,
		QUICConfig:      c.quicConfig,
	}

	return &HTTP3Transport{
		baseTransport: transport,
		closed:        false,
	}, nil
}

func (c *DoHClient) ResetClient(resetErr error) (*http.Client, error) {
	if c == nil {
		return nil, errors.New("DoH client is empty")
	}

	c.clientMu.Lock()
	defer c.clientMu.Unlock()

	if errors.Is(resetErr, quic.Err0RTTRejected) {
		Debug("0-RTT rejected, disabling 0-RTT for next attempt")
		c.quicConfig = &quic.Config{
			MaxIdleTimeout:     SecureIdleTimeout,
			MaxIncomingStreams: MaxIncomingStreams,
			KeepAlivePeriod:    SecureKeepAlive,
			Allow0RTT:          false,
			InitialPacketSize:  InitialPacketSize,
		}
	}

	oldClient := c.client
	if oldClient != nil {
		c.CloseClient(oldClient)
	}

	var err error
	c.client, err = c.CreateClient()
	return c.client, err
}

func (c *DoHClient) CloseClient(client *http.Client) {
	if c == nil || client == nil {
		return
	}

	if c.IsHTTP3(client) {
		if closer, ok := client.Transport.(io.Closer); ok {
			if closeErr := closer.Close(); closeErr != nil {
				Debug("Closing HTTP3 transport failed: %v", closeErr)
			}
		}
	}
}

func (c *DoHClient) ShouldRetry(err error) bool {
	if c == nil {
		return false
	}
	return globalErrorHandler.IsRetryableError("https", err)
}

func (c *DoHClient) SupportsHTTP3() bool {
	for _, proto := range c.httpVersions {
		if proto == "h3" {
			return true
		}
	}
	return false
}

func (c *DoHClient) SupportsHTTP() bool {
	for _, proto := range c.httpVersions {
		if proto == http2.NextProtoTLS || proto == "http/1.1" {
			return true
		}
	}
	return false
}

func (c *DoHClient) IsHTTP3(client *http.Client) bool {
	_, ok := client.Transport.(*HTTP3Transport)
	return ok
}

func (c *DoHClient) Close() error {
	if c == nil || !atomic.CompareAndSwapInt32(&c.closed, 0, 1) {
		return nil
	}

	runtime.SetFinalizer(c, nil)

	c.clientMu.Lock()
	defer c.clientMu.Unlock()

	if c.client != nil {
		c.CloseClient(c.client)
		c.client = nil
	}

	return nil
}

func (h *HTTP3Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if h == nil || h.baseTransport == nil {
		return nil, errors.New("HTTP/3 transport is empty")
	}

	h.mu.RLock()
	defer h.mu.RUnlock()

	if h.closed {
		return nil, net.ErrClosed
	}

	resp, err := h.baseTransport.RoundTripOpt(req, http3.RoundTripOpt{OnlyCachedConn: true})
	if errors.Is(err, http3.ErrNoCachedConn) {
		resp, err = h.baseTransport.RoundTrip(req)
	}

	return resp, err
}

func (h *HTTP3Transport) Close() error {
	if h == nil {
		return nil
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	h.closed = true
	if h.baseTransport != nil {
		return h.baseTransport.Close()
	}
	return nil
}

func NewSecureErrorHandler() *SecureErrorHandler {
	return &SecureErrorHandler{}
}

func (h *SecureErrorHandler) IsRetryableError(protocol string, err error) bool {
	if h == nil || err == nil {
		return false
	}

	if errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}

	protocol = strings.ToLower(protocol)

	switch protocol {
	case "quic", "http3":
		return h.HandleQUICErrors(err)
	case "tls":
		return h.HandleTLSErrors(err)
	case "https":
		return h.HandleHTTPErrors(err)
	default:
		return false
	}
}

func (h *SecureErrorHandler) HandleQUICErrors(err error) bool {
	var qAppErr *quic.ApplicationError
	if errors.As(err, &qAppErr) {
		return qAppErr.ErrorCode == 0 || qAppErr.ErrorCode == quic.ApplicationErrorCode(0x100)
	}

	var qIdleErr *quic.IdleTimeoutError
	if errors.As(err, &qIdleErr) {
		return true
	}

	var resetErr *quic.StatelessResetError
	if errors.As(err, &resetErr) {
		return true
	}

	var qTransportError *quic.TransportError
	if errors.As(err, &qTransportError) && qTransportError.ErrorCode == quic.NoError {
		return true
	}

	return errors.Is(err, quic.Err0RTTRejected)
}

func (h *SecureErrorHandler) HandleTLSErrors(err error) bool {
	errStr := err.Error()
	connectionErrors := []string{
		"broken pipe", "connection reset", "use of closed network connection",
		"connection refused", "no route to host", "network is unreachable",
	}

	for _, connErr := range connectionErrors {
		if strings.Contains(strings.ToLower(errStr), strings.ToLower(connErr)) {
			return true
		}
	}

	return errors.Is(err, io.EOF)
}

func (h *SecureErrorHandler) HandleHTTPErrors(err error) bool {
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}

	return h.HandleQUICErrors(err)
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
	um.mu.RLock()
	defer um.mu.RUnlock()
	return um.servers
}

func (u *UpstreamServer) IsRecursive() bool {
	return strings.ToLower(u.Address) == RecursiveIndicator
}

// =============================================================================
// DNS Processing Core
// =============================================================================

func NewDNSServer(config *ServerConfig) (*DNSServer, error) {
	ctx, cancel := context.WithCancel(context.Background())

	// Initialize root server manager first
	rootServerManager := NewRootServerManager(*config)

	ednsManager, err := NewEDNSManager(config.Server.DefaultECS, config.Server.Features.Padding)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("EDNS manager initialization failed: %w", err)
	}

	ipFilter := NewIPFilter()
	if config.Server.TrustedCIDRFile != "" {
		if err := ipFilter.LoadCIDRs(config.Server.TrustedCIDRFile); err != nil {
			cancel()
			return nil, fmt.Errorf("failed to load trusted CIDR file: %w", err)
		}
	}

	dnsRewriter := NewDNSRewriter()
	if len(config.Rewrite) > 0 {
		if err := dnsRewriter.LoadRules(config.Rewrite); err != nil {
			cancel()
			return nil, fmt.Errorf("failed to load DNS rewrite rules: %w", err)
		}
	}

	upstreamManager := NewUpstreamManager(config.Upstream)
	connectionPool := NewConnectionPool()
	taskManager := NewTaskManager(MaxConcurrency)
	queryClient := NewQueryClient(connectionPool, QueryTimeout)
	hijackPrevention := NewHijackPrevention(config.Server.Features.HijackProtection)

	server := &DNSServer{
		config:            config,
		rootServerManager: rootServerManager,
		connPool:          connectionPool,
		dnssecValidator:   NewDNSSECValidator(),
		concurrencyLimit:  make(chan struct{}, MaxConcurrency),
		ctx:               ctx,
		cancel:            cancel,
		shutdown:          make(chan struct{}),
		ipFilter:          ipFilter,
		dnsRewriter:       dnsRewriter,
		upstreamManager:   upstreamManager,
		queryClient:       queryClient,
		hijackPrevention:  hijackPrevention,
		taskManager:       taskManager,
		ednsManager:       ednsManager,
		speedDebounce:     make(map[string]time.Time),
		speedInterval:     SpeedDebounceInterval,
	}

	if config.Server.TLS.CertFile != "" && config.Server.TLS.KeyFile != "" {
		tlsManager, err := NewTLSManager(server, config)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("secure DNS manager initialization failed: %w", err)
		}
		server.tlsManager = tlsManager
	}

	var cache CacheManager
	if config.Redis.Address == "" {
		cache = NewNullCache()
	} else {
		redisCache, err := NewRedisCache(config, server)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("redis cache initialization failed: %w", err)
		}
		cache = redisCache
	}

	server.cache = cache
	server.SetupSignalHandling()
	return server, nil
}

func (s *DNSServer) SetupSignalHandling() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start root server periodic sorting
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer func() { RecoverPanic("Root server periodic sorting") }()
		s.rootServerManager.StartPeriodicSorting(s.ctx)
	}()

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer func() { RecoverPanic("Signal handler") }()

		select {
		case sig := <-sigChan:
			Info("Received signal %v, starting graceful shutdown...", sig)
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

	Info("Starting DNS server shutdown...")

	s.CleanupSpeedDebounce()

	if s.cancel != nil {
		s.cancel()
	}

	if s.cache != nil {
		if err := s.cache.Close(); err != nil {
			Error("Cache shutdown failed: %v", err)
		}
	}

	if s.tlsManager != nil {
		if err := s.tlsManager.Shutdown(); err != nil {
			Error("Secure DNS manager shutdown failed: %v", err)
		}
	}

	if s.connPool != nil {
		if err := s.connPool.Close(); err != nil {
			Error("Connection pool shutdown failed: %v", err)
		}
	}

	if s.taskManager != nil {
		if err := s.taskManager.Shutdown(ShutdownTimeout); err != nil {
			Error("Task manager shutdown failed: %v", err)
		}
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		s.wg.Wait()
	}()

	select {
	case <-done:
		Info("All components have been safely shut down")
	case <-time.After(ShutdownTimeout):
		Warn("Component shutdown timeout")
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

	if s.tlsManager != nil {
		serverCount += 1
	}

	errChan := make(chan error, serverCount)

	Info("Starting ZJDNS Server")
	Info("Listening port: %s", s.config.Server.Port)

	s.DisplayInfo()

	wg.Add(serverCount)

	go func() {
		defer wg.Done()
		defer func() { RecoverPanic("Critical-UDP server") }()
		server := &dns.Server{
			Addr:    ":" + s.config.Server.Port,
			Net:     "udp",
			Handler: dns.HandlerFunc(s.HandleDNSRequest),
			UDPSize: UDPBufferSize,
		}
		Info("UDP server started: [::]:%s", s.config.Server.Port)
		if err := server.ListenAndServe(); err != nil {
			errChan <- fmt.Errorf("UDP startup failed: %w", err)
		}
	}()

	go func() {
		defer wg.Done()
		defer func() { RecoverPanic("Critical-TCP server") }()
		server := &dns.Server{
			Addr:    ":" + s.config.Server.Port,
			Net:     "tcp",
			Handler: dns.HandlerFunc(s.HandleDNSRequest),
		}
		Info("TCP server started: [::]:%s", s.config.Server.Port)
		if err := server.ListenAndServe(); err != nil {
			errChan <- fmt.Errorf("TCP startup failed: %w", err)
		}
	}()

	if s.tlsManager != nil {
		go func() {
			defer wg.Done()
			defer func() { RecoverPanic("Critical-Secure DNS server") }()
			httpsPort := s.config.Server.TLS.HTTPS.Port
			if err := s.tlsManager.Start(httpsPort); err != nil {
				errChan <- fmt.Errorf("secure DNS startup failed: %w", err)
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
	servers := s.upstreamManager.GetServers()
	if len(servers) > 0 {
		for _, server := range servers {
			if server.IsRecursive() {
				Info("Upstream server: recursive resolution - %s", server.Policy)
			} else {
				protocol := strings.ToUpper(server.Protocol)
				if protocol == "" {
					protocol = "UDP"
				}
				serverInfo := fmt.Sprintf("%s (%s) - %s", server.Address, protocol, server.Policy)
				if server.SkipTLSVerify && IsSecureProtocol(strings.ToLower(server.Protocol)) {
					serverInfo += " [Skip TLS verification]"
				}
				Info("Upstream server: %s", serverInfo)
			}
		}
		Info("Upstream mode: total %d servers", len(servers))
	} else {
		if s.config.Redis.Address == "" {
			Info("Recursive mode (no cache)")
		} else {
			Info("Recursive mode + Redis cache: %s", s.config.Redis.Address)
		}
	}

	if s.tlsManager != nil {
		Info("Listening secure DNS protocol port: %s (DoT/DoQ)", s.config.Server.TLS.Port)

		httpsPort := s.config.Server.TLS.HTTPS.Port
		if httpsPort != "" {
			endpoint := s.config.Server.TLS.HTTPS.Endpoint
			if endpoint == "" {
				endpoint = strings.TrimPrefix(DefaultQueryPath, "/")
			}
			Info("Listening secure DNS protocol port: %s (DoH/DoH3, endpoint: %s)", httpsPort, endpoint)
		}
	}

	if s.ipFilter.HasData() {
		Info("IP filter: enabled (config file: %s)", s.config.Server.TrustedCIDRFile)
	}
	if s.dnsRewriter.HasRules() {
		Info("DNS rewriter: enabled (%d rules)", len(s.config.Rewrite))
	}
	if s.config.Server.Features.HijackProtection {
		Info("DNS hijacking prevention: enabled")
	}
	if defaultECS := s.ednsManager.GetDefaultECS(); defaultECS != nil {
		Info("Default ECS: %s/%d", defaultECS.Address, defaultECS.SourcePrefix)
	}
	if s.ednsManager.IsPaddingEnabled() {
		Info("DNS Padding: enabled")
	}

	if len(s.config.SpeedTest) > 0 {
		Info("SpeedTest: enabled")
	} else {
		Info("SpeedTest: not enabled")
	}

	Info("Max concurrency: %d", MaxConcurrency)
	Info("Connection pool optimizations: enabled (TLS session resumption, QUIC 0-RTT)")
}

func (s *DNSServer) HandleDNSRequest(w dns.ResponseWriter, req *dns.Msg) {
	defer func() { RecoverPanic("DNS request processing") }()

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
	if globalLogger.GetLevel() >= LogDebug {
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
		tracker.AddStep("Starting query processing: %s %s", question.Name, dns.TypeToString[question.Qtype])
		if isSecureConnection {
			tracker.AddStep("Secure connection query, DNS Padding will be enabled")
		}
	}

	if s.dnsRewriter.HasRules() {
		rewriteResult := s.dnsRewriter.RewriteWithDetails(question.Name, question.Qtype)
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
		ecsOpt = s.ednsManager.ParseFromDNS(req)
		if tracker != nil && ecsOpt != nil {
			tracker.AddStep("Client ECS: %s/%d", ecsOpt.Address, ecsOpt.SourcePrefix)
		}
	}

	if ecsOpt == nil {
		ecsOpt = s.ednsManager.GetDefaultECS()
		if tracker != nil && ecsOpt != nil {
			tracker.AddStep("Using default ECS: %s/%d", ecsOpt.Address, ecsOpt.SourcePrefix)
		}
	}

	serverDNSSECEnabled := s.config.Server.Features.DNSSEC
	cacheKey := globalCacheUtils.BuildKey(question, ecsOpt, serverDNSSECEnabled)

	if tracker != nil {
		tracker.AddStep("Cache key: %s", cacheKey)
	}

	if entry, found, isExpired := s.cache.Get(cacheKey); found {
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
		ecsOpt = s.ednsManager.ParseFromDNS(req)
	}

	if ecsOpt == nil {
		ecsOpt = s.ednsManager.GetDefaultECS()
	}

	shouldAddEDNS := clientHasEDNS || ecsOpt != nil || s.ednsManager.IsPaddingEnabled() ||
		(clientRequestedDNSSEC && s.config.Server.Features.DNSSEC)

	if shouldAddEDNS {
		s.ednsManager.AddToMessage(response, ecsOpt, clientRequestedDNSSEC && s.config.Server.Features.DNSSEC, isSecureConnection)
		if tracker != nil && ecsOpt != nil {
			tracker.AddStep("Adding response ECS: %s/%d", ecsOpt.Address, ecsOpt.SourcePrefix)
		}
	}

	return response
}

func (s *DNSServer) BuildResponse(req *dns.Msg) *dns.Msg {
	msg := globalResourceManager.GetDNSMessage()
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

	msg.Answer = globalRecordHandler.ProcessRecords(globalRecordHandler.ExpandRecords(entry.Answer), responseTTL, clientRequestedDNSSEC)
	msg.Ns = globalRecordHandler.ProcessRecords(globalRecordHandler.ExpandRecords(entry.Authority), responseTTL, clientRequestedDNSSEC)
	msg.Extra = globalRecordHandler.ProcessRecords(globalRecordHandler.ExpandRecords(entry.Additional), responseTTL, clientRequestedDNSSEC)

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

	shouldAddEDNS := clientHasEDNS || responseECS != nil || s.ednsManager.IsPaddingEnabled() ||
		(clientRequestedDNSSEC && s.config.Server.Features.DNSSEC)

	if shouldAddEDNS {
		s.ednsManager.AddToMessage(msg, responseECS, clientRequestedDNSSEC && s.config.Server.Features.DNSSEC, isSecureConnection)
		if tracker != nil && responseECS != nil {
			tracker.AddStep("Adding response ECS: %s/%d", responseECS.Address, responseECS.SourcePrefix)
		}
	}

	if isExpired && s.config.Server.Features.ServeStale && s.config.Server.Features.Prefetch && entry.ShouldRefresh() {
		if tracker != nil {
			tracker.AddStep("Starting background prefetch refresh")
		}
		s.cache.RequestRefresh(RefreshRequest{
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

	servers := s.upstreamManager.GetServers()
	if len(servers) > 0 {
		if tracker != nil {
			tracker.AddStep("Using upstream server query (%d available)", len(servers))
		}
		answer, authority, additional, validated, ecsResponse, err = s.QueryUpstreamServers(
			question, ecsOpt, serverDNSSECEnabled, tracker)
	} else {
		if tracker != nil {
			tracker.AddStep("Using recursive resolution")
		}
		ctx, cancel := context.WithTimeout(s.ctx, RecursiveTimeout)
		defer cancel()
		answer, authority, additional, validated, ecsResponse, err = s.ResolveWithCNAME(ctx, question, ecsOpt, tracker)
	}

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
		if entry, found, _ := s.cache.Get(cacheKey); found {
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

			msg.Answer = globalRecordHandler.ProcessRecords(globalRecordHandler.ExpandRecords(entry.Answer), responseTTL, clientRequestedDNSSEC)
			msg.Ns = globalRecordHandler.ProcessRecords(globalRecordHandler.ExpandRecords(entry.Authority), responseTTL, clientRequestedDNSSEC)
			msg.Extra = globalRecordHandler.ProcessRecords(globalRecordHandler.ExpandRecords(entry.Additional), responseTTL, clientRequestedDNSSEC)

			if s.config.Server.Features.DNSSEC && entry.Validated {
				msg.AuthenticatedData = true
			}

			responseECS := entry.GetECSOption()
			if responseECS == nil {
				responseECS = ecsOpt
			}

			shouldAddEDNS := clientHasEDNS || responseECS != nil || s.ednsManager.IsPaddingEnabled() ||
				(clientRequestedDNSSEC && s.config.Server.Features.DNSSEC)

			if shouldAddEDNS {
				s.ednsManager.AddToMessage(msg, responseECS, clientRequestedDNSSEC && s.config.Server.Features.DNSSEC, isSecureConnection)
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
			tracker.AddStep("DNSSEC validation passed")
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

	s.cache.Set(cacheKey, answer, authority, additional, validated, responseECS)

	msg.Answer = globalRecordHandler.ProcessRecords(answer, 0, clientRequestedDNSSEC)
	msg.Ns = globalRecordHandler.ProcessRecords(authority, 0, clientRequestedDNSSEC)
	msg.Extra = globalRecordHandler.ProcessRecords(additional, 0, clientRequestedDNSSEC)

	if len(s.config.SpeedTest) > 0 {
		Debug("SpeedTest feature enabled")
		if tracker != nil {
			tracker.AddStep("SpeedTest enabled")
		}

		shouldPerformSpeedTest := s.ShouldPerformSpeedTest(question.Name)
		if shouldPerformSpeedTest {
			Debug("SpeedTest: triggering background detection for domain %s", question.Name)
			msgCopy := msg.Copy()
			s.taskManager.ExecuteAsync(fmt.Sprintf("speed-test-%s", question.Name), func(ctx context.Context) error {
				Debug("SpeedTest: starting background detection for domain %s", question.Name)
				speedTester := NewSpeedTester(*s.config)
				defer func() {
					_ = speedTester.Close()
				}()
				speedTester.PerformSpeedTestAndSort(msgCopy)

				s.cache.Set(cacheKey,
					msgCopy.Answer,
					msgCopy.Ns,
					msgCopy.Extra,
					validated, responseECS)
				Debug("SpeedTest: background detection completed for domain %s", question.Name)

				return nil
			})

			if tracker != nil {
				tracker.AddStep("First response not sorted, background SpeedTest in progress")
			}
		} else {
			Debug("SpeedTest: domain %s skipped by debounce mechanism", question.Name)
			if tracker != nil {
				tracker.AddStep("SpeedTest skipped (debounce mechanism)")
			}
		}
	} else {
		Debug("SpeedTest feature not enabled")
	}

	shouldAddEDNS := clientHasEDNS || responseECS != nil || s.ednsManager.IsPaddingEnabled() ||
		(clientRequestedDNSSEC && s.config.Server.Features.DNSSEC)

	if shouldAddEDNS {
		s.ednsManager.AddToMessage(msg, responseECS, clientRequestedDNSSEC && s.config.Server.Features.DNSSEC, isSecureConnection)
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

func (s *DNSServer) QueryUpstreamServers(question dns.Question, ecs *ECSOption,
	serverDNSSECEnabled bool, tracker *RequestTracker) ([]dns.RR, []dns.RR, []dns.RR, bool, *ECSOption, error) {

	servers := s.upstreamManager.GetServers()
	if len(servers) == 0 {
		return nil, nil, nil, false, nil, errors.New("no available upstream servers")
	}

	if tracker != nil {
		tracker.AddStep("Starting concurrent query of %d servers", len(servers))
	}

	resultChan := make(chan *QueryResult, len(servers))
	ctx, cancel := context.WithTimeout(s.ctx, QueryTimeout)
	defer cancel()

	for _, server := range servers {
		srv := server

		if srv.IsRecursive() {
			s.taskManager.ExecuteAsync("Query-Recursive", func(taskCtx context.Context) error {
				recursiveCtx, recursiveCancel := context.WithTimeout(taskCtx, RecursiveTimeout)
				defer recursiveCancel()

				answer, authority, additional, validated, ecsResponse, err := s.ResolveWithCNAME(
					recursiveCtx, question, ecs, tracker)

				if err == nil && len(answer) > 0 {
					// 应用 policy 过滤
					filteredAnswer := s.FilterRecordsByPolicy(answer, FilterContext{
						Policy:       srv.Policy,
						IsGlueRecord: false,
					})
					filteredAdditional := s.FilterRecordsByPolicy(additional, FilterContext{
						Policy:       srv.Policy,
						IsGlueRecord: false,
					})

					// 检查是否有有效记录
					if len(filteredAnswer) > 0 {
						if tracker != nil && srv.Policy != "all" {
							tracker.AddStep("Recursive query after policy filter: %d answer records", len(filteredAnswer))
						}
						select {
						case resultChan <- &QueryResult{
							Answer:     filteredAnswer,
							Authority:  authority,
							Additional: filteredAdditional,
							Validated:  validated,
							ECS:        ecsResponse,
							Server:     srv.Address,
						}:
						case <-ctx.Done():
						}
					} else {
						// 所有记录被过滤
						if tracker != nil {
							tracker.AddStep("Recursive query: all records filtered by policy '%s'", srv.Policy)
						}
					}
				}
				return nil
			})

		} else {
			originalMsg := s.BuildQueryMessage(question, ecs, serverDNSSECEnabled, true, false)
			msg := SafeCopyMessage(originalMsg)
			globalResourceManager.PutDNSMessage(originalMsg)

			s.taskManager.ExecuteAsync(fmt.Sprintf("Query-%s", srv.Address), func(taskCtx context.Context) error {
				result := s.queryClient.ExecuteQuery(taskCtx, msg, srv, tracker)

				if result.Error == nil && result.Response != nil {
					rcode := result.Response.Rcode
					if rcode == dns.RcodeSuccess || rcode == dns.RcodeNameError {
						// DNSSEC 验证
						if serverDNSSECEnabled && s.config.Server.Features.DNSSEC {
							result.Validated = s.dnssecValidator.ValidateResponse(result.Response, true)
						}

						// 应用 policy 过滤
						filteredAnswer := s.FilterRecordsByPolicy(result.Response.Answer, FilterContext{
							Policy:       srv.Policy,
							IsGlueRecord: false,
						})
						filteredExtra := s.FilterRecordsByPolicy(result.Response.Extra, FilterContext{
							Policy:       srv.Policy,
							IsGlueRecord: false,
						})

						// 检查是否有有效记录
						if len(filteredAnswer) > 0 {
							ecsResponse := s.ednsManager.ParseFromDNS(result.Response)

							if tracker != nil && srv.Policy != "all" {
								tracker.AddStep("Server %s after policy filter: %d answer records", srv.Address, len(filteredAnswer))
							}

							select {
							case resultChan <- &QueryResult{
								Answer:     filteredAnswer,
								Authority:  result.Response.Ns,
								Additional: filteredExtra,
								Validated:  result.Validated,
								ECS:        ecsResponse,
								Server:     srv.Address,
							}:
							case <-ctx.Done():
							}
						} else {
							// 所有记录被过滤
							if tracker != nil {
								tracker.AddStep("Server %s: all records filtered by policy '%s'", srv.Address, srv.Policy)
							}
						}
					}
				}
				return nil
			})
		}
	}

	// 等待第一个成功的结果
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
					tracker.AddStep("Server %s returned error: %v", result.Server, result.Error)
				}
				continue
			}

			// 检查是否有有效的 Answer
			if len(result.Answer) > 0 {
				if tracker != nil {
					tracker.AddStep("Using successful result from: %s", result.Server)
				}
				return result.Answer, result.Authority, result.Additional, result.Validated, result.ECS, nil
			}

			// 没有有效记录，继续等待其他结果
			continue

		case <-ctx.Done():
			if tracker != nil {
				tracker.AddStep("Query context cancelled after receiving %d/%d responses", receivedCount, serversCount)
			}
			if lastError != nil {
				return nil, nil, nil, false, nil, lastError
			}
			return nil, nil, nil, false, nil, errors.New("all upstream queries failed or timed out")
		}
	}

	// 所有服务器都返回了结果但都没有有效记录
	if tracker != nil {
		tracker.AddStep("All %d upstream servers returned no valid records", serversCount)
	}
	if lastError != nil {
		return nil, nil, nil, false, nil, lastError
	}
	return nil, nil, nil, false, nil, errors.New("all upstream queries returned no valid records")
}

func (s *DNSServer) BuildQueryMessage(question dns.Question, ecs *ECSOption, dnssecEnabled bool, recursionDesired bool, isSecureConnection bool) *dns.Msg {
	msg := globalResourceManager.GetDNSMessage()

	if msg == nil {
		msg = &dns.Msg{}
	}

	if err := s.SafeSetQuestion(msg, question.Name, question.Qtype); err != nil {
		Debug("Setting DNS question failed: %v", err)
		msg = &dns.Msg{}
		msg.SetQuestion(dns.Fqdn(question.Name), question.Qtype)
	}

	msg.RecursionDesired = recursionDesired

	if s.ednsManager != nil {
		s.ednsManager.AddToMessage(msg, ecs, dnssecEnabled, isSecureConnection)
	}

	return msg
}

func (s *DNSServer) SafeSetQuestion(msg *dns.Msg, name string, qtype uint16) error {
	if msg == nil {
		return errors.New("message is empty")
	}

	if name == "" {
		return errors.New("domain is empty")
	}

	if len(name) > MaxDomainLength {
		return errors.New("domain is too long")
	}

	if msg.Question == nil {
		msg.Question = make([]dns.Question, 0, 1)
	}

	defer func() {
		if r := recover(); r != nil {
			Error("Panic occurred while setting DNS question: %v", r)
		}
	}()

	msg.SetQuestion(dns.Fqdn(name), qtype)
	return nil
}

func (s *DNSServer) ResolveWithCNAME(ctx context.Context, question dns.Question, ecs *ECSOption,
	tracker *RequestTracker) ([]dns.RR, []dns.RR, []dns.RR, bool, *ECSOption, error) {

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
			tracker.AddStep("Resolving CNAME chain step %d: %s", i+1, currentQuestion.Name)
		}

		answer, authority, additional, validated, ecsResponse, err := s.RecursiveQuery(ctx, currentQuestion, ecs, 0, false, tracker)
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

func (s *DNSServer) RecursiveQuery(ctx context.Context, question dns.Question, ecs *ECSOption,
	depth int, forceTCP bool, tracker *RequestTracker) ([]dns.RR, []dns.RR, []dns.RR, bool, *ECSOption, error) {

	if depth > MaxRecursionDepth {
		return nil, nil, nil, false, nil, fmt.Errorf("recursion depth exceeded: %d", depth)
	}

	qname := dns.Fqdn(question.Name)
	question.Name = qname
	nameservers := s.GetRootServers()
	currentDomain := "."

	normalizedQname := strings.ToLower(strings.TrimSuffix(qname, "."))

	if tracker != nil {
		tracker.AddStep("Starting recursive query: %s, depth=%d, TCP=%v", normalizedQname, depth, forceTCP)
	}

	if normalizedQname == "" {
		response, err := s.QueryNameserversConcurrent(ctx, nameservers, question, ecs, forceTCP, tracker)
		if err != nil {
			return nil, nil, nil, false, nil, fmt.Errorf("root domain query failed: %w", err)
		}

		if s.hijackPrevention.IsEnabled() {
			if valid, reason := s.hijackPrevention.CheckResponse(currentDomain, normalizedQname, response); !valid {
				return s.HandleSuspiciousResponse(reason, forceTCP, tracker)
			}
		}

		validated := false
		if s.config.Server.Features.DNSSEC {
			validated = s.dnssecValidator.ValidateResponse(response, true)
		}

		ecsResponse := s.ednsManager.ParseFromDNS(response)

		answer := response.Answer
		authority := response.Ns
		additional := response.Extra

		return answer, authority, additional, validated, ecsResponse, nil
	}

	for {
		select {
		case <-ctx.Done():
			return nil, nil, nil, false, nil, ctx.Err()
		default:
		}

		if tracker != nil {
			tracker.AddStep("Querying authoritative server: %s (%d NS)", currentDomain, len(nameservers))
		}

		response, err := s.QueryNameserversConcurrent(ctx, nameservers, question, ecs, forceTCP, tracker)
		if err != nil {
			if !forceTCP && strings.HasPrefix(err.Error(), "DNS_HIJACK_DETECTED") {
				if tracker != nil {
					tracker.AddStep("DNS hijacking detected, switching to TCP mode retry")
				}
				return s.RecursiveQuery(ctx, question, ecs, depth, true, tracker)
			}
			return nil, nil, nil, false, nil, fmt.Errorf("query %s failed: %w", currentDomain, err)
		}

		if s.hijackPrevention.IsEnabled() {
			if valid, reason := s.hijackPrevention.CheckResponse(currentDomain, normalizedQname, response); !valid {
				answer, authority, additional, validated, ecsResponse, err := s.HandleSuspiciousResponse(reason, forceTCP, tracker)
				if err != nil && !forceTCP && strings.HasPrefix(err.Error(), "DNS_HIJACK_DETECTED") {
					if tracker != nil {
						tracker.AddStep("DNS hijacking detected, switching to TCP mode retry")
					}
					return s.RecursiveQuery(ctx, question, ecs, depth, true, tracker)
				}
				return answer, authority, additional, validated, ecsResponse, err
			}
		}

		validated := false
		if s.config.Server.Features.DNSSEC {
			validated = s.dnssecValidator.ValidateResponse(response, true)
		}

		ecsResponse := s.ednsManager.ParseFromDNS(response)

		if len(response.Answer) > 0 {
			if tracker != nil {
				tracker.AddStep("Obtained final answer: %d records", len(response.Answer))
			}

			answer := response.Answer
			authority := response.Ns
			additional := response.Extra

			return answer, authority, additional, validated, ecsResponse, nil
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
				tracker.AddStep("No matching NS records found, returning authority info")
			}
			return nil, response.Ns, response.Extra, validated, ecsResponse, nil
		}

		currentDomainNormalized := strings.ToLower(strings.TrimSuffix(currentDomain, "."))
		if bestMatch == currentDomainNormalized && currentDomainNormalized != "" {
			if tracker != nil {
				tracker.AddStep("Query loop detected, stopping recursion")
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
						nextNS = append(nextNS, net.JoinHostPort(a.A.String(), DefaultDNSPort))
					}
				case *dns.AAAA:
					if s.config.Server.Features.IPv6 && strings.EqualFold(a.Header().Name, ns.Ns) {
						nextNS = append(nextNS, net.JoinHostPort(a.AAAA.String(), DefaultDNSPort))
					}
				}
			}
		}

		if len(nextNS) == 0 {
			if tracker != nil {
				tracker.AddStep("No NS addresses in Additional, starting NS record resolution")
			}
			nextNS = s.ResolveNSAddressesConcurrent(ctx, bestNSRecords, qname, depth, forceTCP, tracker)
		}

		if len(nextNS) == 0 {
			if tracker != nil {
				tracker.AddStep("Cannot obtain NS addresses, returning authority info")
			}
			return nil, response.Ns, response.Extra, validated, ecsResponse, nil
		}

		nameservers = nextNS
		if tracker != nil {
			tracker.AddStep("Next round query, switching to domain: %s (%d NS)", bestMatch, len(nextNS))
		}
	}
}

func (s *DNSServer) FilterRecordsByPolicy(records []dns.RR, ctx FilterContext) []dns.RR {
	if ctx.IsGlueRecord || ctx.Policy == "all" || !s.ipFilter.HasData() {
		return records
	}

	filtered := make([]dns.RR, 0, len(records))

	for _, rr := range records {
		var ip net.IP

		switch record := rr.(type) {
		case *dns.A:
			ip = record.A
		case *dns.AAAA:
			ip = record.AAAA
		default:
			// 非 IP 记录直接保留
			filtered = append(filtered, rr)
			continue
		}

		// IP 记录根据策略过滤
		isTrusted := s.ipFilter.IsTrustedIP(ip)
		shouldKeep := (ctx.Policy == "trusted_only" && isTrusted) ||
			(ctx.Policy == "untrusted_only" && !isTrusted)

		if shouldKeep {
			filtered = append(filtered, rr)
			Debug("Policy filter: keeping %s IP %s", ctx.Policy, ip)
		} else {
			Debug("Policy filter: filtering out %s IP %s", ctx.Policy, ip)
		}
	}

	return filtered
}

func (s *DNSServer) HandleSuspiciousResponse(reason string, currentlyTCP bool, tracker *RequestTracker) ([]dns.RR, []dns.RR, []dns.RR, bool, *ECSOption, error) {
	if !currentlyTCP {
		if tracker != nil {
			tracker.AddStep("DNS hijacking detected, will switch to TCP mode: %s", reason)
		}
		return nil, nil, nil, false, nil, fmt.Errorf("DNS_HIJACK_DETECTED: %s", reason)
	} else {
		if tracker != nil {
			tracker.AddStep("DNS hijacking still detected in TCP mode, rejecting response: %s", reason)
		}
		return nil, nil, nil, false, nil, fmt.Errorf("DNS hijacking detected (TCP mode): %s", reason)
	}
}

func (s *DNSServer) QueryNameserversConcurrent(ctx context.Context, nameservers []string,
	question dns.Question, ecs *ECSOption, forceTCP bool, tracker *RequestTracker) (*dns.Msg, error) {

	if len(nameservers) == 0 {
		return nil, errors.New("no available nameservers")
	}

	select {
	case s.concurrencyLimit <- struct{}{}:
		defer func() { <-s.concurrencyLimit }()
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
			Policy:   "all",
		}
	}

	resultChan := make(chan *QueryResult, concurrency)

	for _, server := range tempServers {
		srv := server
		originalMsg := s.BuildQueryMessage(question, ecs, s.config.Server.Features.DNSSEC, true, false)
		msg := SafeCopyMessage(originalMsg)
		globalResourceManager.PutDNSMessage(originalMsg)

		s.taskManager.ExecuteAsync(fmt.Sprintf("Query-%s", srv.Address),
			func(ctx context.Context) error {
				result := s.queryClient.ExecuteQuery(ctx, msg, srv, tracker)

				if result.Error == nil && result.Response != nil {
					rcode := result.Response.Rcode
					if rcode == dns.RcodeSuccess || rcode == dns.RcodeNameError {
						if s.config.Server.Features.DNSSEC {
							result.Validated = s.dnssecValidator.ValidateResponse(result.Response, true)
							if tracker != nil && result.Validated {
								tracker.AddStep("DNSSEC validation passed")
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
			tracker.AddStep("Query successful, selected server: %s", result.Server)
		}
		return result.Response, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (s *DNSServer) ResolveNSAddressesConcurrent(ctx context.Context, nsRecords []*dns.NS,
	qname string, depth int, forceTCP bool, tracker *RequestTracker) []string {

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
		s.taskManager.ExecuteAsync(fmt.Sprintf("NSResolve-%s", ns.Ns),
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
				if nsAnswer, _, _, _, _, err := s.RecursiveQuery(resolveCtx, nsQuestion, nil, depth+1, forceTCP, tracker); err == nil {
					for _, rr := range nsAnswer {
						if a, ok := rr.(*dns.A); ok {
							addresses = append(addresses, net.JoinHostPort(a.A.String(), DefaultDNSPort))
						}
					}
				}

				if s.config.Server.Features.IPv6 && len(addresses) == 0 {
					nsQuestionV6 := dns.Question{Name: dns.Fqdn(ns.Ns), Qtype: dns.TypeAAAA, Qclass: dns.ClassINET}
					if nsAnswerV6, _, _, _, _, err := s.RecursiveQuery(resolveCtx, nsQuestionV6, nil, depth+1, forceTCP, tracker); err == nil {
						for _, rr := range nsAnswerV6 {
							if aaaa, ok := rr.(*dns.AAAA); ok {
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
		tracker.AddStep("NS resolution completed: obtained %d addresses", len(allAddresses))
	}

	return allAddresses
}

func (s *DNSServer) GetRootServers() []string {
	return s.rootServerManager.GetOptimalRootServers(s.config.Server.Features.IPv6)
}

func (s *DNSServer) QueryForRefresh(question dns.Question, ecs *ECSOption, serverDNSSECEnabled bool) ([]dns.RR, []dns.RR, []dns.RR, bool, *ECSOption, error) {
	defer func() { RecoverPanic("Cache refresh query") }()

	if atomic.LoadInt32(&s.closed) != 0 {
		return nil, nil, nil, false, nil, errors.New("server is closed")
	}

	refreshCtx, cancel := context.WithTimeout(s.ctx, ExtendedTimeout)
	defer cancel()

	servers := s.upstreamManager.GetServers()
	if len(servers) > 0 {
		return s.QueryUpstreamServers(question, ecs, serverDNSSECEnabled, nil)
	} else {
		return s.ResolveWithCNAME(refreshCtx, question, ecs, nil)
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
			return nil, fmt.Errorf("ECS configuration parsing failed: %w", err)
		}
		manager.defaultECS = ecs
		if ecs != nil {
			Info("Default ECS config: %s/%d", ecs.Address, ecs.SourcePrefix)
		}
	}

	if paddingEnabled {
		Info("DNS Padding enabled (block size: %d bytes)", PaddingBlockSize)
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
		Debug("Adding ECS option: %s/%d", ecs.Address, ecs.SourcePrefix)
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
					Debug("DNS Padding: %d -> %d bytes (+%d)", currentSize, PaddingBlockSize, paddingDataSize)
				}
			}
		} else {
			Debug("Failed to calculate padding: %v", err)
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
			return nil, fmt.Errorf("CIDR parsing failed: %w", err)
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
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			Debug("Closing response body failed: %v", closeErr)
		}
	}()

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
// DNS Rewriting
// =============================================================================

func NewDNSRewriter() *DNSRewriter {
	return &DNSRewriter{
		rules: make([]RewriteRule, 0, 32),
	}
}

func (r *DNSRewriter) LoadRules(rules []RewriteRule) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	validRules := make([]RewriteRule, 0, len(rules))
	for _, rule := range rules {
		if len(rule.Name) > MaxDomainLength {
			continue
		}

		validRules = append(validRules, rule)
	}

	r.rules = validRules
	Info("DNS rewriter loaded: %d rules", len(validRules))
	return nil
}

func (r *DNSRewriter) RewriteWithDetails(domain string, qtype uint16) DNSRewriteResult {
	result := DNSRewriteResult{
		Domain:        domain,
		ShouldRewrite: false,
		ResponseCode:  dns.RcodeSuccess,
		Records:       nil,
		Additional:    nil,
	}

	if !r.HasRules() || len(domain) > MaxDomainLength {
		return result
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	domain = strings.ToLower(strings.TrimSuffix(domain, "."))

	for i := range r.rules {
		rule := &r.rules[i]

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

					rr := r.BuildDNSRecord(domain, record)
					if rr != nil {
						result.Records = append(result.Records, rr)
					}
				}

				for _, record := range rule.Additional {
					rr := r.BuildDNSRecord(domain, record)
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

func (r *DNSRewriter) BuildDNSRecord(domain string, record DNSRecordConfig) dns.RR {
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

func (r *DNSRewriter) HasRules() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.rules) > 0
}

// =============================================================================
// IP Filtering
// =============================================================================

func NewIPFilter() *IPFilter {
	return &IPFilter{
		trustedCIDRs:   make([]*net.IPNet, 0, MaxTrustedIPv4),
		trustedCIDRsV6: make([]*net.IPNet, 0, MaxTrustedIPv6),
	}
}

func (f *IPFilter) LoadCIDRs(filename string) error {
	if filename == "" {
		Info("IP filter config file path not set")
		return nil
	}

	if !IsValidFilePath(filename) {
		return fmt.Errorf("invalid file path: %s", filename)
	}

	file, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("failed to open CIDR file: %w", err)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			Warn("Failed to close CIDR file: %v", closeErr)
		}
	}()

	f.mu.Lock()
	defer f.mu.Unlock()

	f.trustedCIDRs = make([]*net.IPNet, 0, MaxTrustedIPv4)
	f.trustedCIDRsV6 = make([]*net.IPNet, 0, MaxTrustedIPv6)

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

	f.OptimizeCIDRs()
	Info("IP filter loaded: IPv4=%d rules, IPv6=%d rules", totalV4, totalV6)
	return scanner.Err()
}

func (f *IPFilter) OptimizeCIDRs() {
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

func (f *IPFilter) HasData() bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return len(f.trustedCIDRs) > 0 || len(f.trustedCIDRsV6) > 0
}

// =============================================================================
// Hijack Prevention
// =============================================================================

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
				reason := fmt.Sprintf("Root server overstepped authority and returned %s record for '%s'", recordType, queryDomain)
				return false, reason
			}
		}
	}
	return true, ""
}

// =============================================================================
// DNSSEC Validation
// =============================================================================

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

// =============================================================================
// Record Handling
// =============================================================================

func NewRecordHandler() *RecordHandler {
	return &RecordHandler{}
}

func (rh *RecordHandler) CompactRecord(rr dns.RR) *CompactRecord {
	if rh == nil || rr == nil {
		return nil
	}
	return &CompactRecord{
		Text:    rr.String(),
		OrigTTL: rr.Header().Ttl,
		Type:    rr.Header().Rrtype,
	}
}

func (rh *RecordHandler) ExpandRecord(cr *CompactRecord) dns.RR {
	if rh == nil || cr == nil || cr.Text == "" {
		return nil
	}
	rr, err := dns.NewRR(cr.Text)
	if err != nil {
		return nil
	}
	return rr
}

func (rh *RecordHandler) CompactRecords(rrs []dns.RR) []*CompactRecord {
	if rh == nil || len(rrs) == 0 {
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
			if cr := rh.CompactRecord(rr); cr != nil {
				result = append(result, cr)
			}
		}
	}
	return result
}

func (rh *RecordHandler) ExpandRecords(crs []*CompactRecord) []dns.RR {
	if rh == nil || len(crs) == 0 {
		return nil
	}
	result := make([]dns.RR, 0, len(crs))
	for _, cr := range crs {
		if rr := rh.ExpandRecord(cr); rr != nil {
			result = append(result, rr)
		}
	}
	return result
}

func (rh *RecordHandler) ProcessRecords(rrs []dns.RR, ttl uint32, includeDNSSEC bool) []dns.RR {
	if rh == nil || len(rrs) == 0 {
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

// =============================================================================
// Cache Utilities
// =============================================================================

func NewCacheUtils() *CacheUtils {
	return &CacheUtils{}
}

func (cu *CacheUtils) BuildKey(question dns.Question, ecs *ECSOption, dnssecEnabled bool) string {
	if cu == nil {
		return ""
	}

	sb := globalResourceManager.GetStringBuilder()
	defer globalResourceManager.PutStringBuilder(sb)

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

func (cu *CacheUtils) CalculateTTL(rrs []dns.RR) int {
	if cu == nil || len(rrs) == 0 {
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
// Security & TLS Management
// =============================================================================

func NewTLSManager(server *DNSServer, config *ServerConfig) (*TLSManager, error) {
	cert, err := tls.LoadX509KeyPair(config.Server.TLS.CertFile, config.Server.TLS.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("certificate loading failed: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}

	ctx, cancel := context.WithCancel(context.Background())

	quicAddrValidator, err := NewQUICAddrValidator(QUICAddrValidatorCacheSize, QUICAddrValidatorTTL)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create QUIC address validator: %w", err)
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
		defer func() { RecoverPanic("Critical-DoT server") }()
		if err := tm.StartTLSServer(); err != nil {
			errChan <- fmt.Errorf("DoT startup failed: %w", err)
		}
	}()

	go func() {
		defer wg.Done()
		defer func() { RecoverPanic("Critical-DoQ server") }()
		if err := tm.StartQUICServer(); err != nil {
			errChan <- fmt.Errorf("DoQ startup failed: %w", err)
		}
	}()

	if httpsPort != "" {
		go func() {
			defer wg.Done()
			defer func() { RecoverPanic("Critical-DoH server") }()
			if err := tm.StartDoHServer(httpsPort); err != nil {
				errChan <- fmt.Errorf("DoH startup failed: %w", err)
			}
		}()

		go func() {
			defer wg.Done()
			defer func() { RecoverPanic("Critical-DoH3 server") }()
			if err := tm.StartDoH3Server(httpsPort); err != nil {
				errChan <- fmt.Errorf("DoH3 startup failed: %w", err)
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
		return fmt.Errorf("DoT listening failed: %w", err)
	}

	tm.tlsListener = tls.NewListener(listener, tm.tlsConfig)
	Info("DoT server started: %s", tm.tlsListener.Addr())

	tm.wg.Add(1)
	go func() {
		defer tm.wg.Done()
		defer func() { RecoverPanic("DoT server") }()
		tm.HandleTLSConnections()
	}()

	return nil
}

func (tm *TLSManager) StartQUICServer() error {
	addr := ":" + tm.server.config.Server.TLS.Port

	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return fmt.Errorf("UDP address parsing failed: %w", err)
	}

	tm.quicConn, err = net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("UDP listening failed: %w", err)
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
		KeepAlivePeriod:       SecureKeepAlive,
		Allow0RTT:             true,
	}

	tm.quicListener, err = tm.quicTransport.ListenEarly(quicTLSConfig, quicConfig)
	if err != nil {
		if closeErr := tm.quicConn.Close(); closeErr != nil {
			Debug("Closing QUIC connection failed: %v", closeErr)
		}
		return fmt.Errorf("DoQ listening failed: %w", err)
	}

	Info("DoQ server started: %s", tm.quicListener.Addr())

	tm.wg.Add(1)
	go func() {
		defer tm.wg.Done()
		defer func() { RecoverPanic("DoQ server") }()
		tm.HandleQUICConnections()
	}()

	return nil
}

func (tm *TLSManager) StartDoHServer(port string) error {
	listener, err := net.Listen("tcp", ":"+port)
	if err != nil {
		return fmt.Errorf("DoH listening failed: %w", err)
	}

	tlsConfig := tm.tlsConfig.Clone()
	tlsConfig.NextProtos = []string{http2.NextProtoTLS, "http/1.1"}

	tm.httpsListener = tls.NewListener(listener, tlsConfig)
	Info("DoH server started: %s", tm.httpsListener.Addr())

	tm.httpsServer = &http.Server{
		Handler:           tm,
		ReadHeaderTimeout: DoHReadHeaderTimeout,
		WriteTimeout:      DoHWriteTimeout,
	}

	tm.wg.Add(1)
	go func() {
		defer tm.wg.Done()
		defer func() { RecoverPanic("DoH server") }()
		if err := tm.httpsServer.Serve(tm.httpsListener); err != nil && err != http.ErrServerClosed {
			Error("DoH server error: %v", err)
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
		return fmt.Errorf("DoH3 listening failed: %w", err)
	}

	tm.h3Listener = quicListener
	Info("DoH3 server started: %s", tm.h3Listener.Addr())

	tm.h3Server = &http3.Server{
		Handler: tm,
	}

	tm.wg.Add(1)
	go func() {
		defer tm.wg.Done()
		defer func() { RecoverPanic("DoH3 server") }()
		if err := tm.h3Server.ServeListener(tm.h3Listener); err != nil && err != http.ErrServerClosed {
			Error("DoH3 server error: %v", err)
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

	if globalLogger.GetLevel() >= LogDebug {
		Debug("Received DoH request: %s %s", r.Method, r.URL.Path)
	}

	req, statusCode := tm.ParseDoHRequest(r)
	if req == nil {
		http.Error(w, http.StatusText(statusCode), statusCode)
		return
	}

	response := tm.server.ProcessDNSQuery(req, nil, true)
	if err := tm.RespondDoH(w, response); err != nil {
		Error("DoH response sending failed: %v", err)
	}
}

func (tm *TLSManager) ParseDoHRequest(r *http.Request) (*dns.Msg, int) {
	var buf []byte
	var err error

	switch r.Method {
	case http.MethodGet:
		dnsParam := r.URL.Query().Get("dns")
		if dnsParam == "" {
			Debug("DoH GET request missing dns parameter")
			return nil, http.StatusBadRequest
		}
		buf, err = base64.RawURLEncoding.DecodeString(dnsParam)
		if err != nil {
			Debug("DoH GET request dns parameter decoding failed: %v", err)
			return nil, http.StatusBadRequest
		}

	case http.MethodPost:
		contentType := r.Header.Get("Content-Type")
		if contentType != "application/dns-message" {
			Debug("DoH POST request Content-Type not supported: %s", contentType)
			return nil, http.StatusUnsupportedMediaType
		}

		r.Body = http.MaxBytesReader(nil, r.Body, DoHMaxRequestSize)
		buf, err = io.ReadAll(r.Body)
		if err != nil {
			Debug("DoH POST request body reading failed: %v", err)
			return nil, http.StatusBadRequest
		}
		defer func() {
			if closeErr := r.Body.Close(); closeErr != nil {
				Debug("Closing request body failed: %v", closeErr)
			}
		}()

	default:
		Debug("DoH request method not supported: %s", r.Method)
		return nil, http.StatusMethodNotAllowed
	}

	if len(buf) == 0 {
		Debug("DoH request data is empty")
		return nil, http.StatusBadRequest
	}

	req := new(dns.Msg)
	if err := req.Unpack(buf); err != nil {
		Debug("DoH DNS message parsing failed: %v", err)
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
		return fmt.Errorf("response packing failed: %w", err)
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
			Error("DoT connection accept failed: %v", err)
			continue
		}

		tm.wg.Add(1)
		go func() {
			defer tm.wg.Done()
			defer func() { RecoverPanic("DoT connection handling") }()
			defer func() {
				if closeErr := conn.Close(); closeErr != nil {
					Debug("Closing DoT connection failed: %v", closeErr)
				}
			}()
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
			tm.LogQUICError("accepting quic conn", err)
			continue
		}

		tm.wg.Add(1)
		go func() {
			defer tm.wg.Done()
			defer func() { RecoverPanic("DoQ connection handling") }()
			tm.HandleQUICConnection(conn)
		}()
	}
}

func (tm *TLSManager) HandleQUICConnection(conn *quic.Conn) {
	defer func() {
		if conn != nil {
			if closeErr := conn.CloseWithError(QUICCodeNoError, ""); closeErr != nil {
				Debug("Closing QUIC connection failed: %v", closeErr)
			}
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
				tm.LogQUICError("accepting quic stream", err)
			}
			return
		}

		if stream == nil {
			continue
		}

		tm.wg.Add(1)
		go func(s *quic.Stream) {
			defer tm.wg.Done()
			defer func() { RecoverPanic("DoQ stream handling") }()
			if s != nil {
				defer func() {
					if closeErr := s.Close(); closeErr != nil {
						Debug("Closing QUIC stream failed: %v", closeErr)
					}
				}()
				tm.HandleQUICStream(s, conn)
			}
		}(stream)
	}
}

func (tm *TLSManager) HandleQUICStream(stream *quic.Stream, conn *quic.Conn) {
	buf := make([]byte, SecureBufferSize)
	n, err := tm.ReadAll(stream, buf)

	if err != nil && err != io.EOF {
		Debug("DoQ stream reading failed: %v", err)
		return
	}

	if n < MinDNSPacketSize {
		Debug("DoQ message too short: %d bytes", n)
		return
	}

	req := new(dns.Msg)
	var msgData []byte

	packetLen := binary.BigEndian.Uint16(buf[:2])
	if packetLen == uint16(n-2) {
		msgData = buf[2:n]
	} else {
		Debug("DoQ unsupported message format")
		if closeErr := conn.CloseWithError(QUICCodeProtocolError, ""); closeErr != nil {
			Debug("Closing QUIC connection failed: %v", closeErr)
		}
		return
	}

	if err := req.Unpack(msgData); err != nil {
		Debug("DoQ message parsing failed: %v", err)
		if closeErr := conn.CloseWithError(QUICCodeProtocolError, ""); closeErr != nil {
			Debug("Closing QUIC connection failed: %v", closeErr)
		}
		return
	}

	if !tm.ValidQUICMsg(req) {
		if closeErr := conn.CloseWithError(QUICCodeProtocolError, ""); closeErr != nil {
			Debug("Closing QUIC connection failed: %v", closeErr)
		}
		return
	}

	clientIP := tm.GetSecureClientIP(conn)
	response := tm.server.ProcessDNSQuery(req, clientIP, true)

	if err := tm.RespondQUIC(stream, response); err != nil {
		Debug("DoQ response sending failed: %v", err)
	}
}

func (tm *TLSManager) HandleSecureDNSConnection(conn net.Conn, protocol string) {
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return
	}

	if deadlineErr := tlsConn.SetReadDeadline(time.Now().Add(QueryTimeout)); deadlineErr != nil {
		Debug("Setting TLS read deadline failed: %v", deadlineErr)
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
				Debug("%s length reading failed: %v", protocol, err)
			}
			return
		}

		msgLength := binary.BigEndian.Uint16(lengthBuf)
		if msgLength == 0 || msgLength > TCPBufferSize {
			Warn("%s message length abnormal: %d", protocol, msgLength)
			return
		}

		msgBuf := make([]byte, msgLength)
		if _, err := io.ReadFull(tlsConn, msgBuf); err != nil {
			Debug("%s message reading failed: %v", protocol, err)
			return
		}

		req := new(dns.Msg)
		if err := req.Unpack(msgBuf); err != nil {
			Debug("%s message parsing failed: %v", protocol, err)
			return
		}

		clientIP := tm.GetSecureClientIP(tlsConn)
		response := tm.server.ProcessDNSQuery(req, clientIP, true)

		respBuf, err := response.Pack()
		if err != nil {
			Error("%s response packing failed: %v", protocol, err)
			return
		}

		lengthPrefix := make([]byte, 2)
		binary.BigEndian.PutUint16(lengthPrefix, uint16(len(respBuf)))

		if _, err := tlsConn.Write(lengthPrefix); err != nil {
			Debug("%s response length writing failed: %v", protocol, err)
			return
		}

		if _, err := tlsConn.Write(respBuf); err != nil {
			Debug("%s response writing failed: %v", protocol, err)
			return
		}

		if deadlineErr := tlsConn.SetReadDeadline(time.Now().Add(QueryTimeout)); deadlineErr != nil {
			Debug("Updating TLS read deadline failed: %v", deadlineErr)
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
				Debug("DoQ client sent disallowed TCP keepalive option")
				return false
			}
		}
	}
	return true
}

func (tm *TLSManager) RespondQUIC(stream *quic.Stream, response *dns.Msg) error {
	if response == nil {
		return errors.New("response message is empty")
	}

	respBuf, err := response.Pack()
	if err != nil {
		return fmt.Errorf("response packing failed: %w", err)
	}

	buf := make([]byte, 2+len(respBuf))
	binary.BigEndian.PutUint16(buf[:2], uint16(len(respBuf)))
	copy(buf[2:], respBuf)

	n, err := stream.Write(buf)
	if err != nil {
		return fmt.Errorf("stream writing failed: %w", err)
	}

	if n != len(buf) {
		return fmt.Errorf("write length mismatch: %d != %d", n, len(buf))
	}

	return nil
}

func (tm *TLSManager) LogQUICError(prefix string, err error) {
	if tm.IsQUICErrorForDebugLog(err) {
		Debug("DoQ connection closed: %s - %v", prefix, err)
	} else {
		Error("DoQ error: %s - %v", prefix, err)
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
	Info("Shutting down secure DNS server...")

	tm.cancel()

	if tm.tlsListener != nil {
		if closeErr := tm.tlsListener.Close(); closeErr != nil {
			Debug("Closing TLS listener failed: %v", closeErr)
		}
	}
	if tm.quicListener != nil {
		if closeErr := tm.quicListener.Close(); closeErr != nil {
			Debug("Closing QUIC listener failed: %v", closeErr)
		}
	}
	if tm.quicConn != nil {
		if closeErr := tm.quicConn.Close(); closeErr != nil {
			Debug("Closing QUIC connection failed: %v", closeErr)
		}
	}
	if tm.quicAddrValidator != nil {
		tm.quicAddrValidator.Close()
		Debug("QUIC address validator closed")
	}

	if tm.httpsServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), ShutdownTimeout)
		defer cancel()
		if shutdownErr := tm.httpsServer.Shutdown(ctx); shutdownErr != nil {
			Debug("Closing HTTPS server failed: %v", shutdownErr)
		}
	}

	if tm.h3Server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), ShutdownTimeout)
		defer cancel()
		if shutdownErr := tm.h3Server.Shutdown(ctx); shutdownErr != nil {
			Debug("Closing HTTP/3 server failed: %v", shutdownErr)
		}
	}

	if tm.httpsListener != nil {
		if closeErr := tm.httpsListener.Close(); closeErr != nil {
			Debug("Closing HTTPS listener failed: %v", closeErr)
		}
	}

	if tm.h3Listener != nil {
		if closeErr := tm.h3Listener.Close(); closeErr != nil {
			Debug("Closing HTTP/3 listener failed: %v", closeErr)
		}
	}

	tm.wg.Wait()
	Info("Secure DNS server has been shut down")
	return nil
}

// =============================================================================
// QUIC Address Validator & Utilities
// =============================================================================

func NewQUICAddrValidator(cacheSize int, ttl time.Duration) (*QuicAddrValidator, error) {
	cache, err := ristretto.NewCache(&ristretto.Config[string, struct{}]{
		NumCounters: int64(cacheSize * 10),
		MaxCost:     int64(cacheSize),
		BufferItems: 64,
	})
	if err != nil {
		return nil, fmt.Errorf("creating ristretto cache: %w", err)
	}

	Debug("QUIC address validator initialized: cacheSize=%d, ttl=%v", cacheSize, ttl)

	return &QuicAddrValidator{
		cache: cache,
		ttl:   ttl,
	}, nil
}

func (v *QuicAddrValidator) RequiresValidation(addr net.Addr) bool {
	if v == nil || v.cache == nil {
		Debug("QUIC address validation: validator not initialized, requiring validation")
		return true
	}

	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		Debug("QUIC address validation: unexpected address type %T, requiring validation", addr)
		return true
	}

	key := udpAddr.IP.String()

	if _, found := v.cache.Get(key); found {
		Debug("QUIC address validation: %s found in cache, skipping validation", key)
		return false
	}

	v.cache.SetWithTTL(key, struct{}{}, 1, v.ttl)
	Debug("QUIC address validation: %s not in cache, requiring validation and caching for %v", key, v.ttl)

	return true
}

func (v *QuicAddrValidator) Close() {
	if v != nil && v.cache != nil {
		v.cache.Close()
		Debug("QUIC address validator cache closed and resources released")
	}
}

// =============================================================================
// Root Server Management
// =============================================================================

func NewRootServerManager(config ServerConfig) *RootServerManager {
	Debug("RootServer: Initializing manager with %d IPv4 and %d IPv6 root servers", 13, 13)

	// Create DNS-specific speed test configuration for root servers
	dnsSpeedTestConfig := config
	dnsSpeedTestConfig.SpeedTest = []SpeedTestMethod{
		{
			Type:    "udp",
			Port:    DefaultDNSPort,
			Timeout: int(DefaultSpeedTimeout.Milliseconds()),
		},
	}

	rsm := &RootServerManager{
		serversV4: []string{
			"198.41.0.4:53", "170.247.170.2:53", "192.33.4.12:53", "199.7.91.13:53",
			"192.203.230.10:53", "192.5.5.241:53", "192.112.36.4:53", "198.97.190.53:53",
			"192.36.148.17:53", "192.58.128.30:53", "193.0.14.129:53", "199.7.83.42:53", "202.12.27.33:53",
		},
		serversV6: []string{
			"[2001:503:ba3e::2:30]:53", "[2801:1b8:10::b]:53", "[2001:500:2::c]:53", "[2001:500:2d::d]:53",
			"[2001:500:a8::e]:53", "[2001:500:2f::f]:53", "[2001:500:12::d0d]:53", "[2001:500:1::53]:53",
			"[2001:7fe::53]:53", "[2001:503:c27::2:30]:53", "[2001:7fd::1]:53", "[2001:500:9f::42]:53", "[2001:dc3::35]:53",
		},
		speedTester: NewSpeedTester(dnsSpeedTestConfig),
	}

	Debug("RootServer: Manager created with servers - IPv4: %v, IPv6: %v",
		rsm.serversV4[:3], rsm.serversV6[:3])

	// Initialize with default order
	rsm.sortedV4 = make([]string, len(rsm.serversV4))
	rsm.sortedV6 = make([]string, len(rsm.serversV6))
	copy(rsm.sortedV4, rsm.serversV4)
	copy(rsm.sortedV6, rsm.serversV6)

	Debug("RootServer: Using default server order until speed test completes")

	// Start initial sorting in background
	go rsm.sortServersBySpeed()

	return rsm
}

func (rsm *RootServerManager) GetOptimalRootServers(ipv6Enabled bool) []string {
	rsm.mu.RLock()
	defer rsm.mu.RUnlock()

	Debug("RootServer: Requesting optimal servers - IPv6 enabled: %v", ipv6Enabled)

	if ipv6Enabled {
		// Return mixed optimal servers (IPv4 + IPv6)
		mixed := make([]string, 0, 8)
		v4Count := min(4, len(rsm.sortedV4))
		v6Count := min(4, len(rsm.sortedV6))

		mixed = append(mixed, rsm.sortedV4[:v4Count]...)
		mixed = append(mixed, rsm.sortedV6[:v6Count]...)

		Debug("RootServer: Selected %d mixed servers (IPv4: %d, IPv6: %d): %v",
			len(mixed), v4Count, v6Count, mixed)
		return mixed
	}

	// Return top IPv4 servers
	count := min(6, len(rsm.sortedV4))
	result := make([]string, count)
	copy(result, rsm.sortedV4[:count])

	Debug("RootServer: Selected %d IPv4 servers: %v", count, result)
	return result
}

func (rsm *RootServerManager) sortServersBySpeed() {
	defer func() { RecoverPanic("Root server speed sorting") }()

	Debug("RootServer: Starting speed-based server sorting")

	// Sort IPv4 servers using existing SpeedTest
	if len(rsm.serversV4) > 0 {
		Debug("RootServer: Testing %d IPv4 servers via UDP:%s", len(rsm.serversV4), DefaultDNSPort)
		ips := extractIPsFromServers(rsm.serversV4)
		results := rsm.speedTester.SpeedTest(ips)

		sorted := sortBySpeedResult(rsm.serversV4, results)

		rsm.mu.Lock()
		rsm.sortedV4 = sorted
		rsm.mu.Unlock()

		reachableCount := 0
		for _, result := range results {
			if result != nil && result.Reachable {
				reachableCount++
			}
		}
		Debug("RootServer: IPv4 test complete - %d/%d reachable",
			reachableCount, len(rsm.serversV4))
		Info("RootServer: IPv4 servers sorted by latency - top 3: %v",
			sorted[:min(3, len(sorted))])
	}

	// Sort IPv6 servers using existing SpeedTest
	if len(rsm.serversV6) > 0 {
		Debug("RootServer: Testing %d IPv6 servers via UDP:%s", len(rsm.serversV6), DefaultDNSPort)
		ips := extractIPsFromServers(rsm.serversV6)
		results := rsm.speedTester.SpeedTest(ips)

		sorted := sortBySpeedResult(rsm.serversV6, results)

		rsm.mu.Lock()
		rsm.sortedV6 = sorted
		rsm.mu.Unlock()

		reachableCount := 0
		for _, result := range results {
			if result != nil && result.Reachable {
				reachableCount++
			}
		}
		Debug("RootServer: IPv6 test complete - %d/%d reachable",
			reachableCount, len(rsm.serversV6))
		Info("RootServer: IPv6 servers sorted by latency - top 3: %v",
			sorted[:min(3, len(sorted))])
	}

	rsm.mu.Lock()
	rsm.lastSortTime = time.Now()
	rsm.mu.Unlock()
	Debug("RootServer: Speed sorting completed")
}

func extractIPsFromServers(servers []string) []string {
	ips := make([]string, len(servers))
	for i, server := range servers {
		ips[i] = extractIPFromServer(server)
	}
	return ips
}

func (rsm *RootServerManager) StartPeriodicSorting(ctx context.Context) {
	Debug("RootServer: Starting periodic sorting (%v interval)", RootServerSortInterval)
	ticker := time.NewTicker(RootServerSortInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			Debug("RootServer: Triggering periodic speed test")
			rsm.sortServersBySpeed()
		case <-ctx.Done():
			Debug("RootServer: Stopping periodic sorting - context cancelled")
			return
		}
	}
}

func sortBySpeedResult(servers []string, results map[string]*SpeedResult) []string {
	Debug("RootServer: Processing speed test results for %d servers", len(servers))

	type serverWithLatency struct {
		server    string
		latency   time.Duration
		reachable bool
	}

	serverList := make([]serverWithLatency, len(servers))
	reachableCount := 0

	for i, server := range servers {
		ip := extractIPFromServer(server)
		if result, exists := results[ip]; exists && result.Reachable {
			serverList[i] = serverWithLatency{
				server:    server,
				latency:   result.Latency,
				reachable: true,
			}
			reachableCount++
			Debug("RootServer: %s reachable, latency: %v", server, result.Latency)
		} else {
			serverList[i] = serverWithLatency{
				server:    server,
				latency:   9999 * time.Millisecond, // Put unreachable servers at the end
				reachable: false,
			}
			Debug("RootServer: %s unreachable", server)
		}
	}

	Debug("RootServer: Speed test summary - %d/%d reachable", reachableCount, len(servers))

	// Sort by latency (reachable first, then by latency)
	sort.Slice(serverList, func(i, j int) bool {
		if serverList[i].reachable != serverList[j].reachable {
			return serverList[i].reachable
		}
		return serverList[i].latency < serverList[j].latency
	})

	sorted := make([]string, len(servers))
	for i, item := range serverList {
		sorted[i] = item.server
	}

	Debug("RootServer: Server ranking updated - top 3: %v", sorted[:min(3, reachableCount)])
	return sorted
}

func extractIPFromServer(server string) string {
	host, _, err := net.SplitHostPort(server)
	if err != nil {
		// If server does not contain a port, return as is (could be just an IP)
		return server
	}
	return host
}

// =============================================================================
// SpeedTesting & Utilities
// =============================================================================

func NewSpeedTester(config ServerConfig) *SpeedTester {
	st := &SpeedTester{
		timeout:     DefaultSpeedTimeout,
		concurrency: DefaultSpeedConcurrency,
		cache:       make(map[string]*SpeedResult),
		cacheTTL:    DefaultSpeedCacheTTL,
		methods:     config.SpeedTest,
	}

	st.InitICMP()

	return st
}

func (st *SpeedTester) InitICMP() {
	conn4, err := icmp.ListenPacket("ip4:icmp", "")
	if err == nil {
		st.icmpConn4 = conn4
	} else {
		if strings.Contains(err.Error(), "operation not permitted") {
			Debug("SpeedTest: no permission to create IPv4 ICMP connection, skipping ICMP test")
		} else {
			Debug("SpeedTest: cannot create IPv4 ICMP connection: %v", err)
		}
	}

	conn6, err := icmp.ListenPacket("ip6:ipv6-icmp", "")
	if err == nil {
		st.icmpConn6 = conn6
	} else {
		if strings.Contains(err.Error(), "operation not permitted") {
			Debug("SpeedTest: no permission to create IPv6 ICMP connection, skipping ICMP test")
		} else {
			Debug("SpeedTest: cannot create IPv6 ICMP connection: %v", err)
		}
	}
}

func (st *SpeedTester) Close() error {
	if st.icmpConn4 != nil {
		_ = st.icmpConn4.Close()
	}
	if st.icmpConn6 != nil {
		_ = st.icmpConn6.Close()
	}
	return nil
}

func (st *SpeedTester) PerformSpeedTestAndSort(response *dns.Msg) *dns.Msg {
	if response == nil {
		Debug("SpeedTest: response is empty")
		return response
	}

	Debug("SpeedTest: starting to process response, answer records count: %d", len(response.Answer))

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

	Debug("SpeedTest: A records=%d, AAAA records=%d, CNAME records=%d", len(aRecords), len(aaaaRecords), len(cnameRecords))

	if len(aRecords) > 1 {
		Debug("SpeedTest: performing SpeedTest sorting for %d A records", len(aRecords))
		aRecords = st.SortARecords(aRecords)
	} else {
		Debug("SpeedTest: A records count insufficient or equal to 1, skipping SpeedTest")
	}

	if len(aaaaRecords) > 1 {
		Debug("SpeedTest: performing SpeedTest sorting for %d AAAA records", len(aaaaRecords))
		aaaaRecords = st.SortAAAARecords(aaaaRecords)
	} else {
		Debug("SpeedTest: AAAA records count insufficient or equal to 1, skipping SpeedTest")
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

	Debug("SpeedTest: processing completed, answer records count: %d", len(response.Answer))

	return response
}

func (st *SpeedTester) SortARecords(records []*dns.A) []*dns.A {
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

func (st *SpeedTester) SortAAAARecords(records []*dns.AAAA) []*dns.AAAA {
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

func (st *SpeedTester) SpeedTest(ips []string) map[string]*SpeedResult {
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
		Debug("SpeedTest: all IPs have valid cache, returning cached results directly")
		return cachedResults
	}

	Debug("SpeedTest: need to test %d IPs, %d IPs using cache", len(remainingIPs), len(cachedResults))

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

func (st *SpeedTester) PerformSpeedTest(ips []string) map[string]*SpeedResult {
	Debug("SpeedTest: starting concurrent SpeedTest for %d IPs", len(ips))

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

	Debug("SpeedTest: concurrent SpeedTest completed, obtained %d results", len(results))

	return results
}

func (st *SpeedTester) TestSingleIP(ip string) *SpeedResult {
	Debug("SpeedTest: starting to test IP %s", ip)

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
			Debug("SpeedTest: IP %s total timeout, marked as unreachable", ip)
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
			Debug("SpeedTest: IP %s %s test successful, latency: %v", ip, method.Type, result.Latency)
			return result
		}
	}

	result.Reachable = false
	result.Latency = st.timeout
	Debug("SpeedTest: IP %s all connection attempts failed, marked as unreachable", ip)
	return result
}

func (st *SpeedTester) PingWithICMP(ip string, timeout time.Duration) time.Duration {
	Debug("SpeedTest: starting ICMP ping test %s", ip)

	dst, err := net.ResolveIPAddr("ip", ip)
	if err != nil {
		Debug("SpeedTest: cannot parse IP address %s: %v", ip, err)
		return -1
	}

	var conn *icmp.PacketConn
	if dst.IP.To4() != nil {
		conn = st.icmpConn4
	} else {
		conn = st.icmpConn6
	}

	if conn == nil {
		Debug("SpeedTest: no available ICMP connection for testing %s", ip)
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
		Debug("SpeedTest: cannot serialize ICMP message %s: %v", ip, err)
		return -1
	}

	_ = conn.SetWriteDeadline(time.Now().Add(timeout))

	start := time.Now()

	_, err = conn.WriteTo(wb, dst)
	if err != nil {
		Debug("SpeedTest: ICMP message sending failed %s: %v", ip, err)
		return -1
	}

	_ = conn.SetReadDeadline(time.Now().Add(timeout))

	rb := make([]byte, 1500)
	n, peer, err := conn.ReadFrom(rb)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			Debug("SpeedTest: ICMP ping timeout %s", ip)
		} else {
			Debug("SpeedTest: reading ICMP reply failed %s: %v", ip, err)
		}
		return -1
	}

	Debug("SpeedTest: received reply from %v, size %d bytes", peer, n)

	rm, err := icmp.ParseMessage(protocol, rb[:n])
	if err != nil {
		Debug("SpeedTest: cannot parse ICMP reply %s: %v", ip, err)
		return -1
	}

	switch rm.Type {
	case ipv4.ICMPTypeEchoReply, ipv6.ICMPTypeEchoReply:
		latency := time.Since(start)
		Debug("SpeedTest: ICMP ping successful %s, latency: %v", ip, latency)
		return latency
	default:
		Debug("SpeedTest: received unexpected ICMP message type %s: %v", ip, rm.Type)
		return -1
	}
}

func (st *SpeedTester) PingWithTCP(ip, port string, timeout time.Duration) time.Duration {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	start := time.Now()

	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(ip, port))
	if err != nil {
		Debug("SpeedTest: TCP connection failed %s:%s - %v", ip, port, err)
		return -1
	}

	latency := time.Since(start)
	_ = conn.Close()

	Debug("SpeedTest: TCP connection successful %s:%s, latency: %v", ip, port, latency)

	return latency
}

func (st *SpeedTester) PingWithUDP(ip, port string, timeout time.Duration) time.Duration {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	start := time.Now()

	conn, err := (&net.Dialer{}).DialContext(ctx, "udp", net.JoinHostPort(ip, port))
	if err != nil {
		Debug("SpeedTest: UDP connection failed %s:%s - %v", ip, port, err)
		return -1
	}

	_, writeErr := conn.Write([]byte{})
	if writeErr != nil {
		Debug("SpeedTest: UDP data sending failed %s:%s - %v", ip, port, writeErr)
		_ = conn.Close()
		return -1
	}

	latency := time.Since(start)
	_ = conn.Close()

	Debug("SpeedTest: UDP connection successful %s:%s, latency: %v", ip, port, latency)

	return latency
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

	defer func() { RecoverPanic(fmt.Sprintf("Task-%s", name)) }()
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
		defer func() { RecoverPanic(fmt.Sprintf("AsyncTask-%s", name)) }()

		if err := tm.ExecuteTask(name, fn); err != nil {
			if err != context.Canceled {
				atomic.AddInt64(&tm.stats.failed, 1)
				Error("Async task execution failed [%s]: %v", name, err)
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

	Info("Shutting down task manager...")
	tm.cancel()

	done := make(chan struct{})
	go func() {
		tm.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		Info("Task manager has been safely shut down")
		return nil
	case <-time.After(timeout):
		Warn("Task manager shutdown timeout")
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
	if rt == nil || globalLogger.GetLevel() < LogDebug {
		return
	}

	rt.mu.Lock()
	defer rt.mu.Unlock()

	timestamp := time.Since(rt.StartTime)
	stepMsg := fmt.Sprintf("[%v] %s", timestamp.Truncate(time.Microsecond), fmt.Sprintf(step, args...))
	rt.Steps = append(rt.Steps, stepMsg)

	Debug("[%s] %s", rt.ID, stepMsg)
}

func (rt *RequestTracker) Finish() {
	if rt == nil {
		return
	}

	rt.ResponseTime = time.Since(rt.StartTime)
	if globalLogger.GetLevel() >= LogInfo {
		Info("[%s] Query completed: %s %s | Time:%v | Upstream:%s",
			rt.ID, rt.Domain, rt.QueryType, rt.ResponseTime.Truncate(time.Microsecond), rt.Upstream)
	}
}

func SafeCopyMessage(msg *dns.Msg) *dns.Msg {
	if msg == nil {
		newMsg := globalResourceManager.GetDNSMessage()
		return newMsg
	}

	msgCopy := globalResourceManager.GetDNSMessage()

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

func RecoverPanic(operation string) {
	if r := recover(); r != nil {
		buf := make([]byte, 2048)
		n := runtime.Stack(buf, false)
		stackTrace := string(buf[:n])

		Error("Panic triggered [%s]: %v\nStack:\n%s\nProgram exiting due to panic",
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

// =============================================================================
// Main Function
// =============================================================================

func main() {
	var configFile string
	var generateConfig bool

	flag.StringVar(&configFile, "config", "", "Configuration file path (JSON format)")
	flag.BoolVar(&generateConfig, "generate-config", false, "Generate example configuration file")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "ZJDNS Server\n\n")
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  %s -config <configuration file>     # Start with configuration file\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -generate-config       # Generate example configuration file\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s                         # Start with default configuration\n\n", os.Args[0])
	}

	flag.Parse()

	if generateConfig {
		fmt.Println(GenerateExampleConfig())
		return
	}

	config, err := LoadConfig(configFile)
	if err != nil {
		log.Fatalf("Configuration loading failed: %v", err)
	}

	server, err := NewDNSServer(config)
	if err != nil {
		log.Fatalf("Server creation failed: %v", err)
	}

	Info("ZJDNS Server started successfully!")

	if err := server.Start(); err != nil {
		log.Fatalf("Server startup failed: %v", err)
	}
}
