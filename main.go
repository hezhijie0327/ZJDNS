// Package main implements ZJDNS - High Performance DNS Server
// Supporting DoT/DoH/DoQ/DoH3 with connection pooling and recursive resolution
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/gob"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"maps"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"runtime"
	"slices"
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
	"golang.org/x/sync/errgroup"
)

// =============================================================================
// Global Variables
// =============================================================================

var (
	Version    = "1.4.3"
	CommitHash = "dirty"
	BuildTime  = "dev"

	globalLog = NewLogManager()

	// Protocol configurations
	NextProtoDOT  = []string{"dot"}
	NextProtoDoQ  = []string{"doq", "doq-i00", "doq-i02", "doq-i03", "dq"}
	NextProtoDoH3 = []string{"h3"}
	NextProtoDoH  = []string{"h2", "http/1.1"}

	// Minimal message pool to reduce GC pressure
	messagePool = sync.Pool{
		New: func() any {
			return &dns.Msg{}
		},
	}
)

// =============================================================================
// Constants Section
// =============================================================================

const (
	// Server Ports
	DefaultDNSPort   = "53"
	DefaultDOTPort   = "853"
	DefaultDOHPort   = "443"
	DefaultPprofPort = "6060"

	// Protocol Indicators
	RecursiveIndicator = "builtin_recursive"
	DefaultQueryPath   = "/dns-query"
	PprofPath          = "/debug/pprof/"

	// Buffer Sizes
	UDPBufferSize       = 1232
	TCPBufferSize       = 4096
	SecureBufferSize    = 8192
	DoHMaxRequestSize   = 8192
	TLSSessionCacheSize = 256

	// Domain Limits
	MaxDomainLength = 253
	MaxCNAMEChain   = 16
	MaxRecursionDep = 16
	MaxConcurrency  = 200
	MaxSingleQuery  = 2
	MaxNSResolve    = 2

	// Timeouts
	QueryTimeout           = 3 * time.Second
	RecursiveTimeout       = 5 * time.Second
	ConnTimeout            = 2 * time.Second
	TLSHandshakeTimeout    = 2 * time.Second
	PublicIPTimeout        = 2 * time.Second
	HTTPClientTimeout      = 3 * time.Second
	ShutdownTimeout        = 2 * time.Second
	DoHReadHeaderTimeout   = 3 * time.Second
	DoHWriteTimeout        = 3 * time.Second
	DoTReadTimeout         = 3 * time.Second
	DoTWriteTimeout        = 3 * time.Second
	DoTIdleTimeout         = 45 * time.Second
	SecureIdleTimeout      = 45 * time.Second
	PprofReadHeaderTimeout = 3 * time.Second
	PprofReadTimeout       = 3 * time.Second
	PprofIdleTimeout       = 45 * time.Second
	ConnCloseTimeout       = 200 * time.Millisecond
	ConnDialTimeout        = 2 * time.Second
	ConnMaxLifetime        = 90 * time.Second
	ConnMaxIdleTime        = 30 * time.Second
	ConnValidateEvery      = 8 * time.Second
	ConnKeepAlive          = 30 * time.Second
	ConnPoolCleanup        = 8 * time.Second

	// Cache Configuration
	DefaultCacheTTL    = 10
	StaleTTL           = 30
	StaleMaxAge        = 86400 * 7
	DefaultSpeedTTL    = 180 * time.Second
	SpeedDebounceDelay = 3 * time.Second
	RootServerRefresh  = 900 * time.Second

	// Redis Configuration
	RedisPoolSize     = 3
	RedisMinIdle      = 1
	RedisMaxRetries   = 2
	RedisPoolTimeout  = 2 * time.Second
	RedisReadTimeout  = 2 * time.Second
	RedisWriteTimeout = 2 * time.Second
	RedisDialTimeout  = 2 * time.Second

	// Redis Key Prefixes
	RedisPrefixDNS           = "dns:"
	RedisPrefixSpeedtest     = "speed:"
	RedisPrefixQUICValidator = "quic:v:"
	RedisPrefixQUICSession   = "quic:s:"

	// EDNS Configuration
	DefaultECSv4Len = 24
	DefaultECSv6Len = 64
	DefaultECSScope = 0
	PaddingSize     = 468

	// QUIC Configuration
	MaxIncomingStreams   = 512
	QUICAddrValidatorTTL = 15 * time.Second
	QUICSessionCacheTTL  = 90 * time.Second
	MaxIdleConnections   = 3

	QUICCodeNoError       quic.ApplicationErrorCode = 0
	QUICCodeInternalError quic.ApplicationErrorCode = 1
	QUICCodeProtocolError quic.ApplicationErrorCode = 2

	// Speed Test Configuration
	DefaultSpeedTimeout     = 200 * time.Millisecond
	DefaultSpeedConcurrency = 2
	UnreachableLatency      = 5 * time.Second

	// Logging
	DefaultLogLevel = "info"
	ColorReset      = "\033[0m"
	ColorRed        = "\033[31m"
	ColorYellow     = "\033[33m"
	ColorGreen      = "\033[32m"
	ColorCyan       = "\033[36m"
	ColorBold       = "\033[1m"

	Error LogLevel = iota
	Warn
	Info
	Debug
)

type LogLevel int

// =============================================================================
// Type Definitions - Core Types
// =============================================================================

type LogManager struct {
	level    atomic.Int32 // LogLevel
	writer   io.Writer
	colorMap map[LogLevel]string
}

type ServerConfig struct {
	Server    ServerSettings    `json:"server"`
	Redis     RedisSettings     `json:"redis"`
	Speedtest []SpeedTestMethod `json:"speedtest"`
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

// Cache and Storage Types
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

type CacheManager interface {
	Get(key string) (*CacheEntry, bool, bool)
	Set(key string, answer, authority, additional []dns.RR, validated bool, ecs *ECSOption)
	Close() error
}

type NullCache struct{}

type RedisCache struct {
	client *redis.Client
	config *ServerConfig
	ctx    context.Context
	cancel context.CancelFunc
	closed int32
	wg     sync.WaitGroup
}

// EDNS and DNS Options
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

type IPDetector struct {
	httpClient *http.Client
}

// Query and Response Types
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

type UpstreamQueryResult struct {
	answer     []dns.RR
	authority  []dns.RR
	additional []dns.RR
	validated  bool
	ecs        *ECSOption
	server     string
}

type DNSRewriteResult struct {
	Domain        string
	ShouldRewrite bool
	ResponseCode  int
	Records       []dns.RR
	Additional    []dns.RR
}

type RequestTracker struct {
	ID           string
	StartTime    time.Time
	Domain       string
	QueryType    string
	ClientIP     string
	Upstream     atomic.Value // string
	ResponseTime time.Duration
}

// Speed Test Types
type SpeedResult struct {
	IP        string        `json:"ip"`
	Latency   time.Duration `json:"latency"`
	Reachable bool          `json:"reachable"`
	Timestamp time.Time     `json:"timestamp"`
}

type RootServerWithLatency struct {
	Server    string
	Latency   time.Duration
	Reachable bool
}

// RootServerSortResult contains both the sorted servers and the sort timestamp
// This ensures atomic consistency when reading both values together
type RootServerSortResult struct {
	SortedServers []RootServerWithLatency
	SortTime      time.Time
}

type SpeedTestManager struct {
	timeout     time.Duration
	concurrency int
	redis       *redis.Client
	cacheTTL    time.Duration
	keyPrefix   string
	icmpConn4   *icmp.PacketConn
	icmpConn6   *icmp.PacketConn
	methods     []SpeedTestMethod
	closed      int32
}

type RootServerManager struct {
	servers     []string
	speedTester *SpeedTestManager
	sortResult  atomic.Value // *RootServerSortResult
	needsSpeed  bool
}

// CIDR Management Types
type CIDRRule struct {
	tag  string
	nets []*net.IPNet
}

type CIDRManager struct {
	rules map[string]*CIDRRule
	mu    sync.RWMutex
}

// Rewrite Management Type
type RewriteManager struct {
	rules    atomic.Value // []RewriteRule
	rulesLen atomic.Int64
}

// Connection Pool Types
type ConnPoolEntry struct {
	conn       any
	lastUsed   atomic.Value // time.Time
	createdAt  time.Time
	useCount   atomic.Int64
	serverAddr string
	protocol   string
	healthy    atomic.Bool
	closed     atomic.Bool
}

type ConnPool struct {
	http2Conns    sync.Map
	http3Conns    sync.Map
	quicConns     sync.Map
	tlsConns      sync.Map
	sessionCache  tls.ClientSessionCache
	ctx           context.Context
	cancel        context.CancelFunc
	wg            sync.WaitGroup
	closed        atomic.Bool
	cleanupTicker *time.Ticker
	connCount     atomic.Int64
}

type QueryClient struct {
	timeout  time.Duration
	connPool *ConnPool
}

// Security Types
type DNSSECValidator struct{}

type HijackPrevention struct {
	enabled bool
}

type SecurityManager struct {
	tls    *TLSManager
	dnssec *DNSSECValidator
	hijack *HijackPrevention
}

// TLS Management Type
type TLSManager struct {
	server        *DNSServer
	tlsConfig     *tls.Config
	ctx           context.Context
	cancel        context.CancelFunc
	wg            sync.WaitGroup
	dotListener   net.Listener
	doqConn       *net.UDPConn
	doqListener   *quic.EarlyListener
	doqTransport  *quic.Transport
	httpsServer   *http.Server
	h3Server      *http3.Server
	httpsListener net.Listener
	h3Listener    *quic.EarlyListener
}

// DNS Server Type
type DNSServer struct {
	config        *ServerConfig
	cacheMgr      CacheManager
	queryClient   *QueryClient
	connPool      *ConnPool
	securityMgr   *SecurityManager
	ednsMgr       *EDNSManager
	rewriteMgr    *RewriteManager
	speedTestMgr  *SpeedTestManager
	rootServerMgr *RootServerManager
	cidrMgr       *CIDRManager
	pprofServer   *http.Server
	redisClient   *redis.Client
	ctx           context.Context
	cancel        context.CancelFunc
	shutdown      chan struct{}
	wg            sync.WaitGroup
	closed        int32
	queryMgr      *QueryManager
}

type ConfigManager struct{}

// Query Manager Types
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
	server        *DNSServer
	rootServerMgr *RootServerManager
}

type CNAMEHandler struct {
	server *DNSServer
}

type ResponseValidator struct {
	hijackPrevention *HijackPrevention
	dnssecValidator  *DNSSECValidator
}

// =============================================================================
// LogManager Implementation
// =============================================================================

func NewLogManager() *LogManager {
	lm := &LogManager{
		writer: os.Stdout,
		colorMap: map[LogLevel]string{
			Error: ColorRed,
			Warn:  ColorYellow,
			Info:  ColorGreen,
			Debug: ColorCyan,
		},
	}
	lm.level.Store(int32(Info))
	return lm
}

func (lm *LogManager) SetLevel(level LogLevel) {
	// Clamp level to valid range
	if level < Error {
		level = Error
	} else if level > Debug {
		level = Debug
	}
	lm.level.Store(int32(level))
}

func (lm *LogManager) GetLevel() LogLevel {
	return LogLevel(lm.level.Load())
}

func (lm *LogManager) Log(level LogLevel, format string, args ...any) {
	// Clamp level to valid range to prevent array out of bounds
	if level < Error {
		level = Error
	} else if level > Debug {
		level = Debug
	}

	if level > LogLevel(lm.level.Load()) {
		return
	}

	// Use switch instead of array index to avoid panic
	var levelStr string
	switch level {
	case Error:
		levelStr = "ERROR"
	case Warn:
		levelStr = "WARN"
	case Info:
		levelStr = "INFO"
	case Debug:
		levelStr = "DEBUG"
	default:
		levelStr = "UNKNOWN"
	}

	// Safely get color from map with fallback
	color, ok := lm.colorMap[level]
	if !ok {
		color = ColorReset
	}

	timestamp := time.Now().Format("2006-01-02 15:04:05")
	message := fmt.Sprintf(format, args...)

	logLine := fmt.Sprintf("%s[%s]%s %s%-5s%s %s\n",
		ColorBold, timestamp, ColorReset,
		color, levelStr, ColorReset,
		message)

	_, _ = fmt.Fprint(lm.writer, logLine)
}

func (lm *LogManager) Error(format string, args ...any) { lm.Log(Error, format, args...) }
func (lm *LogManager) Warn(format string, args ...any)  { lm.Log(Warn, format, args...) }
func (lm *LogManager) Info(format string, args ...any)  { lm.Log(Info, format, args...) }
func (lm *LogManager) Debug(format string, args ...any) { lm.Log(Debug, format, args...) }

func LogError(format string, args ...any) { globalLog.Error(format, args...) }
func LogWarn(format string, args ...any)  { globalLog.Warn(format, args...) }
func LogInfo(format string, args ...any)  { globalLog.Info(format, args...) }
func LogDebug(format string, args ...any) { globalLog.Debug(format, args...) }

// =============================================================================
// ConnectionPool Implementation
// =============================================================================

func NewConnPool() *ConnPool {
	ctx, cancel := context.WithCancel(context.Background())

	pool := &ConnPool{
		ctx:           ctx,
		cancel:        cancel,
		cleanupTicker: time.NewTicker(ConnPoolCleanup),
		sessionCache:  tls.NewLRUClientSessionCache(TLSSessionCacheSize),
	}

	go pool.cleanupLoop()

	LogInfo("POOL: Connection pool initialized")
	return pool
}

func (p *ConnPool) cleanupLoop() {
	defer HandlePanic("Connection pool cleanup")

	validateTicker := time.NewTicker(ConnValidateEvery)
	defer validateTicker.Stop()

	for {
		select {
		case <-p.cleanupTicker.C:
			p.cleanupExpiredConns()
		case <-validateTicker.C:
			p.validateConns()
		case <-p.ctx.Done():
			return
		}
	}
}

func (p *ConnPool) cleanupExpiredConns() {
	now := time.Now()
	removed := 0

	cleanupMap := func(m *sync.Map) {
		m.Range(func(key, value any) bool {
			entry := value.(*ConnPoolEntry)

			lastUsed := entry.lastUsed.Load().(time.Time)
			shouldRemove := entry.closed.Load() ||
				now.Sub(entry.createdAt) > ConnMaxLifetime ||
				now.Sub(lastUsed) > ConnMaxIdleTime ||
				!entry.healthy.Load()

			if shouldRemove {
				m.Delete(key)
				p.closeEntry(entry)
				removed++
			}

			return true
		})
	}

	cleanupMap(&p.http2Conns)
	cleanupMap(&p.http3Conns)
	cleanupMap(&p.quicConns)
	cleanupMap(&p.tlsConns)

	if removed > 0 {
		LogDebug("POOL: Cleaned up %d expired connections", removed)
	}
}

func (p *ConnPool) validateConns() {
	validated := 0
	failed := 0

	validateMap := func(m *sync.Map) {
		m.Range(func(key, value any) bool {
			entry := value.(*ConnPoolEntry)

			if entry.closed.Load() {
				return true
			}

			valid := p.validateConn(entry)
			entry.healthy.Store(valid)

			if !valid {
				failed++
				m.Delete(key)
				p.closeEntry(entry)
			} else {
				validated++
			}

			return true
		})
	}

	validateMap(&p.quicConns)
	validateMap(&p.tlsConns)

	if validated > 0 || failed > 0 {
		LogDebug("POOL: Validation - valid: %d, failed: %d", validated, failed)
	}
}

func (p *ConnPool) validateConn(entry *ConnPoolEntry) bool {
	switch conn := entry.conn.(type) {
	case *quic.Conn:
		select {
		case <-conn.Context().Done():
			return false
		default:
			return true
		}
	case *tls.Conn:
		_ = conn.SetReadDeadline(time.Now().Add(time.Millisecond))
		buf := make([]byte, 1)
		_, err := conn.Read(buf)
		_ = conn.SetReadDeadline(time.Time{})
		return err == nil || IsTemporaryError(err)
	default:
		return true
	}
}

func (p *ConnPool) closeEntry(entry *ConnPoolEntry) {
	if !entry.closed.CompareAndSwap(false, true) {
		return
	}

	p.connCount.Add(-1)

	switch conn := entry.conn.(type) {
	case *http.Transport:
		conn.CloseIdleConnections()
	case *http3.Transport:
		_ = conn.Close()
	case *quic.Conn:
		ctx, cancel := context.WithTimeout(context.Background(), ConnCloseTimeout)
		_ = conn.CloseWithError(QUICCodeNoError, "cleanup")
		select {
		case <-conn.Context().Done():
		case <-ctx.Done():
		}
		cancel()
	case *tls.Conn:
		_ = conn.Close()
	}
}

func (p *ConnPool) GetOrCreateHTTP2(serverAddr string, tlsConfig *tls.Config) (*http.Client, error) {
	if p.closed.Load() {
		return nil, errors.New("pool closed")
	}

	key := "h2:" + serverAddr

	if value, ok := p.http2Conns.Load(key); ok {
		entry := value.(*ConnPoolEntry)
		if !entry.closed.Load() && entry.healthy.Load() {
			entry.lastUsed.Store(time.Now())
			entry.useCount.Add(1)
			return &http.Client{
				Transport: entry.conn.(*http.Transport),
				Timeout:   QueryTimeout,
			}, nil
		}
		p.http2Conns.Delete(key)
		p.closeEntry(entry)
	}

	tlsConfig = tlsConfig.Clone()
	tlsConfig.ClientSessionCache = p.sessionCache

	transport := &http.Transport{
		TLSClientConfig:       tlsConfig,
		DisableCompression:    true,
		DisableKeepAlives:     false,
		MaxIdleConns:          8,
		IdleConnTimeout:       ConnMaxIdleTime,
		ForceAttemptHTTP2:     true,
		MaxIdleConnsPerHost:   4,
		ResponseHeaderTimeout: QueryTimeout,
	}

	if err := http2.ConfigureTransport(transport); err != nil {
		return nil, fmt.Errorf("configure HTTP/2: %w", err)
	}

	entry := &ConnPoolEntry{
		conn:       transport,
		createdAt:  time.Now(),
		serverAddr: serverAddr,
		protocol:   "http2",
	}
	entry.lastUsed.Store(time.Now())
	entry.useCount.Store(1)
	entry.healthy.Store(true)

	p.http2Conns.Store(key, entry)
	p.connCount.Add(1)

	return &http.Client{
		Transport: transport,
		Timeout:   QueryTimeout,
	}, nil
}

func (p *ConnPool) GetOrCreateHTTP3(serverAddr string, tlsConfig *tls.Config) (*http.Client, error) {
	if p.closed.Load() {
		return nil, errors.New("pool closed")
	}

	key := "h3:" + serverAddr

	if value, ok := p.http3Conns.Load(key); ok {
		entry := value.(*ConnPoolEntry)
		if !entry.closed.Load() && entry.healthy.Load() {
			entry.lastUsed.Store(time.Now())
			entry.useCount.Add(1)
			return &http.Client{
				Transport: entry.conn.(*http3.Transport),
				Timeout:   QueryTimeout,
			}, nil
		}
		p.http3Conns.Delete(key)
		p.closeEntry(entry)
	}

	tlsConfig = tlsConfig.Clone()
	tlsConfig.NextProtos = NextProtoDoH3
	tlsConfig.ClientSessionCache = p.sessionCache

	transport := &http3.Transport{
		TLSClientConfig: tlsConfig,
		QUICConfig: &quic.Config{
			MaxIdleTimeout:             ConnMaxIdleTime,
			MaxIncomingStreams:         MaxIncomingStreams / 2,
			KeepAlivePeriod:            ConnKeepAlive,
			EnableDatagrams:            true,
			Allow0RTT:                  true,
			MaxStreamReceiveWindow:     4 * 1024 * 1024,
			MaxConnectionReceiveWindow: 8 * 1024 * 1024,
		},
	}

	entry := &ConnPoolEntry{
		conn:       transport,
		createdAt:  time.Now(),
		serverAddr: serverAddr,
		protocol:   "http3",
	}
	entry.lastUsed.Store(time.Now())
	entry.useCount.Store(1)
	entry.healthy.Store(true)

	p.http3Conns.Store(key, entry)
	p.connCount.Add(1)

	return &http.Client{
		Transport: transport,
		Timeout:   QueryTimeout,
	}, nil
}

func (p *ConnPool) GetOrCreateQUIC(ctx context.Context, serverAddr string, tlsConfig *tls.Config) (*quic.Conn, error) {
	if p.closed.Load() {
		return nil, errors.New("pool closed")
	}

	key := "quic:" + serverAddr

	if value, ok := p.quicConns.Load(key); ok {
		entry := value.(*ConnPoolEntry)
		conn := entry.conn.(*quic.Conn)

		if !entry.closed.Load() && entry.healthy.Load() {
			select {
			case <-conn.Context().Done():
				p.quicConns.Delete(key)
				p.closeEntry(entry)
			default:
				entry.lastUsed.Store(time.Now())
				entry.useCount.Add(1)
				return conn, nil
			}
		} else {
			p.quicConns.Delete(key)
			p.closeEntry(entry)
		}
	}

	tlsConfig = tlsConfig.Clone()
	tlsConfig.NextProtos = NextProtoDoQ
	tlsConfig.ClientSessionCache = p.sessionCache

	quicConfig := &quic.Config{
		MaxIdleTimeout:             ConnMaxIdleTime,
		MaxIncomingStreams:         MaxIncomingStreams / 2,
		KeepAlivePeriod:            ConnKeepAlive,
		EnableDatagrams:            true,
		Allow0RTT:                  true,
		MaxStreamReceiveWindow:     4 * 1024 * 1024,
		MaxConnectionReceiveWindow: 8 * 1024 * 1024,
	}

	dialCtx, cancel := context.WithTimeout(ctx, ConnDialTimeout)
	defer cancel()

	conn, err := quic.DialAddr(dialCtx, serverAddr, tlsConfig, quicConfig)
	if err != nil {
		return nil, fmt.Errorf("QUIC dial: %w", err)
	}

	entry := &ConnPoolEntry{
		conn:       conn,
		createdAt:  time.Now(),
		serverAddr: serverAddr,
		protocol:   "quic",
	}
	entry.lastUsed.Store(time.Now())
	entry.useCount.Store(1)
	entry.healthy.Store(true)

	p.quicConns.Store(key, entry)
	p.connCount.Add(1)

	go p.monitorQUICConn(key, entry, conn)

	return conn, nil
}

func (p *ConnPool) monitorQUICConn(key string, entry *ConnPoolEntry, conn *quic.Conn) {
	defer HandlePanic("Monitor QUIC connection")

	<-conn.Context().Done()

	entry.healthy.Store(false)

	p.quicConns.Delete(key)
	p.closeEntry(entry)
}

func (p *ConnPool) GetOrCreateTLS(ctx context.Context, serverAddr string, tlsConfig *tls.Config) (*tls.Conn, error) {
	if p.closed.Load() {
		return nil, errors.New("pool closed")
	}

	key := "tls:" + serverAddr

	if value, ok := p.tlsConns.Load(key); ok {
		entry := value.(*ConnPoolEntry)
		conn := entry.conn.(*tls.Conn)

		if !entry.closed.Load() && entry.healthy.Load() && p.validateConn(entry) {
			entry.lastUsed.Store(time.Now())
			entry.useCount.Add(1)
			return conn, nil
		}

		p.tlsConns.Delete(key)
		p.closeEntry(entry)
	}

	tlsConfig = tlsConfig.Clone()
	tlsConfig.ClientSessionCache = p.sessionCache

	host, port, err := net.SplitHostPort(serverAddr)
	if err != nil {
		return nil, fmt.Errorf("parse address: %w", err)
	}

	dialer := &net.Dialer{
		Timeout:   ConnDialTimeout,
		KeepAlive: ConnKeepAlive,
	}
	netConn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}

	tlsConn := tls.Client(netConn, tlsConfig)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = netConn.Close()
		return nil, fmt.Errorf("TLS handshake: %w", err)
	}

	entry := &ConnPoolEntry{
		conn:       tlsConn,
		createdAt:  time.Now(),
		serverAddr: serverAddr,
		protocol:   "tls",
	}
	entry.lastUsed.Store(time.Now())
	entry.useCount.Store(1)
	entry.healthy.Store(true)

	p.tlsConns.Store(key, entry)
	p.connCount.Add(1)

	return tlsConn, nil
}

func (p *ConnPool) Close() error {
	if !p.closed.CompareAndSwap(false, true) {
		return nil
	}

	LogInfo("POOL: Shutting down connection pool")

	p.cancel()
	p.cleanupTicker.Stop()

	closeMap := func(m *sync.Map) {
		m.Range(func(key, value any) bool {
			entry := value.(*ConnPoolEntry)
			p.closeEntry(entry)
			m.Delete(key)
			return true
		})
	}

	closeMap(&p.http2Conns)
	closeMap(&p.http3Conns)
	closeMap(&p.quicConns)
	closeMap(&p.tlsConns)

	p.wg.Wait()
	LogInfo("POOL: Connection pool shut down")
	return nil
}

// =============================================================================
// QueryClient Implementation
// =============================================================================

func NewQueryClient(connPool *ConnPool) *QueryClient {
	return &QueryClient{
		timeout:  QueryTimeout,
		connPool: connPool,
	}
}

func (qc *QueryClient) ExecuteQuery(ctx context.Context, msg *dns.Msg, server *UpstreamServer) *QueryResult {
	start := time.Now()
	result := &QueryResult{Server: server.Address, Protocol: server.Protocol}

	queryCtx, cancel := context.WithTimeout(ctx, qc.timeout)
	defer cancel()

	protocol := strings.ToLower(server.Protocol)

	if IsSecureProtocol(protocol) {
		result.Response, result.Error = qc.executeSecureQuery(queryCtx, msg, server, protocol)
	} else {
		result.Response, result.Error = qc.executeTraditionalQuery(queryCtx, msg, server)
		if qc.needsTCPFallback(result, protocol) {
			tcpServer := *server
			tcpServer.Protocol = "tcp"
			if tcpResp, tcpErr := qc.executeTraditionalQuery(queryCtx, msg, &tcpServer); tcpErr == nil {
				result.Response = tcpResp
				result.Error = nil
				result.Protocol = "TCP"
			}
		}
	}

	result.Duration = time.Since(start)
	result.Protocol = strings.ToUpper(protocol)

	return result
}

func (qc *QueryClient) executeSecureQuery(ctx context.Context, msg *dns.Msg, server *UpstreamServer, protocol string) (*dns.Msg, error) {
	tlsConfig := &tls.Config{
		ServerName:         server.ServerName,
		InsecureSkipVerify: server.SkipTLSVerify,
		MinVersion:         tls.VersionTLS12,
		ClientSessionCache: qc.connPool.sessionCache,
	}

	if server.SkipTLSVerify {
		LogDebug("QUERY: TLS verification disabled for %s - security risk!", server.ServerName)
	}

	switch protocol {
	case "dot", "tls":
		return qc.executeTLS(ctx, msg, server, tlsConfig)
	case "doq", "quic":
		return qc.executeQUIC(ctx, msg, server, tlsConfig)
	case "doh", "https":
		return qc.executeDoH(ctx, msg, server, tlsConfig)
	case "doh3", "http3":
		return qc.executeDoH3(ctx, msg, server, tlsConfig)
	default:
		return nil, fmt.Errorf("unsupported protocol: %s", protocol)
	}
}

func (qc *QueryClient) executeTLS(ctx context.Context, msg *dns.Msg, server *UpstreamServer, tlsConfig *tls.Config) (*dns.Msg, error) {
	conn, err := qc.connPool.GetOrCreateTLS(ctx, server.Address, tlsConfig)
	if err != nil {
		return nil, err
	}

	_ = conn.SetDeadline(time.Now().Add(qc.timeout))
	defer func() { _ = conn.SetDeadline(time.Time{}) }()

	msgData, err := msg.Pack()
	if err != nil {
		return nil, fmt.Errorf("pack message: %w", err)
	}

	buf := make([]byte, 2+len(msgData))
	binary.BigEndian.PutUint16(buf[:2], uint16(len(msgData)))
	copy(buf[2:], msgData)

	if _, err := conn.Write(buf); err != nil {
		return nil, fmt.Errorf("write: %w", err)
	}

	lengthBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, lengthBuf); err != nil {
		return nil, fmt.Errorf("read length: %w", err)
	}

	respLength := binary.BigEndian.Uint16(lengthBuf)
	if respLength == 0 || respLength > TCPBufferSize {
		return nil, fmt.Errorf("invalid length: %d", respLength)
	}

	respBuf := make([]byte, respLength)
	if _, err := io.ReadFull(conn, respBuf); err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	response := new(dns.Msg)
	if err := response.Unpack(respBuf); err != nil {
		return nil, fmt.Errorf("unpack: %w", err)
	}

	return response, nil
}

func (qc *QueryClient) executeQUIC(ctx context.Context, msg *dns.Msg, server *UpstreamServer, tlsConfig *tls.Config) (*dns.Msg, error) {
	conn, err := qc.connPool.GetOrCreateQUIC(ctx, server.Address, tlsConfig)
	if err != nil {
		return nil, err
	}

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("open stream: %w", err)
	}
	defer func() { _ = stream.Close() }()

	_ = stream.SetDeadline(time.Now().Add(qc.timeout))

	originalID := msg.Id
	msg.Id = 0

	msgData, err := msg.Pack()
	if err != nil {
		msg.Id = originalID
		return nil, fmt.Errorf("pack: %w", err)
	}

	buf := make([]byte, 2+len(msgData))
	binary.BigEndian.PutUint16(buf[:2], uint16(len(msgData)))
	copy(buf[2:], msgData)

	if _, err := stream.Write(buf); err != nil {
		msg.Id = originalID
		return nil, fmt.Errorf("write: %w", err)
	}

	respBuf := make([]byte, SecureBufferSize)
	n, err := stream.Read(respBuf)
	if err != nil && n == 0 {
		msg.Id = originalID
		return nil, fmt.Errorf("read: %w", err)
	}

	if n < 2 {
		msg.Id = originalID
		return nil, fmt.Errorf("response too short: %d", n)
	}

	response := new(dns.Msg)
	if err := response.Unpack(respBuf[2:n]); err != nil {
		msg.Id = originalID
		return nil, fmt.Errorf("unpack: %w", err)
	}

	msg.Id = originalID
	response.Id = originalID

	return response, nil
}

func (qc *QueryClient) executeDoH(ctx context.Context, msg *dns.Msg, server *UpstreamServer, tlsConfig *tls.Config) (*dns.Msg, error) {
	parsedURL, err := url.Parse(server.Address)
	if err != nil {
		return nil, fmt.Errorf("parse URL: %w", err)
	}

	if parsedURL.Port() == "" {
		parsedURL.Host = net.JoinHostPort(parsedURL.Host, DefaultDOHPort)
	}

	httpClient, err := qc.connPool.GetOrCreateHTTP2(parsedURL.Host, tlsConfig)
	if err != nil {
		return nil, err
	}

	originalID := msg.Id
	msg.Id = 0

	buf, err := msg.Pack()
	if err != nil {
		msg.Id = originalID
		return nil, fmt.Errorf("pack: %w", err)
	}

	q := url.Values{"dns": []string{base64.RawURLEncoding.EncodeToString(buf)}}
	u := url.URL{
		Scheme:   parsedURL.Scheme,
		Host:     parsedURL.Host,
		Path:     parsedURL.Path,
		RawQuery: q.Encode(),
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		msg.Id = originalID
		return nil, fmt.Errorf("create request: %w", err)
	}

	httpReq.Header.Set("Accept", "application/dns-message")

	httpResp, err := httpClient.Do(httpReq)
	if err != nil {
		msg.Id = originalID
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = httpResp.Body.Close() }()

	if httpResp.StatusCode != http.StatusOK {
		msg.Id = originalID
		return nil, fmt.Errorf("HTTP status: %d", httpResp.StatusCode)
	}

	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		msg.Id = originalID
		return nil, fmt.Errorf("read body: %w", err)
	}

	response := &dns.Msg{}
	if err := response.Unpack(body); err != nil {
		msg.Id = originalID
		return nil, fmt.Errorf("unpack: %w", err)
	}

	msg.Id = originalID
	response.Id = originalID

	return response, nil
}

func (qc *QueryClient) executeDoH3(ctx context.Context, msg *dns.Msg, server *UpstreamServer, tlsConfig *tls.Config) (*dns.Msg, error) {
	parsedURL, err := url.Parse(server.Address)
	if err != nil {
		return nil, fmt.Errorf("parse URL: %w", err)
	}

	if parsedURL.Port() == "" {
		parsedURL.Host = net.JoinHostPort(parsedURL.Host, DefaultDOHPort)
	}

	httpClient, err := qc.connPool.GetOrCreateHTTP3(parsedURL.Host, tlsConfig)
	if err != nil {
		return nil, err
	}

	originalID := msg.Id
	msg.Id = 0

	buf, err := msg.Pack()
	if err != nil {
		msg.Id = originalID
		return nil, fmt.Errorf("pack: %w", err)
	}

	q := url.Values{"dns": []string{base64.RawURLEncoding.EncodeToString(buf)}}
	u := url.URL{
		Scheme:   parsedURL.Scheme,
		Host:     parsedURL.Host,
		Path:     parsedURL.Path,
		RawQuery: q.Encode(),
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		msg.Id = originalID
		return nil, fmt.Errorf("create request: %w", err)
	}

	httpReq.Header.Set("Accept", "application/dns-message")

	httpResp, err := httpClient.Do(httpReq)
	if err != nil {
		msg.Id = originalID
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = httpResp.Body.Close() }()

	if httpResp.StatusCode != http.StatusOK {
		msg.Id = originalID
		return nil, fmt.Errorf("HTTP status: %d", httpResp.StatusCode)
	}

	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		msg.Id = originalID
		return nil, fmt.Errorf("read body: %w", err)
	}

	response := &dns.Msg{}
	if err := response.Unpack(body); err != nil {
		msg.Id = originalID
		return nil, fmt.Errorf("unpack: %w", err)
	}

	msg.Id = originalID
	response.Id = originalID

	return response, nil
}

func (qc *QueryClient) executeTraditionalQuery(ctx context.Context, msg *dns.Msg, server *UpstreamServer) (*dns.Msg, error) {
	client := &dns.Client{Timeout: qc.timeout, Net: server.Protocol}
	if server.Protocol == "udp" {
		client.UDPSize = UDPBufferSize
	}

	response, _, err := client.ExchangeContext(ctx, msg, server.Address)
	return response, err
}

func (qc *QueryClient) needsTCPFallback(result *QueryResult, protocol string) bool {
	return protocol != "tcp" && (result.Error != nil || (result.Response != nil && result.Response.Truncated))
}

// =============================================================================
// ConfigManager Implementation
// =============================================================================

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

	LogInfo("CONFIG: Configuration loaded successfully")
	return config, nil
}

func (cm *ConfigManager) validateConfig(config *ServerConfig) error {
	validLevels := map[string]LogLevel{
		"error": Error,
		"warn":  Warn,
		"info":  Info,
		"debug": Debug,
	}

	logLevelStr := strings.ToLower(config.Server.LogLevel)
	if logLevelStr == "" {
		logLevelStr = DefaultLogLevel
	}

	if level, ok := validLevels[logLevelStr]; ok {
		globalLog.SetLevel(level)
	} else {
		// Use default level instead of error, to avoid panic before validation
		globalLog.SetLevel(Info)
		LogWarn("CONFIG: Invalid log level '%s', using default: info", config.Server.LogLevel)
	}

	if config.Server.DefaultECS != "" {
		ecs := strings.ToLower(config.Server.DefaultECS)
		validPresets := []string{"auto", "auto_v4", "auto_v6"}
		isValidPreset := slices.Contains(validPresets, ecs)
		if !isValidPreset {
			if _, _, err := net.ParseCIDR(config.Server.DefaultECS); err != nil {
				return fmt.Errorf("invalid ECS subnet: %w", err)
			}
		}
	}

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
			return fmt.Errorf("CIDR config %d: either 'file' or 'rules' must be specified", i)
		}
		if cidrConfig.File != "" && !IsValidFilePath(cidrConfig.File) {
			return fmt.Errorf("CIDR config %d: file not found: %s", i, cidrConfig.File)
		}
	}

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

		for _, matchTag := range server.Match {
			cleanTag := strings.TrimPrefix(matchTag, "!")
			if !cidrTags[cleanTag] {
				return fmt.Errorf("upstream server %d: match tag '%s' not found", i, cleanTag)
			}
		}
	}

	if config.Redis.Address != "" {
		if _, _, err := net.SplitHostPort(config.Redis.Address); err != nil {
			return fmt.Errorf("redis address invalid: %w", err)
		}
	}

	if config.Server.TLS.SelfSigned && (config.Server.TLS.CertFile != "" || config.Server.TLS.KeyFile != "") {
		LogWarn("CONFIG: TLS: Self-signed enabled, ignoring cert/key files")
	}

	if !config.Server.TLS.SelfSigned && (config.Server.TLS.CertFile != "" || config.Server.TLS.KeyFile != "") {
		if config.Server.TLS.CertFile == "" || config.Server.TLS.KeyFile == "" {
			return errors.New("config: cert and key files must be configured together")
		}
		if !IsValidFilePath(config.Server.TLS.CertFile) {
			return fmt.Errorf("config: cert file not found: %s", config.Server.TLS.CertFile)
		}
		if !IsValidFilePath(config.Server.TLS.KeyFile) {
			return fmt.Errorf("config: key file not found: %s", config.Server.TLS.KeyFile)
		}
		if _, err := tls.LoadX509KeyPair(config.Server.TLS.CertFile, config.Server.TLS.KeyFile); err != nil {
			return fmt.Errorf("config: load certificate: %w", err)
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
	config.Server.TLS.Port = DefaultDOTPort
	config.Server.TLS.HTTPS.Port = DefaultDOHPort
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
	nxdomainCode := dns.RcodeNameError

	svcbRecords := []DNSRecordConfig{
		{Type: "SVCB", Content: "1 . alpn=h3,h2 port=" + config.Server.TLS.HTTPS.Port},
		{Type: "SVCB", Content: "2 . alpn=doq,dot port=" + config.Server.TLS.Port},
	}

	var additionalRecords []DNSRecordConfig
	var directRecords []DNSRecordConfig

	if config.Server.DDR.IPv4 != "" {
		svcbRecords[0].Content += " ipv4hint=" + config.Server.DDR.IPv4
		svcbRecords[1].Content += " ipv4hint=" + config.Server.DDR.IPv4
		additionalRecords = append(additionalRecords, DNSRecordConfig{
			Name: domain, Type: "A", Content: config.Server.DDR.IPv4,
		})
		directRecords = append(directRecords, DNSRecordConfig{
			Type: "A", Content: config.Server.DDR.IPv4,
		})
	} else {
		directRecords = append(directRecords, DNSRecordConfig{
			Type: "A", ResponseCode: &nxdomainCode,
		})
	}

	if config.Server.DDR.IPv6 != "" {
		svcbRecords[0].Content += " ipv6hint=" + config.Server.DDR.IPv6
		svcbRecords[1].Content += " ipv6hint=" + config.Server.DDR.IPv6
		additionalRecords = append(additionalRecords, DNSRecordConfig{
			Name: domain, Type: "AAAA", Content: config.Server.DDR.IPv6,
		})
		directRecords = append(directRecords, DNSRecordConfig{
			Type: "AAAA", Content: config.Server.DDR.IPv6,
		})
	} else {
		directRecords = append(directRecords, DNSRecordConfig{
			Type: "AAAA", ResponseCode: &nxdomainCode,
		})
	}

	config.Rewrite = append(config.Rewrite, RewriteRule{
		Name:    domain,
		Records: directRecords,
	})

	ddrNames := []string{"_dns.resolver.arpa", "_dns." + domain}
	if config.Server.Port != "" && config.Server.Port != DefaultDNSPort {
		ddrNames = append(ddrNames, "_"+config.Server.Port+"._dns."+domain)
	}

	for _, name := range ddrNames {
		config.Rewrite = append(config.Rewrite, RewriteRule{
			Name:       name,
			Records:    svcbRecords,
			Additional: additionalRecords,
		})
	}

	LogInfo("CONFIG: DDR enabled for domain %s (IPv4: %s, IPv6: %s)",
		domain, config.Server.DDR.IPv4, config.Server.DDR.IPv6)
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

	config.Speedtest = []SpeedTestMethod{
		{Type: "icmp", Timeout: int(DefaultSpeedTimeout.Milliseconds())},
		{Type: "tcp", Port: "443", Timeout: int(DefaultSpeedTimeout.Milliseconds())},
		{Type: "tcp", Port: "80", Timeout: int(DefaultSpeedTimeout.Milliseconds())},
		{Type: "udp", Port: "53", Timeout: int(DefaultSpeedTimeout.Milliseconds())},
	}

	data, _ := json.MarshalIndent(config, "", "  ")
	return string(data)
}

// =============================================================================
// NullCache Implementation
// =============================================================================

func NewNullCache() *NullCache {
	LogInfo("CACHE: Null cache mode enabled")
	return &NullCache{}
}

func (nc *NullCache) Get(key string) (*CacheEntry, bool, bool) { return nil, false, false }
func (nc *NullCache) Set(key string, answer, authority, additional []dns.RR, validated bool, ecs *ECSOption) {
}
func (nc *NullCache) Close() error { return nil }

// =============================================================================
// RedisCache Implementation
// =============================================================================

func NewRedisCache(config *ServerConfig) (*RedisCache, error) {
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
		client: rdb,
		config: config,
		ctx:    cacheCtx,
		cancel: cacheCancel,
	}

	LogInfo("CACHE: Redis cache initialized")
	return cache, nil
}

func (rc *RedisCache) Get(key string) (*CacheEntry, bool, bool) {
	defer HandlePanic("Redis cache get")

	if atomic.LoadInt32(&rc.closed) != 0 {
		return nil, false, false
	}

	ctx, cancel := context.WithTimeout(rc.ctx, RedisReadTimeout)
	defer cancel()

	data, err := rc.client.Get(ctx, key).Result()
	if err != nil {
		return nil, false, false
	}

	var entry CacheEntry
	// Use binary serialization only for maximum performance
	if err := deserializeFromBinary([]byte(data), entry); err != nil {
		// Invalid cache entry - remove it
		go func() {
			defer HandlePanic("Clean corrupted cache")
			cleanCtx, cleanCancel := context.WithTimeout(rc.ctx, RedisWriteTimeout)
			defer cleanCancel()
			rc.client.Del(cleanCtx, key)
		}()
		return nil, false, false
	}

	isExpired := entry.IsExpired()

	entry.AccessTime = time.Now().Unix()
	go func() {
		defer HandlePanic("Update access time")
		if atomic.LoadInt32(&rc.closed) == 0 {
			updateCtx, updateCancel := context.WithTimeout(rc.ctx, RedisWriteTimeout)
			defer updateCancel()
			// Use binary serialization only for maximum performance
			data, err := serializeToBinary(entry)
			if err != nil {
				LogWarn("CACHE: Binary serialization failed, skipping update: %v", err)
				return
			}
			rc.client.Set(updateCtx, key, data, redis.KeepTTL)
		}
	}()

	return &entry, true, isExpired
}

func (rc *RedisCache) Set(key string, answer, authority, additional []dns.RR, validated bool, ecs *ECSOption) {
	defer HandlePanic("Redis cache set")

	if atomic.LoadInt32(&rc.closed) != 0 {
		return
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
	}

	if ecs != nil {
		entry.ECSFamily = ecs.Family
		entry.ECSSourcePrefix = ecs.SourcePrefix
		entry.ECSScopePrefix = ecs.ScopePrefix
		entry.ECSAddress = ecs.Address.String()
	}

	// Use binary serialization only for maximum performance
	data, err := serializeToBinary(entry)
	if err != nil {
		LogWarn("CACHE: Binary serialization failed, skipping cache write: %v", err)
		return
	}

	ctx, cancel := context.WithTimeout(rc.ctx, RedisWriteTimeout)
	defer cancel()

	expiration := time.Duration(cacheTTL)*time.Second + time.Duration(StaleMaxAge)*time.Second
	rc.client.Set(ctx, key, data, expiration)
}

func (rc *RedisCache) Close() error {
	if !atomic.CompareAndSwapInt32(&rc.closed, 0, 1) {
		return nil
	}

	LogInfo("CACHE: Shutting down Redis cache")

	rc.cancel()

	// Wait for all goroutines to finish with a timeout
	done := make(chan struct{})
	go func() {
		rc.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		LogDebug("CACHE: All Redis goroutines finished gracefully")
	case <-time.After(5 * time.Second):
		LogWarn("CACHE: Redis goroutine shutdown timeout")
	}

	if err := rc.client.Close(); err != nil {
		LogError("CACHE: Redis client shutdown failed: %v", err)
	}

	LogInfo("CACHE: Redis cache shut down")
	return nil
}

// =============================================================================
// CacheEntry Implementation
// =============================================================================

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
	return c.IsExpired() && (now-c.Timestamp) > refreshInterval
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
// Serialization Helper Functions
// =============================================================================

// serializeToBinary efficiently serializes any value to binary format using gob
func serializeToBinary(v any) ([]byte, error) {
	var buf bytes.Buffer
	encoder := gob.NewEncoder(&buf)

	if err := encoder.Encode(v); err != nil {
		return nil, fmt.Errorf("binary encode: %w", err)
	}

	return buf.Bytes(), nil
}

// deserializeFromBinary efficiently deserializes binary data to any value using gob
func deserializeFromBinary(data []byte, v any) error {
	buf := bytes.NewReader(data)
	decoder := gob.NewDecoder(buf)

	if err := decoder.Decode(v); err != nil {
		return fmt.Errorf("binary decode: %w", err)
	}

	return nil
}

// =============================================================================
// CIDRManager Implementation
// =============================================================================

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
		LogInfo("CIDR: Loaded tag=%s, source=%s, total=%d", config.Tag, sourceInfo, len(rule.nets))
	}

	return cm, nil
}

func (cm *CIDRManager) loadCIDRConfig(config CIDRConfig) (*CIDRRule, error) {
	rule := &CIDRRule{tag: config.Tag, nets: make([]*net.IPNet, 0)}
	validCount := 0

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

	if config.File != "" {
		if !IsValidFilePath(config.File) {
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

// =============================================================================
// CIDRRule Implementation
// =============================================================================

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
// EDNSManager Implementation
// =============================================================================

func NewEDNSManager(defaultSubnet string) (*EDNSManager, error) {
	manager := &EDNSManager{
		detector: &IPDetector{
			httpClient: &http.Client{Timeout: HTTPClientTimeout},
		},
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

func (em *EDNSManager) AddToMessage(msg *dns.Msg, ecs *ECSOption, clientRequestedDNSSEC bool, isSecureConnection bool) {
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
		},
	}

	opt.SetDo()

	var options []dns.EDNS0

	if ecs != nil {
		options = append(options, &dns.EDNS0_SUBNET{
			Code:          dns.EDNS0SUBNET,
			Family:        ecs.Family,
			SourceNetmask: ecs.SourcePrefix,
			SourceScope:   DefaultECSScope,
			Address:       ecs.Address,
		})
	}

	if isSecureConnection {
		opt.Option = options
		msg.Extra = append(msg.Extra, opt)
		if wireData, err := msg.Pack(); err == nil {
			currentSize := len(wireData)
			if currentSize < PaddingSize {
				paddingDataSize := PaddingSize - currentSize - 4
				if paddingDataSize > 0 {
					options = append(options, &dns.EDNS0_PADDING{
						Padding: make([]byte, paddingDataSize),
					})
				}
			}
		}
		msg.Extra = msg.Extra[:len(msg.Extra)-1]
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

// =============================================================================
// IPDetector Implementation
// =============================================================================

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
// RewriteManager Implementation
// =============================================================================

func NewRewriteManager() *RewriteManager {
	rm := &RewriteManager{}
	rm.rules.Store(make([]RewriteRule, 0, 16))
	rm.rulesLen.Store(0)
	return rm
}

func (rm *RewriteManager) LoadRules(rules []RewriteRule) error {
	validRules := make([]RewriteRule, 0, len(rules))
	for _, rule := range rules {
		if len(rule.Name) <= MaxDomainLength {
			validRules = append(validRules, rule)
		}
	}

	rm.rules.Store(validRules)
	rm.rulesLen.Store(int64(len(validRules)))
	LogInfo("REWRITE: DNS rewriter loaded: %d rules", len(validRules))
	return nil
}

func (rm *RewriteManager) hasRules() bool {
	return rm.rulesLen.Load() > 0
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

	// Copy-on-read pattern: get rules snapshot without holding lock
	rules := rm.rules.Load().([]RewriteRule)
	domain = NormalizeDomain(domain)

	for i := range rules {
		rule := &rules[i]
		if domain != NormalizeDomain(rule.Name) {
			continue
		}

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

	// Try to create any type of DNS record using dns.NewRR()
	// This supports ALL DNS record types (MX, NS, SRV, CAA, DNSKEY, etc.)
	rrStr := fmt.Sprintf("%s %d IN %s %s", name, ttl, record.Type, record.Content)
	if rr, err := dns.NewRR(rrStr); err == nil {
		return rr
	}

	// If direct parsing fails, fall back to RFC3597 format
	rrType, exists := dns.StringToType[record.Type]
	if !exists {
		rrType = 0
	}

	return &dns.RFC3597{
		Hdr:   dns.RR_Header{Name: name, Rrtype: rrType, Class: dns.ClassINET, Ttl: ttl},
		Rdata: record.Content,
	}
}

// =============================================================================
// SpeedTestManager Implementation
// =============================================================================

func NewSpeedTestManager(config ServerConfig, redisClient *redis.Client, keyPrefix string) *SpeedTestManager {
	if keyPrefix == "" {
		keyPrefix = config.Redis.KeyPrefix + RedisPrefixSpeedtest
	}

	st := &SpeedTestManager{
		timeout:     DefaultSpeedTimeout,
		concurrency: DefaultSpeedConcurrency,
		redis:       redisClient,
		cacheTTL:    DefaultSpeedTTL,
		keyPrefix:   keyPrefix,
		methods:     config.Speedtest,
	}
	st.initICMP()

	// Start periodic ICMP health check (if ICMP methods are enabled)
	if len(config.Speedtest) > 0 {
		go st.icmpHealthCheckLoop()
	}

	return st
}

func (st *SpeedTestManager) initICMP() {
	st.reinitICMP()
}

func (st *SpeedTestManager) reinitICMP() {
	// Close existing connections
	if st.icmpConn4 != nil {
		_ = st.icmpConn4.Close()
		st.icmpConn4 = nil
	}
	if st.icmpConn6 != nil {
		_ = st.icmpConn6.Close()
		st.icmpConn6 = nil
	}

	// Initialize new connections with proper error handling
	if conn4, err := icmp.ListenPacket("ip4:icmp", ""); err == nil {
		st.icmpConn4 = conn4
		LogDebug("SPEEDTEST: ICMPv4 connection initialized")
	} else {
		LogWarn("SPEEDTEST: Failed to initialize ICMPv4 connection: %v", err)
	}

	if conn6, err := icmp.ListenPacket("ip6:ipv6-icmp", ""); err == nil {
		st.icmpConn6 = conn6
		LogDebug("SPEEDTEST: ICMPv6 connection initialized")
	} else {
		LogWarn("SPEEDTEST: Failed to initialize ICMPv6 connection: %v", err)
	}
}

func (st *SpeedTestManager) getICMPConn(isIPv6 bool) *icmp.PacketConn {
	var conn *icmp.PacketConn
	if isIPv6 {
		conn = st.icmpConn6
	} else {
		conn = st.icmpConn4
	}

	// Check if connection is still valid by attempting to set a deadline
	if conn != nil {
		if err := conn.SetReadDeadline(time.Now().Add(time.Millisecond)); err != nil {
			LogWarn("SPEEDTEST: ICMP connection appears dead, reinitializing: %v", err)
			go st.reinitICMP() // Reinitialize in background
			return nil
		}
		// Reset the deadline to remove the temporary one
		_ = conn.SetReadDeadline(time.Time{})
	}

	return conn
}

func (st *SpeedTestManager) icmpHealthCheckLoop() {
	defer HandlePanic("ICMP health check")

	ticker := time.NewTicker(30 * time.Second) // Health check every 30 seconds
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if atomic.LoadInt32(&st.closed) != 0 {
				return
			}

			// Check both ICMP connections
			if st.icmpConn4 != nil {
				if err := st.icmpConn4.SetReadDeadline(time.Now().Add(time.Millisecond)); err != nil {
					LogWarn("SPEEDTEST: ICMPv4 health check failed, reinitializing: %v", err)
					go st.reinitICMP()
					continue
				}
				_ = st.icmpConn4.SetReadDeadline(time.Time{})
			}

			if st.icmpConn6 != nil {
				if err := st.icmpConn6.SetReadDeadline(time.Now().Add(time.Millisecond)); err != nil {
					LogWarn("SPEEDTEST: ICMPv6 health check failed, reinitializing: %v", err)
					go st.reinitICMP()
					continue
				}
				_ = st.icmpConn6.SetReadDeadline(time.Time{})
			}

		case <-time.After(time.Minute): // Safety timeout
			// If we haven't checked in a minute, exit to avoid goroutine leak
			return
		}
	}
}

func (st *SpeedTestManager) Close() error {
	if !atomic.CompareAndSwapInt32(&st.closed, 0, 1) {
		return nil
	}

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

	response.Answer = append(append(append(cnameRecords, ToRRSlice(aRecords)...), ToRRSlice(aaaaRecords)...), otherRecords...)
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

	if st.redis != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()

		for _, ip := range ips {
			key := st.keyPrefix + ip
			data, err := st.redis.Get(ctx, key).Result()
			if err == nil {
				var result SpeedResult
				// Use binary serialization only for maximum performance
				if deserializeFromBinary([]byte(data), result) == nil {
					if time.Since(result.Timestamp) < st.cacheTTL {
						results[ip] = &result
						continue
					}
				} else {
					// Invalid cache entry - skip it
					continue
				}
			}
			remainingIPs = append(remainingIPs, ip)
		}
	} else {
		remainingIPs = ips
	}

	if len(remainingIPs) == 0 {
		return results
	}

	newResults := st.performSpeedTest(remainingIPs)

	if st.redis != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()

		for ip, result := range newResults {
			key := st.keyPrefix + ip
			// Use binary serialization only for maximum performance
			data, err := serializeToBinary(result)
			if err != nil {
				LogWarn("SPEEDTEST: Binary serialization failed for %s: %v", ip, err)
				continue
			}
			st.redis.Set(ctx, key, data, st.cacheTTL)
		}
	}

	maps.Copy(results, newResults)

	return results
}

func (st *SpeedTestManager) performSpeedTest(ips []string) map[string]*SpeedResult {
	semaphore := make(chan struct{}, st.concurrency)
	resultChan := make(chan *SpeedResult, len(ips))

	g, ctx := errgroup.WithContext(context.Background())
	for _, ip := range ips {
		testIP := ip
		g.Go(func() error {
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			// Create a reusable timer for this goroutine
			timer := time.NewTimer(st.timeout)
			defer timer.Stop()

			if result := st.testSingleIP(testIP); result != nil {
				select {
				case resultChan <- result:
				case <-timer.C:
					LogDebug("SPEEDTEST: Drop result for %s due to timeout", testIP)
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			return nil
		})
	}

	go func() {
		_ = g.Wait()
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
			return result
		}
	}

	result.Reachable = false
	result.Latency = st.timeout
	return result
}

func (st *SpeedTestManager) pingWithICMP(ip string, timeout time.Duration) time.Duration {
	dst, err := net.ResolveIPAddr("ip", ip)
	if err != nil {
		return -1
	}

	var icmpType icmp.Type
	isIPv6 := dst.IP.To4() == nil

	if isIPv6 {
		icmpType = ipv6.ICMPTypeEchoRequest
	} else {
		icmpType = ipv4.ICMPTypeEcho
	}

	// Get connection with health checking
	conn := st.getICMPConn(isIPv6)
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
		// If write fails, the connection might be dead
		if !IsTemporaryError(err) {
			LogWarn("SPEEDTEST: ICMP write failed permanently, triggering reinit: %v", err)
			go st.reinitICMP()
		}
		return -1
	}

	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	rb := make([]byte, 1500)
	n, _, err := conn.ReadFrom(rb)
	if err != nil {
		// If read fails due to timeout or connection error, trigger reinit for permanent errors
		if !IsTemporaryError(err) {
			LogWarn("SPEEDTEST: ICMP read failed permanently, triggering reinit: %v", err)
			go st.reinitICMP()
		}
		return -1
	}

	protocol := 1
	if dst.IP.To4() == nil {
		protocol = 58
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
// RootServerManager Implementation
// =============================================================================

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

	sorted := make([]RootServerWithLatency, len(rsm.servers))
	for i, server := range rsm.servers {
		sorted[i] = RootServerWithLatency{
			Server:    server,
			Latency:   UnreachableLatency,
			Reachable: false,
		}
	}
	// Initialize with default values - ensures atomic consistency from startup
	initialResult := &RootServerSortResult{
		SortedServers: sorted,
		SortTime:      time.Time{}, // Zero time indicates no sorting has occurred yet
	}
	rsm.sortResult.Store(initialResult)

	if needsRecursive {
		dnsSpeedTestConfig := config
		dnsSpeedTestConfig.Speedtest = []SpeedTestMethod{
			{Type: "icmp", Timeout: int(DefaultSpeedTimeout.Milliseconds())},
			{Type: "tcp", Port: DefaultDNSPort, Timeout: int(DefaultSpeedTimeout.Milliseconds())},
		}

		rootServerPrefix := config.Redis.KeyPrefix + RedisPrefixSpeedtest
		rsm.speedTester = NewSpeedTestManager(dnsSpeedTestConfig, redisClient, rootServerPrefix)
		rsm.speedTester.cacheTTL = DefaultSpeedTTL

		go rsm.sortServersBySpeed()
		LogInfo("SPEEDTEST: Root server speed testing enabled")
	}

	return rsm
}

func (rsm *RootServerManager) GetOptimalRootServers() []RootServerWithLatency {
	// Load the sort result with type checking and fallback
	if result, ok := rsm.sortResult.Load().(*RootServerSortResult); ok && result != nil {
		// Create a copy to avoid race conditions
		serversCopy := make([]RootServerWithLatency, len(result.SortedServers))
		copy(serversCopy, result.SortedServers)
		return serversCopy
	}

	// Fallback: return empty slice if no data is available
	// This prevents runtime crashes and ensures graceful degradation
	return []RootServerWithLatency{}
}

// GetLastSortTime returns the timestamp of the last sort operation
// Returns zero time.Time if no sort has been performed yet
func (rsm *RootServerManager) GetLastSortTime() time.Time {
	if result, ok := rsm.sortResult.Load().(*RootServerSortResult); ok && result != nil {
		return result.SortTime
	}
	return time.Time{} // Return zero time as fallback
}

func (rsm *RootServerManager) sortServersBySpeed() {
	defer HandlePanic("Root server speed sorting")

	if !rsm.needsSpeed || rsm.speedTester == nil {
		return
	}

	ips := ExtractIPsFromServers(rsm.servers)
	results := rsm.speedTester.speedTest(ips)
	sortedWithLatency := SortBySpeedResultWithLatency(rsm.servers, results)

	// Store both the sorted servers and timestamp atomically as one unit
	// This ensures consistency when reading both values together
	sortResult := &RootServerSortResult{
		SortedServers: sortedWithLatency,
		SortTime:      time.Now(),
	}
	rsm.sortResult.Store(sortResult)
}

func (rsm *RootServerManager) StartPeriodicSorting(ctx context.Context) {
	if !rsm.needsSpeed {
		return
	}

	ticker := time.NewTicker(RootServerRefresh)
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
// Security: DNSSECValidator Implementation
// =============================================================================

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

// =============================================================================
// Security: HijackPrevention Implementation
// =============================================================================

func (hp *HijackPrevention) IsEnabled() bool {
	return hp.enabled
}

func (hp *HijackPrevention) CheckResponse(currentDomain, queryDomain string, response *dns.Msg) (bool, string) {
	if !hp.enabled || response == nil {
		return true, ""
	}

	currentDomain = NormalizeDomain(currentDomain)
	queryDomain = NormalizeDomain(queryDomain)

	for _, rr := range response.Answer {
		answerName := NormalizeDomain(rr.Header().Name)
		rrType := rr.Header().Rrtype

		if answerName != queryDomain {
			continue
		}

		if rrType == dns.TypeNS || rrType == dns.TypeDS {
			continue
		}

		if valid, reason := hp.validateAnswer(currentDomain, queryDomain, rrType); !valid {
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
// SecurityManager Implementation
// =============================================================================

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

// =============================================================================
// TLS Manager: Certificate Generation
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
		NotAfter:              time.Now().Add(90 * 24 * time.Hour),
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
		NotAfter:    time.Now().Add(90 * 24 * time.Hour),
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

	return cert, nil
}

// =============================================================================
// TLSManager Implementation
// =============================================================================

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
		Certificates:           []tls.Certificate{cert},
		MinVersion:             tls.VersionTLS13,
		SessionTicketsDisabled: false,
	}

	ctx, cancel := context.WithCancel(context.Background())

	tm := &TLSManager{
		server:    server,
		tlsConfig: tlsConfig,
		ctx:       ctx,
		cancel:    cancel,
	}

	tm.displayCertificateInfo(cert)

	return tm, nil
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

func (tm *TLSManager) Start(httpsPort string) error {
	errChan := make(chan error, 1)

	g, ctx := errgroup.WithContext(context.Background())

	if httpsPort != "" {
		g.Go(func() error {
			defer HandlePanic("DoH server")
			if err := tm.startDOHServer(httpsPort); err != nil {
				return fmt.Errorf("DoH startup: %w", err)
			}
			<-ctx.Done()
			return nil
		})

		g.Go(func() error {
			defer HandlePanic("DoH3 server")
			if err := tm.startDoH3Server(httpsPort); err != nil {
				return fmt.Errorf("DoH3 startup: %w", err)
			}
			<-ctx.Done()
			return nil
		})
	}

	g.Go(func() error {
		defer HandlePanic("DoT server")
		if err := tm.startDOTServer(); err != nil {
			return fmt.Errorf("DoT startup: %w", err)
		}
		<-ctx.Done()
		return nil
	})

	g.Go(func() error {
		defer HandlePanic("DoQ server")
		if err := tm.startDOQServer(); err != nil {
			return fmt.Errorf("DoQ startup: %w", err)
		}
		<-ctx.Done()
		return nil
	})

	go func() {
		defer HandlePanic("TLS manager coordinator")
		if err := g.Wait(); err != nil {
			select {
			case errChan <- err:
			default:
			}
		}
		close(errChan)
	}()

	for err := range errChan {
		if err != nil {
			return err
		}
	}

	return nil
}

// =============================================================================
// TLSManager: DoT (DNS over TLS) Implementation
// =============================================================================

func (tm *TLSManager) startDOTServer() error {
	listener, err := net.Listen("tcp", ":"+tm.server.config.Server.TLS.Port)
	if err != nil {
		return fmt.Errorf("DoT listen: %w", err)
	}

	dotTLSConfig := tm.tlsConfig.Clone()
	dotTLSConfig.NextProtos = NextProtoDOT

	tm.dotListener = tls.NewListener(listener, dotTLSConfig)
	LogInfo("DOT: DoT server started on port %s", tm.server.config.Server.TLS.Port)

	go func() {
		defer HandlePanic("DoT server")
		tm.handleDOTConnections()
	}()

	return nil
}

func (tm *TLSManager) handleDOTConnections() {
	for {
		select {
		case <-tm.ctx.Done():
			return
		default:
		}

		conn, err := tm.dotListener.Accept()
		if err != nil {
			if tm.ctx.Err() != nil {
				return
			}
			LogError("DOT: Accept error: %v", err)
			continue
		}

		go func(c net.Conn) {
			defer HandlePanic("DoT connection handler")
			defer func() { _ = c.Close() }()
			tm.handleDOTConnection(c)
		}(conn)
	}
}

func (tm *TLSManager) handleDOTConnection(conn net.Conn) {
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return
	}

	_ = tlsConn.SetReadDeadline(time.Now().Add(DoTReadTimeout))
	_ = tlsConn.SetWriteDeadline(time.Now().Add(DoTWriteTimeout))

	reader := bufio.NewReaderSize(tlsConn, 2048)

	for {
		select {
		case <-tm.ctx.Done():
			return
		default:
		}

		_ = tlsConn.SetReadDeadline(time.Now().Add(DoTReadTimeout))
		_ = tlsConn.SetWriteDeadline(time.Now().Add(DoTWriteTimeout))

		lengthBuf := make([]byte, 2)
		n, err := io.ReadFull(reader, lengthBuf)
		if err != nil {
			if err != io.EOF && !IsTemporaryError(err) {
				LogDebug("DOT: Read length error: %v", err)
			}
			return
		}
		if n != 2 {
			LogDebug("DOT: Invalid length read: %d bytes", n)
			return
		}

		msgLength := binary.BigEndian.Uint16(lengthBuf)
		if msgLength == 0 || msgLength > TCPBufferSize {
			LogWarn("DOT: Invalid message length: %d", msgLength)
			return
		}

		msgBuf := make([]byte, msgLength)
		n, err = io.ReadFull(reader, msgBuf)
		if err != nil {
			LogDebug("DOT: Read message error: %v", err)
			return
		}
		if n != int(msgLength) {
			LogDebug("DOT: Incomplete message read: %d/%d bytes", n, msgLength)
			return
		}

		req := new(dns.Msg)
		if err := req.Unpack(msgBuf); err != nil {
			LogDebug("DOT: DNS message unpack error: %v", err)
			continue
		}

		var clientIP net.IP
		if addr := tlsConn.RemoteAddr(); addr != nil {
			clientIP = addr.(*net.TCPAddr).IP
		}
		response := tm.server.processDNSQuery(req, clientIP, true)

		if response != nil {
			respBuf, err := response.Pack()
			if err != nil {
				LogDebug("DOT: Response pack error: %v", err)
				return
			}

			lengthBuf := make([]byte, 2)
			binary.BigEndian.PutUint16(lengthBuf, uint16(len(respBuf)))

			if _, err := tlsConn.Write(lengthBuf); err != nil {
				LogDebug("DOT: Write length error: %v", err)
				return
			}

			if _, err := tlsConn.Write(respBuf); err != nil {
				LogDebug("DOT: Write response error: %v", err)
				return
			}
		}
	}
}

// =============================================================================
// TLSManager: DoQ (DNS over QUIC) Implementation
// =============================================================================

func (tm *TLSManager) startDOQServer() error {
	addr := ":" + tm.server.config.Server.TLS.Port

	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return fmt.Errorf("resolve UDP address: %w", err)
	}

	tm.doqConn, err = net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("UDP listen: %w", err)
	}

	tm.doqTransport = &quic.Transport{
		Conn: tm.doqConn,
	}

	quicTLSConfig := tm.tlsConfig.Clone()
	quicTLSConfig.NextProtos = NextProtoDoQ

	quicConfig := &quic.Config{
		MaxIdleTimeout:        SecureIdleTimeout,
		MaxIncomingStreams:    MaxIncomingStreams / 2,
		MaxIncomingUniStreams: MaxIncomingStreams / 4,
		Allow0RTT:             true,
		EnableDatagrams:       true,
		KeepAlivePeriod:       ConnKeepAlive,
	}

	tm.doqListener, err = tm.doqTransport.ListenEarly(quicTLSConfig, quicConfig)
	if err != nil {
		_ = tm.doqConn.Close()
		return fmt.Errorf("DoQ listen: %w", err)
	}

	LogInfo("DOQ: DoQ server started on port %s", tm.server.config.Server.TLS.Port)

	go func() {
		defer HandlePanic("DoQ server")
		tm.handleDOQConnections()
	}()

	return nil
}

func (tm *TLSManager) handleDOQConnections() {
	for {
		select {
		case <-tm.ctx.Done():
			return
		default:
		}

		conn, err := tm.doqListener.Accept(tm.ctx)
		if err != nil {
			if tm.ctx.Err() != nil {
				return
			}
			continue
		}

		if conn == nil {
			continue
		}

		go func(quicConn *quic.Conn) {
			defer HandlePanic("DoQ connection handler")
			tm.handleDOQConnection(quicConn)
		}(conn)
	}
}

func (tm *TLSManager) handleDOQConnection(conn *quic.Conn) {
	if conn == nil {
		return
	}

	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), ConnCloseTimeout)
		defer cancel()

		_ = conn.CloseWithError(QUICCodeNoError, "")

		done := make(chan struct{})
		go func() {
			<-conn.Context().Done()
			close(done)
		}()

		select {
		case <-done:
		case <-ctx.Done():
			LogDebug("QUIC: Connection close timeout")
		}
	}()

	g, streamCtx := errgroup.WithContext(tm.ctx)

	g.SetLimit(MaxIncomingStreams / 2)

	acceptDone := make(chan struct{})
	g.Go(func() error {
		defer close(acceptDone)
		for {
			select {
			case <-tm.ctx.Done():
				return tm.ctx.Err()
			case <-conn.Context().Done():
				return conn.Context().Err()
			default:
			}

			stream, err := conn.AcceptStream(streamCtx)
			if err != nil {
				if streamCtx.Err() != nil {
					return streamCtx.Err()
				}
				return err
			}

			if stream == nil {
				continue
			}

			s := stream
			g.Go(func() error {
				defer HandlePanic("DoQ stream handler")
				defer func() { _ = s.Close() }()
				tm.handleDOQStream(s, conn)
				return nil
			})
		}
	})

	if err := g.Wait(); err != nil && err != context.Canceled {
		LogDebug("QUIC: Connection handler error: %v", err)
	}
}

func (tm *TLSManager) handleDOQStream(stream *quic.Stream, conn *quic.Conn) {
	buf := make([]byte, SecureBufferSize)
	n, err := io.ReadFull(stream, buf[:2])
	if err != nil || n < 2 {
		return
	}

	msgLen := binary.BigEndian.Uint16(buf[:2])
	if msgLen == 0 || msgLen > SecureBufferSize-2 {
		_ = conn.CloseWithError(QUICCodeProtocolError, "invalid length")
		return
	}

	n, err = io.ReadFull(stream, buf[2:2+msgLen])
	if err != nil || n != int(msgLen) {
		return
	}

	req := new(dns.Msg)
	if err := req.Unpack(buf[2 : 2+msgLen]); err != nil {
		_ = conn.CloseWithError(QUICCodeProtocolError, "invalid DNS message")
		return
	}

	clientIP := GetSecureClientIP(conn)
	response := tm.server.processDNSQuery(req, clientIP, true)

	if err := tm.respondQUIC(stream, response); err != nil {
		LogDebug("PROTOCOL: DoQ response failed: %v", err)
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

// =============================================================================
// TLSManager: DoH (DNS over HTTPS) Implementation
// =============================================================================

func (tm *TLSManager) startDOHServer(port string) error {
	listener, err := net.Listen("tcp", ":"+port)
	if err != nil {
		return fmt.Errorf("DoH listen: %w", err)
	}

	tlsConfig := tm.tlsConfig.Clone()
	tlsConfig.NextProtos = NextProtoDoH

	tm.httpsListener = tls.NewListener(listener, tlsConfig)
	LogInfo("DOH: DoH server started on port %s", port)

	tm.httpsServer = &http.Server{
		Handler:           tm,
		ReadHeaderTimeout: DoHReadHeaderTimeout,
		WriteTimeout:      DoHWriteTimeout,
		IdleTimeout:       DoTIdleTimeout,
	}

	go func() {
		defer HandlePanic("DoH server")
		if err := tm.httpsServer.Serve(tm.httpsListener); err != nil && err != http.ErrServerClosed {
			LogError("DOH: DoH server error: %v", err)
		}
	}()

	return nil
}

func (tm *TLSManager) startDoH3Server(port string) error {
	addr := ":" + port

	tlsConfig := tm.tlsConfig.Clone()
	tlsConfig.NextProtos = NextProtoDoH3

	quicConfig := &quic.Config{
		MaxIdleTimeout:        SecureIdleTimeout,
		MaxIncomingStreams:    MaxIncomingStreams / 2,
		MaxIncomingUniStreams: MaxIncomingStreams / 4,
		Allow0RTT:             true,
		EnableDatagrams:       true,
		KeepAlivePeriod:       ConnKeepAlive,
	}

	quicListener, err := quic.ListenAddrEarly(addr, tlsConfig, quicConfig)
	if err != nil {
		return fmt.Errorf("DoH3 listen: %w", err)
	}

	tm.h3Listener = quicListener
	LogInfo("DOH3: DoH3 server started on port %s", port)

	tm.h3Server = &http3.Server{Handler: tm}

	go func() {
		defer HandlePanic("DoH3 server")
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

func (tm *TLSManager) shutdown() error {
	LogInfo("TLS: Shutting down secure DNS server")

	tm.cancel()

	if tm.dotListener != nil {
		CloseWithLog(tm.dotListener, "DoT listener")
	}
	if tm.doqListener != nil {
		CloseWithLog(tm.doqListener, "DoQ listener")
	}
	if tm.doqConn != nil {
		CloseWithLog(tm.doqConn, "DoQ connection")
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
		CloseWithLog(tm.httpsListener, "HTTPS listener")
	}
	if tm.h3Listener != nil {
		CloseWithLog(tm.h3Listener, "HTTP/3 listener")
	}

	tm.wg.Wait()
	LogInfo("TLS: Secure DNS server shut down")
	return nil
}

// =============================================================================
// RequestTracker Implementation
// =============================================================================

func NewRequestTracker(domain, qtype, clientIP string) *RequestTracker {
	rt := &RequestTracker{
		ID:        fmt.Sprintf("%x", time.Now().UnixNano()&0xFFFFFF),
		StartTime: time.Now(),
		Domain:    domain,
		QueryType: qtype,
		ClientIP:  clientIP,
	}
	rt.Upstream.Store("") // Initialize with empty string
	return rt
}

func (rt *RequestTracker) AddStep(step string, args ...any) {
	if rt == nil || globalLog.GetLevel() < Debug {
		return
	}

	timestamp := time.Since(rt.StartTime)
	stepMsg := fmt.Sprintf("[%v] %s", timestamp.Truncate(time.Microsecond), fmt.Sprintf(step, args...))
	LogDebug("[%s] %s", rt.ID, stepMsg)
}

func (rt *RequestTracker) Finish() {
	if rt == nil {
		return
	}
	rt.ResponseTime = time.Since(rt.StartTime)
	if globalLog.GetLevel() >= Info {
		upstream, _ := rt.Upstream.Load().(string)
		if upstream == "" {
			upstream = RecursiveIndicator
		}
		LogDebug("FINISH [%s]: Query completed: %s %s | Time:%v | Upstream:%s",
			rt.ID, rt.Domain, rt.QueryType, rt.ResponseTime.Truncate(time.Microsecond), upstream)
	}
}

// =============================================================================
// DNSServer Implementation
// =============================================================================

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

	connPool := NewConnPool()

	var redisClient *redis.Client
	var cache CacheManager
	if config.Redis.Address == "" {
		cache = NewNullCache()
	} else {
		redisCache, err := NewRedisCache(config)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("redis cache init: %w", err)
		}
		cache = redisCache
		redisClient = redisCache.client
	}

	rootServerManager := NewRootServerManager(*config, redisClient)

	server := &DNSServer{
		config:        config,
		rootServerMgr: rootServerManager,
		ednsMgr:       ednsManager,
		rewriteMgr:    rewriteManager,
		cidrMgr:       cidrManager,
		connPool:      connPool,
		redisClient:   redisClient,
		cacheMgr:      cache,
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

	queryClient := NewQueryClient(connPool)
	server.queryClient = queryClient

	queryManager := NewQueryManager(server)
	if err := queryManager.Initialize(config.Upstream); err != nil {
		cancel()
		return nil, fmt.Errorf("query manager init: %w", err)
	}
	server.queryMgr = queryManager

	if len(config.Speedtest) > 0 {
		domainSpeedPrefix := config.Redis.KeyPrefix + RedisPrefixSpeedtest
		server.speedTestMgr = NewSpeedTestManager(*config, redisClient, domainSpeedPrefix)
	}

	if config.Server.Pprof != "" {
		server.pprofServer = &http.Server{
			Addr:              ":" + config.Server.Pprof,
			ReadHeaderTimeout: PprofReadHeaderTimeout,
			ReadTimeout:       PprofReadTimeout,
			IdleTimeout:       PprofIdleTimeout,
		}

		if server.securityMgr != nil && server.securityMgr.tls != nil {
			server.pprofServer.TLSConfig = server.securityMgr.tls.tlsConfig
		}
	}

	server.setupSignalHandling()

	return server, nil
}

// =============================================================================
// DNSServer: Lifecycle Management Implementation
// =============================================================================

func (s *DNSServer) setupSignalHandling() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		defer HandlePanic("Root server periodic sorting")
		s.rootServerMgr.StartPeriodicSorting(s.ctx)
	}()

	go func() {
		defer HandlePanic("Signal handler")
		select {
		case sig := <-sigChan:
			LogInfo("SIGNAL: Received signal %v, starting graceful shutdown", sig)
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

	LogInfo("SERVER: Starting DNS server shutdown")

	if s.cancel != nil {
		s.cancel()
	}

	if s.cacheMgr != nil {
		CloseWithLog(s.cacheMgr, "Cache manager")
	}

	if s.securityMgr != nil {
		if err := s.securityMgr.Shutdown(ShutdownTimeout); err != nil {
			LogError("SECURITY: Security manager shutdown failed: %v", err)
		}
	}

	if s.connPool != nil {
		CloseWithLog(s.connPool, "Connection pool")
	}

	if s.speedTestMgr != nil {
		CloseWithLog(s.speedTestMgr, "SpeedTest manager")
	}

	if s.pprofServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), ShutdownTimeout)
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

	errChan := make(chan error, 1)
	serverCtx, serverCancel := context.WithCancel(context.Background())
	defer serverCancel()

	LogInfo("SERVER: Starting ZJDNS Server %s", getVersion())
	LogInfo("SERVER: Listening on port: %s", s.config.Server.Port)

	s.displayInfo()

	g, ctx := errgroup.WithContext(serverCtx)

	g.Go(func() error {
		defer HandlePanic("UDP server")
		server := &dns.Server{
			Addr:    ":" + s.config.Server.Port,
			Net:     "udp",
			Handler: dns.HandlerFunc(s.handleDNSRequest),
			UDPSize: UDPBufferSize,
		}
		LogInfo("DNS: UDP server started on port %s", s.config.Server.Port)
		err := server.ListenAndServe()
		if err != nil {
			return fmt.Errorf("UDP startup: %w", err)
		}
		<-ctx.Done()
		return nil
	})

	if s.pprofServer != nil {
		g.Go(func() error {
			defer HandlePanic("pprof server")
			LogInfo("PPROF: pprof server started on port %s", s.config.Server.Pprof)
			var err error
			if s.pprofServer.TLSConfig != nil {
				err = s.pprofServer.ListenAndServeTLS("", "")
			} else {
				err = s.pprofServer.ListenAndServe()
			}

			if err != nil && err != http.ErrServerClosed {
				return fmt.Errorf("pprof startup: %w", err)
			}
			<-ctx.Done()
			return nil
		})
	}

	g.Go(func() error {
		defer HandlePanic("TCP server")
		server := &dns.Server{
			Addr:    ":" + s.config.Server.Port,
			Net:     "tcp",
			Handler: dns.HandlerFunc(s.handleDNSRequest),
		}
		LogInfo("DNS: TCP server started on port %s", s.config.Server.Port)
		err := server.ListenAndServe()
		if err != nil {
			return fmt.Errorf("TCP startup: %w", err)
		}
		<-ctx.Done()
		return nil
	})

	if s.securityMgr.tls != nil {
		g.Go(func() error {
			defer HandlePanic("Secure DNS server")
			httpsPort := s.config.Server.TLS.HTTPS.Port
			err := s.securityMgr.tls.Start(httpsPort)
			if err != nil {
				return fmt.Errorf("secure DNS startup: %w", err)
			}
			<-ctx.Done()
			return nil
		})
	}

	go func() {
		defer HandlePanic("Server coordinator")
		if err := g.Wait(); err != nil {
			select {
			case errChan <- err:
			default:
			}
		}
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
				if server.SkipTLSVerify && IsSecureProtocol(strings.ToLower(server.Protocol)) {
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
		LogInfo("TLS: Listening on port: %s (DoT/DoQ)", s.config.Server.TLS.Port)
		httpsPort := s.config.Server.TLS.HTTPS.Port
		if httpsPort != "" {
			endpoint := s.config.Server.TLS.HTTPS.Endpoint
			if endpoint == "" {
				endpoint = strings.TrimPrefix(DefaultQueryPath, "/")
			}
			LogInfo("TLS: Listening on port: %s (DoH/DoH3, endpoint: %s)", httpsPort, endpoint)
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

	if len(s.config.Speedtest) > 0 {
		if s.redisClient != nil {
			LogInfo("SPEEDTEST: SpeedTest: enabled (with Redis caching)")
		} else {
			LogInfo("SPEEDTEST: SpeedTest: enabled (no caching)")
		}
	}

	if s.rootServerMgr.needsSpeed {
		LogInfo("SPEEDTEST: Root server speed testing: enabled")
	}
}

// =============================================================================
// DNSServer: Query Processing Implementation
// =============================================================================

func (s *DNSServer) handleDNSRequest(w dns.ResponseWriter, req *dns.Msg) {
	defer HandlePanic("DNS request processing")

	select {
	case <-s.ctx.Done():
		return
	default:
	}

	response := s.processDNSQuery(req, GetClientIP(w), false)
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
	var ecsOpt *ECSOption

	if opt := req.IsEdns0(); opt != nil {
		clientRequestedDNSSEC = opt.Do()
		ecsOpt = s.ednsMgr.ParseFromDNS(req)
	}

	if ecsOpt == nil {
		ecsOpt = s.ednsMgr.GetDefaultECS()
	}

	cacheKey := BuildCacheKey(question, ecsOpt, clientRequestedDNSSEC, s.config.Redis.KeyPrefix)

	if entry, found, isExpired := s.cacheMgr.Get(cacheKey); found {
		return s.processCacheHit(req, entry, isExpired, question, clientRequestedDNSSEC, ecsOpt, cacheKey, isSecureConnection)
	}

	return s.processCacheMiss(req, question, ecsOpt, clientRequestedDNSSEC, cacheKey, isSecureConnection, tracker)
}

func (s *DNSServer) processCacheHit(req *dns.Msg, entry *CacheEntry, isExpired bool, question dns.Question, clientRequestedDNSSEC bool, ecsOpt *ECSOption, cacheKey string, isSecureConnection bool) *dns.Msg {
	responseTTL := entry.GetRemainingTTL()

	msg := s.buildResponse(req)
	if msg == nil {
		msg = &dns.Msg{}
		msg.SetReply(req)
		msg.Rcode = dns.RcodeServerFailure
		return msg
	}

	msg.Answer = ProcessRecords(ExpandRecords(entry.Answer), responseTTL, clientRequestedDNSSEC)
	msg.Ns = ProcessRecords(ExpandRecords(entry.Authority), responseTTL, clientRequestedDNSSEC)
	msg.Extra = ProcessRecords(ExpandRecords(entry.Additional), responseTTL, clientRequestedDNSSEC)

	if entry.Validated {
		msg.AuthenticatedData = true
	}

	s.addEDNS(msg, req, isSecureConnection)

	if isExpired && entry.ShouldRefresh() {
		go func() {
			defer HandlePanic("cache refresh")
			ctx, cancel := context.WithTimeout(context.Background(), QueryTimeout)
			defer cancel()
			_ = s.refreshCacheEntry(ctx, question, ecsOpt, cacheKey, entry)
		}()
	}

	s.restoreOriginalDomain(msg, req.Question[0].Name, question.Name)

	return msg
}

func (s *DNSServer) processCacheMiss(req *dns.Msg, question dns.Question, ecsOpt *ECSOption, clientRequestedDNSSEC bool, cacheKey string, isSecureConnection bool, tracker *RequestTracker) *dns.Msg {
	answer, authority, additional, validated, ecsResponse, usedServer, err := s.queryMgr.Query(question, ecsOpt)

	if tracker != nil {
		tracker.Upstream.Store(usedServer)
	}

	if err != nil {
		return s.processQueryError(req, cacheKey, question, clientRequestedDNSSEC, ecsOpt, isSecureConnection)
	}

	return s.processQuerySuccess(req, question, ecsOpt, clientRequestedDNSSEC, cacheKey, answer, authority, additional, validated, ecsResponse, isSecureConnection)
}

func (s *DNSServer) refreshCacheEntry(_ context.Context, question dns.Question, ecs *ECSOption, cacheKey string, _ *CacheEntry) error {
	defer HandlePanic("cache refresh")

	if atomic.LoadInt32(&s.closed) != 0 {
		return errors.New("server closed")
	}

	answer, authority, additional, validated, ecsResponse, _, err := s.queryMgr.Query(question, ecs)

	if err != nil {
		return err
	}

	if len(s.config.Speedtest) > 0 &&
		(question.Qtype == dns.TypeA || question.Qtype == dns.TypeAAAA) {
		tempMsg := &dns.Msg{Answer: answer, Ns: authority, Extra: additional}
		domainSpeedPrefix := s.config.Redis.KeyPrefix + RedisPrefixSpeedtest
		speedTester := NewSpeedTestManager(*s.config, s.redisClient, domainSpeedPrefix)
		speedTester.performSpeedTestAndSort(tempMsg)
		_ = speedTester.Close()
		answer, authority, additional = tempMsg.Answer, tempMsg.Ns, tempMsg.Extra
	}

	s.cacheMgr.Set(cacheKey, answer, authority, additional, validated, ecsResponse)

	return nil
}

func (s *DNSServer) processQueryError(req *dns.Msg, cacheKey string, question dns.Question, clientRequestedDNSSEC bool, _ *ECSOption, isSecureConnection bool) *dns.Msg {
	if entry, found, _ := s.cacheMgr.Get(cacheKey); found {
		msg := s.buildResponse(req)
		if msg == nil {
			msg = &dns.Msg{}
			msg.SetReply(req)
			msg.Rcode = dns.RcodeServerFailure
			return msg
		}

		responseTTL := uint32(StaleTTL)
		msg.Answer = ProcessRecords(ExpandRecords(entry.Answer), responseTTL, clientRequestedDNSSEC)
		msg.Ns = ProcessRecords(ExpandRecords(entry.Authority), responseTTL, clientRequestedDNSSEC)
		msg.Extra = ProcessRecords(ExpandRecords(entry.Additional), responseTTL, clientRequestedDNSSEC)

		if entry.Validated {
			msg.AuthenticatedData = true
		}

		s.addEDNS(msg, req, isSecureConnection)
		s.restoreOriginalDomain(msg, req.Question[0].Name, question.Name)
		return msg
	}

	msg := s.buildResponse(req)
	if msg == nil {
		msg = &dns.Msg{}
		msg.SetReply(req)
	}
	msg.Rcode = dns.RcodeServerFailure
	return msg
}

func (s *DNSServer) processQuerySuccess(req *dns.Msg, question dns.Question, ecsOpt *ECSOption, clientRequestedDNSSEC bool, cacheKey string, answer, authority, additional []dns.RR, validated bool, ecsResponse *ECSOption, isSecureConnection bool) *dns.Msg {
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

	msg.Answer = ProcessRecords(answer, 0, clientRequestedDNSSEC)
	msg.Ns = ProcessRecords(authority, 0, clientRequestedDNSSEC)
	msg.Extra = ProcessRecords(additional, 0, clientRequestedDNSSEC)

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

	shouldAddEDNS := ecsOpt != nil || clientRequestedDNSSEC || true

	if shouldAddEDNS {
		s.ednsMgr.AddToMessage(msg, ecsOpt, clientRequestedDNSSEC, isSecureConnection)
	}
}

func (s *DNSServer) buildResponse(req *dns.Msg) *dns.Msg {
	msg := AcquireMessage()
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

func (s *DNSServer) buildQueryMessage(question dns.Question, ecs *ECSOption, recursionDesired bool, isSecureConnection bool) *dns.Msg {
	msg := AcquireMessage()
	if msg == nil {
		msg = &dns.Msg{}
	}

	msg.SetQuestion(dns.Fqdn(question.Name), question.Qtype)
	msg.RecursionDesired = recursionDesired

	if s.ednsMgr != nil {
		s.ednsMgr.AddToMessage(msg, ecs, true, isSecureConnection)
	}

	return msg
}

// =============================================================================
// QueryManager Implementation
// =============================================================================

func NewQueryManager(server *DNSServer) *QueryManager {
	return &QueryManager{
		upstream: &UpstreamHandler{servers: make([]*UpstreamServer, 0)},
		recursive: &RecursiveResolver{
			server:        server,
			rootServerMgr: server.rootServerMgr,
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

func (qm *QueryManager) Query(question dns.Question, ecs *ECSOption) ([]dns.RR, []dns.RR, []dns.RR, bool, *ECSOption, string, error) {
	servers := qm.upstream.getServers()
	if len(servers) > 0 {
		return qm.queryUpstream(question, ecs)
	}
	ctx, cancel := context.WithTimeout(qm.server.ctx, RecursiveTimeout)
	defer cancel()

	answer, authority, additional, validated, ecsResponse, server, err := qm.cname.resolveWithCNAME(ctx, question, ecs)
	return answer, authority, additional, validated, ecsResponse, server, err
}

// =============================================================================
// UpstreamServer Implementation
// =============================================================================

func (s *UpstreamServer) IsRecursive() bool {
	if s == nil {
		return false
	}
	return s.Address == RecursiveIndicator
}

// =============================================================================
// UpstreamHandler Implementation
// =============================================================================

func (uh *UpstreamHandler) getServers() []*UpstreamServer {
	uh.mu.RLock()
	defer uh.mu.RUnlock()
	return uh.servers
}

func (qm *QueryManager) queryUpstream(question dns.Question, ecs *ECSOption) ([]dns.RR, []dns.RR, []dns.RR, bool, *ECSOption, string, error) {
	servers := qm.upstream.getServers()
	if len(servers) == 0 {
		return nil, nil, nil, false, nil, "", errors.New("no upstream servers")
	}

	maxConcurrent := min(len(servers), MaxSingleQuery)

	ctx, cancel := context.WithTimeout(qm.server.ctx, QueryTimeout)
	defer cancel()

	resultChan := make(chan UpstreamQueryResult, 1)

	g, ctx := errgroup.WithContext(ctx)

	for i := 0; i < maxConcurrent && i < len(servers); i++ {
		srv := servers[i]

		g.Go(func() error {
			defer HandlePanic("Query upstream")

			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			if srv.IsRecursive() {
				recursiveCtx, recursiveCancel := context.WithTimeout(ctx, RecursiveTimeout)
				defer recursiveCancel()

				answer, authority, additional, validated, ecsResponse, usedServer, err := qm.cname.resolveWithCNAME(recursiveCtx, question, ecs)

				if err == nil && len(answer) > 0 {
					if len(srv.Match) > 0 {
						filteredAnswer, shouldRefuse := qm.filterRecordsByCIDR(answer, srv.Match)
						if shouldRefuse {
							return nil
						}
						answer = filteredAnswer
					}

					select {
					case resultChan <- UpstreamQueryResult{
						answer:     answer,
						authority:  authority,
						additional: additional,
						validated:  validated,
						ecs:        ecsResponse,
						server:     usedServer,
					}:
						return nil
					case <-ctx.Done():
						return ctx.Err()
					}
				}
			} else {
				msg := qm.server.buildQueryMessage(question, ecs, true, false)
				defer ReleaseMessage(msg)

				queryResult := qm.server.queryClient.ExecuteQuery(ctx, msg, srv)

				if queryResult.Error != nil {
					return nil
				}

				if queryResult.Response != nil {
					rcode := queryResult.Response.Rcode

					if rcode == dns.RcodeSuccess || rcode == dns.RcodeNameError {
						if len(srv.Match) > 0 {
							filteredAnswer, shouldRefuse := qm.filterRecordsByCIDR(queryResult.Response.Answer, srv.Match)
							if shouldRefuse {
								return nil
							}
							queryResult.Response.Answer = filteredAnswer
						}

						queryResult.Validated = qm.validator.dnssecValidator.ValidateResponse(queryResult.Response, true)
						ecsResponse := qm.server.ednsMgr.ParseFromDNS(queryResult.Response)

						serverDesc := srv.Address
						if srv.Protocol != "" && srv.Protocol != "udp" {
							serverDesc = fmt.Sprintf("%s (%s)", srv.Address, strings.ToUpper(srv.Protocol))
						}

						select {
						case resultChan <- UpstreamQueryResult{
							answer:     queryResult.Response.Answer,
							authority:  queryResult.Response.Ns,
							additional: queryResult.Response.Extra,
							validated:  queryResult.Validated,
							ecs:        ecsResponse,
							server:     serverDesc,
						}:
							return nil
						case <-ctx.Done():
							return ctx.Err()
						}
					}
				}
			}
			return nil
		})
	}

	go func() {
		_ = g.Wait()
		close(resultChan)
	}()

	select {
	case res, ok := <-resultChan:
		if ok {
			return res.answer, res.authority, res.additional, res.validated, res.ecs, res.server, nil
		}
		return nil, nil, nil, false, nil, "", errors.New("all upstream queries failed")
	case <-ctx.Done():
		return nil, nil, nil, false, nil, "", ctx.Err()
	}
}

func (qm *QueryManager) filterRecordsByCIDR(records []dns.RR, matchTags []string) ([]dns.RR, bool) {
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

// =============================================================================
// CNAMEHandler Implementation
// =============================================================================

func (ch *CNAMEHandler) resolveWithCNAME(ctx context.Context, question dns.Question, ecs *ECSOption) ([]dns.RR, []dns.RR, []dns.RR, bool, *ECSOption, string, error) {
	var allAnswers []dns.RR
	var finalAuthority, finalAdditional []dns.RR
	var finalECSResponse *ECSOption
	var usedServer string
	allValidated := true

	currentQuestion := question
	visitedCNAMEs := make(map[string]bool)

	for range MaxCNAMEChain {
		select {
		case <-ctx.Done():
			return nil, nil, nil, false, nil, "", ctx.Err()
		default:
		}

		currentName := NormalizeDomain(currentQuestion.Name)
		if visitedCNAMEs[currentName] {
			return nil, nil, nil, false, nil, "", fmt.Errorf("CNAME loop detected: %s", currentName)
		}
		visitedCNAMEs[currentName] = true

		answer, authority, additional, validated, ecsResponse, server, err := ch.server.queryMgr.recursive.recursiveQuery(ctx, currentQuestion, ecs, 0, false)
		if err != nil {
			return nil, nil, nil, false, nil, "", err
		}

		if usedServer == "" {
			usedServer = server
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

	return allAnswers, finalAuthority, finalAdditional, allValidated, finalECSResponse, usedServer, nil
}

// =============================================================================
// RecursiveResolver Implementation
// =============================================================================

func (rr *RecursiveResolver) recursiveQuery(ctx context.Context, question dns.Question, ecs *ECSOption, depth int, forceTCP bool) ([]dns.RR, []dns.RR, []dns.RR, bool, *ECSOption, string, error) {
	if depth > MaxRecursionDep {
		return nil, nil, nil, false, nil, "", fmt.Errorf("recursion depth exceeded: %d", depth)
	}

	qname := dns.Fqdn(question.Name)
	question.Name = qname
	nameservers := rr.getRootServers()
	currentDomain := "."
	normalizedQname := NormalizeDomain(qname)

	if normalizedQname == "" {
		response, err := rr.queryNameserversConcurrent(ctx, nameservers, question, ecs, forceTCP)
		if err != nil {
			return nil, nil, nil, false, nil, "", fmt.Errorf("root domain query: %w", err)
		}

		if rr.server.securityMgr.hijack.IsEnabled() {
			if valid, reason := rr.server.securityMgr.hijack.CheckResponse(currentDomain, normalizedQname, response); !valid {
				return rr.handleSuspiciousResponse(reason, forceTCP, ctx, question, ecs, depth)
			}
		}

		validated := rr.server.securityMgr.dnssec.ValidateResponse(response, true)
		ecsResponse := rr.server.ednsMgr.ParseFromDNS(response)
		return response.Answer, response.Ns, response.Extra, validated, ecsResponse, RecursiveIndicator, nil
	}

	for {
		select {
		case <-ctx.Done():
			return nil, nil, nil, false, nil, "", ctx.Err()
		default:
		}

		response, err := rr.queryNameserversConcurrent(ctx, nameservers, question, ecs, forceTCP)
		if err != nil {
			if !forceTCP && strings.HasPrefix(err.Error(), "DNS_HIJACK_DETECTED") {
				return rr.recursiveQuery(ctx, question, ecs, depth, true)
			}
			return nil, nil, nil, false, nil, "", fmt.Errorf("query %s: %w", currentDomain, err)
		}

		if rr.server.securityMgr.hijack.IsEnabled() {
			if valid, reason := rr.server.securityMgr.hijack.CheckResponse(currentDomain, normalizedQname, response); !valid {
				answer, authority, additional, validated, ecsResponse, server, err := rr.handleSuspiciousResponse(reason, forceTCP, ctx, question, ecs, depth)
				if err != nil && !forceTCP && strings.HasPrefix(err.Error(), "DNS_HIJACK_DETECTED") {
					return rr.recursiveQuery(ctx, question, ecs, depth, true)
				}
				return answer, authority, additional, validated, ecsResponse, server, err
			}
		}

		validated := rr.server.securityMgr.dnssec.ValidateResponse(response, true)
		ecsResponse := rr.server.ednsMgr.ParseFromDNS(response)

		if len(response.Answer) > 0 {
			return response.Answer, response.Ns, response.Extra, validated, ecsResponse, RecursiveIndicator, nil
		}

		bestMatch := ""
		var bestNSRecords []*dns.NS

		for _, rrec := range response.Ns {
			if ns, ok := rrec.(*dns.NS); ok {
				nsName := NormalizeDomain(rrec.Header().Name)

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

		if len(bestNSRecords) == 0 {
			return nil, response.Ns, response.Extra, validated, ecsResponse, RecursiveIndicator, nil
		}

		currentDomainNormalized := NormalizeDomain(currentDomain)
		if bestMatch == currentDomainNormalized && currentDomainNormalized != "" {
			return nil, response.Ns, response.Extra, validated, ecsResponse, RecursiveIndicator, nil
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
					if strings.EqualFold(a.Header().Name, ns.Ns) {
						nextNS = append(nextNS, net.JoinHostPort(a.AAAA.String(), DefaultDNSPort))
					}
				}
			}
		}

		if len(nextNS) == 0 {
			nextNS = rr.resolveNSAddressesConcurrent(ctx, bestNSRecords, qname, depth, forceTCP)
		}

		if len(nextNS) == 0 {
			return nil, response.Ns, response.Extra, validated, ecsResponse, RecursiveIndicator, nil
		}

		nameservers = nextNS
	}
}

func (rr *RecursiveResolver) handleSuspiciousResponse(reason string, currentlyTCP bool, _ context.Context, _ dns.Question, _ *ECSOption, _ int) ([]dns.RR, []dns.RR, []dns.RR, bool, *ECSOption, string, error) {
	if !currentlyTCP {
		return nil, nil, nil, false, nil, "", fmt.Errorf("DNS_HIJACK_DETECTED: %s", reason)
	}
	return nil, nil, nil, false, nil, "", fmt.Errorf("DNS hijacking detected (TCP): %s", reason)
}

func (rr *RecursiveResolver) queryNameserversConcurrent(ctx context.Context, nameservers []string, question dns.Question, ecs *ECSOption, forceTCP bool) (*dns.Msg, error) {
	if len(nameservers) == 0 {
		return nil, errors.New("no nameservers")
	}

	concurrency := min(len(nameservers), MaxSingleQuery)

	// Create a sub-context that can be cancelled when we get first success
	queryCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	tempServers := make([]*UpstreamServer, concurrency)
	for i := 0; i < concurrency && i < len(nameservers); i++ {
		protocol := "udp"
		if forceTCP {
			protocol = "tcp"
		}
		tempServers[i] = &UpstreamServer{Address: nameservers[i], Protocol: protocol}
	}

	resultChan := make(chan *QueryResult, concurrency)

	g, ctx := errgroup.WithContext(queryCtx)

	for _, server := range tempServers {
		srv := server
		msg := rr.server.buildQueryMessage(question, ecs, true, false)

		g.Go(func() error {
			defer ReleaseMessage(msg)
			defer HandlePanic("Query nameserver")

			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			result := rr.server.queryClient.ExecuteQuery(ctx, msg, srv)

			if result.Error == nil && result.Response != nil {
				rcode := result.Response.Rcode

				if rcode == dns.RcodeSuccess || rcode == dns.RcodeNameError {
					result.Validated = rr.server.securityMgr.dnssec.ValidateResponse(result.Response, true)
					select {
					case resultChan <- result:
						// Cancel all other queries when we get first success
						cancel()
						return nil
					case <-ctx.Done():
						return ctx.Err()
					}
				}
			}
			return nil
		})
	}

	go func() {
		_ = g.Wait()
		close(resultChan)
	}()

	select {
	case result, ok := <-resultChan:
		if ok && result != nil {
			return result.Response, nil
		}
		return nil, errors.New("no successful response")
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (rr *RecursiveResolver) resolveNSAddressesConcurrent(ctx context.Context, nsRecords []*dns.NS, qname string, depth int, forceTCP bool) []string {
	resolveCount := min(len(nsRecords), MaxNSResolve)

	nsChan := make(chan []string, resolveCount)
	resolveCtx, resolveCancel := context.WithTimeout(ctx, ConnTimeout)
	defer resolveCancel()

	g, ctx := errgroup.WithContext(resolveCtx)

	for i := range resolveCount {
		ns := nsRecords[i]
		g.Go(func() error {
			defer HandlePanic("NS resolve")

			if strings.EqualFold(strings.TrimSuffix(ns.Ns, "."), strings.TrimSuffix(qname, ".")) {
				select {
				case nsChan <- nil:
				case <-ctx.Done():
				}
				return nil
			}

			var addresses []string

			nsQuestion := dns.Question{Name: dns.Fqdn(ns.Ns), Qtype: dns.TypeA, Qclass: dns.ClassINET}
			if nsAnswer, _, _, _, _, _, err := rr.recursiveQuery(ctx, nsQuestion, nil, depth+1, forceTCP); err == nil {
				for _, rrec := range nsAnswer {
					if a, ok := rrec.(*dns.A); ok {
						addresses = append(addresses, net.JoinHostPort(a.A.String(), DefaultDNSPort))
					}
				}
			}

			if len(addresses) == 0 {
				nsQuestionV6 := dns.Question{Name: dns.Fqdn(ns.Ns), Qtype: dns.TypeAAAA, Qclass: dns.ClassINET}
				if nsAnswerV6, _, _, _, _, _, err := rr.recursiveQuery(ctx, nsQuestionV6, nil, depth+1, forceTCP); err == nil {
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

	go func() {
		_ = g.Wait()
		close(nsChan)
	}()

	var allAddresses []string
	for addresses := range nsChan {
		if len(addresses) > 0 {
			allAddresses = append(allAddresses, addresses...)
			if len(allAddresses) >= MaxNSResolve {
				resolveCancel()
				break
			}
		}
	}

	_ = g.Wait() // Ensure all goroutines complete and check for errors
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

// =============================================================================
// ResponseValidator Implementation
// =============================================================================

// (ResponseValidator methods inherited from DNSSECValidator and HijackPrevention)

// =============================================================================
// Utility Functions
// =============================================================================

func getVersion() string {
	return fmt.Sprintf("v%s-%s@%s (%s)", Version, CommitHash, BuildTime, runtime.Version())
}

func NormalizeDomain(domain string) string {
	return strings.ToLower(strings.TrimSuffix(domain, "."))
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
	return err == nil && info.Mode().IsRegular()
}

func IsTemporaryError(err error) bool {
	if err == nil {
		return false
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return true
	}
	return strings.Contains(err.Error(), "timeout") || strings.Contains(err.Error(), "temporary")
}

func HandlePanic(operation string) {
	if r := recover(); r != nil {
		buf := make([]byte, 4096)
		n := runtime.Stack(buf, false)
		stackTrace := string(buf[:n])
		LogError("PANIC: Panic [%s]: %v\nStack:\n%s\nExiting due to panic", operation, r, stackTrace)
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

func GetSecureClientIP(conn any) net.IP {
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

func CloseWithLog(c any, name string) {
	if c == nil {
		return
	}
	if closer, ok := c.(interface{ Close() error }); ok {
		if err := closer.Close(); err != nil {
			LogWarn("SERVER: Close %s failed: %v", name, err)
		}
	}
}

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

func BuildCacheKey(question dns.Question, ecs *ECSOption, clientRequestedDNSSEC bool, globalPrefix string) string {
	key := globalPrefix + RedisPrefixDNS +
		fmt.Sprintf("%s:%d:%d", NormalizeDomain(question.Name), question.Qtype, question.Qclass)

	if ecs != nil {
		key += fmt.Sprintf(":%s/%d", ecs.Address.String(), ecs.SourcePrefix)
	}

	if clientRequestedDNSSEC {
		key += ":dnssec"
	}

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

func ExtractIPsFromServers(servers []string) []string {
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

func SortBySpeedResultWithLatency(servers []string, results map[string]*SpeedResult) []RootServerWithLatency {
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

func ToRRSlice[T dns.RR](records []T) []dns.RR {
	result := make([]dns.RR, len(records))
	for i, r := range records {
		result[i] = r
	}
	return result
}

func AcquireMessage() *dns.Msg {
	msg := messagePool.Get().(*dns.Msg)
	*msg = dns.Msg{}
	return msg
}

func ReleaseMessage(msg *dns.Msg) {
	if msg == nil {
		return
	}

	messagePool.Put(msg)
}

// =============================================================================
// Main Entry Point
// =============================================================================

func main() {
	var configFile string
	var generateConfig bool
	var showVersion bool

	flag.StringVar(&configFile, "config", "", "Configuration file path (JSON format)")
	flag.BoolVar(&generateConfig, "generate-config", false, "Generate example configuration file")
	flag.BoolVar(&showVersion, "version", false, "Show version information and exit")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "ZJDNS Server - High Performance DNS Server\n\n")
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
