// Package main implements ZJDNS - High Performance DNS Server
// Supporting DoT/DoH/DoQ/DoH3 and recursive resolution
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
	"errors"
	"flag"
	"fmt"
	"hash/fnv"
	"io"
	"log"
	"maps"
	"math"
	"math/big"
	mrand "math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"runtime"
	"slices"
	"strconv"
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
	"golang.org/x/sync/errgroup"
)

// =============================================================================
// Global Constants - Network Configuration
// =============================================================================

const (
	DefaultDNSPort   = "53"
	DefaultDOTPort   = "853"
	DefaultDOHPort   = "443"
	DefaultPprofPort = "6060"

	RecursiveIndicator = "builtin_recursive"
	DefaultQueryPath   = "/dns-query"
	PprofPath          = "/debug/pprof/"
)

// =============================================================================
// Global Constants - Buffer & Memory Configuration
// =============================================================================

const (
	UDPBufferSize        = 1232
	TCPBufferSize        = 4096
	SecureBufferSize     = 8192
	DoHMaxRequestSize    = 8192
	TLSConnBufferSize    = 128
	ResultBufferCapacity = 128
	MaxIncomingStreams   = math.MaxUint16

	// Object pool sizes
	MessagePoolSize = 512
	BufferPoolSize  = 256
)

// =============================================================================
// Global Constants - Protocol Limits & Constraints
// =============================================================================

const (
	MaxDomainLength = 253
	MaxCNAMEChain   = 16
	MaxRecursionDep = 16
	MaxResultLength = 512

	DefaultECSv4Len = 24
	DefaultECSv6Len = 64
	DefaultECSScope = 0
	PaddingSize     = 468
)

// =============================================================================
// Global Constants - Timing Configuration
// =============================================================================

const (
	DefaultTimeout   = 2 * time.Second
	OperationTimeout = 3 * time.Second
	IdleTimeout      = 5 * time.Second
)

// =============================================================================
// Global Constants - Cache Configuration
// =============================================================================

const (
	DefaultCacheTTL = 10
	StaleTTL        = 30
	StaleMaxAge     = 30 * 86400

	RedisPrefixDNS = "dns:"
)

// =============================================================================
// Global Constants - QUIC Configuration
// =============================================================================

const (
	QUICCodeNoError       quic.ApplicationErrorCode = 0
	QUICCodeInternalError quic.ApplicationErrorCode = 1
	QUICCodeProtocolError quic.ApplicationErrorCode = 2
)

// =============================================================================
// Global Constants - Logging Configuration
// =============================================================================

const (
	DefaultLogLevel = "info"

	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorYellow = "\033[33m"
	ColorGreen  = "\033[32m"
	ColorCyan   = "\033[36m"
	ColorBold   = "\033[1m"
)

// =============================================================================
// Variables - Protocol Next Protos
// =============================================================================

var (
	NextProtoDOT  = []string{"dot"}
	NextProtoDoQ  = []string{"doq"}
	NextProtoDoH3 = []string{"h3"}
	NextProtoDoH  = []string{"h2"}
)

// =============================================================================
// Variables - Root Servers
// =============================================================================

var DefaultRootServers = []string{
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
}

// =============================================================================
// Variables - Global Variables
// =============================================================================

var (
	Version    = "1.5.5"
	CommitHash = "dirty"
	BuildTime  = "dev"

	globalLog = NewLogManager()
	timeCache = NewTimeCache()
	globalRNG = mrand.New(mrand.NewSource(time.Now().UnixNano()))

	// Object pools for memory reuse
	messagePool *MessagePool
	bufferPool  *BufferPool
)

// =============================================================================
// Type Definitions - LogManager & Log Level
// =============================================================================

type LogManager struct {
	level    atomic.Int32
	writer   io.Writer
	colorMap map[LogLevel]string
}

type LogLevel int

const (
	Error LogLevel = iota
	Warn
	Info
	Debug
)

// =============================================================================
// Type Definitions - TimeCache
// =============================================================================

type TimeCache struct {
	currentTime atomic.Value
	ticker      *time.Ticker
}

// =============================================================================
// Type Definitions - Configuration Types
// =============================================================================

type ServerConfig struct {
	Server   ServerSettings   `json:"server"`
	Redis    RedisSettings    `json:"redis"`
	Upstream []UpstreamServer `json:"upstream"`
	Rewrite  []RewriteRule    `json:"rewrite"`
	CIDR     []CIDRConfig     `json:"cidr"`
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
	ServerName    string   `json:"server_name,omitempty"`
	SkipTLSVerify bool     `json:"skip_tls_verify,omitempty"`
	Match         []string `json:"match,omitempty"`
}

type RewriteRule struct {
	Name           string            `json:"name"`
	NormalizedName string            `json:"normalized_name,omitempty"`
	ResponseCode   *int              `json:"response_code,omitempty"`
	Records        []DNSRecordConfig `json:"records,omitempty"`
	Additional     []DNSRecordConfig `json:"additional,omitempty"`
}

type DNSRecordConfig struct {
	Name         string `json:"name,omitempty"`
	Type         string `json:"type"`
	TTL          uint32 `json:"ttl,omitempty"`
	Content      string `json:"content"`
	ResponseCode *int   `json:"response_code,omitempty"`
}

type CIDRConfig struct {
	File  string   `json:"file,omitempty"`
	Rules []string `json:"rules,omitempty"`
	Tag   string   `json:"tag"`
}

// =============================================================================
// Type Definitions - Cache Types
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

type CacheManager interface {
	Get(key string) (*CacheEntry, bool, bool)
	Set(key string, answer, authority, additional []dns.RR, validated bool, ecs *ECSOption)
	Close() error
}

type NullCache struct{}

type RedisCache struct {
	client  *redis.Client
	config  *ServerConfig
	ctx     context.Context
	cancel  context.CancelCauseFunc
	closed  int32
	bgGroup *errgroup.Group
	bgCtx   context.Context
}

// =============================================================================
// Type Definitions - EDNS Types
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

type IPDetector struct {
	httpClient *http.Client
}

// =============================================================================
// Type Definitions - Query Result Types
// =============================================================================

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

// =============================================================================
// Type Definitions - CIDR Management Types
// =============================================================================

type CIDRRule struct {
	tag       string
	nets      []*net.IPNet
	ipv4Nets  []ipv4Net
	ipv6Nets  []*net.IPNet
	totalNets int
}

type CIDRManager struct {
	rules      atomic.Value
	matchCache atomic.Value
}

type CIDRMatchInfo struct {
	Tag      string
	Negate   bool
	Original string
}

type ipv4Net struct {
	ip     uint32
	mask   uint32
	prefix uint8
}

// =============================================================================
// Type Definitions - Rewrite Management
// =============================================================================

type RewriteManager struct {
	rules    atomic.Pointer[[]RewriteRule]
	rulesLen atomic.Uint64
}

// =============================================================================
// Type Definitions - Query Client
// =============================================================================

type QueryClient struct {
	timeout    time.Duration
	udpClient  *dns.Client
	tcpClient  *dns.Client
	tlsClient  *dns.Client
	dohClient  *http.Client
	doh3Client *http.Client
}

// =============================================================================
// Type Definitions - Security Types
// =============================================================================

type DNSSECValidator struct{}

type HijackPrevention struct {
	enabled atomic.Bool
}

type SecurityManager struct {
	tls    *TLSManager
	dnssec *DNSSECValidator
	hijack *HijackPrevention
}

// =============================================================================
// Type Definitions - TLS Manager
// =============================================================================

type TLSManager struct {
	server        *DNSServer
	tlsConfig     *tls.Config
	ctx           context.Context
	cancel        context.CancelCauseFunc
	serverGroup   *errgroup.Group
	serverCtx     context.Context
	dotListener   net.Listener
	doqConn       *net.UDPConn
	doqListener   *quic.EarlyListener
	doqTransport  *quic.Transport
	httpsServer   *http.Server
	h3Server      *http3.Server
	httpsListener net.Listener
	h3Listener    *quic.EarlyListener
}

// =============================================================================
// Type Definitions - DNS Server
// =============================================================================

type DNSServer struct {
	config            *ServerConfig
	cacheMgr          CacheManager
	queryClient       *QueryClient
	securityMgr       *SecurityManager
	ednsMgr           *EDNSManager
	rewriteMgr        *RewriteManager
	cidrMgr           *CIDRManager
	pprofServer       *http.Server
	redisClient       *redis.Client
	ctx               context.Context
	cancel            context.CancelCauseFunc
	shutdown          chan struct{}
	backgroundGroup   *errgroup.Group
	backgroundCtx     context.Context
	cacheRefreshGroup *errgroup.Group
	cacheRefreshCtx   context.Context
	closed            int32
	queryMgr          *QueryManager
}

type ConfigManager struct{}

// =============================================================================
// Type Definitions - Query Manager
// =============================================================================

type QueryManager struct {
	upstream  *UpstreamHandler
	recursive *RecursiveResolver
	cname     *CNAMEHandler
	validator *ResponseValidator
	server    *DNSServer
}

type UpstreamHandler struct {
	servers atomic.Pointer[[]*UpstreamServer]
}

type RecursiveResolver struct {
	server *DNSServer
}

type CNAMEHandler struct {
	server *DNSServer
}

type ResponseValidator struct {
	hijackPrevention *HijackPrevention
	dnssecValidator  *DNSSECValidator
}

// =============================================================================
// Type Definitions - Object Pool System
// =============================================================================

type MessagePool struct {
	pool sync.Pool
}

type BufferPool struct {
	pool sync.Pool
	size int
}

// =============================================================================
// Initialization Functions
// =============================================================================

func init() {
	messagePool = NewMessagePool()
	bufferPool = NewBufferPool(SecureBufferSize, BufferPoolSize)
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
	if level < Error {
		level = Error
	} else if level > Debug {
		level = Debug
	}

	if level > LogLevel(lm.level.Load()) {
		return
	}

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

	color, ok := lm.colorMap[level]
	if !ok {
		color = ColorReset
	}

	timestamp := timeCache.Now().Format("2006-01-02 15:04:05")
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
// TimeCache Implementation
// =============================================================================

func NewTimeCache() *TimeCache {
	tc := &TimeCache{
		ticker: time.NewTicker(time.Second),
	}
	tc.currentTime.Store(time.Now())

	go func() {
		for range tc.ticker.C {
			tc.currentTime.Store(time.Now())
		}
	}()

	return tc
}

func (tc *TimeCache) Now() time.Time {
	return tc.currentTime.Load().(time.Time)
}

func (tc *TimeCache) Stop() {
	if tc.ticker != nil {
		tc.ticker.Stop()
	}
}

// =============================================================================
// MessagePool Implementation
// =============================================================================

func NewMessagePool() *MessagePool {
	return &MessagePool{
		pool: sync.Pool{
			New: func() any {
				return &dns.Msg{}
			},
		},
	}
}

func (mp *MessagePool) Get() *dns.Msg {
	msg := mp.pool.Get().(*dns.Msg)
	*msg = dns.Msg{}
	return msg
}

func (mp *MessagePool) Put(msg *dns.Msg) {
	if msg != nil {
		*msg = dns.Msg{}
		mp.pool.Put(msg)
	}
}

// =============================================================================
// BufferPool Implementation
// =============================================================================

func NewBufferPool(size int, poolSize int) *BufferPool {
	bp := &BufferPool{
		size: size,
		pool: sync.Pool{},
	}
	for range poolSize {
		buf := make([]byte, size)
		bp.pool.Put(&buf)
	}
	return bp
}

func (bp *BufferPool) Get() []byte {
	bufPtr := bp.pool.Get()
	if bufPtr == nil {
		return make([]byte, bp.size)
	}
	buf := bufPtr.(*[]byte)
	return *buf
}

func (bp *BufferPool) Put(buf []byte) {
	if buf != nil && cap(buf) >= bp.size {
		bufCopy := make([]byte, bp.size)
		copy(bufCopy, buf[:bp.size])
		bp.pool.Put(&bufCopy)
	}
}

// =============================================================================

// =============================================================================
// QueryClient Implementation
// =============================================================================

func NewQueryClient() *QueryClient {
	udpClient := &dns.Client{
		Timeout: OperationTimeout,
		Net:     "udp",
		UDPSize: UDPBufferSize,
	}

	tcpClient := &dns.Client{
		Timeout: OperationTimeout,
		Net:     "tcp",
	}

	tlsClient := &dns.Client{
		Timeout: OperationTimeout,
		Net:     "tcp-tls",
	}

	dohTransport := &http.Transport{
		MaxIdleConns:        1,
		MaxIdleConnsPerHost: 1,
		IdleConnTimeout:     IdleTimeout,
		DisableCompression:  false,
		ForceAttemptHTTP2:   true,
	}

	doh3Transport := &http.Transport{
		MaxIdleConns:        1,
		MaxIdleConnsPerHost: 1,
		IdleConnTimeout:     IdleTimeout,
		DisableCompression:  false,
		ForceAttemptHTTP2:   false,
	}

	return &QueryClient{
		timeout:   OperationTimeout,
		udpClient: udpClient,
		tcpClient: tcpClient,
		tlsClient: tlsClient,
		dohClient: &http.Client{
			Timeout:   OperationTimeout,
			Transport: dohTransport,
		},
		doh3Client: &http.Client{
			Timeout:   OperationTimeout,
			Transport: doh3Transport,
		},
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
		CurvePreferences:   []tls.CurveID{},
		InsecureSkipVerify: server.SkipTLSVerify,
		MinVersion:         tls.VersionTLS12,
		ServerName:         server.ServerName,
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
	qc.tlsClient.TLSConfig = tlsConfig
	response, _, err := qc.tlsClient.ExchangeContext(ctx, msg, server.Address)
	return response, err
}

func (qc *QueryClient) executeQUIC(ctx context.Context, msg *dns.Msg, server *UpstreamServer, tlsConfig *tls.Config) (*dns.Msg, error) {
	tlsConfig = tlsConfig.Clone()
	tlsConfig.NextProtos = NextProtoDoQ

	quicConfig := &quic.Config{
		MaxIdleTimeout:        IdleTimeout,
		MaxIncomingStreams:    MaxIncomingStreams,
		MaxIncomingUniStreams: MaxIncomingStreams,
		EnableDatagrams:       true,
		Allow0RTT:             false,
	}

	dialCtx, cancel := context.WithTimeout(ctx, DefaultTimeout)
	defer cancel()

	conn, err := quic.DialAddr(dialCtx, server.Address, tlsConfig, quicConfig)
	if err != nil {
		return nil, fmt.Errorf("QUIC dial: %w", err)
	}
	defer func() {
		_ = conn.CloseWithError(QUICCodeNoError, "query completed")
	}()

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

	buf := bufferPool.Get()
	defer bufferPool.Put(buf)

	if len(buf) < 2+len(msgData) {
		buf = make([]byte, 2+len(msgData))
	}

	binary.BigEndian.PutUint16(buf[:2], uint16(len(msgData)))
	copy(buf[2:], msgData)

	if _, err := stream.Write(buf[:2+len(msgData)]); err != nil {
		msg.Id = originalID
		return nil, fmt.Errorf("write: %w", err)
	}

	respBuf := bufferPool.Get()
	defer bufferPool.Put(respBuf)

	n, err := stream.Read(respBuf)
	if err != nil && n == 0 {
		msg.Id = originalID
		return nil, fmt.Errorf("read: %w", err)
	}

	if n < 2 {
		msg.Id = originalID
		return nil, fmt.Errorf("response too short: %d", n)
	}

	response := messagePool.Get()
	if err := response.Unpack(respBuf[2:n]); err != nil {
		msg.Id = originalID
		messagePool.Put(response)
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

	dohTransport := qc.dohClient.Transport.(*http.Transport)
	dohTransport.TLSClientConfig = tlsConfig.Clone()
	if err := http2.ConfigureTransport(dohTransport); err != nil {
		return nil, fmt.Errorf("configure HTTP/2: %w", err)
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
	httpReq.Header.Set("User-Agent", "")

	httpResp, err := qc.dohClient.Do(httpReq)
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

	response := messagePool.Get()
	if err := response.Unpack(body); err != nil {
		msg.Id = originalID
		messagePool.Put(response)
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

	tlsConfig = tlsConfig.Clone()
	tlsConfig.NextProtos = NextProtoDoH3

	transport := &http3.Transport{
		TLSClientConfig: tlsConfig,
		QUICConfig: &quic.Config{
			MaxIdleTimeout:        IdleTimeout,
			MaxIncomingStreams:    MaxIncomingStreams,
			MaxIncomingUniStreams: MaxIncomingStreams,
			EnableDatagrams:       true,
			Allow0RTT:             false,
		},
	}

	qc.doh3Client.Transport = transport

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
	httpReq.Header.Set("User-Agent", "")

	httpResp, err := qc.doh3Client.Do(httpReq)
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

	response := messagePool.Get()
	if err := response.Unpack(body); err != nil {
		msg.Id = originalID
		messagePool.Put(response)
		return nil, fmt.Errorf("unpack: %w", err)
	}

	msg.Id = originalID
	response.Id = originalID

	return response, nil
}

func (qc *QueryClient) executeTraditionalQuery(ctx context.Context, msg *dns.Msg, server *UpstreamServer) (*dns.Msg, error) {
	var client *dns.Client

	switch server.Protocol {
	case "tcp":
		client = qc.tcpClient
	default:
		client = qc.udpClient
	}

	response, _, err := client.ExchangeContext(ctx, msg, server.Address)
	return response, err
}

func (qc *QueryClient) needsTCPFallback(result *QueryResult, protocol string) bool {
	return protocol != "tcp" && (result.Error != nil || (result.Response != nil && result.Response.Truncated))
}

// =============================================================================
// Utility Functions - Shuffle and Concurrency
// =============================================================================

func shuffleSlice[T any](slice []T) []T {
	if len(slice) <= 1 {
		return slice
	}

	shuffled := make([]T, len(slice))
	copy(shuffled, slice)

	for i := len(shuffled) - 1; i > 0; i-- {
		j := globalRNG.Intn(i + 1)
		shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
	}

	return shuffled
}

func calculateConcurrencyLimit(serverCount int) int {
	if serverCount <= 0 {
		return 1
	}

	switch {
	case serverCount <= 4:
		return serverCount
	case serverCount <= 12:
		return (serverCount*2 + 2) / 3
	case serverCount <= 20:
		return (serverCount + 1) / 2
	default:
		limit := serverCount / 3
		if limit < 8 {
			return 8
		}
		return limit
	}
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
		Addr:     config.Redis.Address,
		Password: config.Redis.Password,
		DB:       config.Redis.Database,
	})

	ctx, cancel := context.WithTimeout(context.Background(), DefaultTimeout)
	defer cancel()

	if err := rdb.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("redis connection: %w", err)
	}

	cacheCtx, cacheCancel := context.WithCancelCause(context.Background())
	bgGroup, bgCtx := errgroup.WithContext(cacheCtx)

	cache := &RedisCache{
		client:  rdb,
		config:  config,
		ctx:     cacheCtx,
		cancel:  cacheCancel,
		bgGroup: bgGroup,
		bgCtx:   bgCtx,
	}

	LogInfo("CACHE: Redis cache initialized")
	return cache, nil
}

func (rc *RedisCache) Get(key string) (*CacheEntry, bool, bool) {
	defer HandlePanic("Redis cache get")

	if atomic.LoadInt32(&rc.closed) != 0 {
		return nil, false, false
	}

	ctx, cancel := context.WithTimeout(rc.ctx, OperationTimeout)
	defer cancel()

	data, err := rc.client.Get(ctx, key).Result()
	if err != nil {
		return nil, false, false
	}

	var entry CacheEntry
	if err := json.Unmarshal([]byte(data), &entry); err != nil {
		rc.bgGroup.Go(func() error {
			defer HandlePanic("Clean corrupted cache")
			cleanCtx, cleanCancel := context.WithTimeout(rc.bgCtx, OperationTimeout)
			defer cleanCancel()
			if err := rc.client.Del(cleanCtx, key).Err(); err != nil {
				LogError("CACHE: Failed to clean corrupted cache key %s: %v", key, err)
				return nil
			}
			return nil
		})
		return nil, false, false
	}

	isExpired := entry.IsExpired()

	entry.AccessTime = time.Now().Unix()
	rc.bgGroup.Go(func() error {
		defer HandlePanic("Update access time")
		if atomic.LoadInt32(&rc.closed) == 0 {
			updateCtx, updateCancel := context.WithTimeout(rc.bgCtx, OperationTimeout)
			defer updateCancel()
			if data, err := json.Marshal(entry); err == nil {
				if err := rc.client.Set(updateCtx, key, data, redis.KeepTTL).Err(); err != nil {
					LogError("CACHE: Failed to update access time for key %s: %v", key, err)
				}
			}
		}
		return nil
	})

	return &entry, true, isExpired
}

func (rc *RedisCache) Set(key string, answer, authority, additional []dns.RR, validated bool, ecs *ECSOption) {
	defer HandlePanic("Redis cache set")

	if atomic.LoadInt32(&rc.closed) != 0 {
		return
	}

	allRRs := slices.Concat(answer, authority, additional)
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

	data, err := json.Marshal(entry)
	if err != nil {
		return
	}

	ctx, cancel := context.WithTimeout(rc.ctx, OperationTimeout)
	defer cancel()

	expiration := time.Duration(cacheTTL)*time.Second + time.Duration(StaleMaxAge)*time.Second
	rc.client.Set(ctx, key, data, expiration)
}

func (rc *RedisCache) Close() error {
	if !atomic.CompareAndSwapInt32(&rc.closed, 0, 1) {
		return nil
	}

	LogInfo("CACHE: Shutting down Redis cache")

	rc.cancel(errors.New("redis cache shutdown"))

	done := make(chan error, 1)
	go func() {
		defer HandlePanic("Redis background group wait")
		done <- rc.bgGroup.Wait()
	}()

	select {
	case err := <-done:
		if err != nil {
			LogError("CACHE: Background goroutine error: %v", err)
		}
		LogDebug("CACHE: All Redis background goroutines finished gracefully")
	case <-time.After(IdleTimeout):
		LogWarn("CACHE: Redis background goroutine shutdown timeout")
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
// CIDRManager Implementation
// =============================================================================

func NewCIDRManager(configs []CIDRConfig) (*CIDRManager, error) {
	cm := &CIDRManager{}
	rules := make(map[string]*CIDRRule)
	matchCache := make(map[string]*CIDRMatchInfo)
	cm.rules.Store(rules)
	cm.matchCache.Store(matchCache)

	for _, config := range configs {
		if config.Tag == "" {
			return nil, errors.New("CIDR tag cannot be empty")
		}
		if _, exists := rules[config.Tag]; exists {
			return nil, fmt.Errorf("duplicate CIDR tag: %s", config.Tag)
		}

		rule, err := cm.loadCIDRConfig(config)
		if err != nil {
			return nil, fmt.Errorf("load CIDR config for tag '%s': %w", config.Tag, err)
		}
		rules[config.Tag] = rule

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

	cm.rules.Store(rules)
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

	rule.preprocessNetworks()
	return rule, nil
}

func (cm *CIDRManager) MatchIP(ip net.IP, matchTag string) (matched bool, exists bool) {
	if cm == nil || matchTag == "" {
		return true, true
	}

	matchInfo := cm.getMatchInfo(matchTag)
	if matchInfo == nil {
		return false, false
	}

	rules := cm.rules.Load().(map[string]*CIDRRule)
	rule, exists := rules[matchInfo.Tag]

	if !exists {
		return false, false
	}

	inList := rule.contains(ip)
	if matchInfo.Negate {
		return !inList, true
	}
	return inList, true
}

func (cm *CIDRManager) getMatchInfo(matchTag string) *CIDRMatchInfo {
	matchCache := cm.matchCache.Load().(map[string]*CIDRMatchInfo)

	if info, exists := matchCache[matchTag]; exists {
		return info
	}

	negate := strings.HasPrefix(matchTag, "!")
	tag := strings.TrimPrefix(matchTag, "!")

	info := &CIDRMatchInfo{
		Tag:      tag,
		Negate:   negate,
		Original: matchTag,
	}

	newCache := make(map[string]*CIDRMatchInfo, len(matchCache)+1)
	maps.Copy(newCache, matchCache)
	newCache[matchTag] = info
	cm.matchCache.Store(newCache)

	return info
}

// =============================================================================
// CIDRRule Implementation
// =============================================================================

func (r *CIDRRule) preprocessNetworks() {
	if r == nil {
		return
	}

	r.totalNets = len(r.nets)
	r.ipv4Nets = make([]ipv4Net, 0, r.totalNets)
	r.ipv6Nets = make([]*net.IPNet, 0, r.totalNets)

	for _, ipNet := range r.nets {
		if ipNet == nil {
			continue
		}

		if ipNet.IP.To4() != nil {
			if ipv4Net := toIPv4Net(ipNet); ipv4Net != nil {
				r.ipv4Nets = append(r.ipv4Nets, *ipv4Net)
			}
		} else {
			r.ipv6Nets = append(r.ipv6Nets, ipNet)
		}
	}

	slices.SortFunc(r.ipv4Nets, func(a, b ipv4Net) int {
		if a.prefix != b.prefix {
			return int(b.prefix) - int(a.prefix)
		}
		return 0
	})
}

func toIPv4Net(ipNet *net.IPNet) *ipv4Net {
	if ipNet == nil || ipNet.IP.To4() == nil {
		return nil
	}

	ipv4 := ipNet.IP.To4()
	if ipv4 == nil {
		return nil
	}

	ipUint := uint32(ipv4[0])<<24 | uint32(ipv4[1])<<16 | uint32(ipv4[2])<<8 | uint32(ipv4[3])

	maskSize, _ := ipNet.Mask.Size()
	var maskUint uint32
	if maskSize <= 32 {
		maskUint = ^uint32(0) << (32 - maskSize)
	}

	return &ipv4Net{
		ip:     ipUint & maskUint,
		mask:   maskUint,
		prefix: uint8(maskSize),
	}
}

func (r *CIDRRule) contains(ip net.IP) bool {
	if r == nil || ip == nil {
		return false
	}

	if ipv4 := ip.To4(); ipv4 != nil {
		return r.containsIPv4(ipv4)
	}

	return r.containsIPv6(ip)
}

func (r *CIDRRule) containsIPv4(ipv4 net.IP) bool {
	if len(r.ipv4Nets) == 0 {
		return false
	}

	ipUint := uint32(ipv4[0])<<24 | uint32(ipv4[1])<<16 | uint32(ipv4[2])<<8 | uint32(ipv4[3])

	for _, net := range r.ipv4Nets {
		if (ipUint & net.mask) == net.ip {
			return true
		}
	}

	return false
}

func (r *CIDRRule) containsIPv6(ip net.IP) bool {
	for _, ipNet := range r.ipv6Nets {
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
			httpClient: &http.Client{Timeout: OperationTimeout},
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
			dialer := &net.Dialer{Timeout: DefaultTimeout}
			if forceIPv6 {
				return dialer.DialContext(ctx, "tcp6", addr)
			}
			return dialer.DialContext(ctx, "tcp4", addr)
		},
	}

	client := &http.Client{Timeout: OperationTimeout, Transport: transport}
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
	initialRules := make([]RewriteRule, 0, 16)
	rm.rules.Store(&initialRules)
	rm.rulesLen.Store(0)
	return rm
}

func (rm *RewriteManager) LoadRules(rules []RewriteRule) error {
	validRules := make([]RewriteRule, 0, len(rules))
	for _, rule := range rules {
		if len(rule.Name) <= MaxDomainLength {
			rule.NormalizedName = NormalizeDomain(rule.Name)
			validRules = append(validRules, rule)
		}
	}

	rm.rules.Store(&validRules)
	rm.rulesLen.Store(uint64(len(validRules)))
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

	rulesPtr := rm.rules.Load()
	if rulesPtr == nil {
		return result
	}
	rules := *rulesPtr
	domain = NormalizeDomain(domain)

	for i := range rules {
		rule := &rules[i]
		if domain != rule.NormalizedName {
			continue
		}

		if rule.ResponseCode != nil {
			result.ResponseCode = *rule.ResponseCode
			result.ShouldRewrite = true
			return result
		}

		if len(rule.Records) > 0 || len(rule.Additional) > 0 {
			result.Records = make([]dns.RR, 0, len(rule.Records))
			result.Additional = make([]dns.RR, 0, len(rule.Additional))

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

	var sb strings.Builder
	sb.Grow(len(name) + len(record.Type) + len(record.Content) + 20)
	sb.WriteString(name)
	sb.WriteByte(' ')
	sb.WriteString(strconv.FormatUint(uint64(ttl), 10))
	sb.WriteString(" IN ")
	sb.WriteString(record.Type)
	sb.WriteByte(' ')
	sb.WriteString(record.Content)

	if rr, err := dns.NewRR(sb.String()); err == nil {
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
	return hp.enabled.Load()
}

func (hp *HijackPrevention) CheckResponse(currentDomain, queryDomain string, response *dns.Msg) (bool, string) {
	if !hp.enabled.Load() || response == nil {
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
		hijack: &HijackPrevention{},
	}
	sm.hijack.enabled.Store(config.Server.Features.HijackProtection)

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
		Certificates:     []tls.Certificate{cert},
		CurvePreferences: []tls.CurveID{},
		MinVersion:       tls.VersionTLS13,
	}

	ctx, cancel := context.WithCancelCause(context.Background())
	serverGroup, serverCtx := errgroup.WithContext(ctx)

	tm := &TLSManager{
		server:      server,
		tlsConfig:   tlsConfig,
		ctx:         ctx,
		cancel:      cancel,
		serverGroup: serverGroup,
		serverCtx:   serverCtx,
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

// =============================================================================
// TLSManager: Server Management
// =============================================================================

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
// TLSManager: DoT Implementation
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

	tm.serverGroup.Go(func() error {
		defer HandlePanic("DoT server")
		tm.handleDOTConnections()
		return nil
	})

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

		tm.serverGroup.Go(func() error {
			defer HandlePanic("DoT connection handler")
			defer func() { _ = conn.Close() }()
			tm.handleDOTConnection(conn)
			return nil
		})
	}
}

func (tm *TLSManager) handleDOTConnection(conn net.Conn) {
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return
	}

	_ = tlsConn.SetReadDeadline(time.Now().Add(OperationTimeout))
	_ = tlsConn.SetWriteDeadline(time.Now().Add(OperationTimeout))

	reader := bufio.NewReaderSize(tlsConn, TLSConnBufferSize)

	for {
		select {
		case <-tm.ctx.Done():
			return
		default:
		}

		_ = tlsConn.SetReadDeadline(time.Now().Add(OperationTimeout))
		_ = tlsConn.SetWriteDeadline(time.Now().Add(OperationTimeout))

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

		req := messagePool.Get()
		if err := req.Unpack(msgBuf); err != nil {
			LogDebug("DOT: DNS message unpack error: %v", err)
			messagePool.Put(req)
			continue
		}

		var clientIP net.IP
		if addr := tlsConn.RemoteAddr(); addr != nil {
			clientIP = addr.(*net.TCPAddr).IP
		}
		response := tm.server.processDNSQuery(req, clientIP, true)
		messagePool.Put(req)

		if response != nil {
			respBuf, err := response.Pack()
			if err != nil {
				LogDebug("DOT: Response pack error: %v", err)
				messagePool.Put(response)
				return
			}

			lengthBuf := make([]byte, 2)
			binary.BigEndian.PutUint16(lengthBuf, uint16(len(respBuf)))

			if _, err := tlsConn.Write(lengthBuf); err != nil {
				LogDebug("DOT: Write length error: %v", err)
				messagePool.Put(response)
				return
			}

			if _, err := tlsConn.Write(respBuf); err != nil {
				LogDebug("DOT: Write response error: %v", err)
				messagePool.Put(response)
				return
			}

			messagePool.Put(response)
		}
	}
}

// =============================================================================
// TLSManager: DoQ Implementation
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
		MaxIdleTimeout:        IdleTimeout,
		MaxIncomingStreams:    MaxIncomingStreams,
		MaxIncomingUniStreams: MaxIncomingStreams,
		Allow0RTT:             false,
		EnableDatagrams:       true,
	}

	tm.doqListener, err = tm.doqTransport.ListenEarly(quicTLSConfig, quicConfig)
	if err != nil {
		_ = tm.doqConn.Close()
		return fmt.Errorf("DoQ listen: %w", err)
	}

	LogInfo("DOQ: DoQ server started on port %s", tm.server.config.Server.TLS.Port)

	tm.serverGroup.Go(func() error {
		defer HandlePanic("DoQ server")
		tm.handleDOQConnections()
		return nil
	})

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

		tm.serverGroup.Go(func() error {
			defer HandlePanic("DoQ connection handler")
			tm.handleDOQConnection(conn)
			return nil
		})
	}
}

func (tm *TLSManager) handleDOQConnection(conn *quic.Conn) {
	if conn == nil {
		return
	}

	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), DefaultTimeout)
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

	streamGroup, _ := errgroup.WithContext(tm.ctx)

	for {
		select {
		case <-tm.ctx.Done():
			if err := streamGroup.Wait(); err != nil {
				LogError("DoQ: Stream group finished with error: %v", err)
			}
			return
		case <-conn.Context().Done():
			if err := streamGroup.Wait(); err != nil {
				LogError("DoQ: Stream group finished with error: %v", err)
			}
			return
		default:
		}

		stream, err := conn.AcceptStream(tm.ctx)
		if err != nil {
			if err := streamGroup.Wait(); err != nil {
				LogError("DoQ: Stream group finished with error: %v", err)
			}
			return
		}

		if stream == nil {
			continue
		}

		streamGroup.Go(func() error {
			defer HandlePanic("DoQ stream handler")
			if stream != nil {
				defer func() { _ = stream.Close() }()
				tm.handleDOQStream(stream, conn)
			}
			return nil
		})
	}
}

func (tm *TLSManager) handleDOQStream(stream *quic.Stream, conn *quic.Conn) {
	buf := bufferPool.Get()
	defer bufferPool.Put(buf)

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

	req := messagePool.Get()
	if err := req.Unpack(buf[2 : 2+msgLen]); err != nil {
		_ = conn.CloseWithError(QUICCodeProtocolError, "invalid DNS message")
		messagePool.Put(req)
		return
	}

	clientIP := GetSecureClientIP(conn)
	response := tm.server.processDNSQuery(req, clientIP, true)
	messagePool.Put(req)

	if err := tm.respondQUIC(stream, response); err != nil {
		LogDebug("PROTOCOL: DoQ response failed: %v", err)
	}
	if response != nil {
		messagePool.Put(response)
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

	buf := bufferPool.Get()
	defer bufferPool.Put(buf)

	if len(buf) < 2+len(respBuf) {
		buf = make([]byte, 2+len(respBuf))
	}

	binary.BigEndian.PutUint16(buf[:2], uint16(len(respBuf)))
	copy(buf[2:], respBuf)

	n, err := stream.Write(buf[:2+len(respBuf)])
	if err != nil {
		return fmt.Errorf("stream write: %w", err)
	}
	if n != len(buf[:2+len(respBuf)]) {
		return fmt.Errorf("write length mismatch: %d != %d", n, len(buf))
	}

	return nil
}

// =============================================================================
// TLSManager: DoH Implementation
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
		ReadHeaderTimeout: OperationTimeout,
		WriteTimeout:      OperationTimeout,
		IdleTimeout:       IdleTimeout,
	}

	tm.serverGroup.Go(func() error {
		defer HandlePanic("DoH server")
		if err := tm.httpsServer.Serve(tm.httpsListener); err != nil && err != http.ErrServerClosed {
			LogError("DOH: DoH server error: %v", err)
			return err
		}
		return nil
	})

	return nil
}

func (tm *TLSManager) startDoH3Server(port string) error {
	addr := ":" + port

	tlsConfig := tm.tlsConfig.Clone()
	tlsConfig.NextProtos = NextProtoDoH3

	quicConfig := &quic.Config{
		MaxIdleTimeout:        IdleTimeout,
		MaxIncomingStreams:    MaxIncomingStreams,
		MaxIncomingUniStreams: MaxIncomingStreams,
		Allow0RTT:             false,
		EnableDatagrams:       true,
	}

	quicListener, err := quic.ListenAddrEarly(addr, tlsConfig, quicConfig)
	if err != nil {
		return fmt.Errorf("DoH3 listen: %w", err)
	}

	tm.h3Listener = quicListener
	LogInfo("DOH3: DoH3 server started on port %s", port)

	tm.h3Server = &http3.Server{Handler: tm}

	tm.serverGroup.Go(func() error {
		defer HandlePanic("DoH3 server")
		if err := tm.h3Server.ServeListener(tm.h3Listener); err != nil && err != http.ErrServerClosed {
			LogError("DOH3: DoH3 server error: %v", err)
			return err
		}
		return nil
	})

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
	if response != nil {
		messagePool.Put(response)
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

	req := messagePool.Get()
	if err := req.Unpack(buf); err != nil {
		messagePool.Put(req)
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

	tm.cancel(errors.New("tls manager shutdown"))

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
		ctx, cancel := context.WithTimeout(context.Background(), DefaultTimeout)
		defer cancel()
		_ = tm.httpsServer.Shutdown(ctx)
	}

	if tm.h3Server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), DefaultTimeout)
		defer cancel()
		_ = tm.h3Server.Shutdown(ctx)
	}

	if tm.httpsListener != nil {
		CloseWithLog(tm.httpsListener, "HTTPS listener")
	}
	if tm.h3Listener != nil {
		CloseWithLog(tm.h3Listener, "HTTP/3 listener")
	}

	if err := tm.serverGroup.Wait(); err != nil {
		LogError("TLS: Server goroutines finished with error: %v", err)
	}
	LogInfo("TLS: Secure DNS server shut down")
	return nil
}

// =============================================================================
// DNSServer Implementation
// =============================================================================

func NewDNSServer(config *ServerConfig) (*DNSServer, error) {
	ctx, cancel := context.WithCancelCause(context.Background())
	backgroundGroup, backgroundCtx := errgroup.WithContext(ctx)
	cacheRefreshGroup, cacheRefreshCtx := errgroup.WithContext(ctx)

	ednsManager, err := NewEDNSManager(config.Server.DefaultECS)
	if err != nil {
		cancel(fmt.Errorf("EDNS manager init: %w", err))
		return nil, fmt.Errorf("EDNS manager init: %w", err)
	}

	rewriteManager := NewRewriteManager()
	if len(config.Rewrite) > 0 {
		if err := rewriteManager.LoadRules(config.Rewrite); err != nil {
			cancel(fmt.Errorf("load rewrite rules: %w", err))
			return nil, fmt.Errorf("load rewrite rules: %w", err)
		}
	}

	var cidrManager *CIDRManager
	if len(config.CIDR) > 0 {
		cidrManager, err = NewCIDRManager(config.CIDR)
		if err != nil {
			cancel(fmt.Errorf("CIDR manager init: %w", err))
			return nil, fmt.Errorf("CIDR manager init: %w", err)
		}
	}

	var redisClient *redis.Client
	var cache CacheManager
	if config.Redis.Address == "" {
		cache = NewNullCache()
	} else {
		redisCache, err := NewRedisCache(config)
		if err != nil {
			cancel(fmt.Errorf("redis cache init: %w", err))
			return nil, fmt.Errorf("redis cache init: %w", err)
		}
		cache = redisCache
		redisClient = redisCache.client
	}

	server := &DNSServer{
		config:            config,
		ednsMgr:           ednsManager,
		rewriteMgr:        rewriteManager,
		cidrMgr:           cidrManager,
		redisClient:       redisClient,
		cacheMgr:          cache,
		ctx:               ctx,
		cancel:            cancel,
		shutdown:          make(chan struct{}),
		backgroundGroup:   backgroundGroup,
		backgroundCtx:     backgroundCtx,
		cacheRefreshGroup: cacheRefreshGroup,
		cacheRefreshCtx:   cacheRefreshCtx,
	}

	securityManager, err := NewSecurityManager(config, server)
	if err != nil {
		cancel(fmt.Errorf("security manager init: %w", err))
		return nil, fmt.Errorf("security manager init: %w", err)
	}
	server.securityMgr = securityManager

	queryClient := NewQueryClient()
	server.queryClient = queryClient

	queryManager := NewQueryManager(server)
	if err := queryManager.Initialize(config.Upstream); err != nil {
		cancel(fmt.Errorf("query manager init: %w", err))
		return nil, fmt.Errorf("query manager init: %w", err)
	}
	server.queryMgr = queryManager

	if config.Server.Pprof != "" {
		server.pprofServer = &http.Server{
			Addr:              ":" + config.Server.Pprof,
			ReadHeaderTimeout: OperationTimeout,
			ReadTimeout:       OperationTimeout,
			IdleTimeout:       IdleTimeout,
		}

		if server.securityMgr != nil && server.securityMgr.tls != nil {
			server.pprofServer.TLSConfig = server.securityMgr.tls.tlsConfig
		}
	}

	server.setupSignalHandling()

	return server, nil
}

// =============================================================================
// DNSServer: Lifecycle Management
// =============================================================================

func (s *DNSServer) setupSignalHandling() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	s.backgroundGroup.Go(func() error {
		defer HandlePanic("Signal handler")
		select {
		case sig := <-sigChan:
			LogInfo("SIGNAL: Received signal %v, starting graceful shutdown", sig)
			s.shutdownServer()
		case <-s.backgroundCtx.Done():
			return nil
		}
		return nil
	})
}

func (s *DNSServer) shutdownServer() {
	if !atomic.CompareAndSwapInt32(&s.closed, 0, 1) {
		return
	}

	LogInfo("SERVER: Starting DNS server shutdown")

	if s.cancel != nil {
		s.cancel(errors.New("server shutdown"))
	}

	if s.cacheMgr != nil {
		CloseWithLog(s.cacheMgr, "Cache manager")
	}

	if s.securityMgr != nil {
		if err := s.securityMgr.Shutdown(DefaultTimeout); err != nil {
			LogError("SECURITY: Security manager shutdown failed: %v", err)
		}
	}

	if s.pprofServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), DefaultTimeout)
		if err := s.pprofServer.Shutdown(ctx); err != nil {
			LogError("PPROF: pprof server shutdown failed: %v", err)
		} else {
			LogInfo("PPROF: pprof server shut down successfully")
		}
		cancel()
	}

	bgDone := make(chan error, 1)
	go func() {
		defer HandlePanic("Background group wait")
		bgDone <- s.backgroundGroup.Wait()
	}()

	select {
	case err := <-bgDone:
		if err != nil {
			LogError("SERVER: Background goroutines finished with error: %v", err)
		}
		LogInfo("SERVER: All background tasks shut down")
	case <-time.After(DefaultTimeout):
		LogWarn("SERVER: Background tasks shutdown timeout")
	}

	refreshDone := make(chan error, 1)
	go func() {
		defer HandlePanic("Cache refresh group wait")
		refreshDone <- s.cacheRefreshGroup.Wait()
	}()

	select {
	case err := <-refreshDone:
		if err != nil {
			LogError("SERVER: Cache refresh goroutines finished with error: %v", err)
		}
		LogInfo("SERVER: All cache refresh tasks shut down")
	case <-time.After(DefaultTimeout):
		LogWarn("SERVER: Cache refresh tasks shutdown timeout")
	}

	timeCache.Stop()

	if s.shutdown != nil {
		close(s.shutdown)
	}

	os.Exit(0)
}

func (s *DNSServer) Start() error {
	if atomic.LoadInt32(&s.closed) != 0 {
		return errors.New("server is closed")
	}

	errChan := make(chan error, 1)
	serverCtx, serverCancel := context.WithCancelCause(context.Background())
	defer serverCancel(errors.New("server startup completed"))

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
}

// =============================================================================
// DNSServer: Query Processing
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
		messagePool.Put(response)
	}
}

func (s *DNSServer) processDNSQuery(req *dns.Msg, _ net.IP, isSecureConnection bool) *dns.Msg {
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

	startTime := time.Now()
	defer func() {
		if globalLog.GetLevel() >= Debug {
			responseTime := time.Since(startTime)
			LogDebug("Query completed: %s %s | Time:%v", question.Name, dns.TypeToString[question.Qtype], responseTime.Truncate(time.Microsecond))
		}
	}()

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

	return s.processCacheMiss(req, question, ecsOpt, clientRequestedDNSSEC, cacheKey, isSecureConnection)
}

func (s *DNSServer) processCacheHit(req *dns.Msg, entry *CacheEntry, isExpired bool, question dns.Question, clientRequestedDNSSEC bool, ecsOpt *ECSOption, cacheKey string, isSecureConnection bool) *dns.Msg {
	responseTTL := entry.GetRemainingTTL()

	msg := s.buildResponse(req)
	if msg == nil {
		msg := messagePool.Get()
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
		s.cacheRefreshGroup.Go(func() error {
			defer HandlePanic("cache refresh")
			ctx, cancel := context.WithTimeout(s.cacheRefreshCtx, OperationTimeout)
			defer cancel()
			return s.refreshCacheEntry(ctx, question, ecsOpt, cacheKey, entry)
		})
	}

	s.restoreOriginalDomain(msg, req.Question[0].Name, question.Name)

	return msg
}

func (s *DNSServer) processCacheMiss(req *dns.Msg, question dns.Question, ecsOpt *ECSOption, clientRequestedDNSSEC bool, cacheKey string, isSecureConnection bool) *dns.Msg {
	answer, authority, additional, validated, ecsResponse, _, err := s.queryMgr.Query(question, ecsOpt)

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

	s.cacheMgr.Set(cacheKey, answer, authority, additional, validated, ecsResponse)

	return nil
}

func (s *DNSServer) processQueryError(req *dns.Msg, cacheKey string, question dns.Question, clientRequestedDNSSEC bool, _ *ECSOption, isSecureConnection bool) *dns.Msg {
	if entry, found, _ := s.cacheMgr.Get(cacheKey); found {
		msg := s.buildResponse(req)
		if msg == nil {
			msg := messagePool.Get()
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
		msg = messagePool.Get()
		msg.SetReply(req)
	}
	msg.Rcode = dns.RcodeServerFailure
	return msg
}

func (s *DNSServer) processQuerySuccess(req *dns.Msg, question dns.Question, ecsOpt *ECSOption, clientRequestedDNSSEC bool, cacheKey string, answer, authority, additional []dns.RR, validated bool, ecsResponse *ECSOption, isSecureConnection bool) *dns.Msg {
	msg := s.buildResponse(req)
	if msg == nil {
		msg := messagePool.Get()
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
	msg := messagePool.Get()

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
	msg := messagePool.Get()

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
	upstream := &UpstreamHandler{}
	emptyServers := make([]*UpstreamServer, 0)
	upstream.servers.Store(&emptyServers)

	return &QueryManager{
		upstream: upstream,
		recursive: &RecursiveResolver{
			server: server,
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

	qm.upstream.servers.Store(&activeServers)

	return nil
}

func (qm *QueryManager) Query(question dns.Question, ecs *ECSOption) ([]dns.RR, []dns.RR, []dns.RR, bool, *ECSOption, string, error) {
	servers := qm.upstream.getServers()
	if len(servers) > 0 {
		return qm.queryUpstream(question, ecs)
	}
	ctx, cancel := context.WithTimeout(qm.server.ctx, IdleTimeout)
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
	serversPtr := uh.servers.Load()
	if serversPtr == nil {
		return []*UpstreamServer{}
	}
	return *serversPtr
}

func (qm *QueryManager) queryUpstream(question dns.Question, ecs *ECSOption) ([]dns.RR, []dns.RR, []dns.RR, bool, *ECSOption, string, error) {
	servers := qm.upstream.getServers()
	if len(servers) == 0 {
		return nil, nil, nil, false, nil, "", errors.New("no upstream servers")
	}

	servers = shuffleSlice(servers)

	resultChan := make(chan UpstreamQueryResult, 1)
	queryCtx, cancel := context.WithCancelCause(context.Background())
	defer cancel(errors.New("query completed"))

	g, queryCtx := errgroup.WithContext(queryCtx)
	g.SetLimit(calculateConcurrencyLimit(len(servers)))

	var activeConnections atomic.Int32

	for _, srv := range servers {
		server := srv

		g.Go(func() error {
			select {
			case <-queryCtx.Done():
				return nil
			default:
			}

			activeConnections.Add(1)
			defer activeConnections.Add(-1)

			if server.IsRecursive() {
				recursiveCtx, recursiveCancel := context.WithTimeout(queryCtx, IdleTimeout)
				defer recursiveCancel()

				answer, authority, additional, validated, ecsResponse, usedServer, err := qm.cname.resolveWithCNAME(recursiveCtx, question, ecs)

				if err == nil && len(answer) > 0 {
					if len(server.Match) > 0 {
						filteredAnswer, shouldRefuse := qm.filterRecordsByCIDR(answer, server.Match)
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
						cancel(errors.New("successful result obtained from recursive resolution"))
						return nil
					case <-queryCtx.Done():
						return nil
					}
				}
			} else {
				msg := qm.server.buildQueryMessage(question, ecs, true, false)
				queryResult := qm.server.queryClient.ExecuteQuery(queryCtx, msg, server)
				messagePool.Put(msg)

				if queryResult.Error == nil && queryResult.Response != nil {
					rcode := queryResult.Response.Rcode

					if rcode == dns.RcodeSuccess || rcode == dns.RcodeNameError {
						if len(server.Match) > 0 {
							filteredAnswer, shouldRefuse := qm.filterRecordsByCIDR(queryResult.Response.Answer, server.Match)
							if shouldRefuse {
								messagePool.Put(queryResult.Response)
								return nil
							}
							queryResult.Response.Answer = filteredAnswer
						}

						queryResult.Validated = qm.validator.dnssecValidator.ValidateResponse(queryResult.Response, true)
						ecsResponse := qm.server.ednsMgr.ParseFromDNS(queryResult.Response)

						serverDesc := server.Address
						if server.Protocol != "" && server.Protocol != "udp" {
							serverDesc = fmt.Sprintf("%s (%s)", server.Address, strings.ToUpper(server.Protocol))
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
							remaining := activeConnections.Load() - 1
							if remaining > 0 {
								LogDebug("UPSTREAM: First win achieved, terminating %d remaining connections", remaining)
							}
							cancel(errors.New("successful result obtained from upstream"))
							messagePool.Put(queryResult.Response)
							return nil
						case <-queryCtx.Done():
							messagePool.Put(queryResult.Response)
							return nil
						}
					} else {
						messagePool.Put(queryResult.Response)
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
	case <-queryCtx.Done():
		return nil, nil, nil, false, nil, "", queryCtx.Err()
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
	nameservers := shuffleSlice(DefaultRootServers)
	currentDomain := "."
	normalizedQname := NormalizeDomain(qname)

	if normalizedQname == "" {
		response, err := rr.queryNameserversConcurrent(ctx, nameservers, question, ecs, forceTCP)
		if err != nil {
			return nil, nil, nil, false, nil, "", fmt.Errorf("root domain query: %w", err)
		}

		if rr.server.securityMgr.hijack.IsEnabled() {
			if valid, reason := rr.server.securityMgr.hijack.CheckResponse(currentDomain, normalizedQname, response); !valid {
				messagePool.Put(response)
				return rr.handleSuspiciousResponse(reason, forceTCP, ctx, question, ecs, depth)
			}
		}

		validated := rr.server.securityMgr.dnssec.ValidateResponse(response, true)
		ecsResponse := rr.server.ednsMgr.ParseFromDNS(response)

		answer := response.Answer
		authority := response.Ns
		additional := response.Extra
		valid := validated
		ecsResp := ecsResponse
		server := RecursiveIndicator
		err = nil
		messagePool.Put(response)
		return answer, authority, additional, valid, ecsResp, server, err
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
				messagePool.Put(response)
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
			answer, authority, additional := response.Answer, response.Ns, response.Extra
			messagePool.Put(response)
			return answer, authority, additional, validated, ecsResponse, RecursiveIndicator, nil
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
			nsSlice, extraSlice := response.Ns, response.Extra
			messagePool.Put(response)
			return nil, nsSlice, extraSlice, validated, ecsResponse, RecursiveIndicator, nil
		}

		currentDomainNormalized := NormalizeDomain(currentDomain)
		if bestMatch == currentDomainNormalized && currentDomainNormalized != "" {
			nsSlice, extraSlice := response.Ns, response.Extra
			messagePool.Put(response)
			return nil, nsSlice, extraSlice, validated, ecsResponse, RecursiveIndicator, nil
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
			nsSlice, extraSlice := response.Ns, response.Extra
			messagePool.Put(response)
			return nil, nsSlice, extraSlice, validated, ecsResponse, RecursiveIndicator, nil
		}

		nextNS = shuffleSlice(nextNS)

		messagePool.Put(response)
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

	nameservers = shuffleSlice(nameservers)

	queryCtx, cancel := context.WithCancelCause(ctx)
	defer cancel(errors.New("query resolution completed"))

	resultChan := make(chan *dns.Msg, 1)

	g, queryCtx := errgroup.WithContext(queryCtx)
	g.SetLimit(calculateConcurrencyLimit(len(nameservers)))

	// Track active connections for immediate termination
	var activeConnections atomic.Int32

	for _, ns := range nameservers {
		nsAddr := ns
		protocol := "udp"
		if forceTCP {
			protocol = "tcp"
		}
		server := &UpstreamServer{Address: nsAddr, Protocol: protocol}
		msg := rr.server.buildQueryMessage(question, ecs, true, false)

		g.Go(func() error {
			defer HandlePanic("Query nameserver")
			activeConnections.Add(1)
			defer activeConnections.Add(-1)

			select {
			case <-queryCtx.Done():
				messagePool.Put(msg)
				return queryCtx.Err()
			default:
			}

			// Create a sub-context with shorter timeout for individual queries
			subCtx, subCancel := context.WithTimeout(queryCtx, DefaultTimeout/2)
			defer subCancel()

			result := rr.server.queryClient.ExecuteQuery(subCtx, msg, server)

			if result.Error == nil && result.Response != nil {
				rcode := result.Response.Rcode

				if rcode == dns.RcodeSuccess || rcode == dns.RcodeNameError {
					result.Validated = rr.server.securityMgr.dnssec.ValidateResponse(result.Response, true)
					select {
					case resultChan <- result.Response:
						// First win - immediately cancel all other connections
						cancel(errors.New("first win successful query completed"))
						messagePool.Put(msg)
						return nil
					case <-queryCtx.Done():
						messagePool.Put(msg)
						messagePool.Put(result.Response)
						return queryCtx.Err()
					}
				}
				messagePool.Put(result.Response)
			}
			messagePool.Put(msg)
			return nil
		})
	}

	// Monitor for first success and terminate remaining connections
	go func() {
		_ = g.Wait()
		close(resultChan)
	}()

	select {
	case result, ok := <-resultChan:
		if ok && result != nil {
			// Log connection termination stats
			remaining := activeConnections.Load()
			if remaining > 0 {
				LogDebug("RECURSION: First win achieved, terminating %d remaining connections", remaining)
			}
			return result, nil
		}
		return nil, errors.New("no successful response")
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (rr *RecursiveResolver) resolveNSAddressesConcurrent(ctx context.Context, nsRecords []*dns.NS, qname string, depth int, forceTCP bool) []string {
	if len(nsRecords) == 0 {
		return nil
	}

	nsRecords = shuffleSlice(nsRecords)

	resolveCtx, resolveCancel := context.WithTimeout(ctx, DefaultTimeout)
	defer resolveCancel()

	g, queryCtx := errgroup.WithContext(resolveCtx)
	g.SetLimit(calculateConcurrencyLimit(len(nsRecords)))

	var allAddresses atomic.Pointer[[]string]
	empty := []string{}
	allAddresses.Store(&empty)

	// For first-win optimization: cancel when we get sufficient addresses
	addressCtx, addressCancel := context.WithCancelCause(queryCtx)
	defer addressCancel(errors.New("NS address resolution completed"))

	var foundAddresses atomic.Int32
	var activeResolutions atomic.Int32

	for _, ns := range nsRecords {
		nsRecord := ns

		g.Go(func() error {
			defer HandlePanic("Resolve NS addresses")
			activeResolutions.Add(1)
			defer activeResolutions.Add(-1)

			select {
			case <-queryCtx.Done():
				return nil
			default:
			}

			if strings.EqualFold(strings.TrimSuffix(nsRecord.Ns, "."), strings.TrimSuffix(qname, ".")) {
				return nil
			}

			var nsAddresses atomic.Value
			nsAddresses.Store([]string{})

			// Use first-win for IPv4/IPv6 resolution (A and AAAA records)
			queryGroup, subCtx := errgroup.WithContext(addressCtx)
			queryGroup.SetLimit(calculateConcurrencyLimit(2)) // IPv4 + IPv6 queries

			// IPv4 resolution
			queryGroup.Go(func() error {
				defer HandlePanic("Resolve NS IPv4")

				nsQuestion := dns.Question{
					Name:   dns.Fqdn(nsRecord.Ns),
					Qtype:  dns.TypeA,
					Qclass: dns.ClassINET,
				}

				// Create sub-context with shorter timeout
				ipv4Ctx, ipv4Cancel := context.WithTimeout(subCtx, DefaultTimeout/3)
				defer ipv4Cancel()

				var ipv4Addresses []string
				if nsAnswer, _, _, _, _, _, err := rr.recursiveQuery(ipv4Ctx, nsQuestion, nil, depth+1, forceTCP); err == nil {
					for _, rrec := range nsAnswer {
						if a, ok := rrec.(*dns.A); ok {
							ipv4Addresses = append(ipv4Addresses, net.JoinHostPort(a.A.String(), DefaultDNSPort))
						}
					}
				}

				if len(ipv4Addresses) > 0 {
					if existing := nsAddresses.Load().([]string); len(existing) > 0 {
						combined := append(existing, ipv4Addresses...)
						nsAddresses.Store(combined)
					} else {
						nsAddresses.Store(ipv4Addresses)
					}
					// First win - cancel IPv6 resolution
					addressCancel(errors.New("IPv4 addresses resolved - first win"))
				}
				return nil
			})

			// IPv6 resolution
			queryGroup.Go(func() error {
				defer HandlePanic("Resolve NS IPv6")

				nsQuestionV6 := dns.Question{
					Name:   dns.Fqdn(nsRecord.Ns),
					Qtype:  dns.TypeAAAA,
					Qclass: dns.ClassINET,
				}

				// Create sub-context with shorter timeout
				ipv6Ctx, ipv6Cancel := context.WithTimeout(subCtx, DefaultTimeout/3)
				defer ipv6Cancel()

				var ipv6Addresses []string
				if nsAnswerV6, _, _, _, _, _, err := rr.recursiveQuery(ipv6Ctx, nsQuestionV6, nil, depth+1, forceTCP); err == nil {
					for _, rrec := range nsAnswerV6 {
						if aaaa, ok := rrec.(*dns.AAAA); ok {
							ipv6Addresses = append(ipv6Addresses, net.JoinHostPort(aaaa.AAAA.String(), DefaultDNSPort))
						}
					}
				}

				if len(ipv6Addresses) > 0 {
					if existing := nsAddresses.Load().([]string); len(existing) > 0 {
						combined := append(existing, ipv6Addresses...)
						nsAddresses.Store(combined)
					} else {
						nsAddresses.Store(ipv6Addresses)
					}
					// First win - cancel IPv4 resolution
					addressCancel(errors.New("IPv6 addresses resolved - first win"))
				}
				return nil
			})

			_ = queryGroup.Wait()

			if nsAddrs := nsAddresses.Load().([]string); len(nsAddrs) > 0 {
				current := allAddresses.Load()
				newAddresses := append(*current, nsAddrs...)
				allAddresses.Store(&newAddresses)

				// First win optimization: if we have enough addresses, cancel remaining NS resolutions
				if foundAddresses.Add(1) >= int32(calculateConcurrencyLimit(len(nsRecords))) {
					resolveCancel()
					LogDebug("RECURSION: First win NS resolution - canceling %d remaining NS lookups", activeResolutions.Load())
				}
			}

			return nil
		})
	}

	_ = g.Wait()

	if finalAddresses := allAddresses.Load(); finalAddresses != nil {
		return *finalAddresses
	}

	return nil
}

// =============================================================================
// Utility Functions - Strings and Helpers
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
	dangerousPrefixes := []string{"/etc/", "/proc/", "/sys/"}
	if strings.Contains(path, "..") || slices.ContainsFunc(dangerousPrefixes, func(prefix string) bool {
		return strings.HasPrefix(path, prefix)
	}) {
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
		buf := make([]byte, TCPBufferSize)
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
	var buf strings.Builder
	buf.Grow(ResultBufferCapacity)

	buf.WriteString(globalPrefix)
	buf.WriteString(RedisPrefixDNS)

	buf.WriteString(NormalizeDomain(question.Name))
	buf.WriteByte(':')

	buf.WriteString(strconv.FormatUint(uint64(question.Qtype), 10))
	buf.WriteByte(':')
	buf.WriteString(strconv.FormatUint(uint64(question.Qclass), 10))

	if ecs != nil {
		buf.WriteString(":ecs:")
		buf.WriteString(ecs.Address.String())
		buf.WriteByte('/')
		buf.WriteString(strconv.FormatUint(uint64(ecs.SourcePrefix), 10))
	}

	if clientRequestedDNSSEC {
		buf.WriteString(":dnssec")
	}

	result := buf.String()
	if len(result) > MaxResultLength {
		hash := fnv.New64a()
		hash.Write([]byte(result))
		return fmt.Sprintf("h:%x", hash.Sum64())
	}
	return result
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

func ToRRSlice[T dns.RR](records []T) []dns.RR {
	result := make([]dns.RR, len(records))
	for i, r := range records {
		result[i] = r
	}
	return result
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
