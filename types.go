// Package main implements ZJDNS - High Performance DNS Server
package main

import (
	"container/list"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/redis/go-redis/v9"
	"golang.org/x/sync/errgroup"
)

// =============================================================================
// Log Types
// =============================================================================

// LogLevel represents the logging level
type LogLevel int

const (
	Error LogLevel = iota
	Warn
	Info
	Debug
)

// LogManager manages logging with thread-safe level control
type LogManager struct {
	level    atomic.Int32
	writer   io.Writer
	colorMap map[LogLevel]string
}

// TimeCache provides cached time for performance
type TimeCache struct {
	currentTime atomic.Value
	ticker      *time.Ticker
}

// =============================================================================
// Configuration Types
// =============================================================================

// ServerConfig represents the complete server configuration
type ServerConfig struct {
	Server   ServerSettings   `json:"server"`
	Redis    RedisSettings    `json:"redis"`
	Upstream []UpstreamServer `json:"upstream"`
	Rewrite  []RewriteRule    `json:"rewrite"`
	CIDR     []CIDRConfig     `json:"cidr"`
}

// ServerSettings contains server-specific settings
type ServerSettings struct {
	Port            string             `json:"port"`
	Pprof           string             `json:"pprof"`
	LogLevel        string             `json:"log_level"`
	DefaultECS      string             `json:"default_ecs_subnet"`
	MemoryCacheSize int                `json:"memory_cache_size,omitempty"`
	DDR             DDRSettings        `json:"ddr"`
	TLS             TLSSettings        `json:"tls"`
	Features        FeatureFlags       `json:"features"`
	LatencyProbe    []LatencyProbeStep `json:"latency_probe,omitempty"`
}

// LatencyProbeStep represents one step in the latency probe sequence.
type LatencyProbeStep struct {
	Protocol string `json:"protocol"`
	Port     int    `json:"port,omitempty"`
	Timeout  int    `json:"timeout,omitempty"`
}

// DDRSettings contains DDR (Discovery of Designated Resolvers) configuration
type DDRSettings struct {
	Domain string `json:"domain"`
	IPv4   string `json:"ipv4"`
	IPv6   string `json:"ipv6"`
}

// TLSSettings contains TLS configuration
type TLSSettings struct {
	Port       string        `json:"port"`
	CertFile   string        `json:"cert_file"`
	KeyFile    string        `json:"key_file"`
	SelfSigned bool          `json:"self_signed"`
	HTTPS      HTTPSSettings `json:"https"`
}

// HTTPSSettings contains HTTPS/DoH configuration
type HTTPSSettings struct {
	Port     string `json:"port"`
	Endpoint string `json:"endpoint"`
}

// FeatureFlags contains feature toggle settings
type FeatureFlags struct {
	ForceDNSSEC      bool `json:"force_dnssec,omitempty"`
	HijackProtection bool `json:"hijack_protection"`
}

// RedisSettings contains Redis connection settings
type RedisSettings struct {
	Address   string `json:"address"`
	Password  string `json:"password"`
	Database  int    `json:"database"`
	KeyPrefix string `json:"key_prefix"`
}

// UpstreamServer represents an upstream DNS server
type UpstreamServer struct {
	Address       string   `json:"address"`
	Protocol      string   `json:"protocol"`
	ServerName    string   `json:"server_name,omitempty"`
	SkipTLSVerify bool     `json:"skip_tls_verify,omitempty"`
	Match         []string `json:"match,omitempty"`
}

// RewriteRule represents a DNS rewrite rule
type RewriteRule struct {
	Name           string            `json:"name"`
	NormalizedName string            `json:"normalized_name,omitempty"`
	ResponseCode   *int              `json:"response_code,omitempty"`
	Records        []DNSRecordConfig `json:"records,omitempty"`
	Additional     []DNSRecordConfig `json:"additional,omitempty"`
}

// DNSRecordConfig represents a DNS record configuration
type DNSRecordConfig struct {
	Name         string `json:"name,omitempty"`
	Type         string `json:"type"`
	Class        string `json:"class,omitempty"`
	TTL          uint32 `json:"ttl,omitempty"`
	Content      string `json:"content"`
	ResponseCode *int   `json:"response_code,omitempty"`
}

// CIDRConfig represents CIDR filtering configuration
type CIDRConfig struct {
	File  string   `json:"file,omitempty"`
	Rules []string `json:"rules,omitempty"`
	Tag   string   `json:"tag"`
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

// CompactRecord is a compact representation of a DNS record
type CompactRecord struct {
	Text    string `json:"text"`
	OrigTTL uint32 `json:"orig_ttl"`
	Type    uint16 `json:"type"`
}

// CacheManager defines the cache interface
type CacheManager interface {
	Get(key string) (*CacheEntry, bool, bool)
	Set(key string, answer, authority, additional []dns.RR, validated bool, ecs *ECSOption)
	Close() error
}

// MemoryCache is a high-performance in-memory cache implementation.
type MemoryCache struct {
	mu      sync.RWMutex
	entries map[string]*memoryCacheItem
	order   *list.List
	limit   int
	closed  int32
}

type memoryCacheItem struct {
	entry   *CacheEntry
	element *list.Element
}

// HybridCache combines a local memory cache with an optional Redis persistent cache.
type HybridCache struct {
	memory  *MemoryCache
	redis   *RedisCache
	ctx     context.Context
	cancel  context.CancelCauseFunc
	bgGroup *errgroup.Group
	bgCtx   context.Context
	closed  int32
}

// RedisCache implements cache using Redis
type RedisCache struct {
	client  *redis.Client
	config  *ServerConfig
	ctx     context.Context
	cancel  context.CancelCauseFunc
	closed  int32
	bgGroup *errgroup.Group
	bgCtx   context.Context
}

// CookieOption represents DNS Cookie option (RFC 7873)
type CookieOption struct {
	ClientCookie []byte // 8 bytes fixed
	ServerCookie []byte // 8-32 bytes (optional in requests)
}

// EDEOption represents Extended DNS Error option (RFC 8914)
type EDEOption struct {
	InfoCode  uint16 // Extended error code
	ExtraText string // Optional diagnostic text
}

// EDNS Types

// ECSOption represents EDNS Client Subnet options
type ECSOption struct {
	Address      net.IP
	Family       uint16
	SourcePrefix uint8
	ScopePrefix  uint8
}

// EDNSManager manages EDNS options
type EDNSManager struct {
	defaultECS      *ECSOption
	detector        *IPDetector
	cookieGenerator *CookieGenerator // Server cookie generator
}

// IPDetector detects public IP addresses
type IPDetector struct {
	httpClient *http.Client
}

// =============================================================================
// Query Result Types
// =============================================================================

// QueryResult represents the result of a DNS query
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

// UpstreamQueryResult represents upstream query results
type UpstreamQueryResult struct {
	answer     []dns.RR
	authority  []dns.RR
	additional []dns.RR
	validated  bool
	edeCode    uint16
	ecs        *ECSOption
	server     string
}

// DNSRewriteResult represents the result of DNS rewrite
type DNSRewriteResult struct {
	Domain        string
	ShouldRewrite bool
	ResponseCode  int
	Records       []dns.RR
	Additional    []dns.RR
}

// =============================================================================
// CIDR Management Types
// =============================================================================

// CIDRRule represents a CIDR filtering rule
type CIDRRule struct {
	tag       string
	nets      []*net.IPNet
	ipv4Nets  []ipv4Net
	ipv6Nets  []*net.IPNet
	totalNets int
}

// CIDRManager manages CIDR filtering rules
type CIDRManager struct {
	rules      atomic.Value
	matchCache atomic.Value
}

// CIDRMatchInfo represents CIDR match information
type CIDRMatchInfo struct {
	Tag      string
	Negate   bool
	Original string
}

// ipv4Net represents an IPv4 network in optimized form
type ipv4Net struct {
	ip     uint32
	mask   uint32
	prefix uint8
}

// =============================================================================
// Rewrite Management
// =============================================================================

// RewriteManager manages DNS rewrite rules
type RewriteManager struct {
	rules    atomic.Pointer[[]RewriteRule]
	rulesLen atomic.Uint64
}

// =============================================================================
// Query Client
// =============================================================================

// QueryClient handles DNS queries over various protocols
type QueryClient struct {
	timeout    time.Duration
	udpClient  *dns.Client
	tcpClient  *dns.Client
	tlsClient  *dns.Client
	dohClient  *http.Client
	doh3Client *http.Client
}

// =============================================================================
// Security Types
// =============================================================================

// DNSSECValidator validates DNSSEC responses
type DNSSECValidator struct {
	server       *DNSServer
	trustAnchors map[uint16]*dns.DNSKEY // Root trust anchors (keyTag -> DNSKEY)
	mu           sync.RWMutex
	initialized  bool
}

// HijackPrevention prevents DNS hijacking
type HijackPrevention struct {
	enabled atomic.Bool
}

// SecurityManager manages security features
type SecurityManager struct {
	tls    *TLSManager
	dnssec *DNSSECValidator
	hijack *HijackPrevention
}

// =============================================================================
// TLS Manager
// =============================================================================

// TLSManager manages TLS and secure DNS protocols
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
// DNS Server
// =============================================================================

// DNSServer is the main DNS server
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
	redisCache        *RedisCache
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

// ConfigManager manages configuration loading
type ConfigManager struct{}

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

// UpstreamHandler handles upstream server queries
type UpstreamHandler struct {
	servers atomic.Pointer[[]*UpstreamServer]
}

// RecursiveResolver performs recursive DNS resolution
type RecursiveResolver struct {
	server *DNSServer
}

// CNAMEHandler handles CNAME chain resolution
type CNAMEHandler struct {
	server *DNSServer
}

// ResponseValidator validates DNS responses
type ResponseValidator struct {
	hijackPrevention *HijackPrevention
	dnssecValidator  *DNSSECValidator
}

// =============================================================================
// Object Pool System
// =============================================================================

// MessagePool is a pool for dns.Msg objects
type MessagePool struct {
	pool sync.Pool
}

// BufferPool is a pool for byte buffers
type BufferPool struct {
	pool sync.Pool
	size int
}

// =============================================================================
// DNSSEC Types
// =============================================================================

// RootTrustAnchor represents a DNSSEC trust anchor for the root zone
// This is the IANA root key signing key (KSK) used to bootstrap DNSSEC validation
type RootTrustAnchor struct {
	Zone       string
	KeyTag     uint16
	Algorithm  uint8
	Digest     string // Hex encoded digest of DNSKEY
	DigestType uint8  // Digest type (1=SHA1, 2=SHA256)
	PublicKey  string // Base64 encoded public key
	Flags      uint16 // Key flags (256=ZSK, 257=KSK)
}
