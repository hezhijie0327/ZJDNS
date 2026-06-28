package config

import "time"

// Network ports and paths.
const (
	DefaultDNSPort      = "53"
	DefaultDOTPort      = "853"
	DefaultDOHPort      = "443"
	DefaultDNSCryptPort = "8443"
	DefaultPprofPort    = "6060"
	DefaultQueryPath    = "/dns-query"
	DefaultPprofPath    = "/debug/pprof/"
	DNSCryptV2Prefix    = "2.dnscrypt-cert."
)

// Cache sizing, TTL, and serve-stale parameters.
const (
	DefaultCacheSize            = 4 * 1024 * 1024
	DefaultCachePersistInterval = 30 * time.Second
	DefaultTTL                  = 10
	DefaultStaleTTL             = 30
	DefaultStaleMaxAge          = 30 * 86400 // RFC 8767 §6 recommends ≤ 30 days

	DefaultPrefetchThresholdPercent  = 40
	DefaultServeExpiredClientTimeout = 1800 * time.Millisecond // RFC 8767 §5.2
	DefaultPrefetchThrottleInterval  = 3 * time.Second
)

// Timeout values for DNS queries, connections, and background tasks.
const (
	DefaultDNSQueryTimeout   = 10 * time.Second // RFC 8767 §4.2
	DefaultBackgroundTimeout = 10 * time.Second // Bounded wait for background tasks

	DefaultDNSCryptTCPReadTimeout = 2 * time.Second // DNSCrypt TCP first read deadline
	DefaultDNSCryptTCPIdleTimeout = 8 * time.Second // DNSCrypt TCP subsequent read deadline

	DefaultAcceptRetryDelay      = 100 * time.Millisecond // DoT/DoQ accept retry sleep
	DefaultHijackSettleTimeout   = 5 * time.Millisecond   // Max window for GFW detection race after clean response wins
	DefaultSweepInterval         = 5 * time.Minute        // Periodic cleanup sweep
	DefaultTCPWriteMuStaleCutoff = 10 * time.Minute       // Stale TCP write mutex cutoff

	DefaultHTTPIdleConnTimeout = 5 * time.Minute  // HTTP transport idle connection
	DefaultQUICKeepAlive       = 20 * time.Second // QUIC keep-alive period

	DefaultQUICClientIdleTimeout   = 60 * time.Second // Client QUIC idle (must exceed KeepAlive)
	DefaultQUICServerIdleTimeout   = 30 * time.Second // Server QUIC idle (RFC 9000 default)
	DefaultHTTPServerIdleTimeout   = 60 * time.Second // HTTP keep-alive idle
	DefaultHTTPServerWriteTimeout  = 10 * time.Second // HTTP response write
	DefaultHTTPReadHeaderTimeout   = 5 * time.Second  // HTTP header read (Slowloris protection)
	DefaultRecursiveResolveTimeout = 30 * time.Second // Full recursive resolution
	DefaultShutdownTimeout         = 15 * time.Second // Graceful shutdown deadline
)

// Security parameters: certificates, DNSSEC, keys, and access control.
const (
	DefaultCACertValidity     = 45 * 24 * time.Hour // CA self-signed certificate lifetime
	DefaultServerCertValidity = 45 * 24 * time.Hour // Server certificate lifetime
	DefaultCertExpiryWarnDays = 14                  // Days before expiry to emit warning

	DefaultCookieSecretRotationInterval = 30 * time.Minute
	DefaultECSRefreshInterval           = 15 * time.Minute

	DefaultCookieSecretSize   = 32                   // DNS cookie secret size in bytes
	DefaultDNSKeyCacheTTL     = 86400                // DNSKEY record cache TTL (seconds)
	DefaultDNSKeyCacheMinTTL  = 300                  // DNSKEY cache minimum TTL (seconds)
	DefaultMaxNSEC3Iterations = 150                  // NSEC3 iteration cap (RFC 5155 §10.3)
	DefaultPaddingBlockSize   = 468                  // RFC 7830: EDNS padding block size
	DefaultDNSCryptCertTTL    = 365 * 24 * time.Hour // DNSCrypt certificate TTL (365 days)

	DefaultStatsPersistInterval = 86400 // Stats cache persist TTL (seconds)

	GroupOtherPermMask = 0077 // TLS cert/key files must be owner-only
)

// Operational limits: concurrency, pool sizes, rate limits, capacities.
const (
	MaxDomainLength = 253

	DefaultMaxCNAMEChain     = 16
	DefaultMaxRecursionDepth = 16

	DefaultMaxPipe              = 16  // Max in-flight queries per TCP/DoT connection
	DefaultMaxConns             = 4   // Max connections per upstream
	DefaultMaxConcurrentNS      = 3   // Max concurrent NS queries during resolution
	DefaultMaxProbes            = 16  // Max concurrent latency probes
	DefaultMaxIncomingStreams   = 256 // QUIC max incoming streams
	DefaultMaxConcurrentStreams = 64

	DefaultServerGoroutineLimit  = 1024
	DefaultMaxConnsPerIP         = 64
	DefaultUDPRateLimit          = 500   // Max UDP queries/sec per client IP
	DefaultUDPRateBurst          = 1000  // Max burst for UDP rate limiter
	DefaultRateLimiterMaxEntries = 10000 // Max unique client IPs tracked before rejecting new IPs
	DefaultMinConcurrencyLimit   = 8

	DefaultTransportMax         = 32
	DefaultTLSSessionCacheSize  = 32
	DefaultMaxIdleConns         = 100
	DefaultMaxIdleConnsPerHost  = 2
	DefaultDoTWriteChannelSize  = 64
	DefaultDoHMaxRequestSize    = 8192 // Max DoH request body size
	DefaultCacheKeyBufferSize   = 128
	DefaultCacheKeyMaxLength    = 512
	DefaultCacheKeyECSPrefix    = ":ecs:"
	DefaultCacheKeyDNSSECSuffix = ":dnssec"
	DefaultCacheKeySeparator    = ':'
	DefaultCacheKeyECSDelim     = '/'
	DefaultCacheKeyHashFormat   = "h:%x"
	DefaultCacheEvictSampleSize = 25
	DefaultRewriteRulesCapacity = 16

	DefaultTokenStoreCapacity     = 4  // QUIC LRU token store capacity per key
	DefaultTokenStoreMaxEntries   = 10 // QUIC LRU token store max total entries
	DefaultSecureTransportRetries = 2  // DoH/DoH3 recreate-and-retry attempts

	DefaultStatsInterval      = 3600  // Stats collection interval (seconds)
	DefaultStatsResetInterval = 86400 // Stats reset interval (seconds)

	DefaultNSLatencyTTL = 900 // NS address sort cache TTL (seconds)

	DefaultDNSClass  = "IN"      // Default DNS resource record class
	StatsPersistKey  = "stats:"  // Stats cache persistence key (matches dns:/dnskey: convention)
	FallbackClientIP = "0.0.0.0" // Fallback IP when client address is nil
	DNSRootZone      = "."       // DNS root zone label
)

// Latency probe defaults.
const (
	DefaultLatencyProbeTimeout = 100 * time.Millisecond
	DefaultInfraProbeTimeout   = 5 * time.Second

	DefaultProbePortDNS   = 53
	DefaultProbePortHTTP  = 80
	DefaultProbePortHTTPS = 443
)

// Proxy defaults.
const (
	DefaultProxyScheme = "socks5"
	DefaultProxyPort   = "1080"
)

// SOCKS5 protocol constants (RFC 1928).
const (
	Socks5UDPHeaderLenIPv4 = 10  // IPv4 SOCKS5 UDP header length
	Socks5UDPHeaderLenIPv6 = 22  // IPv6 SOCKS5 UDP header length
	Socks5MaxAuthLen       = 255 // RFC 1929 max username/password length
)

// String sentinels and protocol identifiers.
const (
	RecursiveIndicator = "builtin_recursive"

	DNSSECStatusSecure   = "secure"
	DNSSECStatusInsecure = "insecure"
	DNSSECStatusBogus    = "bogus"

	DoHContentType = "application/dns-message" // RFC 8484

	ProtoUDP       = "udp"
	ProtoTCP       = "tcp"
	ProtoTLS       = "tls"
	ProtoQUIC      = "quic"
	ProtoHTTP      = "https"
	ProtoHTTP3     = "http3"
	ProtoPing      = "ping"
	ProtoICMP      = "icmp"
	ProtoHTTPPlain = "http"

	// User-facing protocol aliases (map to config file values).
	ProtoDOT      = "dot"      // DoT user config alias
	ProtoDOQ      = "doq"      // DoQ user config alias
	ProtoDOH      = "doh"      // DoH user config alias
	ProtoDOH3     = "doh3"     // DoH3 user config alias
	ProtoDNSCrypt = "dnscrypt" // DNSCrypt v2 protocol identifier
	ProtoTLSTCP   = "tcp-tls"  // dns.Client.Net for TLS-wrapped TCP
)

// ALPN protocol identifiers for secure DNS transports.
var (
	NextProtoDOT  = []string{"dot"} // RFC 7858: DNS-over-TLS
	NextProtoDOH  = []string{"h2"}  // RFC 8484: DNS-over-HTTPS (HTTP/2)
	NextProtoDOQ  = []string{"doq"} // RFC 9250: DNS-over-QUIC
	NextProtoDOH3 = []string{"h3"}  // DNS-over-HTTP/3
)

// ProjectName is the application name, set at build time.
var ProjectName = "ZJDNS"

// DefaultDNSCryptProviderName is the default DNSCrypt provider name.
var DefaultDNSCryptProviderName = DNSCryptV2Prefix + ProjectName

// Version is the build version, set at build time via ldflags.
var Version = "dev"
