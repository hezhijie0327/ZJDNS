package config

import "time"

// Network ports and paths.
const (
	DefaultDNSPort   = "53"
	DefaultDOTPort   = "853"
	DefaultDOHPort   = "443"
	DefaultPprofPort = "6060"
	DefaultQueryPath = "/dns-query"
	DefaultPprofPath = "/debug/pprof/"
)

// Cache sizing, TTL, and serve-stale parameters.
const (
	DefaultMaxCacheEntries   = 10000
	DefaultCacheMMapSizeMB   = 16
	DefaultCacheCacheSizeMB  = 4
	DefaultCacheMaxOpenConns = 4
	DefaultCacheMaxIdleConns = 2
	DefaultTTL               = 10
	DefaultStaleTTL          = 30
	DefaultStaleMaxAge       = 30 * 86400 // RFC 8767 §6 recommends ≤ 30 days

	DefaultPrefetchThresholdPercent  = 40
	DefaultServeExpiredClientTimeout = 600 * time.Millisecond // RFC 8767 §5.2: short wait before serving stale
	DefaultPrefetchThrottleInterval  = 3 * time.Second
)

// Timeout values for DNS queries, connections, and background tasks.
const (
	// RFC 8767 §4.2: timeout SHOULD default to less than 10 seconds.
	DefaultDNSQueryTimeout = 10 * time.Second // single DNS query / dial / per-message I/O

	// DefaultHijackProbeTimeout bounds the TLD hijack probe query.
	// The probe detects GFW-injected A/AAAA records at the delegation
	// level before the authoritative query.  A short timeout avoids
	// blocking the resolution pipeline when a TLD server is
	// unresponsive.
	DefaultHijackProbeTimeout = 2 * time.Second

	DefaultBackgroundTimeout         = 10 * time.Second // bounded wait for background tasks
	DefaultBackgroundShutdownTimeout = 30 * time.Second // bounded wait for background tasks during shutdown (matches recursive timeout)

	DefaultAcceptRetryDelay      = 100 * time.Millisecond // DoT/DoQ accept retry sleep
	DefaultHijackSettleTimeout   = 5 * time.Millisecond   // Max window for GFW detection race after clean response wins
	DefaultSweepInterval         = 5 * time.Minute        // Periodic cleanup sweep
	DefaultTCPWriteMuStaleCutoff = 2 * time.Minute        // Stale TCP write mutex cutoff

	DefaultHTTPIdleConnTimeout = 5 * time.Minute  // HTTP transport idle connection
	DefaultQUICKeepAlive       = 20 * time.Second // QUIC keep-alive period

	DefaultQUICClientIdleTimeout   = 60 * time.Second  // Client QUIC idle (must exceed KeepAlive)
	DefaultQUICServerIdleTimeout   = 30 * time.Second  // Server QUIC idle (RFC 9000 default)
	DefaultQUICAddrCacheTTL        = 30 * time.Minute  // QUIC address cache sweep cutoff
	DefaultTCPPoolIdleTimeout      = 120 * time.Second // TCP/DoT pool connection idle (must exceed typical query intervals)
	DefaultTCPKeepAlivePeriod      = 30 * time.Second  // TCP keep-alive probe interval
	DefaultEDNSTCPKeepaliveTimeout = 1200              // EDNS TCP keepalive idle timeout (100ms units = 120s)
	DefaultHTTPServerIdleTimeout   = 60 * time.Second  // HTTP keep-alive idle
	DefaultHTTPServerWriteTimeout  = 10 * time.Second  // HTTP response write
	DefaultHTTPReadHeaderTimeout   = 5 * time.Second   // HTTP header read (Slowloris protection)
	DefaultRecursiveResolveTimeout = 30 * time.Second  // Full recursive resolution
	DefaultShutdownTimeout         = 15 * time.Second  // Graceful shutdown deadline
)

// Security parameters: certificates, DNSSEC, keys, and access control.
const (
	DefaultCACertValidity     = 45 * 24 * time.Hour // CA self-signed certificate lifetime
	DefaultServerCertValidity = 45 * 24 * time.Hour // Server certificate lifetime
	DefaultCertExpiryWarnDays = 14                  // Days before expiry to emit warning

	DefaultCookieSecretRotationInterval = 30 * time.Minute
	DefaultECSRefreshInterval           = 15 * time.Minute

	DefaultCookieSecretSize         = 32    // DNS cookie secret size in bytes
	DefaultDNSKeyCacheTTL           = 86400 // DNSKEY record cache TTL (seconds)
	DefaultDNSKeyCacheMinTTL        = 300   // DNSKEY cache minimum TTL (seconds)
	DefaultMaxNegativeTTL           = 10800 // RFC 9077 / RFC 2308 §5: max negative cache TTL (3 hours)
	DefaultMaxNSEC3Iterations       = 150   // NSEC3 iteration cap (RFC 5155 §10.3)
	DefaultQnameMinimiseCount       = 10    // RFC 9156 §2.3: max QNAME minimisation iterations
	DefaultMinimiseOneLabel         = 4     // RFC 9156 §2.3: labels added one-at-a-time before proportional division
	DefaultPaddingRequestBlockSize  = 128   // RFC 8467: EDNS request padding block size
	DefaultPaddingResponseBlockSize = 468   // RFC 8467: EDNS response padding block size

	GroupOtherPermMask = 0077 // TLS cert/key files must be owner-only
)

// Operational limits: concurrency, pool sizes, rate limits, capacities.
const (
	MaxDomainLength = 253

	DefaultMaxCNAMEChain     = 16
	DefaultMaxRecursionDepth = 16

	DefaultMaxPipe              = 16  // Max in-flight queries per TCP/DoT connection
	DefaultMaxConns             = 4   // Max connections per upstream
	DefaultMaxConcurrentNS      = 6   // Max concurrent NS queries during resolution
	DefaultMaxProbes            = 16  // Max concurrent latency probes
	DefaultMaxIncomingStreams   = 256 // QUIC max incoming streams
	DefaultMaxConcurrentStreams = 64

	DefaultServerGoroutineLimit = 1024
	DefaultMinConcurrencyLimit  = 8

	DefaultTransportMax         = 64
	DefaultTLSSessionCacheSize  = 256
	DefaultMaxIdleConns         = 100
	DefaultMaxIdleConnsPerHost  = 8
	DefaultDOTWriteChannelSize  = 64
	DefaultDOHMaxRequestSize    = 8192 // Max DoH request body size
	DefaultRewriteRulesCapacity = 16

	DefaultTokenStoreCapacity     = 32  // QUIC LRU token store capacity per key
	DefaultTokenStoreMaxEntries   = 100 // QUIC LRU token store max total entries
	DefaultSecureTransportRetries = 2   // DoH/DoH3 recreate-and-retry attempts

	DefaultDNSClass  = "IN"      // Default DNS resource record class
	FallbackClientIP = "0.0.0.0" // Fallback IP when client address is nil
	DNSRootZone      = "."       // DNS root zone label
)

// Latency probe defaults.
const (
	DefaultLatencyProbeTimeout = 100 * time.Millisecond
	DefaultNSProbeTimeout      = 5 * time.Second // Timeout for NS/Root latency probing
	DefaultRootCacheTTL        = 3600            // Root server cache entry TTL (seconds)
	DefaultProbePortDNS        = 53
	DefaultProbePortHTTP       = 80
	DefaultProbePortHTTPS      = 443
)

// Proxy defaults.
const (
	DefaultProxyPort = "1080"
)

// SOCKS5 protocol constants (RFC 1928).
const (
	SOCKS5UDPHeaderLenIPv4 = 10  // IPv4 SOCKS5 UDP header length
	SOCKS5UDPHeaderLenIPv6 = 22  // IPv6 SOCKS5 UDP header length
	SOCKS5MaxAuthLen       = 255 // RFC 1929 max username/password length
)

// String sentinels and protocol identifiers.
const (
	RecursiveIndicator = "builtin_recursive"

	DNSSECStatusSecure   = "secure"
	DNSSECStatusInsecure = "insecure"
	DNSSECStatusBogus    = "bogus"

	DOHContentType = "application/dns-message" // RFC 8484

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
	ProtoDOT    = "dot"     // DoT user config alias
	ProtoDOQ    = "doq"     // DoQ user config alias
	ProtoDOH    = "doh"     // DoH user config alias
	ProtoDOH3   = "doh3"    // DoH3 user config alias
	ProtoTLSTCP = "tcp-tls" // dns.Client.Net for TLS-wrapped TCP
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

// Version is the build version, set at build time via ldflags.
var Version = "dev"
