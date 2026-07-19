package config

import "time"

// =============================================================================
// Ports & Paths — listener ports and HTTP endpoint paths.
// =============================================================================

const (
	DefaultUDPPort = "53" // plain DNS UDP
	DefaultTCPPort = "53" // plain DNS TCP

	DefaultDNSCryptPort = "8443" // DNSCrypt (draft-denis-dprive-dnscrypt-10)

	DefaultTLSPort   = "853" // DoT (RFC 7858)
	DefaultQUICPort  = "853" // DoQ (RFC 9250)
	DefaultHTTPSPort = "443" // DoH (RFC 8484)
	DefaultHTTP3Port = "443" // DoH3
	DefaultDTLSPort  = "853" // DoD (RFC 8094 §3.3)

	DefaultTLCPPort     = "853" // TLCP DoT (GB/T 38636-2020)
	DefaultHTTPTLCPPort = "443" // TLCP DoH
	DefaultDTLCPPort    = "853" // DTLCP (GM/T 0128-2023)

	DefaultPprofPort = "6060"

	DefaultQueryPath = "/dns-query"
	DefaultPprofPath = "/debug/pprof/"
)

// =============================================================================
// Cache & TTL — cache sizing, TTL, serve-stale, and prefetch parameters.
// =============================================================================

const (
	DefaultMaxCacheEntries   = 10000
	DefaultCacheMMapSizeMB   = 64
	DefaultCacheCacheSizeMB  = 32
	DefaultCacheMaxOpenConns = 4 // SQLite WAL: single writer, readers served concurrently
	DefaultCacheMaxIdleConns = 2

	DefaultQueryJournalRetention = 3 * 86400     // seconds — auto-cleanup window for query_stats + query_log
	DefaultPruneInterval         = 1 * time.Hour // interval between PruneQueryJournal runs
	DefaultPruneBatchSize        = 10000         // rows per iteration during prune

	DefaultTTL         = 10
	DefaultStaleTTL    = 30
	DefaultStaleMaxAge = 30 * 86400 // RFC 8767 §6 recommends ≤ 30 days

	DefaultPrefetchThresholdPercent  = 40
	DefaultServeExpiredClientTimeout = 600 * time.Millisecond // RFC 8767 §5.2: short wait before serving stale
	DefaultPrefetchThrottleInterval  = 3 * time.Second
)

// =============================================================================
// DNS Timeouts — per-query and resolution timeouts.
// =============================================================================

const (
	// RFC 8767 §4.2: timeout SHOULD default to less than 10 seconds.
	DefaultDNSQueryTimeout = 10 * time.Second // single DNS query / dial / per-message I/O

	// DefaultHijackProbeTimeout bounds the TLD hijack probe query.
	// The probe detects GFW-injected A/AAAA records at the delegation
	// level before the authoritative query.  A short timeout avoids
	// blocking the resolution pipeline when a TLD server is unresponsive.
	DefaultHijackProbeTimeout = 2 * time.Second

	DefaultRecursiveResolveTimeout = 30 * time.Second // full recursive resolution
)

// =============================================================================
// Connection Timeouts — idle timeouts and keepalive for long-lived connections.
// =============================================================================

const (
	DefaultHTTPIdleConnTimeout   = 5 * time.Minute  // HTTP transport idle connection
	DefaultQUICKeepAlive         = 20 * time.Second // QUIC keep-alive period
	DefaultQUICClientIdleTimeout = 60 * time.Second // client QUIC idle (must exceed KeepAlive)
	DefaultQUICServerIdleTimeout = 30 * time.Second // server QUIC idle (RFC 9000 default)
	DefaultQUICAddrCacheTTL      = 30 * time.Minute // QUIC address cache sweep cutoff

	DefaultTCPPoolIdleTimeout      = 120 * time.Second // TCP/DoT pool connection idle
	DefaultTCPKeepAlivePeriod      = 30 * time.Second  // TCP keep-alive probe interval
	DefaultEDNSTCPKeepaliveTimeout = 1200              // EDNS TCP keepalive idle timeout (100ms units = 120s)

	DefaultHTTPServerIdleTimeout  = 60 * time.Second // HTTP keep-alive idle
	DefaultHTTPServerWriteTimeout = 10 * time.Second // HTTP response write
	DefaultHTTPReadHeaderTimeout  = 5 * time.Second  // HTTP header read (Slowloris protection)

	DefaultDTLSIdleTimeout = 30 * time.Second // DTLS idle timeout (RFC 8094 §3.3)
)

// =============================================================================
// Lifecycle — shutdown and background-task timeouts.
// =============================================================================

const (
	DefaultBackgroundTimeout         = 10 * time.Second // bounded wait for background tasks
	DefaultBackgroundShutdownTimeout = 30 * time.Second // bounded wait during shutdown (matches recursive timeout)
	DefaultShutdownTimeout           = 15 * time.Second // graceful shutdown deadline
)

// =============================================================================
// Maintenance — intervals, delays, rotation periods, and retry windows.
// =============================================================================

const (
	DefaultAcceptRetryDelay      = 100 * time.Millisecond // DoT/DoQ accept retry sleep
	DefaultHijackSettleTimeout   = 5 * time.Millisecond   // max window for GFW detection race after clean response wins
	DefaultSweepInterval         = 5 * time.Minute        // periodic cleanup sweep
	DefaultTCPWriteMuStaleCutoff = 2 * time.Minute        // stale TCP write mutex cutoff

	DefaultCookieSecretRotationInterval = 30 * time.Minute
	DefaultECSRefreshInterval           = 15 * time.Minute
)

// =============================================================================
// Concurrency — pool sizes, connection limits, stream caps, and rate limits.
// =============================================================================

const (
	DefaultMaxPipe              = 16  // max in-flight queries per TCP/DoT connection
	DefaultMaxConns             = 4   // max connections per upstream
	DefaultMaxConcurrentNS      = 6   // max concurrent NS queries during resolution
	DefaultMaxProbes            = 16  // max concurrent latency probes
	DefaultMaxIncomingStreams   = 256 // QUIC max incoming streams
	DefaultMaxConcurrentStreams = 64

	DefaultServerGoroutineLimit = 1024
	DefaultMinConcurrencyLimit  = 8

	DefaultTransportMax        = 64
	DefaultTLSSessionCacheSize = 256
	DefaultMaxIdleConns        = 100
	DefaultMaxIdleConnsPerHost = 8
	DefaultDOTWriteChannelSize = 64
	DefaultDOHMaxRequestSize   = 8192 // max DoH request body size

	DefaultTokenStoreCapacity     = 32  // QUIC LRU token store capacity per key
	DefaultTokenStoreMaxEntries   = 100 // QUIC LRU token store max total entries
	DefaultSecureTransportRetries = 2   // DoH/DoH3 recreate-and-retry attempts
)

// =============================================================================
// DNS Protocol — domain limits, CNAME, recursion, QNAME minimisation, padding.
// =============================================================================

const (
	MaxDomainLength = 253

	DefaultMaxCNAMEChain     = 16
	DefaultMaxRecursionDepth = 16

	DefaultQnameMinimiseCount = 10 // RFC 9156 §2.3: max QNAME minimisation iterations
	DefaultMinimiseOneLabel   = 4  // RFC 9156 §2.3: labels added one-at-a-time before proportional division

	DefaultPaddingRequestBlockSize  = 128 // RFC 8467: EDNS request padding block size
	DefaultPaddingResponseBlockSize = 468 // RFC 8467: EDNS response padding block size

	DefaultDNS64Prefix = "64:ff9b::/96" // RFC 6052 §2.1 well-known prefix

	FallbackClientIP = "0.0.0.0" // fallback IP when client address is nil
	DNSRootZone      = "."       // DNS root zone label
)

// =============================================================================
// DNSSEC & Security — validation, certificates, keys, and access control.
// =============================================================================

const (
	DefaultDNSKeyCacheTTL     = 86400 // DNSKEY record cache TTL (seconds)
	DefaultMaxNSEC3Iterations = 150   // NSEC3 iteration cap (RFC 5155 §10.3)

	DefaultCACertValidity     = 45 * 24 * time.Hour // CA self-signed certificate lifetime
	DefaultServerCertValidity = 45 * 24 * time.Hour // server certificate lifetime
	DefaultCertExpiryWarnDays = 14                  // days before expiry to emit warning

	GroupOtherPermMask = 0o077 // TLS cert/key files must be owner-only
)

// =============================================================================
// Latency Probe — probe timeouts, intervals, and default probe ports.
// =============================================================================

const (
	DefaultLatencyProbeTimeout     = 100 * time.Millisecond
	DefaultNSProbeTimeout          = 5 * time.Second // timeout for NS/root latency probing
	DefaultLatencyProbeMinInterval = 60              // min interval between probes for the same IP (seconds)
	DefaultRootCacheTTL            = 3600            // root server cache entry TTL (seconds)

	DefaultProbePortDNS   = 53
	DefaultProbePortHTTP  = 80
	DefaultProbePortHTTPS = 443
)

// =============================================================================
// Protocol Identifiers — protocol name strings, content types, and DNSSEC status.
// =============================================================================

const (
	RecursiveIndicator = "builtin_recursive"

	DNSSECStatusSecure   = "secure"
	DNSSECStatusInsecure = "insecure"
	DNSSECStatusBogus    = "bogus"

	ProtoUDP   = "udp"
	ProtoTCP   = "tcp"
	ProtoTLS   = "tls"
	ProtoQUIC  = "quic"
	ProtoHTTPS = "https"
	ProtoHTTP3 = "http3"
	ProtoPing  = "ping"
	ProtoICMP  = "icmp"
	ProtoHTTP  = "http"

	ProtoDNSCrypt    = "dnscrypt"     // DNSCrypt v2 encrypted DNS (UDP)
	ProtoDNSCryptTCP = "dnscrypt-tcp" // DNSCrypt v2 encrypted DNS (TCP)
	ProtoTLCP        = "tlcp"         // DoT over TLCP (GB/T 38636-2020)
	ProtoHTTPTLCP    = "http-tlcp"    // DoH over TLCP (matches config protocol.http_tlcp)
	ProtoDTLS        = "dtls"         // DNS-over-DTLS (RFC 8094, matches config protocol.dod)
	ProtoDTLCP       = "dtlcp"        // DNS-over-DTLCP (GM/T 0128-2023)
)

// =============================================================================
// DNSCrypt — DNSCrypt v2 protocol defaults.
// =============================================================================

const (
	DefaultDNSCryptCertificateTTL      = 24 * time.Hour
	DefaultDNSCryptUDPSize             = 4096
	DefaultDNSCryptCertificateCacheTTL = 1 * time.Hour
	DefaultDNSCryptReadTimeout         = 2 * time.Second
	DefaultDNSCryptResponseBuffer      = 512 // cert queries use no EDNS0; TC retry goes over TCP
	DefaultDNSCryptPQTicketLifetime    = 600 * time.Second
	DefaultDNSCryptKeyOverlap          = 1 * time.Hour
)

// =============================================================================
// Proxy & SOCKS5 — proxy defaults and SOCKS5 protocol constants (RFC 1928).
// =============================================================================

const (
	DefaultProxyPort = "1080"

	SOCKS5UDPHeaderLenIPv4 = 10  // IPv4 SOCKS5 UDP header length
	SOCKS5UDPHeaderLenIPv6 = 22  // IPv6 SOCKS5 UDP header length
	SOCKS5MaxAuthLen       = 255 // RFC 1929 max username/password length
)

// =============================================================================
// ALPN — protocol identifiers for secure DNS transport negotiation.
// =============================================================================

var (
	NextProtoDOT  = []string{"dot"} // RFC 7858: DNS-over-TLS
	NextProtoDOH  = []string{"h2"}  // RFC 8484: DNS-over-HTTPS (HTTP/2)
	NextProtoDOQ  = []string{"doq"} // RFC 9250: DNS-over-QUIC
	NextProtoDOH3 = []string{"h3"}  // DNS-over-HTTP/3
	NextProtoDTLS = []string{"dot"} // RFC 8094: DNS-over-DTLS (same ALPN as DoT)
)

// =============================================================================
// Application — build-time identity defaults (overridden via ldflags).
// =============================================================================

var (
	// DefaultProjectName is the default application name, used in CHAOS records
	// and zone rule names before the build-time value takes effect.
	DefaultProjectName = "ZJDNS"

	// DefaultVersion is the default build version, used in CHAOS records before the
	// build-time value (set via ldflags) takes effect.
	DefaultVersion = "dev"
)
