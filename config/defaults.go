package config

import "time"

// Default network ports, paths, and protocol identifiers.
const (
	DefaultDNSPort   = "53"
	DefaultDOTPort   = "853"
	DefaultDOHPort   = "443"
	DefaultPprofPort = "6060"
	DefaultQueryPath = "/dns-query"
	DefaultPprofPath = "/debug/pprof/"

	// Default probe ports (integer form for latency probe steps).
	DefaultProbePortDNS   = 53
	DefaultProbePortHTTP  = 80
	DefaultProbePortHTTPS = 443
)

// Default cache and TTL values.
const (
	DefaultCacheSize            = 4 * 1024 * 1024
	DefaultCachePersistInterval = 30 * time.Second
	DefaultTTL                  = 10
	DefaultStaleTTL             = 30
	DefaultStaleMaxAge          = 45 * 86400
)

// Default timeouts and intervals.
const (
	DefaultDNSQueryTimeout   = 10 * time.Second // Single DNS query / dial timeout (RFC 8767 §4.2)
	DefaultBackgroundTimeout = 10 * time.Second // Bounded wait for background tasks and shutdown

	DefaultLatencyProbeTimeout          = 100 * time.Millisecond
	DefaultStatsPersistTTL              = 86400
	DefaultDNSKeyCacheTTL               = 86400
	DefaultServeExpiredClientTimeout    = 1800 * time.Millisecond
	DefaultCookieSecretRotationInterval = 1 * time.Hour
	DefaultECSRefreshInterval           = 15 * time.Minute
	DefaultPrefetchThrottleInterval     = 3 * time.Second

	// Subsystem-specific timeouts.
	DefaultAcceptRetryDelay      = 100 * time.Millisecond // DoT/DoQ accept retry sleep
	DefaultSweepInterval         = 5 * time.Minute        // Periodic cleanup sweep interval
	DefaultTCPWriteMuStaleCutoff = 10 * time.Minute       // Stale TCP write mutex entry cutoff
	DefaultInfraProbeTimeout     = 30 * time.Second       // Root/NS latency probe timeout
	DefaultH2ReadIdleTimeout     = 30 * time.Second       // HTTP/2 ping keep-alive timeout
	DefaultHTTPIdleConnTimeout   = 5 * time.Minute        // HTTP transport idle connection timeout
	DefaultQUICKeepAlive         = 20 * time.Second       // QUIC keep-alive period
	DefaultCertValidity          = 45 * 24 * time.Hour    // Self-signed certificate validity (https://letsencrypt.org/2025/12/02/from-90-to-45)

	// Protocol-level connection timeouts (server and client).
	DefaultQUICClientIdleTimeout   = 60 * time.Second // Client-side QUIC idle (must exceed KeepAlive)
	DefaultQUICServerIdleTimeout   = 30 * time.Second // Server-side QUIC idle (RFC 9000 default)
	DefaultHTTPServerIdleTimeout   = 60 * time.Second // HTTP keep-alive idle timeout
	DefaultHTTPServerWriteTimeout  = 30 * time.Second // HTTP response write timeout
	DefaultHTTPReadHeaderTimeout   = 5 * time.Second  // HTTP header read timeout (Slowloris protection)
	DefaultRecursiveResolveTimeout = 30 * time.Second // Full recursive resolution timeout
	DefaultShutdownTimeout         = 15 * time.Second // Graceful shutdown deadline
)

// Default limits and thresholds.
const (
	DefaultPrefetchThresholdPercent = 40
	MaxDomainLength                 = 253

	DefaultMaxCNAMEChain     = 16
	DefaultMaxRecursionDepth = 16

	DefaultMaxPipe  = 16
	DefaultMaxConns = 4

	DefaultRootProbeInterval = 900
	DefaultMaxProbes         = 16
	DefaultMaxConcurrentNS   = 3

	DefaultMaxIncomingStreams = 256

	// Pool sizes, capacities, and operational limits.
	DefaultServerGoroutineLimit = 1024
	DefaultMaxConnsPerIP        = 64
	DefaultMaxConcurrentStreams = 64
	DefaultTransportMax         = 32
	DefaultTLSSessionCacheSize  = 32
	DefaultMaxIdleConns         = 100
	DefaultMaxIdleConnsPerHost  = 2
	DefaultDoTWriteChannelSize  = 64
	DefaultDedupSweepThreshold  = 1024
	DefaultCacheKeyBufferSize   = 128
	DefaultCacheKeyMaxLength    = 512
	DefaultCacheEvictSampleSize = 25
	DefaultRewriteRulesCapacity = 16
	DefaultMinConcurrencyLimit  = 8
)

// RecursiveIndicator is the sentinel address value that enables the built-in
// recursive resolver instead of upstream forwarding.
const RecursiveIndicator = "builtin_recursive"

// ALPN protocol identifiers for secure DNS transports.
var (
	NextProtoDOT  = []string{"dot"}
	NextProtoDoH  = []string{"h2"}
	NextProtoDoQ  = []string{"doq"}
	NextProtoDoH3 = []string{"h3"}
)

// ProjectName is the application name, set at build time.
var ProjectName = "ZJDNS"

// Version is the build version, set at build time via ldflags.
var Version = "dev"
