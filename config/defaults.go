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
)

// Default cache and TTL values.
const (
	DefaultCacheSize            = 4 * 1024 * 1024
	DefaultCachePersistInterval = 30 * time.Second
	DefaultTTL                  = 10
	DefaultStaleTTL             = 30
	DefaultStaleMaxAge          = 3 * 86400
)

// Default timeouts and intervals.
const (
	Timeout = 10 * time.Second // Global timeout for DNS queries, connections, and idle

	DefaultLatencyProbeTimeout          = 100 * time.Millisecond
	DefaultStatsPersistTTL              = 86400
	DefaultDNSKeyCacheTTL               = 86400
	DefaultServeExpiredClientTimeout    = 1800 * time.Millisecond
	DefaultCookieSecretRotationInterval = 1 * time.Hour
	DefaultECSRefreshInterval           = 15 * time.Minute
	DefaultPrefetchThrottleInterval     = 3 * time.Second
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
