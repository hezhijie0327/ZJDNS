package config

import "time"

// =============================================================================
// Ports & Paths — listener ports and HTTP endpoint paths.
// =============================================================================

const (
	DefaultUDPPort = "53" // plain DNS UDP
	DefaultTCPPort = "53" // plain DNS TCP

	DefaultDNSCryptPort = "443" // DNSCrypt (draft-denis-dprive-dnscrypt-10)

	DefaultTLSPort   = "853" // DoT (RFC 7858)
	DefaultQUICPort  = "853" // DoQ (RFC 9250)
	DefaultHTTPSPort = "443" // DoH (RFC 8484)
	DefaultHTTP3Port = "443" // DoH3
	DefaultDTLSPort  = "853" // DTLS (RFC 8094)

	DefaultTLCPPort     = "853" // TLCP (GB/T 38636-2020) DoT
	DefaultHTTPTLCPPort = "443" // TLCP (GB/T 38636-2020) DoH
	DefaultDTLCPPort    = "853" // DTLCP (GM/T 0128-2023) DoD

	DefaultPprofPort = "6060"

	DefaultQueryPath = "/dns-query"
)

// =============================================================================
// Lifecycle — shutdown and background-task timeouts.
// =============================================================================

const (
	DefaultBackgroundTimeout         = 10 * time.Second // bounded wait for background tasks
	DefaultBackgroundShutdownTimeout = 30 * time.Second // bounded wait during shutdown (matches recursive timeout)
	DefaultShutdownTimeout           = 15 * time.Second // graceful shutdown deadline

	DefaultPendingFollowerTimeout = 60 * time.Second // singleflight follower poll timeout (after leader completion)
)

// =============================================================================
// Maintenance — intervals, delays, rotation periods, and retry windows.
// =============================================================================

const (
	DefaultAcceptRetryDelay = 100 * time.Millisecond // DoT/DoQ accept retry sleep
	// DefaultPoolReapInterval is the dead-socket reap window for all upstream
	// connection pools.  Idle-recycled sockets keep pinning a read buffer plus
	// an FD and stay counted against each pool's global cap until reaped — a
	// 5-minute sweep let them starve the cap and forced eviction churn, so the
	// pool reap runs on its own short interval instead.
	DefaultPoolReapInterval = 30 * time.Second

	DefaultCookieSecretRotationInterval = 24 * time.Hour // RFC 7873 §7.1: default lifetime 1 day
	DefaultECSRefreshInterval           = 15 * time.Minute
)

// =============================================================================
// Concurrency — pool sizes, connection limits, stream caps, and rate limits.
// =============================================================================

const (
	DefaultMaxPipe  = 16 // max in-flight queries per TCP/DoT connection
	DefaultMaxConns = 8  // max connections per upstream
	// DefaultMaxPoolTotalConns bounds the live connections across ALL upstream
	// keys in one pool instance.  Recursive resolution fans out to every
	// authoritative NS address (one pool key per ip:port) plus TLD probes; a
	// small cap forced eviction of in-flight sockets, whose failed queries
	// fell through to per-query dials and re-entered the pool — a self-
	// reinforcing churn loop.  The cap is now a soft ceiling (in-flight
	// sockets are never evicted; idle sockets idle-recycle at 30s and the 30s
	// reap reclaims their slots), so 512 mostly bounds the QUIC side (each
	// connection is hundreds of KB) rather than the 16 KB-buffer UDP side:
	// 9 pool instances × 512 × 16 KB ≈ 73 MB transient worst case.
	DefaultMaxPoolTotalConns  = 512
	DefaultMaxProbes          = 16    // max concurrent latency probes
	DefaultMaxIncomingStreams = 65535 // QUIC max incoming streams (RFC 9250: one stream per query — 256 exhausted a client's stream quota in seconds, then every query waited on MAX_STREAMS behind quic-go's 25ms ACK delay)
	// DefaultHTTP3MaxIncomingStreams bounds DoH3 request streams.  DoH3
	// multiplexes many requests over one stream-pair (browsers use ~100
	// concurrent streams per connection), so the DoQ 65535 quota is
	// unnecessary here — and every accepted stream pins a handler
	// goroutine a trickle-feeding client can hold open, so the lower cap
	// bounds the slowloris surface.
	DefaultHTTP3MaxIncomingStreams = 1024
	DefaultMaxConcurrentStreams    = 64 // QUIC concurrent in-flight stream limit
	DefaultCacheRefreshConcurrency = 64 // background cache refresh goroutine cap

	// DefaultMaxRecursiveInflightQueries caps the recursive fan-out queries in
	// flight across ALL concurrent walks.  When exceeded, new fan-out queries
	// are dropped (the level fails fast instead of queueing).  Healthy load
	// sits far below the cap — it is a last-line guard against query
	// amplification (delegation loops with unreachable authorities), layered
	// under the per-(name,qtype) NS-address singleflight.
	DefaultMaxRecursiveInflightQueries = 8192

	// DefaultServerGoroutineLimit is the unified server-side concurrency
	// cap: the TLS/TLCP serverGroup, the plain-TCP/DoH LimitListener, the
	// DNSCrypt workerCap, and the QUIC connection semaphore (half of this)
	// all derive from it.  Far above realistic personal-deployment
	// concurrency (5900 QPS ≈ 32 in flight) while still bounded against
	// connection floods.  Deliberately NOT the QUIC stream limit: DNSCrypt
	// is UDP-first with no per-packet cap elsewhere — a cap in this
	// hundreds-range absorbs ordinary load without diverting saturated
	// packets into the CPU-heavy SERVFAIL path.
	DefaultServerGoroutineLimit = 256

	DefaultTransportMax          = 64
	DefaultQUICConfigCacheSize   = 128 // max cached QUIC configs (LRU)
	DefaultTLSSessionCacheSize   = 128
	DefaultDTLSSessionCacheSize  = 128
	DefaultTLCPSessionCacheSize  = 128
	DefaultDTLCPSessionCacheSize = 128
	DefaultHTTPTLCPClientMax     = 64 // max cached TLCP DoH HTTP clients
	DefaultMaxIdleConns          = 100
	DefaultMaxIdleConnsPerHost   = 8
	DefaultDOTWriteChannelSize   = 64
	DefaultDOHMaxRequestSize     = 65535 // max DoH request body size (RFC 8484 §6)

	DefaultTokenStoreCapacity     = 32  // QUIC LRU token store capacity per key
	DefaultTokenStoreMaxEntries   = 128 // QUIC LRU token store max total entries
	DefaultQUICAddrCacheSize      = 128 // RFC 9000: address validation token cache (LRU entries)
	DefaultSecureTransportRetries = 2   // DoH/DoH3 recreate-and-retry attempts
)

// =============================================================================
// Protocol Identifiers — protocol name strings, content types, and DNSSEC status.
// =============================================================================

const (
	DNSSECStatusSecure   = "secure"
	DNSSECStatusInsecure = "insecure"
	DNSSECStatusBogus    = "bogus"

	ProtoPing = "ping"
	ProtoHTTP = "http"

	ProtoUDP = "udp"
	ProtoTCP = "tcp"

	ProtoDNS    = "dns"
	ProtoDNSTCP = "dns-tcp"

	ProtoRecursive = "recursive" // built-in recursive resolver

	ProtoTLS   = "tls"
	ProtoQUIC  = "quic"
	ProtoHTTPS = "https"
	ProtoHTTP3 = "http3"

	ProtoDNSCrypt    = "dnscrypt"     // DNSCrypt v2 encrypted DNS (UDP)
	ProtoDNSCryptTCP = "dnscrypt-tcp" // DNSCrypt v2 encrypted DNS (TCP)

	ProtoTLCP     = "tlcp"      // DoT over TLCP (GB/T 38636-2020)
	ProtoHTTPTLCP = "http-tlcp" // DoH over TLCP (matches config protocol.http_tlcp)
	ProtoDTLS     = "dtls"      // DNS-over-DTLS (RFC 8094, matches config protocol.dtls)
	ProtoDTLCP    = "dtlcp"     // DNS-over-DTLCP (GM/T 0128-2023)

	ProtoSOCKS5 = "socks5" // SOCKS5 proxy URL scheme (RFC 1928)
)

// =============================================================================
// DNSCrypt — DNSCrypt v2 protocol defaults.
// =============================================================================

const (
	DefaultDNSCryptCertificateTTL      = 24 * time.Hour // cert validity period (matches ref encrypted-dns-server)
	DefaultDNSCryptCertificateRenewal  = 8 * time.Hour  // renewal interval — a new window is minted every 8h (matches ref)
	DefaultDNSCryptSharedKeyCacheSize  = 2048           // max cached shared keys per server
	DefaultDNSCryptReplayCacheSize     = 8192           // max tracked (client, nonce) replay entries
	DefaultDNSCryptReplayAllow         = 3              // occurrences per window before dropping (UDP retransmits are legitimate)
	DefaultDNSCryptReplayWindow        = 10 * time.Second
	DefaultDNSCryptCertificateCacheTTL = 1 * time.Hour
	DefaultDNSCryptReadTimeout         = 2 * time.Second
	DefaultDNSCryptWriteTimeout        = 10 * time.Second // DNSCrypt TCP response write
	DefaultDNSCryptResponseBuffer      = 512              // cert queries use no EDNS0; TC retry goes over TCP
	DefaultDNSCryptPQTicketLifetime    = 600 * time.Second
	DefaultDNSCryptKeyPurgeInterval    = 30 * time.Second // server: safety-net sweep of expired key windows
	DefaultDNSCryptMinQueryLen         = 512              // min wire query size (matches dnscrypt-proxy InitialMinQuestionSize)
)

// =============================================================================
// Proxy & SOCKS5 — proxy defaults and SOCKS5 protocol constants (RFC 1928).
// =============================================================================

const (
	DefaultProxyPort = "1080"

	SOCKS5UDPHeaderLenIPv4 = 10 // IPv4 SOCKS5 UDP header length
	SOCKS5UDPHeaderLenIPv6 = 22 // IPv6 SOCKS5 UDP header length
)

// =============================================================================
// ALPN — protocol identifiers for secure DNS transport negotiation.
// =============================================================================

var (
	NextProtoDOT  = []string{"dot"} // RFC 7858: DNS-over-TLS
	NextProtoDOH  = []string{"h2"}  // RFC 8484: DNS-over-HTTPS (HTTP/2)
	NextProtoDOQ  = []string{"doq"} // RFC 9250: DNS-over-QUIC
	NextProtoDOH3 = []string{"h3"}  // DNS-over-HTTP/3
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
