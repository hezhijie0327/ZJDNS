package config

import "time"

// =============================================================================
// Ports & Paths — listener ports and HTTP endpoint paths.
// =============================================================================

const (
	DefaultUDPPort = "53" // plain DNS UDP
	DefaultTCPPort = "53" // plain DNS TCP

	DefaultDNSCryptPort = "8443" // DNSCrypt (draft-denis-dprive-dnscrypt-10)

	DefaultTLSPort   = "853"  // DoT (RFC 7858)
	DefaultQUICPort  = "853"  // DoQ (RFC 9250)
	DefaultHTTPSPort = "443"  // DoH (RFC 8484)
	DefaultHTTP3Port = "443"  // DoH3
	DefaultDTLSPort  = "8853" // DTLS (RFC 8094 specifies 853; 8853 is widely deployed)

	DefaultTLCPPort     = "9853" // TLCP (GB/T 38636-2020) DoT
	DefaultHTTPTLCPPort = "9443" // TLCP (GB/T 38636-2020) DoH
	DefaultDTLCPPort    = "9853" // DTLCP (GM/T 0128-2023) DoD

	DefaultPprofPort = "6060"

	DefaultQueryPath = "/dns-query"
)

// =============================================================================
// Cache & TTL — cache sizing, TTL, serve-stale, and prefetch parameters.
// =============================================================================

const (
	// Defaults tuned for small-memory devices (64–128 MB): the hot tier
	// stays under ~3 MB and the spill index (≈100 B per disk record) under
	// ~4 MB at full caps.
	DefaultMaxCacheEntries      = 2000
	DefaultMaxLatencyEntries    = 1000 // per-IP latency table bound
	DefaultMaxDelegationEntries = 2000 // zone-cut delegation cache bound

	// Spill tier defaults (second-tier disk caps, in entries).
	DefaultSpillCacheEntries      = 20000
	DefaultSpillLatencyEntries    = 5000
	DefaultSpillDelegationEntries = 20000

	DefaultTTL         = 10
	DefaultStaleTTL    = 30
	DefaultStaleMaxAge = 3 * 86400 // seconds — RFC 8767 §6: stale retention window (1–3 days recommended)

	// DefaultMaxCacheableTTL caps the TTL of incoming records per RFC 8767 §4.
	DefaultMaxCacheableTTL = 7 * 86400 // RFC 8767 §4: SHOULD cap at 604800 seconds (7 days)

	// DefaultCompressionThreshold is the minimum wire-format size in bytes
	// below which zstd compression is skipped.  Empirical benchmark data:
	//   < 100B: compression often expands (129% @ 45B) — pure overhead
	//   100-200B: marginal savings (73% @ 93B) — not worth 1.2µs decompress
	//   > 200B: good savings (42% @ 206B) — decompress cost amortised
	// 256 is chosen as a round number that excludes all simple A/AAAA
	// responses while including DNSSEC-signed and large answer sets.
	DefaultCompressionThreshold = 256

	DefaultPrefetchThresholdPercent  = 10
	DefaultServeExpiredClientTimeout = 600 * time.Millisecond // short client wait before serving stale (RFC 8767 stale-answer-ttl concept)
	DefaultPrefetchThrottleInterval  = 3 * time.Second

	// DefaultPrefetchCooldownMaxEntries caps the PrefetchCooldown map size.
	// When exceeded, the oldest half of entries are evicted to prevent
	// unbounded growth under sustained diverse-query load.
	DefaultPrefetchCooldownMaxEntries = 10000

	// DefaultCacheSnapshotInterval is the periodic cache snapshot ticker
	// (used only when features.cache.state_file is configured).
	DefaultCacheSnapshotInterval = 5 * time.Minute
)

// =============================================================================
// DNS Timeouts — per-query and resolution timeouts.
// =============================================================================

const (
	// Single DNS query / dial / per-message I/O budget. Engineering default
	// (RFC 8767 defines no query timeout).
	DefaultDNSQueryTimeout = 9 * time.Second

	// DefaultRecursiveQueryTimeout bounds each authority query in the
	// recursive walk.  Authorities answer in well under a second; 9s (the
	// forwarding timeout) made a failing authority stall the whole walk —
	// the fan-out cancels on the first success, but when every NS fails the
	// walk waited out the full timeout.  3s fails fast and moves on.
	DefaultRecursiveQueryTimeout = 3 * time.Second

	// DefaultPoisonProbeTimeout bounds the TLD hijack probe query.
	// The probe detects GFW-injected A/AAAA records at the delegation
	// level before the authoritative query.  A short timeout avoids
	// blocking the resolution pipeline when a TLD server is unresponsive.
	DefaultPoisonProbeTimeout = 2 * time.Second

	DefaultRecursiveResolveTimeout = 30 * time.Second // full recursive resolution

)

// =============================================================================
// Connection Timeouts — idle timeouts and keepalive for long-lived connections.
// =============================================================================

const (
	DefaultHTTPIdleConnTimeout   = 5 * time.Minute  // HTTP transport idle connection
	DefaultQUICKeepAlive         = 20 * time.Second // QUIC keep-alive period
	DefaultQUICClientIdleTimeout = 60 * time.Second // client QUIC idle (must exceed KeepAlive)

	// DefaultQUICStreamOpenTimeout bounds how long OpenStreamSync may wait
	// for the server's MAX_STREAMS frame.  RFC 9250 is one stream per query;
	// when the server's stream quota is exhausted, quic-go blocks until the
	// stream closes and the server replenishes the quota — which trails
	// behind a 25ms ACK delay.  Waiting the full query timeout stalls the
	// pipeline; a short budget treats "slow stream open" as an exhausted
	// connection and the pool dials a fresh one (0-RTT resumption).
	DefaultQUICStreamOpenTimeout = 100 * time.Millisecond
	DefaultQUICServerIdleTimeout = 30 * time.Second // server QUIC idle (RFC 9000 default)
	DefaultTCPPoolIdleTimeout    = 60 * time.Second // TCP/DoT pool connection idle (handshake cost justifies a longer hold)
	// DefaultUDPPoolIdleTimeout is the idle-reap window for pooled UDP
	// sockets.  UDP dialing is a bare connect(2) — no handshake — so
	// reconnecting is cheap and retaining idle sockets is pure cost: each
	// conn pins a 64KB read buffer plus a socket/FD.  The recursive resolver
	// and plain forwarders share this pool and can hold one socket per
	// destination address (root/TLD/authoritative + forwarding upstreams);
	// a 30s window keeps the working set small between query bursts while
	// avoiding churn for TTL-driven re-queries of the same authorities.
	DefaultUDPPoolIdleTimeout  = 30 * time.Second
	DefaultTLSHandshakeTimeout = 10 * time.Second  // pre-handshake bound for DoT (an idle-connect flood must not hold shared errgroup slots)
	DefaultTCPKeepAlivePeriod  = 30 * time.Second  // TCP keep-alive probe interval
	DefaultTCPIdleTimeout      = 120 * time.Second // RFC 7766 §6.2.3: plain TCP server idle timeout

	DefaultHTTPServerIdleTimeout  = 60 * time.Second // HTTP keep-alive idle
	DefaultHTTPServerWriteTimeout = 10 * time.Second // HTTP response write
	DefaultHTTPReadHeaderTimeout  = 5 * time.Second  // HTTP header read (Slowloris protection)

	DefaultDTLSIdleTimeout = 30 * time.Second // DTLS idle timeout (RFC 8094 §3.3)

	// DefaultPMTU is the assumed path MTU when the actual value is unknown
	// (RFC 8094 §5).  Safe DNS payload = PMTU − DTLSDNSOverhead − DNSFramePrefixLen.
	DefaultPMTU     = 1280 // IPv6 minimum MTU
	DTLSDNSOverhead = 59   // UDP(8) + DTLS body(~13) + MAC(~16) + IP min(20) + margin(2)
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
// Defense — anti-pollution defaults.
// =============================================================================

const (
	DefaultSpoofguardCollectWindow = 500 * time.Millisecond // silence window before returning best EDNS candidate
	DefaultSpoofguardPollInterval  = 100 * time.Millisecond // per-read poll interval
	// DefaultSpoofguardConfirmRounds bounds the pure-UDP re-query
	// confirmation for an ambiguous single-answer non-EDNS response: a
	// matching repeat (same answer records) confirms it as the real server's
	// response, since GFW fakes vary per packet while the real answer is
	// deterministic.  Re-queries stop after this many rounds or at the query
	// deadline — an unconfirmed ambiguous response is never served.
	DefaultSpoofguardConfirmRounds     = 3
	DefaultSplitguardMaxSegSize        = 4                      // max bytes per TCP segment (random [1,N] to avoid fingerprinting)
	DefaultQUICSecondQueryProbeTimeout = 100 * time.Millisecond // DoQ: probe for a second query on the same stream (RFC 9250 §4.3.3)
)

// =============================================================================
// Maintenance — intervals, delays, rotation periods, and retry windows.
// =============================================================================

const (
	DefaultAcceptRetryDelay      = 100 * time.Millisecond // DoT/DoQ accept retry sleep
	DefaultSweepInterval         = 5 * time.Minute        // periodic cleanup sweep
	DefaultTCPWriteMuStaleCutoff = 2 * time.Minute        // stale TCP write mutex cutoff

	DefaultCookieSecretRotationInterval = 24 * time.Hour // RFC 7873 §7.1: default lifetime 1 day
	DefaultECSRefreshInterval           = 15 * time.Minute
)

// =============================================================================
// Concurrency — pool sizes, connection limits, stream caps, and rate limits.
// =============================================================================

const (
	DefaultMaxPipe  = 16 // max in-flight queries per TCP/DoT connection
	DefaultMaxConns = 4  // max connections per upstream
	// DefaultMaxPoolTotalConns caps the total live connections across ALL
	// upstream keys in one pool instance — recursive resolution otherwise
	// opens up to 4 sockets per distinct authoritative NS address (UDP) or
	// forced-TCP upstream (TCP/QUIC) with no global bound (H1).
	DefaultMaxPoolTotalConns       = 128
	DefaultMaxConcurrentNS         = 6     // max concurrent NS queries during resolution
	DefaultMaxProbes               = 16    // max concurrent latency probes
	DefaultMaxIncomingStreams      = 65535 // QUIC max incoming streams (RFC 9250: one stream per query — 256 exhausted a client's stream quota in seconds, then every query waited on MAX_STREAMS behind quic-go's 25ms ACK delay)
	DefaultMaxConcurrentStreams    = 64    // QUIC concurrent in-flight stream limit
	DefaultCacheRefreshConcurrency = 64    // background cache refresh goroutine cap

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
	DefaultMinConcurrencyLimit  = 8

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
// DNS Protocol — domain limits, CNAME, recursion, QNAME minimisation, padding.
// =============================================================================

const (
	MaxDomainLength   = 253
	MaxDNSMessageSize = 65535 // DNS wire format max message size (uint16 length prefix)
	MaxPortNumber     = 65535 // TCP/UDP max port number

	DefaultMaxCNAMEChain     = 16
	DefaultMaxRecursionDepth = 16

	// DefaultMQTypeMaxQTx is the RFC 10029 §4 QTx cap: the maximum number of
	// additional RR types a server will process per MQTYPE-Query.  Public DNS
	// expects 4; the operator-configured upstream mqtype list is itself
	// bounded by this value.
	DefaultMQTypeMaxQTx = 4

	// DefaultMQTypeResolveTimeout bounds each QTx resolution during a
	// server-side MQTYPE merge, and the walk's MQTYPE-Query fallback retry —
	// a malicious client could otherwise use the option to amplify the
	// resolver's outbound work (RFC 10029 §4).  Matches the recursive walk's
	// authority query budget (DefaultRecursiveQueryTimeout) so the combined
	// first-attempt + fallback worst case is 6s, not 8s.
	DefaultMQTypeResolveTimeout = 3 * time.Second

	DefaultQnameMinimiseCount = 10 // RFC 9156 §2.3: max QNAME minimisation iterations
	DefaultMinimiseOneLabel   = 4  // RFC 9156 §2.3: labels added one-at-a-time before proportional division

	DefaultPaddingRequestBlockSize  = 128 // RFC 8467: EDNS request padding block size
	DefaultPaddingResponseBlockSize = 468 // RFC 8467: EDNS response padding block size

	DefaultDNS64Prefix = "64:ff9b::/96" // RFC 6052 §2.1 well-known prefix

	// DefaultMaxUDPResponseSize caps UDP responses per RFC 9715 R3:
	// the recommended maximum DNS/UDP payload (MTU 1500 − IP/UDP headers,
	// allowing for tunnel overhead).  Larger responses are truncated (TC=1),
	// triggering a TCP retry.
	DefaultMaxUDPResponseSize = 1400

	// DefaultRESINFOTTL is the TTL for locally-served resolver.arpa RESINFO
	// records (RFC 9606).
	DefaultRESINFOTTL = 3600

	// DefaultHINFOTTL is the TTL for the RFC 8482 minimal ANY response
	// HINFO record.
	DefaultHINFOTTL = 3600

	FallbackClientIP = "0.0.0.0" // fallback IP when client address is nil
	DNSRootZone      = "."       // DNS root zone label
)

// =============================================================================
// DNSSEC & Security — validation, certificates, keys, and access control.
// =============================================================================

const (
	DefaultMaxNSEC3Iterations = 150 // NSEC3 iteration cap (RFC 5155 §10.3)

	DefaultCACertValidity     = 45 * 24 * time.Hour // CA self-signed certificate lifetime
	DefaultServerCertValidity = 45 * 24 * time.Hour // server certificate lifetime
	DefaultCertExpiryWarnDays = 14                  // days before expiry to emit warning

	GroupOtherPermMask = 0o077 // TLS cert/key files must be owner-only
)

// =============================================================================
// Latency Probe — probe timeouts, intervals, and default probe ports.
// =============================================================================

const (
	// PrivacyProfileStrict requires TLS with PKIX certificate verification
	// (RFC 8310 §6). This is the default for encrypted upstreams.
	PrivacyProfileStrict = "strict"

	// unauthenticated TLS (SkipTLSVerify), providing protection against
	// passive eavesdropping but not active MITM (RFC 8310 §5).
	PrivacyProfileOpportunistic = "opportunistic"

	DefaultLatencyProbeTimeout      = 100 * time.Millisecond
	DefaultNSProbeTimeout           = 5 * time.Second // timeout for NS/root latency probing
	DefaultLatencyProbeMinInterval  = 60              // min interval between probes for the same IP (seconds)
	DefaultLatencyProbeSmoothFactor = 2               // EWMA smoothing factor: srtt = ((N-1)·srtt + rtt) / N (N=2 → α=1/2)
	DefaultRootCacheTTL             = 3600            // root server cache entry TTL (seconds)
	DefaultDelegationLookupZones    = 16              // max ancestor zones per delegation lookup

	DefaultProbePortDNS   = 53
	DefaultProbePortHTTP  = 80
	DefaultProbePortHTTPS = 443
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
