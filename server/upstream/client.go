// Package upstream implements outbound DNS query execution over UDP, TCP, DoT,
// DoQ, DoH, DoH3, DNSCrypt, TLCP, and DTLCP with connection pooling.
package upstream

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
	"zjdns/config"
	"zjdns/internal/log"
	"zjdns/internal/lrumap"
	zpool "zjdns/internal/pool"
	"zjdns/server/defense"
	"zjdns/server/upstream/dnscrypt"
	"zjdns/server/upstream/plain"
	"zjdns/server/upstream/pool"

	socks5 "zjdns/server/upstream/socks5"
	tlcpclient "zjdns/server/upstream/tlcp"
	tlsclient "zjdns/server/upstream/tls"

	"codeberg.org/miekg/dns"
	stdtls "crypto/tls"
	eHTTP "gitlab.com/go-extension/http"
	eTLS "gitlab.com/go-extension/tls"
)

// Result holds the outcome of a single DNS query including response, timing,
// and metadata.
type Result struct {
	Response  *dns.Msg
	Server    string
	Error     error
	Duration  time.Duration
	Protocol  string
	Validated bool
}

// Client manages outbound DNS queries across multiple transport protocols with
// pooling. Protocol-specific logic is delegated to sub-packages.
type Client struct {
	timeout        time.Duration
	plainClient    *plain.Client
	tlsClient      *tlsclient.Client
	tlcpClient     *tlcpclient.Client
	dnscryptClient *dnscrypt.Client

	proxyDialers *lrumap.Map[string, *socks5.Dialer]

	skipVerifyWarned sync.Map // serverName → struct{}{}, dedup SkipTLSVerify warning

	// capsGuardMismatches counts CapsGuard (0x20) echo mismatches for
	// warn-log sampling (config.DefaultCapsGuardWarnEvery) — the mismatch
	// path is attacker-triggerable, so Warn must not fire per query.
	capsGuardMismatches atomic.Uint64

	// capsDowngrades tracks per-address 0x20 mismatch counts: once an
	// address exceeds DefaultCapsGuardDowngradeAfter mismatches,
	// randomisation is skipped for it outright for DefaultCapsGuardRetryAfter
	// — an on-path echo-forger otherwise doubles our outbound queries per
	// attempt (randomised query + unrandomised retry, every query).
	capsDowngrades *lrumap.Map[string, *capsDowngradeStat]

	warmWg sync.WaitGroup // tracks in-flight WarmUpConnections goroutines
}

// New creates a Client with default timeouts, transport pools, and session
// caches. Sub-clients for each protocol family are created and wired with
// shared resources (proxy dialers, connection pools).
//
// The zero-parameter constructor is intentional: all transport configuration
// comes from config.UpstreamServer at query time (per-server TLS verification,
// protocol selection, proxy).  The pools and caches created here are shared
// across all upstream servers for efficiency.
func New() *Client {
	defaultTransport := &dns.Transport{
		Dialer: &net.Dialer{
			Timeout:   config.DefaultDNSQueryTimeout,
			KeepAlive: config.DefaultTCPKeepAlivePeriod,
		},
		ReadTimeout:  config.DefaultDNSQueryTimeout,
		WriteTimeout: config.DefaultDNSQueryTimeout,
	}

	// NOTE: All three clients alias the same *dns.Transport. This is safe
	// because dns.Client only reads Transport config fields (Dialer, timeouts)
	// and never mutates them. A future change to Transport on one client would
	// affect all three -- clone the Transport if per-client divergence is needed.
	udpClient := &dns.Client{Transport: defaultTransport}
	tcpClient := &dns.Client{Transport: defaultTransport}
	tlsDNSClient := &dns.Client{Transport: defaultTransport}

	dohTransport := &eHTTP.Transport{
		MaxIdleConns:        config.DefaultMaxIdleConns,
		MaxIdleConnsPerHost: config.DefaultMaxIdleConnsPerHost,
		MaxConnsPerHost:     config.DefaultMaxIdleConnsPerHost,
		IdleConnTimeout:     config.DefaultHTTPIdleConnTimeout,
		DisableCompression:  true,
		ForceAttemptHTTP2:   true,
	}
	dohClient := &eHTTP.Client{
		Timeout:   config.DefaultDNSQueryTimeout,
		Transport: dohTransport,
	}
	doh3Client := &http.Client{
		Timeout: config.DefaultDNSQueryTimeout,
	}

	timeout := config.DefaultDNSQueryTimeout
	sessionCache := eTLS.NewLRUClientSessionCache(config.DefaultTLSSessionCacheSize)
	quicSessionCache := stdtls.NewLRUClientSessionCache(config.DefaultTLSSessionCacheSize)
	dtlsSessions := lrumap.NewDTLSSessionStore(config.DefaultDTLSSessionCacheSize)
	tcpPool := pool.NewConnPool(config.DefaultMaxConns, config.DefaultMaxPipe, config.DefaultMaxPoolTotalConns)
	dotPool := pool.NewConnPool(config.DefaultMaxConns, config.DefaultMaxPipe, config.DefaultMaxPoolTotalConns)
	quicPool := pool.NewQUIC(config.DefaultMaxConns, config.DefaultMaxPoolTotalConns)

	c := &Client{
		timeout:      timeout,
		proxyDialers: lrumap.New[string, *socks5.Dialer](config.DefaultTransportMax * 2),
		// Pointer values + per-stat mutex: lrumap.Get returns a copy, so a
		// value-typed read-modify-write lost concurrent increments and
		// delayed the 0x20 downgrade threshold (2026-09 U6).
		capsDowngrades: lrumap.New[string, *capsDowngradeStat](config.DefaultCapsGuardDowngradeMapCapacity),
	}

	// OnEvict runs with the map mutex held (lrumap contract) — Dialer.Close
	// is local resource cleanup (UDP relay conn close, no network I/O), so
	// it cannot block the map.
	c.proxyDialers.OnEvict = func(_ string, d *socks5.Dialer) {
		if d != nil {
			_ = d.Close()
		}
	}

	c.plainClient = plain.New(udpClient, tcpClient, tcpPool, c.proxyDialer, timeout)
	c.tlsClient = tlsclient.New(tlsDNSClient, dohClient, doh3Client, dotPool, quicPool, sessionCache, quicSessionCache, dtlsSessions, c.proxyDialer, timeout)
	c.tlcpClient = tlcpclient.New(c.proxyDialer, timeout)
	c.dnscryptClient = dnscrypt.New(c.proxyDialer)

	return c
}

// ExecuteQuery sends a DNS query to an upstream server and returns the result.
//
// When the upstream enables CapsGuard (config.UpstreamServer.CapsGuard), the
// question name is 0x20-randomized on every outbound query
// (draft-vixie-dnsext-dns0x20-00 §5.1): the case bit of each ASCII letter is
// flipped randomly, and a legitimate response must echo the question
// byte-for-byte — one extra bit of transaction entropy per ASCII letter
// (RFC 4343 §3).  A response that does not echo the randomized case — a
// spoofing signature or a case-rewriting middlebox — is discarded and the
// query is retried once with the original case (§6.4 fallback; the retry's
// security equals the pre-CapsGuard baseline).
func (c *Client) ExecuteQuery(ctx context.Context, msg *dns.Msg, server *config.UpstreamServer) *Result {
	if msg == nil {
		return &Result{Error: errors.New("nil query message")}
	}
	if server == nil {
		return &Result{Error: errors.New("nil server config")}
	}

	start := time.Now()

	original := ""
	if len(msg.Question) > 0 {
		original = msg.Question[0].Header().Name
	}

	// CapsGuard randomization: flip the case bit of every ASCII letter in
	// the question name.  The randomized bytes never outlive this message —
	// the caller packs and sends it, and cached responses are rebuilt from
	// the canonical qname — so no random case can leak into the cache or
	// later responses (draft §5.4).
	//
	// The question RR is copied before mutating its header: the fan-out
	// callers (forward.go / nameserver.go) append the SAME RR interface to
	// every worker's message, so all upstreams share one *Header — mutating
	// it in place would let concurrent queries overwrite each other's
	// randomized (or original) name.
	randomized := false
	var randName string
	qtype := uint16(0)
	if server.CapsGuard && original != "" && !c.capsDisabled(server.Address) {
		qtype = dns.RRToType(msg.Question[0])
		randName = defense.RandomizeCase(original)
		if randName != original {
			qd := msg.Question[0]
			if newFn, ok := dns.TypeToRR[qtype]; ok {
				rr := newFn()
				rr.Header().Name = randName
				rr.Header().Class = qd.Header().Class
				msg.Question[0] = rr
				randomized = true
			}
		}
	}

	// Log the name actually sent — after CapsGuard randomization, so the
	// 0x20 case pattern is visible in the debug log (the caller-facing
	// original is restored only on a mismatch retry below).
	if len(msg.Question) > 0 {
		log.Debugf("UPSTREAM: querying %s (%s) for %s", server.Address, server.Protocol, msg.Question[0].Header().Name)
	}

	result := c.execute(ctx, msg, server)

	// Draft §6.4 semantics: only CONSECUTIVE mismatches count — a
	// successful echo resets the per-address counter, so an intermittent
	// case-rewriting middlebox (1 mismatch per N queries) no longer
	// accumulates to a periodic 10-minute downgrade window (S8).
	if randomized && result.Error == nil && result.Response != nil &&
		len(result.Response.Question) > 0 &&
		result.Response.Question[0].Header().Name == randName {
		c.noteCapsSuccess(server.Address)
	}

	// Echo verification (§5.5): when the QID/type/class all match but the
	// echoed question differs from the randomized name, the response is not
	// ours — discard it and retry once with the original case (§6.4).
	// PTR (reverse) queries are exempt from the check: some middleboxes
	// (Cisco DNS guard) rewrite the case of reverse-lookup qnames, which
	// would trigger a spurious mismatch on every reverse query (mirrors
	// unbound's PTR exemption in serviced_query_callback).
	if randomized && qtype != dns.TypePTR && result.Error == nil && result.Response != nil &&
		len(result.Response.Question) > 0 &&
		result.Response.Question[0].Header().Name != randName {
		log.Debugf("UPSTREAM: %s did not echo the 0x20-cased question for %s — retrying with the original case", server.Address, original)
		// The mismatch path is attacker-triggerable — Debug only: a loaded
		// recursive walk against non-0x20-compliant authorities would
		// otherwise log Warn per upstream (mismatch counts stay observable
		// at Debug for operations, draft-vixie-dnsext-dns0x20-00 §5.3).
		if n := c.capsGuardMismatches.Add(1); n%config.DefaultCapsGuardWarnEvery == 1 {
			log.Debugf("SECURITY: upstream %s does not echo 0x20-cased questions (mismatch #%d, e.g. %s) — unrandomized retries serve as fallback", server.Address, n, original)
		}
		if c.noteCapsMismatch(server.Address) {
			log.Debugf("SECURITY: upstream %s exceeded %d 0x20 mismatches — skipping randomisation for %s (no per-query retry doubling)", server.Address, config.DefaultCapsGuardDowngradeAfter, config.DefaultCapsGuardRetryAfter)
		}
		zpool.DefaultMessage.Put(result.Response)
		// msg.Question[0] is this call's private copy — safe to restore.
		msg.Question[0].Header().Name = original
		result = c.execute(ctx, msg, server)
	}

	result.Duration = time.Since(start)

	if result.Error != nil {
		log.Debugf("UPSTREAM: query failed for %s via %s (%s) in %v, error=%v", original, server.Address, result.Protocol, result.Duration, result.Error)
	} else if result.Response != nil {
		log.Debugf("UPSTREAM: success for %s via %s (%s) in %v, rcode=%s, answer=%d", original, server.Address, result.Protocol, result.Duration, dns.RcodeToString[result.Response.Rcode], len(result.Response.Answer))
	}

	return result
}

// SetKTLS configures kernel TLS offload for upstream DoT/DoH connections.
func (c *Client) SetKTLS(tx, rx bool) {
	c.tlsClient.SetKTLS(tx, rx)
}

// ReapDeadConns drops idle-recycled dead sockets/connections from ALL
// outbound pools (plain UDP/TCP, DoT, DTLS, DoQ, TLCP/DTLCP, DNSCrypt) so
// unused authoritative addresses do not pin memory and fds forever and do
// not keep counting against each pool's global cap.  Called periodically by
// the server.
func (c *Client) ReapDeadConns() {
	if c == nil {
		return
	}
	if c.plainClient != nil {
		c.plainClient.ReapDead()
	}
	if c.tlsClient != nil {
		c.tlsClient.ReapDead()
	}
	if c.tlcpClient != nil {
		c.tlcpClient.ReapDead()
	}
	if c.dnscryptClient != nil {
		c.dnscryptClient.ReapDead()
	}
}

// Close shuts down all pooled connections and transports.
func (c *Client) Close() {
	if c == nil {
		return
	}

	c.warmWg.Wait()

	c.plainClient.Close()
	c.tlsClient.Close()

	// The dialer map is intentionally NOT nil'd here: in-flight proxied
	// queries read c.proxyDialers from proxyDialer (warmup.go) and a nil
	// write would race those reads (same pattern as tls.Client.Close —
	// server/upstream/tls/client.go). The map dies with the Client.
	if c.proxyDialers != nil {
		// The dialers are closed by this Range (M-low).
		c.proxyDialers.Range(func(key string, d *socks5.Dialer) bool {
			if d != nil {
				_ = d.Close()
			}
			return true
		})
	}

	c.dnscryptClient.Close()
}

// needsTCPFallback checks whether a UDP result should be retried over TCP.
// Caller-side cancellation (resolver first-wins fan-out) is not a transport
// failure — falling back on it wastes a TCP attempt that fails immediately
// (M-low).
func (c *Client) needsTCPFallback(result *Result, protocol string) bool {
	if protocol == config.ProtoTCP || errors.Is(result.Error, context.Canceled) {
		return false
	}
	return result.Error != nil || (result.Response != nil && result.Response.Truncated)
}
