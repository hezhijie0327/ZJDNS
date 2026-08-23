// Package upstream implements outbound DNS query execution over UDP, TCP, DoT,
// DoQ, DoH, DoH3, DNSCrypt, TLCP, and DTLCP with connection pooling.
package upstream

import (
	"context"
	"errors"
	"fmt"
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

	zdnsutil "zjdns/internal/dnsutil"

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
	if server.CapsGuard && original != "" {
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

// execute performs one DNS exchange attempt: deadline wrapping, protocol
// dispatch, and DNSCrypt/UDP→TCP fallback.  The 0x20 randomization and echo
// verification live in ExecuteQuery — the mismatch retry reuses this path
// with the original-case message — and Duration is accounted there so a
// retry measures the combined attempts.
func (c *Client) execute(ctx context.Context, msg *dns.Msg, server *config.UpstreamServer) *Result {
	result := &Result{Server: server.Address, Protocol: server.Protocol}

	qname := ""
	if len(msg.Question) > 0 {
		qname = msg.Question[0].Header().Name
	}

	// Avoid a nested timeout timer when the caller already carries a tighter
	// deadline (recursive resolution wraps every NS query in a 9s deadline) —
	// a second WithTimeout duplicated the timer + context per query (a
	// dominant allocation under full guards).
	queryCtx := ctx
	var cancel context.CancelFunc
	if dl, ok := ctx.Deadline(); !ok || time.Until(dl) > c.timeout {
		queryCtx, cancel = context.WithTimeout(ctx, c.timeout)
	}
	if cancel != nil {
		defer cancel()
	}

	// Protocol is normalized to lowercase at registration (ConfigureServers);
	// the per-query ToLower scan is gone from the upstream hot path.
	protocol := server.Protocol

	if protocol == config.ProtoDNSCrypt || protocol == config.ProtoDNSCryptTCP {
		useTCP := protocol == config.ProtoDNSCryptTCP
		result.Response, result.Error = c.dnscryptClient.Execute(queryCtx, msg, server, useTCP)

		if !useTCP && result.Error == nil && result.Response != nil && result.Response.Truncated {
			log.Debugf("UPSTREAM: DNSCrypt UDP response truncated for %s, falling back to TCP", qname)
			useTCP = true
		} else if !useTCP && result.Error != nil {
			log.Debugf("UPSTREAM: DNSCrypt UDP query failed for %s, falling back to TCP: %v", qname, result.Error)
			useTCP = true
		}

		if useTCP && protocol == config.ProtoDNSCrypt {
			// Use a fresh context for the TCP fallback — the UDP
			// attempt may have exhausted the original deadline.
			tcpCtx, tcpCancel := context.WithTimeout(ctx, c.timeout)
			defer tcpCancel()
			if result.Response != nil {
				zpool.DefaultMessage.Put(result.Response)
				result.Response = nil
			}
			result.Response, result.Error = c.dnscryptClient.Execute(tcpCtx, msg, server, true)
			if result.Error == nil {
				protocol = config.ProtoDNSCryptTCP
				log.Debugf("UPSTREAM: DNSCrypt TCP fallback succeeded for %s", qname)
			} else {
				log.Debugf("UPSTREAM: DNSCrypt TCP fallback failed for %s: %v", qname, result.Error)
			}
		} else if result.Error != nil {
			log.Debugf("UPSTREAM: DNSCrypt query failed for %s via %s: %v", qname, server.Address, result.Error)
		}

		result.Protocol = protocol
		return result
	}

	if zdnsutil.IsSecureProtocol(protocol) {
		result.Response, result.Error = c.executeSecureQuery(queryCtx, msg, server, protocol)
	} else {
		if protocol == config.ProtoTCP {
			result.Response, result.Error = c.plainClient.ExecuteTCP(queryCtx, msg, server)
		} else {
			result.Response, result.Error = c.plainClient.ExecuteUDP(queryCtx, msg, server)
		}

		result.Protocol = server.Protocol

		if c.needsTCPFallback(result, protocol) {
			if result.Response != nil && result.Response.Truncated {
				log.Debugf("UPSTREAM: UDP response truncated for %s, falling back to TCP for %s", qname, server.Address)
			} else {
				log.Debugf("UPSTREAM: UDP query failed for %s, falling back to TCP for %s: %v", qname, server.Address, result.Error)
			}

			// Use a fresh context — the UDP attempt may have
			// exhausted the original deadline.  WithTimeout takes the
			// EARLIER of parent-deadline and timeout, so when the caller
			// set a budget the combined wait cannot exceed it; only
			// deadline-less parents get the full c.timeout here (M-low).
			tcpCtx, tcpCancel := context.WithTimeout(ctx, c.timeout)
			defer tcpCancel()

			tcpServer := *server
			tcpServer.Protocol = config.ProtoTCP

			if tcpResp, tcpErr := c.plainClient.ExecuteTCP(tcpCtx, msg, &tcpServer); tcpErr == nil {
				if result.Response != nil {
					zpool.DefaultMessage.Put(result.Response)
				}
				result.Response = tcpResp
				result.Error = nil
				result.Protocol = config.ProtoTCP
				log.Debugf("UPSTREAM: TCP fallback succeeded for %s via %s", qname, server.Address)
			} else {
				log.Debugf("UPSTREAM: TCP fallback failed for %s via %s: %v", qname, server.Address, tcpErr)
				// Discard the truncated UDP response — returning it as a
				// success would serve incomplete data without a TC signal.
				if result.Response != nil {
					zpool.DefaultMessage.Put(result.Response)
					result.Response = nil
				}
				if result.Error == nil {
					result.Error = fmt.Errorf("tcp fallback after truncated response failed: %w", tcpErr)
				} else {
					// Both transports failed — join the errors so neither
					// the original UDP failure nor the TCP failure is lost
					// for diagnostics (M-low).
					result.Error = errors.Join(result.Error, fmt.Errorf("tcp fallback failed: %w", tcpErr))
				}
			}
		}
	}

	return result
}

func (c *Client) executeSecureQuery(ctx context.Context, msg *dns.Msg, server *config.UpstreamServer, protocol string) (*dns.Msg, error) {
	if server.SkipTLSVerify {
		if _, loaded := c.skipVerifyWarned.LoadOrStore(server.ServerName, struct{}{}); !loaded {
			log.Warnf("UPSTREAM: TLS verification disabled for %s — connection is vulnerable to MITM attacks!", server.ServerName)
		}
	}

	log.Debugf("UPSTREAM: secure query to %s via %s", server.Address, protocol)
	switch protocol {
	case config.ProtoTLS:
		return c.tlsClient.ExecuteTLS(ctx, msg, server)
	case config.ProtoQUIC:
		return c.tlsClient.ExecuteQUIC(ctx, msg, server)
	case config.ProtoHTTPS:
		return c.tlsClient.ExecuteHTTPS(ctx, msg, server)
	case config.ProtoHTTP3:
		return c.tlsClient.ExecuteHTTP3(ctx, msg, server)
	case config.ProtoDTLS:
		// RFC 8094 §3.3: fall back to TLS when DTLS fails (e.g. PMTU
		// drops large responses).  This works when DTLS and TLS share
		// the same port — the standard deployment is port 853 where
		// DTLS is UDP and TLS (DoT) is TCP.  The fallback dials TCP
		// to the same address; if the upstream has no TLS listener on
		// that port the fallback fails with "connection refused" (no
		// worse than no fallback at all).
		resp, err := c.tlsClient.ExecuteDTLS(ctx, msg, server)
		if err == nil {
			return resp, nil
		}
		log.Debugf("UPSTREAM: DTLS query failed for %s, falling back to TLS: %v", server.Address, err)
		return c.tlsClient.ExecuteTLS(ctx, msg, server)
	case config.ProtoTLCP:
		return c.tlcpClient.ExecuteTLCP(ctx, msg, server)
	case config.ProtoHTTPTLCP:
		return c.tlcpClient.ExecuteHTTPTLCP(ctx, msg, server)
	case config.ProtoDTLCP:
		// Same RFC 8094 §3.3 pattern as DTLS→TLS: fall back to TLCP
		// when DTLCP fails.  Works when both share the same port.
		resp, err := c.tlcpClient.ExecuteDTLCP(ctx, msg, server)
		if err == nil {
			return resp, nil
		}
		log.Debugf("UPSTREAM: DTLCP query failed for %s, falling back to TLCP: %v", server.Address, err)
		return c.tlcpClient.ExecuteTLCP(ctx, msg, server)
	default:
		return nil, fmt.Errorf("unsupported protocol: %s", protocol)
	}
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
		// The dialers are closed by this Range (M-low: comment previously
		// pointed above the block instead of at it).
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
