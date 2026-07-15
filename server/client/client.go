// Package client implements outbound DNS query execution over UDP, TCP, DoT,
// DoQ, DoH, and DoH3 with connection pooling.
package client

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
	"zjdns/config"
	"zjdns/edns"
	zdnsutil "zjdns/internal/dnsutil"
	"zjdns/internal/log"
	"zjdns/server/client/pool"

	"codeberg.org/miekg/dns"
	"github.com/quic-go/quic-go"
	eHTTP "gitlab.com/go-extension/http"
	eTLS "gitlab.com/go-extension/tls"
)

// Result holds the outcome of a single DNS query including response, timing,
// and metadata.
type Result struct {
	Response   *dns.Msg
	Answer     []dns.RR
	Authority  []dns.RR
	Additional []dns.RR
	Server     string
	Error      error
	Duration   time.Duration
	Protocol   string
	Validated  bool
	ECS        *edns.ECSOption
}

// Client manages outbound DNS queries across multiple transport protocols with
// pooling.
type Client struct {
	timeout    time.Duration
	udpClient  *dns.Client
	tcpClient  *dns.Client
	tlsClient  *dns.Client
	dohClient  *eHTTP.Client
	doh3Client *http.Client

	dohTransportMu sync.RWMutex
	dohTransports  map[string]*http.Client

	doh3TransportMu sync.RWMutex
	doh3Transports  map[string]*http.Client

	quicConfigs   map[string]*quic.Config
	quicConfigsMu sync.Mutex

	quicPool *pool.QUICPool

	SessionCache eTLS.ClientSessionCache

	tcpPool *pool.Pool
	dotPool *pool.Pool

	proxyDialers map[string]*SOCKS5Dialer
	proxyMu      sync.Mutex

	dnscryptCache   map[string]*dnscryptState
	dnscryptCacheMu sync.RWMutex

	warmWg sync.WaitGroup // tracks in-flight WarmUpConnections goroutines

	// KTLS offload settings — defaults to false (off). Set via SetKTLS() from
	// the server config before use.
	ktlsTX bool
	ktlsRX bool
}

// New creates a Client with default timeouts, transport pools, and session
// caches.
func New() *Client {
	defaultTransport := &dns.Transport{
		Dialer: &net.Dialer{
			Timeout:   config.DefaultDNSQueryTimeout,
			KeepAlive: 30 * time.Second,
		},
		ReadTimeout:  config.DefaultDNSQueryTimeout,
		WriteTimeout: config.DefaultDNSQueryTimeout,
	}

	udpClient := &dns.Client{Transport: defaultTransport}
	tcpClient := &dns.Client{Transport: defaultTransport}
	tlsClient := &dns.Client{Transport: defaultTransport}

	dohTransport := &eHTTP.Transport{
		MaxIdleConns:        config.DefaultMaxIdleConns,
		MaxIdleConnsPerHost: config.DefaultMaxIdleConnsPerHost,
		IdleConnTimeout:     config.DefaultHTTPIdleConnTimeout,
		DisableCompression:  true,
		ForceAttemptHTTP2:   true,
	}

	c := &Client{
		timeout:   config.DefaultDNSQueryTimeout,
		udpClient: udpClient,
		tcpClient: tcpClient,
		tlsClient: tlsClient,
		dohClient: &eHTTP.Client{
			Timeout:   config.DefaultDNSQueryTimeout,
			Transport: dohTransport,
		},
		doh3Client: &http.Client{
			Timeout: config.DefaultDNSQueryTimeout,
		},
		dohTransports:  make(map[string]*http.Client),
		doh3Transports: make(map[string]*http.Client),
		quicConfigs:    make(map[string]*quic.Config),
		quicPool:       pool.NewQUICPool(config.DefaultMaxConns),
		SessionCache:   eTLS.NewLRUClientSessionCache(config.DefaultTLSSessionCacheSize),
		dnscryptCache:  make(map[string]*dnscryptState),
		tcpPool:        pool.NewPool(config.DefaultMaxConns, config.DefaultMaxPipe),
		dotPool:        pool.NewPool(config.DefaultMaxConns, config.DefaultMaxPipe),
		proxyDialers:   make(map[string]*SOCKS5Dialer),
	}
	return c
}

// ExecuteQuery sends a DNS query to an upstream server and returns the result.
func (c *Client) ExecuteQuery(ctx context.Context, msg *dns.Msg, server *config.UpstreamServer) *Result {
	start := time.Now()
	result := &Result{Server: server.Address, Protocol: server.Protocol}

	qname := ""
	if len(msg.Question) > 0 {
		qname = msg.Question[0].Header().Name
	}
	log.Debugf("UPSTREAM: querying %s (%s) for %s", server.Address, strings.ToUpper(server.Protocol), qname)

	queryCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	protocol := strings.ToLower(server.Protocol)

	if protocol == config.ProtoDNSCrypt || protocol == config.ProtoDNSCryptTCP {
		useTCP := protocol == config.ProtoDNSCryptTCP
		result.Response, result.Error = c.executeDNSCrypt(queryCtx, msg, server, useTCP)

		// UDP→TCP fallback: retry over TCP on truncation, timeout, or
		// general error (e.g. query too large to pad for UDP), matching
		// dnscrypt-proxy's behaviour.
		if !useTCP && result.Error == nil && result.Response != nil && result.Response.Truncated {
			log.Debugf("UPSTREAM: DNSCrypt UDP response truncated for %s, falling back to TCP", qname)
			useTCP = true
		} else if !useTCP && result.Error != nil {
			log.Debugf("UPSTREAM: DNSCrypt UDP query failed for %s, falling back to TCP: %v", qname, result.Error)
			useTCP = true
		}

		if useTCP && protocol == config.ProtoDNSCrypt {
			if queryCtx.Err() == nil {
				result.Response, result.Error = c.executeDNSCrypt(queryCtx, msg, server, true)
				if result.Error == nil {
					protocol = config.ProtoDNSCryptTCP
					log.Debugf("UPSTREAM: DNSCrypt TCP fallback succeeded for %s", qname)
				} else {
					log.Debugf("UPSTREAM: DNSCrypt TCP fallback failed for %s: %v", qname, result.Error)
				}
			}
		} else if result.Error != nil {
			log.Debugf("UPSTREAM: DNSCrypt query failed for %s via %s: %v", qname, server.Address, result.Error)
		}

		result.Duration = time.Since(start)
		result.Protocol = strings.ToUpper(protocol)
		return result
	}

	if zdnsutil.IsSecureProtocol(protocol) {
		result.Response, result.Error = c.executeSecureQuery(queryCtx, msg, server, protocol)
	} else {
		result.Response, result.Error = c.executeTraditionalQuery(queryCtx, msg, server)

		if c.needsTCPFallback(result, protocol) {
			// Skip TCP fallback when the context is already cancelled — the
			// errgroup first-win pattern cancels sibling goroutines after one
			// succeeds, making TCP retry pointless and noisy in logs.
			if queryCtx.Err() != nil {
				return result
			}

			if result.Response != nil && result.Response.Truncated {
				log.Debugf("UPSTREAM: UDP response truncated for %s, falling back to TCP for %s", qname, server.Address)
			} else {
				log.Debugf("UPSTREAM: UDP query failed for %s, falling back to TCP for %s: %v", qname, server.Address, result.Error)
			}

			tcpServer := *server
			tcpServer.Protocol = config.ProtoTCP

			if tcpResp, tcpErr := c.executeTraditionalQuery(queryCtx, msg, &tcpServer); tcpErr == nil {
				result.Response = tcpResp
				result.Error = nil
				result.Protocol = config.ProtoTCP
				log.Debugf("UPSTREAM: TCP fallback succeeded for %s via %s", qname, server.Address)
			} else {
				log.Debugf("UPSTREAM: TCP fallback failed for %s via %s: %v", qname, server.Address, tcpErr)
			}
		}
	}

	result.Duration = time.Since(start)
	result.Protocol = strings.ToUpper(protocol)

	if result.Error != nil {
		log.Debugf("UPSTREAM: query failed for %s via %s (%s) in %v, error=%v", qname, server.Address, result.Protocol, result.Duration, result.Error)
	} else if result.Response != nil {
		log.Debugf("UPSTREAM: success for %s via %s (%s) in %v, rcode=%s, answer=%d", qname, server.Address, result.Protocol, result.Duration, dns.RcodeToString[result.Response.Rcode], len(result.Response.Answer))
	}

	return result
}

// stdTLSConfig builds a standard crypto/tls Config for QUIC-based upstream
// protocols (DoQ, DoH3). KTLS does not apply to QUIC. ClientSessionCache is
// omitted — QUIC uses 0-RTT tokens for session resumption.
func (c *Client) stdTLSConfig(server *config.UpstreamServer) *tls.Config {
	return &tls.Config{
		CurvePreferences:   []tls.CurveID{},
		InsecureSkipVerify: server.SkipTLSVerify, //nolint:gosec // G402: user-configured TLS verification
		MinVersion:         tls.VersionTLS12,
		ServerName:         server.ServerName,
		VerifyConnection: func(cs tls.ConnectionState) error {
			zdnsutil.LogTLSConnectionState("UPSTREAM", "negotiated for", server.Address, cs.Version, cs.CipherSuite, cs.CurveID)
			return nil
		},
	}
}

func (c *Client) executeSecureQuery(ctx context.Context, msg *dns.Msg, server *config.UpstreamServer, protocol string) (*dns.Msg, error) {
	if server.SkipTLSVerify {
		log.Warnf("UPSTREAM: TLS verification disabled for %s — connection is vulnerable to MITM attacks!", server.ServerName)
	}

	switch protocol {
	case config.ProtoTLS:
		return c.executeTLS(ctx, msg, server, c.eTLSClientConfig(server))
	case config.ProtoQUIC:
		return c.executeQUIC(ctx, msg, server, c.stdTLSConfig(server))
	case config.ProtoHTTP:
		return c.executeDOH(ctx, msg, server, c.eTLSClientConfig(server))
	case config.ProtoHTTP3:
		return c.executeDOH3(ctx, msg, server, c.stdTLSConfig(server))
	case config.ProtoTLCP:
		return c.executeTLCP(ctx, msg, server, c.tlcpClientConfig(server))
	case config.ProtoDTLS:
		return c.executeDTLS(ctx, msg, server)
	case config.ProtoDTLCP:
		return c.executeDTLCP(ctx, msg, server)
	case config.ProtoHTTPTLCP:
		return c.executeDOH_TLCP(ctx, msg, server, c.tlcpClientConfig(server))
	default:
		return nil, fmt.Errorf("unsupported protocol: %s", protocol)
	}
}

// SetKTLS configures kernel TLS offload for upstream DoT/DoH connections.
// Both default to false (off). TX (encryption) is typically safe; RX
// (decryption) may produce "bad record MAC" on some kernel/NIC combos.
func (c *Client) SetKTLS(tx, rx bool) {
	c.ktlsTX = tx
	c.ktlsRX = rx
}

// Close shuts down all pooled connections and transports.
func (c *Client) Close() {
	if c == nil {
		return
	}

	c.warmWg.Wait()

	c.dohTransportMu.Lock()
	for _, client := range c.dohTransports {
		if ct, ok := client.Transport.(*eHTTP.CompatableTransport); ok {
			ct.CloseIdleConnections()
		}
	}
	c.dohTransports = nil
	c.dohTransportMu.Unlock()

	c.doh3TransportMu.Lock()
	for _, client := range c.doh3Transports {
		if t, ok := client.Transport.(*http3Transport); ok {
			_ = t.Close()
		}
	}
	c.doh3Transports = nil
	c.doh3TransportMu.Unlock()

	if c.tcpPool != nil {
		c.tcpPool.Shutdown()
	}
	if c.dotPool != nil {
		c.dotPool.Shutdown()
	}
	if c.quicPool != nil {
		c.quicPool.Shutdown()
	}

	c.proxyMu.Lock()
	for _, d := range c.proxyDialers {
		if d != nil {
			_ = d.Close()
		}
	}
	c.proxyDialers = nil
	c.proxyMu.Unlock()

	c.dnscryptCacheMu.Lock()
	c.dnscryptCache = nil
	c.dnscryptCacheMu.Unlock()
}
