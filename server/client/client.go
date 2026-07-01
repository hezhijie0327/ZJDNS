// Package client implements outbound DNS query execution over UDP, TCP, DoT,
// DoQ, DoH, and DoH3 with connection pooling.
package client

import (
	"context"
	"crypto/tls"
	"fmt"
	eTLS "gitlab.com/go-extension/tls"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"

	"zjdns/config"
	"zjdns/edns"
	"zjdns/internal/dnsutil"
	"zjdns/internal/log"
	"zjdns/internal/pool"

	connpool "zjdns/server/client/pool"
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
	dohClient  *http.Client
	doh3Client *http.Client

	dohTransportMu sync.RWMutex
	dohTransports  map[string]*http.Client

	doh3TransportMu sync.RWMutex
	doh3Transports  map[string]*http.Client

	quicConfigs   map[string]*quic.Config
	quicConfigsMu sync.Mutex

	quicPool *connpool.QUICPool

	SessionCache eTLS.ClientSessionCache

	tcpPool *connpool.Pool
	dotPool *connpool.Pool

	proxyDialers map[string]*SOCKS5Dialer
	proxyMu      sync.Mutex

	// KTLS offload settings — defaults to false (off). Set via SetKTLS() from
	// the server config before use.
	ktlsTX bool
	ktlsRX bool
}

// New creates a Client with default timeouts, transport pools, and session
// caches.
func New() *Client {
	udpClient := &dns.Client{
		Timeout: config.DefaultDNSQueryTimeout,
		Net:     config.ProtoUDP,
		UDPSize: pool.UDPBufferSize,
	}

	tcpClient := &dns.Client{
		Timeout: config.DefaultDNSQueryTimeout,
		Net:     config.ProtoTCP,
	}

	tlsClient := &dns.Client{
		Timeout: config.DefaultDNSQueryTimeout,
		Net:     config.ProtoTLSTCP,
	}

	dohTransport := &http.Transport{
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
		dohClient: &http.Client{
			Timeout:   config.DefaultDNSQueryTimeout,
			Transport: dohTransport,
		},
		doh3Client: &http.Client{
			Timeout: config.DefaultDNSQueryTimeout,
		},
		dohTransports:  make(map[string]*http.Client),
		doh3Transports: make(map[string]*http.Client),
		quicConfigs:    make(map[string]*quic.Config),
		quicPool:       connpool.NewQUICPool(config.DefaultMaxConns),
		SessionCache:   eTLS.NewLRUClientSessionCache(config.DefaultTLSSessionCacheSize),
		tcpPool:        connpool.NewPool(config.DefaultMaxConns, config.DefaultMaxPipe),
		dotPool:        connpool.NewPool(config.DefaultMaxConns, config.DefaultMaxPipe),
		proxyDialers:   make(map[string]*SOCKS5Dialer),
	}
	return c
}

// getQUICConfig returns a cached QUIC config for the given upstream key, creating
// one with a TokenStore if none exists. When skipVerify is true (TLS verification
// disabled), 0-RTT is also disabled to prevent replay attacks — without certificate
// verification there is no way to authenticate the server receiving 0-RTT data.
func (c *Client) getQUICConfig(key string, skipVerify bool) *quic.Config {
	c.quicConfigsMu.Lock()
	defer c.quicConfigsMu.Unlock()
	if cfg, ok := c.quicConfigs[key]; ok {
		return cfg
	}
	if len(c.quicConfigs) >= config.DefaultTransportMax {
		for k := range c.quicConfigs {
			delete(c.quicConfigs, k)
			break
		}
	}
	cfg := &quic.Config{
		MaxIdleTimeout:        config.DefaultQUICClientIdleTimeout,
		MaxIncomingStreams:    config.DefaultMaxIncomingStreams,
		MaxIncomingUniStreams: config.DefaultMaxIncomingStreams,
		EnableDatagrams:       true,
		Allow0RTT:             !skipVerify,
		KeepAlivePeriod:       config.DefaultQUICKeepAlive,
		TokenStore:            quic.NewLRUTokenStore(config.DefaultTokenStoreCapacity, config.DefaultTokenStoreMaxEntries),
	}
	c.quicConfigs[key] = cfg
	return cfg
}

// resetQUICConfig recreates the TokenStore for the given upstream key. Call this
// when the server rejects 0-RTT (quic.Err0RTTRejected) to clear stale
// address-validation tokens.
func (c *Client) resetQUICConfig(key string) {
	c.quicConfigsMu.Lock()
	defer c.quicConfigsMu.Unlock()
	cfg, ok := c.quicConfigs[key]
	if !ok {
		return
	}
	cfg = cfg.Clone()
	cfg.TokenStore = quic.NewLRUTokenStore(config.DefaultTokenStoreCapacity, config.DefaultTokenStoreMaxEntries)
	c.quicConfigs[key] = cfg
}

// getProxyDialer returns a cached SOCKS5Dialer for the server's proxy URL.
// Returns nil when no proxy is configured or the proxy URL is invalid
// (the validation error is logged once and the nil is cached).
func (c *Client) getProxyDialer(server *config.UpstreamServer) *SOCKS5Dialer {
	if server.Proxy == "" {
		return nil
	}

	c.proxyMu.Lock()
	defer c.proxyMu.Unlock()

	if d, ok := c.proxyDialers[server.Proxy]; ok {
		return d
	}

	// Evict oldest entry when at capacity (same pattern as dohTransports).
	if len(c.proxyDialers) >= config.DefaultTransportMax {
		for k, d := range c.proxyDialers {
			if d != nil {
				_ = d.Close()
			}
			delete(c.proxyDialers, k)
			break
		}
	}

	d, err := NewSOCKS5Dialer(server.Proxy, c.timeout)
	if err != nil {
		log.Warnf("UPSTREAM: invalid proxy %s for %s: %v", d.SafeURL(), server.Address, err)
		// Cache nil so we don't retry parsing the same bad URL.
		c.proxyDialers[server.Proxy] = nil
		return nil
	}
	c.proxyDialers[server.Proxy] = d
	return d
}

// proxyPoolKey returns a pool key that includes the proxy URL to ensure
// proxied and non-proxied connections to the same upstream are isolated.
func proxyPoolKey(baseKey, proxyURL string) string {
	if proxyURL == "" {
		return baseKey
	}
	return baseKey + "|" + proxyURL
}

// ExecuteQuery sends a DNS query to an upstream server and returns the result.
func (c *Client) ExecuteQuery(ctx context.Context, msg *dns.Msg, server *config.UpstreamServer) *Result {
	start := time.Now()
	result := &Result{Server: server.Address, Protocol: server.Protocol}

	qname := ""
	if len(msg.Question) > 0 {
		qname = msg.Question[0].Name
	}
	log.Debugf("UPSTREAM: querying %s (%s) for %s", server.Address, strings.ToUpper(server.Protocol), qname)

	queryCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	protocol := strings.ToLower(server.Protocol)

	if dnsutil.IsSecureProtocol(protocol) {
		result.Response, result.Error = c.executeSecureQuery(queryCtx, msg, server, protocol)
	} else {
		result.Response, result.Error = c.executeTraditionalQuery(queryCtx, msg, server)

		if c.needsTCPFallback(result, protocol) {
			log.Debugf("UPSTREAM: UDP truncated/failed for %s, falling back to TCP for %s", qname, server.Address)
			tcpServer := *server
			tcpServer.Protocol = config.ProtoTCP

			if tcpResp, tcpErr := c.executeTraditionalQuery(queryCtx, msg, &tcpServer); tcpErr == nil {
				result.Response = tcpResp
				result.Error = nil
				result.Protocol = "TCP"
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
		InsecureSkipVerify: server.SkipTLSVerify,
		MinVersion:         tls.VersionTLS12,
		ServerName:         server.ServerName,
		VerifyConnection: func(cs tls.ConnectionState) error {
			dnsutil.LogTLSConnectionState("UPSTREAM", "negotiated for", server.Address, cs.Version, cs.CipherSuite, cs.CurveID)
			return nil
		},
	}
}

func (c *Client) executeSecureQuery(ctx context.Context, msg *dns.Msg, server *config.UpstreamServer, protocol string) (*dns.Msg, error) {
	if server.SkipTLSVerify {
		log.Debugf("UPSTREAM: TLS verification disabled for %s - security risk!", server.ServerName)
	}

	switch protocol {
	case config.ProtoDOT, config.ProtoTLS:
		return c.executeTLS(ctx, msg, server, c.eTLSClientConfig(server))
	case config.ProtoDOQ, config.ProtoQUIC:
		return c.executeQUIC(ctx, msg, server, c.stdTLSConfig(server))
	case config.ProtoDOH, config.ProtoHTTP:
		return c.executeDoH(ctx, msg, server, c.eTLSClientConfig(server))
	case config.ProtoDOH3, config.ProtoHTTP3:
		return c.executeDoH3(ctx, msg, server, c.stdTLSConfig(server))
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

// WarmUpConnections asynchronously pre-establishes transport-level connections
// to all configured secure upstream servers. This avoids paying the full TLS/QUIC
// handshake cost on the first real query. Non-secure and recursive servers are
// skipped. Errors are logged at Debug level — pre-warming is best-effort.
func (c *Client) WarmUpConnections(servers []config.UpstreamServer) {
	for _, server := range servers {
		if server.IsRecursive() {
			continue
		}
		protocol := strings.ToLower(server.Protocol)
		if !dnsutil.IsSecureProtocol(protocol) {
			continue
		}
		// Capture loop variable for the goroutine.
		s := server
		go func() {
			defer dnsutil.HandlePanic("connection pre-warm")
			warmCtx, cancel := context.WithTimeout(context.Background(), c.timeout)
			defer cancel()
			c.warmUpConnection(warmCtx, &s, protocol)
		}()
	}
}

func (c *Client) warmUpConnection(ctx context.Context, server *config.UpstreamServer, protocol string) {
	switch protocol {
	case config.ProtoDOT, config.ProtoTLS:
		key := transportKey(server.Address, server.ServerName, server.SkipTLSVerify, server.Proxy)
		proxyDialer := c.getProxyDialer(server)
		dotConfig := c.eTLSClientConfig(server).Clone()
		dotConfig.NextProtos = []string{"dot"}
		if c.dotPool != nil {
			pc, err := c.dotPool.Acquire(ctx, key, server.Address, func(dialCtx context.Context, addr string) (net.Conn, error) {
				return c.dialTLSConn(dialCtx, addr, dotConfig, proxyDialer)
			})
			if err != nil {
				log.Debugf("UPSTREAM: pre-warm DoT to %s: %v", server.Address, err)
				return
			}
			log.Debugf("UPSTREAM: pre-warmed DoT connection to %s", server.Address)
			_ = pc // connection is now in the pool
		}

	case config.ProtoDOQ, config.ProtoQUIC:
		poolKey := proxyPoolKey(server.Address, server.Proxy)
		proxyDialer := c.getProxyDialer(server)
		dialTLS := c.stdTLSConfig(server).Clone()
		dialTLS.NextProtos = config.NextProtoDOQ
		if c.quicPool != nil {
			_, err := c.quicPool.Acquire(ctx, poolKey, func(dialCtx context.Context, addr string) (*quic.Conn, error) {
				timeoutCtx, cancel := context.WithTimeout(dialCtx, config.DefaultDNSQueryTimeout)
				defer cancel()
				if proxyDialer != nil {
					pconn, err := proxyDialer.ListenPacket(timeoutCtx)
					if err != nil {
						return nil, fmt.Errorf("proxy ListenPacket: %w", err)
					}
					remoteAddr, err := net.ResolveUDPAddr("udp", addr)
					if err != nil {
						return nil, fmt.Errorf("resolve %s: %w", addr, err)
					}
					return quic.Dial(timeoutCtx, pconn, remoteAddr, dialTLS, c.getQUICConfig("doq:"+addr, dialTLS.InsecureSkipVerify))
				}
				return quic.DialAddrEarly(timeoutCtx, addr, dialTLS, c.getQUICConfig("doq:"+addr, dialTLS.InsecureSkipVerify))
			})
			if err != nil {
				log.Debugf("UPSTREAM: pre-warm DoQ to %s: %v", server.Address, err)
				return
			}
			log.Debugf("UPSTREAM: pre-warmed DoQ connection to %s", server.Address)
		}

	case config.ProtoDOH, config.ProtoHTTP:
		parsedURL, err := url.Parse(server.Address)
		if err != nil {
			log.Debugf("UPSTREAM: pre-warm DoH parse %s: %v", server.Address, err)
			return
		}
		if parsedURL.Port() == "" {
			parsedURL.Host = net.JoinHostPort(parsedURL.Host, config.DefaultDOHPort)
		}
		key := transportKey(parsedURL.Host, server.ServerName, server.SkipTLSVerify, server.Proxy)
		tlsConfig := c.eTLSClientConfig(server)
		c.createDoHClient(parsedURL.Host, server.ServerName, server.SkipTLSVerify, server.Proxy, tlsConfig)
		// H2 connections are established lazily on first use; the transport
		// is now ready and will pool connections once used.
		log.Debugf("UPSTREAM: pre-warmed DoH transport for %s (key=%s)", server.Address, key)

	case config.ProtoDOH3, config.ProtoHTTP3:
		parsedURL, err := url.Parse(server.Address)
		if err != nil {
			log.Debugf("UPSTREAM: pre-warm DoH3 parse %s: %v", server.Address, err)
			return
		}
		if parsedURL.Port() == "" {
			parsedURL.Host = net.JoinHostPort(parsedURL.Host, config.DefaultDOHPort)
		}
		key := transportKey(parsedURL.Host, server.ServerName, server.SkipTLSVerify, server.Proxy)
		tlsConfig := c.stdTLSConfig(server)
		c.createDoH3Client(key, parsedURL.Host, server.Proxy, tlsConfig)
		log.Debugf("UPSTREAM: pre-warmed DoH3 transport for %s (key=%s)", server.Address, key)
	}
}

// Close shuts down all pooled connections and transports, releasing file
// descriptors and goroutines. Safe to call multiple times.
func (c *Client) Close() {
	if c == nil {
		return
	}

	// Close DoH transports (HTTP/2 connections)
	c.dohTransportMu.Lock()
	for _, client := range c.dohTransports {
		if t, ok := client.Transport.(*http.Transport); ok {
			t.CloseIdleConnections()
		}
	}
	c.dohTransports = nil
	c.dohTransportMu.Unlock()

	// Close DoH3 transports (QUIC/HTTP3 connections)
	c.doh3TransportMu.Lock()
	for _, client := range c.doh3Transports {
		if t, ok := client.Transport.(*http3Transport); ok {
			_ = t.Close()
		}
	}
	c.doh3Transports = nil
	c.doh3TransportMu.Unlock()

	// Close pooled TCP/DoT connections
	if c.tcpPool != nil {
		c.tcpPool.Shutdown()
	}
	if c.dotPool != nil {
		c.dotPool.Shutdown()
	}

	// Close pooled QUIC connections
	if c.quicPool != nil {
		c.quicPool.Shutdown()
	}

	// Close proxy dialers
	c.proxyMu.Lock()
	for _, d := range c.proxyDialers {
		if d != nil {
			_ = d.Close()
		}
	}
	c.proxyDialers = nil
	c.proxyMu.Unlock()
}
