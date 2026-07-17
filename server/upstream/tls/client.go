// Package tls implements outbound DNS queries over encrypted transports: DoT,
// DoQ, DoH, DoH3, and DTLS.
package tls

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"
	"zjdns/config"
	zdnsutil "zjdns/internal/dnsutil"
	"zjdns/internal/log"
	"zjdns/server/upstream/pool"
	socks5 "zjdns/server/upstream/socks5"

	"codeberg.org/miekg/dns"
	"github.com/quic-go/quic-go"
	eHTTP "gitlab.com/go-extension/http"
	eTLS "gitlab.com/go-extension/tls"
)

// Client executes DNS queries over encrypted transports: DoT, DoQ, DoH, DoH3,
// and DTLS.
type Client struct {
	tlsClient  *dns.Client
	dohClient  *eHTTP.Client
	doh3Client *http.Client

	dotPool  *pool.ConnPool
	quicPool *pool.QUIC

	sessionCache eTLS.ClientSessionCache

	quicConfigs   map[string]*quic.Config
	quicConfigsMu sync.Mutex

	dohTransports   map[string]*http.Client
	dohTransportMu  sync.RWMutex
	doh3Transports  map[string]*http.Client
	doh3TransportMu sync.RWMutex

	getProxy func(*config.UpstreamServer) *socks5.Dialer

	ktlsTX  bool
	ktlsRX  bool
	timeout time.Duration
}

// New creates a Client for encrypted DNS transports.
func New(
	tlsClient *dns.Client,
	dohClient *eHTTP.Client,
	doh3Client *http.Client,
	dotPool *pool.ConnPool,
	quicPool *pool.QUIC,
	sessionCache eTLS.ClientSessionCache,
	getProxy func(*config.UpstreamServer) *socks5.Dialer,
	timeout time.Duration,
) *Client {
	return &Client{
		tlsClient:      tlsClient,
		dohClient:      dohClient,
		doh3Client:     doh3Client,
		dotPool:        dotPool,
		quicPool:       quicPool,
		sessionCache:   sessionCache,
		quicConfigs:    make(map[string]*quic.Config),
		dohTransports:  make(map[string]*http.Client),
		doh3Transports: make(map[string]*http.Client),
		getProxy:       getProxy,
		timeout:        timeout,
	}
}

// SetKTLS configures kernel TLS offload for upstream DoT/DoH connections.
func (c *Client) SetKTLS(tx, rx bool) {
	c.ktlsTX = tx
	c.ktlsRX = rx
}

// Close shuts down all pooled connections and transports owned by this client.
func (c *Client) Close() {
	if c == nil {
		return
	}

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

	if c.dotPool != nil {
		c.dotPool.Shutdown()
	}
	if c.quicPool != nil {
		c.quicPool.Shutdown()
	}
}

// eTLSClientConfig builds a go-extension/tls Config with kernel TLS offload
// (KTLS) for TCP-based upstream protocols (DoT, DoH).
func (c *Client) eTLSClientConfig(server *config.UpstreamServer) *eTLS.Config {
	return &eTLS.Config{
		KernelTX:           c.ktlsTX,
		KernelRX:           c.ktlsRX,
		CurvePreferences:   []eTLS.CurveID{},
		InsecureSkipVerify: server.SkipTLSVerify,
		MinVersion:         eTLS.VersionTLS12,
		ServerName:         server.ServerName,
		ClientSessionCache: c.sessionCache,
		VerifyConnection: func(cs eTLS.ConnectionState) error {
			zdnsutil.LogTLSConnectionState("UPSTREAM", "negotiated for", server.Address, cs.Version, cs.CipherSuite, cs.CurveID)
			return nil
		},
	}
}

// stdTLSConfig builds a standard crypto/tls Config for QUIC-based upstream
// protocols (DoQ, DoH3). KTLS does not apply to QUIC.
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

// getQUICConfig returns a cached QUIC config for the given upstream key.
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

// resetQUICConfig recreates the TokenStore for the given upstream key on
// 0-RTT rejection.
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

// WarmUpTLS pre-establishes a pipelined DoT connection.
func (c *Client) WarmUpTLS(ctx context.Context, server *config.UpstreamServer) {
	key := transportKey(server.Address, server.ServerName, server.SkipTLSVerify, server.Proxy)
	proxyDialer := c.getProxy(server)
	dotConfig := c.eTLSClientConfig(server).Clone()
	dotConfig.NextProtos = config.NextProtoDOT
	if c.dotPool != nil {
		if err := c.dotPool.WarmUp(ctx, key, server.Address, func(dialCtx context.Context, addr string) (net.Conn, error) {
			return c.dialTLSConn(dialCtx, addr, dotConfig, proxyDialer)
		}); err != nil {
			log.Debugf("UPSTREAM: pre-warm DoT to %s: %v", server.Address, err)
			return
		}
		log.Debugf("UPSTREAM: pre-warmed DoT connection to %s", server.Address)
	}
}

// WarmUpQUIC pre-establishes a QUIC connection for DoQ.
func (c *Client) WarmUpQUIC(ctx context.Context, server *config.UpstreamServer) {
	poolKey := server.Address
	if server.Proxy != "" {
		poolKey = server.Address + "|" + server.Proxy
	}
	proxyDialer := c.getProxy(server)
	dialTLS := c.stdTLSConfig(server).Clone()
	dialTLS.NextProtos = config.NextProtoDOQ
	if c.quicPool != nil {
		if err := c.quicPool.WarmUp(ctx, poolKey, func(dialCtx context.Context, addr string) (*quic.Conn, error) {
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
		}); err != nil {
			log.Debugf("UPSTREAM: pre-warm DoQ to %s: %v", server.Address, err)
			return
		}
		log.Debugf("UPSTREAM: pre-warmed DoQ connection to %s", server.Address)
	}
}

// WarmUpHTTPS pre-creates a DoH transport.
func (c *Client) WarmUpHTTPS(_ context.Context, server *config.UpstreamServer) {
	parsedURL, err := url.Parse(server.Address)
	if err != nil {
		log.Debugf("UPSTREAM: pre-warm DoH parse %s: %v", server.Address, err)
		return
	}
	if parsedURL.Port() == "" {
		parsedURL.Host = net.JoinHostPort(parsedURL.Host, config.DefaultHTTPSPort)
	}
	key := transportKey(parsedURL.Host, server.ServerName, server.SkipTLSVerify, server.Proxy)
	tlsConfig := c.eTLSClientConfig(server)
	c.createDOHClient(parsedURL.Host, server.ServerName, server.SkipTLSVerify, server.Proxy, tlsConfig)
	log.Debugf("UPSTREAM: pre-warmed DoH transport for %s (key=%s)", server.Address, key)
}

// WarmUpHTTP3 pre-creates a DoH3 transport.
func (c *Client) WarmUpHTTP3(_ context.Context, server *config.UpstreamServer) {
	parsedURL, err := url.Parse(server.Address)
	if err != nil {
		log.Debugf("UPSTREAM: pre-warm DoH3 parse %s: %v", server.Address, err)
		return
	}
	if parsedURL.Port() == "" {
		parsedURL.Host = net.JoinHostPort(parsedURL.Host, config.DefaultHTTPSPort)
	}
	key := transportKey(parsedURL.Host, server.ServerName, server.SkipTLSVerify, server.Proxy)
	tlsConfig := c.stdTLSConfig(server)
	c.createDOH3Client(key, parsedURL.Host, server.Proxy, tlsConfig)
	log.Debugf("UPSTREAM: pre-warmed DoH3 transport for %s (key=%s)", server.Address, key)
}
