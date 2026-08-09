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
	"time"
	"zjdns/config"
	zdnsutil "zjdns/internal/dnsutil"
	"zjdns/internal/log"
	"zjdns/internal/lrumap"
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
	dtlsPool *pool.ConnPool

	sessionCache eTLS.ClientSessionCache

	quicSessionCache tls.ClientSessionCache
	dtlsSessions     *lrumap.DTLSSessionStore

	quicConfigs *lrumap.Map[string, *quic.Config]

	dohTransports  *lrumap.Map[string, *http.Client]
	doh3Transports *lrumap.Map[string, *http.Client]

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
	quicSessionCache tls.ClientSessionCache,
	dtlsSessions *lrumap.DTLSSessionStore,
	getProxy func(*config.UpstreamServer) *socks5.Dialer,
	timeout time.Duration,
) *Client {
	c := &Client{
		tlsClient:        tlsClient,
		dohClient:        dohClient,
		doh3Client:       doh3Client,
		dotPool:          dotPool,
		quicPool:         quicPool,
		dtlsPool:         pool.NewConnPool(config.DefaultMaxConns, config.DefaultMaxPipe, config.DefaultMaxPoolTotalConns),
		sessionCache:     sessionCache,
		quicSessionCache: quicSessionCache,
		dtlsSessions:     dtlsSessions,
		quicConfigs:      lrumap.New[string, *quic.Config](config.DefaultQUICConfigCacheSize),
		dohTransports:    lrumap.New[string, *http.Client](config.DefaultTransportMax * 2),
		doh3Transports:   lrumap.New[string, *http.Client](config.DefaultTransportMax),
		getProxy:         getProxy,
		timeout:          timeout,
	}
	c.dohTransports.SetOnEvict(func(_ string, client *http.Client) {
		if ct, ok := client.Transport.(*eHTTP.CompatableTransport); ok {
			ct.CloseIdleConnections()
		}
	})
	c.doh3Transports.SetOnEvict(func(_ string, client *http.Client) {
		if t, ok := client.Transport.(*http3Transport); ok {
			_ = t.Close()
		}
	})
	return c
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

	// Note: the LRU maps are intentionally NOT nil'd here — in-flight
	// queries read them (guarded by nil checks at the call sites), and a
	// nil write would race those reads. The maps die with the Client.
	if c.dohTransports != nil {
		c.dohTransports.Range(func(key string, client *http.Client) bool {
			if ct, ok := client.Transport.(*eHTTP.CompatableTransport); ok {
				ct.CloseIdleConnections()
			}
			return true
		})
	}
	if c.doh3Transports != nil {
		c.doh3Transports.Range(func(key string, client *http.Client) bool {
			if t, ok := client.Transport.(*http3Transport); ok {
				_ = t.Close()
			}
			return true
		})
	}

	if c.dotPool != nil {
		c.dotPool.Shutdown()
	}
	if c.quicPool != nil {
		c.quicPool.Shutdown()
	}
	if c.dtlsPool != nil {
		c.dtlsPool.Shutdown()
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
			zdnsutil.LogHandshake(&zdnsutil.HandshakeInfo{
				Role:       "UPSTREAM",
				Direction:  "negotiated for",
				RemoteAddr: server.Address,
				Version:    cs.Version,
				Cipher:     eTLS.CipherSuiteName(cs.CipherSuite),
				Group:      cs.CurveID.String(),
			})
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
		ClientSessionCache: c.quicSessionCache,
		VerifyConnection: func(cs tls.ConnectionState) error {
			zdnsutil.LogHandshake(&zdnsutil.HandshakeInfo{
				Role:       "UPSTREAM",
				Direction:  "negotiated for",
				RemoteAddr: server.Address,
				Version:    cs.Version,
				Cipher:     tls.CipherSuiteName(cs.CipherSuite),
				Group:      cs.CurveID.String(),
				Resumed:    cs.DidResume,
			})
			return nil
		},
	}
}

// getQUICConfig returns a cached QUIC config for the given upstream key.
// The cache is an LRU map bounded at DefaultQUICConfigCacheSize (128 entries).
func (c *Client) getQUICConfig(key string, skipVerify bool) *quic.Config {
	if cfg, ok := c.quicConfigs.Get(key); ok {
		return cfg
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
	// LoadOrStore: concurrent misses would otherwise build one config (and
	// TokenStore) each and overwrite — the loser's 0-RTT token store then
	// splits from the cached one and resetQUICConfig can never heal it.
	if actual, loaded := c.quicConfigs.LoadOrStore(key, cfg); loaded {
		return actual
	}
	return cfg
}

// resetQUICConfig recreates the TokenStore for the given upstream key on
// 0-RTT rejection.
func (c *Client) resetQUICConfig(key string) {
	cfg, ok := c.quicConfigs.Get(key)
	if !ok {
		return
	}
	cfg = cfg.Clone()
	cfg.TokenStore = quic.NewLRUTokenStore(config.DefaultTokenStoreCapacity, config.DefaultTokenStoreMaxEntries)
	c.quicConfigs.Set(key, cfg)
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
	// Identity-keyed pool/config keys (address|serverName|skipVerify|proxy):
	// two upstreams sharing an address must not share a pooled connection or
	// 0-RTT token store across trust boundaries.
	poolKey := transportKey(server.Address, server.ServerName, server.SkipTLSVerify, server.Proxy)
	configKey := "doq:" + poolKey
	proxyDialer := c.getProxy(server)
	dialTLS := c.stdTLSConfig(server).Clone()
	dialTLS.NextProtos = config.NextProtoDOQ
	if c.quicPool != nil {
		if err := c.quicPool.WarmUp(ctx, poolKey, func(dialCtx context.Context, _ string) (*quic.Conn, error) {
			timeoutCtx, cancel := context.WithTimeout(dialCtx, config.DefaultDNSQueryTimeout)
			defer cancel()
			if proxyDialer != nil {
				pconn, err := proxyDialer.ListenPacket(timeoutCtx)
				if err != nil {
					return nil, fmt.Errorf("proxy ListenPacket: %w", err)
				}
				remoteAddr, err := net.ResolveUDPAddr("udp", server.Address)
				if err != nil {
					_ = pconn.Close()
					return nil, fmt.Errorf("resolve %s: %w", server.Address, err)
				}
				conn, err := quic.Dial(timeoutCtx, pconn, remoteAddr, dialTLS, c.getQUICConfig(configKey, dialTLS.InsecureSkipVerify))
				if err != nil {
					// quic-go does not take ownership of a caller-provided
					// PacketConn on a failed dial — do not leak the UDP socket.
					_ = pconn.Close()
				}
				return conn, err
			}
			return quic.DialAddrEarly(timeoutCtx, server.Address, dialTLS, c.getQUICConfig(configKey, dialTLS.InsecureSkipVerify))
		}); err != nil {
			log.Debugf("UPSTREAM: pre-warm DoQ to %s: %v", server.Address, err)
			return
		}
		log.Debugf("UPSTREAM: pre-warmed DoQ connection to %s", server.Address)
	}
}

// WarmUpHTTPS pre-creates a DoH transport.  The ctx parameter is unused
// (HTTP transports dial lazily — nothing to pre-establish) but kept for
// signature consistency with the other WarmUp* methods, which the warmup
// dispatcher calls uniformly.
func (c *Client) WarmUpHTTPS(_ context.Context, server *config.UpstreamServer) {
	parsedURL, err := url.Parse(server.Address)
	if err != nil {
		log.Debugf("UPSTREAM: pre-warm DoH parse %s: %v", server.Address, err)
		return
	}
	if parsedURL.Port() == "" {
		// Hostname() strips IPv6 brackets — JoinHostPort on the raw Host
		// would double-bracket literals like [[2001:db8::1]]:443.
		parsedURL.Host = net.JoinHostPort(parsedURL.Hostname(), config.DefaultHTTPSPort)
	}
	key := transportKey(parsedURL.Host, server.ServerName, server.SkipTLSVerify, server.Proxy)
	tlsConfig := c.eTLSClientConfig(server)
	c.createDOHClient(parsedURL.Host, server.ServerName, server.SkipTLSVerify, server.Proxy, tlsConfig)
	log.Debugf("UPSTREAM: pre-warmed DoH transport for %s (key=%s)", server.Address, key)
}

// WarmUpHTTP3 pre-creates a DoH3 transport.  The ctx parameter is unused
// (HTTP/3 transports dial lazily) but kept for signature consistency with
// the other WarmUp* methods (see WarmUpHTTPS).
func (c *Client) WarmUpHTTP3(_ context.Context, server *config.UpstreamServer) {
	parsedURL, err := url.Parse(server.Address)
	if err != nil {
		log.Debugf("UPSTREAM: pre-warm DoH3 parse %s: %v", server.Address, err)
		return
	}
	if parsedURL.Port() == "" {
		// Hostname() strips IPv6 brackets — JoinHostPort on the raw Host
		// would double-bracket literals like [[2001:db8::1]]:443.
		parsedURL.Host = net.JoinHostPort(parsedURL.Hostname(), config.DefaultHTTPSPort)
	}
	key := transportKey(parsedURL.Host, server.ServerName, server.SkipTLSVerify, server.Proxy)
	tlsConfig := c.stdTLSConfig(server)
	c.createDOH3Client(key, parsedURL.Host, server.Proxy, tlsConfig)
	log.Debugf("UPSTREAM: pre-warmed DoH3 transport for %s (key=%s)", server.Address, key)
}
