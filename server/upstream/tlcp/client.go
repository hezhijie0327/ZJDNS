// Package tlcp implements outbound DNS queries over TLCP and DTLCP (Chinese
// national cryptographic standards GM/T 0024-2014 and GM/T 0128-2023).
package tlcp

import (
	"net/http"
	"time"
	"zjdns/config"
	zdnsutil "zjdns/internal/dnsutil"
	"zjdns/internal/lrumap"
	zpool "zjdns/server/upstream/pool"
	socks5 "zjdns/server/upstream/socks5"

	"gitee.com/Trisia/gotlcp/dtlcp"
	"gitee.com/Trisia/gotlcp/tlcp"
	"github.com/emmansun/gmsm/smx509"
)

// Client executes DNS queries over TLCP and DTLCP transports.
type Client struct {
	getProxy     func(*config.UpstreamServer) *socks5.Dialer
	timeout      time.Duration
	tlcpSessions tlcp.SessionCache
	dtlcpSession dtlcp.SessionCache
	httpClient   *lrumap.Map[string, *http.Client] // cached DoH-over-TLCP clients by key

	// tlcpPool multiplexes pipelined TLCP connections per upstream (RFC 7766).
	// Previously every query paid a fresh dial + TLCP handshake — a batch of
	// N queries meant N simultaneous handshakes.  nil in tests.
	tlcpPool *zpool.ConnPool
}

// New creates a Client for TLCP and DTLCP DNS queries.
func New(getProxy func(*config.UpstreamServer) *socks5.Dialer, timeout time.Duration) *Client {
	c := &Client{
		getProxy:     getProxy,
		timeout:      timeout,
		tlcpSessions: tlcp.NewLRUSessionCache(config.DefaultTLCPSessionCacheSize),
		dtlcpSession: dtlcp.NewLRUSessionCache(config.DefaultDTLCPSessionCacheSize),
		httpClient:   lrumap.New[string, *http.Client](config.DefaultHTTPTLCPClientMax * 2),
		tlcpPool:     zpool.NewConnPool(config.DefaultMaxConns, config.DefaultMaxPipe),
	}
	c.httpClient.SetOnEvict(func(_ string, client *http.Client) {
		client.CloseIdleConnections()
	})
	return c
}

// Close shuts down all cached DoH-over-TLCP HTTP clients and the TLCP
// connection pool. Idempotent.  The LRU map is intentionally NOT nil'd:
// in-flight queries read it (with nil guards at the call sites) and a nil
// write would race those reads.
func (c *Client) Close() {
	if c == nil {
		return
	}
	if c.httpClient != nil {
		c.httpClient.Range(func(_ string, client *http.Client) bool {
			client.CloseIdleConnections()
			return true
		})
	}
	if c.tlcpPool != nil {
		c.tlcpPool.Shutdown()
	}
}

// tlcpClientConfig builds a gotlcp/tlcp Config for upstream TLCP connections.
//
// NOTE: this project has no per-upstream SM2 CA-file config, so verification
// relies on the system trust pool. With InsecureSkipVerify=false (the strict
// privacy-profile default), the server certificate must chain to a CA in the
// system pool; otherwise skip_tls_verify=true is required.
func (c *Client) tlcpClientConfig(server *config.UpstreamServer) *tlcp.Config {
	addr := server.Address // capture for the VerifyConnection closure
	rootCAs := smx509.NewCertPool()
	if pool, err := smx509.SystemCertPool(); err == nil {
		rootCAs = pool
	}
	return &tlcp.Config{
		CurvePreferences:   []tlcp.CurveID{tlcp.CurveSM2},
		InsecureSkipVerify: server.SkipTLSVerify,
		ServerName:         server.ServerName,
		RootCAs:            rootCAs,
		SessionCache:       c.tlcpSessions,
		VerifyConnection: func(cs tlcp.ConnectionState) error {
			zdnsutil.LogHandshake(&zdnsutil.HandshakeInfo{
				Role:       "UPSTREAM",
				Direction:  "negotiated for",
				RemoteAddr: addr,
				Version:    cs.Version,
				Cipher:     tlcp.CipherSuiteName(cs.CipherSuite),
				Group:      "SM2",
				Resumed:    cs.DidResume,
				ALPN:       cs.NegotiatedProtocol,
			})
			// Logging-only: no additional checks are enforced here. DoT
			// ALPN enforcement lives in exchangeOverTLCP (it must not run
			// here — the DoH-over-TLCP path negotiates a different ALPN).
			return nil
		},
	}
}

// dtlcpClientConfig builds a dtlcp.Config for upstream DTLCP connections.
// Mirrors tlcpClientConfig: ServerName and the SM2 curve preference are
// required for verified handshakes against the server-side listener.
func (c *Client) dtlcpClientConfig(server *config.UpstreamServer) *dtlcp.Config {
	addr := server.Address // capture for the VerifyConnection closure
	rootCAs := smx509.NewCertPool()
	if pool, err := smx509.SystemCertPool(); err == nil {
		rootCAs = pool
	}
	return &dtlcp.Config{
		InsecureSkipVerify: server.SkipTLSVerify,
		ServerName:         server.ServerName,
		CurvePreferences:   []dtlcp.CurveID{dtlcp.CurveSM2},
		RootCAs:            rootCAs,
		SessionCache:       c.dtlcpSession,
		VerifyConnection: func(cs dtlcp.ConnectionState) error {
			zdnsutil.LogHandshake(&zdnsutil.HandshakeInfo{
				Role:       "UPSTREAM",
				Direction:  "DTLCP negotiated for",
				RemoteAddr: addr,
				Version:    cs.Version,
				Cipher:     dtlcp.CipherSuiteName(cs.CipherSuite),
				Group:      "SM2",
				Resumed:    cs.DidResume,
				ALPN:       cs.NegotiatedProtocol,
			})
			// Logging-only: no additional checks are enforced here.
			return nil
		},
	}
}
