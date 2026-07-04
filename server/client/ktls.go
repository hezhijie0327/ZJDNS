package client

import (
	"context"
	"net"

	"codeberg.org/miekg/dns"
	eTLS "gitlab.com/go-extension/tls"

	"zjdns/config"
	"zjdns/internal/dnsutil"
)

// eTLSClientConfig builds a go-extension/tls Config with kernel TLS offload
// (KTLS) for TCP-based upstream protocols (DoT, DoH).
//
// KTLS settings are controlled via Client.SetKTLS(), which mirrors the server
// config (server.tls.ktls.kernel_tx / kernel_rx). Both default to false.
func (c *Client) eTLSClientConfig(server *config.UpstreamServer) *eTLS.Config {
	return &eTLS.Config{
		KernelTX:           c.ktlsTX,
		KernelRX:           c.ktlsRX,
		CurvePreferences:   []eTLS.CurveID{},
		InsecureSkipVerify: server.SkipTLSVerify,
		MinVersion:         eTLS.VersionTLS12,
		ServerName:         server.ServerName,
		ClientSessionCache: c.SessionCache,
		VerifyConnection: func(cs eTLS.ConnectionState) error {
			dnsutil.LogTLSConnectionState("UPSTREAM", "negotiated for", server.Address, cs.Version, cs.CipherSuite, cs.CurveID)
			return nil
		},
	}
}

// dialTLSConn establishes a TCP connection (optionally proxied), performs a
// TLS handshake over it, and returns the resulting TLS connection. Used by
// both the pooled DoT path and the non-pooled fallback.
func (c *Client) dialTLSConn(ctx context.Context, addr string, tlsConfig *eTLS.Config, proxyDialer *SOCKS5Dialer) (net.Conn, error) {
	var tcpConn net.Conn
	var err error
	if proxyDialer != nil {
		tcpConn, err = proxyDialer.DialContext(ctx, "tcp", addr)
	} else {
		var d net.Dialer
		tcpConn, err = d.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return nil, err
	}
	// Enable TCP keep-alive to detect dead connections and maintain NAT bindings.
	if tc, ok := tcpConn.(*net.TCPConn); ok {
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(config.DefaultTCPKeepAlivePeriod)
	}
	tlsConn := eTLS.Client(tcpConn, tlsConfig)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = tcpConn.Close()
		return nil, err
	}
	return tlsConn, nil
}

// exchangeOverTLS dials a TLS connection and performs a single DNS exchange.
// Used as the non-pooled fallback for DoT — dns.Client.TLSConfig expects
// *crypto/tls.Config, so we do the I/O manually with eTLS.
func (c *Client) exchangeOverTLS(ctx context.Context, msg *dns.Msg, addr string, tlsConfig *eTLS.Config, proxyDialer *SOCKS5Dialer) (*dns.Msg, error) {
	tlsConn, err := c.dialTLSConn(ctx, addr, tlsConfig, proxyDialer)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tlsConn.Close() }()
	if _, err := msg.WriteTo(tlsConn); err != nil {
		return nil, err
	}
	response := new(dns.Msg)
	if _, err := response.ReadFrom(tlsConn); err != nil {
		return nil, err
	}
	if err := response.Unpack(); err != nil {
		return nil, err
	}
	return response, nil
}
