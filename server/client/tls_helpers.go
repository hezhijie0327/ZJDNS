package client

import (
	"context"
	"net"

	"github.com/miekg/dns"
	eTLS "gitlab.com/go-extension/tls"

	"zjdns/config"
)

// eTLSClientConfig builds a default [eTLS.Config] for upstream DoT/DoH
// connections using the server's TLS settings.
func (c *Client) eTLSClientConfig(server *config.UpstreamServer) *eTLS.Config {
	return &eTLS.Config{
		CurvePreferences:   []eTLS.CurveID{},
		MinVersion:         eTLS.VersionTLS12,
		ServerName:         server.ServerName,
		InsecureSkipVerify: server.SkipTLSVerify,
	}
}

// dialTLSConn dials a TCP connection to addr and wraps it with eTLS using the
// given config. Used by the DoT connection pool and as a fallback dialer.
func (c *Client) dialTLSConn(ctx context.Context, addr string, tlsConfig *eTLS.Config) (net.Conn, error) {
	var d net.Dialer
	tcpConn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}

	eTLSConn := eTLS.Client(tcpConn, tlsConfig)
	if err := eTLSConn.HandshakeContext(ctx); err != nil {
		_ = tcpConn.Close()
		return nil, err
	}
	return eTLSConn, nil
}

// exchangeOverTLS dials addr with TLS, sends a DNS query, reads the response,
// and closes the connection. Used as the non-pooled fallback for DoT queries.
func (c *Client) exchangeOverTLS(ctx context.Context, msg *dns.Msg, addr string, tlsConfig *eTLS.Config) (*dns.Msg, error) {
	conn, err := c.dialTLSConn(ctx, addr, tlsConfig)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	dnsConn := new(dns.Conn)
	dnsConn.Conn = conn
	if err := dnsConn.WriteMsg(msg); err != nil {
		return nil, err
	}
	response, err := dnsConn.ReadMsg()
	if err != nil {
		return nil, err
	}
	response.Id = msg.Id
	return response, nil
}
