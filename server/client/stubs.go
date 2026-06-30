package client

import (
	"context"
	"fmt"
	"net"

	"github.com/miekg/dns"
	eTLS "gitlab.com/go-extension/tls"

	"zjdns/config"
)

// Stubs for functions removed with ktls.go.

func (c *Client) dialTLSConn(ctx context.Context, addr string, tlsConfig *eTLS.Config) (net.Conn, error) {
	return nil, fmt.Errorf("KTLS removed")
}
func (c *Client) exchangeOverTLS(ctx context.Context, msg *dns.Msg, addr string, tlsConfig *eTLS.Config) (*dns.Msg, error) {
	return nil, fmt.Errorf("KTLS removed")
}

func (c *Client) eTLSClientConfig(server *config.UpstreamServer) *eTLS.Config {
	return &eTLS.Config{
		CurvePreferences:   []eTLS.CurveID{},
		MinVersion:         eTLS.VersionTLS12,
		ServerName:         server.ServerName,
		InsecureSkipVerify: server.SkipTLSVerify,
	}
}
