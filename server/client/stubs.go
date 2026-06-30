package client

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	eTLS "gitlab.com/go-extension/tls"
	"github.com/miekg/dns"

	"zjdns/config"
)

// Stubs for types/functions removed with socks5.go and ktls.go.

type Socks5Dialer struct{}

func NewSocks5Dialer(proxyURL string, timeout time.Duration) (*Socks5Dialer, error) {
	return nil, fmt.Errorf("SOCKS5 proxy removed")
}
func (d *Socks5Dialer) Close() error    { return nil }
func (d *Socks5Dialer) SafeURL() string { return "socks5://removed" }
func (d *Socks5Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return nil, fmt.Errorf("SOCKS5 proxy removed")
}
func (d *Socks5Dialer) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	return nil, fmt.Errorf("SOCKS5 proxy removed")
}

func (c *Client) dialTLSConn(ctx context.Context, addr string, tlsConfig *eTLS.Config, proxyDialer *Socks5Dialer) (net.Conn, error) {
	return nil, fmt.Errorf("KTLS removed")
}
func (c *Client) exchangeOverTLS(ctx context.Context, msg *dns.Msg, addr string, tlsConfig *eTLS.Config, proxyDialer *Socks5Dialer) (*dns.Msg, error) {
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

var socks5ReadPool = sync.Pool{
	New: func() any { b := make([]byte, 8192); return &b },
}
