// Package tlcp implements outbound DNS queries over TLCP and DTLCP (Chinese
// national cryptographic standards GM/T 0024-2014 and GM/T 0128-2023).
package tlcp

import (
	"time"
	"zjdns/config"
	socks5 "zjdns/server/upstream/socks5"

	"gitee.com/Trisia/gotlcp/dtlcp"
	"gitee.com/Trisia/gotlcp/tlcp"
	"github.com/emmansun/gmsm/smx509"
)

// Client executes DNS queries over TLCP and DTLCP transports.
type Client struct {
	getProxy func(*config.UpstreamServer) *socks5.Dialer
	timeout  time.Duration
}

// New creates a Client for TLCP and DTLCP DNS queries.
func New(getProxy func(*config.UpstreamServer) *socks5.Dialer, timeout time.Duration) *Client {
	return &Client{
		getProxy: getProxy,
		timeout:  timeout,
	}
}

// tlcpClientConfig builds a gotlcp/tlcp Config for upstream TLCP connections.
func (c *Client) tlcpClientConfig(server *config.UpstreamServer) *tlcp.Config {
	return &tlcp.Config{
		CurvePreferences:   []tlcp.CurveID{tlcp.CurveSM2},
		InsecureSkipVerify: server.SkipTLSVerify,
		ServerName:         server.ServerName,
		RootCAs:            smx509.NewCertPool(), // prevent fallback to system pool (cannot parse SM2 certs)
	}
}

// dtlcpClientConfig builds a dtlcp.Config for upstream DTLCP connections.
func (c *Client) dtlcpClientConfig(server *config.UpstreamServer) *dtlcp.Config {
	return &dtlcp.Config{
		InsecureSkipVerify: server.SkipTLSVerify,
	}
}
