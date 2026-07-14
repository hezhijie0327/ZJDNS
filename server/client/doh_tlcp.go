package client

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"zjdns/config"

	"codeberg.org/miekg/dns"
	"gitee.com/Trisia/gotlcp/tlcp"
)

// executeDOH_TLCP performs a DoH-over-TLCP query by creating an HTTP client
// whose DialTLSContext establishes TLCP connections instead of TLS connections.
// Transport caching is deferred to a follow-up.
func (c *Client) executeDOH_TLCP(ctx context.Context, msg *dns.Msg, server *config.UpstreamServer, tlcpConfig *tlcp.Config) (*dns.Msg, error) {
	parsedURL, err := url.Parse(server.Address)
	if err != nil {
		return nil, fmt.Errorf("parse URL: %w", err)
	}
	if parsedURL.Port() == "" {
		parsedURL.Host = net.JoinHostPort(parsedURL.Host, config.DefaultTLCPDOHPort)
	}

	tlcpCfg := tlcpConfig.Clone()
	tlcpCfg.NextProtos = config.NextProtoDOH
	if tlcpCfg.ServerName == "" {
		tlcpCfg.ServerName = parsedURL.Hostname()
	}
	proxyDialer := c.getProxyDialer(server)

	transport := &http.Transport{
		MaxIdleConns:        config.DefaultMaxIdleConns,
		MaxIdleConnsPerHost: config.DefaultMaxIdleConnsPerHost,
		IdleConnTimeout:     config.DefaultHTTPIdleConnTimeout,
		DisableCompression:  true,
		ForceAttemptHTTP2:   true,
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return c.dialTLCPConn(ctx, addr, tlcpCfg, proxyDialer)
		},
	}
	client := &http.Client{
		Timeout:   c.timeout,
		Transport: transport,
	}
	defer transport.CloseIdleConnections()

	return executeDOHHTTPRequest(ctx, msg, parsedURL, client)
}
