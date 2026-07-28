package tlcp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"zjdns/config"
	zdnsutil "zjdns/internal/dnsutil"

	"codeberg.org/miekg/dns"
)

// ExecuteHTTPTLCP performs a DoH-over-TLCP query using a cached HTTP client
// whose DialTLSContext establishes TLCP connections. Clients are cached per
// upstream key to amortize the TLCP handshake cost across queries.
func (c *Client) ExecuteHTTPTLCP(ctx context.Context, msg *dns.Msg, server *config.UpstreamServer) (*dns.Msg, error) {
	if msg == nil {
		return nil, errors.New("tlcp: nil query message")
	}
	if server == nil {
		return nil, errors.New("tlcp: nil server config")
	}

	parsedURL, err := url.Parse(server.Address)
	if err != nil {
		return nil, fmt.Errorf("parse URL: %w", err)
	}
	if parsedURL.Port() == "" {
		parsedURL.Host = net.JoinHostPort(parsedURL.Host, config.DefaultHTTPTLCPPort)
	}

	key := fmt.Sprintf("%s|%s|%t|%s", server.Address, server.ServerName, server.SkipTLSVerify, server.Proxy)
	httpClient, ok := c.httpClient.Get(key)
	if !ok {
		tlcpCfg := c.tlcpClientConfig(server).Clone()
		tlcpCfg.NextProtos = config.NextProtoDOH
		if tlcpCfg.ServerName == "" {
			tlcpCfg.ServerName = parsedURL.Hostname()
		}
		proxyDialer := c.getProxy(server)

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
		httpClient = &http.Client{
			Timeout:   c.timeout,
			Transport: transport,
		}

		c.httpClient.Set(key, httpClient)
	}

	return zdnsutil.ExecuteDoHRequest(ctx, msg, parsedURL, httpClient, http.MethodGet)
}
