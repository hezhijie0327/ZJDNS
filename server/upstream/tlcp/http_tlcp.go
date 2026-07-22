package tlcp

import (
	"context"
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
	parsedURL, err := url.Parse(server.Address)
	if err != nil {
		return nil, fmt.Errorf("parse URL: %w", err)
	}
	if parsedURL.Port() == "" {
		parsedURL.Host = net.JoinHostPort(parsedURL.Host, config.DefaultHTTPTLCPPort)
	}

	key := fmt.Sprintf("%s|%s|%t|%s", server.Address, server.ServerName, server.SkipTLSVerify, server.Proxy)
	c.httpMu.Lock()
	httpClient, ok := c.httpClient[key]
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

		// Evict if over threshold.
		if len(c.httpClient) >= config.DefaultHTTPTLCPClientMax*2 {
			for k := range c.httpClient {
				delete(c.httpClient, k)
				if len(c.httpClient) <= config.DefaultHTTPTLCPClientMax {
					break
				}
			}
		}
		if c.httpClient == nil {
			c.httpClient = make(map[string]*http.Client)
		}
		c.httpClient[key] = httpClient
	}
	c.httpMu.Unlock()

	return zdnsutil.ExecuteDoHRequest(ctx, msg, parsedURL, httpClient, http.MethodGet)
}
