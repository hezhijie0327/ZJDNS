package tlcp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
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
	// Reject scheme-less strings and plain http:// — the latter would send
	// the DNS query over plaintext HTTP (DialTLSContext is never invoked).
	if parsedURL.Scheme != "https" || parsedURL.Hostname() == "" {
		return nil, fmt.Errorf("tlcp: upstream address %q must be an https URL with a host", server.Address)
	}
	if parsedURL.Port() == "" {
		// Hostname() strips IPv6 brackets — JoinHostPort on the raw Host
		// would double-bracket literals like [[2001:db8::1]]:9443.
		parsedURL.Host = net.JoinHostPort(parsedURL.Hostname(), config.DefaultHTTPTLCPPort)
	}

	var b strings.Builder
	b.Grow(len(parsedURL.String()) + len(server.ServerName) + len(server.Proxy) + 20)
	b.WriteString(parsedURL.String()) // normalized endpoint — default-port variants share one client
	b.WriteByte('|')
	b.WriteString(server.ServerName)
	b.WriteByte('|')
	b.WriteString(strconv.FormatBool(server.SkipTLSVerify))
	b.WriteByte('|')
	b.WriteString(server.Proxy)
	key := b.String()
	var httpClient *http.Client
	var ok bool
	if c.httpClient != nil { // Close() never nils the map (client.go) — guarded for symmetry
		httpClient, ok = c.httpClient.Get(key)
	}
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
			MaxConnsPerHost:     config.DefaultMaxIdleConnsPerHost,
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
			// Never follow redirects: a 3xx would re-send the full DNS query
			// (dns= URL) to an arbitrary host — query leak + SSRF, and a
			// redirect to http:// would bypass TLCP entirely.
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}

		if c.httpClient != nil {
			// LoadOrStore: concurrent first-use misses must not overwrite
			// each other's client (the loser's transport would leak its
			// connection pool) — use the winner's client instead.
			if cached, ok := c.httpClient.LoadOrStore(key, httpClient); ok {
				httpClient = cached
			}
		}
	}

	return zdnsutil.ExecuteDoHRequest(ctx, msg, parsedURL, httpClient, http.MethodGet)
}
