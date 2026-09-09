// Per-upstream DoH/DoH3 request targets: the parsed URL, transport-cache key
// and base TLS configs are built once per UpstreamServer, never per query —
// per-query construction (url.Parse + transportKey + a fresh TLS config with
// its VerifyConnection closure) would tax every request, including every
// transport-cache hit.

package tls

import (
	"crypto/tls"
	"net"
	"net/url"
	"zjdns/config"

	eTLS "gitlab.com/go-extension/tls"
)

// dohEndpoint is the immutable per-upstream request target shared by the
// DoH (HTTP/2) and DoH3 (QUIC) paths.  Both default ports are 443, so one
// parsed URL serves both.  The TLS configs are base templates — transport
// creation clones them before mutating (NextProtos/ServerName).
type dohEndpoint struct {
	url       *url.URL
	key       string
	eTLSCfg   *eTLS.Config
	stdTLSCfg *tls.Config
}

// dohEndpointFor returns the cached endpoint for server, building it on
// first use.  The UpstreamServer pointer is the cache key: configs are
// static at runtime and a reload registers fresh pointers, so identity
// suffices and the lookup is allocation-free on the query hot path.
func (c *Client) dohEndpointFor(server *config.UpstreamServer) (*dohEndpoint, error) {
	if ep, ok := c.dohEndpoints.Get(server); ok {
		return ep, nil
	}
	parsedURL, err := url.Parse(server.Address)
	if err != nil {
		return nil, err
	}
	if parsedURL.Port() == "" {
		// Hostname() strips IPv6 brackets — JoinHostPort on the raw Host
		// would double-bracket literals like [[2001:db8::1]]:443.
		parsedURL.Host = net.JoinHostPort(parsedURL.Hostname(), config.DefaultHTTPSPort)
	}
	ep := &dohEndpoint{
		url:       parsedURL,
		key:       transportKey(parsedURL.Host, server.ServerName, server.SkipTLSVerify, server.Proxy),
		eTLSCfg:   c.eTLSClientConfig(server),
		stdTLSCfg: c.stdTLSConfig(server),
	}
	c.dohEndpoints.Set(server, ep)
	return ep, nil
}
