package tls

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"zjdns/config"
	zdnsutil "zjdns/internal/dnsutil"
	"zjdns/internal/log"
	"zjdns/internal/resolv"

	"codeberg.org/miekg/dns"
	eHTTP "gitlab.com/go-extension/http"
	eTLS "gitlab.com/go-extension/tls"
)

// ExecuteHTTPS performs a DNS-over-HTTPS query (HTTP/2), using cached
// transports with automatic retry on connection failure.
func (c *Client) ExecuteHTTPS(ctx context.Context, msg *dns.Msg, server *config.UpstreamServer) (*dns.Msg, error) {
	if msg == nil {
		return nil, errors.New("https: nil query message")
	}
	if server == nil {
		return nil, errors.New("https: nil server config")
	}
	parsedURL, err := url.Parse(server.Address)
	if err != nil {
		return nil, fmt.Errorf("parse URL: %w", err)
	}

	if parsedURL.Port() == "" {
		// Hostname() strips IPv6 brackets — JoinHostPort on the raw Host
		// would double-bracket literals like [[2001:db8::1]]:443.
		parsedURL.Host = net.JoinHostPort(parsedURL.Hostname(), config.DefaultHTTPSPort)
	}

	key := transportKey(parsedURL.Host, server.ServerName, server.SkipTLSVerify, server.Proxy)
	tlsConfig := c.eTLSClientConfig(server)

	var client *http.Client
	var isCached bool
	if c.dohTransports != nil { // Close() never nils the map (tls/client.go) — guarded for symmetry
		client, isCached = c.dohTransports.Get(key)
	}
	if !isCached {
		client = c.createDOHClient(parsedURL.Host, server.ServerName, server.SkipTLSVerify, server.Proxy, tlsConfig)
	}

	resp, err := zdnsutil.ExecuteDoHRequest(ctx, msg, parsedURL, client, http.MethodGet)
	if err == nil {
		return resp, nil
	}

	if isCached {
		for i := 0; shouldRetryHTTP(err) && i < config.DefaultSecureTransportRetries; i++ {
			// Atomic compare-and-delete: another goroutine may have replaced
			// the transport for this key — only evict if it is still ours.
			if c.dohTransports != nil && c.dohTransports.CompareAndDelete(key, client) {
				if ct, ok := client.Transport.(*eHTTP.CompatableTransport); ok {
					ct.CloseIdleConnections()
				}
			}

			client = c.createDOHClient(parsedURL.Host, server.ServerName, server.SkipTLSVerify, server.Proxy, tlsConfig)
			resp, err = zdnsutil.ExecuteDoHRequest(ctx, msg, parsedURL, client, http.MethodGet)
			if err == nil {
				return resp, nil
			}
		}
	}

	// Evict the transport only on transport-level failures, not on
	// caller-side timeouts or cancelled contexts — a healthy connection pool
	// must survive a slow upstream (http3.go applies the same distinction).
	if err != nil && !isCallerSideTimeout(err) && c.dohTransports != nil && c.dohTransports.CompareAndDelete(key, client) {
		if ct, ok := client.Transport.(*eHTTP.CompatableTransport); ok {
			ct.CloseIdleConnections()
		}
	}

	return resp, err
}

// isCallerSideTimeout reports whether err is a client-side deadline or
// cancellation rather than a transport failure.
func isCallerSideTimeout(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return true
	}
	netErr, ok := errors.AsType[net.Error](err)
	return ok && netErr.Timeout()
}

// transportKey builds a cache key for transport-level connection pools
// (DoH, DoH3, DoT). The key combines host, server name, TLS verification
// setting, and optional proxy URL.
func transportKey(host, serverName string, skipVerify bool, proxyURL string) string {
	var b strings.Builder
	b.Grow(len(host) + len(serverName) + len(proxyURL) + 16)
	b.WriteString(host)
	b.WriteByte('|')
	b.WriteString(serverName)
	b.WriteByte('|')
	if skipVerify {
		b.WriteString("true")
	} else {
		b.WriteString("false")
	}
	if proxyURL != "" {
		b.WriteByte('|')
		b.WriteString(proxyURL)
	}
	return b.String()
}

// shouldRetryHTTP checks whether an HTTP/2 error warrants recreating the client
// and retrying.
func shouldRetryHTTP(err error) bool {
	netErr, ok := errors.AsType[net.Error](err)
	if ok && netErr.Timeout() {
		return true
	}
	// Also retry on transient operation errors (connection reset, etc.).
	// net.OpError.Temporary is deprecated (Go 1.18) — check the underlying
	// syscall errors directly.
	return errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.ECONNREFUSED) ||
		errors.Is(err, syscall.EPIPE) || errors.Is(err, syscall.ETIMEDOUT)
}

func (c *Client) createDOHClient(host, serverName string, skipVerify bool, proxyURL string, tlsConfig *eTLS.Config) *http.Client {
	// Extract the transport once — used in both non-cached and cached paths.
	tr, ok := c.dohClient.Transport.(*eHTTP.Transport)
	if !ok {
		return &http.Client{Timeout: c.dohClient.Timeout, Transport: &eHTTP.CompatableTransport{}}
	}

	if c.dohTransports == nil {
		return &http.Client{Timeout: c.dohClient.Timeout, Transport: &eHTTP.CompatableTransport{Transport: tr}}
	}

	key := transportKey(host, serverName, skipVerify, proxyURL)
	if client, ok := c.dohTransports.Get(key); ok {
		return client
	}
	transport := tr.Clone()
	tlsCfg := tlsConfig.Clone()
	tlsCfg.NextProtos = config.NextProtoDOH
	tlsCfg.ServerName = serverName
	transport.TLSClientConfig = tlsCfg

	if proxyURL != "" {
		proxyDialer := c.getProxy(&config.UpstreamServer{Proxy: proxyURL})
		if proxyDialer != nil {
			transport.DialContext = proxyDialer.DialContext
		} else {
			// The proxy could not be constructed (invalid URL etc.): dialing
			// without it would silently bypass the configured proxy — a DNS
			// privacy/egress change. getProxy has already logged the reason
			// once; mark the downgrade here at Debug.
			log.Debugf("DOH: proxy %s unavailable — %s transport will dial directly", proxyURL, serverName)
		}
	} else {
		transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := resolv.Default.DialContext(ctx, network, addr, &net.Dialer{})
			if err != nil {
				return nil, err
			}
			if tc, ok := conn.(*net.TCPConn); ok {
				_ = tc.SetKeepAlive(true)
				_ = tc.SetKeepAlivePeriod(config.DefaultTCPKeepAlivePeriod)
			}
			return conn, nil
		}
	}

	client := &http.Client{
		Timeout:   c.dohClient.Timeout,
		Transport: &eHTTP.CompatableTransport{Transport: transport},
	}
	actual, loaded := c.dohTransports.LoadOrStore(key, client)
	if loaded {
		if ct, ok := client.Transport.(*eHTTP.CompatableTransport); ok {
			ct.CloseIdleConnections()
		}
		return actual
	}
	return client
}
