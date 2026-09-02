package tls

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"zjdns/config"
	zdnsutil "zjdns/internal/dnsutil"
	"zjdns/internal/log"
	"zjdns/internal/resolv"
	socks5 "zjdns/server/upstream/socks5"

	"codeberg.org/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// http3Transport wraps [*http3.Transport] to force reuse of a single connection
// per host instead of creating new ones.
type http3Transport struct {
	baseTransport *http3.Transport
	closed        bool
	mu            sync.RWMutex
}

// RoundTrip implements the [http.RoundTripper] interface for *http3Transport.
func (h *http3Transport) RoundTrip(req *http.Request) (resp *http.Response, err error) {
	// Guard only the closed flag, not the network I/O: holding the RLock for
	// the whole RoundTrip would block Close (write lock) until every in-flight
	// request completes, stalling transport eviction and shutdown on one
	// stalled request. quic-go is concurrency-safe for in-flight requests.
	h.mu.RLock()
	closed := h.closed
	h.mu.RUnlock()

	if closed {
		return nil, net.ErrClosed
	}

	resp, err = h.baseTransport.RoundTripOpt(req, http3.RoundTripOpt{OnlyCachedConn: true})
	if errors.Is(err, http3.ErrNoCachedConn) {
		resp, err = h.baseTransport.RoundTrip(req)
	}
	return resp, err
}

// Close implements the [io.Closer] interface for *http3Transport.
func (h *http3Transport) Close() (err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.closed = true
	return h.baseTransport.Close()
}

// ExecuteHTTP3 performs a DNS-over-HTTPS/3 query, using cached transports with
// automatic retry on connection failure.
func (c *Client) ExecuteHTTP3(ctx context.Context, msg *dns.Msg, server *config.UpstreamServer) (*dns.Msg, error) {
	if msg == nil {
		return nil, errors.New("http3: nil query message")
	}
	if server == nil {
		return nil, errors.New("http3: nil server config")
	}
	tlsConfig := c.stdTLSConfig(server)

	parsedURL, err := url.Parse(server.Address)
	if err != nil {
		return nil, fmt.Errorf("parse URL: %w", err)
	}

	if parsedURL.Port() == "" {
		// Hostname() strips IPv6 brackets — JoinHostPort on the raw Host
		// would double-bracket literals like [[2001:db8::1]]:443.
		parsedURL.Host = net.JoinHostPort(parsedURL.Hostname(), config.DefaultHTTP3Port)
	}

	key := transportKey(parsedURL.Host, server.ServerName, server.SkipTLSVerify, server.Proxy)

	var client *http.Client
	var isCached bool
	if c.doh3Transports != nil { // Close() never nils the map (in-flight proxied queries read it; it dies with the Client) — the nil check guards test wiring only
		client, isCached = c.doh3Transports.Get(key)
	}
	if !isCached {
		client = c.createDOH3Client(key, parsedURL.Host, server.Proxy, tlsConfig)
	}

	// All failures are retried below when isQUICRetryable — including the
	// first request: 0-RTT rejection (token store stale across transport
	// generations) can strike a freshly created client too, and only the
	// retry resets it.
	resp, err := zdnsutil.ExecuteDoHRequest(ctx, msg, parsedURL, client, http3.MethodGet0RTT)
	if err == nil {
		return resp, nil
	}

	for range config.DefaultSecureTransportRetries {
		if !isQUICRetryable(err) {
			break
		}

		// 0-RTT rejection must reset the stale token store regardless of
		// whether the client came from cache — the token store and TLS
		// session cache are shared across transport generations.
		if errors.Is(err, quic.Err0RTTRejected) {
			c.resetQUICConfig("doh3:" + key)
		}

		if c.doh3Transports != nil && c.doh3Transports.CompareAndDelete(key, client) {
			if t, ok := client.Transport.(*http3Transport); ok {
				_ = t.Close()
			}
		}

		client = c.createDOH3Client(key, parsedURL.Host, server.Proxy, tlsConfig)
		resp, err = zdnsutil.ExecuteDoHRequest(ctx, msg, parsedURL, client, http3.MethodGet0RTT)
		if err == nil {
			return resp, nil
		}
	}

	// Evict only on QUIC/connection-level failures. Caller-side cancellation,
	// deadline expiry, and HTTP-level errors (e.g. non-200) do not mean the
	// transport is broken — tearing it down would hurt concurrent requests.
	if err != nil && isQUICRetryable(err) && c.doh3Transports != nil && c.doh3Transports.CompareAndDelete(key, client) {
		if t, ok := client.Transport.(*http3Transport); ok {
			_ = t.Close()
		}
	}

	return resp, err
}

func (c *Client) createDOH3Client(key, host, proxyURL string, tlsConfig *tls.Config) *http.Client {
	if c.doh3Transports == nil {
		return c.doh3Client
	}

	if client, ok := c.doh3Transports.Get(key); ok {
		return client
	}

	tlsCfg := tlsConfig.Clone()
	tlsCfg.NextProtos = config.NextProtoDOH3
	if tlsCfg.ServerName == "" {
		// quic-go derives SNI from the dial-addr hostname when ServerName is
		// empty — pin it to the URL host before the dial closure switches to
		// a cached IP (resolv SNI safety contract).  Set once at transport
		// creation: the Dial closure runs concurrently per connection.
		tlsCfg.ServerName = host
	}

	quicCfg := c.getQUICConfig("doh3:"+key, tlsConfig.InsecureSkipVerify)

	var proxyDialer *socks5.Dialer
	if proxyURL != "" {
		proxyDialer = c.getProxy(&config.UpstreamServer{Proxy: proxyURL})
	}

	transport := &http3Transport{
		baseTransport: &http3.Transport{
			Dial: func(ctx context.Context, _ string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
				// cfg is the caller-provided quic.Config; we override it with quicCfg below
				// (except Tracer, which is forwarded).  This is intentional — the transport
				// owns the QUIC configuration and only delegates tracing to the caller.
				cpy := quicCfg.Clone()
				if cfg != nil {
					cpy.Tracer = cfg.Tracer
				}
				if proxyDialer != nil {
					pconn, err := proxyDialer.ListenPacket(ctx)
					if err != nil {
						return nil, fmt.Errorf("proxy ListenPacket: %w", err)
					}
					remoteAddr, err := resolv.Default.ResolveUDPAddr(ctx, host)
					if err != nil {
						_ = pconn.Close()
						return nil, fmt.Errorf("resolve %s: %w", host, err)
					}
					conn, err := quic.Dial(ctx, pconn, remoteAddr, tlsCfg, cpy)
					if err != nil {
						// quic-go does not take over the PacketConn on a failed
						// dial — close it or the UDP socket leaks per query
						// (same pattern as the non-proxy DoQ path).
						_ = pconn.Close()
						return nil, err
					}
					// quic-go never closes a caller-provided PacketConn —
					// the SOCKS5 UDP relay (2 fds + monitor goroutine) leaks
					// on every connection teardown otherwise (2026-09 U4,
					// same hook as ExecuteQUIC).
					done := conn.Context().Done()
					go func() {
						defer zdnsutil.HandlePanic("QUIC proxy relay release")
						<-done
						_ = pconn.Close()
					}()
					return conn, nil
				}
				// Dial an IP literal from the resolution cache (SNI already
				// pinned to the URL host at transport creation).
				dialAddr := host
				if resolved, rErr := resolv.Default.ResolveUDPAddr(ctx, host); rErr == nil {
					dialAddr = resolved.String()
				}
				conn, err := quic.DialAddrEarly(ctx, dialAddr, tlsCfg, cpy)
				if err == nil {
					log.Debugf("UPSTREAM: DoH3 negotiated for %s — cipher=%s resumed=%v 0-RTT=%v",
						host, tls.CipherSuiteName(conn.ConnectionState().TLS.CipherSuite),
						conn.ConnectionState().TLS.DidResume, conn.ConnectionState().Used0RTT)
				}
				return conn, err
			},
			DisableCompression: true,
			TLSClientConfig:    tlsCfg,
			QUICConfig:         quicCfg.Clone(),
		},
	}

	client := &http.Client{
		Timeout:   c.doh3Client.Timeout,
		Transport: transport,
	}
	actual, loaded := c.doh3Transports.LoadOrStore(key, client)
	if loaded {
		if t, ok := client.Transport.(*http3Transport); ok {
			_ = t.Close()
		}
		return actual
	}
	return client
}

// isQUICRetryable checks whether an error signals that the QUIC connection
// should be re-created.
func isQUICRetryable(err error) bool {
	if err == nil {
		return false
	}

	if errors.Is(err, quic.Err0RTTRejected) {
		return true
	}

	if qAppErr, ok := errors.AsType[*quic.ApplicationError](err); ok {
		if qAppErr.ErrorCode == 0 ||
			qAppErr.ErrorCode == quic.ApplicationErrorCode(http3.ErrCodeNoError) {
			return true
		}
	}

	if _, ok := errors.AsType[*quic.IdleTimeoutError](err); ok {
		return true
	}

	if _, ok := errors.AsType[*quic.StatelessResetError](err); ok {
		return true
	}

	if qTransportError, ok := errors.AsType[*quic.TransportError](err); ok && qTransportError.ErrorCode == quic.NoError {
		return true
	}

	// NOTE: os.ErrDeadlineExceeded (which errors.Is also matches for
	// context.DeadlineExceeded) is deliberately NOT retryable: a caller-side
	// timeout does not indicate a broken transport, and retrying against an
	// already-expired context only delays the failure.
	return false
}
