package tls

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync"
	"zjdns/config"
	zdnsutil "zjdns/internal/dnsutil"
	"zjdns/internal/log"
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
	h.mu.RLock()
	defer h.mu.RUnlock()

	if h.closed {
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
		parsedURL.Host = net.JoinHostPort(parsedURL.Host, config.DefaultHTTP3Port)
	}

	key := transportKey(parsedURL.Host, server.ServerName, server.SkipTLSVerify, server.Proxy)

	client, isCached := c.doh3Transports.Get(key)
	if !isCached {
		client = c.createDOH3Client(key, parsedURL.Host, server.Proxy, tlsConfig)
	}

	// NOTE: The first request gets no retry because the initial
	// connection establishment serves as an implicit retry; cached clients
	// do retry. Consider retrying on first failure as well for consistency.
	resp, err := zdnsutil.ExecuteDoHRequest(ctx, msg, parsedURL, client, http3.MethodGet0RTT)
	if err == nil {
		return resp, nil
	}

	if isCached {
		for range config.DefaultSecureTransportRetries {
			if !isQUICRetryable(err) {
				break
			}

			if errors.Is(err, quic.Err0RTTRejected) {
				c.resetQUICConfig("doh3:" + key)
			}

			if cached, ok := c.doh3Transports.Get(key); ok && cached == client {
				if t, ok := client.Transport.(*http3Transport); ok {
					_ = t.Close()
				}
				c.doh3Transports.Delete(key)
			}

			client = c.createDOH3Client(key, parsedURL.Host, server.Proxy, tlsConfig)
			resp, err = zdnsutil.ExecuteDoHRequest(ctx, msg, parsedURL, client, http3.MethodGet0RTT)
			if err == nil {
				return resp, nil
			}
		}
	}

	if err != nil {
		if cached, ok := c.doh3Transports.Get(key); ok && cached == client {
			if t, ok := client.Transport.(*http3Transport); ok {
				_ = t.Close()
			}
			c.doh3Transports.Delete(key)
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

	quicCfg := c.getQUICConfig("doh3:"+key, tlsConfig.InsecureSkipVerify)

	var proxyDialer *socks5.Dialer
	if proxyURL != "" {
		proxyDialer = c.getProxy(&config.UpstreamServer{Proxy: proxyURL})
	}

	transport := &http3Transport{
		baseTransport: &http3.Transport{
			Dial: func(ctx context.Context, _ string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
				cpy := quicCfg.Clone()
				if cfg != nil {
					cpy.Tracer = cfg.Tracer
				}
				if proxyDialer != nil {
					pconn, err := proxyDialer.ListenPacket(ctx)
					if err != nil {
						return nil, fmt.Errorf("proxy ListenPacket: %w", err)
					}
					remoteAddr, err := net.ResolveUDPAddr("udp", host)
					if err != nil {
						_ = pconn.Close()
						return nil, fmt.Errorf("resolve %s: %w", host, err)
					}
					return quic.Dial(ctx, pconn, remoteAddr, tlsCfg, cpy)
				}
				conn, err := quic.DialAddrEarly(ctx, host, tlsCfg, cpy)
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

	var qAppErr *quic.ApplicationError
	if errors.As(err, &qAppErr) {
		if qAppErr.ErrorCode == 0 ||
			qAppErr.ErrorCode == quic.ApplicationErrorCode(http3.ErrCodeNoError) {
			return true
		}
	}

	var qIdleErr *quic.IdleTimeoutError
	if errors.As(err, &qIdleErr) {
		return true
	}

	var resetErr *quic.StatelessResetError
	if errors.As(err, &resetErr) {
		return true
	}

	var qTransportError *quic.TransportError
	if errors.As(err, &qTransportError) && qTransportError.ErrorCode == quic.NoError {
		return true
	}

	if errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}

	return false
}
