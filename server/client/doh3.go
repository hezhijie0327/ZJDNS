package client

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

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"zjdns/config"
)

// http3Transport wraps [*http3.Transport] to force reuse of a single connection
// per host instead of creating new ones. It also mitigates race issues with
// quic-go by preferring cached connections.
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

	// Try the cached connection first to avoid unnecessary QUIC handshakes.
	resp, err = h.baseTransport.RoundTripOpt(req, http3.RoundTripOpt{OnlyCachedConn: true})
	if errors.Is(err, http3.ErrNoCachedConn) {
		// No cached connection available; create a new one (may attempt 0-RTT).
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

func (c *Client) executeDoH3(ctx context.Context, msg *dns.Msg, server *config.UpstreamServer, tlsConfig *tls.Config) (*dns.Msg, error) {
	parsedURL, err := url.Parse(server.Address)
	if err != nil {
		return nil, fmt.Errorf("parse URL: %w", err)
	}

	if parsedURL.Port() == "" {
		parsedURL.Host = net.JoinHostPort(parsedURL.Host, config.DefaultDOHPort)
	}

	key := transportKey(parsedURL.Host, server.ServerName, server.SkipTLSVerify)

	client, isCached := c.getDoH3Client(key)
	if !isCached {
		client = c.createDoH3Client(key, parsedURL.Host, tlsConfig)
	}

	// First attempt with the cached client.
	resp, err := executeDoHHTTPRequest(ctx, msg, parsedURL, client)
	if err == nil {
		return resp, nil
	}

	// If the cached client failed, reset and retry up to 2 times.
	// This handles the case where the server closed the idle connection AND
	// rejects 0-RTT, requiring a fresh full handshake.
	if isCached {
		for i := 0; i < config.DefaultSecureTransportRetries; i++ {
			if !isQUICRetryable(err) {
				break
			}

			if errors.Is(err, quic.Err0RTTRejected) {
				c.resetQUICConfig(key)
			}

			c.doh3TransportMu.Lock()
			if old, ok := c.doh3Transports[key]; ok && old == client {
				if t, ok := old.Transport.(*http3Transport); ok {
					_ = t.Close()
				}
				delete(c.doh3Transports, key)
			}
			c.doh3TransportMu.Unlock()

			client = c.createDoH3Client(key, parsedURL.Host, tlsConfig)
			resp, err = executeDoHHTTPRequest(ctx, msg, parsedURL, client)
			if err == nil {
				return resp, nil
			}
		}
	}

	if err != nil {
		// Clean up the failed transport so the next query starts fresh.
		c.doh3TransportMu.Lock()
		if old, ok := c.doh3Transports[key]; ok && old == client {
			if t, ok := old.Transport.(*http3Transport); ok {
				_ = t.Close()
			}
			delete(c.doh3Transports, key)
		}
		c.doh3TransportMu.Unlock()
	}

	return resp, err
}

func (c *Client) getDoH3Client(key string) (*http.Client, bool) {
	c.doh3TransportMu.RLock()
	defer c.doh3TransportMu.RUnlock()
	client, ok := c.doh3Transports[key]
	return client, ok
}

func (c *Client) createDoH3Client(key, host string, tlsConfig *tls.Config) *http.Client {
	c.doh3TransportMu.Lock()
	defer c.doh3TransportMu.Unlock()

	if client, ok := c.doh3Transports[key]; ok {
		return client
	}

	// Evict oldest entry when at capacity.
	if len(c.doh3Transports) >= config.DefaultTransportMax {
		for k := range c.doh3Transports {
			if t, ok := c.doh3Transports[k].Transport.(*http3Transport); ok {
				_ = t.Close()
			}
			delete(c.doh3Transports, k)
			break
		}
	}

	tlsCfg := tlsConfig.Clone()
	tlsCfg.NextProtos = config.NextProtoDOH3

	quicCfg := c.getQUICConfig(key, tlsConfig.InsecureSkipVerify)

	transport := &http3Transport{
		baseTransport: &http3.Transport{
			Dial: func(ctx context.Context, _ string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
				// Ignore the address from the HTTP request and always dial the
				// bootstrapped address. Uses DialAddrEarly for 0-RTT support.
				cpy := quicCfg.Clone()
				if cfg != nil {
					cpy.Tracer = cfg.Tracer
				}
				return quic.DialAddrEarly(ctx, host, tlsCfg, cpy)
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
	c.doh3Transports[key] = client
	return client
}

// isQUICRetryable checks whether an error signals that the QUIC connection
// should be re-created (e.g. idle timeout, stateless reset, 0-RTT rejection).
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
		// A timeout that could happen when the server has been restarted.
		return true
	}

	return false
}
