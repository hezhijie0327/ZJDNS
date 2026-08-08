package tls

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
	"zjdns/config"
	"zjdns/internal/log"
	"zjdns/internal/pool"
	socks5 "zjdns/server/upstream/socks5"

	"codeberg.org/miekg/dns"
	eTLS "gitlab.com/go-extension/tls"
)

// ExecuteTLS performs a DNS-over-TLS query, using the pipelined connection
// pool when available.
func (c *Client) ExecuteTLS(ctx context.Context, msg *dns.Msg, server *config.UpstreamServer) (*dns.Msg, error) {
	if msg == nil {
		return nil, errors.New("tls: nil query message")
	}
	if server == nil {
		return nil, errors.New("tls: nil server config")
	}
	key := transportKey(server.Address, server.ServerName, server.SkipTLSVerify, server.Proxy)
	proxyDialer := c.getProxy(server)

	if c.dotPool != nil {
		pc, err := c.dotPool.Acquire(ctx, key, server.Address, func(dialCtx context.Context, addr string) (net.Conn, error) {
			// Config built only on dial — the pool-hit path (the common
			// case) skips the per-query config Clone (M-3-6).
			dotConfig := c.eTLSClientConfig(server).Clone()
			dotConfig.NextProtos = config.NextProtoDOT
			return c.dialTLSConn(dialCtx, addr, dotConfig, proxyDialer)
		})
		if err == nil {
			response, err := pc.Exchange(ctx, msg)
			if err == nil {
				return response, nil
			}
			if pc.IsDead() {
				c.dotPool.Remove(pc)
			}
			log.Debugf("UPSTREAM: pipelined DoT query to %s failed: %v, falling back", server.Address, err)
		}
	}

	// Non-pooled fallback: manual dial + TLS + DNS exchange.
	dotConfig := c.eTLSClientConfig(server).Clone()
	dotConfig.NextProtos = config.NextProtoDOT
	return c.exchangeOverTLS(ctx, msg, server.Address, dotConfig, proxyDialer)
}

// dialTLSConn establishes a TCP connection (optionally proxied), performs a
// TLS handshake over it, and returns the resulting TLS connection.
func (c *Client) dialTLSConn(ctx context.Context, addr string, tlsConfig *eTLS.Config, proxyDialer *socks5.Dialer) (net.Conn, error) {
	var tcpConn net.Conn
	var err error
	if proxyDialer != nil {
		tcpConn, err = proxyDialer.DialContext(ctx, "tcp", addr)
	} else {
		var d net.Dialer
		tcpConn, err = d.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return nil, err
	}
	if tc, ok := tcpConn.(*net.TCPConn); ok {
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(config.DefaultTCPKeepAlivePeriod)
	}
	// Defer the handshake: the first Write on the TLS conn will trigger it.
	// When ClientSessionCache has a valid session ticket, this allows TLS 1.3
	// 0-RTT early data — the DNS query is sent as part of the ClientHello,
	// saving one RTT on reconnection (RFC 8446 §2.3).
	tlsConn := eTLS.Client(tcpConn, tlsConfig)
	return tlsConn, nil
}

// exchangeOverTLS dials a TLS connection and performs a single DNS exchange.
func (c *Client) exchangeOverTLS(ctx context.Context, msg *dns.Msg, addr string, tlsConfig *eTLS.Config, proxyDialer *socks5.Dialer) (*dns.Msg, error) {
	tlsConn, err := c.dialTLSConn(ctx, addr, tlsConfig, proxyDialer)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tlsConn.Close() }()
	// The dial deadline was consumed by connect (and cleared by the proxy
	// path) — restore ctx-bound deadlines so a stalled peer cannot hang
	// the exchange goroutine and its fd indefinitely.
	stop := context.AfterFunc(ctx, func() { _ = tlsConn.SetDeadline(time.Now()) })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		_ = tlsConn.SetDeadline(deadline)
	}

	// Pack the message and write as a TCP frame (2-byte length prefix).
	// WriteTo/ReadFrom require dns.ResponseWriter — *eTLS.Conn does not
	// implement it, so we use the same raw frame I/O as the pool path.
	if err := msg.Pack(); err != nil {
		return nil, err
	}
	frame := make([]byte, 2+len(msg.Data))
	frame[0] = byte(len(msg.Data) >> 8) //nolint:gosec // G115: DNS message ≤ 65535
	frame[1] = byte(len(msg.Data))      //nolint:gosec // G115: DNS message ≤ 65535
	copy(frame[2:], msg.Data)
	if _, err := tlsConn.Write(frame); err != nil {
		return nil, fmt.Errorf("tls: write: %w", err)
	}

	// Read the response: 2-byte length prefix + payload.
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(tlsConn, lenBuf); err != nil {
		return nil, fmt.Errorf("tls: read length: %w", err)
	}
	packetLen := int(lenBuf[0])<<8 | int(lenBuf[1])
	if packetLen > dns.MaxMsgSize {
		return nil, fmt.Errorf("tls: response too large: %d", packetLen)
	}
	buf := make([]byte, packetLen)
	if _, err := io.ReadFull(tlsConn, buf); err != nil {
		return nil, fmt.Errorf("tls: read body: %w", err)
	}

	response := pool.DefaultMessage.Get()
	response.Data = buf
	if err := response.Unpack(); err != nil {
		pool.DefaultMessage.Put(response)
		return nil, err
	}
	response.Data = nil
	if response.ID != msg.ID {
		pool.DefaultMessage.Put(response)
		return nil, fmt.Errorf("tls: response id mismatch: expected %d, got %d", msg.ID, response.ID)
	}
	return response, nil
}
