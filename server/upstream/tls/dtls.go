package tls

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"
	"zjdns/config"
	zdnsutil "zjdns/internal/dnsutil"
	"zjdns/internal/log"
	"zjdns/internal/pool"
	"zjdns/internal/resolv"
	socks5 "zjdns/server/upstream/socks5"

	"codeberg.org/miekg/dns"
	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/protocol"
)

// dtlsStreamConn adapts a pion dtls.Conn to stream semantics for the
// connection pool's readLoop.  pion's Read requires a buffer large enough for
// one decrypted record and rejects small reads ("buffer is too small") — the
// pool reads the 2-byte DNS length prefix first, which would fail on the raw
// conn.  The bufio reader fills from the conn in large chunks and serves
// arbitrary-size reads from its buffer.
type dtlsStreamConn struct {
	r *bufio.Reader
	net.Conn
}

// Read serves reads of any size from the buffered stream.
func (c *dtlsStreamConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// ExecuteDTLS performs a DNS-over-DTLS query (RFC 8094).  DNS messages are
// framed with a 2-byte big-endian length prefix, same as DoT (RFC 7858).
// Uses the pipelined connection pool when available (one DTLS connection
// multiplexes many queries), falling back to a per-query dial.
func (c *Client) ExecuteDTLS(ctx context.Context, msg *dns.Msg, server *config.UpstreamServer) (*dns.Msg, error) {
	if msg == nil {
		return nil, errors.New("dtls: nil query message")
	}
	if server == nil {
		return nil, errors.New("dtls: nil server config")
	}
	proxyDialer := c.getProxy(server)
	poolKey := transportKey(server.Address, server.ServerName, server.SkipTLSVerify, server.Proxy)

	if c.dtlsPool != nil {
		pc, err := c.dtlsPool.Acquire(ctx, poolKey, server.Address, func(dialCtx context.Context, addr string) (net.Conn, error) {
			return c.dialDTLSConn(dialCtx, addr, server, proxyDialer)
		})
		if err == nil {
			response, err := pc.Exchange(ctx, msg)
			if err == nil {
				return response, nil
			}
			if pc.IsDead() {
				c.dtlsPool.Remove(pc)
			}
			log.Debugf("UPSTREAM: pipelined DTLS query to %s failed: %v, falling back", server.Address, err)
		}
	}

	// Non-pooled fallback: manual dial + DTLS handshake + DNS exchange.
	conn, err := c.dialDTLSConn(ctx, server.Address, server, proxyDialer)
	if err != nil {
		return nil, err
	}
	defer zdnsutil.CloseWithLog(conn, "DTLS connection", "UPSTREAM")

	// pion's read deadline defaults to never expiring — restore ctx-bound
	// deadlines so a lost datagram cannot hang the read (and its goroutine
	// and socket) forever.
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	if err := msg.Pack(); err != nil {
		return nil, fmt.Errorf("dtls: pack query: %w", err)
	}

	queryLen := len(msg.Data)
	if queryLen > 65535 {
		return nil, fmt.Errorf("dtls: query too large (%d bytes)", queryLen)
	}
	req := make([]byte, 2+queryLen)
	binary.BigEndian.PutUint16(req[:2], uint16(queryLen))
	copy(req[2:], msg.Data)
	if _, err := conn.Write(req); err != nil {
		return nil, fmt.Errorf("dtls: write query: %w", err)
	}

	respBuf := pool.DefaultBuffer.Get()
	defer pool.DefaultBuffer.Put(respBuf)
	n, err := conn.Read(respBuf)
	if err != nil {
		return nil, fmt.Errorf("dtls: read response: %w", err)
	}
	if n < 2 {
		return nil, fmt.Errorf("dtls: response too short (%d bytes)", n)
	}
	respLen := binary.BigEndian.Uint16(respBuf[:2])
	if int(respLen)+2 > n {
		return nil, fmt.Errorf("dtls: short read: want %d + 2, got %d", respLen, n)
	}
	msgBuf := respBuf[2 : 2+respLen]

	response := pool.DefaultMessage.Get()
	response.Data = msgBuf
	if err := response.Unpack(); err != nil {
		response.Data = nil
		pool.DefaultMessage.Put(response)
		return nil, fmt.Errorf("dtls: unpack response: %w", err)
	}

	response.Data = nil // detach from pooled buffer before deferred Put
	// Reject ID mismatches like the TLS/plain-TCP paths (M7) — silently
	// rewriting the ID would accept a datagram belonging to another query.
	if response.ID != msg.ID {
		pool.DefaultMessage.Put(response)
		return nil, fmt.Errorf("dtls: response id mismatch: expected %d, got %d", msg.ID, response.ID)
	}
	log.Debugf("UPSTREAM: DTLS query to %s succeeded", server.Address)
	return response, nil
}

// dialDTLSConn dials a DTLS connection and completes the handshake.  The
// returned connection is owned by the caller (or the pool) and must be closed.
func (c *Client) dialDTLSConn(ctx context.Context, addr string, server *config.UpstreamServer, proxyDialer *socks5.Dialer) (net.Conn, error) {
	tlsConfig := c.stdTLSConfig(server)

	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("dtls: parse address %s: %w", addr, err)
	}
	serverAddr := net.JoinHostPort(host, port)

	var dtlsOpts []dtls.ClientOption
	// DTLS 1.3 preferred, 1.2 fallback for older servers (RFC 9147 §4.2.2).
	// NOTE: our own server is 1.3-only (see server/protocol/tls/dtls.go) —
	// a dual-version [1.2,1.3] server still deadlocks this dual-stack client
	// in current pion (dual-stack server HRR exchange never completes).
	// Revisit when pion fixes the dual-stack server path.
	dtlsOpts = append(dtlsOpts,
		dtls.WithMinVersion(protocol.Version1_2),
		dtls.WithMaxVersion(protocol.Version1_3),
	)
	if server.SkipTLSVerify {
		dtlsOpts = append(dtlsOpts, dtls.WithInsecureSkipVerify(true))
	}
	sni := tlsConfig.ServerName
	if sni == "" && !server.SkipTLSVerify {
		// pion derives SNI from the dial addr when ServerName is unset — with
		// the dial addr switching to a cached IP, pin the original hostname
		// (resolv SNI safety contract).
		if h, _, err := net.SplitHostPort(serverAddr); err == nil && net.ParseIP(h) == nil {
			sni = h
		}
	}
	if sni != "" {
		dtlsOpts = append(dtlsOpts, dtls.WithServerName(sni))
	}
	if c.dtlsSessions != nil {
		dtlsOpts = append(dtlsOpts, dtls.WithSessionStore(c.dtlsSessions))
	}
	dtlsOpts = append(dtlsOpts, dtls.WithVerifyConnection(func(state *dtls.State) error {
		zdnsutil.LogHandshake(&zdnsutil.HandshakeInfo{
			Role:       "UPSTREAM",
			Direction:  "DTLS negotiated for",
			RemoteAddr: serverAddr,
			Cipher:     state.CipherSuiteID.String(),
		})
		return nil
	}))

	var conn net.Conn
	if proxyDialer != nil {
		pconn, pErr := proxyDialer.ListenPacket(ctx)
		if pErr != nil {
			return nil, fmt.Errorf("dtls: proxy ListenPacket: %w", pErr)
		}
		udpAddr, rErr := resolv.Default.ResolveUDPAddr(ctx, serverAddr)
		if rErr != nil {
			_ = pconn.Close()
			return nil, fmt.Errorf("dtls: resolve %s: %w", serverAddr, rErr)
		}
		conn, pErr = dtls.Client(pconn, udpAddr, dtlsOpts...)
		if pErr != nil {
			_ = pconn.Close()
			return nil, fmt.Errorf("dtls: client %s: %w", serverAddr, pErr)
		}
	} else {
		udpAddr, rErr := resolv.Default.ResolveUDPAddr(ctx, serverAddr)
		if rErr != nil {
			return nil, fmt.Errorf("dtls: resolve %s: %w", serverAddr, rErr)
		}
		conn, rErr = dtls.Dial("udp", udpAddr, dtlsOpts...)
		if rErr != nil {
			return nil, fmt.Errorf("dtls: dial %s: %w", serverAddr, rErr)
		}
	}

	// Run the handshake explicitly under the caller's context, bounded by a
	// short handshake deadline: pion's implicit handshake (triggered by the
	// first write) uses context.Background, and the dual-stack client's
	// version negotiation can HANG against an unresponsive or racing server
	// (observed on loopback at ~1 dial in 1e5 under concurrent cold-start —
	// the client-side mirror of the dual-stack server deadlock documented in
	// server/protocol/tls/dtls.go).  Without the bound, one hung handshake
	// burns the whole 9s query budget; with it, the dial fails fast and the
	// caller's existing fallback (pool re-acquire, then a fresh dial)
	// recovers in one round.
	handshakeCtx, cancelHandshake := context.WithTimeout(ctx, config.DefaultDTLSHandshakeTimeout)
	defer cancelHandshake()
	if hc, ok := conn.(interface{ HandshakeContext(context.Context) error }); ok {
		if err := hc.HandshakeContext(handshakeCtx); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("dtls: handshake %s: %w", serverAddr, err)
		}
	}
	return &dtlsStreamConn{r: bufio.NewReaderSize(conn, 65535), Conn: conn}, nil
}
