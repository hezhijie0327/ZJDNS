package tls

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
	"zjdns/config"
	zdnsutil "zjdns/internal/dnsutil"
	"zjdns/internal/doq"
	"zjdns/internal/log"
	"zjdns/internal/pool"

	"codeberg.org/miekg/dns"
	"github.com/quic-go/quic-go"
)

// ExecuteQUIC performs a DNS-over-QUIC query, using the QUIC connection pool
// when available.
func (c *Client) ExecuteQUIC(ctx context.Context, msg *dns.Msg, server *config.UpstreamServer) (*dns.Msg, error) {
	if msg == nil {
		return nil, errors.New("quic: nil query message")
	}
	if server == nil {
		return nil, errors.New("quic: nil server config")
	}
	tlsConfig := c.stdTLSConfig(server)
	key := server.Address
	// Identity-keyed pool/config keys: two upstreams sharing an address but
	// differing in ServerName/SkipTLSVerify must not share a pooled QUIC
	// connection or 0-RTT token store across trust boundaries.
	poolKey := transportKey(key, server.ServerName, server.SkipTLSVerify, server.Proxy)
	configKey := "doq:" + poolKey
	proxyDialer := c.getProxy(server)

	dialQUIC := func(dialCtx context.Context, _ string) (*quic.Conn, error) { // _ = poolKey (unused: we dial the real server addr)
		dialTLS := tlsConfig.Clone()
		dialTLS.NextProtos = config.NextProtoDOQ
		timeoutCtx, cancel := context.WithTimeout(dialCtx, config.DefaultDNSQueryTimeout)
		defer cancel()

		// poolKey contains the full identity (e.g. "host:port|name|true|socks5://…");
		// the proxy path must resolve and dial the actual server address (key).
		if proxyDialer != nil {
			pconn, err := proxyDialer.ListenPacket(timeoutCtx)
			if err != nil {
				return nil, fmt.Errorf("proxy ListenPacket: %w", err)
			}
			remoteAddr, err := net.ResolveUDPAddr("udp", key)
			if err != nil {
				_ = pconn.Close()
				return nil, fmt.Errorf("resolve %s: %w", key, err)
			}
			conn, err := quic.Dial(timeoutCtx, pconn, remoteAddr, dialTLS, c.getQUICConfig(configKey, tlsConfig.InsecureSkipVerify))
			if err != nil {
				// quic-go does not take ownership of a caller-provided
				// PacketConn on a failed dial — do not leak the UDP socket.
				_ = pconn.Close()
				return nil, err
			}
			// quic-go never closes a caller-provided PacketConn (createdConn
			// is false) — the SOCKS5 UDP relay (2 fds + monitor goroutine)
			// would leak on every connection teardown.  The conn's Context
			// closes exactly when the connection ends (pool removal,
			// CloseWithError, idle), so the relay's lifetime mirrors the
			// connection's (H3).
			done := conn.Context().Done()
			go func() {
				defer zdnsutil.HandlePanic("QUIC proxy relay release")
				<-done
				_ = pconn.Close()
			}()
			return conn, nil
		}
		conn, err := quic.DialAddrEarly(timeoutCtx, key, dialTLS, c.getQUICConfig(configKey, tlsConfig.InsecureSkipVerify))
		if err == nil {
			log.Debugf("UPSTREAM: DoQ negotiated for %s — cipher=%s resumed=%v 0-RTT=%v",
				key, tls.CipherSuiteName(conn.ConnectionState().TLS.CipherSuite),
				conn.ConnectionState().TLS.DidResume, conn.ConnectionState().Used0RTT)
		}
		return conn, err
	}

	if c.quicPool != nil {
		pc, err := c.quicPool.Acquire(ctx, poolKey, dialQUIC)
		if err == nil {
			response, err := c.doQUICQuery(ctx, pc.Conn, msg, c.timeout)
			if err == nil {
				return response, nil
			}
			// RFC 9250: 0-RTT rejection requires a FRESH connection — retrying
			// on the rejected conn (relying on quic-go's internal fallback)
			// can leave an invalidated connection in the pool. Remove it,
			// reset the token store, and dial anew.
			if errors.Is(err, quic.Err0RTTRejected) {
				c.resetQUICConfig(configKey)
				c.quicPool.Remove(pc)
				if fresh, aErr := c.quicPool.Acquire(ctx, poolKey, dialQUIC); aErr == nil {
					response, err = c.doQUICQuery(ctx, fresh.Conn, msg, c.timeout)
					if err == nil {
						return response, nil
					}
					// Second failure on the fresh conn — the 0-RTT rejection
					// invalidated it too; remove it so it never re-enters
					// the pool (policy: rejected conns must not be reused).
					c.quicPool.Remove(fresh)
				}
			} else if !errors.Is(err, context.Canceled) {
				// Caller-side cancellation (resolver first-wins fan-out) is
				// not a connection failure — the conn stays pooled.
				c.quicPool.Remove(pc)
			}
			log.Debugf("UPSTREAM: pooled DoQ query to %s failed: %v, retrying with new connection", server.Address, err)
		}
	}

	conn, err := dialQUIC(ctx, key)
	if err != nil {
		if errors.Is(err, quic.Err0RTTRejected) {
			c.resetQUICConfig(configKey)
		}
		return nil, fmt.Errorf("QUIC dial: %w", err)
	}

	response, err := c.doQUICQuery(ctx, conn, msg, c.timeout)
	if err != nil {
		if errors.Is(err, quic.Err0RTTRejected) {
			// RFC 9250: 0-RTT rejection invalidates the connection — close
			// it, reset the token store, and dial a FRESH connection (the
			// rejected conn must never re-enter the pool).
			c.resetQUICConfig(configKey)
			_ = conn.CloseWithError(doq.QUICCodeNoError, "0-RTT rejected")
			conn, err = dialQUIC(ctx, key)
			if err == nil {
				response, err = c.doQUICQuery(ctx, conn, msg, c.timeout)
				if err == nil {
					if c.quicPool != nil {
						c.quicPool.Put(poolKey, conn)
					} else {
						_ = conn.CloseWithError(doq.QUICCodeNoError, "no pool, discarding")
					}
					return response, nil
				}
			}
		}
		// conn may be nil when the post-rejection re-dial failed — the
		// rejected connection was already closed above.
		if conn != nil {
			_ = conn.CloseWithError(doq.QUICCodeNoError, "query failed")
		}
		return nil, err
	}

	if c.quicPool != nil {
		c.quicPool.Put(poolKey, conn)
	} else {
		_ = conn.CloseWithError(doq.QUICCodeNoError, "no pool, discarding")
	}
	return response, nil
}

// doQUICQuery opens a stream on the QUIC connection and performs the DNS
// exchange.
func (c *Client) doQUICQuery(ctx context.Context, conn *quic.Conn, msg *dns.Msg, timeout time.Duration) (*dns.Msg, error) {
	// Short budget for the stream open (see DefaultQUICStreamOpenTimeout):
	// an exhausted stream quota must not block the query for the full
	// timeout — the pool removes the connection and dials a fresh one.
	streamCtx, streamCancel := context.WithTimeout(ctx, config.DefaultQUICStreamOpenTimeout)
	defer streamCancel()
	stream, err := conn.OpenStreamSync(streamCtx)
	if err != nil {
		return nil, fmt.Errorf("open stream: %w", err)
	}
	defer func() {
		// RFC 9250 §4.3.1: cancel with DOQ_REQUEST_CANCELLED on shutdown.
		if ctx.Err() != nil {
			stream.CancelRead(quic.StreamErrorCode(doq.QUICCodeRequestCancelled))
		}
		_ = stream.Close()
	}()

	_ = stream.SetDeadline(time.Now().Add(timeout))
	// Fail fast on ctx cancellation like the DoT/DTLS/DTLCP transports
	// (R3-M6): stream I/O is not ctx-aware, so without this a cancelled
	// query (client disconnect, shutdown) leaves the goroutine and stream
	// blocked until the full timeout elapses.
	stop := context.AfterFunc(ctx, func() {
		stream.CancelRead(quic.StreamErrorCode(doq.QUICCodeRequestCancelled))
		stream.CancelWrite(quic.StreamErrorCode(doq.QUICCodeRequestCancelled))
	})
	defer stop()

	originalID := msg.ID
	msg.ID = 0

	err = msg.Pack()
	msgData := msg.Data
	if err != nil {
		msg.ID = originalID
		return nil, fmt.Errorf("pack: %w", err)
	}

	buf := pool.DefaultBuffer.Get()
	defer pool.DefaultBuffer.Put(buf)

	writeBuf := buf
	if len(buf) < zdnsutil.DNSFramePrefixLen+len(msgData) {
		writeBuf = make([]byte, zdnsutil.DNSFramePrefixLen+len(msgData))
	}

	binary.BigEndian.PutUint16(writeBuf[:zdnsutil.DNSFramePrefixLen], uint16(len(msgData))) //nolint:gosec // G115: DNS length prefix — max 65535 fits uint16
	copy(writeBuf[zdnsutil.DNSFramePrefixLen:], msgData)

	if _, err := stream.Write(writeBuf[:zdnsutil.DNSFramePrefixLen+len(msgData)]); err != nil {
		msg.ID = originalID
		return nil, fmt.Errorf("write: %w", err)
	}

	respBuf := pool.DefaultBuffer.Get()
	defer pool.DefaultBuffer.Put(respBuf)

	if _, err := io.ReadFull(stream, respBuf[:zdnsutil.DNSFramePrefixLen]); err != nil {
		msg.ID = originalID
		return nil, fmt.Errorf("read length prefix: %w", err)
	}
	msgLen := binary.BigEndian.Uint16(respBuf[:zdnsutil.DNSFramePrefixLen])
	if msgLen == 0 {
		msg.ID = originalID
		return nil, errors.New("invalid response length: 0")
	}

	var body []byte
	if int(msgLen) <= len(respBuf)-zdnsutil.DNSFramePrefixLen {
		body = respBuf[zdnsutil.DNSFramePrefixLen : zdnsutil.DNSFramePrefixLen+msgLen]
	} else {
		body = make([]byte, msgLen)
	}

	if _, err := io.ReadFull(stream, body); err != nil {
		msg.ID = originalID
		return nil, fmt.Errorf("read message body: %w", err)
	}

	response := pool.DefaultMessage.Get()
	response.Data = body
	if err := response.Unpack(); err != nil {
		msg.ID = originalID
		response.Data = nil
		pool.DefaultMessage.Put(response)
		return nil, fmt.Errorf("unpack: %w", err)
	}
	response.Data = nil

	// RFC 9250 §4.2.1: the DNS message ID MUST be zero on DoQ. A
	// non-zero ID indicates a protocol violation — discard the response
	// instead of silently rewriting the ID (the stream is 1:1 so the
	// query is unambiguous, but the violation must not be papered over).
	if response.ID != 0 {
		msg.ID = originalID
		pool.DefaultMessage.Put(response)
		return nil, errors.New("doq: response message ID is non-zero (RFC 9250 §4.2.1 violation)")
	}

	msg.ID = originalID
	response.ID = originalID

	return response, nil
}
