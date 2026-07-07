package client

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
	"zjdns/internal/log"
	"zjdns/internal/pool"

	"codeberg.org/miekg/dns"
	"github.com/quic-go/quic-go"
)

func (c *Client) executeQUIC(ctx context.Context, msg *dns.Msg, server *config.UpstreamServer, tlsConfig *tls.Config) (*dns.Msg, error) {
	key := server.Address
	poolKey := proxyPoolKey(key, server.Proxy)
	proxyDialer := c.getProxyDialer(server)

	dialQUIC := func(dialCtx context.Context, addr string) (*quic.Conn, error) {
		dialTLS := tlsConfig.Clone()
		dialTLS.NextProtos = config.NextProtoDOQ
		timeoutCtx, cancel := context.WithTimeout(dialCtx, config.DefaultDNSQueryTimeout)
		defer cancel()

		if proxyDialer != nil {
			pconn, err := proxyDialer.ListenPacket(timeoutCtx)
			if err != nil {
				return nil, fmt.Errorf("proxy ListenPacket: %w", err)
			}
			remoteAddr, err := net.ResolveUDPAddr("udp", addr)
			if err != nil {
				return nil, fmt.Errorf("resolve %s: %w", addr, err)
			}
			return quic.Dial(timeoutCtx, pconn, remoteAddr, dialTLS, c.getQUICConfig("doq:"+key, tlsConfig.InsecureSkipVerify))
		}
		return quic.DialAddrEarly(timeoutCtx, addr, dialTLS, c.getQUICConfig("doq:"+key, tlsConfig.InsecureSkipVerify))
	}

	if c.quicPool != nil {
		pc, err := c.quicPool.Acquire(ctx, poolKey, dialQUIC)
		if err == nil {
			response, err := c.doQUICQuery(ctx, pc.Conn, msg, c.timeout)
			if err == nil {
				return response, nil
			}
			// Err0RTTRejected means the server rejected 0-RTT data on the
			// stream, but the connection is still valid (fell back to 1-RTT).
			// Reset stale tokens and retry on the same connection.
			if errors.Is(err, quic.Err0RTTRejected) {
				c.resetQUICConfig("doq:" + key)
				response, err = c.doQUICQuery(ctx, pc.Conn, msg, c.timeout)
				if err == nil {
					return response, nil
				}
			}
			c.quicPool.Remove(pc)
			log.Debugf("UPSTREAM: pooled DoQ query to %s failed: %v, retrying with new connection", server.Address, err)
		}
	}

	conn, err := dialQUIC(ctx, key)
	if err != nil {
		// On 0-RTT rejection, reset the TokenStore so the next connection
		// attempt starts with a clean address-validation token cache.
		if errors.Is(err, quic.Err0RTTRejected) {
			c.resetQUICConfig("doq:" + key)
		}
		return nil, fmt.Errorf("QUIC dial: %w", err)
	}

	response, err := c.doQUICQuery(ctx, conn, msg, c.timeout)
	if err != nil {
		// Same as the pooled path: a 0-RTT rejection on stream open does
		// not invalidate the connection. Reset tokens and retry.
		if errors.Is(err, quic.Err0RTTRejected) {
			c.resetQUICConfig("doq:" + key)
			response, err = c.doQUICQuery(ctx, conn, msg, c.timeout)
			if err == nil {
				if c.quicPool != nil {
					c.quicPool.Put(poolKey, conn)
				} else {
					_ = conn.CloseWithError(pool.QUICCodeNoError, "no pool, discarding")
				}
				return response, nil
			}
		}
		_ = conn.CloseWithError(pool.QUICCodeNoError, "query failed")
		return nil, err
	}

	if c.quicPool != nil {
		c.quicPool.Put(poolKey, conn)
	} else {
		_ = conn.CloseWithError(pool.QUICCodeNoError, "no pool, discarding")
	}
	return response, nil
}

func (c *Client) doQUICQuery(ctx context.Context, conn *quic.Conn, msg *dns.Msg, timeout time.Duration) (*dns.Msg, error) {
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("open stream: %w", err)
	}
	defer func() { _ = stream.Close() }()

	_ = stream.SetDeadline(time.Now().Add(timeout))

	originalID := msg.ID
	msg.ID = 0

	err = msg.Pack()
	msgData := msg.Data
	if err != nil {
		msg.ID = originalID
		return nil, fmt.Errorf("pack: %w", err)
	}

	buf := pool.DefaultBufferPool.Get()
	defer pool.DefaultBufferPool.Put(buf)

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

	respBuf := pool.DefaultBufferPool.Get()
	defer pool.DefaultBufferPool.Put(respBuf)

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

	response := pool.DefaultMessagePool.Get()
	response.Data = body
	if err := response.Unpack(); err != nil {
		msg.ID = originalID
		pool.DefaultMessagePool.Put(response)
		return nil, fmt.Errorf("unpack: %w", err)
	}

	msg.ID = originalID
	response.ID = originalID

	return response, nil
}
