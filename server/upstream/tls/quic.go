package tls

import (
	"context"
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

// ExecuteQUIC performs a DNS-over-QUIC query, using the QUIC connection pool
// when available.
func (c *Client) ExecuteQUIC(ctx context.Context, msg *dns.Msg, server *config.UpstreamServer) (*dns.Msg, error) {
	tlsConfig := c.stdTLSConfig(server)
	key := server.Address
	poolKey := key
	if server.Proxy != "" {
		poolKey = key + "|" + server.Proxy
	}
	proxyDialer := c.getProxy(server)

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
		if errors.Is(err, quic.Err0RTTRejected) {
			c.resetQUICConfig("doq:" + key)
		}
		return nil, fmt.Errorf("QUIC dial: %w", err)
	}

	response, err := c.doQUICQuery(ctx, conn, msg, c.timeout)
	if err != nil {
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

// doQUICQuery opens a stream on the QUIC connection and performs the DNS
// exchange.
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
		pool.DefaultMessage.Put(response)
		return nil, fmt.Errorf("unpack: %w", err)
	}
	response.Data = nil

	msg.ID = originalID
	response.ID = originalID

	return response, nil
}
