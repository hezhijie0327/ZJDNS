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

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"

	"zjdns/config"
	"zjdns/internal/dnsutil"
	"zjdns/internal/log"
	"zjdns/internal/pool"

	connpool "zjdns/server/client/pool"
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
			return quic.Dial(timeoutCtx, pconn, remoteAddr, dialTLS, c.getQUICConfig(key, tlsConfig.InsecureSkipVerify))
		}
		return quic.DialAddrEarly(timeoutCtx, addr, dialTLS, c.getQUICConfig(key, tlsConfig.InsecureSkipVerify))
	}

	if c.quicPool != nil {
		pc, err := c.quicPool.Acquire(ctx, poolKey, dialQUIC)
		if err == nil {
			response, err := c.doQUICQuery(ctx, pc.Conn, msg, c.timeout)
			if err == nil {
				return response, nil
			}
			c.quicPool.Remove(pc)
			if errors.Is(err, quic.Err0RTTRejected) {
				c.resetQUICConfig(key)
			}
			log.Debugf("UPSTREAM: pooled DoQ query to %s failed: %v, retrying with new connection", server.Address, err)
		}
	}

	conn, err := dialQUIC(ctx, key)
	if err != nil {
		// On 0-RTT rejection, reset the TokenStore so the next connection
		// attempt starts with a clean address-validation token cache.
		if errors.Is(err, quic.Err0RTTRejected) {
			c.resetQUICConfig(key)
		}
		return nil, fmt.Errorf("QUIC dial: %w", err)
	}

	response, err := c.doQUICQuery(ctx, conn, msg, c.timeout)
	if err != nil {
		_ = conn.CloseWithError(connpool.QUICCodeNoError, "query failed")
		return nil, err
	}

	if c.quicPool != nil {
		c.quicPool.Put(poolKey, conn)
	} else {
		_ = conn.CloseWithError(connpool.QUICCodeNoError, "no pool, discarding")
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

	originalID := msg.Id
	msg.Id = 0

	msgData, err := msg.Pack()
	if err != nil {
		msg.Id = originalID
		return nil, fmt.Errorf("pack: %w", err)
	}

	buf := pool.DefaultBufferPool.Get()
	defer pool.DefaultBufferPool.Put(buf)

	writeBuf := buf
	if len(buf) < dnsutil.DNSFramePrefixLen+len(msgData) {
		writeBuf = make([]byte, dnsutil.DNSFramePrefixLen+len(msgData))
	}

	binary.BigEndian.PutUint16(writeBuf[:dnsutil.DNSFramePrefixLen], uint16(len(msgData)))
	copy(writeBuf[dnsutil.DNSFramePrefixLen:], msgData)

	if _, err := stream.Write(writeBuf[:dnsutil.DNSFramePrefixLen+len(msgData)]); err != nil {
		msg.Id = originalID
		return nil, fmt.Errorf("write: %w", err)
	}

	respBuf := pool.DefaultBufferPool.Get()
	defer pool.DefaultBufferPool.Put(respBuf)

	if _, err := io.ReadFull(stream, respBuf[:dnsutil.DNSFramePrefixLen]); err != nil {
		msg.Id = originalID
		return nil, fmt.Errorf("read length prefix: %w", err)
	}
	msgLen := binary.BigEndian.Uint16(respBuf[:dnsutil.DNSFramePrefixLen])
	if msgLen == 0 {
		msg.Id = originalID
		return nil, fmt.Errorf("invalid response length: 0")
	}

	var body []byte
	if int(msgLen) <= len(respBuf)-dnsutil.DNSFramePrefixLen {
		body = respBuf[dnsutil.DNSFramePrefixLen : dnsutil.DNSFramePrefixLen+msgLen]
	} else {
		body = make([]byte, msgLen)
	}

	if _, err := io.ReadFull(stream, body); err != nil {
		msg.Id = originalID
		return nil, fmt.Errorf("read message body: %w", err)
	}

	response := pool.DefaultMessagePool.Get()
	if err := response.Unpack(body); err != nil {
		msg.Id = originalID
		pool.DefaultMessagePool.Put(response)
		return nil, fmt.Errorf("unpack: %w", err)
	}

	msg.Id = originalID
	response.Id = originalID

	return response, nil
}
