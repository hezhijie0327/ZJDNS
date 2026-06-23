package client

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"

	"zjdns/config"
	"zjdns/internal/log"
	"zjdns/internal/pool"

	connpool "zjdns/server/client/pool"
)

func (c *Client) executeQUIC(ctx context.Context, msg *dns.Msg, server *config.UpstreamServer, tlsConfig *tls.Config) (*dns.Msg, error) {
	key := server.Address

	quicCfg := &quic.Config{
		MaxIdleTimeout:        config.Timeout,
		MaxIncomingStreams:    MaxIncomingStreams,
		MaxIncomingUniStreams: MaxIncomingStreams,
		EnableDatagrams:       true,
		Allow0RTT:             true,
	}

	dialQUIC := func(dialCtx context.Context, addr string) (*quic.Conn, error) {
		dialTLS := tlsConfig.Clone()
		dialTLS.NextProtos = config.NextProtoDoQ
		timeoutCtx, cancel := context.WithTimeout(dialCtx, config.Timeout)
		defer cancel()
		return quic.DialAddr(timeoutCtx, addr, dialTLS, quicCfg)
	}

	if c.quicPool != nil {
		pc, err := c.quicPool.Acquire(ctx, key, dialQUIC)
		if err == nil {
			response, err := c.doQUICQuery(ctx, pc.Conn, msg, c.timeout)
			if err == nil {
				return response, nil
			}
			c.quicPool.Remove(pc)
			log.Debugf("UPSTREAM: pooled DoQ query to %s failed: %v, retrying with new connection", server.Address, err)
		}
	}

	conn, err := dialQUIC(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("QUIC dial: %w", err)
	}

	response, err := c.doQUICQuery(ctx, conn, msg, c.timeout)
	if err != nil {
		_ = conn.CloseWithError(connpool.QUICCodeNoError, "query failed")
		return nil, err
	}

	if c.quicPool != nil {
		c.quicPool.Put(key, conn)
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
	if len(buf) < 2+len(msgData) {
		writeBuf = make([]byte, 2+len(msgData))
	}

	binary.BigEndian.PutUint16(writeBuf[:2], uint16(len(msgData)))
	copy(writeBuf[2:], msgData)

	if _, err := stream.Write(writeBuf[:2+len(msgData)]); err != nil {
		msg.Id = originalID
		return nil, fmt.Errorf("write: %w", err)
	}

	respBuf := pool.DefaultBufferPool.Get()
	defer pool.DefaultBufferPool.Put(respBuf)

	if _, err := io.ReadFull(stream, respBuf[:2]); err != nil {
		msg.Id = originalID
		return nil, fmt.Errorf("read length prefix: %w", err)
	}
	msgLen := binary.BigEndian.Uint16(respBuf[:2])
	if msgLen == 0 {
		msg.Id = originalID
		return nil, fmt.Errorf("invalid response length: 0")
	}

	var body []byte
	if int(msgLen) <= len(respBuf)-2 {
		body = respBuf[2 : 2+msgLen]
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
