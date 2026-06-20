package server

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
)

// executeQUIC executes a DNS query over DNS over QUIC (DoQ).
// Uses a connection pool for connection reuse and concurrent query multiplexing.
// Falls back to a single-shot connection if the pool is unavailable.
func (qc *QueryClient) executeQUIC(ctx context.Context, msg *dns.Msg, server *config.UpstreamServer, tlsConfig *tls.Config) (*dns.Msg, error) {
	key := server.Address

	quicCfg := &quic.Config{
		MaxIdleTimeout:        config.IdleTimeout,
		MaxIncomingStreams:    MaxIncomingStreams,
		MaxIncomingUniStreams: MaxIncomingStreams,
		EnableDatagrams:       true,
		Allow0RTT:             false,
	}

	dialQUIC := func(dialCtx context.Context, addr string) (*quic.Conn, error) {
		dialTLS := tlsConfig.Clone()
		dialTLS.NextProtos = NextProtoDoQ
		timeoutCtx, cancel := context.WithTimeout(dialCtx, DefaultTimeout)
		defer cancel()
		return quic.DialAddr(timeoutCtx, addr, dialTLS, quicCfg)
	}

	// Try pooled connection first.
	if qc.quicPool != nil {
		pc, err := qc.quicPool.acquire(ctx, key, dialQUIC)
		if err == nil {
			response, err := qc.doQUICQuery(ctx, pc.conn, msg, qc.timeout)
			if err == nil {
				return response, nil
			}
			// Query failed — connection may be dead, remove from pool.
			qc.quicPool.remove(pc)
			log.Debugf("UPSTREAM: pooled DoQ query to %s failed: %v, retrying with new connection", server.Address, err)
		}
	}

	// Fallback: single-shot connection.
	conn, err := dialQUIC(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("QUIC dial: %w", err)
	}

	response, err := qc.doQUICQuery(ctx, conn, msg, qc.timeout)
	if err != nil {
		_ = conn.CloseWithError(QUICCodeNoError, "query failed")
		return nil, err
	}

	// Return successful connection to pool for reuse.
	if qc.quicPool != nil {
		qc.quicPool.put(key, conn)
	} else {
		_ = conn.CloseWithError(QUICCodeNoError, "no pool, discarding")
	}
	return response, nil
}

// doQUICQuery performs the actual QUIC stream write/read on an established connection.
func (qc *QueryClient) doQUICQuery(ctx context.Context, conn *quic.Conn, msg *dns.Msg, timeout time.Duration) (*dns.Msg, error) {
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
	if msgLen == 0 || int(msgLen) > len(respBuf)-2 {
		msg.Id = originalID
		return nil, fmt.Errorf("invalid response length: %d", msgLen)
	}

	if _, err := io.ReadFull(stream, respBuf[2:2+msgLen]); err != nil {
		msg.Id = originalID
		return nil, fmt.Errorf("read message body: %w", err)
	}

	response := pool.DefaultMessagePool.Get()
	if err := response.Unpack(respBuf[2 : 2+msgLen]); err != nil {
		msg.Id = originalID
		pool.DefaultMessagePool.Put(response)
		return nil, fmt.Errorf("unpack: %w", err)
	}

	msg.Id = originalID
	response.Id = originalID

	return response, nil
}
