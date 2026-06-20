package server

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"golang.org/x/sync/errgroup"

	"zjdns/config"
	"zjdns/internal/dnsutil"
	"zjdns/internal/log"
	"zjdns/internal/pool"
)

// startDOQServer starts the DNS over QUIC server.
func (tm *TLSManager) startDOQServer() error {
	addr := ":" + tm.server.config.Server.TLS.Port

	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return fmt.Errorf("resolve UDP address: %w", err)
	}

	tm.doqConn, err = net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("UDP listen: %w", err)
	}

	tm.doqTransport = &quic.Transport{
		Conn: tm.doqConn,
	}

	// Configure TLS for DoQ
	quicTLSConfig := tm.tlsConfig.Clone()
	quicTLSConfig.NextProtos = NextProtoDoQ

	quicConfig := &quic.Config{
		MaxIdleTimeout:        config.IdleTimeout,
		MaxIncomingStreams:    MaxIncomingStreams,
		MaxIncomingUniStreams: MaxIncomingStreams,
		Allow0RTT:             true,
		EnableDatagrams:       true,
	}

	tm.doqListener, err = tm.doqTransport.ListenEarly(quicTLSConfig, quicConfig)
	if err != nil {
		_ = tm.doqConn.Close()
		return fmt.Errorf("DoQ listen: %w", err)
	}

	log.Infof("TLS: DoQ server started on port %s", tm.server.config.Server.TLS.Port)

	tm.serverGroup.Go(func() error {
		defer dnsutil.HandlePanic("DoQ server")
		tm.handleDOQConnections()
		return nil
	})

	return nil
}

// handleDOQConnections accepts and handles incoming DoQ connections.
func (tm *TLSManager) handleDOQConnections() {
	for {
		select {
		case <-tm.ctx.Done():
			return
		default:
		}

		conn, err := tm.doqListener.Accept(tm.ctx)
		if err != nil {
			if tm.ctx.Err() != nil {
				return
			}
			log.Errorf("TLS: DoQ Accept error: %v", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}

		if conn == nil {
			continue
		}

		tm.serverGroup.Go(func() error {
			defer dnsutil.HandlePanic("DoQ connection handler")
			tm.handleDOQConnection(conn)
			return nil
		})
	}
}

// handleDOQConnection handles a single DoQ connection.
func (tm *TLSManager) handleDOQConnection(conn *quic.Conn) {
	if conn == nil {
		return
	}

	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), DefaultTimeout)
		defer cancel()

		_ = conn.CloseWithError(QUICCodeNoError, "")

		done := make(chan struct{})
		go func() {
			<-conn.Context().Done()
			close(done)
		}()

		select {
		case <-done:
		case <-ctx.Done():
			log.Debugf("TLS: Connection close timeout")
		}
	}()

	streamGroup, _ := errgroup.WithContext(tm.ctx)
	streamGroup.SetLimit(64) // Limit concurrent streams per DoQ connection

	for {
		select {
		case <-tm.ctx.Done():
			if err := streamGroup.Wait(); err != nil {
				log.Errorf("DoQ: Stream group finished with error: %v", err)
			}
			return
		case <-conn.Context().Done():
			if err := streamGroup.Wait(); err != nil {
				log.Errorf("DoQ: Stream group finished with error: %v", err)
			}
			return
		default:
		}

		stream, err := conn.AcceptStream(tm.ctx)
		if err != nil {
			if err := streamGroup.Wait(); err != nil {
				log.Errorf("DoQ: Stream group finished with error: %v", err)
			}
			return
		}

		if stream == nil {
			continue
		}

		streamGroup.Go(func() error {
			defer dnsutil.HandlePanic("DoQ stream handler")
			if stream != nil {
				defer func() { _ = stream.Close() }()
				tm.handleDOQStream(stream, conn)
			}
			return nil
		})
	}
}

// handleDOQStream handles a single DoQ stream.
func (tm *TLSManager) handleDOQStream(stream *quic.Stream, conn *quic.Conn) {
	buf := pool.DefaultBufferPool.Get()
	defer pool.DefaultBufferPool.Put(buf)

	// Read message length
	n, err := io.ReadFull(stream, buf[:2])
	if err != nil || n < 2 {
		return
	}

	msgLen := binary.BigEndian.Uint16(buf[:2])
	if msgLen == 0 || msgLen > pool.SecureBufferSize-2 {
		_ = conn.CloseWithError(QUICCodeProtocolError, "invalid length")
		return
	}

	// Read message body
	n, err = io.ReadFull(stream, buf[2:2+msgLen])
	if err != nil || n != int(msgLen) {
		return
	}

	// Parse DNS message
	req := pool.DefaultMessagePool.Get()
	if err := req.Unpack(buf[2 : 2+msgLen]); err != nil {
		_ = conn.CloseWithError(QUICCodeProtocolError, "invalid DNS message")
		pool.DefaultMessagePool.Put(req)
		return
	}

	// Get client IP and process query
	clientIP := SecureClientIP(conn)
	response := tm.server.processDNSQuery(req, clientIP, true, "DoQ")
	pool.DefaultMessagePool.Put(req)
	// Send response
	if err := tm.respondQUIC(stream, response); err != nil {
		log.Debugf("TLS: DoQ response failed: %v", err)
	}
	if response != nil {
		pool.DefaultMessagePool.Put(response)
	}
}

// respondQUIC sends a DNS response over a QUIC stream.
func (tm *TLSManager) respondQUIC(stream *quic.Stream, response *dns.Msg) error {
	if response == nil {
		return errors.New("response is nil")
	}

	respBuf, err := response.Pack()
	if err != nil {
		return fmt.Errorf("pack response: %w", err)
	}

	buf := pool.DefaultBufferPool.Get()
	defer pool.DefaultBufferPool.Put(buf)

	writeBuf := buf
	if len(buf) < 2+len(respBuf) {
		writeBuf = make([]byte, 2+len(respBuf))
	}

	binary.BigEndian.PutUint16(writeBuf[:2], uint16(len(respBuf)))
	copy(writeBuf[2:], respBuf)

	n, err := stream.Write(writeBuf[:2+len(respBuf)])
	if err != nil {
		return fmt.Errorf("stream write: %w", err)
	}
	if n != len(writeBuf[:2+len(respBuf)]) {
		return fmt.Errorf("write length mismatch: %d != %d", n, len(writeBuf[:2+len(respBuf)]))
	}

	return nil
}
