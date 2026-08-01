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
	"zjdns/internal/lrumap"
	"zjdns/internal/pool"

	"codeberg.org/miekg/dns"
	"github.com/quic-go/quic-go"
	"golang.org/x/sync/errgroup"
)

func (s *Server) startDOQServer() error {
	addrs, err := zdnsutil.ResolveBindAddrs("udp", s.cfg.QUICPort)
	if err != nil {
		return fmt.Errorf("DoQ address resolution: %w", err)
	}

	addrCache := lrumap.New[string, time.Time](config.DefaultQUICAddrCacheSize)

	quicTLSConfig := s.QUICTLSConfig().Clone()
	quicTLSConfig.NextProtos = config.NextProtoDOQ

	quicConfig := &quic.Config{
		MaxIdleTimeout:        config.DefaultQUICServerIdleTimeout,
		MaxIncomingStreams:    config.DefaultMaxIncomingStreams,
		MaxIncomingUniStreams: config.DefaultMaxIncomingStreams,
		Allow0RTT:             true,
		EnableDatagrams:       true,
		KeepAlivePeriod:       config.DefaultQUICKeepAlive,
	}

	log.Infof("TLS: DoQ server started on %v", addrs)
	for _, addr := range addrs {
		udpAddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			return fmt.Errorf("resolve UDP address %s: %w", addr, err)
		}

		conn, err := net.ListenUDP("udp", udpAddr)
		if err != nil {
			return fmt.Errorf("UDP listen on %s: %w", addr, err)
		}
		s.doqConns = append(s.doqConns, conn)

		transport := &quic.Transport{
			Conn:                conn,
			VerifySourceAddress: makeAddrValidator(addrCache),
		}
		s.doqTransports = append(s.doqTransports, transport)

		listener, err := transport.ListenEarly(quicTLSConfig, quicConfig)
		if err != nil {
			_ = conn.Close()
			return fmt.Errorf("DoQ listen on %s: %w", addr, err)
		}
		s.doqListeners = append(s.doqListeners, listener)

		capturedDoQ := listener
		s.serverGroup.Go(func() error {
			defer zdnsutil.HandlePanic("DoQ server")
			s.handleDOQConnections(capturedDoQ)
			return nil
		})
	}

	return nil
}

func (s *Server) handleDOQConnections(doqListener *quic.EarlyListener) {
	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		conn, err := doqListener.Accept(s.ctx)
		if err != nil {
			if s.ctx.Err() != nil {
				return
			}
			log.Debugf("TLS: DoQ Accept error: %v", err)
			time.Sleep(config.DefaultAcceptRetryDelay)
			continue
		}

		if conn == nil {
			continue
		}

		log.Debugf("TLS: DoQ connection from %s — cipher=%s resumed=%v 0-RTT=%v",
			conn.RemoteAddr(), tls.CipherSuiteName(conn.ConnectionState().TLS.CipherSuite),
			conn.ConnectionState().TLS.DidResume, conn.ConnectionState().Used0RTT)

		// Admission cap: quic.Config only limits streams, not connections.
		select {
		case s.quicConnSem <- struct{}{}:
		default:
			log.Debugf("TLS: DoQ connection limit reached, rejecting %s", conn.RemoteAddr())
			_ = conn.CloseWithError(doq.QUICCodeExcessiveLoad, "connection limit reached")
			continue
		}
		s.serverGroup.Go(func() error {
			defer zdnsutil.HandlePanic("DoQ connection handler")
			defer func() { <-s.quicConnSem }()
			s.handleDOQConnection(conn)
			return nil
		})
	}
}

func (s *Server) handleDOQConnection(conn *quic.Conn) {
	if conn == nil {
		return
	}

	// Graceful close: send CONNECTION_CLOSE with NO_ERROR and wait for the
	// peer to acknowledge, or fall through on timeout.
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), config.DefaultBackgroundTimeout)
		defer cancel()
		_ = conn.CloseWithError(doq.QUICCodeNoError, "")

		done := make(chan struct{})
		stop := context.AfterFunc(conn.Context(), func() {
			close(done)
		})
		defer stop()

		select {
		case <-done:
		case <-ctx.Done():
		}
	}()

	streamGroup, streamCtx := errgroup.WithContext(s.ctx)
	_ = streamCtx
	streamGroup.SetLimit(config.DefaultMaxConcurrentStreams)

	for {
		select {
		case <-s.ctx.Done():
			_ = streamGroup.Wait()
			return
		case <-conn.Context().Done():
			_ = streamGroup.Wait()
			return
		default:
		}

		stream, err := conn.AcceptStream(s.ctx)
		if err != nil {
			_ = streamGroup.Wait()
			return
		}

		if stream == nil {
			continue
		}

		streamGroup.Go(func() error {
			defer zdnsutil.HandlePanic("DoQ stream handler")
			defer func() { _ = stream.Close() }()
			s.handleDOQStream(stream, conn)
			return nil
		})
	}
}

func (s *Server) handleDOQStream(stream *quic.Stream, conn *quic.Conn) {
	if stream == nil {
		return
	}
	defer zdnsutil.HandlePanic("DoQ stream handler")
	buf := pool.DefaultBuffer.Get()
	defer pool.DefaultBuffer.Put(buf)

	// Avoid blocking indefinitely during shutdown: derive a per-stream
	// context from the QUIC connection and check it before each read.
	select {
	case <-conn.Context().Done():
		return
	default:
	}

	_ = stream.SetReadDeadline(time.Now().Add(config.DefaultTCPPoolIdleTimeout))
	_, err := io.ReadFull(stream, buf[:zdnsutil.DNSFramePrefixLen])
	if err != nil {
		if err == io.ErrUnexpectedEOF {
			log.Debugf("SERVER: DoQ protocol error: truncated STREAM FIN from %s", conn.RemoteAddr())
		}
		return
	}

	msgLen := binary.BigEndian.Uint16(buf[:zdnsutil.DNSFramePrefixLen])
	switch {
	case msgLen == 0:
		_ = conn.CloseWithError(doq.QUICCodeProtocolError, "zero-length DNS message")
		return
	case msgLen > dns.MaxMsgSize:
		_ = conn.CloseWithError(doq.QUICCodeProtocolError, "message too large")
		return
	}

	var body []byte
	if int(msgLen) <= len(buf)-zdnsutil.DNSFramePrefixLen {
		body = buf[zdnsutil.DNSFramePrefixLen : zdnsutil.DNSFramePrefixLen+msgLen]
	} else {
		body = make([]byte, msgLen)
	}

	_ = stream.SetReadDeadline(time.Now().Add(config.DefaultTCPPoolIdleTimeout))
	_, err = io.ReadFull(stream, body)
	if err != nil {
		return
	}

	req := pool.DefaultMessage.Get()
	req.Data = body
	if err := req.Unpack(); err != nil {
		_ = conn.CloseWithError(doq.QUICCodeProtocolError, "invalid DNS message")
		pool.DefaultMessage.Put(req)
		return
	}

	// RFC 9250 §4.3.3: non-zero Message ID is a protocol error.
	if req.ID != 0 {
		_ = conn.CloseWithError(doq.QUICCodeProtocolError, "non-zero DNS message ID")
		pool.DefaultMessage.Put(req)
		return
	}

	// RFC 9250 §4.5: 0-RTT MUST NOT carry non-replayable transactions.
	// RFC 9250 §4.5: QUERY and NOTIFY are replayable in 0-RTT.
	if conn.ConnectionState().Used0RTT && req.Opcode != dns.OpcodeQuery {
		stream.CancelWrite(quic.StreamErrorCode(doq.QUICCodeProtocolError))
		pool.DefaultMessage.Put(req)
		return
	}

	clientIP := zdnsutil.ClientIPFromAddr(conn.RemoteAddr())
	// RFC 9250 §4.3.1: abort on client STOP_SENDING / RESET_STREAM.
	select {
	case <-conn.Context().Done():
		return
	default:
	}
	response := s.handler.ServeDNS(req, clientIP, true, config.ProtoQUIC)
	// The caller owns req and returns it to the pool exactly once.
	pool.DefaultMessage.Put(req)

	if err := s.respondQUIC(stream, response); err != nil {
		log.Debugf("TLS: DoQ response failed: %v", err)
	}
	// Identity guard: a handler may return the request message itself as the
	// response — pooling the same pointer twice would let two goroutines
	// race on it.
	if response != nil && response != req {
		defer pool.DefaultMessage.Put(response)
	}
}

func (s *Server) respondQUIC(stream *quic.Stream, response *dns.Msg) error {
	if response == nil {
		// RFC 9250 §4.3.2: signal transaction error via RESET_STREAM.
		stream.CancelWrite(quic.StreamErrorCode(doq.QUICCodeInternalError))
		return errors.New("response is nil")
	}

	err := response.Pack()
	respBuf := response.Data
	if err != nil {
		return fmt.Errorf("pack response: %w", err)
	}

	buf := pool.DefaultBuffer.Get()
	defer pool.DefaultBuffer.Put(buf)

	writeBuf := buf
	if len(buf) < zdnsutil.DNSFramePrefixLen+len(respBuf) {
		writeBuf = make([]byte, zdnsutil.DNSFramePrefixLen+len(respBuf))
	}

	// RFC 9250 §4.3.2: oversized response → DOQ_INTERNAL_ERROR
	if len(respBuf) > 65535 {
		return fmt.Errorf("response too large for DoQ: %d bytes (max 65535)", len(respBuf))
	}
	binary.BigEndian.PutUint16(writeBuf[:zdnsutil.DNSFramePrefixLen], uint16(len(respBuf))) //nolint:gosec // G115: bounds checked above
	copy(writeBuf[zdnsutil.DNSFramePrefixLen:], respBuf)

	n, err := stream.Write(writeBuf[:zdnsutil.DNSFramePrefixLen+len(respBuf)])
	if err != nil {
		return fmt.Errorf("stream write: %w", err)
	}
	if n != len(writeBuf[:zdnsutil.DNSFramePrefixLen+len(respBuf)]) {
		return fmt.Errorf("write length mismatch: %d != %d", n, len(writeBuf[:zdnsutil.DNSFramePrefixLen+len(respBuf)]))
	}

	return nil
}
