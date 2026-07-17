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
	"golang.org/x/sync/errgroup"
)

func (s *Server) startDOQServer() error {
	addrs, err := zdnsutil.ResolveBindAddrs("udp", s.cfg.QUICPort)
	if err != nil {
		return fmt.Errorf("DoQ address resolution: %w", err)
	}

	s.doqValidator = newQUICAddrValidator()

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
			VerifySourceAddress: s.doqValidator.requiresValidation,
		}
		s.doqTransports = append(s.doqTransports, transport)

		listener, err := transport.ListenEarly(quicTLSConfig, quicConfig)
		if err != nil {
			_ = conn.Close()
			return fmt.Errorf("DoQ listen on %s: %w", addr, err)
		}
		s.doqListeners = append(s.doqListeners, listener)

		log.Infof("TLS: DoQ server started on %s", addr)

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
			log.Errorf("TLS: DoQ Accept error: %v", err)
			time.Sleep(config.DefaultAcceptRetryDelay)
			continue
		}

		if conn == nil {
			continue
		}

		s.serverGroup.Go(func() error {
			defer zdnsutil.HandlePanic("DoQ connection handler")
			s.handleDOQConnection(conn)
			return nil
		})
	}
}

func (s *Server) handleDOQConnection(conn *quic.Conn) {
	if conn == nil {
		return
	}

	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), config.DefaultBackgroundTimeout)
		defer cancel()
		_ = conn.CloseWithError(pool.QUICCodeNoError, "")
		done := make(chan struct{})
		go func() {
			<-conn.Context().Done()
			close(done)
		}()
		select {
		case <-done:
		case <-ctx.Done():
		}
	}()

	streamGroup, _ := errgroup.WithContext(s.ctx)
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
	defer zdnsutil.HandlePanic("DoQ stream handler")
	buf := pool.DefaultBuffer.Get()
	defer pool.DefaultBuffer.Put(buf)

	_, err := io.ReadFull(stream, buf[:zdnsutil.DNSFramePrefixLen])
	if err != nil {
		return
	}

	msgLen := binary.BigEndian.Uint16(buf[:zdnsutil.DNSFramePrefixLen])
	if msgLen == 0 || msgLen > pool.SecureBufferSize-zdnsutil.DNSFramePrefixLen {
		_ = conn.CloseWithError(pool.QUICCodeProtocolError, "invalid length")
		return
	}

	var body []byte
	if int(msgLen) <= len(buf)-zdnsutil.DNSFramePrefixLen {
		body = buf[zdnsutil.DNSFramePrefixLen : zdnsutil.DNSFramePrefixLen+msgLen]
	} else {
		body = make([]byte, msgLen)
	}

	_, err = io.ReadFull(stream, body)
	if err != nil {
		return
	}

	req := pool.DefaultMessage.Get()
	req.Data = body
	if err := req.Unpack(); err != nil {
		_ = conn.CloseWithError(pool.QUICCodeProtocolError, "invalid DNS message")
		pool.DefaultMessage.Put(req)
		return
	}

	clientIP := secureClientIP(conn)
	response := s.handler.ServeDNS(req, clientIP, true, config.ProtoQUIC)
	pool.DefaultMessage.Put(req)

	if err := s.respondQUIC(stream, response); err != nil {
		log.Debugf("TLS: DoQ response failed: %v", err)
	}
	if response != nil {
		pool.DefaultMessage.Put(response)
	}
}

func (s *Server) respondQUIC(stream *quic.Stream, response *dns.Msg) error {
	if response == nil {
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

	binary.BigEndian.PutUint16(writeBuf[:zdnsutil.DNSFramePrefixLen], uint16(len(respBuf))) //nolint:gosec // G115: DNS length prefix — max 65535 fits uint16
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
