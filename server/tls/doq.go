package tls

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/quic-go/quic-go"
	"golang.org/x/sync/errgroup"

	"zjdns/config"
	"zjdns/internal/dnsutil"
	"zjdns/internal/log"
	"zjdns/internal/pool"
)

func (s *Server) startDOQServer() error {
	addrs, err := dnsutil.ResolveBindAddrs("udp", s.cfg.Port)
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
			defer dnsutil.HandlePanic("DoQ server")
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
			defer dnsutil.HandlePanic("DoQ connection handler")
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
			defer dnsutil.HandlePanic("DoQ stream handler")
			defer func() { _ = stream.Close() }()
			s.handleDOQStream(stream, conn)
			return nil
		})
	}
}

func (s *Server) handleDOQStream(stream *quic.Stream, conn *quic.Conn) {
	defer dnsutil.HandlePanic("DoQ stream handler")
	buf := pool.DefaultBufferPool.Get()
	defer pool.DefaultBufferPool.Put(buf)

	_, err := io.ReadFull(stream, buf[:dnsutil.DNSFramePrefixLen])
	if err != nil {
		return
	}

	msgLen := binary.BigEndian.Uint16(buf[:dnsutil.DNSFramePrefixLen])
	if msgLen == 0 || msgLen > pool.SecureBufferSize-dnsutil.DNSFramePrefixLen {
		_ = conn.CloseWithError(pool.QUICCodeProtocolError, "invalid length")
		return
	}

	var body []byte
	if int(msgLen) <= len(buf)-dnsutil.DNSFramePrefixLen {
		body = buf[dnsutil.DNSFramePrefixLen : dnsutil.DNSFramePrefixLen+msgLen]
	} else {
		body = make([]byte, msgLen)
	}

	_, err = io.ReadFull(stream, body)
	if err != nil {
		return
	}

	req := pool.DefaultMessagePool.Get()
	req.Data = body
	if err := req.Unpack(); err != nil {
		_ = conn.CloseWithError(pool.QUICCodeProtocolError, "invalid DNS message")
		pool.DefaultMessagePool.Put(req)
		return
	}

	clientIP := secureClientIP(conn)
	response := s.handler.ServeDNS(req, clientIP, true, "DoQ")
	pool.DefaultMessagePool.Put(req)

	if err := s.respondQUIC(stream, response); err != nil {
		log.Debugf("TLS: DoQ response failed: %v", err)
	}
	if response != nil {
		pool.DefaultMessagePool.Put(response)
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

	buf := pool.DefaultBufferPool.Get()
	defer pool.DefaultBufferPool.Put(buf)

	writeBuf := buf
	if len(buf) < dnsutil.DNSFramePrefixLen+len(respBuf) {
		writeBuf = make([]byte, dnsutil.DNSFramePrefixLen+len(respBuf))
	}

	binary.BigEndian.PutUint16(writeBuf[:dnsutil.DNSFramePrefixLen], uint16(len(respBuf)))
	copy(writeBuf[dnsutil.DNSFramePrefixLen:], respBuf)

	n, err := stream.Write(writeBuf[:dnsutil.DNSFramePrefixLen+len(respBuf)])
	if err != nil {
		return fmt.Errorf("stream write: %w", err)
	}
	if n != len(writeBuf[:dnsutil.DNSFramePrefixLen+len(respBuf)]) {
		return fmt.Errorf("write length mismatch: %d != %d", n, len(writeBuf[:dnsutil.DNSFramePrefixLen+len(respBuf)]))
	}

	return nil
}
