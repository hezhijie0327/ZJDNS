package tls

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"
	"zjdns/config"
	zdnsutil "zjdns/internal/dnsutil"
	"zjdns/internal/log"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func (s *Server) startDOH3Server(port string) error {
	addrs, err := zdnsutil.ResolveBindAddrs("udp", port)
	if err != nil {
		return fmt.Errorf("DoH3 address resolution: %w", err)
	}

	s.h3Validator = newQUICAddrValidator()

	tlsConfig := s.QUICTLSConfig().Clone()
	tlsConfig.NextProtos = config.NextProtoDOH3

	quicConfig := &quic.Config{
		MaxIdleTimeout:        config.DefaultQUICServerIdleTimeout,
		MaxIncomingStreams:    config.DefaultMaxIncomingStreams,
		MaxIncomingUniStreams: config.DefaultMaxIncomingStreams,
		Allow0RTT:             true,
		EnableDatagrams:       true,
		KeepAlivePeriod:       config.DefaultQUICKeepAlive,
	}

	s.h3Server = &http3.Server{Handler: s}

	log.Infof("TLS: DoH3 server started on %v", addrs)
	for _, addr := range addrs {
		udpAddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			return fmt.Errorf("resolve UDP address %s: %w", addr, err)
		}

		conn, err := net.ListenUDP("udp", udpAddr)
		if err != nil {
			return fmt.Errorf("UDP listen on %s: %w", addr, err)
		}
		s.h3Conns = append(s.h3Conns, conn)

		transport := &quic.Transport{
			Conn:                conn,
			VerifySourceAddress: s.h3Validator.requiresValidation,
		}
		s.h3Transports = append(s.h3Transports, transport)

		listener, err := transport.ListenEarly(tlsConfig, quicConfig)
		if err != nil {
			_ = conn.Close()
			return fmt.Errorf("DoH3 listen on %s: %w", addr, err)
		}
		s.h3Listeners = append(s.h3Listeners, listener)

		capturedH3 := listener
		s.serverGroup.Go(func() error {
			defer zdnsutil.HandlePanic("DoH3 server")
			for {
				conn, err := capturedH3.Accept(s.ctx)
				if err != nil {
					if s.ctx.Err() != nil {
						return nil
					}
					log.Errorf("TLS: DoH3 Accept error: %v", err)
					time.Sleep(config.DefaultAcceptRetryDelay)
					continue
				}

				s.serverGroup.Go(func() error {
					defer zdnsutil.HandlePanic("DoH3 connection handler")
					if err := s.h3Server.ServeQUICConn(conn); err != nil && !errors.Is(err, http.ErrServerClosed) {
						log.Debugf("TLS: DoH3 connection error: %v", err)
					}
					return nil
				})
			}
		})
	}

	return nil
}
