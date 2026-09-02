package tls

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"
	"zjdns/config"
	zdnsutil "zjdns/internal/dnsutil"
	"zjdns/internal/doq"
	"zjdns/internal/log"
	"zjdns/internal/lrumap"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func (s *Server) startDOH3Server(port string) error {
	addrs, err := zdnsutil.ResolveBindAddrs("udp", port)
	if err != nil {
		return fmt.Errorf("DoH3 address resolution: %w", err)
	}

	addrCache := lrumap.New[string, time.Time](config.DefaultQUICAddrCacheSize)

	tlsConfig := s.QUICTLSConfig().Clone()
	tlsConfig.NextProtos = config.NextProtoDOH3

	quicConfig := &quic.Config{
		MaxIdleTimeout:        config.DefaultQUICServerIdleTimeout,
		MaxIncomingStreams:    config.DefaultHTTP3MaxIncomingStreams,
		MaxIncomingUniStreams: config.DefaultHTTP3MaxIncomingStreams,
		Allow0RTT:             true,
		KeepAlivePeriod:       config.DefaultQUICKeepAlive,
	}

	s.listenerMu.Lock()
	// IdleTimeout is the HTTP/3-layer idle bound: QUIC-layer trickles
	// (ACKs, PINGs — which reset the transport MaxIdleTimeout) do NOT
	// reset it, so a client that keeps the connection transport-alive
	// while sending no requests is still closed.
	s.h3Server = &http3.Server{Handler: s, IdleTimeout: config.DefaultQUICServerIdleTimeout}
	s.listenerMu.Unlock()

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
		s.listenerMu.Lock()
		s.h3Conns = append(s.h3Conns, conn)
		s.listenerMu.Unlock()

		transport := &quic.Transport{
			Conn:                conn,
			VerifySourceAddress: makeAddrValidator(addrCache),
		}
		s.listenerMu.Lock()
		s.h3Transports = append(s.h3Transports, transport)
		s.listenerMu.Unlock()

		listener, err := transport.ListenEarly(tlsConfig, quicConfig)
		if err != nil {
			_ = conn.Close()
			return fmt.Errorf("DoH3 listen on %s: %w", addr, err)
		}
		s.listenerMu.Lock()
		s.h3Listeners = append(s.h3Listeners, listener)
		s.listenerMu.Unlock()

		capturedH3 := listener
		s.serverGroup.Go(func() error {
			defer zdnsutil.HandlePanic("DoH3 server")
			// The accept/admission loop lives in handleHTTP3Connections —
			// the standalone path previously carried a line-for-line copy
			// that had already drifted from the shared one (P-M2).
			s.handleHTTP3Connections(capturedH3)
			return nil
		})
	}

	return nil
}

// handleHTTP3Connections runs the accept loop for DoH3 QUIC connections.
// Shared with HandleHTTP3FromPacketConn (shared-port mode) and
// startDOH3Server (standalone mode) — the single implementation so the
// stream bounds and admission cap cannot drift between the two paths.
func (s *Server) handleHTTP3Connections(h3Listener *quic.EarlyListener) {
	for {
		conn, err := h3Listener.Accept(s.ctx)
		if err != nil {
			if s.ctx.Err() != nil {
				return
			}
			log.Debugf("TLS: DoH3 ACCEPT error: %v", err)
			time.Sleep(config.DefaultAcceptRetryDelay)
			continue
		}
		if conn == nil {
			continue
		}

		// Admission cap: quic.Config only limits streams, not
		// connections — a single client could otherwise open
		// unbounded QUIC connections and exhaust goroutines.
		select {
		case s.quicConnSem <- struct{}{}:
		default:
			log.Debugf("TLS: DoH3 connection limit reached, rejecting %s", conn.RemoteAddr())
			_ = conn.CloseWithError(doq.QUICCodeExcessiveLoad, "connection limit reached")
			continue
		}
		s.serverGroup.Go(func() error {
			defer zdnsutil.HandlePanic("DoH3 connection handler")
			defer func() { <-s.quicConnSem }()
			if err := s.h3Server.ServeQUICConn(conn); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Debugf("TLS: DoH3 connection error: %v", err)
			}
			return nil
		})
	}
}
