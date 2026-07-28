package tls

import (
	"encoding/binary"
	"errors"
	"net"
	"time"
	"zjdns/config"
	zdnsutil "zjdns/internal/dnsutil"
	"zjdns/internal/log"
	"zjdns/internal/lrumap"
	"zjdns/internal/pool"

	"codeberg.org/miekg/dns"
	"github.com/pion/dtls/v3"
)

// startDTLSServer binds UDP sockets and starts DTLS listeners for DNS-over-DTLS.
func (s *Server) startDTLSServer() error {
	addrs, err := zdnsutil.ResolveBindAddrs("udp", s.cfg.DTLSPort)
	if err != nil {
		return err
	}

	log.Infof("TLS: DTLS server started on %v", addrs)
	for _, addr := range addrs {
		udpAddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			return err
		}

		listener, err := dtls.ListenWithOptions("udp", udpAddr,
			dtls.WithCertificates(s.stdCert),
			dtls.WithSessionStore(lrumap.NewDTLSSessionStore(config.DefaultDTLSSessionCacheSize)),
			dtls.WithVerifyConnection(func(state *dtls.State) error {
				zdnsutil.LogHandshake(&zdnsutil.HandshakeInfo{
					Role:       "TLS",
					Direction:  "DTLS handshake from",
					RemoteAddr: "client",
					Cipher:     dtls.CipherSuiteName(state.CipherSuiteID),
				})
				return nil
			}),
		)
		if err != nil {
			return err
		}

		s.dtlsListeners = append(s.dtlsListeners, listener)
		s.serverGroup.Go(func() error {
			defer zdnsutil.HandlePanic("DTLS server")
			s.handleDTLSConnections(listener)
			return nil
		})
	}
	return nil
}

// handleDTLSConnections accepts DTLS connections and dispatches them to
// per-connection handlers.
func (s *Server) handleDTLSConnections(listener net.Listener) {
	defer zdnsutil.HandlePanic("DTLS accept loop")

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-s.ctx.Done():
				return
			default:
				if zdnsutil.IsTemporaryError(err) {
					log.Debugf("TLS: DTLS accept temporary error: %v", err)
					continue
				}
				log.Errorf("TLS: DTLS accept error: %v", err)
				return
			}
		}

		s.serverGroup.Go(func() error {
			defer zdnsutil.HandlePanic("DTLS connection")
			s.handleDTLSConnection(conn)
			return nil
		})
	}
}

// handleDTLSConnection reads DNS-over-DTLS queries (RFC 8094).  Each DTLS
// record carries one framed DNS message: a 2-byte big-endian length prefix
// followed by the DNS payload.  pion/dtls requires reading the full DTLS
// record in a single Read() call — partial reads fail.
func (s *Server) handleDTLSConnection(conn net.Conn) {
	defer zdnsutil.CloseWithLog(conn, "DTLS connection", "TLS")

	var clientIP net.IP
	if addr, ok := conn.RemoteAddr().(*net.UDPAddr); ok {
		clientIP = addr.IP
	}

	idleTimeout := config.DefaultDTLSIdleTimeout
	buf := pool.DefaultBuffer.Get()
	defer pool.DefaultBuffer.Put(buf)

	for {
		// Set read deadline for idle timeout (RFC 8094 §3.3).  When the
		// deadline fires, Read returns a timeout error and the connection
		// is closed.  pion/dtls sends a fatal alert on close.
		if err := conn.SetReadDeadline(time.Now().Add(idleTimeout)); err != nil {
			log.Debugf("TLS: DTLS SetReadDeadline error: %v", err)
			continue
		}

		n, err := conn.Read(buf)
		if err != nil {
			// Idle timeout — close connection per RFC 8094 §3.3 (pion/dtls
			// sends a fatal alert on close).  Do NOT treat timeouts as
			// temporary — that would keep idle connections alive forever.
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				return
			}
			if !zdnsutil.IsTemporaryError(err) {
				return
			}
			continue
		}

		// Parse 2-byte length prefix (TCP DNS framing, RFC 1035 §4.2.2).
		// DTLS records provide datagram boundaries — the inner prefix
		// mirrors DoT framing and is not required by RFC 8094.
		if n < zdnsutil.DNSFramePrefixLen {
			continue
		}
		msgLen := binary.BigEndian.Uint16(buf[:zdnsutil.DNSFramePrefixLen])
		if int(msgLen)+zdnsutil.DNSFramePrefixLen > n {
			log.Debugf("TLS: DTLS short read: want %d + 2, got %d", msgLen, n)
			continue
		}

		query := pool.DefaultMessage.Get()
		query.Data = buf[zdnsutil.DNSFramePrefixLen : zdnsutil.DNSFramePrefixLen+msgLen]
		if err := query.Unpack(); err != nil {
			log.Debugf("TLS: DTLS unpack error: %v", err)
			pool.DefaultMessage.Put(query)
			continue
		}

		response := s.handler.ServeDNS(query, clientIP, true, config.ProtoDTLS)
		pool.DefaultMessage.Put(query)
		if !s.sendDTLSResponse(conn, response) {
			return
		}
	}
}

// sendDTLSResponse packs and writes a DTLS response with 2-byte length prefix.
// Returns true to continue the connection loop, false to close the connection.
// The response is always returned to the pool (defer-protected).
func (s *Server) sendDTLSResponse(conn net.Conn, response *dns.Msg) bool {
	if response == nil {
		return true
	}
	defer pool.DefaultMessage.Put(response)

	if err := response.Pack(); err != nil {
		log.Debugf("TLS: DTLS pack error: %v", err)
		return true
	}

	respLen := len(response.Data)
	if respLen > config.MaxDNSMessageSize {
		log.Debugf("TLS: DTLS response too large (%d bytes)", respLen)
		return true
	}
	resp := make([]byte, zdnsutil.DNSFramePrefixLen+respLen)
	binary.BigEndian.PutUint16(resp[:zdnsutil.DNSFramePrefixLen], uint16(respLen)) //nolint:gosec // G115: DNS response length bounded by MaxDNSMessageSize
	copy(resp[zdnsutil.DNSFramePrefixLen:], response.Data)

	if _, err := conn.Write(resp); err != nil {
		log.Debugf("TLS: DTLS write error: %v", err)
		return false
	}
	return true
}
