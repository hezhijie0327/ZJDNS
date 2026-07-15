package tls

import (
	"encoding/binary"
	"net"
	"time"
	"zjdns/config"
	zdnsutil "zjdns/internal/dnsutil"
	"zjdns/internal/log"
	"zjdns/internal/pool"

	"github.com/pion/dtls/v3"
)

// startDTLSServer binds UDP sockets and starts DTLS listeners for DNS-over-DTLS.
func (s *Server) startDTLSServer() error {
	addrs, err := zdnsutil.ResolveBindAddrs("udp", s.cfg.DTLSPort)
	if err != nil {
		return err
	}

	for _, addr := range addrs {
		udpAddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			return err
		}

		listener, err := dtls.ListenWithOptions("udp", udpAddr,
			dtls.WithCertificates(s.stdCert),
		)
		if err != nil {
			return err
		}

		s.dtlsListeners = append(s.dtlsListeners, listener)
		go s.handleDTLSConnections(listener)
		log.Infof("TLS: DTLS server started on %s", addr)
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
				if isTemporaryError(err) {
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
	buf := make([]byte, pool.UDPBufferSize)

	for {
		// Set read deadline for idle timeout (RFC 8094 §3.3).  When the
		// deadline fires, Read returns a timeout error and the connection
		// is closed.  pion/dtls sends a fatal alert on close.
		if err := conn.SetReadDeadline(time.Now().Add(idleTimeout)); err != nil {
			return
		}

		n, err := conn.Read(buf)
		if err != nil {
			if !isTemporaryError(err) {
				return
			}
			continue
		}

		// Parse 2-byte length prefix (RFC 8094 §5.2).
		if n < 2 {
			continue
		}
		msgLen := binary.BigEndian.Uint16(buf[:2])
		if int(msgLen)+2 > n {
			log.Debugf("TLS: DTLS short read: want %d + 2, got %d", msgLen, n)
			continue
		}

		query := pool.DefaultMessagePool.Get()
		query.Data = buf[2 : 2+msgLen]
		if err := query.Unpack(); err != nil {
			log.Debugf("TLS: DTLS unpack error: %v", err)
			pool.DefaultMessagePool.Put(query)
			continue
		}

		response := s.handler.ServeDNS(query, clientIP, true, config.ProtoDTLS)
		pool.DefaultMessagePool.Put(query)

		if err := response.Pack(); err != nil {
			log.Debugf("TLS: DTLS pack error: %v", err)
			continue
		}

		// Write response with 2-byte length prefix in a single Write.
		respLen := len(response.Data)
		if respLen > 65535 {
			log.Debugf("TLS: DTLS response too large (%d bytes)", respLen)
			continue
		}
		resp := make([]byte, 2+respLen)
		binary.BigEndian.PutUint16(resp[:2], uint16(respLen))
		copy(resp[2:], response.Data)

		if _, err := conn.Write(resp); err != nil {
			log.Debugf("TLS: DTLS write error: %v", err)
			return
		}
	}
}
