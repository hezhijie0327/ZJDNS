package tls

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"time"
	"zjdns/config"
	zdnsutil "zjdns/internal/dnsutil"
	"zjdns/internal/log"
	"zjdns/internal/lrumap"
	"zjdns/internal/pool"

	"codeberg.org/miekg/dns"
	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/protocol"
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

		listener, err := dtls.ListenAddr("udp", udpAddr,
			// DTLS 1.3 only.  A dual-stack server [1.2,1.3] still deadlocks
			// against a dual-stack client (i.e. our own upstream client) in
			// pion v3.1.3-0.20260829132121: the server's DTLS 1.3 Flight 0
			// cannot complete its HelloRetryRequest exchange with a client
			// that is still in version negotiation — server spins re-sending,
			// client waits, handshake times out. The 1.3-only server path
			// (prepareHandshakeStart13, no version negotiation) completes the
			// 1.3 handshake with dual-stack clients fine, so we stay
			// 1.3-only. Re-verified 2026-08-29 with ZJDNS loopback E2E:
			// dual server works with {pure-1.2, pure-1.3} clients (1.2
			// negotiation was fixed upstream since v3.1.3-0.20260821014627)
			// but still deadlocks with dual-stack clients — and our upstream
			// client is dual-stack per RFC 9147 §4.2.2, so a dual-stack
			// server would break ZJDNS-to-ZJDNS DTLS. Revisit when pion
			// fixes the dual-stack server HRR path.
			dtls.WithMinVersion(protocol.Version1_3),
			dtls.WithMaxVersion(protocol.Version1_3),
			dtls.WithCertificates(s.stdCert),
			dtls.WithSessionStore(lrumap.NewDTLSSessionStore(config.DefaultDTLSSessionCacheSize)),
			dtls.WithVerifyConnection(func(state *dtls.State) error {
				zdnsutil.LogHandshake(&zdnsutil.HandshakeInfo{
					Role:       "TLS",
					Direction:  "DTLS handshake from",
					RemoteAddr: "client",
					Cipher:     state.CipherSuiteID.String(),
				})
				return nil
			}),
		)
		if err != nil {
			return err
		}

		s.listenerMu.Lock()
		s.dtlsListeners = append(s.dtlsListeners, listener)
		s.listenerMu.Unlock()
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
				// Back off like every other accept loop (tls.go, quic.go,
				// tlcp.go, dnscrypt): a sustained temporary failure (EMFILE,
				// ENOBUFS) would otherwise spin this loop at 100% CPU.
				if zdnsutil.IsTemporaryError(err) {
					log.Debugf("TLS: DTLS accept temporary error: %v", err)
				} else {
					log.Warnf("TLS: DTLS accept error: %v", err)
				}
				time.Sleep(config.DefaultAcceptRetryDelay)
				continue
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
			if errors.Is(err, io.ErrShortBuffer) {
				// pion/dtls does not consume the oversized record — Read
				// returns ErrShortBuffer on every retry, and the re-armed
				// deadline made this loop spin at 100% CPU forever.  A
				// record larger than the buffer from a handshaked client is
				// a protocol violation: close the connection (H4).
				log.Debugf("TLS: closing DTLS connection: record too large for buffer from %s", conn.RemoteAddr())
				return
			}
			// A read-deadline expiry means the peer went idle — close the
			// connection instead of retrying forever (the deadline error
			// is classified as temporary by IsTemporaryError, and without
			// this check the loop re-armed the deadline and spun, holding
			// an errgroup slot per zombie connection).
			if ne, ok := errors.AsType[net.Error](err); ok && ne.Timeout() {
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

		// Sequential Put per loop iteration (defer would accumulate every
		// query until the connection closes — the per-connection loop is
		// not a single-request scope, AUDIT-METHODOLOGY §6.1.1).
		response := s.handler.ServeDNS(query, clientIP, true, config.ProtoDTLS)
		if response == query { //nolint:revive // identity guard: ServeDNS must never return the request (L5)
			response = nil
		}
		pool.DefaultMessage.Put(query)
		if !s.sendDTLSResponse(conn, response) {
			return
		}
	}
}

// sendDTLSResponse packs and writes a DTLS response with 2-byte length prefix.
// Returns true to continue the connection loop, false to close the connection.
// The response is always returned to the pool (defer-protected).  The frame
// path (PMTU truncation preserving the trailing OPT per RFC 6891 §6.2.5,
// pooled frame buffer) is the shared dnsutil.WriteDTLSFrame — the DTLCP
// twin previously carried a 95 %-identical copy that destroyed the OPT on
// truncation and allocated per response (P-M4).
func (s *Server) sendDTLSResponse(conn net.Conn, response *dns.Msg) bool {
	if response == nil {
		return true
	}
	defer pool.DefaultMessage.Put(response)

	safeMax := config.DefaultPMTU - config.DTLSDNSOverhead - zdnsutil.DNSFramePrefixLen
	return zdnsutil.WriteDTLSFrame(conn, response, safeMax, config.MaxDNSMessageSize, "TLS: DTLS")
}
