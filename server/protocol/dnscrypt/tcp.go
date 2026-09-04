package dnscrypt

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"time"
	"zjdns/config"
	dnscryptcrypto "zjdns/internal/dnscryptcrypto"
	"zjdns/internal/log"

	zdnsutil "zjdns/internal/dnsutil"

	"codeberg.org/miekg/dns"
)

// tcpResponseWriter writes DNSCrypt-encrypted responses over TCP.
type tcpResponseWriter struct {
	conn    net.Conn
	req     *dns.Msg
	query   *dnscryptcrypto.EncryptedQuery
	encrypt func(m *dns.Msg, q *dnscryptcrypto.EncryptedQuery, isUDP bool) ([]byte, error)
}

const (
	defaultReadTimeout  = config.DefaultDNSCryptReadTimeout
	defaultWriteTimeout = config.DefaultDNSCryptWriteTimeout
)

func (w *tcpResponseWriter) LocalAddr() net.Addr  { return w.conn.LocalAddr() }
func (w *tcpResponseWriter) RemoteAddr() net.Addr { return w.conn.RemoteAddr() }

func (w *tcpResponseWriter) WriteMsg(_ context.Context, m *dns.Msg) error {
	dnscryptcrypto.Normalize("tcp", w.req, m, 0)
	res, err := w.encrypt(m, w.query, false)
	if err != nil {
		return fmt.Errorf("encrypting response: %w", err)
	}
	// A client that stops reading must not block this goroutine forever.
	if err := w.conn.SetWriteDeadline(time.Now().Add(defaultWriteTimeout)); err != nil {
		return fmt.Errorf("setting write deadline: %w", err)
	}
	return dnscryptcrypto.WritePrefixed(res, w.conn)
}

// serveTCP listens for and handles DNSCrypt TCP connections.  It blocks until
// the server context is cancelled or the listener is closed.
func (s *Server) serveTCP(ctx context.Context, listener net.Listener) {
	defer zdnsutil.HandlePanic("DNSCrypt TCP server")

	// Add under s.mu: Shutdown swaps s.wg under the same lock (R3-M2).
	s.mu.Lock()
	s.wg.Add(1)
	s.mu.Unlock()
	defer s.wg.Done()

	for s.isStarted() {
		select {
		case <-ctx.Done():
			return
		default:
		}

		conn, err := listener.Accept()
		if err != nil {
			if !s.isStarted() {
				return
			}
			if !zdnsutil.IsTemporaryError(err) {
				// Non-temporary accept errors (EMFILE etc.) are usually
				// transient resource conditions — returning here would take
				// the whole TCP listener down permanently with only a Debug
				// line. Back off and keep serving, like the TLS listeners.
				log.Warnf("DNSCRYPT: TCP accept error: %v — retrying", err)
				time.Sleep(config.DefaultAcceptRetryDelay)
				continue
			}
			// Temporary error: back off too, or a sustained condition spins
			// at 100% CPU (all other accept loops sleep on retry).
			time.Sleep(config.DefaultAcceptRetryDelay)
			continue
		}

		// Track the connection for graceful shutdown.
		s.mu.Lock()
		s.tcpConns[conn] = struct{}{}
		s.mu.Unlock()

		select {
		case s.workerCap <- struct{}{}:
		default:
			// Drop the connection instead of spawning unbounded goroutines.
			_ = conn.Close()
			s.mu.Lock()
			delete(s.tcpConns, conn)
			s.mu.Unlock()
			continue
		}

		// wg.Go must run under s.mu: Shutdown swaps s.wg under the same lock
		// (server.go) and then Waits on the previous group. Adding under the
		// lock guarantees Add either joins the waited group or the fresh
		// (cancelled) one — never an Add-during-Wait on the swapped-out group.
		s.mu.Lock()
		s.wg.Go(func() {
			defer zdnsutil.HandlePanic("DNSCrypt TCP handler")
			defer func() { <-s.workerCap }()
			defer func() {
				_ = conn.Close()
				s.mu.Lock()
				delete(s.tcpConns, conn)
				s.mu.Unlock()
			}()
			s.handleTCPConnection(ctx, conn)
		})
		s.mu.Unlock()
	}
}

// HandleSharedTCPConn processes a single TCP connection received via a
// shared-port listener.  conn already includes the demux-buffered prefix
// bytes (replayed via bufferedConn).  This is the shared-port counterpart
// of the per-connection logic inside serveTCP.
func (s *Server) HandleSharedTCPConn(ctx context.Context, conn net.Conn) {
	if !s.isStarted() {
		_ = conn.Close()
		return
	}

	s.mu.Lock()
	s.tcpConns[conn] = struct{}{}
	s.mu.Unlock()

	select {
	case s.workerCap <- struct{}{}:
	default:
		_ = conn.Close()
		s.mu.Lock()
		delete(s.tcpConns, conn)
		s.mu.Unlock()
		return
	}

	s.mu.Lock()
	s.wg.Go(func() {
		defer zdnsutil.HandlePanic("Shared DNSCrypt TCP handler")
		defer func() { <-s.workerCap }()
		defer func() {
			_ = conn.Close()
			s.mu.Lock()
			delete(s.tcpConns, conn)
			s.mu.Unlock()
		}()
		s.handleTCPConnection(ctx, conn)
	})
	s.mu.Unlock()
}

// handleTCPConnection processes queries on a TCP connection until the peer
// closes it or a read error occurs.  The connection persists across queries
// (RFC 7766 §4 — the DNSCrypt draft leaves connection lifetime unspecified;
// §5.4.4 only specifies the framing).  Reuse amortises the per-query
// connect + handshake that the pooled DNSCrypt TCP client depends on.
func (s *Server) handleTCPConnection(ctx context.Context, conn net.Conn) {
	for {
		// Re-arm the read deadline per frame: an idle-but-open connection
		// must not die between queries, and a peer that sends nothing must
		// not occupy the worker slot indefinitely.
		if err := conn.SetReadDeadline(time.Now().Add(defaultReadTimeout)); err != nil {
			log.Debugf("DNSCRYPT: setting TCP read deadline for %s: %v", conn.RemoteAddr(), err)
			return
		}

		b, err := dnscryptcrypto.ReadPrefixed(conn)
		if err != nil {
			if !s.isStarted() {
				return
			}
			log.Debugf("DNSCRYPT: TCP read error from %s: %v", conn.RemoteAddr(), err)
			return
		}

		// A message-level error (malformed frame) leaves the stream suspect —
		// close the connection rather than continuing to read from it.
		if err := s.handleTCPMsg(ctx, b, conn); err != nil {
			log.Debugf("DNSCRYPT: TCP message handling error: %v", err)
			return
		}
	}
}

// handleTCPMsg processes a single TCP-framed message.
func (s *Server) handleTCPMsg(ctx context.Context, b []byte, conn net.Conn) error {
	if len(b) < dnscryptcrypto.MinDNSPacketSize {
		return dnscryptcrypto.ErrTooShort
	}

	// dnscryptcrypto.Certificate handshake or encrypted query?
	if !s.hasClientMagic(b[:dnscryptcrypto.ClientMagicSize]) && !bytes.Equal(b[:dnscryptcrypto.PQResumeMagicLen], dnscryptcrypto.PQResumeMagic[:]) {
		reply, err := s.handleHandshake(b, false)
		if err != nil {
			return fmt.Errorf("handshake: %w", err)
		}
		log.Debugf("DNSCRYPT: TCP handshake response sent to %s", conn.RemoteAddr())
		return dnscryptcrypto.WritePrefixed(reply, conn)
	}

	// Decrypt the query.
	m, q, err := s.decrypt(b)
	if err != nil {
		return fmt.Errorf("decrypting TCP query: %w", err)
	}
	log.Debugf("DNSCRYPT: decrypted TCP query from %s", conn.RemoteAddr())

	rw := &tcpResponseWriter{
		conn:    conn,
		req:     m,
		query:   q,
		encrypt: s.encrypt,
	}
	return s.serveDNS(ctx, rw, m, config.ProtoDNSCryptTCP)
}
