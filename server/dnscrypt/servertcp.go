package dnscrypt

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"time"
	"zjdns/config"
	"zjdns/internal/log"

	zdnsutil "zjdns/internal/dnsutil"

	"codeberg.org/miekg/dns"
)

type tcpResponseWriter struct {
	conn    net.Conn
	req     *dns.Msg
	query   *encryptedQuery
	encrypt func(m *dns.Msg, q *encryptedQuery, isUDP bool) ([]byte, error)
}

const (
	defaultReadTimeout = config.DefaultDNSCryptReadTimeout
)

// tcpResponseWriter writes DNSCrypt-encrypted responses over TCP.

func (w *tcpResponseWriter) LocalAddr() net.Addr  { return w.conn.LocalAddr() }
func (w *tcpResponseWriter) RemoteAddr() net.Addr { return w.conn.RemoteAddr() }

func (w *tcpResponseWriter) WriteMsg(_ context.Context, m *dns.Msg) error {
	normalize("tcp", w.req, m)
	res, err := w.encrypt(m, w.query, false)
	if err != nil {
		return fmt.Errorf("encrypting response: %w", err)
	}
	return writePrefixed(res, w.conn)
}

// serveTCP listens for and handles DNSCrypt TCP connections.  It blocks until
// the server context is cancelled or the listener is closed.
func (s *Server) serveTCP(ctx context.Context, listener net.Listener) {
	defer zdnsutil.HandlePanic("DNSCrypt TCP server")

	s.wg.Add(1)
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
			if zdnsutil.IsTemporaryError(err) {
				continue
			}
			log.Debugf("DNSCRYPT: TCP accept error: %v", err)
			return
		}

		// Track the connection for graceful shutdown.
		s.mu.Lock()
		s.tcpConns[conn] = struct{}{}
		s.mu.Unlock()

		s.wg.Go(func() {
			defer zdnsutil.HandlePanic("DNSCrypt TCP handler")
			defer func() {
				_ = conn.Close()
				s.mu.Lock()
				delete(s.tcpConns, conn)
				s.mu.Unlock()
			}()
			s.handleTCPConnection(ctx, conn)
		})
	}
}

// handleTCPConnection processes a single query on a TCP connection and then
// returns, causing the connection to be closed.  This matches the reference
// implementation (encrypted-dns-server) and draft-denis-dprive-dnscrypt-10
// §5.4.4, which prohibits multiple transactions over the same connection.
func (s *Server) handleTCPConnection(ctx context.Context, conn net.Conn) {
	_ = conn.SetReadDeadline(time.Now().Add(defaultReadTimeout))

	b, err := readPrefixed(conn)
	if err != nil {
		if !s.isStarted() {
			return
		}
		log.Debugf("DNSCRYPT: TCP read error from %s: %v", conn.RemoteAddr(), err)
		return
	}

	if err := s.handleTCPMsg(ctx, b, conn); err != nil {
		log.Debugf("DNSCRYPT: TCP message handling error: %v", err)
	}
}

// handleTCPMsg processes a single TCP-framed message.
func (s *Server) handleTCPMsg(ctx context.Context, b []byte, conn net.Conn) error {
	if len(b) < minDNSPacketSize {
		return ErrTooShort
	}

	// Certificate handshake or encrypted query?
	if !s.hasClientMagic(b[:ClientMagicSize]) && (!s.esVersion.IsPQ() || len(b) < PQResumeMagicLen || !bytes.Equal(b[:PQResumeMagicLen], PQResumeMagic[:])) {
		reply, err := s.handleHandshake(b)
		if err != nil {
			return fmt.Errorf("handshake: %w", err)
		}
		log.Debugf("DNSCRYPT: TCP handshake response sent to %s", conn.RemoteAddr())
		return writePrefixed(reply, conn)
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
