package dnscrypt

import (
	"bytes"
	"context"
	"net"
	"runtime"
	"time"
	"zjdns/config"
	dnscryptcrypto "zjdns/internal/dnscryptcrypto"
	"zjdns/internal/log"
	"zjdns/internal/pool"

	zdnsutil "zjdns/internal/dnsutil"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// responseWriter is the interface for writing encrypted responses.
type responseWriter interface {
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
	WriteMsg(ctx context.Context, m *dns.Msg) error
}

// udpResponseWriter writes DNSCrypt-encrypted responses over UDP.
type udpResponseWriter struct {
	conn    *net.UDPConn
	addr    *net.UDPAddr
	req     *dns.Msg
	query   *dnscryptcrypto.EncryptedQuery
	encrypt func(m *dns.Msg, q *dnscryptcrypto.EncryptedQuery, isUDP bool) ([]byte, error)
}

func (w *udpResponseWriter) LocalAddr() net.Addr  { return w.conn.LocalAddr() }
func (w *udpResponseWriter) RemoteAddr() net.Addr { return w.addr }

func (w *udpResponseWriter) WriteMsg(_ context.Context, m *dns.Msg) error {
	dnscryptcrypto.Normalize("udp", w.req, m, w.query.ClientQueryLen)
	res, err := w.encrypt(m, w.query, true)
	if err != nil {
		return err
	}
	_, err = w.conn.WriteToUDP(res, w.addr)
	return err
}

// serveUDP reads and handles DNSCrypt UDP messages.
func (s *Server) serveUDP(ctx context.Context, udpConn *net.UDPConn) {
	defer zdnsutil.HandlePanic("DNSCrypt UDP server")

	if err := setUDPSocketOptions(udpConn); err != nil {
		log.Warnf("DNSCRYPT: Failed to configure UDP socket: %v", err)
	}

	// Add under s.mu: Shutdown swaps s.wg under the same lock, so Add either
	// joins the waited group or the fresh (cancelled) one — never races the
	// previous group's Wait (R3-M2, same discipline as the wg.Go calls below).
	s.mu.Lock()
	s.wg.Add(1)
	s.mu.Unlock()
	defer s.wg.Done()

	buf := pool.DefaultBuffer.Get()
	// Single deferred Put covers every exit path, including panics recovered
	// by HandlePanic — per-path Puts leak the pooled buffer on panic.
	defer func() { pool.DefaultBuffer.Put(buf) }()

	for s.isStarted() {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if err := udpConn.SetReadDeadline(time.Now().Add(defaultReadTimeout)); err != nil {
			log.Debugf("DNSCRYPT: UDP SetReadDeadline error: %v", err)
		}

		n, addr, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			if !s.isStarted() {
				return
			}
			if zdnsutil.IsTemporaryError(err) {
				continue
			}
			log.Debugf("DNSCRYPT: UDP read error: %v", err)
			return
		}

		if n < dnscryptcrypto.MinDNSPacketSize {
			continue
		}

		// Transfer buffer ownership to the handler goroutine and obtain
		// a fresh buffer for the next read iteration.  The goroutine
		// returns the buffer to the pool via defer.
		packet := buf[:n]
		buf = pool.DefaultBuffer.Get()

		select {
		case s.workerCap <- struct{}{}:
		default:
			// Worker pool saturated: process cheap work inline instead of
			// silently dropping — a drop makes the client wait out its full
			// query timeout, multiplying load.  A cert handshake is fast (no
			// middleware chain); an encrypted query gets a SERVFAIL so the
			// client recovers in one RTT.
			s.handleSaturated(ctx, packet, addr, udpConn)
			pool.DefaultBuffer.Put(packet)
			continue
		}

		// wg.Go must run under s.mu: Shutdown swaps s.wg under the same lock
		// (server.go) and then Waits on the previous group. Adding under the
		// lock guarantees Add either joins the waited group or the fresh
		// (cancelled) one — never an Add-during-Wait on the swapped-out group.
		s.mu.Lock()
		s.wg.Go(func() {
			defer zdnsutil.HandlePanic("DNSCrypt UDP handler")
			defer pool.DefaultBuffer.Put(packet)
			defer func() { <-s.workerCap }()
			s.handleUDPPacket(ctx, packet, addr, udpConn)
		})
		s.mu.Unlock()
	}
}

// handleSaturated processes a packet inline in the read loop when the worker
// pool is at capacity.  It must not block meaningfully: decryption is fast
// (shared-key cache) and the middleware chain is never invoked — the query is
// answered SERVFAIL, the handshake served from the current cert window.
func (s *Server) handleSaturated(ctx context.Context, b []byte, addr *net.UDPAddr, udpConn *net.UDPConn) {
	if !s.hasClientMagic(b[:dnscryptcrypto.ClientMagicSize]) && !bytes.Equal(b[:dnscryptcrypto.PQResumeMagicLen], dnscryptcrypto.PQResumeMagic[:]) {
		// Certificate handshake — cheap, serve it (dropping on anti-
		// amplification violation: the client retries over TCP).
		reply, err := s.handleHandshake(b, true)
		if err != nil {
			log.Debugf("DNSCRYPT: saturated handshake failed: %v", err)
			return
		}
		if len(reply) <= len(b) {
			if _, err := udpConn.WriteToUDP(reply, addr); err != nil {
				log.Debugf("DNSCRYPT: UDP write error to %s: %v", addr, err)
			}
		}
		return
	}

	m, q, err := s.decrypt(b)
	if err != nil {
		return
	}
	resp := &dns.Msg{}
	dnsutil.SetReply(resp, m)
	resp.Rcode = dns.RcodeServerFailure
	rw := &udpResponseWriter{
		conn:    udpConn,
		addr:    addr,
		req:     m,
		query:   q,
		encrypt: s.encrypt,
	}
	if err := rw.WriteMsg(ctx, resp); err != nil {
		log.Debugf("DNSCRYPT: overload SERVFAIL write error to %s: %v", addr, err)
	}
}

// handleUDPPacket processes a single UDP datagram.
func (s *Server) handleUDPPacket(ctx context.Context, b []byte, addr *net.UDPAddr, udpConn *net.UDPConn) {
	if !s.hasClientMagic(b[:dnscryptcrypto.ClientMagicSize]) && !bytes.Equal(b[:dnscryptcrypto.PQResumeMagicLen], dnscryptcrypto.PQResumeMagic[:]) {
		reply, err := s.handleHandshake(b, true)
		if err != nil {
			log.Debugf("DNSCRYPT: handshake failed: %v", err)
			return
		}
		// §10.3 anti-amplification: over UDP, a certificate response MUST NOT
		// be larger than the request.  If it is, set the TC flag to prompt the
		// client to retry over TCP.
		if len(reply) > len(b) {
			origLen := len(reply)
			truncated := &dns.Msg{}
			truncated.Data = reply
			if unpackErr := truncated.Unpack(); unpackErr == nil {
				dnsutil.Truncate(truncated)
				if packErr := truncated.Pack(); packErr == nil && len(truncated.Data) <= len(b) {
					reply = truncated.Data
				} else {
					// Truncation cannot shrink the response to fit the
					// request — send nothing rather than violate the §10.3
					// anti-amplification guarantee.
					log.Debugf("DNSCRYPT: dropping UDP cert response (%d bytes) for %d-byte request", origLen, len(b))
					return
				}
			} else {
				log.Debugf("DNSCRYPT: dropping unparseable UDP cert response: %v", unpackErr)
				return
			}
			log.Debugf("DNSCRYPT: UDP cert response (%d bytes) exceeds request (%d bytes) — returning TC", origLen, len(b))
		}
		if _, err := udpConn.WriteToUDP(reply, addr); err != nil {
			log.Debugf("DNSCRYPT: UDP write error to %s: %v", addr, err)
		}
		log.Debugf("DNSCRYPT: UDP handshake response sent to %s", addr)
		return
	}

	m, q, err := s.decrypt(b)
	if err != nil {
		log.Debugf("DNSCRYPT: failed to decrypt UDP query: %v", err)
		return
	}
	log.Debugf("DNSCRYPT: decrypted UDP query from %s", addr)

	rw := &udpResponseWriter{
		conn:    udpConn,
		addr:    addr,
		req:     m,
		query:   q,
		encrypt: s.encrypt,
	}
	if err := s.serveDNS(ctx, rw, m, config.ProtoDNSCrypt); err != nil {
		log.Debugf("DNSCRYPT: serveDNS UDP error: %v", err)
	}
}

// setUDPSocketOptions configures the UDP socket for reading packet info.
func setUDPSocketOptions(conn *net.UDPConn) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	err6 := ipv6.NewPacketConn(conn).SetControlMessage(ipv6.FlagDst|ipv6.FlagInterface, true)
	err4 := ipv4.NewPacketConn(conn).SetControlMessage(ipv4.FlagDst|ipv4.FlagInterface, true)
	if err6 != nil && err4 != nil {
		return err4
	}
	return nil
}
