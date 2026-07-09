package dnscrypt

import (
	"bytes"
	"context"
	"net"
	"runtime"
	"time"
	"zjdns/config"
	"zjdns/internal/log"

	zdnsutil "zjdns/internal/dnsutil"

	"codeberg.org/miekg/dns"
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
	query   *encryptedQuery
	encrypt func(m *dns.Msg, q *encryptedQuery, isUDP bool) ([]byte, error)
}

func (w *udpResponseWriter) LocalAddr() net.Addr  { return w.conn.LocalAddr() }
func (w *udpResponseWriter) RemoteAddr() net.Addr { return w.addr }

func (w *udpResponseWriter) WriteMsg(_ context.Context, m *dns.Msg) error {
	normalize("udp", w.req, m)
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

	s.wg.Add(1)
	defer s.wg.Done()

	log.Infof("DNSCRYPT: entering UDP listening loop on %s", udpConn.LocalAddr())

	buf := make([]byte, dns.MaxMsgSize)

	for s.isStarted() {
		_ = udpConn.SetReadDeadline(time.Now().Add(defaultReadTimeout))

		n, addr, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			if !s.isStarted() {
				return
			}
			if isTemporaryNetError(err) {
				continue
			}
			log.Debugf("DNSCRYPT: UDP read error: %v", err)
			return
		}

		if n < minDNSPacketSize {
			continue
		}

		packet := make([]byte, n)
		copy(packet, buf[:n])

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer zdnsutil.HandlePanic("DNSCrypt UDP handler")
			s.handleUDPPacket(ctx, packet, addr, udpConn)
		}()
	}
}

// handleUDPPacket processes a single UDP datagram.
func (s *Server) handleUDPPacket(ctx context.Context, b []byte, addr *net.UDPAddr, udpConn *net.UDPConn) {
	if !bytes.Equal(b[:ClientMagicSize], s.cert.ClientMagic[:]) && (s.esVersion.IsPQ() && len(b) >= PQResumeMagicLen && !bytes.Equal(b[:PQResumeMagicLen], PQResumeMagic[:])) {
		reply, err := s.handleHandshake(b)
		if err != nil {
			log.Debugf("DNSCRYPT: handshake failed: %v", err)
			return
		}
		_, _ = udpConn.WriteToUDP(reply, addr)
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
