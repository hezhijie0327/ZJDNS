package socks5

import (
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
)

// minimalSOCKSServer is a tiny SOCKS5 proxy that supports no-auth TCP
// CONNECT and UDP ASSOCIATE.  UDP packets are echoed back to the sender,
// verifying that each ListenPacket call gets an independent relay and that
// closing one does not affect others.
type minimalSOCKSServer struct {
	listener net.Listener
	wg       sync.WaitGroup
	mu       sync.Mutex
	relays   []io.Closer // UDP relay sockets to close on shutdown
}

func startSOCKSServer(t *testing.T) (addr string, shutdown func()) {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	srv := &minimalSOCKSServer{listener: l}
	srv.wg.Go(func() {
		srv.serve()
	})

	return l.Addr().String(), func() {
		_ = l.Close()
		srv.mu.Lock()
		for _, r := range srv.relays {
			_ = r.Close()
		}
		srv.mu.Unlock()
		srv.wg.Wait()
	}
}

func (s *minimalSOCKSServer) serve() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		s.wg.Go(func() {
			s.handle(conn)
		})
	}
}

func (s *minimalSOCKSServer) handle(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	buf := make([]byte, 263)

	// Handshake — no auth
	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return
	}
	if buf[0] != 0x05 {
		return
	}
	nmethods := int(buf[1])
	if nmethods > 0 {
		if _, err := io.ReadFull(conn, buf[:nmethods]); err != nil {
			return
		}
	}
	_, _ = conn.Write([]byte{0x05, 0x00})

	// Request
	if _, err := io.ReadFull(conn, buf[:4]); err != nil {
		return
	}
	cmd := buf[1]
	atyp := buf[3]

	// Skip dst addr + port
	var skipLen int
	switch atyp {
	case 0x01:
		skipLen = 6 // 4 bytes IPv4 + 2 bytes port
	case 0x03:
		if _, err := io.ReadFull(conn, buf[4:5]); err != nil {
			return
		}
		skipLen = 1 + int(buf[4]) + 2 // 1 len + domain + 2 port
	default:
		s.reply(conn, 0x08)
		return
	}
	if _, err := io.ReadFull(conn, buf[4:4+skipLen]); err != nil {
		return
	}

	switch cmd {
	case 0x01:
		s.reply(conn, 0x00)
	case 0x03:
		s.handleUDP(conn)
	default:
		s.reply(conn, 0x07)
	}
}

func (s *minimalSOCKSServer) reply(conn net.Conn, rep byte) {
	_, _ = conn.Write([]byte{0x05, rep, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01, 0x00, 0x00})
}

func (s *minimalSOCKSServer) handleUDP(ctrlConn net.Conn) {
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		s.reply(ctrlConn, 0x01)
		return
	}

	// Track the relay so shutdown can close it.
	s.mu.Lock()
	s.relays = append(s.relays, udpConn)
	s.mu.Unlock()
	defer func() { _ = udpConn.Close() }()

	// Reply with the relay's bound address.
	relayAddr := udpConn.LocalAddr().(*net.UDPAddr)
	r := make([]byte, 10)
	r[0], r[1], r[2], r[3] = 0x05, 0x00, 0x00, 0x01
	copy(r[4:8], relayAddr.IP.To4())
	binary.BigEndian.PutUint16(r[8:10], uint16(relayAddr.Port)) //nolint:gosec // G115: port fits uint16
	if _, err := ctrlConn.Write(r); err != nil {
		return
	}

	// Echo loop: read a datagram, send it back.
	buf := make([]byte, 65535)
	for {
		n, addr, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if n >= 10 {
			buf[0], buf[1] = 0x00, 0x00
			buf[2] = 0x00
			_, _ = udpConn.WriteTo(buf[:n], addr)
		}
	}
}
