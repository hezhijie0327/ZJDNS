package tlcp

import (
	"encoding/binary"
	"net"
	"sync"
	"time"
	"zjdns/config"
	zdnsutil "zjdns/internal/dnsutil"
	"zjdns/internal/log"
	"zjdns/internal/pool"

	"gitee.com/Trisia/gotlcp/dtlcp"
)

// dtlcpListener implements net.Listener over UDP.  It reads the first
// datagram from each new client, creates a dtlcp.Server Conn, and feeds the
// buffered first datagram into the handshake via a wrapper PacketConn.
type dtlcpListener struct {
	udpConn *net.UDPConn
	cfg     *dtlcp.Config
	mu      sync.Mutex
	buf     []byte
	closed  bool
	active  map[string]*dtlcp.Conn
}

// bufferedPacketConn wraps *net.UDPConn and returns a pre-buffered datagram
// on the first ReadFrom call, then falls through to the underlying UDPConn.
// This allows the dtlcp handshake to see the ClientHello that was already
// consumed by the listener's Accept path.
type bufferedPacketConn struct {
	*net.UDPConn
	buf        []byte
	remoteAddr *net.UDPAddr
	drained    bool
}

// dtlcpConnWrapper removes the connection from the listener's active map on close.
type dtlcpConnWrapper struct {
	*dtlcp.Conn
	parent *dtlcpListener
	key    string
}

func newDTLCPListener(udpConn *net.UDPConn, cfg *dtlcp.Config) *dtlcpListener {
	return &dtlcpListener{
		udpConn: udpConn,
		cfg:     cfg,
		buf:     make([]byte, pool.UDPBufferSize),
		active:  make(map[string]*dtlcp.Conn),
	}
}

func (l *dtlcpListener) Accept() (net.Conn, error) {
	packet, remoteAddr, err := l.readFirstDatagram()
	if err != nil {
		return nil, err
	}

	key := remoteAddr.String()

	dtlcpConn, err := acceptDTLCP(l.udpConn, packet, remoteAddr, l.cfg)
	if err != nil {
		log.Debugf("TLCP: DTLCP handshake error from %s: %v", key, err)
		return nil, err
	}

	l.mu.Lock()
	l.active[key] = dtlcpConn
	l.mu.Unlock()

	return &dtlcpConnWrapper{Conn: dtlcpConn, parent: l, key: key}, nil
}

func (l *dtlcpListener) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	for _, conn := range l.active {
		_ = conn.Close()
	}
	l.active = nil
	return l.udpConn.Close()
}

func (l *dtlcpListener) Addr() net.Addr {
	return l.udpConn.LocalAddr()
}

// readFirstDatagram blocks until a datagram arrives from a client that is not
// already tracked in the active set.
func (l *dtlcpListener) readFirstDatagram() ([]byte, *net.UDPAddr, error) {
	for {
		if l.closed {
			return nil, nil, net.ErrClosed
		}

		n, remoteAddr, err := l.udpConn.ReadFromUDP(l.buf)
		if err != nil {
			return nil, nil, err
		}

		l.mu.Lock()
		_, exists := l.active[remoteAddr.String()]
		l.mu.Unlock()

		if exists {
			// Packet belongs to an existing connection.  The dtlcp.Conn
			// reads directly from the shared UDP socket; discard
			// duplicates that arrive before the Conn's first read.
			continue
		}

		// First packet from a new client.
		packet := make([]byte, n)
		copy(packet, l.buf[:n])
		return packet, remoteAddr, nil
	}
}

func (b *bufferedPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	if !b.drained {
		b.drained = true
		n := copy(p, b.buf)
		return n, b.remoteAddr, nil
	}
	return b.UDPConn.ReadFrom(p)
}

// Close is a no-op to prevent dtlcp.Conn.Close() from closing the shared
// underlying UDP socket.  The socket is owned by the dtlcpListener.
func (b *bufferedPacketConn) Close() error {
	return nil
}

// acceptDTLCP feeds a pre-read first datagram through dtlcp.Server and
// completes the DTLCP handshake.  The returned Conn wraps the shared UDP
// socket via a bufferedPacketConn that returns the first datagram on the
// first ReadFrom, then falls through to the real socket.
//
// TODO: Replace with dtlcp.Listen + Accept when upstream fixes net.Listen("udp").
func acceptDTLCP(udpConn *net.UDPConn, firstPacket []byte, remoteAddr *net.UDPAddr, cfg *dtlcp.Config) (*dtlcp.Conn, error) {
	bpc := &bufferedPacketConn{
		UDPConn:    udpConn,
		buf:        firstPacket,
		remoteAddr: remoteAddr,
	}

	conn := dtlcp.Server(bpc, remoteAddr, cfg)
	if err := conn.Handshake(); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

func (w *dtlcpConnWrapper) Close() error {
	w.parent.mu.Lock()
	delete(w.parent.active, w.key)
	w.parent.mu.Unlock()
	err := w.Conn.Close()
	return err
}

// startDTLCPServer binds UDP sockets and starts DTLCP listeners for
// DNS-over-DTLCP (GM/T 0128-2023).  The wire format is identical to
// RFC 8094: a 2-byte big-endian length prefix followed by the DNS payload.
//
// dtlcp.Listen is not used because it calls net.Listen which does not support
// "udp" in Go.  Instead we create a UDP socket directly and implement a
// custom net.Listener that buffers the first datagram per client so the DTLCP
// handshake can consume it.
func (s *Server) startDTLCPServer() error {
	addrs, err := zdnsutil.ResolveBindAddrs("udp", s.dtlcpPort)
	if err != nil {
		return err
	}

	for _, addr := range addrs {
		udpAddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			return err
		}

		udpConn, err := net.ListenUDP("udp", udpAddr)
		if err != nil {
			return err
		}

		listener := newDTLCPListener(udpConn, s.dtlcpConfig)
		s.dtlcpListeners = append(s.dtlcpListeners, listener)
		go s.handleDTLCPConnections(listener)
		log.Infof("TLCP: DTLCP server started on %s", addr)
	}
	return nil
}

// handleDTLCPConnections accepts DTLCP connections and dispatches them to
// per-connection handlers.
func (s *Server) handleDTLCPConnections(listener net.Listener) {
	defer zdnsutil.HandlePanic("TLCP DTLCP accept loop")

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
					log.Debugf("TLCP: DTLCP accept temporary error: %v", err)
					continue
				}
				log.Errorf("TLCP: DTLCP accept error: %v", err)
				return
			}
		}

		// Handle synchronously — gotlcp shares the underlying UDP socket across
		// all connections. Concurrent reads cause packet stealing between Conn
		// instances and SetReadDeadline on one Conn affects the shared socket's
		// Accept loop. Until gotlcp provides per-connection socket isolation,
		// only one connection is served at a time.
		s.handleDTLCPConnection(conn)
	}
}

// handleDTLCPConnection reads DNS-over-DTLCP queries.  Each DTLCP record
// carries one framed DNS message: a 2-byte big-endian length prefix followed
// by the DNS payload, same as DNS-over-DTLS (RFC 8094 §5.2).
func (s *Server) handleDTLCPConnection(conn net.Conn) {
	defer zdnsutil.CloseWithLog(conn, "TLCP DTLCP connection", "TLCP")

	var clientIP net.IP
	if addr, ok := conn.RemoteAddr().(*net.UDPAddr); ok {
		clientIP = addr.IP
	}

	idleTimeout := config.DefaultDTLSIdleTimeout
	buf := make([]byte, pool.UDPBufferSize)

	for {
		if err := conn.SetReadDeadline(time.Now().Add(idleTimeout)); err != nil {
			return
		}

		n, err := conn.Read(buf)
		if err != nil {
			if !zdnsutil.IsTemporaryError(err) {
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
			log.Debugf("TLCP: DTLCP short read: want %d + 2, got %d", msgLen, n)
			continue
		}

		query := pool.DefaultMessage.Get()
		query.Data = buf[2 : 2+msgLen]
		if err := query.Unpack(); err != nil {
			log.Debugf("TLCP: DTLCP unpack error: %v", err)
			pool.DefaultMessage.Put(query)
			continue
		}

		response := s.handler.ServeDNS(query, clientIP, true, config.ProtoDTLCP)
		pool.DefaultMessage.Put(query)

		if err := response.Pack(); err != nil {
			log.Debugf("TLCP: DTLCP pack error: %v", err)
			continue
		}

		// Write response with 2-byte length prefix in a single Write.
		respLen := len(response.Data)
		if respLen > 65535 {
			log.Debugf("TLCP: DTLCP response too large (%d bytes)", respLen)
			continue
		}
		resp := make([]byte, 2+respLen)
		binary.BigEndian.PutUint16(resp[:2], uint16(respLen)) //nolint:gosec // G115: DNS response length < 65535 (UDP datagram limit)
		copy(resp[2:], response.Data)

		if _, err := conn.Write(resp); err != nil {
			log.Debugf("TLCP: DTLCP write error: %v", err)
			return
		}
	}
}
