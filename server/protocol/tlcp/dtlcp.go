package tlcp

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
	"zjdns/config"
	zdnsutil "zjdns/internal/dnsutil"
	"zjdns/internal/log"
	"zjdns/internal/pool"

	"codeberg.org/miekg/dns"
	"gitee.com/Trisia/gotlcp/dtlcp"
)

// demuxPacket is one datagram routed to a per-client queue.
type demuxPacket struct {
	data []byte
	addr net.Addr
}

// demuxPacketConn routes one client's datagrams from the shared listener
// socket.  ReadFrom drains the per-client queue (filled by the accept
// loop's dispatch); WriteTo sends back through the shared socket so the
// client always sees the listener's source port — gotlcp's readDatagram
// drops datagrams from any other source address, so a per-connection
// socket with a fresh port would never deliver responses.
type demuxPacketConn struct {
	shared  *net.UDPConn
	remote  net.Addr
	ch      chan demuxPacket
	closed  atomic.Bool
	dlMu    sync.Mutex
	dlCh    chan struct{}
	dlTimer *time.Timer
}

// dtlcpListener implements net.Listener over UDP.  The accept loop reads
// every datagram from the shared socket and dispatches it to the owning
// client's queue — one demuxPacketConn per remote address.  This isolates
// each connection's reads (gotlcp connections would otherwise steal each
// other's datagrams from the shared socket), so multiple clients can
// handshake and query concurrently.
type dtlcpListener struct {
	udpConn *net.UDPConn
	cfg     *dtlcp.Config
	mu      sync.Mutex
	conns   map[string]*demuxPacketConn
	closed  atomic.Bool
}

func newDTLCPListener(udpConn *net.UDPConn, cfg *dtlcp.Config) *dtlcpListener {
	return &dtlcpListener{
		udpConn: udpConn,
		cfg:     cfg,
		conns:   make(map[string]*demuxPacketConn),
	}
}

func (d *demuxPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		d.dlMu.Lock()
		dl := d.dlCh
		d.dlMu.Unlock()
		if dl == nil {
			pkt, ok := <-d.ch
			if !ok {
				return 0, nil, net.ErrClosed
			}
			return d.copyPacket(p, pkt)
		}
		select {
		case pkt, ok := <-d.ch:
			if !ok {
				return 0, nil, net.ErrClosed
			}
			return d.copyPacket(p, pkt)
		case <-dl:
			// Deadline fired; a stale timer from a previous deadline may
			// have raced a fresh packet — loop once to re-check the queue
			// before surfacing the timeout.
			d.dlMu.Lock()
			still := d.dlCh == dl
			d.dlMu.Unlock()
			if still {
				return 0, nil, os.ErrDeadlineExceeded
			}
		}
	}
}

// copyPacket copies a queued datagram into p, surfacing io.ErrShortBuffer
// when p is too small instead of silently truncating (a truncated record
// would be indistinguishable from network corruption and churn the
// connection; M-3-5).
func (d *demuxPacketConn) copyPacket(p []byte, pkt demuxPacket) (int, net.Addr, error) {
	if len(p) < len(pkt.data) {
		return 0, pkt.addr, io.ErrShortBuffer
	}
	return copy(p, pkt.data), pkt.addr, nil
}

func (d *demuxPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	return d.shared.WriteTo(p, addr)
}

func (d *demuxPacketConn) Close() error {
	if d.closed.CompareAndSwap(false, true) {
		close(d.ch)
	}
	return nil
}

func (d *demuxPacketConn) LocalAddr() net.Addr  { return d.shared.LocalAddr() }
func (d *demuxPacketConn) RemoteAddr() net.Addr { return d.remote }

func (d *demuxPacketConn) SetDeadline(t time.Time) error    { return d.SetReadDeadline(t) }
func (d *demuxPacketConn) SetWriteDeadline(time.Time) error { return nil } // UDP writes never block
func (d *demuxPacketConn) setReadDeadlineLocked(t time.Time) {
	if d.dlTimer != nil {
		d.dlTimer.Stop()
		d.dlTimer = nil
	}
	d.dlCh = nil
	if t.IsZero() {
		return
	}
	ch := make(chan struct{})
	d.dlCh = ch
	d.dlTimer = time.AfterFunc(time.Until(t), func() { close(ch) })
}

func (d *demuxPacketConn) SetReadDeadline(t time.Time) error {
	d.dlMu.Lock()
	defer d.dlMu.Unlock()
	d.setReadDeadlineLocked(t)
	return nil
}

// startDTLCPServer binds UDP sockets and starts DTLCP listeners for
// DNS-over-DTLCP (GM/T 0128-2023).  The wire format is identical to
// RFC 8094: a 2-byte big-endian length prefix followed by the DNS payload.
//
// dtlcp.Listen is not used because it calls net.Listen which does not support
// "udp" in Go.  Instead we create a UDP socket directly and implement a
// custom listener that demultiplexes datagrams per client (see dtlcpListener).
func (s *Server) startDTLCPServer() error {
	addrs, err := zdnsutil.ResolveBindAddrs("udp", s.dtlcpPort)
	if err != nil {
		return err
	}

	log.Infof("TLCP: DTLCP server started on %v", addrs)
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
		s.listenerMu.Lock()
		s.dtlcpListeners = append(s.dtlcpListeners, listener)
		s.listenerMu.Unlock()
		s.serverGroup.Go(func() error {
			defer zdnsutil.HandlePanic("DTLCP server")
			s.handleDTLCPConnections(listener)
			return nil
		})
	}
	return nil
}

// handleDTLCPConnections is the accept loop: read datagrams from the shared
// socket, hand each to its client's queue, and start a goroutine for new
// clients (handshake + query serving).  Never blocks on a connection.
func (s *Server) handleDTLCPConnections(l *dtlcpListener) {
	defer zdnsutil.HandlePanic("TLCP DTLCP accept loop")

	// SecureBufferSize, not UDPBufferSize: the dispatcher must accept any
	// record the client can send (RFC 8094 framing allows 65535; DTLS reads
	// 8192) — a 1232-byte buffer silently destroyed larger DTLCP datagrams
	// at the socket read (M-3-5).
	buf := make([]byte, pool.SecureBufferSize)

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		n, src, err := l.udpConn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-s.ctx.Done():
				return
			default:
			}
			backoff := config.DefaultAcceptRetryDelay
			if zdnsutil.IsTemporaryError(err) {
				log.Debugf("TLCP: DTLCP accept temporary error: %v", err)
			} else {
				log.Warnf("TLCP: DTLCP accept error: %v", err)
			}
			timer := time.NewTimer(backoff)
			select {
			case <-timer.C:
			case <-s.ctx.Done():
				timer.Stop()
				return
			}
			continue
		}

		key := src.String()
		l.mu.Lock()
		dc, ok := l.conns[key]
		if !ok {
			dc = &demuxPacketConn{
				shared: l.udpConn,
				remote: src,
				ch:     make(chan demuxPacket, 32),
			}
			l.conns[key] = dc
			l.mu.Unlock()
			// The connection goroutine runs under the server group so
			// Shutdown waits for it; listener Close closes the demux
			// queue, which unblocks its reads.  Launched OUTSIDE l.mu:
			// errgroup.Go blocks when the concurrency limit is saturated,
			// and holding the lock there would freeze datagram dispatch
			// for all clients and block Close()/Shutdown (H5).
			s.serverGroup.Go(func() error {
				defer zdnsutil.HandlePanic("DTLCP client connection")
				s.serveDTLCPClient(l, dc, src)
				return nil
			})
		} else {
			l.mu.Unlock()
		}

		// Queue the datagram.  A full queue means the client is flooding —
		// drop it (UDP semantics; DTLCP retransmits handshake flights).
		cp := make([]byte, n)
		copy(cp, buf[:n])
		select {
		case dc.ch <- demuxPacket{data: cp, addr: src}:
		default:
		}
	}
}

// serveDTLCPClient completes the DTLCP handshake and serves queries on one
// client connection.
func (s *Server) serveDTLCPClient(l *dtlcpListener, dc *demuxPacketConn, src *net.UDPAddr) {
	defer func() {
		_ = dc.Close()
		l.mu.Lock()
		delete(l.conns, src.String())
		l.mu.Unlock()
	}()

	// Bound the handshake: a client that sends one datagram then goes
	// silent must not pin a goroutine (or its queue) forever.
	handshakeCtx, cancel := context.WithTimeout(s.ctx, config.DefaultDTLSIdleTimeout)
	defer cancel()

	conn := dtlcp.Server(dc, src, l.cfg)
	if err := conn.HandshakeContext(handshakeCtx); err != nil {
		log.Debugf("TLCP: DTLCP handshake error from %s: %v", src, err)
		return
	}
	log.Debugf("TLCP: DTLCP handshake from client — version=0x%x cipher=%s",
		conn.ConnectionState().Version, dtlcp.CipherSuiteName(conn.ConnectionState().CipherSuite))

	s.handleDTLCPConnection(conn)
}

// handleDTLCPConnection reads DNS-over-DTLCP queries.  Each DTLCP record
// carries one framed DNS message: a 2-byte big-endian length prefix followed
// by the DNS payload, same as DNS-over-DTLS (TCP framing, RFC 1035 §4.2.2).
func (s *Server) handleDTLCPConnection(conn net.Conn) {
	defer zdnsutil.CloseWithLog(conn, "TLCP DTLCP connection", "TLCP")

	var clientIP net.IP
	if addr, ok := conn.RemoteAddr().(*net.UDPAddr); ok {
		clientIP = addr.IP
	}

	idleTimeout := config.DefaultDTLSIdleTimeout
	buf := pool.DefaultBuffer.Get()
	defer pool.DefaultBuffer.Put(buf)

	for {
		if err := conn.SetReadDeadline(time.Now().Add(idleTimeout)); err != nil {
			log.Debugf("TLCP: DTLCP SetReadDeadline error: %v", err)
			continue
		}

		n, err := conn.Read(buf)
		if err != nil {
			// A read-deadline expiry means the peer went idle — close the
			// connection instead of retrying forever (a timeout was being
			// classified as temporary and the loop spun).
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				return
			}
			if !zdnsutil.IsTemporaryError(err) {
				return
			}
			continue
		}

		// Parse 2-byte length prefix (TCP DNS framing, RFC 1035 §4.2.2).
		if n < zdnsutil.DNSFramePrefixLen {
			continue
		}
		msgLen := binary.BigEndian.Uint16(buf[:zdnsutil.DNSFramePrefixLen])
		if int(msgLen)+zdnsutil.DNSFramePrefixLen > n {
			log.Debugf("TLCP: DTLCP short read: want %d + 2, got %d", msgLen, n)
			continue
		}

		query := pool.DefaultMessage.Get()
		query.Data = buf[zdnsutil.DNSFramePrefixLen : zdnsutil.DNSFramePrefixLen+msgLen]
		if err := query.Unpack(); err != nil {
			log.Debugf("TLCP: DTLCP unpack error: %v", err)
			pool.DefaultMessage.Put(query)
			continue
		}

		// Sequential Put per loop iteration (defer would accumulate every
		// query until the connection closes — the per-connection loop is
		// not a single-request scope, AUDIT-METHODOLOGY §6.1.1).
		response := s.handler.ServeDNS(query, clientIP, true, config.ProtoDTLCP)
		pool.DefaultMessage.Put(query)
		if !s.sendDTLCPResponse(conn, response) {
			return
		}
	}
}

// sendDTLCPResponse packs and writes a DTLCP response with 2-byte length prefix.
// Returns true to continue the connection loop, false to close the connection.
// The response is always returned to the pool (defer-protected).
func (s *Server) sendDTLCPResponse(conn net.Conn, response *dns.Msg) bool {
	// The per-connection loop only refreshes the READ deadline; the write
	// deadline was set once at accept time and would expire mid-conversation
	// for any connection alive longer than the idle timeout. Refresh it per
	// response.
	if err := conn.SetWriteDeadline(time.Now().Add(config.DefaultDTLSIdleTimeout)); err != nil {
		log.Debugf("TLCP: DTLCP SetWriteDeadline error: %v", err)
		return false
	}
	if response == nil {
		return true
	}
	defer pool.DefaultMessage.Put(response)

	if err := response.Pack(); err != nil {
		log.Debugf("TLCP: DTLCP pack error: %v", err)
		return true
	}

	// RFC 8094 §5: truncate if the datagram would exceed the assumed PMTU.
	if safeMax := config.DefaultPMTU - config.DTLSDNSOverhead - zdnsutil.DNSFramePrefixLen; len(response.Data) > safeMax {
		response.Truncated = true
		response.Answer = nil
		response.Ns = nil
		response.Extra = nil
		if err := response.Pack(); err != nil {
			log.Debugf("TLCP: DTLCP repack after truncation: %v", err)
			return true
		}
	}

	respLen := len(response.Data)
	if respLen > config.MaxDNSMessageSize {
		log.Debugf("TLCP: DTLCP response too large (%d bytes)", respLen)
		return true
	}
	resp := make([]byte, zdnsutil.DNSFramePrefixLen+respLen)
	binary.BigEndian.PutUint16(resp[:zdnsutil.DNSFramePrefixLen], uint16(respLen)) //nolint:gosec // G115: DNS response length bounded by MaxDNSMessageSize
	copy(resp[zdnsutil.DNSFramePrefixLen:], response.Data)

	if _, err := conn.Write(resp); err != nil {
		log.Debugf("TLCP: DTLCP write error: %v", err)
		return false
	}
	return true
}

// Close shuts down the listener: close every client queue (unblocking
// connection goroutines) and the shared socket.
func (l *dtlcpListener) Close() error {
	l.mu.Lock()
	if l.closed.Load() {
		l.mu.Unlock()
		return nil
	}
	l.closed.Store(true)
	conns := make([]*demuxPacketConn, 0, len(l.conns))
	for _, dc := range l.conns {
		conns = append(conns, dc)
	}
	l.mu.Unlock()

	for _, dc := range conns {
		_ = dc.Close()
	}
	return l.udpConn.Close()
}

func (l *dtlcpListener) Addr() net.Addr {
	return l.udpConn.LocalAddr()
}
