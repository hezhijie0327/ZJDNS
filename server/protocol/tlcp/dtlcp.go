package tlcp

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"
	"zjdns/config"
	zdnsutil "zjdns/internal/dnsutil"
	"zjdns/internal/log"
	"zjdns/internal/pool"
	"zjdns/server/protocol/shared"

	"codeberg.org/miekg/dns"
	"gitee.com/Trisia/gotlcp/dtlcp"
)

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
	conns   map[string]*shared.DemuxPacketConn
	closed  atomic.Bool
}

func newDTLCPListener(udpConn *net.UDPConn, cfg *dtlcp.Config) *dtlcpListener {
	return &dtlcpListener{
		udpConn: udpConn,
		cfg:     cfg,
		conns:   make(map[string]*shared.DemuxPacketConn),
	}
}

func (d *dtlcpListener) Addr() net.Addr {
	return d.udpConn.LocalAddr()
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
			dc = &shared.DemuxPacketConn{
				Shared: l.udpConn,
				Remote: src,
				Ch:     make(chan shared.DemuxPacket, 32),
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
				s.serveDTLCPClient(l.cfg, dc, src, func() {
					l.mu.Lock()
					delete(l.conns, src.String())
					l.mu.Unlock()
				})
				return nil
			})
		} else {
			l.mu.Unlock()
		}

		// Queue the datagram.  A full queue means the client is flooding —
		// drop it (UDP semantics; DTLCP retransmits handshake flights).
		pb := shared.PacketBufPool.Get().(*[]byte)
		copy(*pb, buf[:n])
		// Guarded send: the client goroutine's deferred dc.Close() can race
		// this enqueue (handshake failure, idle timeout, Shutdown) — a bare
		// channel send here panicked the whole accept loop (2026-09 P1).
		if !dc.Send(shared.DemuxPacket{Data: (*pb)[:n], Addr: src}) {
			shared.PacketBufPool.Put(pb)
		}
	}
}

// ServeDTLCPClient completes the DTLCP handshake and serves queries on one
// client connection (exported for shared-port Manager).
func (s *Server) ServeDTLCPClient(pc net.PacketConn, src *net.UDPAddr, cleanup func()) {
	dc, ok := pc.(*shared.DemuxPacketConn)
	if !ok {
		// Exported API guard: a foreign PacketConn cannot be served (the
		// dispatch path depends on the demux queue semantics) — close it
		// instead of panicking the client goroutine (2026-09 X5).
		log.Warnf("TLCP: ServeDTLCPClient received a non-demux conn %T — closing", pc)
		_ = pc.Close()
		return
	}
	s.serveDTLCPClient(s.dtlcpConfig, dc, src, cleanup)
}

// serveDTLCPClient completes the DTLCP handshake and serves queries on one
// client connection.  The cleanup function is called on exit to remove the
// client from the dispatch map (varies between standalone and shared mode).
func (s *Server) serveDTLCPClient(cfg *dtlcp.Config, dc *shared.DemuxPacketConn, src *net.UDPAddr, cleanup func()) {
	defer func() {
		_ = dc.Close()
		if cleanup != nil {
			cleanup()
		}
	}()

	// Bound the handshake: a client that sends one datagram then goes
	// silent must not pin a goroutine (or its queue) forever.
	handshakeCtx, cancel := context.WithTimeout(s.ctx, config.DefaultDTLSIdleTimeout)
	defer cancel()

	conn := dtlcp.Server(dc, src, cfg)
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
//
// Queries are served on bounded worker goroutines (DefaultMaxPipe) so one
// slow upstream does not stall the connection; writes are serialized by a
// per-connection mutex (datagram protocol — no stream-ordering hazard).
func (s *Server) handleDTLCPConnection(conn net.Conn) {
	defer zdnsutil.CloseWithLog(conn, "TLCP DTLCP connection", "TLCP")

	var clientIP net.IP
	if addr, ok := conn.RemoteAddr().(*net.UDPAddr); ok {
		clientIP = addr.IP
	}

	idleTimeout := config.DefaultDTLSIdleTimeout
	workerCap := make(chan struct{}, config.DefaultMaxPipe)
	var writeMu sync.Mutex
	var wg sync.WaitGroup
	defer wg.Wait() // pending workers may still write; conn is closed after

	for {
		if err := conn.SetReadDeadline(time.Now().Add(idleTimeout)); err != nil {
			log.Debugf("TLCP: DTLCP SetReadDeadline error: %v", err)
			continue
		}

		// Fresh pooled buffer per datagram — ownership transfers to the
		// worker goroutine, so the read loop must not reuse it.
		buf := pool.DefaultBuffer.Get()
		n, err := conn.Read(buf)
		if err != nil {
			pool.DefaultBuffer.Put(buf)
			// A read-deadline expiry means the peer went idle — close the
			// connection instead of retrying forever (a timeout was being
			// classified as temporary and the loop spun).
			if ne, ok := errors.AsType[net.Error](err); ok && ne.Timeout() {
				return
			}
			if !zdnsutil.IsTemporaryError(err) {
				return
			}
			continue
		}

		// Parse 2-byte length prefix (TCP DNS framing, RFC 1035 §4.2.2).
		if n < zdnsutil.DNSFramePrefixLen {
			pool.DefaultBuffer.Put(buf)
			continue
		}
		msgLen := binary.BigEndian.Uint16(buf[:zdnsutil.DNSFramePrefixLen])
		if int(msgLen)+zdnsutil.DNSFramePrefixLen > n {
			log.Debugf("TLCP: DTLCP short read: want %d + 2, got %d", msgLen, n)
			pool.DefaultBuffer.Put(buf)
			continue
		}

		query := pool.DefaultMessage.Get()
		query.Data = buf[zdnsutil.DNSFramePrefixLen : zdnsutil.DNSFramePrefixLen+msgLen]
		if err := query.Unpack(); err != nil {
			log.Debugf("TLCP: DTLCP unpack error: %v", err)
			pool.DefaultMessage.Put(query)
			pool.DefaultBuffer.Put(buf)
			continue
		}

		// Non-blocking worker admission: a saturated client connection drops
		// the datagram (the client retransmits) instead of stalling the read
		// loop for every other in-flight query.
		select {
		case workerCap <- struct{}{}:
		default:
			pool.DefaultMessage.Put(query)
			pool.DefaultBuffer.Put(buf)
			continue
		}

		wg.Add(1)
		go func(query *dns.Msg, buf []byte) {
			defer func() { <-workerCap }()
			defer zdnsutil.HandlePanic("DTLCP query worker")
			defer wg.Done()
			defer pool.DefaultMessage.Put(query)
			defer pool.DefaultBuffer.Put(buf)

			response := s.handler.ServeDNS(query, clientIP, true, config.ProtoDTLCP)
			if response == query { //nolint:revive // identity guard: ServeDNS must never return the request (L5)
				response = nil
			}
			if response == nil {
				return
			}
			writeMu.Lock()
			ok := s.sendDTLCPResponse(conn, response)
			writeMu.Unlock()
			if !ok {
				// Write error — close so the read loop exits and queued
				// workers fail fast.
				_ = conn.Close()
			}
		}(query, buf)
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

	safeMax := config.DefaultPMTU - config.DTLSDNSOverhead - zdnsutil.DNSFramePrefixLen
	return zdnsutil.WriteDTLSFrame(conn, response, safeMax, config.MaxDNSMessageSize, "TLCP: DTLCP")
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
	conns := make([]*shared.DemuxPacketConn, 0, len(l.conns))
	for _, dc := range l.conns {
		conns = append(conns, dc)
	}
	l.mu.Unlock()

	for _, dc := range conns {
		_ = dc.Close()
	}
	return l.udpConn.Close()
}
