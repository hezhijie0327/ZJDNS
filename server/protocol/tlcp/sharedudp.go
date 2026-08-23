package tlcp

import (
	"net"
	"sync"
	"sync/atomic"
	"time"
	"zjdns/internal/demux"
	zdnsutil "zjdns/internal/dnsutil"
	"zjdns/internal/log"
	"zjdns/internal/pool"
)

// addrKey is an allocation-free map key for UDP client addresses.
// Fixed-size arrays are comparable, unlike net.UDPAddr's IP slice.
type addrKey struct {
	ip   [16]byte
	port uint16
}

// packetBuf is a pooled datagram buffer passed through dispatch channels.
// The consumer copies data out and returns the buffer to packetBufPool.
type packetBuf struct {
	data []byte
	src  *net.UDPAddr
	n    int
}

// dtlsClientConn implements net.PacketConn for a single DTLS client.
// ReadFrom blocks until a datagram arrives from the dispatch loop;
// WriteTo sends through the shared UDP socket.
type dtlsClientConn struct {
	ch     chan packetBuf
	shared *net.UDPConn
	remote net.Addr
	closed atomic.Bool
}

type dtlsAcceptResult struct {
	conn net.PacketConn
	addr net.Addr
}

// dtlsPacketListener implements dtlsnet.PacketListener.  The unified
// dispatch loop pushes new DTLS clients to acceptCh and all DTLS
// datagrams to the per-client dtlsClientConn channels.
type dtlsPacketListener struct {
	udpConn  *net.UDPConn
	acceptCh chan dtlsAcceptResult
	mu       sync.Mutex
	clients  map[addrKey]*dtlsClientConn
	closed   atomic.Bool
	done     chan struct{}
}

// quicPacketConn implements net.PacketConn for the QUIC transport.
// The dispatch loop pushes QUIC packets into ch; quic.Transport's
// read loop reads from ch via ReadFrom.
type quicPacketConn struct {
	ch     chan packetBuf
	shared *net.UDPConn
	closed atomic.Bool
	done   chan struct{}
}

// sharedDTLSClient tracks a DTLCP client in the shared UDP dispatch.
// It mirrors dtlcpListener's per-client fields but writes through the
// shared UDP socket.
type sharedDTLSClient struct {
	mu    sync.Mutex
	conns map[addrKey]*demuxPacketConn
}

var packetBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, pool.SecureBufferSize)
		return &b
	},
}

func makeAddrKey(a *net.UDPAddr) addrKey {
	var k addrKey
	k.port = uint16(a.Port) //nolint:gosec // G115: UDP port always fits uint16
	if len(a.IP) == 4 {
		copy(k.ip[12:], a.IP)
	} else {
		copy(k.ip[:], a.IP)
	}
	return k
}

// ---------------------------------------------------------------------------
// dtlsClientConn — per-DTLS-client net.PacketConn
// ---------------------------------------------------------------------------

func (c *dtlsClientConn) ReadFrom(p []byte) (int, net.Addr, error) {
	pkt, ok := <-c.ch
	if !ok {
		return 0, nil, net.ErrClosed
	}
	if len(p) < pkt.n {
		packetBufPool.Put(&pkt.data)
		return 0, pkt.src, net.ErrClosed
	}
	n := copy(p, pkt.data[:pkt.n])
	packetBufPool.Put(&pkt.data)
	return n, pkt.src, nil
}

func (c *dtlsClientConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	return c.shared.WriteTo(p, c.remote)
}

func (c *dtlsClientConn) Close() error {
	if c.closed.CompareAndSwap(false, true) {
		close(c.ch)
	}
	return nil
}

func (c *dtlsClientConn) LocalAddr() net.Addr                { return c.shared.LocalAddr() }
func (c *dtlsClientConn) RemoteAddr() net.Addr               { return c.remote }
func (c *dtlsClientConn) SetDeadline(_ time.Time) error      { return nil }
func (c *dtlsClientConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *dtlsClientConn) SetWriteDeadline(_ time.Time) error { return nil }

func newDTLSPacketListener(udpConn *net.UDPConn) *dtlsPacketListener {
	return &dtlsPacketListener{
		udpConn:  udpConn,
		acceptCh: make(chan dtlsAcceptResult, 64),
		clients:  make(map[addrKey]*dtlsClientConn),
		done:     make(chan struct{}),
	}
}

// Accept implements dtlsnet.PacketListener.
func (l *dtlsPacketListener) Accept() (net.PacketConn, net.Addr, error) {
	select {
	case r, ok := <-l.acceptCh:
		if !ok {
			return nil, nil, net.ErrClosed
		}
		return r.conn, r.addr, nil
	case <-l.done:
		return nil, nil, net.ErrClosed
	}
}

// Close implements dtlsnet.PacketListener.
func (l *dtlsPacketListener) Close() error {
	if l.closed.CompareAndSwap(false, true) {
		close(l.done)
		l.mu.Lock()
		for _, c := range l.clients {
			_ = c.Close()
		}
		l.mu.Unlock()
	}
	return nil
}

// Addr implements dtlsnet.PacketListener.
func (l *dtlsPacketListener) Addr() net.Addr { return l.udpConn.LocalAddr() }

// dispatch routes a DTLS datagram to the per-client channel, creating a
// new client connection (and Accept entry) on first sight.
// The pooled buffer pb is copied into a new pool buffer for the client
// channel; pb is always returned to the pool before returning.
func (l *dtlsPacketListener) dispatch(src *net.UDPAddr, pb *[]byte, n int) {
	key := makeAddrKey(src)

	l.mu.Lock()
	cc, ok := l.clients[key]
	if !ok {
		cc = &dtlsClientConn{
			ch:     make(chan packetBuf, 32),
			shared: l.udpConn,
			remote: src,
		}
		l.clients[key] = cc
		l.mu.Unlock()

		// Notify Accept() about the new DTLS client.
		select {
		case l.acceptCh <- dtlsAcceptResult{conn: cc, addr: src}:
		default:
		}
	} else {
		l.mu.Unlock()
	}

	cpBuf := packetBufPool.Get().(*[]byte)
	copy(*cpBuf, (*pb)[:n])
	select {
	case cc.ch <- packetBuf{data: *cpBuf, src: src, n: n}:
	default:
		packetBufPool.Put(cpBuf)
	}
	packetBufPool.Put(pb)
}

func newQUICPacketConn(udpConn *net.UDPConn) *quicPacketConn {
	return &quicPacketConn{
		ch:     make(chan packetBuf, 256),
		shared: udpConn,
		done:   make(chan struct{}),
	}
}

func (c *quicPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case pkt, ok := <-c.ch:
		if !ok {
			return 0, nil, net.ErrClosed
		}
		n := copy(p, pkt.data[:pkt.n])
		packetBufPool.Put(&pkt.data)
		return n, pkt.src, nil
	case <-c.done:
		return 0, nil, net.ErrClosed
	}
}

func (c *quicPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	return c.shared.WriteTo(p, addr)
}

func (c *quicPacketConn) Close() error {
	if c.closed.CompareAndSwap(false, true) {
		close(c.done)
	}
	return nil
}

func (c *quicPacketConn) LocalAddr() net.Addr                { return c.shared.LocalAddr() }
func (c *quicPacketConn) SetDeadline(_ time.Time) error      { return nil }
func (c *quicPacketConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *quicPacketConn) SetWriteDeadline(_ time.Time) error { return nil }

// dispatch pushes a QUIC datagram into the channel (non-blocking; drops on full).
// The pooled buffer pb is consumed or returned to the pool.
func (c *quicPacketConn) dispatch(src *net.UDPAddr, pb *[]byte, n int) {
	select {
	case c.ch <- packetBuf{data: *pb, src: src, n: n}:
	default:
		packetBufPool.Put(pb)
	}
}

// ---------------------------------------------------------------------------
// startSharedDTLSServer — main entry point
// ---------------------------------------------------------------------------

// startSharedDTLSServer binds a single UDP socket and dispatches datagrams
// to QUIC (quic-go via quicPacketConn), DTLS (pion/dtls via dtlsPacketListener)
// and DTLCP (gotlcp/dtlcp via per-client demuxPacketConn) based on the first
// datagram's record header.
func (s *Server) startSharedDTLSServer() error {
	addrs, err := zdnsutil.ResolveBindAddrs("udp", s.shared.DTLSPort)
	if err != nil {
		return err
	}

	switch {
	case s.shared.DOQHandler != nil && s.shared.DTLSHandler != nil:
		log.Infof("TLCP: Shared DoQ+DTLS+DTLCP server started on %v", addrs)
	case s.shared.DOQHandler != nil:
		log.Infof("TLCP: Shared DoQ+DTLCP server started on %v", addrs)
	case s.shared.DTLSHandler != nil:
		log.Infof("TLCP: Shared DTLS+DTLCP server started on %v", addrs)
	default:
		log.Infof("TLCP: Shared UDP server started on %v", addrs)
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

		s.listenerMu.Lock()
		s.sharedUDPConn = udpConn
		s.listenerMu.Unlock()

		// DTLS PacketListener — fed by the dispatch loop.
		dtlsPL := newDTLSPacketListener(udpConn)

		s.listenerMu.Lock()
		s.sharedDTLSPktLstnr = dtlsPL
		s.listenerMu.Unlock()

		// DTLCP per-client dispatch state.
		dtlcpState := &sharedDTLSClient{
			conns: make(map[addrKey]*demuxPacketConn),
		}

		// QUIC PacketConn — fed by the dispatch loop (optional).
		var quicPC *quicPacketConn
		if s.shared.DOQHandler != nil {
			quicPC = newQUICPacketConn(udpConn)
			s.listenerMu.Lock()
			s.sharedQUICPktConn = quicPC
			s.listenerMu.Unlock()

			// QUIC side: the TLS server's HandleDOQFromPacketConn
			// creates a quic.Transport and runs the accept loop.
			capturedQUIC := quicPC
			s.serverGroup.Go(func() error {
				defer zdnsutil.HandlePanic("Shared DoQ server")
				if err := s.shared.DOQHandler(capturedQUIC); err != nil {
					if s.ctx.Err() != nil {
						return nil
					}
					log.Warnf("TLCP: shared DoQ error: %v", err)
				}
				return nil
			})
		}

		// DTLS side: the TLS server's HandleDTLSFromPacketListener
		// creates a pion/dtls listener and runs the accept loop (optional).
		if s.shared.DTLSHandler != nil {
			s.serverGroup.Go(func() error {
				defer zdnsutil.HandlePanic("Shared DTLS server")
				if err := s.shared.DTLSHandler(dtlsPL); err != nil {
					if s.ctx.Err() != nil {
						return nil
					}
					log.Warnf("TLCP: shared DTLS error: %v", err)
				}
				return nil
			})
		}

		// Unified dispatch loop: read → detect → route.
		capturedUDP := udpConn
		capturedDTLS := dtlsPL
		capturedDTLCP := dtlcpState
		capturedQUICPC := quicPC
		s.serverGroup.Go(func() error {
			defer zdnsutil.HandlePanic("Shared DoQ+DTLS+DTLCP dispatch")
			s.sharedUDPDispatchLoop(capturedUDP, capturedDTLS, capturedDTLCP, capturedQUICPC)
			return nil
		})
	}
	return nil
}

// sharedUDPDispatchLoop reads datagrams from the shared UDP socket,
// detects QUIC vs DTLS vs DTLCP from the first datagram of each client,
// and routes subsequent datagrams accordingly.
//
// Per-packet allocation-free: the read buffer is pooled (packetBufPool),
// the map key is a value-type addrKey (no src.String()), and the pooled
// buffer is passed through channels — consumers copy out and return it.
func (s *Server) sharedUDPDispatchLoop(
	udpConn *net.UDPConn,
	dtlsPL *dtlsPacketListener,
	dtlcpState *sharedDTLSClient,
	quicPC *quicPacketConn,
) {
	peerProto := make(map[addrKey]string) // client addr → detected protocol
	var peerMu sync.RWMutex

	buf := make([]byte, pool.SecureBufferSize)

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		n, src, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-s.ctx.Done():
				return
			default:
			}
			if zdnsutil.IsTemporaryError(err) {
				continue
			}
			return
		}

		// Acquire a pooled buffer for this datagram.
		pb := packetBufPool.Get().(*[]byte)
		copy(*pb, buf[:n])

		key := makeAddrKey(src)

		// Determine protocol (cached per client).
		peerMu.RLock()
		proto, known := peerProto[key]
		peerMu.RUnlock()

		if !known {
			proto = demux.DetectUDPProtocol((*pb)[:n])
			if proto == "" {
				packetBufPool.Put(pb)
				continue
			}
			peerMu.Lock()
			peerProto[key] = proto
			peerMu.Unlock()
		}

		switch proto {
		case demux.ProtoQUIC:
			if quicPC != nil {
				quicPC.dispatch(src, pb, n)
			} else {
				packetBufPool.Put(pb)
			}

		case demux.ProtoDTLS:
			if s.shared.DTLSHandler != nil {
				dtlsPL.dispatch(src, pb, n)
			} else {
				packetBufPool.Put(pb)
			}

		case demux.ProtoDTLCP:
			dtlcpState.mu.Lock()
			dc, ok := dtlcpState.conns[key]
			if !ok {
				dc = &demuxPacketConn{
					shared: udpConn,
					remote: src,
					ch:     make(chan demuxPacket, 32),
				}
				dtlcpState.conns[key] = dc
				dtlcpState.mu.Unlock()

				capturedDC := dc
				capturedSrc := src
				capturedKey := key
				s.serverGroup.Go(func() error {
					defer zdnsutil.HandlePanic("Shared DTLCP client")
					s.serveDTLCPClient(s.dtlcpConfig, capturedDC, capturedSrc, func() {
						dtlcpState.mu.Lock()
						delete(dtlcpState.conns, capturedKey)
						dtlcpState.mu.Unlock()
					})
					return nil
				})
			} else {
				dtlcpState.mu.Unlock()
			}

			select {
			case dc.ch <- demuxPacket{data: *pb, addr: src}:
			default:
				packetBufPool.Put(pb)
			}
		}
	}
}
