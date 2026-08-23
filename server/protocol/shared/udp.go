package shared

import (
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
	"zjdns/internal/demux"
	"zjdns/internal/log"
	"zjdns/internal/pool"

	zdnsutil "zjdns/internal/dnsutil"
)

// ---------------------------------------------------------------------------
// Types — all type declarations first (decorder: type → const → var → func).
// ---------------------------------------------------------------------------

// DemuxPacket is one datagram routed to a per-client queue.
type DemuxPacket struct {
	Data []byte
	Addr net.Addr
}

// DemuxPacketConn routes one client's datagrams from the shared listener
// socket.  ReadFrom drains the per-client queue (filled by the dispatch
// loop); WriteTo sends back through the shared socket so the client
// always sees the listener's source port.
type DemuxPacketConn struct {
	Shared  *net.UDPConn
	Remote  net.Addr
	Ch      chan DemuxPacket
	closed  atomic.Bool
	dlMu    sync.Mutex
	dlCh    chan struct{}
	dlTimer *time.Timer
}

// addrKey is an allocation-free map key for UDP client addresses.
// Fixed-size arrays are comparable, unlike net.UDPAddr's IP slice.
type addrKey struct {
	ip   [16]byte
	port uint16
}

// packetBuf is a pooled datagram buffer passed through dispatch channels.
// The consumer copies data out and returns the buffer to PacketBufPool.
type packetBuf struct {
	data []byte
	src  *net.UDPAddr
	n    int
}

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

type dtlsPacketListener struct {
	udpConn  *net.UDPConn
	acceptCh chan dtlsAcceptResult
	mu       sync.Mutex
	clients  map[addrKey]*dtlsClientConn
	closed   atomic.Bool
	done     chan struct{}
}

type quicPacketConn struct {
	ch     chan packetBuf
	shared *net.UDPConn
	closed atomic.Bool
	done   chan struct{}
}

type sharedDTLSClient struct {
	mu    sync.Mutex
	conns map[addrKey]*DemuxPacketConn
}

// ---------------------------------------------------------------------------
// Vars
// ---------------------------------------------------------------------------

// PacketBufPool manages pooled datagram buffers.  The dispatch loop
// allocates from the pool; consumers copy data out and return the buffer.
var PacketBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, pool.SecureBufferSize)
		return &b
	},
}

// ---------------------------------------------------------------------------
// DemuxPacketConn methods
// ---------------------------------------------------------------------------

func (d *DemuxPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		d.dlMu.Lock()
		dl := d.dlCh
		d.dlMu.Unlock()
		if dl == nil {
			pkt, ok := <-d.Ch
			if !ok {
				return 0, nil, net.ErrClosed
			}
			return d.copyPacket(p, pkt)
		}
		select {
		case pkt, ok := <-d.Ch:
			if !ok {
				return 0, nil, net.ErrClosed
			}
			return d.copyPacket(p, pkt)
		case <-dl:
			d.dlMu.Lock()
			still := d.dlCh == dl
			d.dlMu.Unlock()
			if still {
				return 0, nil, os.ErrDeadlineExceeded
			}
		}
	}
}

// copyPacket copies a queued datagram into p, surfacing
// io.ErrShortBuffer when p is too small instead of silently truncating.
// The pooled datagram buffer is always returned to PacketBufPool.
func (d *DemuxPacketConn) copyPacket(p []byte, pkt DemuxPacket) (int, net.Addr, error) {
	// Restore the full pool buffer before returning it to the pool.
	// pkt.Data is a sub-slice ([:n]) of the pool buffer; the pool expects
	// the original SecureBufferSize-length slice (New returns make([]byte, N)).
	full := pkt.Data[:cap(pkt.Data)]
	if len(p) < len(pkt.Data) {
		PacketBufPool.Put(&full)
		return 0, pkt.Addr, io.ErrShortBuffer
	}
	n := copy(p, pkt.Data)
	PacketBufPool.Put(&full)
	return n, pkt.Addr, nil
}

func (d *DemuxPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	return d.Shared.WriteTo(p, addr)
}

func (d *DemuxPacketConn) Close() error {
	if d.closed.CompareAndSwap(false, true) {
		close(d.Ch)
	}
	return nil
}

func (d *DemuxPacketConn) LocalAddr() net.Addr  { return d.Shared.LocalAddr() }
func (d *DemuxPacketConn) RemoteAddr() net.Addr { return d.Remote }

func (d *DemuxPacketConn) SetDeadline(t time.Time) error    { return d.SetReadDeadline(t) }
func (d *DemuxPacketConn) SetWriteDeadline(time.Time) error { return nil }
func (d *DemuxPacketConn) setReadDeadlineLocked(t time.Time) {
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

func (d *DemuxPacketConn) SetReadDeadline(t time.Time) error {
	d.dlMu.Lock()
	defer d.dlMu.Unlock()
	d.setReadDeadlineLocked(t)
	return nil
}

// ---------------------------------------------------------------------------
// DTLS client conn
// ---------------------------------------------------------------------------

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

func (c *dtlsClientConn) ReadFrom(p []byte) (int, net.Addr, error) {
	pkt, ok := <-c.ch
	if !ok {
		return 0, nil, net.ErrClosed
	}
	if len(p) < pkt.n {
		PacketBufPool.Put(&pkt.data)
		return 0, pkt.src, net.ErrClosed
	}
	n := copy(p, pkt.data[:pkt.n])
	PacketBufPool.Put(&pkt.data)
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

// ---------------------------------------------------------------------------
// DTLS packet listener
// ---------------------------------------------------------------------------

func newDTLSPacketListener(udpConn *net.UDPConn) *dtlsPacketListener {
	return &dtlsPacketListener{
		udpConn:  udpConn,
		acceptCh: make(chan dtlsAcceptResult, 64),
		clients:  make(map[addrKey]*dtlsClientConn),
		done:     make(chan struct{}),
	}
}

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

		select {
		case l.acceptCh <- dtlsAcceptResult{conn: cc, addr: src}:
		default:
		}
	} else {
		l.mu.Unlock()
	}

	cpBuf := PacketBufPool.Get().(*[]byte)
	copy(*cpBuf, (*pb)[:n])
	select {
	case cc.ch <- packetBuf{data: *cpBuf, src: src, n: n}:
	default:
		PacketBufPool.Put(cpBuf)
	}
	PacketBufPool.Put(pb)
}

// ---------------------------------------------------------------------------
// QUIC packet conn
// ---------------------------------------------------------------------------

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
		PacketBufPool.Put(&pkt.data)
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

func (c *quicPacketConn) dispatch(src *net.UDPAddr, pb *[]byte, n int) {
	select {
	case c.ch <- packetBuf{data: *pb, src: src, n: n}:
	default:
		PacketBufPool.Put(pb)
	}
}

// ---------------------------------------------------------------------------
// startDTLS — main entry point
// ---------------------------------------------------------------------------

func (m *Manager) startDTLS() error {
	addrs, err := zdnsutil.ResolveBindAddrs("udp", m.cfg.DTLSPort)
	if err != nil {
		return err
	}

	switch {
	case m.cfg.DOQHandler != nil && m.cfg.DTLSHandler != nil:
		log.Infof("SHARED: DoQ+DTLS+DTLCP server started on %v", addrs)
	case m.cfg.DOQHandler != nil:
		log.Infof("SHARED: DoQ+DTLCP server started on %v", addrs)
	case m.cfg.DTLSHandler != nil:
		log.Infof("SHARED: DTLS+DTLCP server started on %v", addrs)
	default:
		log.Infof("SHARED: UDP server started on %v", addrs)
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

		m.mu.Lock()
		m.udpConn = udpConn
		m.mu.Unlock()

		dtlsPL := newDTLSPacketListener(udpConn)

		m.mu.Lock()
		m.dtlsPL = dtlsPL
		m.mu.Unlock()

		dtlcpState := &sharedDTLSClient{
			conns: make(map[addrKey]*DemuxPacketConn),
		}

		var quicPC *quicPacketConn
		if m.cfg.DOQHandler != nil {
			quicPC = newQUICPacketConn(udpConn)
			m.mu.Lock()
			m.quicPC = quicPC
			m.mu.Unlock()

			capturedQUIC := quicPC
			m.host.Go(func() error {
				defer zdnsutil.HandlePanic("Shared DoQ server")
				if err := m.cfg.DOQHandler(capturedQUIC); err != nil {
					if m.host.Ctx().Err() != nil {
						return nil
					}
					log.Warnf("SHARED: DoQ error: %v", err)
				}
				return nil
			})
		}

		if m.cfg.DTLSHandler != nil {
			m.host.Go(func() error {
				defer zdnsutil.HandlePanic("Shared DTLS server")
				if err := m.cfg.DTLSHandler(dtlsPL); err != nil {
					if m.host.Ctx().Err() != nil {
						return nil
					}
					log.Warnf("SHARED: DTLS error: %v", err)
				}
				return nil
			})
		}

		capturedUDP := udpConn
		capturedDTLS := dtlsPL
		capturedDTLCP := dtlcpState
		capturedQUICPC := quicPC
		m.host.Go(func() error {
			defer zdnsutil.HandlePanic("Shared DoQ+DTLS+DTLCP dispatch")
			m.udpDispatchLoop(capturedUDP, capturedDTLS, capturedDTLCP, capturedQUICPC)
			return nil
		})
	}
	return nil
}

// udpDispatchLoop reads datagrams from the shared UDP socket,
// detects QUIC vs DTLS vs DTLCP from the first datagram of each client,
// and routes subsequent datagrams accordingly.
//
// Per-packet allocation-free: the read buffer is pooled (PacketBufPool),
// the map key is a value-type addrKey (no src.String()), and the pooled
// buffer is passed through channels — consumers copy out and return it.
func (m *Manager) udpDispatchLoop(
	udpConn *net.UDPConn,
	dtlsPL *dtlsPacketListener,
	dtlcpState *sharedDTLSClient,
	quicPC *quicPacketConn,
) {
	peerProto := make(map[addrKey]string)
	var peerMu sync.RWMutex

	buf := make([]byte, pool.SecureBufferSize)

	for {
		select {
		case <-m.groupCtx.Done():
			return
		default:
		}

		n, src, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-m.groupCtx.Done():
				return
			default:
			}
			if zdnsutil.IsTemporaryError(err) {
				continue
			}
			return
		}

		pb := PacketBufPool.Get().(*[]byte)
		copy(*pb, buf[:n])

		key := makeAddrKey(src)

		peerMu.RLock()
		proto, known := peerProto[key]
		peerMu.RUnlock()

		if !known {
			proto = demux.DetectUDPProtocol((*pb)[:n])
			if proto == "" {
				PacketBufPool.Put(pb)
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
				PacketBufPool.Put(pb)
			}

		case demux.ProtoDTLS:
			if m.cfg.DTLSHandler != nil {
				dtlsPL.dispatch(src, pb, n)
			} else {
				PacketBufPool.Put(pb)
			}

		case demux.ProtoDTLCP:
			dtlcpState.mu.Lock()
			dc, ok := dtlcpState.conns[key]
			if !ok {
				dc = &DemuxPacketConn{
					Shared: udpConn,
					Remote: src,
					Ch:     make(chan DemuxPacket, 32),
				}
				dtlcpState.conns[key] = dc
				dtlcpState.mu.Unlock()

				capturedDC := dc
				capturedSrc := src
				capturedKey := key
				m.host.Go(func() error {
					defer zdnsutil.HandlePanic("Shared DTLCP client")
					m.cfg.ServeDTLCP(capturedDC, capturedSrc, func() {
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
			case dc.Ch <- DemuxPacket{Data: (*pb)[:n], Addr: src}:
			default:
				PacketBufPool.Put(pb)
			}
		}
	}
}
