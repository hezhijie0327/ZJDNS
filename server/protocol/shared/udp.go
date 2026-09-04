package shared

import (
	"io"
	"math"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"zjdns/config"
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
	Shared   *net.UDPConn
	Remote   net.Addr
	Ch       chan DemuxPacket
	lastSeen atomic.Int64 // unix seconds of the last dispatched datagram
	closed   atomic.Bool
	// sendMu serialises the dispatch-loop channel send against Close's
	// close(Ch): the protocol handler (idle timeout, error path) closes the
	// conn from ITS goroutine while the dispatch loop is sending — an
	// unguarded send on the closed channel panicked the whole dispatch
	// loop and killed the shared port.
	sendMu  sync.Mutex
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

type packetBuf struct {
	data []byte
	src  *net.UDPAddr
	n    int
}

type dtlsClientConn struct {
	ch       chan packetBuf
	shared   *net.UDPConn
	remote   net.Addr
	lastSeen atomic.Int64 // unix seconds of the last dispatched datagram
	closed   atomic.Bool
	// sendMu guards the dispatch send against the pion-side Close (idle
	// timeout closes the conn from the DTLS accept goroutine).
	sendMu sync.Mutex
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

type sharedDNSCryptClient struct {
	mu    sync.Mutex
	conns map[addrKey]*DemuxPacketConn
}

// ---------------------------------------------------------------------------
// Vars
// ---------------------------------------------------------------------------

// Client-state bounds for the shared UDP dispatch loop.  Every unique
// (source IP, port) gets a classification-map entry and, for
// connection-oriented UDP protocols, a per-client conn + goroutine —
// without a bound, NAT port churn or a spoofed-source flood grows them
// without limit.
const (
	// peerProtoMax caps the classification map; on overflow it is rebuilt
	// from scratch (classifications are re-derived from the next datagram).
	peerProtoMax = 1 << 16

	// quicDispatchQueue bounds the per-connection packet queue inside the
	// QUIC packet conn wrapper (backpressure depth, C-L6).
	quicDispatchQueue = 256

	// clientIdleTimeout bounds how long a silent per-client conn is kept.
	clientIdleTimeout = 60 * time.Second

	// reapCheckEveryPackets gates the reap clock reads and map scans to a
	// fixed amortised cost per datagram.
	reapCheckEveryPackets = 1024
)

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
	d.sendMu.Lock()
	defer d.sendMu.Unlock()
	if d.closed.CompareAndSwap(false, true) {
		close(d.Ch)
		// Drain queued datagrams back to the packet pool — up to 32 pooled
		// buffers per conn were simply GC'd under reap churn (L5).  The
		// sendMu critical section guarantees no concurrent Send races the
		// drain (Send returns false once closed is set).
		for pkt := range d.Ch {
			full := pkt.Data[:cap(pkt.Data)]
			PacketBufPool.Put(&full)
		}
	}
	return nil
}

// Send enqueues one datagram.  It reports false when the conn is closed or
// the queue is full — the caller must return the pool buffer.  ALL senders
// must go through this guarded path (sendMu + closed CAS): a bare send on
// the exported Ch races a concurrent Close with a panic that kills the
// whole dispatch loop (2026-09 P1 — the standalone DTLCP accept loop
// bypassed this guard exactly like that).
func (d *DemuxPacketConn) Send(pkt DemuxPacket) bool {
	d.sendMu.Lock()
	defer d.sendMu.Unlock()
	if d.closed.Load() {
		return false
	}
	select {
	case d.Ch <- pkt:
		return true
	default:
		return false
	}
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
		// io.ErrShortBuffer (net.Conn contract), NOT net.ErrClosed — a
		// merely-small caller buffer must not tear the connection down
		// (P-L3).
		return 0, pkt.src, io.ErrShortBuffer
	}
	n := copy(p, pkt.data[:pkt.n])
	PacketBufPool.Put(&pkt.data)
	return n, pkt.src, nil
}

func (c *dtlsClientConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	return c.shared.WriteTo(p, c.remote)
}

func (c *dtlsClientConn) Close() error {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
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
// Ownership of the pooled buffer pb transfers to the client channel (no
// second copy); pb is returned to the pool only on drop/closed paths.
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

	cc.lastSeen.Store(log.NowUnix())
	cc.sendMu.Lock()
	if cc.closed.Load() {
		cc.sendMu.Unlock()
		PacketBufPool.Put(pb)
		return
	}
	select {
	case cc.ch <- packetBuf{data: *pb, src: src, n: n}:
	default:
		PacketBufPool.Put(pb)
	}
	cc.sendMu.Unlock()
}

// ---------------------------------------------------------------------------
// QUIC packet conn
// ---------------------------------------------------------------------------

func newQUICPacketConn(udpConn *net.UDPConn) *quicPacketConn {
	return &quicPacketConn{
		ch:     make(chan packetBuf, quicDispatchQueue),
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
		if len(p) < pkt.n {
			PacketBufPool.Put(&pkt.data)
			// Silent truncation hides data loss — report it (P-L3).
			return 0, pkt.src, io.ErrShortBuffer
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
func (c *quicPacketConn) SetReadBuffer(bytes int) error      { return c.shared.SetReadBuffer(bytes) }

func (c *quicPacketConn) SetWriteBuffer(bytes int) error { return c.shared.SetWriteBuffer(bytes) }

func (c *quicPacketConn) dispatch(src *net.UDPAddr, pb *[]byte, n int) {
	select {
	case c.ch <- packetBuf{data: *pb, src: src, n: n}:
	default:
		PacketBufPool.Put(pb)
	}
}

// ---------------------------------------------------------------------------
// startUDPGroup — start one UDP shared port group
// ---------------------------------------------------------------------------

func (m *Mux) startUDPGroup(g *UDPGroup) error {
	addrs, err := zdnsutil.ResolveBindAddrs("udp", g.Port)
	if err != nil {
		return err
	}

	// Build a log label reflecting the active protocol combination.
	label := "SHARED"
	var parts []string
	if g.DOQHandler != nil {
		parts = append(parts, "DoQ")
	}
	if g.HTTP3Handler != nil {
		parts = append(parts, "DoH3")
	}
	if g.DTLSHandler != nil {
		parts = append(parts, "DTLS")
	}
	if g.ServeDTLCP != nil {
		parts = append(parts, "DTLCP")
	}
	if g.ServeDNSCrypt != nil {
		parts = append(parts, "DNSCrypt")
	}
	if len(parts) > 0 {
		label += ": " + joinStrings(parts, ", ")
	}
	log.Infof("%s server started on %v", label, addrs)
	for _, addr := range addrs {
		udpAddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			return err
		}

		udpConn, err := net.ListenUDP("udp", udpAddr)
		if err != nil {
			return err
		}

		rt := &udpRuntime{
			cfg:  g,
			conn: udpConn,
		}

		if g.DTLSHandler != nil || g.ServeDTLCP != nil {
			rt.dtlsPL = newDTLSPacketListener(udpConn)
		}

		if g.ServeDNSCrypt != nil {
			rt.dcState = &sharedDNSCryptClient{
				conns: make(map[addrKey]*DemuxPacketConn),
			}
		}

		if g.ServeDTLCP != nil {
			rt.dtlcpState = &sharedDTLSClient{
				conns: make(map[addrKey]*DemuxPacketConn),
			}
		}

		// Flood bound for per-client handler goroutines (P3).
		rt.clientSem = make(chan struct{}, config.DefaultServerGoroutineLimit)

		if g.DOQHandler != nil {
			rt.quicPC = newQUICPacketConn(udpConn)

			capturedQUIC := rt.quicPC
			capturedHandler := g.DOQHandler
			m.host.Go(func() error {
				defer zdnsutil.HandlePanic("Shared DoQ server")
				if err := capturedHandler(capturedQUIC); err != nil {
					if m.host.Ctx().Err() != nil {
						return nil
					}
					log.Warnf("TLS: shared-port DoQ error: %v", err)
				}
				return nil
			})
		}

		if g.HTTP3Handler != nil {
			rt.h3PC = newQUICPacketConn(udpConn)

			capturedH3 := rt.h3PC
			capturedHandler := g.HTTP3Handler
			m.host.Go(func() error {
				defer zdnsutil.HandlePanic("Shared DoH3 server")
				if err := capturedHandler(capturedH3); err != nil {
					if m.host.Ctx().Err() != nil {
						return nil
					}
					log.Warnf("TLS: shared-port DoH3 error: %v", err)
				}
				return nil
			})
		}

		if g.DTLSHandler != nil {
			capturedDTLS := rt.dtlsPL
			capturedHandler := g.DTLSHandler
			m.host.Go(func() error {
				defer zdnsutil.HandlePanic("Shared DTLS server")
				if err := capturedHandler(capturedDTLS); err != nil {
					if m.host.Ctx().Err() != nil {
						return nil
					}
					log.Warnf("TLS: shared-port DTLS error: %v", err)
				}
				return nil
			})
		}

		m.mu.Lock()
		m.udpRuntimes = append(m.udpRuntimes, rt)
		m.mu.Unlock()

		capturedRT := rt
		m.host.Go(func() error {
			defer zdnsutil.HandlePanic("Shared UDP dispatch")
			m.udpDispatchLoop(capturedRT)
			return nil
		})
	}
	return nil
}

// joinStrings joins strings with a separator (avoids importing strings
// for a single Join call in the log label builder).
func joinStrings(elems []string, sep string) string {
	if len(elems) == 0 {
		return ""
	}
	var result strings.Builder
	result.WriteString(elems[0])
	for _, e := range elems[1:] {
		result.WriteString(sep + e)
	}
	return result.String()
}

// udpDispatchLoop reads datagrams from the shared UDP socket,
// detects DNSCrypt vs QUIC vs DTLS vs DTLCP from the first datagram of
// each client, and routes subsequent datagrams accordingly.
// DNSCrypt classification (via ClassifyDNSCrypt callback) runs before
// QUIC/DTLS/DTLCP detection because DNSCrypt client magic may collide
// with those protocols' byte ranges.
//
// Per-packet allocation-free: the read buffer is pooled (PacketBufPool),
// the map key is a value-type addrKey (no src.String()), and the pooled
// buffer is passed through channels — consumers copy out and return it.
func (m *Mux) udpDispatchLoop(rt *udpRuntime) {
	g := rt.cfg
	udpConn := rt.conn
	dtlsPL := rt.dtlsPL
	quicPC := rt.quicPC
	h3PC := rt.h3PC
	dnscryptState := rt.dcState
	dtlcpState := rt.dtlcpState

	peerProto := make(map[addrKey]string)
	var peerMu sync.RWMutex

	// Read bound: 8 KiB (pool.SecureBufferSize).  Go's ReadFromUDP
	// silently truncates larger datagrams; QUIC initial packets are ≤1280
	// by design and DNSCrypt frames are capped at 4096, so this bound is
	// safe for every multiplexed protocol (standalone DoQ/DoH3 listeners,
	// where quic-go reads the raw socket itself, are unaffected) (P-L4).
	buf := make([]byte, pool.SecureBufferSize)

	var pktCount uint32
	var lastReap time.Time

	// Exit sweep: closing every per-client conn unblocks the parked client
	// goroutines (DNSCrypt drain `<-Ch`, DTLCP handshake reads) — without
	// this they leaked past Shutdown and stalled the server's background
	// group wait for its full timeout (2026-09 X4).
	defer reapIdleUDPClients(dtlcpState, dnscryptState, dtlsPL, math.MaxInt64)

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

		// Amortised idle-client reaping: per-client conns whose peer went
		// silent are closed and forgotten, bounding the maps under NAT
		// churn and spoofed-source floods.  Runs inline in the dispatch
		// loop — the ONLY sender to the per-client channels — so closing
		// under the map lock cannot race a concurrent dispatch.
		pktCount++
		if pktCount%reapCheckEveryPackets == 0 {
			// Classification-map bound: checked every gate regardless of the
			// reap clock — under a spoofed-source flood the map can exceed
			// peerProtoMax within a single 30s reap window (2026-09 P3).
			peerMu.Lock()
			if len(peerProto) >= peerProtoMax {
				peerProto = make(map[addrKey]string, peerProtoMax)
			}
			peerMu.Unlock()
			if now := time.Now(); now.Sub(lastReap) >= clientIdleTimeout/2 {
				lastReap = now
				cutoff := now.Unix() - int64(clientIdleTimeout/time.Second)
				reapIdleUDPClients(dtlcpState, dnscryptState, dtlsPL, cutoff)
			}
		}

		key := makeAddrKey(src)

		peerMu.RLock()
		proto, known := peerProto[key]
		peerMu.RUnlock()

		if !known {
			// 1. DNSCrypt encrypted query detection (priority — client_magic
			//    may collide with QUIC/DTLS byte ranges).
			if g.ClassifyDNSCrypt != nil {
				proto = g.ClassifyDNSCrypt((*pb)[:n])
			}
			// 2. Standard QUIC/DTLS/DTLCP detection.
			if proto == "" {
				proto = demux.DetectUDPProtocol((*pb)[:n])
			}
			// 3. DNSCrypt cert handshake fallback: the cert fetch is a
			//    plain DNS TXT query (no client_magic), so it does not match
			//    steps 1–2.  Route to DNSCrypt when configured — it handles
			//    both cert handshakes and encrypted queries.
			if proto == "" && g.ServeDNSCrypt != nil {
				proto = demux.ProtoDNSCrypt
			}
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
			// Route to DoQ handler if available; otherwise fall back
			// to HTTP3 handler (both use QUIC and are indistinguishable
			// at the byte level — port assignment determines the protocol).
			switch {
			case quicPC != nil:
				quicPC.dispatch(src, pb, n)
			case h3PC != nil:
				h3PC.dispatch(src, pb, n)
			default:
				PacketBufPool.Put(pb)
			}

		case demux.ProtoDTLS:
			if g.DTLSHandler != nil {
				dtlsPL.dispatch(src, pb, n)
			} else {
				PacketBufPool.Put(pb)
			}

		case demux.ProtoDTLCP:
			if g.ServeDTLCP == nil {
				PacketBufPool.Put(pb)
				continue
			}
			dtlcpState.mu.Lock()
			dc, ok := dtlcpState.conns[key]
			if !ok {
				if !rt.admit() {
					// Per-client cap reached — spoofed-source flood bound;
					// drop like a full queue, the client retransmits (P3).
					dtlcpState.mu.Unlock()
					PacketBufPool.Put(pb)
					continue
				}
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
				capturedHandler := g.ServeDTLCP
				m.host.Go(func() error {
					defer zdnsutil.HandlePanic("Shared DTLCP client")
					defer rt.release()
					capturedHandler(capturedDC, capturedSrc, func() {
						dtlcpState.mu.Lock()
						delete(dtlcpState.conns, capturedKey)
						dtlcpState.mu.Unlock()
					})
					return nil
				})
			} else {
				dtlcpState.mu.Unlock()
			}

			dc.lastSeen.Store(log.NowUnix())
			if !dc.Send(DemuxPacket{Data: (*pb)[:n], Addr: src}) {
				PacketBufPool.Put(pb)
			}

		case demux.ProtoDNSCrypt:
			if dnscryptState == nil || g.ServeDNSCrypt == nil {
				PacketBufPool.Put(pb)
				continue
			}
			dnscryptState.mu.Lock()
			dc, ok := dnscryptState.conns[key]
			if !ok {
				if !rt.admit() {
					// Per-client cap reached — spoofed-source flood bound (P3).
					dnscryptState.mu.Unlock()
					PacketBufPool.Put(pb)
					continue
				}
				dc = &DemuxPacketConn{
					Shared: udpConn,
					Remote: src,
					Ch:     make(chan DemuxPacket, 32),
				}
				dnscryptState.conns[key] = dc
				dnscryptState.mu.Unlock()

				capturedDC := dc
				capturedHandler := g.ServeDNSCrypt
				// Per-client worker admission: DNSCrypt queries are stateless
				// datagrams, so each packet goes to its own goroutine — the
				// former synchronous drain (decrypt→resolve→respond inline in
				// the drain loop) let one slow upstream stall every later
				// packet of the client.  Saturated → drop (client retransmits).
				sem := make(chan struct{}, config.DefaultMaxPipe)
				m.host.Go(func() error {
					defer zdnsutil.HandlePanic("Shared DNSCrypt UDP client")
					defer rt.release()
					for {
						pkt, pktOk := <-capturedDC.Ch
						if !pktOk {
							return nil
						}
						select {
						case sem <- struct{}{}:
						default:
							full := pkt.Data[:cap(pkt.Data)]
							PacketBufPool.Put(&full)
							continue
						}
						go func(pkt DemuxPacket) {
							defer func() { <-sem }()
							defer zdnsutil.HandlePanic("Shared DNSCrypt UDP query")
							capturedHandler(m.host.Ctx(), pkt.Data, pkt.Addr, capturedDC)
							full := pkt.Data[:cap(pkt.Data)]
							PacketBufPool.Put(&full)
						}(pkt)
					}
				})
			} else {
				dnscryptState.mu.Unlock()
			}

			dc.lastSeen.Store(log.NowUnix())
			if !dc.Send(DemuxPacket{Data: (*pb)[:n], Addr: src}) {
				PacketBufPool.Put(pb)
			}
		}
	}
}

// reapIdleUDPClients closes and forgets per-client conns idle since before
// the cutoff (unix seconds) across the DTLCP, DNSCrypt and DTLS client
// maps.  Must be called from the dispatch loop — the sole channel sender —
// so a close can never race an in-flight dispatch send.  Closing the
// channels unblocks the parked client goroutines (DNSCrypt drain loop,
// DTLCP handler read, DTLS accept read), which then run their own cleanup
// callbacks; the double delete is idempotent.
func reapIdleUDPClients(dtlcpState *sharedDTLSClient, dnscryptState *sharedDNSCryptClient, dtlsPL *dtlsPacketListener, cutoff int64) {
	// Close() (not a bare close(Ch)) — the CAS guard makes a later
	// handler-side Close idempotent instead of panicking on double close.
	if dtlcpState != nil {
		dtlcpState.mu.Lock()
		for k, dc := range dtlcpState.conns {
			if dc.lastSeen.Load() < cutoff {
				delete(dtlcpState.conns, k)
				_ = dc.Close()
			}
		}
		dtlcpState.mu.Unlock()
	}
	if dnscryptState != nil {
		dnscryptState.mu.Lock()
		for k, dc := range dnscryptState.conns {
			if dc.lastSeen.Load() < cutoff {
				delete(dnscryptState.conns, k)
				_ = dc.Close()
			}
		}
		dnscryptState.mu.Unlock()
	}
	if dtlsPL != nil {
		dtlsPL.mu.Lock()
		for k, cc := range dtlsPL.clients {
			if cc.lastSeen.Load() < cutoff {
				delete(dtlsPL.clients, k)
				_ = cc.Close()
			}
		}
		dtlsPL.mu.Unlock()
	}
}
