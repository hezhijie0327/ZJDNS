// Per-client virtual packet connections over the shared UDP port: the
// demux packet conn (deadline-aware queue reader), and the DTLS/QUIC
// client-side conns the dispatcher hands to each protocol stack.

package shared

import (
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
	"zjdns/internal/pool"
)

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

type quicPacketConn struct {
	ch     chan packetBuf
	shared *net.UDPConn
	closed atomic.Bool
	done   chan struct{}
}

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

func (d *DemuxPacketConn) LocalAddr() net.Addr { return d.Shared.LocalAddr() }

func (d *DemuxPacketConn) RemoteAddr() net.Addr { return d.Remote }

func (d *DemuxPacketConn) SetDeadline(t time.Time) error { return d.SetReadDeadline(t) }

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

func (c *dtlsClientConn) LocalAddr() net.Addr { return c.shared.LocalAddr() }

func (c *dtlsClientConn) RemoteAddr() net.Addr { return c.remote }

func (c *dtlsClientConn) SetDeadline(_ time.Time) error { return nil }

func (c *dtlsClientConn) SetReadDeadline(_ time.Time) error { return nil }

func (c *dtlsClientConn) SetWriteDeadline(_ time.Time) error { return nil }

// ---------------------------------------------------------------------------
// DTLS packet listener
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

func (c *quicPacketConn) LocalAddr() net.Addr { return c.shared.LocalAddr() }

func (c *quicPacketConn) SetDeadline(_ time.Time) error { return nil }

func (c *quicPacketConn) SetReadDeadline(_ time.Time) error { return nil }

func (c *quicPacketConn) SetWriteDeadline(_ time.Time) error { return nil }

func (c *quicPacketConn) SetReadBuffer(bytes int) error { return c.shared.SetReadBuffer(bytes) }

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
