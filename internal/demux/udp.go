package demux

import (
	"net"
	"sync"
	"time"
)

// udpPacket is a single datagram with its source address.
type udpPacket struct {
	data []byte
	addr net.Addr
}

// packetQueue is a per-protocol datagram queue that implements net.PacketConn.
// The demux read loop pushes datagrams into the queue; the protocol-specific
// server pulls them via ReadFrom().  WriteTo() sends through the shared
// underlying UDP socket.
type packetQueue struct {
	ch     chan *udpPacket
	ctx    chan struct{} // closed on Close
	conn   *net.UDPConn  // shared socket for WriteTo
	addr   net.Addr
	mu     sync.Mutex
	closed bool
}

// UDPConfig configures a UDP demux.
//
// Conn is the shared UDP socket to read datagrams from.
// Routes maps protocol family names ("quic", "dtls", "dtlcp") to handler
// callbacks.  Each callback receives the source address and datagram bytes;
// it returns true if the datagram was accepted, false if rejected (the
// datagram is silently dropped).
type UDPConfig struct {
	Conn   *net.UDPConn
	Routes map[string]func(addr net.Addr, data []byte) bool
}

// UDPDemuxListener demultiplexes UDP datagrams by protocol.  The first
// datagram from each client address is inspected via DetectUDPProtocol;
// the result is cached so subsequent datagrams from the same address
// skip detection.
type UDPDemuxListener struct {
	conn    *net.UDPConn
	routes  map[string]func(addr net.Addr, data []byte) bool
	queues  map[string]*packetQueue
	peers   map[string]string // client addr string → detected protocol
	peersMu sync.RWMutex
	mu      sync.Mutex
	closed  bool
	done    chan struct{}
}

func newPacketQueue(conn *net.UDPConn, addr net.Addr) *packetQueue {
	return &packetQueue{
		ch:   make(chan *udpPacket, 256),
		ctx:  make(chan struct{}),
		conn: conn,
		addr: addr,
	}
}

// ReadFrom waits for and returns the next datagram from the demux.
func (q *packetQueue) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	select {
	case pkt, ok := <-q.ch:
		if !ok {
			return 0, nil, net.ErrClosed
		}
		n = copy(p, pkt.data)
		return n, pkt.addr, nil
	case <-q.ctx:
		return 0, nil, net.ErrClosed
	}
}

// WriteTo sends a datagram through the shared UDP socket.
func (q *packetQueue) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, &net.AddrError{Err: "non-UDP address", Addr: addr.String()}
	}
	return q.conn.WriteToUDP(p, udpAddr)
}

// Close shuts down the queue.
func (q *packetQueue) Close() error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return nil
	}
	q.closed = true
	close(q.ctx)
	return nil
}

// LocalAddr returns the shared socket's local address.
func (q *packetQueue) LocalAddr() net.Addr {
	return q.addr
}

// SetDeadline, SetReadDeadline, SetWriteDeadline are no-ops on the virtual
// queue — the shared socket's deadlines apply globally.
func (q *packetQueue) SetDeadline(_ time.Time) error     { return nil }
func (q *packetQueue) SetReadDeadline(_ time.Time) error { return nil }
func (q *packetQueue) SetWriteDeadline(_ time.Time) error {
	return nil
}

// push enqueues a datagram.  Returns false if the queue is closed or full.
func (q *packetQueue) push(pkt *udpPacket) bool {
	select {
	case q.ch <- pkt:
		return true
	case <-q.ctx:
		return false
	default:
		return false
	}
}

// NewUDPDemux creates and starts a UDP demux.  The read loop runs in a
// background goroutine and exits when Close() is called.
func NewUDPDemux(cfg UDPConfig) *UDPDemuxListener {
	d := &UDPDemuxListener{
		conn:   cfg.Conn,
		routes: cfg.Routes,
		queues: make(map[string]*packetQueue),
		peers:  make(map[string]string),
		done:   make(chan struct{}),
	}

	for proto := range cfg.Routes {
		d.queues[proto] = newPacketQueue(cfg.Conn, cfg.Conn.LocalAddr())
	}

	go d.readLoop()
	return d
}

// PacketConn returns the virtual net.PacketConn for the given protocol.
// The returned PacketConn yields datagrams whose protocol was detected
// as "protocol".  WriteTo sends through the shared UDP socket.
//
// Returns nil if no route is configured for the protocol.
func (d *UDPDemuxListener) PacketConn(protocol string) net.PacketConn {
	d.mu.Lock()
	defer d.mu.Unlock()
	if q, ok := d.queues[protocol]; ok {
		return q
	}
	return nil
}

// Close stops the read loop and closes all per-protocol queues.
func (d *UDPDemuxListener) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil
	}
	d.closed = true
	for _, q := range d.queues {
		_ = q.Close()
	}
	return nil
}

// Done returns a channel that is closed when the read loop exits.
func (d *UDPDemuxListener) Done() <-chan struct{} {
	return d.done
}

func (d *UDPDemuxListener) readLoop() {
	defer close(d.done)

	buf := make([]byte, 65535)
	for {
		n, remoteAddr, err := d.conn.ReadFromUDP(buf)
		if err != nil {
			d.mu.Lock()
			closed := d.closed
			d.mu.Unlock()
			if closed {
				return
			}
			continue
		}

		// Copy the datagram data — the buffer is reused.
		data := make([]byte, n)
		copy(data, buf[:n])

		addrKey := remoteAddr.String()

		// Determine the protocol for this client.
		proto := d.peerProtocol(addrKey, data)
		if proto == "" {
			continue
		}

		// Try the route callback first.
		if handler, ok := d.routes[proto]; ok {
			if handler(remoteAddr, data) {
				continue
			}
		}

		// Fall back to the packet queue.
		if q, ok := d.queues[proto]; ok {
			q.push(&udpPacket{data: data, addr: remoteAddr})
		}
	}
}

// peerProtocol returns the cached protocol for the client, or detects
// it from the first datagram and caches the result.
func (d *UDPDemuxListener) peerProtocol(addrKey string, data []byte) string {
	// Fast path: cached.
	d.peersMu.RLock()
	proto, ok := d.peers[addrKey]
	d.peersMu.RUnlock()
	if ok {
		return proto
	}

	// Slow path: detect and cache.
	proto = DetectUDPProtocol(data)
	if proto == "" {
		return ""
	}

	d.peersMu.Lock()
	d.peers[addrKey] = proto
	d.peersMu.Unlock()
	return proto
}
