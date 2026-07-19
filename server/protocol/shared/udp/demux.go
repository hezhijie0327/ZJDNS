package udp

import (
	"context"
	"errors"
	"net"
	"sync"
	"zjdns/internal/log"
)

// isQUICPacket reports whether the first byte of pkt indicates a valid QUIC
// packet.  QUIC v1 (RFC 9000) requires the Fixed Bit (0x40) to be set and
// the two reserved bits (0x0C) to be clear for all packets.
// demuxRoute represents a single protocol route in the UDP demux.
type demuxRoute struct {
	classifier func([]byte) bool // returns true if pkt belongs to this route
	pconn      *udpPacketConn    // virtual PacketConn for this route
}

// Demux reads datagrams from a shared *net.UDPConn and routes them to
// per-protocol virtual net.PacketConns.  Each route has a classifier function;
// the first matching route receives the packet.  Packets that match no route
// are dropped.
//
// Use PacketConn() to obtain a virtual net.PacketConn for a protocol, then
// pass it to the protocol's server (quic.Transport, dtls.Listener,
// DNSCrypt serve loop, etc.).
type Demux struct {
	conn   *net.UDPConn
	ctx    context.Context
	cancel context.CancelCauseFunc

	mu     sync.Mutex
	routes []*demuxRoute
	buf    []byte
	closed bool
}

// NewDemux creates a UDP demultiplexer that reads from conn.
// Call Start() to begin the read loop.
func NewDemux(conn *net.UDPConn) *Demux {
	ctx, cancel := context.WithCancelCause(context.Background())
	return &Demux{
		conn:   conn,
		ctx:    ctx,
		cancel: cancel,
		buf:    make([]byte, 65536),
	}
}

// PacketConn registers a new route with the given classifier and returns a
// virtual net.PacketConn that receives only packets matching that route.
// Routes are tried in registration order; the first match wins.
// Must be called before Start().
func (d *Demux) PacketConn(classifier func([]byte) bool) net.PacketConn {
	pconn := &udpPacketConn{
		realConn: d.conn,
		queue:    make(chan udpDemuxPacket, 256),
		remote:   nil, // set per-packet by the demux
	}
	d.routes = append(d.routes, &demuxRoute{
		classifier: classifier,
		pconn:      pconn,
	})
	return pconn
}

// Start begins the background demux read loop.
func (d *Demux) Start() {
	go d.readLoop()
}

// Close stops the demux and closes all virtual connections.
func (d *Demux) Close() error {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return nil
	}
	d.closed = true
	d.cancel(errors.New("UDP demux closed"))
	for _, r := range d.routes {
		_ = r.pconn.Close()
	}
	d.mu.Unlock()
	return d.conn.Close()
}

// readLoop reads from the shared socket and routes packets.
func (d *Demux) readLoop() {
	for {
		select {
		case <-d.ctx.Done():
			return
		default:
		}

		n, remoteAddr, err := d.conn.ReadFrom(d.buf)
		if err != nil {
			if d.ctx.Err() != nil {
				return
			}
			log.Debugf("SHARED: demux read error: %v", err)
			return
		}

		// Find the first matching route.
		pkt := d.buf[:n]
		d.mu.Lock()
		var matched *demuxRoute
		for _, r := range d.routes {
			if r.classifier(pkt) {
				matched = r
				break
			}
		}
		d.mu.Unlock()

		if matched == nil {
			log.Debugf("SHARED: demux no route for packet from %s (first byte 0x%02x)", remoteAddr, pkt[0])
			continue
		}

		// Enqueue a copy of the packet with its source address.
		queued := make([]byte, n)
		copy(queued, pkt)
		select {
		case matched.pconn.queue <- udpDemuxPacket{data: queued, remote: remoteAddr}:
		default:
			log.Debugf("SHARED: demux dropping packet for %s (queue full)", remoteAddr)
		}
	}
}
