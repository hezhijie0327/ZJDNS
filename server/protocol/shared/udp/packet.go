package udp

import (
	"net"
	"sync"
	"time"
)

// udpDemuxPacket is a queued packet with its source address.
type udpDemuxPacket struct {
	data   []byte
	remote net.Addr
}

// udpPacketConn is a per-client virtual net.PacketConn.  WriteTo goes
// directly to the real UDP socket; ReadFrom dequeues from the demux queue.
type udpPacketConn struct {
	realConn net.PacketConn
	queue    chan udpDemuxPacket
	remote   *net.UDPAddr
	closed   bool
	mu       sync.Mutex
}

func (c *udpPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	pkt, ok := <-c.queue
	if !ok {
		return 0, nil, net.ErrClosed
	}
	n := copy(p, pkt.data)
	return n, pkt.remote, nil
}

func (c *udpPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	return c.realConn.WriteTo(p, addr)
}

func (c *udpPacketConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed {
		c.closed = true
		close(c.queue)
	}
	return nil
}

func (c *udpPacketConn) LocalAddr() net.Addr                { return c.realConn.LocalAddr() }
func (c *udpPacketConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *udpPacketConn) SetWriteDeadline(t time.Time) error { return c.realConn.SetWriteDeadline(t) }
func (c *udpPacketConn) SetDeadline(t time.Time) error      { return c.realConn.SetDeadline(t) }
