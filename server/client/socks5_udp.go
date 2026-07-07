package client

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// ListenPacket returns a net.PacketConn that sends and receives UDP datagrams
// through the SOCKS5 proxy's UDP relay (RFC 1928 §6).
//
// The returned PacketConn wraps SOCKS5 UDP headers transparently — callers
// use WriteTo/ReadFrom with the real target address, not the relay address.
//
// The underlying TCP control connection stays alive; if the proxy closes it,
// the next ListenPacket call re-establishes the relay automatically.
func (d *SOCKS5Dialer) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	// Fast path: read-lock to check if the relay is alive.
	d.mu.RLock()
	if d.ctrlConn != nil {
		select {
		case <-d.ctrlClosed:
			// Relay died — fall through to slow path.
		default:
			pc := d.wrapPacketConn()
			d.mu.RUnlock()
			return pc, nil
		}
	}
	d.mu.RUnlock()

	// Slow path: take write lock and (re-)establish the relay.
	d.mu.Lock()
	defer d.mu.Unlock()

	// Double-check: another goroutine might have established while we waited.
	if d.ctrlConn != nil {
		select {
		case <-d.ctrlClosed:
			d.cleanupLocked()
		default:
			return d.wrapPacketConn(), nil
		}
	}

	if err := d.establishUDPRelay(ctx); err != nil {
		return nil, err
	}
	return d.wrapPacketConn(), nil
}

func (d *SOCKS5Dialer) establishUDPRelay(ctx context.Context) error {
	deadline, hasDeadline := ctx.Deadline()

	dialer := net.Dialer{}
	if hasDeadline {
		dialer.Timeout = time.Until(deadline)
	}
	ctrlConn, err := dialer.DialContext(ctx, "tcp", d.proxyAddr)
	if err != nil {
		return fmt.Errorf("socks5: dial proxy for UDP relay: %w", err)
	}

	if hasDeadline {
		if err := ctrlConn.SetDeadline(deadline); err != nil {
			_ = ctrlConn.Close()
			return err
		}
	}

	if err := d.handshake(ctrlConn); err != nil {
		_ = ctrlConn.Close()
		return err
	}

	// RFC 1928 §6: UDP ASSOCIATE with 0.0.0.0:0 requests the proxy to allocate a relay.
	req := buildSOCKS5Request(socks5CmdUDP, "0.0.0.0", 0)
	if _, err := ctrlConn.Write(req); err != nil {
		_ = ctrlConn.Close()
		return fmt.Errorf("socks5: send UDP ASSOCIATE: %w", err)
	}

	resp := make([]byte, 4) // VER | REP | RSV | ATYP
	if _, err := io.ReadFull(ctrlConn, resp); err != nil {
		_ = ctrlConn.Close()
		return fmt.Errorf("socks5: read UDP ASSOCIATE response: %w", err)
	}
	if resp[1] != socks5RepSuccess {
		_ = ctrlConn.Close()
		return fmt.Errorf("socks5: UDP ASSOCIATE rejected, code %d", resp[1])
	}

	relay, err := readAddress(ctrlConn, resp[3])
	if err != nil {
		_ = ctrlConn.Close()
		return fmt.Errorf("socks5: read relay address: %w", err)
	}

	// If the proxy returns 0.0.0.0 as the relay address, it means "send to
	// the proxy's own IP". Substitute the proxy's IP from the control connection.
	if relay.IP.IsUnspecified() {
		proxyHost, _, _ := net.SplitHostPort(d.proxyAddr)
		if ip := net.ParseIP(proxyHost); ip != nil {
			relay.IP = ip
		}
	}

	// Use a connected UDP socket to the relay (same approach as mosdns-x).
	// A connected socket allows us to use Read/Write directly and the OS
	// filters out stray datagrams.
	rawConn, err := dialer.DialContext(context.Background(), "udp", relay.String())
	if err != nil {
		_ = ctrlConn.Close()
		return fmt.Errorf("socks5: dial UDP relay %s: %w", relay.String(), err)
	}
	udpConn, ok := rawConn.(*net.UDPConn)
	if !ok {
		_ = rawConn.Close()
		_ = ctrlConn.Close()
		return errors.New("socks5: UDP dial did not return *net.UDPConn")
	}

	// Clear deadline on the control connection — it must stay alive but idle.
	_ = ctrlConn.SetDeadline(time.Time{})

	ctrlClosed := make(chan struct{})
	d.ctrlConn = ctrlConn
	d.ctrlClosed = ctrlClosed
	d.udpConn = udpConn
	d.relayAddr = relay

	// Monitor the control connection. If the proxy closes it, the relay
	// becomes invalid — signal that so the next caller can re-establish.
	go func() {
		var buf [1]byte
		_, _ = ctrlConn.Read(buf[:])
		d.mu.Lock()
		if d.ctrlConn == ctrlConn {
			d.cleanupLocked()
		}
		d.mu.Unlock()
	}()

	return nil
}

func (d *SOCKS5Dialer) wrapPacketConn() net.PacketConn {
	return &socks5PacketConn{
		conn: d.udpConn,
	}
}

func (d *SOCKS5Dialer) cleanupLocked() {
	if d.ctrlConn != nil {
		_ = d.ctrlConn.Close()
		d.ctrlConn = nil
		d.ctrlClosed = make(chan struct{})
	}
	if d.udpConn != nil {
		_ = d.udpConn.Close()
		d.udpConn = nil
	}
	d.relayAddr = nil
}

// ---------------------------------------------------------------------------
// PacketConn wrapper — transparent SOCKS5 UDP header handling
//
// The underlying *net.UDPConn is connected to the SOCKS5 relay, so we use
// Read/Write directly (not ReadFrom/WriteTo). Each datagram is wrapped in
// a SOCKS5 UDP header on write and unwrapped on read.
// ---------------------------------------------------------------------------

// socks5ReadBufPool reuses 64 KB buffers for SOCKS5 UDP reads, avoiding a
// per-connection 64 KB heap allocation from an embedded array.
var socks5ReadBufPool = sync.Pool{
	New: func() any { b := make([]byte, socks5MaxReadBuf); return &b },
}

type socks5PacketConn struct {
	conn *net.UDPConn
}

// ReadFrom reads a datagram from the relay, strips the SOCKS5 UDP header,
// and returns the payload with the real source address.
func (c *socks5PacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	buf := socks5ReadBufPool.Get().(*[]byte)
	defer socks5ReadBufPool.Put(buf)

	nr, err := c.conn.Read((*buf))
	if err != nil {
		return 0, nil, fmt.Errorf("socks5: read: %w", err)
	}

	data := (*buf)[:nr]

	// SOCKS5 UDP header: RSV(2) | FRAG(1) | ATYP(1) | DST.ADDR(var) | DST.PORT(2)
	if nr < 10 {
		return 0, nil, fmt.Errorf("socks5: UDP datagram too short: %d bytes", nr)
	}
	if data[0] != 0x00 || data[1] != 0x00 {
		return 0, nil, errors.New("socks5: invalid reserved bytes in UDP reply")
	}
	if data[2] != 0x00 {
		return 0, nil, errors.New("socks5: fragmented UDP datagram not supported")
	}

	atyp := data[3]
	srcAddr, headerLen, err := parseAddressFromBytes(data[4:nr], atyp)
	if err != nil {
		return 0, nil, fmt.Errorf("socks5: parse UDP header: %w", err)
	}

	payload := data[4+headerLen : nr]
	if len(p) < len(payload) {
		return 0, nil, io.ErrShortBuffer
	}
	n = copy(p, payload)
	return n, srcAddr, nil
}

// WriteTo wraps data in a SOCKS5 UDP header and sends it through the
// connected relay socket.
func (c *socks5PacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, fmt.Errorf("socks5: expected *net.UDPAddr, got %T", addr)
	}

	headerLen, err := socks5UDPHeaderLen(udpAddr)
	if err != nil {
		return 0, err
	}

	totalLen := headerLen + len(p)
	if totalLen > socks5MaxReadBuf {
		return 0, fmt.Errorf("socks5: datagram too large: %d bytes", totalLen)
	}

	// Use pool for typical MTU-sized writes; heap-allocate for larger.
	var buf []byte
	if totalLen <= 1500 {
		bp := socks5WritePool.Get().(*[]byte)
		buf = (*bp)[:totalLen]
		defer socks5WritePool.Put(bp)
	} else {
		buf = make([]byte, totalLen)
	}

	// RSV(2) | FRAG(1) — all zero.
	buf[0], buf[1], buf[2] = 0x00, 0x00, 0x00

	if ip4 := udpAddr.IP.To4(); ip4 != nil {
		buf[3] = socks5ATYPIPv4
		copy(buf[4:8], ip4)
		binary.BigEndian.PutUint16(buf[8:10], uint16(udpAddr.Port)) //nolint:gosec // G115: SOCKS5 UDP payload length — protocol-bounded uint16
	} else {
		buf[3] = socks5ATYPIPv6
		copy(buf[4:20], udpAddr.IP.To16())
		binary.BigEndian.PutUint16(buf[20:22], uint16(udpAddr.Port)) //nolint:gosec // G115: UDP port — protocol-bounded uint16
	}
	copy(buf[headerLen:], p)

	nw, err := c.conn.Write(buf)
	if err != nil {
		return 0, fmt.Errorf("socks5: write: %w", err)
	}
	if nw < headerLen {
		return 0, fmt.Errorf("socks5: short write: %d < %d", nw, headerLen)
	}
	return nw - headerLen, nil
}

func (c *socks5PacketConn) Close() error {
	return c.conn.Close()
}

func (c *socks5PacketConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *socks5PacketConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *socks5PacketConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *socks5PacketConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}
