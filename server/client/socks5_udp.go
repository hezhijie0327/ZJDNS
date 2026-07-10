package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
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
		return fmt.Errorf("%w: UDP ASSOCIATE %s", ErrSOCKS5CmdRejected, repString(resp[1]))
	}
	if resp[0] != socks5Version {
		_ = ctrlConn.Close()
		return fmt.Errorf("%w: UDP ASSOCIATE reply version %d", ErrSOCKS5Version, resp[0])
	}
	if resp[2] != socks5RSV {
		_ = ctrlConn.Close()
		return fmt.Errorf("%w: non-zero RSV byte %#x", ErrSOCKS5BadReply, resp[2])
	}

	relay, err := readAddress(ctrlConn, resp[3])
	if err != nil {
		_ = ctrlConn.Close()
		return fmt.Errorf("socks5: read relay address: %w", err)
	}

	// Non-standard implementations (v2ray/xray) bind the UDP relay on the
	// same port as the TCP proxy.  Handle BND.ADDR=0.0.0.0 and BND.PORT=0
	// by falling back to the proxy's own address.
	proxyHost, proxyPortStr, _ := net.SplitHostPort(d.proxyAddr)
	if relay.IP == nil || relay.IP.IsUnspecified() {
		if ip := net.ParseIP(proxyHost); ip != nil {
			relay.IP = ip
		}
	}
	if relay.Port == 0 {
		if p, err := strconv.Atoi(proxyPortStr); err == nil {
			relay.Port = p
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

	dg, srcAddr, err := parseDatagram((*buf)[:nr])
	if err != nil {
		return 0, nil, fmt.Errorf("socks5: parse UDP datagram: %w", err)
	}
	if len(p) < len(dg.data) {
		return 0, nil, io.ErrShortBuffer
	}
	n = copy(p, dg.data)
	return n, srcAddr, nil
}

// WriteTo wraps data in a SOCKS5 UDP header and sends it through the
// connected relay socket.
func (c *socks5PacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, fmt.Errorf("socks5: expected *net.UDPAddr, got %T", addr)
	}

	headerLen := datagramHeaderLen(udpAddr)
	totalLen := headerLen + len(p)
	if totalLen > socks5MaxReadBuf {
		return 0, fmt.Errorf("socks5: datagram too large: %d bytes", totalLen)
	}

	var buf []byte
	if totalLen <= 1500 {
		bp := socks5WritePool.Get().(*[]byte)
		buf = (*bp)[:totalLen]
		defer socks5WritePool.Put(bp)
	} else {
		buf = make([]byte, totalLen)
	}

	writeDatagramHeader(buf, udpAddr)
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

// ---------------------------------------------------------------------------
// net.Conn wrapper — for protocols that expect direct Read/Write on a
// SOCKS5 UDP relay (e.g. DNSCrypt).  Mirrors golang.org/x/net/proxy's
// Dial("udp", addr) which returns a net.Conn.
// ---------------------------------------------------------------------------

// DialUDP establishes a new UDP connection to targetAddr through the
// SOCKS5 proxy — each call creates a fresh UDP ASSOCIATE and returns an
// independent net.Conn.  Matches golang.org/x/net/proxy.Dialer.Dial("udp").
func (d *SOCKS5Dialer) DialUDP(ctx context.Context, targetAddr string) (net.Conn, error) {
	// Create a fresh, independent dialer so the relay is not shared.
	fresh := &SOCKS5Dialer{
		proxyAddr: d.proxyAddr,
		username:  d.username,
		password:  d.password,
		timeout:   d.timeout,
	}
	if err := fresh.establishUDPRelay(ctx); err != nil {
		return nil, err
	}
	udpAddr, err := net.ResolveUDPAddr("udp", targetAddr)
	if err != nil {
		_ = fresh.Close()
		return nil, fmt.Errorf("socks5: resolve target %s: %w", targetAddr, err)
	}
	return &socks5UDPConn{
		conn: fresh.udpConn,
		addr: udpAddr,
		done: func() { _ = fresh.Close() },
	}, nil
}

// socks5UDPConn wraps a dedicated SOCKS5 UDP relay as a net.Conn.
type socks5UDPConn struct {
	conn *net.UDPConn
	addr *net.UDPAddr
	done func() // called on Close to tear down the relay
}

func (c *socks5UDPConn) Read(p []byte) (n int, err error) {
	buf := socks5ReadBufPool.Get().(*[]byte)
	defer socks5ReadBufPool.Put(buf)

	nr, err := c.conn.Read((*buf))
	if err != nil {
		return 0, err
	}

	dg, _, err := parseDatagram((*buf)[:nr])
	if err != nil {
		return 0, err
	}
	if len(p) < len(dg.data) {
		return 0, io.ErrShortBuffer
	}
	return copy(p, dg.data), nil
}

func (c *socks5UDPConn) Write(p []byte) (n int, err error) {
	headerLen := datagramHeaderLen(c.addr)
	totalLen := headerLen + len(p)
	if totalLen > socks5MaxReadBuf {
		return 0, fmt.Errorf("socks5: datagram too large: %d bytes", totalLen)
	}

	var buf []byte
	if totalLen <= 1500 {
		bp := socks5WritePool.Get().(*[]byte)
		buf = (*bp)[:totalLen]
		defer socks5WritePool.Put(bp)
	} else {
		buf = make([]byte, totalLen)
	}

	writeDatagramHeader(buf, c.addr)
	copy(buf[headerLen:], p)

	nw, err := c.conn.Write(buf)
	if err != nil {
		return 0, err
	}
	if nw < headerLen {
		return 0, fmt.Errorf("socks5: short write: %d < %d", nw, headerLen)
	}
	return nw - headerLen, nil
}

func (c *socks5UDPConn) Close() error                       { c.done(); return nil }
func (c *socks5UDPConn) LocalAddr() net.Addr                { return c.conn.LocalAddr() }
func (c *socks5UDPConn) RemoteAddr() net.Addr               { return c.addr }
func (c *socks5UDPConn) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *socks5UDPConn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *socks5UDPConn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }
