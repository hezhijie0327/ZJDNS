package client

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"sync"
	"time"

	"zjdns/config"
	"zjdns/internal/log"
)

// SOCKS5 pool buffer sizes.
const (
	socks5WriteBufSize = 1500 // MTU-sized buffer
	socks5ReadBufSize  = 8192 // Common DNS response size
	socks5MaxReadBuf   = 65535
)

// SOCKS5 protocol constants (RFC 1928).
const (
	socks5Version = 0x05

	// Authentication methods
	socks5AuthNoAuth   = 0x00
	socks5AuthPassword = 0x02

	// Commands
	socks5CmdConnect = 0x01
	socks5CmdUDP     = 0x03

	// Address types
	socks5ATYPIPv4   = 0x01
	socks5ATYPDomain = 0x03
	socks5ATYPIPv6   = 0x04

	// Response codes
	socks5RepSuccess = 0x00
)

// SOCKS5Dialer provides TCP and UDP connections through a SOCKS5 proxy.
// It implements both RFC 1928 (SOCKS5) and RFC 1929 (Username/Password auth).
//
// A single SOCKS5Dialer reuses its UDP relay — the TCP control connection
// stays alive as long as the relay is needed. If the control connection dies,
// the next ListenPacket call re-establishes it transparently.
type SOCKS5Dialer struct {
	proxyAddr string // host:port of the SOCKS5 proxy
	username  string // empty means no auth
	password  string
	timeout   time.Duration // connection + negotiation timeout

	mu         sync.RWMutex
	udpConn    *net.UDPConn  // connected UDP socket to relay
	relayAddr  *net.UDPAddr  // proxy's UDP relay address
	ctrlConn   net.Conn      // TCP control connection for UDP ASSOCIATE
	ctrlClosed chan struct{} // closed when ctrlConn dies
}

// NewSOCKS5Dialer parses a socks5://[user:pass@]host:port URL and returns
// a ready-to-use dialer. The timeout is used for proxy connection and
// negotiation.
func NewSOCKS5Dialer(proxyURL string, timeout time.Duration) (*SOCKS5Dialer, error) {
	u, err := url.Parse(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("parse proxy URL: %w", err)
	}
	if u.Scheme != "socks5" {
		return nil, fmt.Errorf("unsupported proxy scheme: %q (want socks5)", u.Scheme)
	}

	host := u.Hostname()
	if host == "" {
		return nil, fmt.Errorf("socks5: proxy host required")
	}
	port := u.Port()
	if port == "" {
		port = config.DefaultProxyPort
	}

	d := &SOCKS5Dialer{
		proxyAddr:  net.JoinHostPort(host, port),
		timeout:    timeout,
		ctrlClosed: make(chan struct{}),
	}
	if u.User != nil {
		d.username = u.User.Username()
		d.password, _ = u.User.Password()
	}
	return d, nil
}

// DialContext connects to targetAddr through the SOCKS5 proxy via TCP CONNECT.
// The returned net.Conn is a raw TCP connection forwarded through the proxy.
func (d *SOCKS5Dialer) DialContext(ctx context.Context, network string, targetAddr string) (net.Conn, error) {
	if network != "tcp" {
		return nil, fmt.Errorf("socks5: unsupported network %q (only tcp)", network)
	}

	deadline, hasDeadline := ctx.Deadline()

	dialer := net.Dialer{}
	if hasDeadline {
		dialer.Timeout = time.Until(deadline)
	}
	conn, err := dialer.DialContext(ctx, "tcp", d.proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("socks5: dial proxy %s: %w", d.proxyAddr, err)
	}

	if hasDeadline {
		if err := conn.SetDeadline(deadline); err != nil {
			_ = conn.Close()
			return nil, err
		}
	}

	if err := d.handshake(conn); err != nil {
		_ = conn.Close()
		return nil, err
	}

	if err := d.connect(conn, targetAddr); err != nil {
		_ = conn.Close()
		return nil, err
	}

	// Clear deadline — the caller manages I/O timeouts from here.
	_ = conn.SetDeadline(time.Time{})

	log.Debugf("UPSTREAM: SOCKS5 connected to %s via %s", targetAddr, d.SafeURL())
	return conn, nil
}

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

// SafeURL returns the proxy URL with password redacted for logging.
func (d *SOCKS5Dialer) SafeURL() string {
	if d.password != "" {
		return fmt.Sprintf("socks5://%s:***@%s", d.username, d.proxyAddr)
	}
	if d.username != "" {
		return fmt.Sprintf("socks5://%s@%s", d.username, d.proxyAddr)
	}
	return "socks5://" + d.proxyAddr
}

// Close terminates the UDP relay control connection and releases resources.
// Pending UDP operations will fail after Close.
func (d *SOCKS5Dialer) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.cleanupLocked()
	return nil
}

// ---------------------------------------------------------------------------
// Internal: handshake + request helpers
// ---------------------------------------------------------------------------

func (d *SOCKS5Dialer) handshake(conn net.Conn) error {
	// Build method list
	var methods []byte
	if d.username != "" {
		methods = []byte{socks5AuthNoAuth, socks5AuthPassword}
	} else {
		methods = []byte{socks5AuthNoAuth}
	}

	msg := make([]byte, 2+len(methods))
	msg[0] = socks5Version
	msg[1] = byte(len(methods))
	copy(msg[2:], methods)
	if _, err := conn.Write(msg); err != nil {
		return fmt.Errorf("socks5: send greeting: %w", err)
	}

	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return fmt.Errorf("socks5: read greeting: %w", err)
	}
	if resp[0] != socks5Version {
		return fmt.Errorf("socks5: bad version %d from proxy", resp[0])
	}

	switch resp[1] {
	case socks5AuthNoAuth:
		return nil
	case socks5AuthPassword:
		return d.authUserPass(conn)
	default:
		return fmt.Errorf("socks5: proxy requires unsupported auth method %#x", resp[1])
	}
}

func (d *SOCKS5Dialer) authUserPass(conn net.Conn) error {
	if len(d.username) > 255 || len(d.password) > 255 {
		return errors.New("socks5: username or password exceeds 255 bytes")
	}

	// RFC 1929: VER(1) | ULEN(1) | UNAME | PLEN(1) | PASSWD
	msg := make([]byte, 3+len(d.username)+len(d.password))
	msg[0] = 0x01 // auth sub-negotiation version
	msg[1] = byte(len(d.username))
	copy(msg[2:], d.username)
	msg[2+len(d.username)] = byte(len(d.password))
	copy(msg[3+len(d.username):], d.password)

	if _, err := conn.Write(msg); err != nil {
		return fmt.Errorf("socks5: send auth: %w", err)
	}

	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return fmt.Errorf("socks5: read auth response: %w", err)
	}
	if resp[1] != 0x00 {
		return errors.New("socks5: authentication failed — check username/password")
	}
	return nil
}

// connect sends a CONNECT request and skips the bind address in the response.
func (d *SOCKS5Dialer) connect(conn net.Conn, targetAddr string) error {
	host, port, err := splitHostPort(targetAddr)
	if err != nil {
		return err
	}
	req := buildSOCKS5Request(socks5CmdConnect, host, port)
	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("socks5: send CONNECT: %w", err)
	}

	resp := make([]byte, 4) // VER | REP | RSV | ATYP
	if _, err := io.ReadFull(conn, resp); err != nil {
		return fmt.Errorf("socks5: read CONNECT response: %w", err)
	}
	if resp[1] != socks5RepSuccess {
		return fmt.Errorf("socks5: CONNECT rejected, code %d", resp[1])
	}
	return skipAddress(conn, resp[3])
}

// ---------------------------------------------------------------------------
// Internal: UDP ASSOCIATE
// ---------------------------------------------------------------------------

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
		return fmt.Errorf("socks5: UDP dial did not return *net.UDPConn")
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

// socks5WritePool reuses buffers for SOCKS5 UDP write path.
// MTU-sized (1500) buffer covers DNS queries and typical QUIC datagrams;
// oversized writes fall back to heap allocation.
var socks5WritePool = sync.Pool{
	New: func() any { b := make([]byte, socks5WriteBufSize); return &b },
}

// socks5ReadPool reuses buffers for SOCKS5 UDP read path (exchangeViaProxyUDP).
// 8 KB covers the common DNS response size (~512–1232); larger responses
// get a fresh buffer from ReadFrom's internal cache.
var socks5ReadPool = sync.Pool{
	New: func() any { b := make([]byte, socks5ReadBufSize); return &b },
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

	nr, err := c.conn.Read((*buf)[:])
	if err != nil {
		return 0, nil, fmt.Errorf("socks5: read: %w", err)
	}

	data := (*buf)[:nr]

	// SOCKS5 UDP header: RSV(2) | FRAG(1) | ATYP(1) | DST.ADDR(var) | DST.PORT(2)
	if nr < 10 {
		return 0, nil, fmt.Errorf("socks5: UDP datagram too short: %d bytes", nr)
	}
	if data[0] != 0x00 || data[1] != 0x00 {
		return 0, nil, fmt.Errorf("socks5: invalid reserved bytes in UDP reply")
	}
	if data[2] != 0x00 {
		return 0, nil, fmt.Errorf("socks5: fragmented UDP datagram not supported")
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
		binary.BigEndian.PutUint16(buf[8:10], uint16(udpAddr.Port))
	} else {
		buf[3] = socks5ATYPIPv6
		copy(buf[4:20], udpAddr.IP.To16())
		binary.BigEndian.PutUint16(buf[20:22], uint16(udpAddr.Port))
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

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

// buildSOCKS5Request builds a SOCKS5 request: VER | CMD | RSV | ATYP | ADDR | PORT.
func buildSOCKS5Request(cmd byte, host string, port int) []byte {
	if port < 0 || port > 65535 {
		return nil
	}
	uport := uint16(port)
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			buf := make([]byte, 10) // 4 + 4 + 2
			buf[0], buf[1], buf[2] = socks5Version, cmd, 0x00
			buf[3] = socks5ATYPIPv4
			copy(buf[4:8], ip4)
			binary.BigEndian.PutUint16(buf[8:10], uport)
			return buf
		}
		buf := make([]byte, 22) // 4 + 16 + 2
		buf[0], buf[1], buf[2] = socks5Version, cmd, 0x00
		buf[3] = socks5ATYPIPv6
		copy(buf[4:20], ip)
		binary.BigEndian.PutUint16(buf[20:22], uport)
		return buf
	}

	// Domain name
	buf := make([]byte, 7+len(host)) // 4 + 1 + len(host) + 2
	buf[0], buf[1], buf[2] = socks5Version, cmd, 0x00
	buf[3] = socks5ATYPDomain
	buf[4] = byte(len(host))
	copy(buf[5:], host)
	binary.BigEndian.PutUint16(buf[5+len(host):], uport)
	return buf
}

// splitHostPort is like net.SplitHostPort but uses DefaultDNSPort when no port.
func splitHostPort(addr string) (host string, port int, err error) {
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		// Try adding default DNS port
		h = addr
		p = config.DefaultDNSPort
	}
	port, err = strconv.Atoi(p)
	if err != nil {
		return "", 0, fmt.Errorf("socks5: invalid port in %q: %w", addr, err)
	}
	return h, port, nil
}

// skipAddress reads and discards BND.ADDR + BND.PORT from a SOCKS5 response.
func skipAddress(conn net.Conn, atyp byte) error {
	_, err := readAddress(conn, atyp)
	return err
}

// readAddress parses BND.ADDR + BND.PORT from a SOCKS5 response and returns
// a *net.UDPAddr. The atyp byte must already have been read.
func readAddress(conn net.Conn, atyp byte) (*net.UDPAddr, error) {
	switch atyp {
	case socks5ATYPIPv4:
		buf := make([]byte, 4+2)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return nil, err
		}
		ip := net.IP(buf[:4])
		port := int(binary.BigEndian.Uint16(buf[4:6]))
		return &net.UDPAddr{IP: ip, Port: port}, nil

	case socks5ATYPIPv6:
		buf := make([]byte, 16+2)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return nil, err
		}
		ip := net.IP(buf[:16])
		port := int(binary.BigEndian.Uint16(buf[16:18]))
		return &net.UDPAddr{IP: ip, Port: port}, nil

	case socks5ATYPDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return nil, err
		}
		domainLen := int(lenBuf[0])
		rest := make([]byte, domainLen+2)
		if _, err := io.ReadFull(conn, rest); err != nil {
			return nil, err
		}
		host := string(rest[:domainLen])
		port := int(binary.BigEndian.Uint16(rest[domainLen:]))
		// Resolve the relay hostname to IP — SOCKS5 proxies usually return an
		// IP, but some return a domain. Use the standard resolver.
		ips, err := net.DefaultResolver.LookupIP(context.Background(), "ip", host)
		if err != nil || len(ips) == 0 {
			return nil, fmt.Errorf("socks5: resolve relay host %q: %w", host, err)
		}
		return &net.UDPAddr{IP: ips[0], Port: port}, nil

	default:
		return nil, fmt.Errorf("socks5: unsupported address type %#x", atyp)
	}
}

// parseAddressFromBytes parses a SOCKS5 address from a byte slice (used for
// UDP header parsing). Returns the parsed address and the number of bytes consumed.
func parseAddressFromBytes(data []byte, atyp byte) (*net.UDPAddr, int, error) {
	switch atyp {
	case socks5ATYPIPv4:
		if len(data) < 6 {
			return nil, 0, fmt.Errorf("truncated IPv4 address")
		}
		ip := net.IP(data[:4])
		port := int(binary.BigEndian.Uint16(data[4:6]))
		return &net.UDPAddr{IP: ip, Port: port}, 6, nil

	case socks5ATYPIPv6:
		if len(data) < 18 {
			return nil, 0, fmt.Errorf("truncated IPv6 address")
		}
		ip := net.IP(data[:16])
		port := int(binary.BigEndian.Uint16(data[16:18]))
		return &net.UDPAddr{IP: ip, Port: port}, 18, nil

	case socks5ATYPDomain:
		if len(data) < 1 {
			return nil, 0, fmt.Errorf("truncated domain length")
		}
		domainLen := int(data[0])
		if len(data) < 1+domainLen+2 {
			return nil, 0, fmt.Errorf("truncated domain address")
		}
		host := string(data[1 : 1+domainLen])
		port := int(binary.BigEndian.Uint16(data[1+domainLen:]))
		// The source address in UDP replies is from the actual server,
		// not the relay. We return the hostname:port as a UDPAddr.
		// Only resolve if it's an IP literal.
		if ip := net.ParseIP(host); ip != nil {
			return &net.UDPAddr{IP: ip, Port: port}, 1 + domainLen + 2, nil
		}
		// For domain names in UDP replies (unusual), resolve.
		return nil, 0, fmt.Errorf("domain name in UDP reply not supported (got %q)", host)

	default:
		return nil, 0, fmt.Errorf("unsupported address type %#x", atyp)
	}
}

// socks5UDPHeaderLen returns the number of bytes needed for the SOCKS5 UDP
// header for the given destination address.
func socks5UDPHeaderLen(addr *net.UDPAddr) (int, error) {
	if addr.IP.To4() != nil {
		return config.SOCKS5UDPHeaderLenIPv4, nil
	}
	if addr.IP.To16() != nil {
		return config.SOCKS5UDPHeaderLenIPv6, nil
	}
	return 0, fmt.Errorf("socks5: invalid destination IP: %v", addr.IP)
}
