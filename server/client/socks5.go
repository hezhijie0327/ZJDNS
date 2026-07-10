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

	// RFC 1928 §6: RSV field MUST be X'00'
	socks5RSV = 0x00

	// Reply codes (RFC 1928 §6)
	socks5RepSuccess             = 0x00
	socks5RepServerFailure       = 0x01
	socks5RepNotAllowed          = 0x02
	socks5RepNetworkUnreachable  = 0x03
	socks5RepHostUnreachable     = 0x04
	socks5RepConnectionRefused   = 0x05
	socks5RepTTLExpired          = 0x06
	socks5RepCommandNotSupported = 0x07
	socks5RepAddressNotSupported = 0x08
)

// repString returns a human-readable name for a SOCKS5 reply code.
func repString(rep byte) string {
	switch rep {
	case socks5RepSuccess:
		return "success"
	case socks5RepServerFailure:
		return "server failure"
	case socks5RepNotAllowed:
		return "not allowed by ruleset"
	case socks5RepNetworkUnreachable:
		return "network unreachable"
	case socks5RepHostUnreachable:
		return "host unreachable"
	case socks5RepConnectionRefused:
		return "connection refused"
	case socks5RepTTLExpired:
		return "TTL expired"
	case socks5RepCommandNotSupported:
		return "command not supported"
	case socks5RepAddressNotSupported:
		return "address type not supported"
	default:
		return fmt.Sprintf("unknown(%d)", rep)
	}
}

// Sentinel errors for SOCKS5 operations.
var (
	ErrSOCKS5Version     = errors.New("socks5: protocol version mismatch")
	ErrSOCKS5BadReply    = errors.New("socks5: malformed reply from proxy")
	ErrSOCKS5Auth        = errors.New("socks5: authentication failed")
	ErrSOCKS5NoAuth      = errors.New("socks5: proxy requires unsupported auth method")
	ErrSOCKS5CmdRejected = errors.New("socks5: command rejected by proxy")
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
		return nil, errors.New("socks5: proxy host required")
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
// Internal: handshake + auth
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
	msg[1] = byte(len(methods)) //nolint:gosec // G115: SOCKS5 methods count — max 255 fits byte
	copy(msg[2:], methods)
	if _, err := conn.Write(msg); err != nil {
		return fmt.Errorf("socks5: send greeting: %w", err)
	}

	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return fmt.Errorf("socks5: read greeting: %w", err)
	}
	if resp[0] != socks5Version {
		return fmt.Errorf("%w: got version %d", ErrSOCKS5Version, resp[0])
	}

	switch resp[1] {
	case socks5AuthNoAuth:
		return nil
	case socks5AuthPassword:
		return d.authUserPass(conn)
	default:
		return fmt.Errorf("%w: %#x", ErrSOCKS5NoAuth, resp[1])
	}
}

func (d *SOCKS5Dialer) authUserPass(conn net.Conn) error {
	if len(d.username) > 255 || len(d.password) > 255 {
		return errors.New("socks5: username or password exceeds 255 bytes")
	}

	// RFC 1929: VER(1) | ULEN(1) | UNAME | PLEN(1) | PASSWD
	msg := make([]byte, 3+len(d.username)+len(d.password))
	msg[0] = 0x01                  // auth sub-negotiation version
	msg[1] = byte(len(d.username)) //nolint:gosec // G115: SOCKS5 username length — max 255 fits byte
	copy(msg[2:], d.username)
	msg[2+len(d.username)] = byte(len(d.password)) //nolint:gosec // G115: SOCKS5 password length — max 255 fits byte
	copy(msg[3+len(d.username):], d.password)

	if _, err := conn.Write(msg); err != nil {
		return fmt.Errorf("socks5: send auth: %w", err)
	}

	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return fmt.Errorf("socks5: read auth response: %w", err)
	}
	if resp[1] != 0x00 {
		return ErrSOCKS5Auth
	}
	return nil
}

// ---------------------------------------------------------------------------
// Pools
// ---------------------------------------------------------------------------

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
// UDP datagram (RFC 1928 §7)
// ---------------------------------------------------------------------------

// socks5Datagram wraps a SOCKS5 UDP datagram header and payload.
// Wire format: RSV(2) | FRAG(1) | ATYP(1) | DST.ADDR(var) | DST.PORT(2) | DATA
type socks5Datagram struct {
	atyp    byte
	dstAddr []byte // raw address (IP bytes or domain with length prefix)
	dstPort uint16
	data    []byte
}

// parseDatagram parses a SOCKS5 UDP datagram from raw bytes.  Returns the
// source address and any validation error (RSV, FRAG, truncation).
func parseDatagram(b []byte) (*socks5Datagram, *net.UDPAddr, error) {
	if len(b) < 10 {
		return nil, nil, fmt.Errorf("datagram too short: %d bytes", len(b))
	}
	if b[0] != 0x00 || b[1] != 0x00 {
		return nil, nil, errors.New("invalid reserved bytes in UDP datagram")
	}
	if b[2] != 0x00 {
		return nil, nil, errors.New("fragmented UDP datagram not supported")
	}

	d := &socks5Datagram{atyp: b[3]}

	var headerLen int
	switch d.atyp {
	case socks5ATYPIPv4:
		headerLen = 4 + 2
		if len(b) < 4+headerLen {
			return nil, nil, errors.New("truncated IPv4 address in UDP datagram")
		}
		d.dstAddr = b[4 : 4+4]
		d.dstPort = binary.BigEndian.Uint16(b[8:10])
	case socks5ATYPIPv6:
		headerLen = 16 + 2
		if len(b) < 4+headerLen {
			return nil, nil, errors.New("truncated IPv6 address in UDP datagram")
		}
		d.dstAddr = b[4 : 4+16]
		d.dstPort = binary.BigEndian.Uint16(b[20:22])
	case socks5ATYPDomain:
		domainLen := int(b[4])
		headerLen = 1 + domainLen + 2
		if len(b) < 4+headerLen {
			return nil, nil, errors.New("truncated domain address in UDP datagram")
		}
		d.dstAddr = b[4 : 5+domainLen] // includes length prefix byte
		d.dstPort = binary.BigEndian.Uint16(b[5+domainLen : 7+domainLen])
	default:
		return nil, nil, fmt.Errorf("unsupported address type %#x in UDP datagram", d.atyp)
	}

	totalHeader := 4 + headerLen
	d.data = b[totalHeader:]

	srcAddr := &net.UDPAddr{IP: net.IP(d.dstAddr), Port: int(d.dstPort)}
	if d.atyp == socks5ATYPDomain {
		host := string(d.dstAddr[1:])
		if ip := net.ParseIP(host); ip != nil {
			srcAddr.IP = ip
		} else {
			return nil, nil, fmt.Errorf("domain name in UDP reply not supported (got %q)", host)
		}
	}

	return d, srcAddr, nil
}

// writeDatagramHeader writes the SOCKS5 UDP header for dst into buf.
// Returns the number of header bytes written.
func writeDatagramHeader(buf []byte, dst *net.UDPAddr) int {
	buf[0], buf[1], buf[2] = 0x00, 0x00, 0x00 // RSV + FRAG

	if ip4 := dst.IP.To4(); ip4 != nil {
		buf[3] = socks5ATYPIPv4
		copy(buf[4:8], ip4)
		binary.BigEndian.PutUint16(buf[8:10], uint16(dst.Port)) //nolint:gosec // G115: protocol-bounded uint16
		return config.SOCKS5UDPHeaderLenIPv4
	}
	buf[3] = socks5ATYPIPv6
	copy(buf[4:20], dst.IP.To16())
	binary.BigEndian.PutUint16(buf[20:22], uint16(dst.Port)) //nolint:gosec // G115: protocol-bounded uint16
	return config.SOCKS5UDPHeaderLenIPv6
}

// datagramHeaderLen returns the SOCKS5 UDP header length for the destination.
func datagramHeaderLen(dst *net.UDPAddr) int {
	if dst.IP.To4() != nil {
		return config.SOCKS5UDPHeaderLenIPv4
	}
	return config.SOCKS5UDPHeaderLenIPv6
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
	buf[4] = byte(len(host)) //nolint:gosec // G115: SOCKS5 address length — max 255 fits byte
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
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
		if err != nil || len(ips) == 0 {
			return nil, fmt.Errorf("socks5: resolve relay host %q: %w", host, err)
		}
		return &net.UDPAddr{IP: ips[0], Port: port}, nil

	default:
		return nil, fmt.Errorf("socks5: unsupported address type %#x", atyp)
	}
}
