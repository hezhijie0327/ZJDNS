package socks5

import (
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

// Dialer provides TCP and UDP connections through a SOCKS5 proxy.
// It implements both RFC 1928 (SOCKS5) and RFC 1929 (Username/Password auth).
//
// TCP connections are multiplexed over a single Dialer.  UDP connections
// (ListenPacket, DialUDP) each create an independent UDP ASSOCIATE relay
// so that closing one caller's connection does not affect others.
type Dialer struct {
	proxyAddr string // host:port of the SOCKS5 proxy
	username  string // empty means no auth
	password  string
	timeout   time.Duration // connection + negotiation timeout

	mu        sync.RWMutex
	udpConn   *net.UDPConn // connected UDP socket to relay
	relayAddr *net.UDPAddr // proxy's UDP relay address
	ctrlConn  net.Conn     // TCP control connection for UDP ASSOCIATE

	// The above fields (udpConn, relayAddr, ctrlConn) are only used by
	// establishUDPRelay and the monitor goroutine. They are never set on the
	// base Dialer returned by New() — each ListenPacket/DialUDP call creates
	// a fresh clone that populates them.  Retained on the struct for clarity;
	// consider extracting into a separate udpRelay type.
}

// ---------------------------------------------------------------------------
// UDP datagram (RFC 1928 §7)
// ---------------------------------------------------------------------------

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

// Sentinel errors for SOCKS5 operations.
var (
	ErrSOCKS5Version     = errors.New("socks5: protocol version mismatch")
	ErrSOCKS5BadReply    = errors.New("socks5: malformed reply from proxy")
	ErrSOCKS5Auth        = errors.New("socks5: authentication failed")
	ErrSOCKS5NoAuth      = errors.New("socks5: proxy requires unsupported auth method")
	ErrSOCKS5CmdRejected = errors.New("socks5: command rejected by proxy")
)

// ---------------------------------------------------------------------------
// Pools
// ---------------------------------------------------------------------------

// socks5WritePool reuses buffers for SOCKS5 UDP write path.
// MTU-sized (1500) buffer covers DNS queries and typical QUIC datagrams;
// oversized writes fall back to heap allocation.
var socks5WritePool = sync.Pool{
	New: func() any { b := make([]byte, socks5WriteBufSize); return &b },
}

// ReadPool reuses buffers for SOCKS5 UDP read path (exchangeViaProxyUDP).
// 8 KB covers the common DNS response size (~512–1232); larger responses
// get a fresh buffer from ReadFrom's internal cache.
var ReadPool = sync.Pool{
	New: func() any { b := make([]byte, socks5ReadBufSize); return &b },
}

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
		return "unknown(" + strconv.Itoa(int(rep)) + ")"
	}
}

// New parses a socks5://[user:pass@]host:port URL and returns
// a ready-to-use dialer. The timeout is used for proxy connection and
// negotiation.
func New(proxyURL string, timeout time.Duration) (*Dialer, error) {
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

	d := &Dialer{
		proxyAddr: net.JoinHostPort(host, port),
		timeout:   timeout,
	}
	if u.User != nil {
		d.username = u.User.Username()
		// _ = error: Password() fails only for missing/percent-encoded
		// password — an empty password is then treated as no-auth below
		// (user@host must not advertise password auth to no-auth proxies).
		d.password, _ = u.User.Password()
		if d.password == "" {
			d.username = ""
		}
	}
	return d, nil
}

// SafeURL returns the proxy URL with password redacted for logging.
func (d *Dialer) SafeURL() string {
	if d == nil {
		return ""
	}
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
func (d *Dialer) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.cleanupLocked()
	return nil
}

// ---------------------------------------------------------------------------
// Internal: handshake + auth
// ---------------------------------------------------------------------------

func (d *Dialer) handshake(conn net.Conn) error {
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

func (d *Dialer) authUserPass(conn net.Conn) error {
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
// UDP datagram (RFC 1928 §7)
// ---------------------------------------------------------------------------
