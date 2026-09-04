// SOCKS5 UDP ASSOCIATE datagram framing: header parsing/building and
// address encoding (RFC 1928 §7).

package socks5

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
	"zjdns/config"
)

// datagram wraps a SOCKS5 UDP datagram header and payload.
// Wire format: RSV(2) | FRAG(1) | ATYP(1) | DST.ADDR(var) | DST.PORT(2) | DATA
type datagram struct {
	atyp    byte
	dstAddr []byte // raw address (IP bytes or domain with length prefix)
	dstPort uint16
	data    []byte
}

// parseDatagram parses a SOCKS5 UDP datagram from raw bytes.  Returns the
// source address and any validation error (RSV, FRAG, truncation).
func parseDatagram(b []byte) (*datagram, *net.UDPAddr, error) {
	// Only guarantee the ATYP byte is readable; per-ATYP bounds checks below
	// handle truncation (a valid 1-byte domain datagram is only 8 bytes).
	if len(b) < 4 {
		return nil, nil, fmt.Errorf("datagram too short: %d bytes", len(b))
	}
	if b[0] != 0x00 || b[1] != 0x00 {
		return nil, nil, errors.New("invalid reserved bytes in UDP datagram")
	}
	if b[2] != 0x00 {
		return nil, nil, errors.New("fragmented UDP datagram not supported")
	}

	d := &datagram{atyp: b[3]}

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

	// d.dstAddr aliases the pooled read buffer, which ReadFrom clears on
	// return — copy the IP so the returned address survives the buffer
	// recycle.  A zeroed IP broke source-address validation in DTLCP
	// (gotlcp) client handshakes over a proxy: the response's source came
	// back as 0.0.0.0, failed the server-address match, and the handshake
	// stalled until timeout.
	srcAddr := &net.UDPAddr{IP: append(net.IP(nil), d.dstAddr...), Port: int(d.dstPort)}
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

	// Domain name — reject oversized hosts instead of wrapping byte(len).
	if len(host) > 255 {
		return nil
	}
	buf := make([]byte, 7+len(host)) // 4 + 1 + len(host) + 2
	buf[0], buf[1], buf[2] = socks5Version, cmd, 0x00
	buf[3] = socks5ATYPDomain
	buf[4] = byte(len(host)) //nolint:gosec // G115: SOCKS5 address length — max 255 fits byte
	copy(buf[5:], host)
	binary.BigEndian.PutUint16(buf[5+len(host):], uport)
	return buf
}

// splitHostPort is like net.SplitHostPort but uses DefaultUDPPort when no port.
func splitHostPort(addr string) (host string, port int, err error) {
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		// net.SplitHostPort failed — assume no port specified; use DNS default.
		// Original error is intentionally discarded (best-effort heuristic).
		h = addr
		// net.SplitHostPort also fails for bracketed IPv6 without a port
		// (e.g. "[::1]"); strip the brackets so the host stays a valid IP
		// literal instead of being sent to the proxy as a bogus domain.
		if len(h) > 1 && h[0] == '[' && h[len(h)-1] == ']' {
			h = h[1 : len(h)-1]
		}
		p = config.DefaultUDPPort // DNS default; non-DNS proxy users should configure explicitly
	}
	port, err = strconv.Atoi(p)
	if err != nil {
		return "", 0, fmt.Errorf("socks5: invalid port in %q: %w", addr, err)
	}
	return h, port, nil
}

// skipAddress reads and discards BND.ADDR + BND.PORT from a SOCKS5 response
// without resolving a domain-typed address (a CONNECT reply's bind address is
// never used).
func skipAddress(conn net.Conn, atyp byte) error {
	switch atyp {
	case socks5ATYPIPv4:
		_, err := io.CopyN(io.Discard, conn, 4+2)
		return err
	case socks5ATYPIPv6:
		_, err := io.CopyN(io.Discard, conn, 16+2)
		return err
	case socks5ATYPDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return err
		}
		_, err := io.CopyN(io.Discard, conn, int64(lenBuf[0])+2)
		return err
	default:
		return fmt.Errorf("socks5: unsupported address type %#x", atyp)
	}
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
		// IP, but some return a domain. Bound the lookup by the connection's
		// deadline (set by the caller during negotiation) instead of a fixed
		// timeout that ignores the caller's context.
		lookupCtx := context.Background()
		if c, ok := conn.(interface{ Deadline() (time.Time, error) }); ok {
			if dl, err := c.Deadline(); err == nil && !dl.IsZero() {
				var cancel context.CancelFunc
				lookupCtx, cancel = context.WithDeadline(context.Background(), dl)
				defer cancel()
			}
		}
		ips, err := net.DefaultResolver.LookupIP(lookupCtx, "ip", host)
		if len(ips) == 0 {
			// No resolution error but no addresses either — err is nil here;
			// %w(nil) renders "%!w(<nil>)" (U17).
			return nil, fmt.Errorf("socks5: resolve relay host %q: no addresses", host)
		}
		if err != nil {
			return nil, fmt.Errorf("socks5: resolve relay host %q: %w", host, err)
		}
		return &net.UDPAddr{IP: ips[0], Port: port}, nil

	default:
		return nil, fmt.Errorf("socks5: unsupported address type %#x", atyp)
	}
}
