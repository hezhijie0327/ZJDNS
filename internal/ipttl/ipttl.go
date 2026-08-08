// Package ipttl provides platform-independent IP TTL (IPv4) and Hop Limit
// (IPv6) capture from UDP connections via the golang.org/x/net control-message
// API. On platforms that do not support the required socket options (e.g.
// Windows), the constructor returns nil and the caller falls back to plain
// reads.
package ipttl

import (
	"errors"
	"net"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// Capture wraps a *net.UDPConn with IP-layer TTL/HopLimit extraction.
type Capture struct {
	pc4 *ipv4.PacketConn
	pc6 *ipv6.PacketConn
}

// ErrNoControlMessage is returned when a read produced no TTL/HopLimit
// control message — the TTL would be silently wrong (0).
var ErrNoControlMessage = errors.New("ipttl: no IP TTL control message received")

// New enables TTL (IPv4) or HopLimit (IPv6) capture on conn, choosing the
// family from the socket's bound address. For a dual-stack wildcard socket
// (::) IPv4 capture is attempted first and falls back to IPv6. Returns nil
// if the platform does not support the required socket option.
func New(conn *net.UDPConn) *Capture {
	if conn == nil {
		return nil
	}
	c := &Capture{}
	addr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return nil
	}
	if addr.IP.To4() != nil {
		c.pc4 = ipv4.NewPacketConn(conn)
		if err := c.pc4.SetControlMessage(ipv4.FlagTTL, true); err != nil {
			return nil
		}
		return c
	}
	if addr.IP.IsUnspecified() {
		// Dual-stack wildcard: try IPv4 first; fall back to IPv6 if the
		// socket rejects the IPv4 control-message option.
		c.pc4 = ipv4.NewPacketConn(conn)
		if err := c.pc4.SetControlMessage(ipv4.FlagTTL, true); err == nil {
			return c
		}
		c.pc4 = nil
	}
	c.pc6 = ipv6.NewPacketConn(conn)
	if err := c.pc6.SetControlMessage(ipv6.FlagHopLimit, true); err != nil {
		return nil
	}
	return c
}

// ReadFrom reads a datagram and extracts the IP TTL (IPv4) or HopLimit (IPv6).
// A missing control message is an explicit error — reporting TTL 0 would
// poison the hopguard fingerprint.
func (c *Capture) ReadFrom(buf []byte) (n int, ttl uint8, err error) {
	switch {
	case c.pc4 != nil:
		var cm *ipv4.ControlMessage
		n, cm, _, err = c.pc4.ReadFrom(buf)
		if cm != nil {
			ttl = uint8(cm.TTL) //nolint:gosec // TTL is always 0-255
		} else if err == nil {
			err = ErrNoControlMessage
		}
	case c.pc6 != nil:
		var cm *ipv6.ControlMessage
		n, cm, _, err = c.pc6.ReadFrom(buf)
		if cm != nil {
			ttl = uint8(cm.HopLimit) //nolint:gosec // HopLimit is always 0-255
		} else if err == nil {
			err = ErrNoControlMessage
		}
	default:
		// Zero-value Capture (neither pc4 nor pc6) — New always wires one,
		// but a hand-constructed Capture must not nil-deref (M-low).
		return 0, 0, ErrNoControlMessage
	}
	return n, ttl, err
}
