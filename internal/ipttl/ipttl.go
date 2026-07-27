// Package ttlcap provides platform-independent IP TTL (IPv4) and Hop Limit
// (IPv6) capture from UDP connections via the golang.org/x/net control-message
// API. On platforms that do not support the required socket options (e.g.
// Windows), the constructor returns nil and the caller falls back to plain
// reads.
package ipttl

import (
	"net"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// Capture wraps a *net.UDPConn with IP-layer TTL/HopLimit extraction.
type Capture struct {
	conn *net.UDPConn
	pc4  *ipv4.PacketConn
	pc6  *ipv6.PacketConn
}

// New enables TTL (IPv4) or HopLimit (IPv6) capture on conn. Returns nil if
// the platform does not support the required socket option.
func New(conn *net.UDPConn) *Capture {
	c := &Capture{conn: conn}
	if conn.RemoteAddr().(*net.UDPAddr).IP.To4() != nil {
		c.pc4 = ipv4.NewPacketConn(conn)
		if err := c.pc4.SetControlMessage(ipv4.FlagTTL, true); err != nil {
			return nil
		}
	} else {
		c.pc6 = ipv6.NewPacketConn(conn)
		if err := c.pc6.SetControlMessage(ipv6.FlagHopLimit, true); err != nil {
			return nil
		}
	}
	return c
}

// ReadFrom reads a datagram and extracts the IP TTL (IPv4) or HopLimit (IPv6).
func (c *Capture) ReadFrom(buf []byte) (n int, ttl uint8, err error) {
	if c.pc4 != nil {
		var cm *ipv4.ControlMessage
		n, cm, _, err = c.pc4.ReadFrom(buf)
		if cm != nil {
			ttl = uint8(cm.TTL) //nolint:gosec // TTL is always 0-255
		}
	} else {
		var cm *ipv6.ControlMessage
		n, cm, _, err = c.pc6.ReadFrom(buf)
		if cm != nil {
			ttl = uint8(cm.HopLimit) //nolint:gosec // HopLimit is always 0-255
		}
	}
	return n, ttl, err
}
