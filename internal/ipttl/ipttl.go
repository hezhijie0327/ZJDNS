// Package ipttl provides platform-independent IP TTL (IPv4) and Hop Limit
// (IPv6) capture from UDP connections via the golang.org/x/net control-message
// API. On platforms that do not support the required socket options (e.g.
// Windows), the constructor returns nil and the caller falls back to plain
// reads.
//
// On unix platforms the per-read hot path is a zero-allocation unix.Recvmsg
// through the socket's RawConn (capture_unix.go) instead of x/net's per-packet
// sockaddr/control-message allocations — the hopguard TTL capture read was
// ~1B allocations on a loaded server.  The constructor's one-time
// SetControlMessage setup is unchanged and stays on the x/net API.
package ipttl

import (
	"errors"
	"net"
	"syscall"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// Capture wraps a *net.UDPConn with IP-layer TTL/HopLimit extraction.
// One goroutine (the socket's readLoop) reads from a Capture — the unix
// path's reused result fields rely on that.
type Capture struct {
	pc4    *ipv4.PacketConn
	pc6    *ipv6.PacketConn
	raw    syscall.RawConn    // zero-alloc recvmsg path (unix); zero value elsewhere
	fam    int                // 4 or 6 — expected cmsg level/type for the TTL read
	oob    []byte             // reused recvmsg control-message buffer (unix only)
	buf    []byte             // per-read input buffer (unix; set by ReadFrom)
	n      int                // last read result (unix)
	ttl    uint8              // last read result (unix)
	rerr   error              // last read error (unix)
	readFn func(uintptr) bool // recvmsg closure, built once in New (unix)
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
	} else {
		if addr.IP.IsUnspecified() {
			// Dual-stack wildcard: try IPv4 first; fall back to IPv6 if the
			// socket rejects the IPv4 control-message option.
			c.pc4 = ipv4.NewPacketConn(conn)
			if err := c.pc4.SetControlMessage(ipv4.FlagTTL, true); err != nil {
				c.pc4 = nil
			}
		}
		if c.pc4 == nil {
			c.pc6 = ipv6.NewPacketConn(conn)
			if err := c.pc6.SetControlMessage(ipv6.FlagHopLimit, true); err != nil {
				return nil
			}
		}
	}

	// Zero-alloc read path (unix): RawConn.Read + unix.Recvmsg reuse c.oob,
	// skipping x/net's per-read sockaddr/control-message allocations.  When
	// SyscallConn fails (never in practice for *net.UDPConn), ReadFrom falls
	// back to the x/net path — the capture is still valid.
	if sc, err := conn.SyscallConn(); err == nil {
		c.raw = sc
		if c.pc4 != nil {
			c.fam = 4
		} else {
			c.fam = 6
		}
		c.oob = newControlBuf()
		c.initReadFn()
	}
	return c
}
