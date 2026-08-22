//go:build !(linux || darwin || freebsd || netbsd || openbsd || dragonfly)

package ipttl

import (
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// newControlBuf is a no-op off unix: the RawConn recvmsg path is not built,
// so no control-message buffer is needed.
func newControlBuf() []byte { return nil }

// initReadFn is a no-op off unix: the x/net ReadFrom path below needs no
// callback.
func (c *Capture) initReadFn() {}

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
