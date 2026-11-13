//go:build linux

package shared

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// udpRcvBufTarget is the receive-buffer target for DNS UDP listeners —
// bursts of small datagrams are served from the buffer instead of dropping
// while the worker pool drains.  SO_RCVBUFFORCE needs CAP_NET_ADMIN; on
// EPERM it degrades to SO_RCVBUF (doubled-and-capped by the kernel).
const udpRcvBufTarget = 1 << 22 // 4 MiB

// UDPListenControl returns a ListenConfig Control for DNS UDP listeners.
// It composes SO_REUSEPORT (multi-shard dispatch) with Linux datagram
// hardening: IP_MTU_DISCOVER=IP_PMTUDISC_DONT lets the kernel fragment
// responses above the path MTU instead of setting DF and silently losing
// them on tunnel paths (WireGuard/PPPoE MTUs sit below the 1400-byte UDP
// response cap of RFC 9715), and a raised receive buffer absorbs request
// bursts.  Fragmentation is the accepted trade-off for datagrams ≤64KiB —
// the same choice dnscrypt-proxy makes.
func UDPListenControl(multiShard bool) func(string, string, syscall.RawConn) error {
	return func(network, _ string, c syscall.RawConn) error {
		isV6 := len(network) > 0 && network[len(network)-1] == '6'
		var serr error
		err := c.Control(func(fd uintptr) {
			if multiShard {
				serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
				if serr != nil {
					return
				}
			}
			level, opt := unix.IPPROTO_IP, unix.IP_MTU_DISCOVER
			if isV6 {
				level, opt = unix.IPPROTO_IPV6, unix.IPV6_MTU_DISCOVER
			}
			if serr = unix.SetsockoptInt(int(fd), level, opt, unix.IP_PMTUDISC_DONT); serr != nil {
				return
			}
			if serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, udpRcvBufTarget); serr != nil {
				// Without CAP_NET_ADMIN fall back to the unprivileged knob;
				// buffer sizing is best-effort and never blocks startup.
				if serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF, udpRcvBufTarget); serr != nil {
					serr = nil
				}
			}
		})
		if err != nil {
			return err
		}
		return serr
	}
}
