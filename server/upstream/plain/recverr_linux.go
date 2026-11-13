//go:build linux

package plain

import (
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// recvErrControl arms IP_RECVERR / IPV6_RECVERR on outbound connected UDP
// sockets.  Without the option the kernel drops host- and network-unreachable
// ICMP errors for connected datagram sockets (Linux net/ipv4/udp.c
// __udp4_lib_err) and a read against an unreachable upstream waits out the
// full query budget; with it the pending read fails immediately with the
// ICMP errno, so the pool evicts the conn and the next query redials or the
// race's other upstreams win.
func recvErrControl(network, _ string, c syscall.RawConn) error {
	level, opt := unix.IPPROTO_IP, unix.IP_RECVERR
	if strings.HasSuffix(network, "6") {
		level, opt = unix.IPPROTO_IPV6, unix.IPV6_RECVERR
	}
	var serr error
	err := c.Control(func(fd uintptr) {
		serr = unix.SetsockoptInt(int(fd), level, opt, 1)
	})
	if err != nil {
		return err
	}
	return serr
}
