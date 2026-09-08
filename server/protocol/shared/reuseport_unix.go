//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package shared

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// controlReusePort returns a ListenConfig Control that sets SO_REUSEPORT so
// several dispatch sockets can bind the same UDP port and the kernel hashes
// each flow (4-tuple) to one of them — per-client packet affinity is
// preserved because one client's 4-tuple always lands on the same shard.
// Returns a no-op Control on platforms without SO_REUSEPORT (see
// reuseport_windows.go), where the dispatch shard count collapses to 1.
func controlReusePort() func(string, string, syscall.RawConn) error {
	return func(_, _ string, c syscall.RawConn) error {
		var serr error
		err := c.Control(func(fd uintptr) {
			serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
		})
		if err != nil {
			return err
		}
		return serr
	}
}

// reusePortSupported reports whether controlReusePort actually enables
// multi-socket binding on this platform.
func reusePortSupported() bool { return true }
