//go:build !linux

package plain

import "syscall"

// recvErrControl is a no-op outside Linux — IP_RECVERR queueing is a Linux
// socket option; other platforms surface unreachable errors through the
// socket's regular read path or not at all (the timeout stays the bound).
func recvErrControl(_, _ string, _ syscall.RawConn) error { return nil }
