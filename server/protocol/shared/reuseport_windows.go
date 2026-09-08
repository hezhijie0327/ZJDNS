//go:build windows

package shared

import "syscall"

// controlReusePort is a no-op on Windows: SO_REUSEPORT does not exist there,
// so the dispatch shard count collapses to 1 (see startUDPGroup).
func controlReusePort() func(string, string, syscall.RawConn) error {
	return nil
}

func reusePortSupported() bool { return false }
