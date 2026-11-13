//go:build !linux

package shared

import (
	"syscall"
)

// UDPListenControl returns a ListenConfig Control for DNS UDP listeners.
// Non-Linux platforms keep the existing SO_REUSEPORT-only behavior — the
// PMTU/buffer hardening knobs are Linux-specific.
func UDPListenControl(multiShard bool) func(string, string, syscall.RawConn) error {
	if !multiShard {
		return nil
	}
	return ReusePortControl()
}
