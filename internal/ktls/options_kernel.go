//go:build linux || freebsd

package ktls

import (
	eTLS "gitlab.com/go-extension/tls"
)

// Options enables kernel TLS offload directions for platforms that support
// them; eTLS downgrades to the software implementation when the kernel
// cannot take the offload.
func Options(tx, rx bool) eTLS.KernelOptions {
	return eTLS.KernelOptions{TX: tx, RX: rx}
}

// requested reports whether cfg asks for kernel offload in any direction.
// Fields exist only on Linux/FreeBSD, so the check is platform-split.
func requested(cfg *eTLS.Config) bool {
	return cfg != nil && (cfg.KernelOptions.TX || cfg.KernelOptions.RX)
}
