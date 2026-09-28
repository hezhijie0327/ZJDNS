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
