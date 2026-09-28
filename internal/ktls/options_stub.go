//go:build !(linux || freebsd)

package ktls

import (
	eTLS "gitlab.com/go-extension/tls"
)

// Options is a no-op off Linux/FreeBSD: eTLS's KernelOptions carries no
// fields there, mirroring the old flat Config.KernelTX/KernelRX flags that
// silently did nothing on unsupported platforms.
func Options(_, _ bool) eTLS.KernelOptions {
	return eTLS.KernelOptions{}
}
