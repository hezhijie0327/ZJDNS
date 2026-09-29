//go:build !(linux || freebsd)

package demux

import "net"

// sniffHeader reads the record header destructively and returns a
// replay-wrapped connection.  These platforms have no kernel TLS offload, so
// a wrapper conn beneath the eTLS layer costs nothing; the Linux/FreeBSD
// builds use a non-destructive MSG_PEEK instead (sniff_peek.go).
func sniffHeader(conn net.Conn) ([]byte, net.Conn, error) {
	return sniffHeaderRead(conn)
}
