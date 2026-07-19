package tcp

import (
	"fmt"
	"io"
	"net"
	"zjdns/server/protocol/shared"
)

// detectConn wraps a raw net.Conn and peeks at the first record layer header
// to determine whether the client speaks TLS or TLCP.  The peeked bytes are
// replayed transparently on the first Read so the TLS/TLCP Server function
// sees the complete ClientHello.
type detectConn struct {
	net.Conn
	header []byte // peeked record header (nil once fully consumed)
	major  uint8  // protocol major version
	minor  uint8  // protocol minor version
}

// readHeader reads the first shared.RecordHeaderLen bytes from the raw connection.
// After this returns nil, major and minor are set.
func (c *detectConn) readHeader() error {
	c.header = make([]byte, shared.RecordHeaderLen)
	if _, err := io.ReadFull(c.Conn, c.header); err != nil {
		return fmt.Errorf("shared: read record header: %w", err)
	}
	c.major = c.header[1]
	c.minor = c.header[2]
	return nil
}

// Read replays the buffered record header on the first call, then delegates
// to the underlying connection.  This lets the TLS/TLCP Server function
// consume the ClientHello as if the peek never happened.
func (c *detectConn) Read(b []byte) (n int, err error) {
	if len(c.header) == 0 {
		return c.Conn.Read(b)
	}

	if len(b) >= len(c.header) {
		n = copy(b, c.header)
		c.header = nil
		if len(b) > n {
			var n1 int
			n1, err = c.Conn.Read(b[n:])
			n += n1
		}
		return n, err
	}

	// Caller's buffer is smaller than the remaining header bytes.
	n = copy(b, c.header[:len(b)])
	c.header = c.header[len(b):]
	return n, nil
}
