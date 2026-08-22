//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package ipttl

import (
	"encoding/binary"
	"errors"
	"runtime"

	"golang.org/x/sys/unix"
)

// newControlBuf returns the reused recvmsg control-message buffer.  IP_TTL
// and IPV6_HOPLIMIT both carry a single int (one cmsg, 4 payload bytes), so
// CmsgSpace(4) covers header + aligned payload on any word size.
func newControlBuf() []byte { return make([]byte, unix.CmsgSpace(4)) }

// initReadFn builds the recvmsg callback once — it captures only the
// Capture pointer, so a per-read closure (which would escape to the heap)
// is avoided; results travel back through c.n/c.ttl/c.rerr.
func (c *Capture) initReadFn() {
	c.readFn = func(fd uintptr) bool {
		var e error
		c.n, c.ttl, e = readTTL(int(fd), c.fam, c.buf, c.oob)
		switch {
		case e == nil:
			return true
		case errors.Is(e, unix.EAGAIN), errors.Is(e, unix.EWOULDBLOCK):
			// Nothing ready — the netpoller waits (honoring the conn's read
			// deadline) and re-invokes us.  Single reader per socket, so the
			// readable signal cannot be consumed by anyone else.
			return false
		default:
			c.rerr = e
			return true
		}
	}
}

// ReadFrom reads one datagram and extracts the IP TTL (IPv4) or HopLimit
// (IPv6) with only the unavoidable Sockaddr allocation inside unix.Recvmsg
// (1/read) — the x/net path it replaces allocated a control message, a
// Sockaddr and a UDPAddr per read (~1B allocations on a loaded server).
// The read deadline set via UDPConn.SetReadDeadline is honored by
// RawConn.Read: expiry surfaces as *net.OpError with Timeout()==true,
// identical to conn.Read.
func (c *Capture) ReadFrom(buf []byte) (n int, ttl uint8, err error) {
	c.buf = buf
	c.rerr = nil
	rcErr := c.raw.Read(c.readFn)
	if rcErr != nil {
		return c.n, 0, rcErr
	}
	return c.n, c.ttl, c.rerr
}

// readTTL performs a non-blocking recvmsg and parses the TTL/HopLimit cmsg.
func readTTL(fd, fam int, buf, oob []byte) (n int, ttl uint8, err error) {
	var oobn int
	n, oobn, _, _, err = unix.Recvmsg(fd, buf, oob, unix.MSG_DONTWAIT)
	if err != nil {
		return 0, 0, err
	}
	if ttl, ok := cmsgTTL(oob[:oobn], fam); ok {
		return n, ttl, nil
	}
	return n, 0, ErrNoControlMessage
}

// cmsgTTL walks the received control-message list and returns the
// TTL/HopLimit payload.  Zero-allocation: the list is parsed in place with
// binary.NativeEndian — no unsafe, no unix.ParseSocketControlMessage (which
// allocates a data slice per cmsg).
//
// Platform quirks handled here: cmsg_len is size_t on Linux (8 bytes on
// 64-bit) but socklen_t (4 bytes) on macOS and the BSDs — all our build-tag
// platforms are little-endian in practice (amd64/arm64 CI), so the low
// bytes of a size_t hold the full value; the 8-byte read is only correct
// where the field IS 8 bytes.  And the delivered IPv4 cmsg type is IP_TTL
// on Linux but the socket-option name IP_RECVTTL on macOS/BSDs (verified on
// darwin: level 0, type 24).  Malformed input (short header, over-long len,
// non-positive stride) returns ok=false.
func cmsgTTL(oob []byte, fam int) (ttl uint8, ok bool) {
	wantLevel := unix.IPPROTO_IP
	wantType := unix.IP_TTL
	if runtime.GOOS != "linux" {
		wantType = unix.IP_RECVTTL
	}
	if fam == 6 {
		wantLevel = unix.IPPROTO_IPV6
		wantType = unix.IPV6_HOPLIMIT
	}
	hdrLen := unix.SizeofCmsghdr
	for len(oob) >= hdrLen {
		l := int(binary.NativeEndian.Uint32(oob[0:4]))
		if runtime.GOOS == "linux" && unix.SizeofPtr == 8 {
			//nolint:gosec // G115: kernel-written cmsg_len, bounded by the oob buffer (checked below)
			l = int(binary.NativeEndian.Uint64(oob[0:8]))
		}
		if l < hdrLen || l > len(oob) {
			return 0, false
		}
		level := binary.NativeEndian.Uint32(oob[hdrLen-8 : hdrLen-4])
		typ := binary.NativeEndian.Uint32(oob[hdrLen-4 : hdrLen])
		if int(level) == wantLevel && int(typ) == wantType && l >= hdrLen+1 {
			return oob[hdrLen], true
		}
		// Align to the platform word size for the next cmsghdr.
		step := (l + unix.SizeofPtr - 1) &^ (unix.SizeofPtr - 1)
		if step <= 0 {
			return 0, false
		}
		oob = oob[step:]
	}
	return 0, false
}
