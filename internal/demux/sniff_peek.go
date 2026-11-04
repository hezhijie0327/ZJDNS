//go:build linux || freebsd

package demux

import (
	"errors"
	"io"
	"net"
	"os"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// errPeekFallback signals that the conn cannot be peeked (not syscall-backed,
// or recvfrom rejected MSG_PEEK) — sniffHeader falls back to the destructive
// read path, which works for any net.Conn.
var errPeekFallback = errors.New("demux: conn does not support MSG_PEEK")

// Backoff bounds for a stalled partial-header peer: poll(2) is level-triggered
// and MSG_PEEK never consumes, so bytes already queued keep POLLIN permanently
// ready — without a zero-progress backoff a peer sending 1–4 bytes and stalling
// spins the loop hot for the whole sniff budget.
const (
	peekStallBackoffStart = time.Millisecond
	peekStallBackoffMax   = 50 * time.Millisecond
)

// sniffHeader reads the record header non-destructively: recvfrom(MSG_PEEK)
// leaves every byte queued, so the TLS route can hand the raw *net.TCPConn to
// eTLS and keep kernel TLS offload working (eTLS's setup() requires a
// *net.TCPConn directly beneath it and silently skips offload otherwise).
func sniffHeader(conn net.Conn) ([]byte, net.Conn, error) {
	sc, ok := conn.(syscall.Conn)
	if !ok {
		return sniffHeaderRead(conn)
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return sniffHeaderRead(conn)
	}

	header := make([]byte, tcpRecordHeaderLen)
	var peekErr error
	// The conn is fresh off Accept with no other reader — the Control callback
	// is the only code touching the fd for the duration of the sniff.
	if ctrlErr := raw.Control(func(fd uintptr) {
		peekErr = peekHeader(int(fd), header)
	}); ctrlErr != nil {
		return sniffHeaderRead(conn)
	}
	if errors.Is(peekErr, errPeekFallback) {
		return sniffHeaderRead(conn)
	}
	if peekErr != nil {
		return nil, nil, peekErr
	}
	return header, conn, nil
}

// peekHeader fills buf via recvfrom(MSG_PEEK) without consuming bytes.  The
// Go runtime keeps accepted sockets non-blocking, so an empty receive returns
// EAGAIN; poll(2) with the remaining sniff budget covers the wait.  MSG_PEEK
// always reads from the front of the queue, so a short receive just means the
// client has not sent the full header yet — loop until all 5 bytes are
// visible, the peer half-closes (POLLRDHUP: partial data is
// ErrUnexpectedEOF, not a timeout burn), or the deadline passes.
func peekHeader(fd int, buf []byte) error {
	deadline := time.Now().Add(sniffTimeout)
	prev := 0
	backoff := peekStallBackoffStart
	for {
		n, _, err := unix.Recvfrom(fd, buf, unix.MSG_PEEK|unix.MSG_DONTWAIT)
		switch {
		case err == nil:
			switch {
			case n == 0:
				return io.EOF
			case n >= len(buf):
				return nil
			}
		case errors.Is(err, unix.EINTR):
			continue
		case errors.Is(err, unix.EAGAIN), errors.Is(err, unix.EWOULDBLOCK):
			// no data yet — wait below
		default:
			return errPeekFallback
		}
		// Progress bookkeeping only while bytes are actually visible (n>0):
		// an empty queue blocks inside poll until the first data arrives, so
		// EAGAIN rounds are waits, not stalls.
		if n > prev {
			prev = n
			backoff = peekStallBackoffStart
		}
		hup, err := waitReadable(fd, deadline)
		if err != nil {
			return err
		}
		if hup {
			// POLLIN and POLLRDHUP arm together when the FIN trails data:
			// re-peek once before declaring the header incomplete — the
			// remaining bytes may already sit in the queue.
			n, _, err = unix.Recvfrom(fd, buf, unix.MSG_PEEK|unix.MSG_DONTWAIT)
			if err == nil {
				switch {
				case n >= len(buf):
					return nil
				case n > 0:
					return io.ErrUnexpectedEOF
				}
			}
			return io.EOF
		}
		if n > 0 && n == prev {
			// Zero-progress wake: the same partial bytes keep level-triggered
			// POLLIN hot.  Back off before the next poll round.
			time.Sleep(backoff)
			backoff = min(backoff*2, peekStallBackoffMax)
		}
	}
}

// waitReadable blocks until fd is readable or the deadline passes.  Raw
// poll(2) is used because the Go runtime's SetReadDeadline machinery only
// governs reads made through the runtime, not raw syscalls.  Reports whether
// the peer half-closed (POLLHUP/POLLRDHUP) alongside readability.
func waitReadable(fd int, deadline time.Time) (hup bool, err error) {
	fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN | unix.POLLRDHUP}} //nolint:gosec // G115: fd is a small non-negative socket handle, fits int32
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return false, os.ErrDeadlineExceeded
		}
		n, err := unix.Poll(fds, int(remaining.Milliseconds()))
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return false, err
		}
		if n == 0 {
			return false, os.ErrDeadlineExceeded
		}
		revents := fds[0].Revents
		// A closed-under-us fd reports POLLNVAL (and pending socket errors
		// report POLLERR) — waiting further is pointless either way.
		if revents&(unix.POLLERR|unix.POLLNVAL) != 0 {
			return false, os.ErrClosed
		}
		return revents&(unix.POLLHUP|unix.POLLRDHUP) != 0, nil
	}
}
