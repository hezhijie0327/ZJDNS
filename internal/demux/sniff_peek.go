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
	// Control runs with exclusive fd access — the conn is fresh off Accept,
	// nobody else reads it yet.
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
// visible or the deadline passes.
func peekHeader(fd int, buf []byte) error {
	deadline := time.Now().Add(sniffTimeout)
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
		if err := waitReadable(fd, deadline); err != nil {
			return err
		}
	}
}

// waitReadable blocks until fd is readable or the deadline passes.  Raw
// poll(2) is used because the Go runtime's SetReadDeadline machinery only
// governs reads made through the runtime, not raw syscalls.
func waitReadable(fd int, deadline time.Time) error {
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return os.ErrDeadlineExceeded
		}
		n, err := unix.Poll([]unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}, int(remaining.Milliseconds()))
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return os.ErrDeadlineExceeded
		}
		return nil
	}
}
