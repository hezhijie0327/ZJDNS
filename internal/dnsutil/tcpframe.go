package dnsutil

import (
	"errors"
	"io"
	"math/rand/v2"
	"net"

	"codeberg.org/miekg/dns"
)

// errFrameTooLarge is returned when a TCP DNS frame exceeds dns.MaxMsgSize.
var errFrameTooLarge = errors.New("dns: TCP frame exceeds maximum message size")

// ReadTCPMsg reads a DNS message prefixed with a 2-byte big-endian length
// from conn (RFC 1035 §4.2.2).  Shared by server and upstream TLCP/TLS stacks.
//
// The caller MUST set a read deadline on conn before calling this function
// to prevent goroutine leaks on unresponsive peers. See SetReadDeadline.
func ReadTCPMsg(conn net.Conn) (*dns.Msg, error) {
	if conn == nil {
		return nil, errors.New("dns: nil connection")
	}
	var prefix [2]byte
	if _, err := io.ReadFull(conn, prefix[:]); err != nil {
		return nil, err
	}
	length := int(prefix[0])<<8 | int(prefix[1])
	if length > dns.MaxMsgSize {
		return nil, &net.OpError{Op: "read", Net: "tcp", Err: errFrameTooLarge}
	}
	buf := make([]byte, length)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}
	msg := new(dns.Msg)
	msg.Data = buf
	if err := msg.Unpack(); err != nil {
		return nil, err
	}
	return msg, nil
}

// WriteTCPMsgSegmented writes a DNS wire-format message to conn with a
// 2-byte length prefix, optionally splitting the write into multiple
// segments to hinder DPI-based domain matching.
//
// When segSize is 0 or >= len(msg)-2, the entire message (length prefix
// + payload) is written in a single Write call.
//
// When segSize > 0, each segment's payload size is randomly chosen from
// [1, segSize] to avoid fingerprinting (a fixed size like 1B is a DPI
// signature).  The first segment includes the 2-byte length prefix.
func WriteTCPMsgSegmented(conn net.Conn, msg []byte, segSize int) (int, error) {
	if conn == nil {
		return 0, errors.New("dns: nil connection")
	}
	if segSize <= 0 || segSize >= len(msg)-2 {
		return conn.Write(msg)
	}

	totalWritten := 0
	firstSeg := true
	for totalWritten < len(msg) {
		// Random payload size in [1, segSize] to avoid fingerprinting.
		n := 1 + rand.IntN(segSize) //nolint:gosec // G404: TCP segmentation jitter — not cryptographic
		var end int
		if firstSeg {
			end = totalWritten + 2 + n // first segment includes 2B length prefix
			firstSeg = false
		} else {
			end = totalWritten + n
		}
		if end > len(msg) {
			end = len(msg)
		}

		written, err := conn.Write(msg[totalWritten:end])
		if written == 0 && err == nil {
			return totalWritten, errors.New("dns: zero-byte write without error — possible infinite loop")
		}
		totalWritten += written
		if err != nil {
			return totalWritten, err
		}

	}
	return totalWritten, nil
}

// WriteTCPMsg writes a DNS message prefixed with a 2-byte big-endian length
// to conn (RFC 1035 §4.2.2) in two separate writes (2-byte prefix + payload).
// Callers must serialize access to conn — concurrent calls on the same
// net.Conn will interleave frames and corrupt the TCP stream. Use a
// per-connection sync.Mutex or equivalent.
func WriteTCPMsg(conn net.Conn, msg *dns.Msg) error {
	if conn == nil {
		return errors.New("dns: nil connection")
	}
	if err := msg.Pack(); err != nil {
		return err
	}
	length := uint16(len(msg.Data))                    //nolint:gosec // G115: DNS TCP message — protocol-bounded uint16
	prefix := [2]byte{byte(length >> 8), byte(length)} //nolint:gosec // G115: DNS wire format — protocol-bounded byte
	if _, err := conn.Write(prefix[:]); err != nil {
		return err
	}
	_, err := conn.Write(msg.Data)
	return err
}
