package dnsutil

import (
	"errors"
	"io"
	"math/rand/v2"
	"net"
	"slices"
	"sync"

	"codeberg.org/miekg/dns"
)

// tcpReadBufPool reuses read buffers for TCP DNS frames up to MaxMsgSize.
var tcpReadBufPool = sync.Pool{New: func() any { b := make([]byte, dns.MaxMsgSize); return &b }}

// ReadTCPMsg reads a DNS message prefixed with a 2-byte big-endian length
// from conn (RFC 1035 §4.2.2).  Shared by server and upstream TLCP/TLS stacks.
//
// The caller MUST set a read deadline on conn before calling this function
// to prevent goroutine leaks on unresponsive peers. See SetReadDeadline.
// A 2-byte length prefix bounds frames at 65535 = dns.MaxMsgSize, so an
// oversized frame is impossible on the wire and needs no explicit check.
func ReadTCPMsg(conn net.Conn) (*dns.Msg, error) {
	if conn == nil {
		return nil, errors.New("dns: nil connection")
	}
	var prefix [2]byte
	if _, err := io.ReadFull(conn, prefix[:]); err != nil {
		return nil, err
	}
	length := int(prefix[0])<<8 | int(prefix[1])
	bufPtr := tcpReadBufPool.Get().(*[]byte)
	defer tcpReadBufPool.Put(bufPtr)
	buf := (*bufPtr)[:length]
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}
	msg := new(dns.Msg)
	msg.Data = buf
	if err := msg.Unpack(); err != nil {
		return nil, err
	}
	msg.Data = slices.Clone(msg.Data) // detach from pool buffer before deferred Put
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
	length := uint16(len(msg.Data)) //nolint:gosec // G115: DNS TCP message — protocol-bounded uint16
	// RFC 7766 §8: pass length prefix and message in a single write.
	buf := make([]byte, 2+len(msg.Data))
	buf[0] = byte(length >> 8) //nolint:gosec // G115: DNS wire format — protocol-bounded byte
	buf[1] = byte(length)      //nolint:gosec // G115: DNS wire format — protocol-bounded byte
	copy(buf[2:], msg.Data)
	_, err := conn.Write(buf)
	return err
}
