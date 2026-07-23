package dnsutil

import (
	"io"
	"math/rand/v2"
	"net"
	"time"

	"codeberg.org/miekg/dns"
)

// ReadTCPMsg reads a DNS message prefixed with a 2-byte big-endian length
// from conn (RFC 1035 §4.2.2).  Shared by server and upstream TLCP/TLS stacks.
func ReadTCPMsg(conn net.Conn) (*dns.Msg, error) {
	var prefix [2]byte
	if _, err := io.ReadFull(conn, prefix[:]); err != nil {
		return nil, err
	}
	length := int(prefix[0])<<8 | int(prefix[1])
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
// An optional inter-segment delay can be set via the delay parameter.
func WriteTCPMsgSegmented(conn net.Conn, msg []byte, segSize int, delay time.Duration) (int, error) {
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
		totalWritten += written
		if err != nil {
			return totalWritten, err
		}

		if totalWritten < len(msg) && delay > 0 {
			time.Sleep(time.Duration(rand.Int64N(int64(delay)))) //nolint:gosec // G404: delay jitter — not cryptographic
		}
	}
	return totalWritten, nil
}

// WriteTCPMsg writes a DNS message prefixed with a 2-byte big-endian length
// to conn (RFC 1035 §4.2.2).  Shared by server and upstream TLCP/TLS stacks.
func WriteTCPMsg(conn net.Conn, msg *dns.Msg) error {
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
