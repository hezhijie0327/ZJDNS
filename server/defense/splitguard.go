// Package defense — TCP DNS message segmentation (
// Connection Tracking Covert Protocol) to hinder DPI-based domain matching
// and RST injection.
//
// WriteTCPMsgSegmented splits a DNS wire-format message into small
// segments. The first segment carries the 2-byte length prefix plus
// segSize payload bytes; subsequent segments each carry up to segSize
// bytes. An optional inter-segment delay can be used for additional
// timing-based evasion.
package defense

import (
	"net"
	"time"
)

// WriteTCPMsgSegmented writes a DNS wire-format message to conn with a
// 2-byte length prefix, optionally splitting the write into multiple
// segments to hinder DPI-based domain matching.
//
// When segSize is 0 or >= len(msg)-2, the entire message (length prefix
// + payload) is written in a single Write call (equivalent to a normal
// TCP DNS send).
//
// When segSize > 0, the first segment consists of the 2-byte length
// prefix plus segSize bytes of payload. Subsequent segments each carry
// up to segSize bytes of payload. An optional inter-segment delay can
// be set via the delay parameter.
//
// This is the CTCP (Connection Tracking Covert Protocol) technique for
// evading RST injection by TCP DPI middleboxes.
func WriteTCPMsgSegmented(conn net.Conn, msg []byte, segSize int, delay time.Duration) (int, error) {
	if segSize <= 0 || segSize >= len(msg)-2 {
		return conn.Write(msg)
	}

	totalWritten := 0
	firstSeg := true
	for totalWritten < len(msg) {
		var end int
		if firstSeg {
			// First segment: 2-byte length prefix + segSize payload bytes.
			end = totalWritten + 2 + segSize
			firstSeg = false
		} else {
			end = totalWritten + segSize
		}
		if end > len(msg) {
			end = len(msg)
		}

		n, err := conn.Write(msg[totalWritten:end])
		totalWritten += n
		if err != nil {
			return totalWritten, err
		}

		if totalWritten < len(msg) && delay > 0 {
			time.Sleep(delay)
		}
	}
	return totalWritten, nil
}
