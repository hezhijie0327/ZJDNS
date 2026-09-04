package server

import (
	"fmt"
	"net"
	"zjdns/config"
	zdnsutil "zjdns/internal/dnsutil"
	"zjdns/internal/log"
	"zjdns/internal/pool"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// handleDNSRequest is the protocol bridge for the miekg-managed UDP
// listeners: it extracts the client IP and delegates to the handler.  (TCP
// is served by the hand-rolled pipelining listener in server/protocol/plain.)
func (s *Server) handleDNSRequest(w dns.ResponseWriter, req *dns.Msg) {
	defer zdnsutil.HandlePanic("DNS request processing")

	select {
	case <-s.ctx.Done():
		return
	default:
	}

	clientIP := net.ParseIP(dnsutil.RemoteIP(w))

	response := s.handler.ServeDNS(req, clientIP, false, config.ProtoUDP)
	if response == req { //nolint:revive // identity guard: ServeDNS must never return the request (L5)
		response = nil
	}
	if response != nil {
		// Pre-packed responses (cache hits without EDNS modification) already
		// carry Data and skip the pack.
		if len(response.Data) == 0 {
			if err := packSafe(response); err != nil {
				// RemoteAddr().String() allocates — gate it (C-L5).
				if log.IsDebug() {
					log.Debugf("SERVER: UDP pack error for %s: %v", w.RemoteAddr().String(), err)
				}
				pool.DefaultMessage.Put(response)
				return
			}
		}

		// RFC 2181 §9: if the response exceeds the client's EDNS buffer,
		// truncate and set TC so the client retries over TCP.  Use the real
		// wire length — Msg.Len() computes the uncompressed size from RR
		// fields, which are nil for pre-packed responses.
		// RFC 9715 R3: cap the response at the recommended 1400-byte
		// maximum DNS/UDP payload (MTU 1500 minus IP/UDP headers, allowing
		// for tunnel overhead) — larger responses get truncated (TC=1) and
		// the client retries over TCP, avoiding IP fragmentation.
		udpSize := min(max(req.UDPSize, dns.MinMsgSize), config.DefaultMaxUDPResponseSize)
		if len(response.Data) > int(udpSize) {
			// Wire-level truncation (RFC 2181 §9 + RFC 9715 R3): set TC,
			// drop every RR section, keep header + question (+ OPT).  No
			// Unpack/Pack round-trip — pre-packed cache wires stay
			// pre-packed, and EDE inside the preserved OPT is kept (RFC
			// 8914 §3's space trade-off does not apply — the whole answer
			// section is freed).
			response.Data = truncateWire(response.Data)
			response.Truncated = true
		}

		// Use WriteTo, not w.Write(response.Data).
		// WriteTo detects the underlying *net.UDPConn and calls
		// WriteMsgUDP(data, oob, clientAddr) — required because the
		// UDP socket is unconnected (ListenUDP, not DialUDP).
		// w.Write() would fail with "destination address required".
		if _, err := response.WriteTo(w); err != nil {
			if log.IsDebug() { // RemoteAddr().String() allocates — gate it (C-L5)
				log.Debugf("SERVER: UDP write error for %s: %v", w.RemoteAddr().String(), err)
			}
		}
		pool.DefaultMessage.Put(response)
	}
}

// truncateWire shrinks a packed response to header + question (+ trailing
// OPT) with TC set — see dnsutil.TruncateWire for the semantics (OPT
// preserved per RFC 6891 §6.2.5 so EDE inside it survives).
func truncateWire(wire []byte) []byte {
	return zdnsutil.TruncateWire(wire)
}

// packSafe calls msg.Pack() and recovers from any panic, returning it as an
// error so the caller can handle it gracefully (e.g. send SERVFAIL) instead
// of crashing the request goroutine.
func packSafe(msg *dns.Msg) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
			log.Errorf("SERVER: pack panic recovered: %v", r)
		}
	}()
	return msg.Pack()
}
