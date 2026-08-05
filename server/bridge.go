package server

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
	"zjdns/config"
	zdnsutil "zjdns/internal/dnsutil"
	"zjdns/internal/log"
	"zjdns/internal/pool"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// tcpWriteEntry manages per-client TCP write serialization for pipelined queries.
type tcpWriteEntry struct {
	writeMu      chan struct{}
	lastAccess   atomic.Int64
	capacity     chan struct{}
	capacityOnce sync.Once
	// refs counts in-flight request goroutines (plus the synchronous SERVFAIL
	// path). The writeMu sweep only deletes entries with refs == 0.
	refs atomic.Int64
}

// tcpWriteShard is one shard of the TCP write-serialization registry.  mu
// serializes the entry lifecycle within the shard: the request path does
// lookup-or-create + in-flight ref under the lock, the sweep does the
// refs==0 check + delete under the same lock — closing the check-then-delete
// TOCTOU that would otherwise detach a writeMu from the map mid-request.
type tcpWriteShard struct {
	mu      sync.Mutex
	entries map[string]*tcpWriteEntry
}

// tcpWriteShardCount is the number of TCP write-registry shards.  Power of
// two so shard selection is a mask.  Concurrent connections hash to different
// shards, so a busy server never contends on a single global lock.
const tcpWriteShardCount = 16

// tcpWriteShardFor returns the shard owning addr.  FNV-1a over the address
// string — stable so the sweep finds entries in the same shard.
func (s *Server) tcpWriteShardFor(addr string) *tcpWriteShard {
	var h uint64 = 14695981039346656037 // FNV-1a offset basis
	for i := range addr {
		h ^= uint64(addr[i])
		h *= 1099511628211 // FNV-1a prime
	}
	return &s.tcpWriteShards[h&(tcpWriteShardCount-1)]
}

// handleDNSRequest is the protocol bridge: it extracts client IP, determines
// protocol (UDP/TCP), serializes TCP writes, and delegates to the handler.
func (s *Server) handleDNSRequest(w dns.ResponseWriter, req *dns.Msg) {
	defer zdnsutil.HandlePanic("DNS request processing")

	select {
	case <-s.ctx.Done():
		return
	default:
	}

	if _, isTCP := w.RemoteAddr().(*net.TCPAddr); isTCP {
		addr := w.RemoteAddr().String()
		// Entry lifecycle is serialized by the owning shard's mutex:
		// lookup-or-create and the in-flight ref happen under the lock, and
		// the sweep's refs==0 check + delete share the same lock. The sweep
		// therefore can never delete an entry between a request's create and
		// its ref add — no placeholder ref is needed, and a request can never
		// hold a writeMu detached from the map while a newer entry (with a
		// separate writeMu) is created for the same connection, which would
		// interleave frames on the same TCP stream.
		// NOTE: Lazy init via capacityOnce.Do means the map entry exists
		// before channels are ready. Concurrent readers of entry.capacity or
		// entry.writeMu between the create and the Do closure would see
		// nil channels, causing a nil-send hang. This is safe because the
		// entry is only read after the Do completes within the same request
		// goroutine -- the first request creates the entry synchronously and
		// all subsequent requests find a fully-initialized one.
		shard := s.tcpWriteShardFor(addr)
		shard.mu.Lock()
		entry, ok := shard.entries[addr]
		if !ok {
			entry = &tcpWriteEntry{}
			if shard.entries == nil {
				shard.entries = make(map[string]*tcpWriteEntry)
			}
			shard.entries[addr] = entry
		}
		// In-flight refcount: incremented under the lock so the sweep can
		// never delete an entry a handler goroutine still holds (the
		// goroutine releases it on exit; the synchronous SERVFAIL path
		// releases it via defer before returning).
		entry.refs.Add(1)
		shard.mu.Unlock()

		entry.capacityOnce.Do(func() {
			entry.capacity = make(chan struct{}, config.DefaultMaxPipe)
			entry.writeMu = make(chan struct{}, 1)
		})

		// In-flight refcount: incremented synchronously so the sweep can never
		// delete an entry a handler goroutine still holds (the goroutine
		// releases it on exit; the synchronous SERVFAIL path releases it via
		// defer before returning).
		entry.refs.Add(1)

		select {
		case entry.capacity <- struct{}{}:
		default:
			defer entry.refs.Add(-1)
			msg := pool.DefaultMessage.Get()
			dnsutil.SetReply(msg, req)
			msg.Rcode = dns.RcodeServerFailure
			if err := packSafe(msg); err != nil {
				log.Debugf("SERVER: TCP SERVFAIL pack error for %s: %v", addr, err)
				pool.DefaultMessage.Put(msg)
				return
			}
			// Acquire writeMu to serialize writes and prevent TCP stream
			// corruption when pipelined queries race with the SERVFAIL path.
			writeTimer := time.NewTimer(config.DefaultDNSQueryTimeout)
			select {
			case entry.writeMu <- struct{}{}:
				if !writeTimer.Stop() {
					<-writeTimer.C
				}
				defer func() { <-entry.writeMu }()
			case <-writeTimer.C:
				log.Debugf("SERVER: TCP SERVFAIL write lock timeout for %s", addr)
				pool.DefaultMessage.Put(msg)
				return
			}
			// WriteTo handles the protocol-specific framing:
			//   UDP: WriteMsgUDP(data, oob, clientAddr) to the correct client
			//   TCP: 2-byte big-endian length prefix + data
			// Do NOT replace with w.Write(msg.Data) — for unconnected UDP
			// sockets, Write lacks the destination address and fails with
			// "destination address required".
			if _, err := msg.WriteTo(w); err != nil {
				log.Debugf("SERVER: TCP SERVFAIL write error for %s: %v", addr, err)
			}
			pool.DefaultMessage.Put(msg)
			return
		}

		// NOTE: This goroutine is fire-and-forget — context cancellation (s.ctx.Done())
		// causes the listener Accept loop to return, so in-flight goroutines exit quickly.
		// No WaitGroup is needed because shutdown blocks on listener close before returning.
		go func() {
			defer entry.refs.Add(-1)
			defer func() { <-entry.capacity }()
			defer zdnsutil.HandlePanic("TCP query handler")

			// Global TCP goroutine bound — matches TLS errgroup.SetLimit.
			// Bounded wait: a saturated semaphore must not occupy the
			// per-client slot forever. On timeout the request is dropped
			// silently (this fire-and-forget goroutine has no response
			// path to the client); the client's own query timeout will
			// surface the failure.
			semTimer := time.NewTimer(config.DefaultDNSQueryTimeout)
			select {
			case s.tcpSem <- struct{}{}:
				if !semTimer.Stop() {
					// Go 1.23+ timers use unbuffered channels: drain so the
					// timer value is not left undelivered.
					select {
					case <-semTimer.C:
					default:
					}
				}
				defer func() { <-s.tcpSem }()
			case <-s.ctx.Done():
				semTimer.Stop()
				return
			case <-semTimer.C:
				return
			}

			response := s.handler.ServeDNS(req, net.ParseIP(dnsutil.RemoteIP(w)), false, config.ProtoTCP)
			if response != nil {
				entry.lastAccess.Store(log.NowUnixNano())

				// Pack before acquiring writeMu — keeps the lock
				// critical section I/O-only and brief (P2).  Pre-packed
				// responses (cache hits without EDNS modification) already
				// carry Data and skip the pack.
				if len(response.Data) == 0 {
					if err := packSafe(response); err != nil {
						log.Debugf("SERVER: TCP pack error for %s: %v", addr, err)
						pool.DefaultMessage.Put(response)
						return
					}
				}

				writeTimer := time.NewTimer(config.DefaultDNSQueryTimeout)
				select {
				case entry.writeMu <- struct{}{}:
					if !writeTimer.Stop() {
						<-writeTimer.C
					}
					defer func() { <-entry.writeMu }()
				case <-writeTimer.C:
					log.Debugf("SERVER: TCP write lock timeout for %s", addr)
					pool.DefaultMessage.Put(response)
					return
				}
				// Write the RFC 1035 §4.2.2 length prefix + payload in one
				// frame.  Msg.WriteTo would allocate a fresh 2+len frame per
				// response; preallocate once instead.
				frame := make([]byte, zdnsutil.DNSFramePrefixLen+len(response.Data))
				binary.BigEndian.PutUint16(frame, uint16(len(response.Data))) //nolint:gosec // G115: TCP frame length — protocol-bounded uint16
				copy(frame[zdnsutil.DNSFramePrefixLen:], response.Data)
				if _, err := w.Write(frame); err != nil {
					log.Debugf("SERVER: TCP write error for %s: %v", addr, err)
				}
				pool.DefaultMessage.Put(response)
			}
		}()
		return
	}

	clientIP := net.ParseIP(dnsutil.RemoteIP(w))

	response := s.handler.ServeDNS(req, clientIP, false, config.ProtoUDP)
	if response != nil {
		// Pre-packed responses (cache hits without EDNS modification) already
		// carry Data and skip the pack.
		if len(response.Data) == 0 {
			if err := packSafe(response); err != nil {
				log.Debugf("SERVER: UDP pack error for %s: %v", w.RemoteAddr().String(), err)
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
			log.Debugf("SERVER: UDP write error for %s: %v", w.RemoteAddr().String(), err)
		}
		pool.DefaultMessage.Put(response)
	}
}

// truncateWire performs RFC 2181 §9 truncation directly on a packed message:
// sets the TC bit, zeroes the RR counts and drops every RR section, keeping
// only the header + question section and — when present — the trailing OPT
// record (RFC 6891 §6.2.5).  Unlike dnsutil.Truncate + re-Pack, no
// Unpack/Pack round-trip happens: the truncated wire is produced in place
// with zero allocations (the typical pre-packed cache wire has no OPT).
// EDE options are kept inside the preserved OPT — the truncation frees the
// entire answer section, so RFC 8914 §3's space trade-off does not apply.
func truncateWire(wire []byte) []byte {
	if len(wire) < dns.MsgHeaderSize {
		return wire
	}
	// Question section: starts after the 12-byte header.
	pos := 12
	questions := int(binary.BigEndian.Uint16(wire[4:6]))
	for range questions {
		off, ok := skipWireName(wire, pos)
		if !ok {
			// Malformed question — keep only the header.
			return wire[:dns.MsgHeaderSize]
		}
		pos = off + 4 // QTYPE(2) + QCLASS(2)
	}
	questionEnd := pos

	// Scan the RR sections for a trailing OPT (type 41) to preserve.
	var opt []byte
	for pos+10 <= len(wire) {
		off, ok := skipWireName(wire, pos)
		if !ok || off+10 > len(wire) {
			break
		}
		rrEnd := off + 10 + int(binary.BigEndian.Uint16(wire[off+8:]))
		if rrEnd > len(wire) {
			break
		}
		if binary.BigEndian.Uint16(wire[off:]) == dns.TypeOPT {
			opt = wire[pos:rrEnd] // include the owner name (root label)
		}
		pos = rrEnd
	}

	// Rebuild: header + question (+ OPT).  TC bit = flags byte 2, bit 0x02.
	truncated := wire[:questionEnd]
	if len(truncated) < dns.MsgHeaderSize {
		// Defensive: questionEnd is derived from QDCOUNT and can never be
		// below 12, but a malformed wire must not panic the request path.
		// (wire length ≥ MsgHeaderSize guaranteed by the guard above.)
		return wire[:dns.MsgHeaderSize] //nolint:gosec // G602: guarded above
	}
	truncated[2] |= 0x02
	truncated[6], truncated[7] = 0, 0 // ANCOUNT
	truncated[8], truncated[9] = 0, 0 // NSCOUNT
	if opt != nil {
		truncated = append(truncated, opt...)
		binary.BigEndian.PutUint16(truncated[10:12], 1) // ARCOUNT
	} else {
		truncated[10], truncated[11] = 0, 0 // ARCOUNT
	}
	return truncated
}

// skipWireName returns the offset after the domain name at pos in a packed
// message.  Handles label sequences and compression pointers (RFC 1035 §4.1.4).
func skipWireName(wire []byte, pos int) (int, bool) {
	for {
		if pos >= len(wire) {
			return 0, false
		}
		l := wire[pos]
		if l == 0 {
			return pos + 1, true
		}
		if l&0xC0 == 0xC0 {
			return pos + 2, true
		}
		pos += int(l) + 1
	}
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
