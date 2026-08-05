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
		udpSize := max(req.UDPSize, dns.MinMsgSize)
		if len(response.Data) > int(udpSize) {
			// Pre-packed wire: unpack so Truncate can operate on the RR
			// sections instead of producing an empty message.
			if len(response.Answer) == 0 {
				if err := response.Unpack(); err != nil {
					log.Debugf("SERVER: UDP unpack for truncation failed for %s: %v", w.RemoteAddr().String(), err)
					pool.DefaultMessage.Put(response)
					return
				}
				response.Data = nil
			}
			// RFC 8914 §3: drop EDE options before truncating answer data.
			response.Pseudo = dropEDE(response.Pseudo)
			dnsutil.Truncate(response)
			if err := packSafe(response); err != nil {
				log.Debugf("SERVER: UDP truncate pack error for %s: %v", w.RemoteAddr().String(), err)
				pool.DefaultMessage.Put(response)
				return
			}
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

// dropEDE removes EDE options from Pseudo section before truncation,
// per RFC 8914 §3 SHOULD: drop EDE before dropping answer data.
func dropEDE(pseudo []dns.RR) []dns.RR {
	filtered := pseudo[:0]
	for _, rr := range pseudo {
		if _, ok := rr.(*dns.EDE); !ok {
			filtered = append(filtered, rr)
		}
	}
	return filtered
}
