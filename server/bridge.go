package server

import (
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
		// NOTE: Lazy init via LoadOrStore + capacityOnce.Do means the map
		// entry exists before channels are ready. Concurrent readers of
		// entry.capacity or entry.writeMu between LoadOrStore and the Do
		// closure would see nil channels, causing a nil-send hang. This is
		// safe because the entry is only read after the Do completes within
		// the same request goroutine -- the first request creates the entry
		// synchronously and all subsequent requests find a fully-initialized one.
		entryI, _ := s.tcpWriteMu.LoadOrStore(addr, &tcpWriteEntry{})
		entry, ok := entryI.(*tcpWriteEntry)
		if !ok {
			log.Warnf("SERVER: unexpected type in tcpWriteMu for %s: %T", addr, entryI)
			return
		}
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
				// critical section I/O-only and brief (P2).
				if err := packSafe(response); err != nil {
					log.Debugf("SERVER: TCP pack error for %s: %v", addr, err)
					pool.DefaultMessage.Put(response)
					return
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
				// Use WriteTo, not w.Write(response.Data).
				// WriteTo adds the 2-byte TCP length prefix per RFC 1035 §4.2.2
				// and handles the connected-UDP WriteMsgUDP path.
				if _, err := response.WriteTo(w); err != nil {
					log.Debugf("SERVER: TCP write error for %s: %v", addr, err)
				}
				pool.DefaultMessage.Put(response)
			}
		}()
		return
	}

	clientIP := net.ParseIP(dnsutil.RemoteIP(w))

	response := s.handler.ServeDNS(req, clientIP, false, detectRequestProtocol(w))
	if response != nil {
		if err := packSafe(response); err != nil {
			log.Debugf("SERVER: UDP pack error for %s: %v", w.RemoteAddr().String(), err)
			pool.DefaultMessage.Put(response)
			return
		}

		// RFC 2181 §9: if the response exceeds the client's EDNS buffer,
		// truncate and set TC so the client retries over TCP.
		udpSize := max(req.UDPSize, dns.MinMsgSize)
		if response.Len() > int(udpSize) {
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

func detectRequestProtocol(w dns.ResponseWriter) string {
	addr := w.RemoteAddr()
	if addr == nil {
		return config.ProtoUDP
	}
	network := addr.Network()
	if network != "" {
		switch network[0] {
		case 't', 'T':
			return config.ProtoTCP
		}
	}
	return config.ProtoUDP
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
