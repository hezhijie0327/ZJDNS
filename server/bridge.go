package server

import (
	"io"
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
		entryI, _ := s.tcpWriteMu.LoadOrStore(addr, &tcpWriteEntry{})
		entry := entryI.(*tcpWriteEntry)
		entry.capacityOnce.Do(func() {
			entry.capacity = make(chan struct{}, config.DefaultMaxPipe)
			entry.writeMu = make(chan struct{}, 1)
		})

		select {
		case entry.capacity <- struct{}{}:
		default:
			msg := pool.DefaultMessage.Get()
			dnsutil.SetReply(msg, req)
			msg.Rcode = dns.RcodeServerFailure
			if err := msg.Pack(); err != nil {
				log.Debugf("SERVER: TCP SERVFAIL pack error for %s: %v", addr, err)
				pool.DefaultMessage.Put(msg)
				return
			}
			if _, err := io.Copy(w, msg); err != nil {
				log.Debugf("SERVER: TCP SERVFAIL write error for %s: %v", addr, err)
			}
			pool.DefaultMessage.Put(msg)
			return
		}

		go func() {
			defer func() { <-entry.capacity }()
			defer zdnsutil.HandlePanic("TCP query handler")

			// Global TCP goroutine bound — matches TLS errgroup.SetLimit.
			select {
			case s.tcpSem <- struct{}{}:
				defer func() { <-s.tcpSem }()
			case <-s.ctx.Done():
				return
			}

			response := s.handler.ServeDNS(req, zdnsutil.ClientIP(w), false, config.ProtoTCP)
			if response != nil {
				entry.lastAccess.Store(log.NowUnixNano())

				// Pack before acquiring writeMu — keeps the lock
				// critical section I/O-only and brief (P2).
				if err := response.Pack(); err != nil {
					log.Debugf("SERVER: TCP pack error for %s: %v", addr, err)
					pool.DefaultMessage.Put(response)
					return
				}

				writeTimer := time.NewTimer(config.DefaultDNSQueryTimeout)
				select {
				case entry.writeMu <- struct{}{}:
					writeTimer.Stop()
					defer func() { <-entry.writeMu }()
				case <-writeTimer.C:
					log.Debugf("SERVER: TCP write lock timeout for %s", addr)
					pool.DefaultMessage.Put(response)
					return
				}
				if _, err := io.Copy(w, response); err != nil {
					log.Debugf("SERVER: TCP write error for %s: %v", addr, err)
				}
				pool.DefaultMessage.Put(response)
			}
		}()
		return
	}

	clientIP := zdnsutil.ClientIP(w)

	response := s.handler.ServeDNS(req, clientIP, false, detectRequestProtocol(w))
	if response != nil {
		if err := response.Pack(); err != nil {
			log.Debugf("SERVER: UDP pack error for %s: %v", w.RemoteAddr().String(), err)
			pool.DefaultMessage.Put(response)
			return
		}

		// RFC 2181 §9: if the response exceeds the client's EDNS buffer,
		// truncate and set TC so the client retries over TCP.
		udpSize := max(req.UDPSize, dns.MinMsgSize)
		if response.Len() > int(udpSize) {
			dnsutil.Truncate(response)
			if err := response.Pack(); err != nil {
				log.Debugf("SERVER: UDP truncate pack error for %s: %v", w.RemoteAddr().String(), err)
				pool.DefaultMessage.Put(response)
				return
			}
		}

		if _, err := io.Copy(w, response); err != nil {
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
