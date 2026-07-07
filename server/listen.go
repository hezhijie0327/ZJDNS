package server

import (
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
	"zjdns/config"
	"zjdns/internal/dnsutil"
	"zjdns/internal/log"
	"zjdns/internal/pool"

	"codeberg.org/miekg/dns"
	dnsutilv2 "codeberg.org/miekg/dns/dnsutil"
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
	defer dnsutil.HandlePanic("DNS request processing")

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
			msg := pool.DefaultMessagePool.Get()
			dnsutilv2.SetReply(msg, req)
			msg.Rcode = dns.RcodeServerFailure
			if err := msg.Pack(); err != nil {
				log.Debugf("SERVER: TCP SERVFAIL pack error for %s: %v", addr, err)
			}
			if _, err := io.Copy(w, msg); err != nil {
				log.Debugf("SERVER: TCP SERVFAIL write error for %s: %v", addr, err)
			}
			pool.DefaultMessagePool.Put(msg)
			return
		}

		go func() {
			defer func() { <-entry.capacity }()
			defer dnsutil.HandlePanic("TCP query handler")
			response := s.handler.ServeDNS(req, dnsutil.ClientIP(w), false, "TCP")
			if response != nil {
				entry.lastAccess.Store(log.NowUnixNano())
				writeTimer := time.NewTimer(config.DefaultDNSQueryTimeout)
				select {
				case entry.writeMu <- struct{}{}:
					writeTimer.Stop()
					defer func() { <-entry.writeMu }()
				case <-writeTimer.C:
					log.Debugf("SERVER: TCP write lock timeout for %s", addr)
					pool.DefaultMessagePool.Put(response)
					return
				}
				if err := response.Pack(); err != nil {
					log.Debugf("SERVER: TCP pack error for %s: %v", addr, err)
				}
				if _, err := io.Copy(w, response); err != nil {
					log.Debugf("SERVER: TCP write error for %s: %v", addr, err)
				}
				pool.DefaultMessagePool.Put(response)
			}
		}()
		return
	}

	clientIP := dnsutil.ClientIP(w)

	response := s.handler.ServeDNS(req, clientIP, false, detectRequestProtocol(w))
	if response != nil {
		if err := response.Pack(); err != nil {
			log.Debugf("SERVER: UDP pack error for %s: %v", w.RemoteAddr().String(), err)
		}
		if _, err := io.Copy(w, response); err != nil {
			log.Debugf("SERVER: UDP write error for %s: %v", w.RemoteAddr().String(), err)
		}
		pool.DefaultMessagePool.Put(response)
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
