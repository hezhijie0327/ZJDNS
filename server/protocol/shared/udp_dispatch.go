// The shared-UDP runtime: per-group listener startup, the demultiplex
// dispatch loop (protocol sniffing: DTLS/DTLCP/DNSCrypt/QUIC/HTTP3), and
// idle client reaping.

package shared

import (
	"math"
	"net"
	"strings"
	"sync"
	"time"
	"zjdns/config"
	"zjdns/internal/demux"
	"zjdns/internal/log"
	"zjdns/internal/pool"

	zdnsutil "zjdns/internal/dnsutil"
)

func (m *Mux) startUDPGroup(g *UDPGroup) error {
	addrs, err := zdnsutil.ResolveBindAddrs("udp", g.Port)
	if err != nil {
		return err
	}

	// Build a log label reflecting the active protocol combination.
	label := "SHARED"
	var parts []string
	if g.DOQHandler != nil {
		parts = append(parts, "DoQ")
	}
	if g.HTTP3Handler != nil {
		parts = append(parts, "DoH3")
	}
	if g.DTLSHandler != nil {
		parts = append(parts, "DTLS")
	}
	if g.ServeDTLCP != nil {
		parts = append(parts, "DTLCP")
	}
	if g.ServeDNSCrypt != nil {
		parts = append(parts, "DNSCrypt")
	}
	if len(parts) > 0 {
		label += ": " + joinStrings(parts, ", ")
	}
	log.Infof("%s server started on %v", label, addrs)
	for _, addr := range addrs {
		udpAddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			return err
		}

		udpConn, err := net.ListenUDP("udp", udpAddr)
		if err != nil {
			return err
		}

		rt := &udpRuntime{
			cfg:  g,
			conn: udpConn,
		}

		if g.DTLSHandler != nil || g.ServeDTLCP != nil {
			rt.dtlsPL = newDTLSPacketListener(udpConn)
		}

		if g.ServeDNSCrypt != nil {
			rt.dcState = &sharedDNSCryptClient{
				conns: make(map[addrKey]*DemuxPacketConn),
			}
		}

		if g.ServeDTLCP != nil {
			rt.dtlcpState = &sharedDTLSClient{
				conns: make(map[addrKey]*DemuxPacketConn),
			}
		}

		// Flood bound for per-client handler goroutines (P3).
		rt.clientSem = make(chan struct{}, config.DefaultServerGoroutineLimit)

		if g.DOQHandler != nil {
			rt.quicPC = newQUICPacketConn(udpConn)

			capturedQUIC := rt.quicPC
			capturedHandler := g.DOQHandler
			m.host.Go(func() error {
				defer zdnsutil.HandlePanic("Shared DoQ server")
				if err := capturedHandler(capturedQUIC); err != nil {
					if m.host.Ctx().Err() != nil {
						return nil
					}
					log.Warnf("TLS: shared-port DoQ error: %v", err)
				}
				return nil
			})
		}

		if g.HTTP3Handler != nil {
			rt.h3PC = newQUICPacketConn(udpConn)

			capturedH3 := rt.h3PC
			capturedHandler := g.HTTP3Handler
			m.host.Go(func() error {
				defer zdnsutil.HandlePanic("Shared DoH3 server")
				if err := capturedHandler(capturedH3); err != nil {
					if m.host.Ctx().Err() != nil {
						return nil
					}
					log.Warnf("TLS: shared-port DoH3 error: %v", err)
				}
				return nil
			})
		}

		if g.DTLSHandler != nil {
			capturedDTLS := rt.dtlsPL
			capturedHandler := g.DTLSHandler
			m.host.Go(func() error {
				defer zdnsutil.HandlePanic("Shared DTLS server")
				if err := capturedHandler(capturedDTLS); err != nil {
					if m.host.Ctx().Err() != nil {
						return nil
					}
					log.Warnf("TLS: shared-port DTLS error: %v", err)
				}
				return nil
			})
		}

		m.mu.Lock()
		m.udpRuntimes = append(m.udpRuntimes, rt)
		m.mu.Unlock()

		capturedRT := rt
		m.host.Go(func() error {
			defer zdnsutil.HandlePanic("Shared UDP dispatch")
			m.udpDispatchLoop(capturedRT)
			return nil
		})
	}
	return nil
}

// joinStrings joins strings with a separator (avoids importing strings
// for a single Join call in the log label builder).
func joinStrings(elems []string, sep string) string {
	if len(elems) == 0 {
		return ""
	}
	var result strings.Builder
	result.WriteString(elems[0])
	for _, e := range elems[1:] {
		result.WriteString(sep + e)
	}
	return result.String()
}

// udpDispatchLoop reads datagrams from the shared UDP socket,
// detects DNSCrypt vs QUIC vs DTLS vs DTLCP from the first datagram of
// each client, and routes subsequent datagrams accordingly.
// DNSCrypt classification (via ClassifyDNSCrypt callback) runs before
// QUIC/DTLS/DTLCP detection because DNSCrypt client magic may collide
// with those protocols' byte ranges.
//
// Per-packet allocation-free: the read buffer is pooled (PacketBufPool),
// the map key is a value-type addrKey (no src.String()), and the pooled
// buffer is passed through channels — consumers copy out and return it.
func (m *Mux) udpDispatchLoop(rt *udpRuntime) {
	g := rt.cfg
	udpConn := rt.conn
	dtlsPL := rt.dtlsPL
	quicPC := rt.quicPC
	h3PC := rt.h3PC
	dnscryptState := rt.dcState
	dtlcpState := rt.dtlcpState

	peerProto := make(map[addrKey]string)
	var peerMu sync.RWMutex

	// Read bound: 8 KiB (pool.SecureBufferSize).  Go's ReadFromUDP
	// silently truncates larger datagrams; QUIC initial packets are ≤1280
	// by design and DNSCrypt frames are capped at 4096, so this bound is
	// safe for every multiplexed protocol (standalone DoQ/DoH3 listeners,
	// where quic-go reads the raw socket itself, are unaffected) (P-L4).
	buf := make([]byte, pool.SecureBufferSize)

	var pktCount uint32
	var lastReap time.Time

	// Exit sweep: closing every per-client conn unblocks the parked client
	// goroutines (DNSCrypt drain `<-Ch`, DTLCP handshake reads) — without
	// this they leaked past Shutdown and stalled the server's background
	// group wait for its full timeout (2026-09 X4).
	defer reapIdleUDPClients(dtlcpState, dnscryptState, dtlsPL, math.MaxInt64)

	for {
		select {
		case <-m.groupCtx.Done():
			return
		default:
		}

		n, src, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-m.groupCtx.Done():
				return
			default:
			}
			if zdnsutil.IsTemporaryError(err) {
				continue
			}
			return
		}

		pb := PacketBufPool.Get().(*[]byte)
		copy(*pb, buf[:n])

		// Amortised idle-client reaping: per-client conns whose peer went
		// silent are closed and forgotten, bounding the maps under NAT
		// churn and spoofed-source floods.  Runs inline in the dispatch
		// loop — the ONLY sender to the per-client channels — so closing
		// under the map lock cannot race a concurrent dispatch.
		pktCount++
		if pktCount%reapCheckEveryPackets == 0 {
			// Classification-map bound: checked every gate regardless of the
			// reap clock — under a spoofed-source flood the map can exceed
			// peerProtoMax within a single 30s reap window (2026-09 P3).
			peerMu.Lock()
			if len(peerProto) >= peerProtoMax {
				peerProto = make(map[addrKey]string, peerProtoMax)
			}
			peerMu.Unlock()
			if now := time.Now(); now.Sub(lastReap) >= clientIdleTimeout/2 {
				lastReap = now
				cutoff := now.Unix() - int64(clientIdleTimeout/time.Second)
				reapIdleUDPClients(dtlcpState, dnscryptState, dtlsPL, cutoff)
			}
		}

		key := makeAddrKey(src)

		peerMu.RLock()
		proto, known := peerProto[key]
		peerMu.RUnlock()

		if !known {
			// 1. DNSCrypt encrypted query detection (priority — client_magic
			//    may collide with QUIC/DTLS byte ranges).
			if g.ClassifyDNSCrypt != nil {
				proto = g.ClassifyDNSCrypt((*pb)[:n])
			}
			// 2. Standard QUIC/DTLS/DTLCP detection.
			if proto == "" {
				proto = demux.DetectUDPProtocol((*pb)[:n])
			}
			// 3. DNSCrypt cert handshake fallback: the cert fetch is a
			//    plain DNS TXT query (no client_magic), so it does not match
			//    steps 1–2.  Route to DNSCrypt when configured — it handles
			//    both cert handshakes and encrypted queries.
			if proto == "" && g.ServeDNSCrypt != nil {
				proto = demux.ProtoDNSCrypt
			}
			if proto == "" {
				PacketBufPool.Put(pb)
				continue
			}
			peerMu.Lock()
			peerProto[key] = proto
			peerMu.Unlock()
		}

		switch proto {
		case demux.ProtoQUIC:
			// Route to DoQ handler if available; otherwise fall back
			// to HTTP3 handler (both use QUIC and are indistinguishable
			// at the byte level — port assignment determines the protocol).
			switch {
			case quicPC != nil:
				quicPC.dispatch(src, pb, n)
			case h3PC != nil:
				h3PC.dispatch(src, pb, n)
			default:
				PacketBufPool.Put(pb)
			}

		case demux.ProtoDTLS:
			if g.DTLSHandler != nil {
				dtlsPL.dispatch(src, pb, n)
			} else {
				PacketBufPool.Put(pb)
			}

		case demux.ProtoDTLCP:
			if g.ServeDTLCP == nil {
				PacketBufPool.Put(pb)
				continue
			}
			dtlcpState.mu.Lock()
			dc, ok := dtlcpState.conns[key]
			if !ok {
				if !rt.admit() {
					// Per-client cap reached — spoofed-source flood bound;
					// drop like a full queue, the client retransmits (P3).
					dtlcpState.mu.Unlock()
					PacketBufPool.Put(pb)
					continue
				}
				dc = &DemuxPacketConn{
					Shared: udpConn,
					Remote: src,
					Ch:     make(chan DemuxPacket, 32),
				}
				dtlcpState.conns[key] = dc
				dtlcpState.mu.Unlock()

				capturedDC := dc
				capturedSrc := src
				capturedKey := key
				capturedHandler := g.ServeDTLCP
				m.host.Go(func() error {
					defer zdnsutil.HandlePanic("Shared DTLCP client")
					defer rt.release()
					capturedHandler(capturedDC, capturedSrc, func() {
						dtlcpState.mu.Lock()
						delete(dtlcpState.conns, capturedKey)
						dtlcpState.mu.Unlock()
					})
					return nil
				})
			} else {
				dtlcpState.mu.Unlock()
			}

			dc.lastSeen.Store(log.NowUnix())
			if !dc.Send(DemuxPacket{Data: (*pb)[:n], Addr: src}) {
				PacketBufPool.Put(pb)
			}

		case demux.ProtoDNSCrypt:
			if dnscryptState == nil || g.ServeDNSCrypt == nil {
				PacketBufPool.Put(pb)
				continue
			}
			dnscryptState.mu.Lock()
			dc, ok := dnscryptState.conns[key]
			if !ok {
				if !rt.admit() {
					// Per-client cap reached — spoofed-source flood bound (P3).
					dnscryptState.mu.Unlock()
					PacketBufPool.Put(pb)
					continue
				}
				dc = &DemuxPacketConn{
					Shared: udpConn,
					Remote: src,
					Ch:     make(chan DemuxPacket, 32),
				}
				dnscryptState.conns[key] = dc
				dnscryptState.mu.Unlock()

				capturedDC := dc
				capturedHandler := g.ServeDNSCrypt
				// Per-client worker admission: DNSCrypt queries are stateless
				// datagrams, so each packet goes to its own goroutine — the
				// former synchronous drain (decrypt→resolve→respond inline in
				// the drain loop) let one slow upstream stall every later
				// packet of the client.  Saturated → drop (client retransmits).
				sem := make(chan struct{}, config.DefaultMaxPipe)
				m.host.Go(func() error {
					defer zdnsutil.HandlePanic("Shared DNSCrypt UDP client")
					defer rt.release()
					for {
						pkt, pktOk := <-capturedDC.Ch
						if !pktOk {
							return nil
						}
						select {
						case sem <- struct{}{}:
						default:
							full := pkt.Data[:cap(pkt.Data)]
							PacketBufPool.Put(&full)
							continue
						}
						go func(pkt DemuxPacket) {
							defer func() { <-sem }()
							defer zdnsutil.HandlePanic("Shared DNSCrypt UDP query")
							capturedHandler(m.host.Ctx(), pkt.Data, pkt.Addr, capturedDC)
							full := pkt.Data[:cap(pkt.Data)]
							PacketBufPool.Put(&full)
						}(pkt)
					}
				})
			} else {
				dnscryptState.mu.Unlock()
			}

			dc.lastSeen.Store(log.NowUnix())
			if !dc.Send(DemuxPacket{Data: (*pb)[:n], Addr: src}) {
				PacketBufPool.Put(pb)
			}
		}
	}
}

// reapIdleUDPClients closes and forgets per-client conns idle since before
// the cutoff (unix seconds) across the DTLCP, DNSCrypt and DTLS client
// maps.  Must be called from the dispatch loop — the sole channel sender —
// so a close can never race an in-flight dispatch send.  Closing the
// channels unblocks the parked client goroutines (DNSCrypt drain loop,
// DTLCP handler read, DTLS accept read), which then run their own cleanup
// callbacks; the double delete is idempotent.
func reapIdleUDPClients(dtlcpState *sharedDTLSClient, dnscryptState *sharedDNSCryptClient, dtlsPL *dtlsPacketListener, cutoff int64) {
	// Close() (not a bare close(Ch)) — the CAS guard makes a later
	// handler-side Close idempotent instead of panicking on double close.
	if dtlcpState != nil {
		dtlcpState.mu.Lock()
		for k, dc := range dtlcpState.conns {
			if dc.lastSeen.Load() < cutoff {
				delete(dtlcpState.conns, k)
				_ = dc.Close()
			}
		}
		dtlcpState.mu.Unlock()
	}
	if dnscryptState != nil {
		dnscryptState.mu.Lock()
		for k, dc := range dnscryptState.conns {
			if dc.lastSeen.Load() < cutoff {
				delete(dnscryptState.conns, k)
				_ = dc.Close()
			}
		}
		dnscryptState.mu.Unlock()
	}
	if dtlsPL != nil {
		dtlsPL.mu.Lock()
		for k, cc := range dtlsPL.clients {
			if cc.lastSeen.Load() < cutoff {
				delete(dtlsPL.clients, k)
				_ = cc.Close()
			}
		}
		dtlsPL.mu.Unlock()
	}
}
