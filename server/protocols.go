package server

import (
	_ "expvar" // /debug/vars: runtime MemStats for RSS diagnosis (served only when pprof is enabled)
	"fmt"
	"net"
	"net/http"
	_ "net/http/pprof" //nolint:gosec // G108: pprof is off unless configured
	"zjdns/config"
	"zjdns/internal/log"
	"zjdns/server/handler"
	"zjdns/server/protocol/shared"
	"zjdns/server/protocol/tls"

	zdnsutil "zjdns/internal/dnsutil"

	serverdnscrypt "zjdns/server/protocol/dnscrypt"
	serverplain "zjdns/server/protocol/plain"
	servertlcp "zjdns/server/protocol/tlcp"
)

// initProtocolListeners creates and wires all protocol servers (TLS, TLCP,
// DNSCrypt, Plain) into the Server struct.  The first error is returned and
// fails New() — a configured protocol that cannot initialise (bad
// certificate, invalid port) is a configuration error, not something to
// silently skip.
func (s *Server) initProtocolListeners(cfg *config.ServerConfig, h *handler.Handler) error {
	// Detect shared ports early so protocol servers can coordinate:
	//   - TCP 443: HTTPS + HTTPoverTLCP + DNSCrypt (any subset ≥2)
	//   - TCP 853: TLS(DoT) + TLCP(DoT) (record-layer demux)
	//   - UDP:     any combination of QUIC(DoQ), DTLS, DTLCP, DNSCrypt, HTTP3
	wantShared := cfg.Server.Protocol.HTTPS.Port != "" &&
		cfg.Server.Certificate.TLS.IsEnabled() &&
		((cfg.Server.Protocol.HTTPS.Port == cfg.Server.Protocol.HTTPTLCP.Port && cfg.Server.Certificate.TLCP.IsEnabled()) ||
			(cfg.Server.Protocol.DNSCrypt != "" && cfg.Server.Protocol.DNSCrypt == cfg.Server.Protocol.HTTPS.Port &&
				cfg.Server.Certificate.DNSCrypt.PublicKey != "" && cfg.Server.Certificate.DNSCrypt.PrivateKey != ""))
	wantSharedDOT := cfg.Server.Protocol.TLS != "" &&
		cfg.Server.Protocol.TLS == cfg.Server.Protocol.TLCP &&
		cfg.Server.Certificate.TLS.IsEnabled() &&
		cfg.Server.Certificate.TLCP.IsEnabled()
	// UDP port sharing: detect per-protocol-pair sharing.
	// Each combination only checks the certificates it actually needs:
	// QUIC/DTLS/HTTP3 use TLS certs; DTLCP/DTLCP use TLCP certs.
	dtlsDTLCPShare := cfg.Server.Protocol.DTLS != "" &&
		cfg.Server.Protocol.DTLS == cfg.Server.Protocol.DTLCP &&
		cfg.Server.Certificate.TLS.IsEnabled() && cfg.Server.Certificate.TLCP.IsEnabled()
	quicDTLSShare := cfg.Server.Protocol.QUIC != "" &&
		cfg.Server.Protocol.QUIC == cfg.Server.Protocol.DTLS &&
		cfg.Server.Certificate.TLS.IsEnabled()
	quicDTLCPShare := cfg.Server.Protocol.QUIC != "" &&
		cfg.Server.Protocol.QUIC == cfg.Server.Protocol.DTLCP &&
		cfg.Server.Certificate.TLS.IsEnabled() && cfg.Server.Certificate.TLCP.IsEnabled()

	// DNSCrypt shared-port detection:
	//   - TCP 443: DNSCrypt + DoH + HTTPoverTLCP (length-prefix demux)
	//   - UDP:     DNSCrypt + QUIC/DTLS/DTLCP/HTTP3 (client-magic demux)
	dnsCryptReady := cfg.Server.Protocol.DNSCrypt != "" &&
		cfg.Server.Certificate.DNSCrypt.PublicKey != "" &&
		cfg.Server.Certificate.DNSCrypt.PrivateKey != ""
	wantSharedDNSTCP := dnsCryptReady &&
		cfg.Server.Protocol.DNSCrypt == cfg.Server.Protocol.HTTPS.Port
	wantSharedDNSUDP := dnsCryptReady &&
		(cfg.Server.Protocol.DNSCrypt == cfg.Server.Protocol.QUIC ||
			cfg.Server.Protocol.DNSCrypt == cfg.Server.Protocol.HTTP3.Port ||
			cfg.Server.Protocol.DNSCrypt == cfg.Server.Protocol.DTLS ||
			cfg.Server.Protocol.DNSCrypt == cfg.Server.Protocol.DTLCP)
	// wantSharedUDP: true when ANY two UDP protocols share a port.
	wantSharedUDP := dtlsDTLCPShare || quicDTLSShare || quicDTLCPShare || wantSharedDNSUDP

	// Per-protocol "port is shared" checks for skip flags and handler wiring.
	// Each is true when the protocol's UDP port has ≥2 protocols on it.
	quicPortShared := (cfg.Server.Protocol.QUIC != "") &&
		(cfg.Server.Protocol.QUIC == cfg.Server.Protocol.DTLS ||
			cfg.Server.Protocol.QUIC == cfg.Server.Protocol.DTLCP ||
			(dnsCryptReady && cfg.Server.Protocol.QUIC == cfg.Server.Protocol.DNSCrypt))
	dtlsPortShared := (cfg.Server.Protocol.DTLS != "") &&
		(cfg.Server.Protocol.DTLS == cfg.Server.Protocol.QUIC ||
			cfg.Server.Protocol.DTLS == cfg.Server.Protocol.DTLCP ||
			(dnsCryptReady && cfg.Server.Protocol.DTLS == cfg.Server.Protocol.DNSCrypt))
	http3PortShared := (cfg.Server.Protocol.HTTP3.Port != "") &&
		(dnsCryptReady && cfg.Server.Protocol.HTTP3.Port == cfg.Server.Protocol.DNSCrypt)

	// Parse the trusted-proxy list once for all HTTP-based listeners (DoH,
	// DoH3, HTTPTLCP).  Load-time validation already rejects bad entries.
	trustedProxies, err := cfg.Server.ParsedTrustedProxies()
	if err != nil {
		return fmt.Errorf("parse trusted proxies: %w", err)
	}
	if len(trustedProxies) > 0 {
		log.Infof("CONFIG: trusted proxies enabled for HTTP listeners (DoH/DoH3/HTTPTLCP): %d network(s)", len(trustedProxies))
	}

	if cfg.Server.Certificate.TLS.IsEnabled() {
		tlsCfg := tls.Config{
			TLSPort:       cfg.Server.Protocol.TLS,
			QUICPort:      cfg.Server.Protocol.QUIC,
			DTLSPort:      cfg.Server.Protocol.DTLS,
			HTTPSPort:     cfg.Server.Protocol.HTTPS.Port,
			HTTP3Port:     cfg.Server.Protocol.HTTP3.Port,
			HTTPSEndpoint: cfg.Server.Protocol.HTTPS.Endpoint,
			HTTP3Endpoint: cfg.Server.Protocol.HTTP3.Endpoint,
			SelfSigned:    cfg.Server.Certificate.TLS.SelfSigned,
			CertFile:      cfg.Server.Certificate.TLS.CertFile,
			KeyFile:       cfg.Server.Certificate.TLS.KeyFile,
			Domain:        cfg.Server.Certificate.Domain,

			TrustedProxies: trustedProxies,
		}
		if cfg.Server.Features.KTLS != nil {
			tlsCfg.KTLS = &tls.KTLSSettings{KernelTX: cfg.Server.Features.KTLS.KernelTX, KernelRX: cfg.Server.Features.KTLS.KernelRX}
		}
		if wantShared {
			tlsCfg.SkipHTTPS = true
		}
		if wantSharedDOT {
			tlsCfg.SkipDOT = true
		}
		if dtlsPortShared {
			tlsCfg.SkipDTLS = true
		}
		if quicPortShared {
			tlsCfg.SkipDOQ = true
		}
		if http3PortShared {
			tlsCfg.SkipHTTP3 = true
		}
		tlsSrv, err := tls.New(h, &tlsCfg)
		if err != nil {
			return fmt.Errorf("TLS server init: %w", err)
		}
		s.tls = tlsSrv
	}

	// Create the TLCP server before the shared Manager so that TLCP-side
	// handlers can be wired into the shared config.
	if cfg.Server.Certificate.TLCP.IsEnabled() && (cfg.Server.Protocol.TLCP != "" || cfg.Server.Protocol.HTTPTLCP.Port != "" || cfg.Server.Protocol.DTLCP != "") {
		tlcpSrv, err := servertlcp.New(&servertlcp.Options{
			Certificate: &cfg.Server.Certificate.TLCP,
			Domain:      cfg.Server.Certificate.Domain,
			DOTPort:     cfg.Server.Protocol.TLCP,
			DOHPort:     cfg.Server.Protocol.HTTPTLCP.Port,
			DOHEndpoint: cfg.Server.Protocol.HTTPTLCP.Endpoint,
			DTLCPPort:   cfg.Server.Protocol.DTLCP,
		})
		if err != nil {
			return fmt.Errorf("TLCP server init: %w", err)
		}
		tlcpSrv.SetTrustedProxies(trustedProxies)
		tlcpSrv.SetDomain(cfg.Server.Certificate.Domain)
		s.tlcpServer = tlcpSrv
	}

	// Create the DNSCrypt server BEFORE the shared Manager so that its
	// callbacks can be wired into the shared config.
	if cfg.Server.Protocol.DNSCrypt != "" {
		providerName := cfg.Server.Certificate.DNSCrypt.ProviderName(cfg.Server.Certificate.Domain)
		stateStore := serverdnscrypt.NewFileStore(cfg.Server.Certificate.DNSCrypt.StateFile)
		dnscryptSrv, err := serverdnscrypt.New(&cfg.Server.Certificate.DNSCrypt, cfg.Server.Protocol.DNSCrypt, providerName, stateStore)
		if err != nil {
			return fmt.Errorf("DNSCrypt server init: %w", err)
		}
		s.dnscryptServer = dnscryptSrv
	}

	// Build the shared-port Manager now that both protocol servers exist.
	if wantShared || wantSharedDOT || wantSharedUDP || wantSharedDNSTCP || wantSharedDNSUDP {
		sharedCfg := shared.Config{}
		// Build TCP groups.
		wrapConn := func(c net.Conn, nextProtos []string) net.Conn {
			if s.tlcpServer != nil {
				return s.tlcpServer.WrapTLCPConn(c, nextProtos)
			}
			return c
		}
		tcpGroups := make([]shared.TCPGroup, 0, 2)
		if wantShared {
			g := shared.TCPGroup{
				Port:       cfg.Server.Protocol.HTTPS.Port,
				TLSCfg:     s.tls.ETLSConfigForDOH(),
				NextProtos: config.NextProtoDOH,
				DOHHandler: s.tls.DOHHandler(),
				WrapConn:   wrapConn,
			}
			if s.tlcpServer != nil && cfg.Server.Protocol.HTTPTLCP.Port == cfg.Server.Protocol.HTTPS.Port {
				// The mux serves HTTPoverTLCP on this port — the standalone
				// DoH-TLCP listener would EADDRINUSE.  DoH-TLCP joins ONLY
				// when its configured port IS this group's port: attaching it
				// on a port mismatch would serve TLCP-record connections with
				// a handler configured for a different port (and wire it even
				// when HTTPTLCP was never configured at all).
				s.tlcpServer.SkipDOH = true
				g.DOHTLCP = http.HandlerFunc(s.tlcpServer.ServeDOH)
				g.DOHConnContext = servertlcp.StashConn
			}
			if s.dnscryptServer != nil && wantSharedDNSTCP {
				g.ServeDNSCryptTCP = s.dnscryptServer.HandleSharedTCPConn
			}
			tcpGroups = append(tcpGroups, g)
		}
		if wantSharedDOT {
			// The mux serves both DoT flavors on this port — skip the
			// standalone TLCP DoT bind (tls.Server gets SkipDOT above).
			s.tlcpServer.SkipDOT = true
			tcpGroups = append(tcpGroups, shared.TCPGroup{
				Port:       cfg.Server.Protocol.TLS,
				TLSCfg:     s.tls.ETLSConfigForDOH(),
				NextProtos: config.NextProtoDOT,
				DOTHandler: s.tls.HandleDOTFromListener,
				DOTTLCP:    s.tlcpServer.ServeDOT,
				WrapConn:   wrapConn,
			})
		}
		sharedCfg.TCPGroups = tcpGroups
		if wantSharedUDP {
			// One group per genuinely shared UDP port (≥2 multiplexed
			// protocols on it).  Wiring a single "primary" port and
			// attaching handlers whose configured port differed from it
			// double-bound ports (REUSEPORT group vs standalone bind) or
			// served protocols on ports they were not configured for.
			dtlcpShared := cfg.Server.Protocol.DTLCP != "" &&
				(dtlsDTLCPShare || quicDTLCPShare ||
					(wantSharedDNSUDP && cfg.Server.Protocol.DTLCP == cfg.Server.Protocol.DNSCrypt))
			sharedPorts := make(map[string]struct{}, 2)
			addSharedPort := func(p string) { sharedPorts[p] = struct{}{} }
			if quicPortShared {
				addSharedPort(cfg.Server.Protocol.QUIC)
			}
			if dtlsPortShared {
				addSharedPort(cfg.Server.Protocol.DTLS)
			}
			if dtlcpShared {
				addSharedPort(cfg.Server.Protocol.DTLCP)
			}
			if wantSharedDNSUDP {
				addSharedPort(cfg.Server.Protocol.DNSCrypt)
			}

			udpGroups := make([]shared.UDPGroup, 0, len(sharedPorts))
			for port := range sharedPorts {
				g := shared.UDPGroup{Port: port}
				if quicPortShared && cfg.Server.Protocol.QUIC == port {
					g.DOQHandler = s.tls.HandleDOQFromPacketConn
				}
				if dtlsPortShared && cfg.Server.Protocol.DTLS == port {
					g.DTLSHandler = s.tls.HandleDTLSFromPacketListener
				}
				if s.tlcpServer != nil && dtlcpShared && cfg.Server.Protocol.DTLCP == port {
					// The mux serves DTLCP on this UDP port — skip the
					// standalone DTLCP bind.
					s.tlcpServer.SkipDTLCP = true
					g.ServeDTLCP = s.tlcpServer.ServeDTLCPClient
				}
				if wantSharedDNSUDP && cfg.Server.Protocol.DNSCrypt == port {
					g.ServeDNSCrypt = s.dnscryptServer.HandleSharedUDPPacket
					g.ClassifyDNSCrypt = func(data []byte) string {
						if s.dnscryptServer.HasClientMagic(data) {
							return "dnscrypt"
						}
						return ""
					}
					if http3PortShared && cfg.Server.Protocol.HTTP3.Port == port {
						if cfg.Server.Protocol.QUIC == port && quicPortShared {
							// DoQ and DoH3 initial datagrams are both QUIC
							// long headers — the demux layer cannot tell
							// them apart, and the dispatch would route
							// every datagram to DoQ, silently blackholing
							// DoH3 on this port.
							return fmt.Errorf("http3 and quic cannot share UDP port %s: their initial datagrams are indistinguishable", port)
						}
						g.HTTP3Handler = s.tls.HandleHTTP3FromPacketConn
					}
				}
				udpGroups = append(udpGroups, g)
			}
			sharedCfg.UDPGroups = udpGroups
		}
		s.sharedManager = shared.New(s, &sharedCfg)
	}

	s.plain = serverplain.New(cfg)
	return nil
}

// initPprof starts the optional pprof HTTP listener on all interfaces.
func (s *Server) initPprof(cfg *config.ServerConfig) {
	if cfg.Server.Pprof == "" {
		return
	}
	addrs, err := zdnsutil.ResolveBindAddrs("tcp", cfg.Server.Pprof)
	if err != nil {
		log.Warnf("PPROF: skipping — no available bind address for port %s: %v", cfg.Server.Pprof, err)
		return
	}
	s.pprofServers = make([]*http.Server, 0, len(addrs))
	for _, addr := range addrs {
		s.pprofServers = append(s.pprofServers, &http.Server{
			Addr:              addr,
			ReadHeaderTimeout: config.DefaultHTTPReadHeaderTimeout,
			ReadTimeout:       0,
			IdleTimeout:       config.DefaultHTTPServerIdleTimeout,
			// net/http/pprof's init registers /debug/pprof/ here; without a
			// handler every pprof path would 404.
			Handler: http.DefaultServeMux,
		})
	}
}

// ServeDNS delegates to the query handler. Required by server/tls.DNSHandler
// interface and external benchmarks.
