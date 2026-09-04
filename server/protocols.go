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
// silently skip (M-low).
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
		tlcpSrv, err := servertlcp.New(&cfg.Server.Certificate.TLCP, cfg.Server.Protocol.TLCP, cfg.Server.Protocol.HTTPTLCP.Port, cfg.Server.Protocol.HTTPTLCP.Endpoint, cfg.Server.Protocol.DTLCP)
		if err != nil {
			return fmt.Errorf("TLCP server init: %w", err)
		}
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
			if s.tlcpServer != nil {
				g.DOHTLCP = http.HandlerFunc(s.tlcpServer.ServeDOH)
			}
			if s.dnscryptServer != nil && wantSharedDNSTCP {
				g.ServeDNSCryptTCP = s.dnscryptServer.HandleSharedTCPConn
			}
			tcpGroups = append(tcpGroups, g)
		}
		if wantSharedDOT {
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
			// Determine the primary UDP port from QUIC/DTLS/DTLCP.
			primaryPort := cfg.Server.Protocol.QUIC
			if primaryPort == "" {
				primaryPort = cfg.Server.Protocol.DTLS
			}
			if primaryPort == "" {
				primaryPort = cfg.Server.Protocol.DTLCP
			}
			hasQuicDTLSDTLCP := primaryPort != ""

			// Build UDP groups (pre-allocate capacity 2 so pointers
			// remain stable after append).
			udpGroups := make([]shared.UDPGroup, 0, 2)

			if hasQuicDTLSDTLCP {
				// Primary group: QUIC/DTLS/DTLCP (+ DNSCrypt/HTTP3 if same port).
				dnsCryptOnPrimary := wantSharedDNSUDP &&
					cfg.Server.Protocol.DNSCrypt == primaryPort

				// Only create the primary group if there are actual
				// handlers (i.e. protocols share or DNSCrypt joins).
				hasPrimaryHandlers := quicPortShared || dtlsPortShared ||
					dnsCryptOnPrimary || s.tlcpServer != nil

				if hasPrimaryHandlers {
					primary := shared.UDPGroup{Port: primaryPort}
					if quicPortShared {
						primary.DOQHandler = s.tls.HandleDOQFromPacketConn
					}
					if dtlsPortShared {
						primary.DTLSHandler = s.tls.HandleDTLSFromPacketListener
					}
					if s.tlcpServer != nil && cfg.Server.Protocol.DTLCP != "" {
						primary.ServeDTLCP = s.tlcpServer.ServeDTLCPClient
					}
					if dnsCryptOnPrimary {
						primary.ServeDNSCrypt = s.dnscryptServer.HandleSharedUDPPacket
						primary.ClassifyDNSCrypt = func(data []byte) string {
							if s.dnscryptServer.HasClientMagic(data) {
								return "dnscrypt"
							}
							return ""
						}
						if cfg.Server.Protocol.HTTP3.Port == primaryPort {
							primary.HTTP3Handler = s.tls.HandleHTTP3FromPacketConn
						}
					}
					udpGroups = append(udpGroups, primary)
				}

				// Secondary group: DNSCrypt (+ HTTP3) on a different port.
				if wantSharedDNSUDP && !dnsCryptOnPrimary {
					sec := shared.UDPGroup{
						Port:          cfg.Server.Protocol.DNSCrypt,
						ServeDNSCrypt: s.dnscryptServer.HandleSharedUDPPacket,
						ClassifyDNSCrypt: func(data []byte) string {
							if s.dnscryptServer.HasClientMagic(data) {
								return "dnscrypt"
							}
							return ""
						},
					}
					if cfg.Server.Protocol.HTTP3.Port == cfg.Server.Protocol.DNSCrypt {
						sec.HTTP3Handler = s.tls.HandleHTTP3FromPacketConn
					}
					udpGroups = append(udpGroups, sec)
				}
			} else if wantSharedDNSUDP {
				// No QUIC/DTLS/DTLCP — DNSCrypt (+ HTTP3 if same port).
				g := shared.UDPGroup{
					Port:          cfg.Server.Protocol.DNSCrypt,
					ServeDNSCrypt: s.dnscryptServer.HandleSharedUDPPacket,
					ClassifyDNSCrypt: func(data []byte) string {
						if s.dnscryptServer.HasClientMagic(data) {
							return "dnscrypt"
						}
						return ""
					},
				}
				if cfg.Server.Protocol.HTTP3.Port == cfg.Server.Protocol.DNSCrypt {
					g.HTTP3Handler = s.tls.HandleHTTP3FromPacketConn
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
