package shared

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"zjdns/config"
	"zjdns/internal/demux"
	"zjdns/internal/log"

	zdnsutil "zjdns/internal/dnsutil"

	eHTTP "gitlab.com/go-extension/http"
	eTLS "gitlab.com/go-extension/tls"
)

// queueListener adapts a demux protocol queue (net.Listener) into a plain
// net.Listener.  Connections from the queue are already wrapped by the
// route function so Accept simply passes them through.
type queueListener struct {
	inner net.Listener
}

func (q *queueListener) Accept() (net.Conn, error) { return q.inner.Accept() }
func (q *queueListener) Close() error              { return q.inner.Close() }
func (q *queueListener) Addr() net.Addr            { return q.inner.Addr() }

// startTCPGroup creates a single TCP listener on the group's port and uses a
// TCP demux to route connections by record-layer protocol:
//   - TLS (first byte 0x14–0x17, version 0x03) → eTLS wrap → handler
//   - TLCP (first byte 0x16, version 0x01) → TLCP wrap → handler
//   - DNSCrypt (first byte 0x00–0x04) → DNSCrypt TCP handler (optional)
//
// The TLS handler is either DOHHandler (HTTP-level, port 443) or
// DOTHandler (raw listener, port 853).  Similarly for TLCP: DOHTLCP
// (HTTP-level) or DOTTLCP (raw listener).
func (m *Manager) startTCPGroup(g *TCPGroup) error {
	addrs, err := zdnsutil.ResolveBindAddrs("tcp", g.Port)
	if err != nil {
		return fmt.Errorf("resolve bind addrs: %w", err)
	}

	// Build the route map; DNSCrypt is optional.
	routes := map[string]func(net.Conn) net.Conn{
		demux.ProtoTLS: func(c net.Conn) net.Conn {
			return c // eTLS.NewListener below handles the handshake
		},
		demux.ProtoTLCP: func(c net.Conn) net.Conn {
			return g.WrapConn(c, g.NextProtos)
		},
	}
	if g.ServeDNSCryptTCP != nil {
		routes[demux.ProtoDNSCrypt] = func(c net.Conn) net.Conn {
			return c // bufferedConn replays 5 demux bytes
		}
	}

	// Build a log label reflecting the active protocol combination.
	label := "SHARED"
	var parts []string
	if g.DOHHandler != nil || g.DOTHandler != nil {
		parts = append(parts, "DoT")
		if g.DOHHandler != nil {
			parts[0] = "DoH"
		}
	}
	if g.DOHTLCP != nil || g.DOTTLCP != nil {
		parts = append(parts, "HTTPoverTLCP")
		if g.DOTTLCP != nil && g.DOHTLCP == nil {
			parts[len(parts)-1] = "DoT(TLCP)"
		}
	}
	if g.ServeDNSCryptTCP != nil {
		parts = append(parts, "DNSCrypt")
	}
	if len(parts) > 0 {
		label += ": " + joinStrings(parts, ", ")
	}
	log.Infof("%s server started on %v", label, addrs)

	for _, addr := range addrs {
		rawListener, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("TCP listen on %s: %w", addr, err)
		}

		d := demux.NewTCPDemux(demux.TCPConfig{
			Inner: &zdnsutil.TCPKeepAliveListener{
				Listener:        rawListener,
				KeepAlivePeriod: config.DefaultTCPKeepAlivePeriod,
			},
			Routes: routes,
		})

		rt := &tcpRuntime{cfg: g, demux: d}

		m.mu.Lock()
		m.tcpRuntimes = append(m.tcpRuntimes, rt)
		m.mu.Unlock()

		// TLS side: eTLS.NewListener → handler.
		tlsListener := d.Listener(demux.ProtoTLS)
		if tlsListener != nil {
			limited := zdnsutil.NewLimitListener(tlsListener, config.DefaultServerGoroutineLimit)

			tlsConfig := g.TLSCfg.Clone()
			tlsConfig.NextProtos = g.NextProtos
			tlsConfig.GetConfigForClient = sharedTLSConfigForClient(g.TLSCfg, g.NextProtos)

			if g.DOHHandler != nil {
				// HTTP-level: eTLS.Listener → eHTTP.Server.
				httpsListener := eTLS.NewListener(limited, tlsConfig)

				dohSrv := &eHTTP.Server{
					Handler:           g.DOHHandler,
					ReadHeaderTimeout: config.DefaultHTTPReadHeaderTimeout,
					WriteTimeout:      config.DefaultHTTPServerWriteTimeout,
					IdleTimeout:       config.DefaultHTTPServerIdleTimeout,
				}
				rt.dohSrv = dohSrv

				capturedSrv := dohSrv
				capturedLn := httpsListener
				m.host.Go(func() error {
					defer zdnsutil.HandlePanic("Shared DoH (TLS) server")
					if err := capturedSrv.Serve(capturedLn); err != nil && !errors.Is(err, eHTTP.ErrServerClosed) {
						if m.host.Ctx().Err() != nil {
							return nil
						}
						log.Warnf("SHARED: DoH (TLS) serve error: %v", err)
					}
					return nil
				})
			} else if g.DOTHandler != nil {
				// Raw listener: eTLS.Listener → DOTHandler.
				dotListener := eTLS.NewListener(limited, tlsConfig)

				capturedLn := dotListener
				capturedHandler := g.DOTHandler
				m.host.Go(func() error {
					defer zdnsutil.HandlePanic("Shared DoT (TLS) server")
					if err := capturedHandler(capturedLn); err != nil {
						if m.host.Ctx().Err() != nil {
							return nil
						}
						log.Warnf("SHARED: DoT (TLS) error: %v", err)
					}
					return nil
				})
			}
		}

		// TLCP side: queueListener → handler.
		tlcpQueue := d.Listener(demux.ProtoTLCP)
		if tlcpQueue != nil {
			ql := &queueListener{inner: tlcpQueue}

			if g.DOHTLCP != nil {
				// HTTP-level: http.Server.
				tlcpSrv := &http.Server{
					Handler:           g.DOHTLCP,
					ReadHeaderTimeout: config.DefaultHTTPReadHeaderTimeout,
					WriteTimeout:      config.DefaultHTTPServerWriteTimeout,
					IdleTimeout:       config.DefaultHTTPServerIdleTimeout,
					TLSNextProto:      make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
				}
				rt.tlcpSrv = tlcpSrv

				capturedTLCP := tlcpSrv
				capturedTLCPln := ql
				m.host.Go(func() error {
					defer zdnsutil.HandlePanic("Shared DoH (TLCP) server")
					if err := capturedTLCP.Serve(capturedTLCPln); err != nil && err != http.ErrServerClosed {
						log.Warnf("SHARED: DoH (TLCP) serve error: %v", err)
					}
					return nil
				})
			} else if g.DOTTLCP != nil {
				// Raw listener.
				rt.tlcpLn = ql

				capturedQL := ql
				capturedHandler := g.DOTTLCP
				m.host.Go(func() error {
					defer zdnsutil.HandlePanic("Shared DoT (TLCP) server")
					capturedHandler(capturedQL)
					return nil
				})
			}
		}

		// DNSCrypt side: accept loop dispatching to ServeDNSCryptTCP.
		dnscryptQueue := d.Listener(demux.ProtoDNSCrypt)
		if dnscryptQueue != nil {
			ql := &queueListener{inner: dnscryptQueue}
			capturedQL := ql
			capturedHandler := g.ServeDNSCryptTCP
			m.host.Go(func() error {
				defer zdnsutil.HandlePanic("Shared DNSCrypt TCP server")
				for {
					conn, err := capturedQL.Accept()
					if err != nil {
						if m.host.Ctx().Err() != nil {
							return nil
						}
						if !zdnsutil.IsTemporaryError(err) {
							return nil
						}
						continue
					}
					capturedConn := conn
					m.host.Go(func() error {
						capturedHandler(m.host.Ctx(), capturedConn)
						return nil
					})
				}
			})
		}
	}
	return nil
}

// sharedTLSConfigForClient returns a GetConfigForClient callback for the
// shared-port TLS side.  It mirrors the TLS server's getConfigForClient
// pattern: clone the base config, scope NextProtos, and log the handshake.
func sharedTLSConfigForClient(baseCfg *eTLS.Config, nextProtos []string) func(*eTLS.ClientHelloInfo) (*eTLS.Config, error) {
	return func(info *eTLS.ClientHelloInfo) (*eTLS.Config, error) {
		remoteAddr := info.Conn.RemoteAddr().String()
		sni := info.ServerName
		if sni == "" {
			sni = "(empty)"
		}
		log.Debugf("TLS: ClientHello from %s, SNI=%s, supported curves=%d", remoteAddr, sni, len(info.SupportedCurves))
		cfg := baseCfg.Clone()
		cfg.NextProtos = nextProtos
		cfg.VerifyConnection = func(cs eTLS.ConnectionState) error {
			zdnsutil.LogHandshake(&zdnsutil.HandshakeInfo{
				Role:       "TLS",
				Direction:  "handshake from",
				RemoteAddr: remoteAddr,
				Version:    cs.Version,
				Cipher:     eTLS.CipherSuiteName(cs.CipherSuite),
				Group:      cs.CurveID.String(),
				Resumed:    cs.DidResume,
			})
			return nil
		}
		return cfg, nil
	}
}
