package tlcp

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"zjdns/config"
	"zjdns/internal/demux"
	zdnsutil "zjdns/internal/dnsutil"
	"zjdns/internal/log"

	"gitee.com/Trisia/gotlcp/tlcp"
	eHTTP "gitlab.com/go-extension/http"
	eTLS "gitlab.com/go-extension/tls"
)

// queueListener adapts a demux protocol queue (net.Listener) into a plain
// net.Listener.  Connections from the queue are already wrapped by the
// route function (e.g. tlcp.Server) so Accept simply passes them through.
type queueListener struct {
	inner net.Listener
}

func (q *queueListener) Accept() (net.Conn, error) { return q.inner.Accept() }
func (q *queueListener) Close() error              { return q.inner.Close() }
func (q *queueListener) Addr() net.Addr            { return q.inner.Addr() }

// startSharedDOHServer creates a single TCP listener on the shared port and
// uses a TCP demux to route connections by record-layer protocol:
//   - TLS (major=0x03) → eTLS wrap → eHTTP.Server (DOH handler from TLS server)
//   - TLCP (major=0x01) → tlcp.Server wrap → http.Server (HTTPoverTLCP handler)
func (s *Server) startSharedDOHServer() error {
	addrs, err := zdnsutil.ResolveBindAddrs("tcp", s.shared.Port)
	if err != nil {
		return fmt.Errorf("resolve bind addrs: %w", err)
	}

	log.Infof("TLCP: Shared DoH+HTTPoverTLCP server started on %v", addrs)
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
			Routes: map[string]func(net.Conn) net.Conn{
				demux.ProtoTLS: func(c net.Conn) net.Conn {
					// Pass through without eTLS wrapping — the
					// eTLS.NewListener below handles the handshake,
					// matching the standalone DoH server pattern.
					return c
				},
				demux.ProtoTLCP: func(c net.Conn) net.Conn {
					cfg := s.tlcpConfig.Clone()
					cfg.NextProtos = config.NextProtoDOH
					return tlcp.Server(c, cfg)
				},
			},
		})

		s.listenerMu.Lock()
		s.sharedDemux = d
		s.listenerMu.Unlock()

		// TLS side: wrap the demux TLS queue with eTLS.NewListener
		// then serve via eHTTP.Server — identical to the standalone
		// DoH server in tls/https.go.  This ensures the bundled h2
		// detects eTLS connections from the listener automatically.
		tlsListener := d.Listener(demux.ProtoTLS)
		if tlsListener != nil {
			limited := zdnsutil.NewLimitListener(tlsListener, config.DefaultServerGoroutineLimit)

			tlsConfig := s.shared.TLSCfg.Clone()
			tlsConfig.NextProtos = config.NextProtoDOH
			tlsConfig.GetConfigForClient = s.getSharedTLSConfigForClient(config.NextProtoDOH)

			httpsListener := eTLS.NewListener(limited, tlsConfig)

			dohSrv := &eHTTP.Server{
				Handler:           s.shared.DOHHandler,
				ReadHeaderTimeout: config.DefaultHTTPReadHeaderTimeout,
				WriteTimeout:      config.DefaultHTTPServerWriteTimeout,
				IdleTimeout:       config.DefaultHTTPServerIdleTimeout,
			}
			s.listenerMu.Lock()
			s.sharedDOHSrv = dohSrv
			s.listenerMu.Unlock()

			capturedSrv := dohSrv
			capturedLn := httpsListener
			s.serverGroup.Go(func() error {
				defer zdnsutil.HandlePanic("Shared DoH (TLS) server")
				if err := capturedSrv.Serve(capturedLn); err != nil && !errors.Is(err, eHTTP.ErrServerClosed) {
					if s.ctx.Err() != nil {
						return nil
					}
					log.Warnf("TLCP: shared DoH (TLS) serve error: %v", err)
				}
				return nil
			})
		}

		// TLCP side: http.Server with the HTTPoverTLCP handler.
		tlcpListener := d.Listener(demux.ProtoTLCP)
		if tlcpListener != nil {
			tlcpSrv := &http.Server{
				Handler:           http.HandlerFunc(s.serveDOH),
				ReadHeaderTimeout: config.DefaultHTTPReadHeaderTimeout,
				WriteTimeout:      config.DefaultHTTPServerWriteTimeout,
				IdleTimeout:       config.DefaultHTTPServerIdleTimeout,
				TLSNextProto:      make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
			}
			s.listenerMu.Lock()
			s.sharedTLCPsrv = tlcpSrv
			s.listenerMu.Unlock()

			capturedTLCP := tlcpSrv
			capturedTLCPln := tlcpListener
			s.serverGroup.Go(func() error {
				defer zdnsutil.HandlePanic("Shared DoH (TLCP) server")
				if err := capturedTLCP.Serve(capturedTLCPln); err != nil && err != http.ErrServerClosed {
					log.Warnf("TLCP: shared DoH (TLCP) serve error: %v", err)
				}
				return nil
			})
		}
	}
	return nil
}

// getSharedTLSConfigForClient returns a GetConfigForClient callback for the
// shared-port TLS side.  It mirrors the TLS server's getConfigForClient
// pattern: clone the base config, scope NextProtos, and log the handshake.
func (s *Server) getSharedTLSConfigForClient(nextProtos []string) func(*eTLS.ClientHelloInfo) (*eTLS.Config, error) {
	return func(info *eTLS.ClientHelloInfo) (*eTLS.Config, error) {
		remoteAddr := info.Conn.RemoteAddr().String()
		sni := info.ServerName
		if sni == "" {
			sni = "(empty)"
		}
		log.Debugf("TLS: ClientHello from %s, SNI=%s, supported curves=%d", remoteAddr, sni, len(info.SupportedCurves))
		cfg := s.shared.TLSCfg.Clone()
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

// startSharedDOTServer creates a single TCP listener on the shared DOT port
// and uses a TCP demux to route connections by record-layer protocol:
//   - TLS (major=0x03) → eTLS wrap → handleDOTConnections (from TLS server)
//   - TLCP (major=0x01) → tlcp.Server wrap → serveDOT (TLCP DoT handler)
func (s *Server) startSharedDOTServer() error {
	addrs, err := zdnsutil.ResolveBindAddrs("tcp", s.shared.DOTPort)
	if err != nil {
		return fmt.Errorf("resolve bind addrs: %w", err)
	}

	log.Infof("TLCP: Shared DoT+DoT(TLCP) server started on %v", addrs)
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
			Routes: map[string]func(net.Conn) net.Conn{
				demux.ProtoTLS: func(c net.Conn) net.Conn {
					// Pass through — eTLS.NewListener below
					// handles the handshake.
					return c
				},
				demux.ProtoTLCP: func(c net.Conn) net.Conn {
					cfg := s.tlcpConfig.Clone()
					cfg.NextProtos = config.NextProtoDOT
					return tlcp.Server(c, cfg)
				},
			},
		})

		s.listenerMu.Lock()
		s.sharedDOTDemux = d
		s.listenerMu.Unlock()

		// TLS side: eTLS.NewListener wraps the queue, then the TLS
		// server's HandleDOTFromListener consumes the connections.
		tlsListener := d.Listener(demux.ProtoTLS)
		if tlsListener != nil {
			limited := zdnsutil.NewLimitListener(tlsListener, config.DefaultServerGoroutineLimit)

			tlsConfig := s.shared.TLSCfg.Clone()
			tlsConfig.NextProtos = config.NextProtoDOT
			tlsConfig.GetConfigForClient = s.getSharedDOTConfigForClient()

			dotListener := eTLS.NewListener(limited, tlsConfig)

			capturedLn := dotListener
			s.serverGroup.Go(func() error {
				defer zdnsutil.HandlePanic("Shared DoT (TLS) server")
				if err := s.shared.DOTHandler(capturedLn); err != nil {
					if s.ctx.Err() != nil {
						return nil
					}
					log.Warnf("TLCP: shared DoT (TLS) error: %v", err)
				}
				return nil
			})
		}

		// TLCP side: connections from the queue are already wrapped
		// with tlcp.Server by the route function.  serveDOT accepts
		// them via the queueListener adapter.
		tlcpQueue := d.Listener(demux.ProtoTLCP)
		if tlcpQueue != nil {
			ql := &queueListener{inner: tlcpQueue}
			s.listenerMu.Lock()
			s.sharedDOTTLCPsrv = ql
			s.listenerMu.Unlock()

			capturedQL := ql
			s.serverGroup.Go(func() error {
				defer zdnsutil.HandlePanic("Shared DoT (TLCP) server")
				s.serveDOT(capturedQL)
				return nil
			})
		}
	}
	return nil
}

// getSharedDOTConfigForClient returns a GetConfigForClient callback for the
// shared DOT port TLS side (NextProtos = ["dot"]).
func (s *Server) getSharedDOTConfigForClient() func(*eTLS.ClientHelloInfo) (*eTLS.Config, error) {
	return s.getSharedTLSConfigForClient(config.NextProtoDOT)
}
