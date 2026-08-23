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

// startDOH creates a single TCP listener on the shared DOH port and uses a
// TCP demux to route connections by record-layer protocol:
//   - TLS (major=0x03) → eTLS wrap → eHTTP.Server (DOH handler from TLS server)
//   - TLCP (major=0x01) → TLCP wrap → http.Server (HTTPoverTLCP handler)
func (m *Manager) startDOH() error {
	addrs, err := zdnsutil.ResolveBindAddrs("tcp", m.cfg.Port)
	if err != nil {
		return fmt.Errorf("resolve bind addrs: %w", err)
	}

	log.Infof("SHARED: DoH+HTTPoverTLCP server started on %v", addrs)
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
					return c // eTLS.NewListener below handles the handshake
				},
				demux.ProtoTLCP: func(c net.Conn) net.Conn {
					return m.cfg.WrapConn(c, config.NextProtoDOH)
				},
			},
		})

		m.mu.Lock()
		m.dohDemux = d
		m.mu.Unlock()

		// TLS side: eTLS.NewListener → eHTTP.Server.
		tlsListener := d.Listener(demux.ProtoTLS)
		if tlsListener != nil {
			limited := zdnsutil.NewLimitListener(tlsListener, config.DefaultServerGoroutineLimit)

			tlsConfig := m.cfg.TLSCfg.Clone()
			tlsConfig.NextProtos = config.NextProtoDOH
			tlsConfig.GetConfigForClient = sharedTLSConfigForClient(m.cfg.TLSCfg, config.NextProtoDOH)

			httpsListener := eTLS.NewListener(limited, tlsConfig)

			dohSrv := &eHTTP.Server{
				Handler:           m.cfg.DOHHandler,
				ReadHeaderTimeout: config.DefaultHTTPReadHeaderTimeout,
				WriteTimeout:      config.DefaultHTTPServerWriteTimeout,
				IdleTimeout:       config.DefaultHTTPServerIdleTimeout,
			}
			m.mu.Lock()
			m.dohSrv = dohSrv
			m.mu.Unlock()

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
		}

		// TLCP side: http.Server with the HTTPoverTLCP handler.
		tlcpListener := d.Listener(demux.ProtoTLCP)
		if tlcpListener != nil {
			tlcpSrv := &http.Server{
				Handler:           m.cfg.DOHTLCP,
				ReadHeaderTimeout: config.DefaultHTTPReadHeaderTimeout,
				WriteTimeout:      config.DefaultHTTPServerWriteTimeout,
				IdleTimeout:       config.DefaultHTTPServerIdleTimeout,
				TLSNextProto:      make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
			}
			m.mu.Lock()
			m.tlcpSrv = tlcpSrv
			m.mu.Unlock()

			capturedTLCP := tlcpSrv
			capturedTLCPln := tlcpListener
			m.host.Go(func() error {
				defer zdnsutil.HandlePanic("Shared DoH (TLCP) server")
				if err := capturedTLCP.Serve(capturedTLCPln); err != nil && err != http.ErrServerClosed {
					log.Warnf("SHARED: DoH (TLCP) serve error: %v", err)
				}
				return nil
			})
		}
	}
	return nil
}

// startDOT creates a single TCP listener on the shared DOT port and uses a
// TCP demux to route connections by record-layer protocol:
//   - TLS (major=0x03) → eTLS wrap → DOTHandler
//   - TLCP (major=0x01) → TLCP wrap → DOTTLCP accept loop
func (m *Manager) startDOT() error {
	addrs, err := zdnsutil.ResolveBindAddrs("tcp", m.cfg.DOTPort)
	if err != nil {
		return fmt.Errorf("resolve bind addrs: %w", err)
	}

	log.Infof("SHARED: DoT+DoT(TLCP) server started on %v", addrs)
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
					return c // eTLS.NewListener below handles the handshake
				},
				demux.ProtoTLCP: func(c net.Conn) net.Conn {
					return m.cfg.WrapConn(c, config.NextProtoDOT)
				},
			},
		})

		m.mu.Lock()
		m.dotDemux = d
		m.mu.Unlock()

		// TLS side: eTLS.NewListener → DOTHandler.
		tlsListener := d.Listener(demux.ProtoTLS)
		if tlsListener != nil {
			limited := zdnsutil.NewLimitListener(tlsListener, config.DefaultServerGoroutineLimit)

			tlsConfig := m.cfg.TLSCfg.Clone()
			tlsConfig.NextProtos = config.NextProtoDOT
			tlsConfig.GetConfigForClient = sharedTLSConfigForClient(m.cfg.TLSCfg, config.NextProtoDOT)

			dotListener := eTLS.NewListener(limited, tlsConfig)

			capturedLn := dotListener
			m.host.Go(func() error {
				defer zdnsutil.HandlePanic("Shared DoT (TLS) server")
				if err := m.cfg.DOTHandler(capturedLn); err != nil {
					if m.host.Ctx().Err() != nil {
						return nil
					}
					log.Warnf("SHARED: DoT (TLS) error: %v", err)
				}
				return nil
			})
		}

		// TLCP side: queueListener → DOTTLCP accept loop.
		tlcpQueue := d.Listener(demux.ProtoTLCP)
		if tlcpQueue != nil {
			ql := &queueListener{inner: tlcpQueue}
			m.mu.Lock()
			m.dotTLCPln = ql
			m.mu.Unlock()

			capturedQL := ql
			m.host.Go(func() error {
				defer zdnsutil.HandlePanic("Shared DoT (TLCP) server")
				m.cfg.DOTTLCP(capturedQL)
				return nil
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
