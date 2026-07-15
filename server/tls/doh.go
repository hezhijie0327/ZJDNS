package tls

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"zjdns/config"
	zdnsutil "zjdns/internal/dnsutil"
	"zjdns/internal/log"

	eHTTP "gitlab.com/go-extension/http"
	eTLS "gitlab.com/go-extension/tls"
)

// dohResponseWriter adapts an eHTTP.ResponseWriter to net/http.ResponseWriter
// for bridging between the eHTTP server and the shared ServeHTTP handler.
type dohResponseWriter struct {
	w eHTTP.ResponseWriter
}

func (a *dohResponseWriter) Header() http.Header         { return http.Header(a.w.Header()) }
func (a *dohResponseWriter) Write(b []byte) (int, error) { return a.w.Write(b) }
func (a *dohResponseWriter) WriteHeader(code int)        { a.w.WriteHeader(code) }

func (s *Server) startDOHServer(port string) error {
	addrs, err := zdnsutil.ResolveBindAddrs("tcp", port)
	if err != nil {
		return fmt.Errorf("DoH address resolution: %w", err)
	}

	for _, addr := range addrs {
		listener, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("TCP listen on %s: %w", addr, err)
		}

		rawListener := &debugListener{Listener: &TCPKeepAliveListener{Listener: listener}, name: "DoH"}

		tlsConfig := s.tlsConfig.Clone()
		tlsConfig.NextProtos = config.NextProtoDOH
		tlsConfig.GetConfigForClient = s.getConfigForClient(config.NextProtoDOH)

		httpsListener := eTLS.NewListener(rawListener, tlsConfig)
		s.httpsListeners = append(s.httpsListeners, httpsListener)

		// eHTTP server with native eTLS-aware HTTP/2 — the bundled h2
		// detects eTLS connections from the listener automatically.
		dohSrv := &eHTTP.Server{
			Handler: eHTTP.HandlerFunc(func(w eHTTP.ResponseWriter, r *eHTTP.Request) {
				s.ServeHTTP(&dohResponseWriter{w}, eHTTP.FromRequest(r))
			}),
			ReadHeaderTimeout: config.DefaultHTTPReadHeaderTimeout,
			WriteTimeout:      config.DefaultHTTPServerWriteTimeout,
			IdleTimeout:       config.DefaultHTTPServerIdleTimeout,
		}
		s.dohServers = append(s.dohServers, dohSrv)

		log.Infof("TLS: DoH server started on %s", addr)

		capturedSrv := dohSrv
		capturedListener := httpsListener
		s.serverGroup.Go(func() error {
			defer zdnsutil.HandlePanic("DoH server")
			if err := capturedSrv.Serve(capturedListener); err != nil && !errors.Is(err, eHTTP.ErrServerClosed) {
				if s.ctx.Err() != nil {
					return nil
				}
				log.Warnf("TLS: DoH Serve error: %v", err)
			}
			return nil
		})
	}
	return nil
}
