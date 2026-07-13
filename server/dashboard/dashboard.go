// Package dashboard provides an optional embedded web dashboard for monitoring
// DNS server statistics, performance metrics, and query logs. The dashboard
// serves a React single-page application at / and a JSON API at /api/*.
//
// HTTPS uses eHTTP over eTLS (KTLS-capable, same as DoH). HTTP/3 is not yet
// implemented for the dashboard.
package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"zjdns/config"
	"zjdns/database"
	"zjdns/internal/log"

	eHTTP "gitlab.com/go-extension/http"
	eTLS "gitlab.com/go-extension/tls"
	zdnsutil "zjdns/internal/dnsutil"
)

// TLSConfig carries optional TLS settings for the dashboard.
type TLSConfig struct {
	CertFile   string
	KeyFile    string
	SelfSigned bool
}

// Server serves the dashboard web UI and JSON API.
type Server struct {
	db         *database.DB
	port       string
	auth       *AuthManager
	authCfg    AuthConfig
	mux        *http.ServeMux
	servers    []*http.Server
	tlsConfig  *eTLS.Config
	httpsSrv   *eHTTP.Server
	httpsAddrs []string
}

// eHTTPAdapter adapts eHTTP.ResponseWriter to http.ResponseWriter.
type eHTTPAdapter struct{ w eHTTP.ResponseWriter }

// errDashboardDisabled is returned when port is empty.
var errDashboardDisabled = errors.New("dashboard port is empty")

func (a *eHTTPAdapter) Header() http.Header         { return http.Header(a.w.Header()) }
func (a *eHTTPAdapter) Write(b []byte) (int, error) { return a.w.Write(b) }
func (a *eHTTPAdapter) WriteHeader(code int)        { a.w.WriteHeader(code) }

// New creates a dashboard Server.
func New(db *database.DB, port string, authCfg AuthConfig, tlsCfg *TLSConfig) (*Server, error) {
	if port == "" {
		return nil, errDashboardDisabled
	}

	auth := NewAuthManager()

	mux := http.NewServeMux()
	s := &Server{
		db:      db,
		port:    port,
		auth:    auth,
		authCfg: authCfg,
		mux:     mux,
	}
	s.registerHandlers(mux)

	// Plain HTTP listeners (always enabled)
	tcpAddrs, err := zdnsutil.ResolveBindAddrs("tcp", port)
	if err != nil {
		log.Warnf("DASHBOARD: no available addresses: %v", err)
		return s, nil
	}
	for _, addr := range tcpAddrs {
		s.servers = append(s.servers, &http.Server{
			Addr:              addr,
			Handler:           mux,
			ReadHeaderTimeout: config.DefaultHTTPReadHeaderTimeout,
			IdleTimeout:       config.DefaultHTTPServerIdleTimeout,
		})
	}

	// TLS via eHTTP + eTLS (KTLS-capable)
	if tlsCfg != nil {
		cert, err := eTLS.LoadX509KeyPair(tlsCfg.CertFile, tlsCfg.KeyFile)
		if err != nil {
			log.Warnf("DASHBOARD: TLS cert load failed: %v — HTTPS disabled", err)
		} else {
			s.tlsConfig = &eTLS.Config{
				Certificates: []eTLS.Certificate{cert},
				MinVersion:   eTLS.VersionTLS13,
				NextProtos:   []string{"h2"},
			}
			s.httpsSrv = &eHTTP.Server{
				Handler: eHTTP.HandlerFunc(func(w eHTTP.ResponseWriter, r *eHTTP.Request) {
					mux.ServeHTTP(&eHTTPAdapter{w}, eHTTP.FromRequest(r))
				}),
				ReadHeaderTimeout: config.DefaultHTTPReadHeaderTimeout,
				IdleTimeout:       config.DefaultHTTPServerIdleTimeout,
			}
			// HTTPS shares the same TCP addresses
			s.httpsAddrs = tcpAddrs
		}
	}

	return s, nil
}

// Start begins serving the dashboard.
func (s *Server) Start(ctx context.Context) error {
	if s == nil {
		return nil
	}
	defer zdnsutil.HandlePanic("dashboard server")

	for _, srv := range s.servers {
		go func() {
			log.Infof("DASHBOARD: HTTP server started on http://%s", srv.Addr)
			err := srv.ListenAndServe()
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Errorf("DASHBOARD: HTTP error on %s: %v", srv.Addr, err)
			}
		}()
	}

	if s.httpsSrv != nil {
		for _, addr := range s.httpsAddrs {
			go func() {
				l, err := net.Listen("tcp", addr)
				if err != nil {
					log.Warnf("DASHBOARD: HTTPS listen failed on %s: %v", addr, err)
					return
				}
				tlsListener := eTLS.NewListener(l, s.tlsConfig)
				log.Infof("DASHBOARD: HTTPS server started on https://%s", addr)
				err = s.httpsSrv.Serve(tlsListener)
				if err != nil && !errors.Is(err, http.ErrServerClosed) {
					log.Errorf("DASHBOARD: HTTPS error on %s: %v", addr, err)
				}
			}()
		}
	}

	<-ctx.Done()
	return nil
}

// Shutdown gracefully stops the dashboard server.
func (s *Server) Shutdown(ctx context.Context) error {
	if s == nil {
		return nil
	}
	for _, srv := range s.servers {
		if err := srv.Shutdown(ctx); err != nil {
			log.Warnf("DASHBOARD: shutdown failed on %s: %v", srv.Addr, err)
		}
	}
	if s.httpsSrv != nil {
		if err := s.httpsSrv.Shutdown(ctx); err != nil {
			log.Warnf("DASHBOARD: HTTPS shutdown failed: %v", err)
		}
	}
	log.Infof("DASHBOARD: shut down successfully")
	return nil
}

func (s *Server) isAuthEnabled() bool {
	return s.authCfg.Username != "" || s.authCfg.Password != ""
}

func (s *Server) registerHandlers(mux *http.ServeMux) {
	mux.HandleFunc("/", s.handleIndex)

	if s.isAuthEnabled() {
		mux.HandleFunc("/api/auth/login", s.auth.HandleLogin(s.authCfg))
		protected := func(h http.HandlerFunc) http.HandlerFunc {
			return s.auth.Middleware(h)
		}
		mux.HandleFunc("/api/overview", protected(s.handleOverview))
		mux.HandleFunc("/api/rcodes", protected(s.handleRCodes))
		mux.HandleFunc("/api/protocols", protected(s.handleProtocols))
		mux.HandleFunc("/api/dnssec", protected(s.handleDNSSEC))
		mux.HandleFunc("/api/top-domains", protected(s.handleTopDomains))
		mux.HandleFunc("/api/query-log", protected(s.handleQueryLog))
		mux.HandleFunc("/api/latency", protected(s.handleLatency))
		mux.HandleFunc("/api/timeseries", protected(s.handleTimeseries))
	} else {
		mux.HandleFunc("/api/overview", s.handleOverview)
		mux.HandleFunc("/api/rcodes", s.handleRCodes)
		mux.HandleFunc("/api/protocols", s.handleProtocols)
		mux.HandleFunc("/api/dnssec", s.handleDNSSEC)
		mux.HandleFunc("/api/top-domains", s.handleTopDomains)
		mux.HandleFunc("/api/query-log", s.handleQueryLog)
		mux.HandleFunc("/api/latency", s.handleLatency)
		mux.HandleFunc("/api/timeseries", s.handleTimeseries)
	}
}

func writeJSON(w http.ResponseWriter, v any) bool {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Warnf("DASHBOARD: JSON encode error: %v", err)
		return false
	}
	return true
}

func parseQueryInt(r *http.Request, key string, def int) int {
	s := r.URL.Query().Get(key)
	if s == "" {
		return def
	}
	var n int
	if _, err := fmt.Sscanf(s, "%d", &n); err != nil || n < 0 {
		return def
	}
	return n
}
