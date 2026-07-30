package tls

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"zjdns/config"
	zdnsutil "zjdns/internal/dnsutil"
	"zjdns/internal/log"
	"zjdns/internal/pool"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnshttp"
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

	log.Infof("TLS: DoH server started on %v", addrs)
	for _, addr := range addrs {
		listener, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("TCP listen on %s: %w", addr, err)
		}

		rawListener := &debugListener{Listener: &zdnsutil.TCPKeepAliveListener{Listener: listener}, name: "DoH"}

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

// ServeHTTP handles incoming DoH and DoH3 HTTP requests, parsing the DNS query
// from GET or POST and returning the DNS response.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if s == nil || s.handler == nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	expectedPath := s.cfg.HTTPSEndpoint
	if expectedPath == "" {
		expectedPath = config.DefaultQueryPath
	}
	if !strings.HasPrefix(expectedPath, "/") {
		expectedPath = "/" + expectedPath
	}
	expectedPath3 := s.cfg.HTTP3Endpoint
	if expectedPath3 == "" {
		expectedPath3 = config.DefaultQueryPath
	}
	if !strings.HasPrefix(expectedPath3, "/") {
		expectedPath3 = "/" + expectedPath3
	}

	if r.URL.Path != expectedPath && r.URL.Path != expectedPath3 {
		http.NotFound(w, r)
		return
	}

	req, statusCode := s.parseDOHRequest(r, w)
	if req == nil {
		http.Error(w, http.StatusText(statusCode), statusCode)
		return
	}

	var clientIP net.IP
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		clientIP = net.ParseIP(host)
	}

	protocol := config.ProtoHTTPS
	if strings.HasPrefix(r.Proto, "HTTP/3") {
		protocol = config.ProtoHTTP3
	}
	response := s.handler.ServeDNS(req, clientIP, true, protocol)
	if response != nil {
		defer pool.DefaultMessage.Put(response)
	}

	if err := s.respondDOH(w, response); err != nil {
		log.Debugf("TLS: DoH response failed for %s: %v", r.URL.String(), err)
	}
}

func (s *Server) parseDOHRequest(r *http.Request, w http.ResponseWriter) (msg *dns.Msg, statusCode int) {
	// Validate GET request size before delegating to the library parser.
	if r.Method == http.MethodGet {
		dnsParam := r.URL.Query().Get("dns")
		if dnsParam == "" || len(dnsParam) > config.DefaultDOHMaxRequestSize {
			return nil, http.StatusBadRequest
		}
	}
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, config.DefaultDOHMaxRequestSize)
	}

	req, err := dnshttp.Request(r)
	if err != nil {
		// RFC 8484 §4.2.1: POST with wrong Content-Type → 415.
		if r.Method == http.MethodPost && r.Header.Get("Content-Type") != "" &&
			!strings.HasPrefix(r.Header.Get("Content-Type"), dnshttp.MimeType) {
			return nil, http.StatusUnsupportedMediaType
		}
		return nil, http.StatusBadRequest
	}

	return req, http.StatusOK
}

func (s *Server) respondDOH(w http.ResponseWriter, response *dns.Msg) error {
	if response == nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return nil
	}

	if err := response.Pack(); err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return fmt.Errorf("pack response: %w", err)
	}
	bytes := response.Data

	w.Header().Set("Content-Type", dnshttp.MimeType)
	w.Header().Set("Cache-Control", "max-age=0")
	n, err := w.Write(bytes) //nolint:gosec // G705: DNS wire format, not user-facing HTML
	if n != len(bytes) {
		return fmt.Errorf("short write: %d/%d bytes", n, len(bytes))
	}
	return err
}
