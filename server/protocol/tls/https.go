package tls

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"zjdns/config"
	"zjdns/edns"
	zdnsutil "zjdns/internal/dnsutil"
	"zjdns/internal/ktls"
	"zjdns/internal/log"
	"zjdns/internal/pool"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnshttp"
)

// startDOHServer starts the dedicated-port DoH server.  Go 1.27 net/http
// accepts the eTLS backend directly: the ktls listener hands it conns whose
// ConnectionState is stdlib-compatible, http.Server drives the handshake and
// dispatches ALPN-negotiated h2 itself.
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

		rawListener := &debugListener{Listener: &zdnsutil.TCPKeepAliveListener{Listener: listener, KeepAlivePeriod: config.DefaultTCPKeepAlivePeriod}, name: "DoH"}
		// http.Server spawns its own per-connection goroutines (not through
		// serverGroup) — cap concurrent connections at the listener instead.
		// The cap wraps the RAW listener: the ktls eTLS layer must sit on top
		// of it, since http.Server reads the TLS state off the accepted conn —
		// any wrapper above the eTLS listener would hide ConnectionState.
		limited := zdnsutil.NewLimitListener(rawListener, config.DefaultServerGoroutineLimit)

		tlsConfig := s.tlsConfig.Clone()
		tlsConfig.NextProtos = config.NextProtoDOH
		tlsConfig.GetConfigForClient = s.getConfigForClient(config.NextProtoDOH)

		httpsListener := ktls.NewListener(limited, tlsConfig)
		s.listenerMu.Lock()
		s.httpsListeners = append(s.httpsListeners, httpsListener)
		s.listenerMu.Unlock()

		// TLSConfig stays nil on the http.Server (the ktls listener already
		// wraps eTLS), which lets Serve() auto-configure HTTP/2; ALPN "h2"
		// conns are then dispatched to the bundled h2 server.
		dohSrv := &http.Server{
			Handler:           http.HandlerFunc(s.ServeHTTP),
			ReadHeaderTimeout: config.DefaultHTTPReadHeaderTimeout,
			WriteTimeout:      config.DefaultHTTPServerWriteTimeout,
			IdleTimeout:       config.DefaultHTTPServerIdleTimeout,
		}
		s.listenerMu.Lock()
		s.dohServers = append(s.dohServers, dohSrv)
		s.listenerMu.Unlock()

		capturedSrv := dohSrv
		capturedListener := httpsListener
		s.groups.doh.Go(func() error {
			defer zdnsutil.HandlePanic("DoH server")
			if err := capturedSrv.Serve(capturedListener); err != nil && !errors.Is(err, http.ErrServerClosed) {
				if s.ctx.Err() != nil {
					return nil
				}
				log.Warnf("TLS: DoH Serve error: %v", err)
			}
			return nil
		})
	}
	log.Infof("TLS: DoH server started on %v", addrs)
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

	// Path forms: the endpoint itself, or "{endpoint}/{name}" carrying a
	// client-name credential (NextDNS-style).  Unknown extra segments 404.
	clientName, pathOK := zdnsutil.ClientNameFromPath(r.URL.Path, expectedPath)
	if !pathOK {
		if name3, ok3 := zdnsutil.ClientNameFromPath(r.URL.Path, expectedPath3); ok3 {
			clientName, pathOK = name3, true
		}
	}
	if !pathOK {
		http.NotFound(w, r)
		return
	}
	// SNI fallback: "https://{name}.{domain}{endpoint}" names the client
	// without a path segment (only when the path form didn't carry one).
	if clientName == "" && r.TLS != nil {
		clientName = zdnsutil.ClientNameFromSNI(r.TLS.ServerName, s.cfg.Domain)
	}

	req, statusCode := s.parseDOHRequest(r, w)
	if req == nil {
		http.Error(w, http.StatusText(statusCode), statusCode)
		return
	}

	clientIP := zdnsutil.ClientIPFromRequest(r.RemoteAddr, s.trustedProxies, r.Header)

	protocol := config.ProtoHTTPS
	if strings.HasPrefix(r.Proto, "HTTP/3") {
		protocol = config.ProtoHTTP3
		// The HTTP/3 peer completed its QUIC handshake and served a request —
		// whitelist it so its next connection skips the Retry (RFC 9000
		// §8.1.1). r.RemoteAddr is the direct QUIC peer (no proxying in h3).
		if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
			markAddrVerified(s.h3AddrCache, net.ParseIP(host))
		}
	}
	response := s.handler.ServeDNS(req, edns.RequestMeta{ClientIP: clientIP, ClientName: clientName, IsSecure: true, Protocol: protocol})
	if response == req { //nolint:revive // identity guard: ServeDNS must never return the request
		response = nil
	}
	if response != nil {
		defer pool.DefaultMessage.Put(response)
	}

	if err := s.respondDOH(w, response); err != nil {
		log.Debugf("TLS: DoH response failed for %s: %v", r.URL.String(), err)
	}
}

func (s *Server) parseDOHRequest(r *http.Request, w http.ResponseWriter) (msg *dns.Msg, statusCode int) {
	// Validate GET request size before delegating to the library parser.
	// The limit bounds the raw DNS wire message (RFC 8484 §4.1/§4.2.1), so
	// the base64url parameter must be DECODED first — base64 expands ~4/3,
	// and comparing the encoded length would reject valid messages between
	// ~49KB and 64KB that the POST path accepts.
	if r.Method == http.MethodGet {
		dnsParam := r.URL.Query().Get("dns")
		if dnsParam == "" {
			return nil, http.StatusBadRequest
		}
		if decoded, err := base64.RawURLEncoding.DecodeString(dnsParam); err != nil {
			return nil, http.StatusBadRequest
		} else if len(decoded) > config.DefaultDOHMaxRequestSize {
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

	// Pre-packed cache-hit wires are served verbatim — Pack would
	// re-serialize the nil RR sections into a header-only wire.
	if len(response.Data) == 0 {
		if err := response.Pack(); err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return fmt.Errorf("pack response: %w", err)
		}
	}
	bytes := response.Data

	w.Header().Set("Content-Type", dnshttp.MimeType)
	// RFC 8484 §5.1: Cache-Control max-age SHOULD equal the smallest TTL
	// in the Answer section (SOA MINIMUM for negative responses) —
	// shared with the TLCP DoH handler via dnsutil.DOHCacheControl.
	w.Header().Set("Cache-Control", zdnsutil.DOHCacheControl(response))
	n, err := w.Write(bytes) //nolint:gosec // G705: DNS wire format, not user-facing HTML
	if n != len(bytes) {
		return fmt.Errorf("short write: %d/%d bytes: %w", n, len(bytes), err)
	}
	return err
}
