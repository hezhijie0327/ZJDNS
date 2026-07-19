package tcp

import (
	"context"
	stdtls "crypto/tls"
	"errors"
	"net"
	"net/http"
	"strings"
	"zjdns/config"
	"zjdns/edns"
	zdnsutil "zjdns/internal/dnsutil"
	"zjdns/internal/log"
	"zjdns/internal/pool"

	"codeberg.org/miekg/dns/dnshttp"
)

// ServeDOH starts an HTTP/1.1 DNS-over-HTTPS server on a shared TLS/TLCP
// listener.  Both TLS and TLCP connections arrive post-handshake and are
// served identically at the HTTP level.
func ServeDOH(listener net.Listener, handler edns.DNSHandler, endpoint string, ctx context.Context) error {
	dnshttp.MsgAcceptFunc = zdnsutil.ServerDOHMsgAccept

	if endpoint == "" {
		endpoint = config.DefaultQueryPath
	}
	if !strings.HasPrefix(endpoint, "/") {
		endpoint = "/" + endpoint
	}

	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ServeDoHHTTP(w, r, handler, endpoint)
		}),
		ReadHeaderTimeout: config.DefaultHTTPReadHeaderTimeout,
		IdleTimeout:       config.DefaultHTTPServerIdleTimeout,
		// Disable HTTP/2 — the shared listener returns post-handshake
		// connections that the standard http.Server cannot detect as TLS
		// for ALPN-based protocol upgrade.
		TLSNextProto: make(map[string]func(*http.Server, *stdtls.Conn, http.Handler)),
	}

	log.Infof("SHARED: DoH server started on %s (HTTP/1.1, TLS + TLCP)", listener.Addr())

	serveErr := srv.Serve(listener)
	if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) && !errors.Is(serveErr, net.ErrClosed) {
		// The shared listener may be closed by the TLS or TLCP server
		// during shutdown before http.Server finishes gracefully.
		// Treat any post-shutdown error as non-fatal.
		select {
		case <-ctx.Done():
			log.Debugf("SHARED: DoH server stopped after shutdown: %v", serveErr)
			return nil
		default:
		}
		return serveErr
	}
	return nil
}

// serveDOH handles a single DoH HTTP request, parsing the DNS query from
// GET or POST and writing the DNS response.
func ServeDoHHTTP(w http.ResponseWriter, r *http.Request, handler edns.DNSHandler, endpoint string) {
	if r.URL.Path != endpoint {
		http.NotFound(w, r)
		return
	}

	// Validate GET request size.
	if r.Method == http.MethodGet {
		dnsParam := r.URL.Query().Get("dns")
		if dnsParam == "" || len(dnsParam) > config.DefaultDOHMaxRequestSize {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
	}
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, config.DefaultDOHMaxRequestSize)
	}

	req, err := dnshttp.Request(r)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	var clientIP net.IP
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		clientIP = net.ParseIP(host)
	}

	response := handler.ServeDNS(req, clientIP, true, config.ProtoHTTPS)
	pool.DefaultMessage.Put(req)

	if response == nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	defer pool.DefaultMessage.Put(response)

	if err := response.Pack(); err != nil {
		log.Debugf("SHARED: DoH pack error: %v", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", dnshttp.MimeType)
	w.Header().Set("Cache-Control", "max-age=0")
	_, _ = w.Write(response.Data) //nolint:gosec // G705: DNS wire format bytes, not HTML
}
