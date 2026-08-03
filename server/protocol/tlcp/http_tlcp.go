package tlcp

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"strings"
	"zjdns/config"
	zdnsutil "zjdns/internal/dnsutil"
	"zjdns/internal/log"
	"zjdns/internal/pool"

	"codeberg.org/miekg/dns/dnshttp"
	"gitee.com/Trisia/gotlcp/tlcp"
)

func (s *Server) startDOHServer() error {
	addrs, err := zdnsutil.ResolveBindAddrs("tcp", s.dohPort)
	if err != nil {
		return fmt.Errorf("resolve bind addrs: %w", err)
	}

	log.Infof("TLCP: DoH server started on %v (TLCP HTTP/1.1)", addrs)
	for _, addr := range addrs {
		rawListener, err := net.Listen("tcp", addr)
		if err != nil {
			log.Warnf("TLCP: skipping tcp address %s: %v", addr, err)
			continue
		}
		keepAliveListener := &tcpKeepAliveListener{Listener: rawListener}

		tlcpCfg := s.tlcpConfig.Clone()
		// This http.Server is served over a gotlcp tlcp.Listener — net/http
		// only performs ALPN dispatch for *tls.Conn, so it always parses
		// HTTP/1.1 here. Advertising h2 would make ALPN-compliant clients
		// negotiate HTTP/2 and send the HTTP/2 preface, which the HTTP/1.1
		// parser rejects.
		tlcpCfg.NextProtos = []string{"http/1.1"}
		tlcpListener := tlcp.NewListener(keepAliveListener, tlcpCfg)

		s.dohListeners = append(s.dohListeners, tlcpListener)

		dohSrv := &http.Server{
			Handler:           http.HandlerFunc(s.serveDOH),
			ReadHeaderTimeout: config.DefaultHTTPReadHeaderTimeout,
			// Bound the full request read: without it a client can trickle a
			// POST body byte-by-byte and hold the connection forever
			// (IdleTimeout does not apply mid-request).
			ReadTimeout:  config.DefaultHTTPServerReadTimeout,
			WriteTimeout: config.DefaultHTTPServerWriteTimeout,
			IdleTimeout:  config.DefaultHTTPServerIdleTimeout,
			TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
		}
		s.dohServers = append(s.dohServers, dohSrv)

		s.serverGroup.Go(func() error {
			defer zdnsutil.HandlePanic("TLCP DoH server")
			if err := dohSrv.Serve(tlcpListener); err != nil && err != http.ErrServerClosed && s.ctx.Err() == nil {
				log.Errorf("TLCP: DoH serve error: %v", err)
			}
			return nil
		})
	}
	return nil
}

func (s *Server) serveDOH(w http.ResponseWriter, r *http.Request) {
	if s == nil || s.handler == nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	endpoint := s.dohEndpoint
	if endpoint == "" {
		endpoint = config.DefaultQueryPath
	}

	if r.URL.Path != endpoint {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	// RFC 8484 §4.2.1: POST with a wrong Content-Type → 415 (mirrors the
	// TLS DoH handler; dnshttp.Request itself does not check it here).
	if r.Method == http.MethodPost && r.Header.Get("Content-Type") != "" &&
		!strings.HasPrefix(r.Header.Get("Content-Type"), dnshttp.MimeType) {
		http.Error(w, http.StatusText(http.StatusUnsupportedMediaType), http.StatusUnsupportedMediaType)
		return
	}

	// Validate GET request size before delegation (same as TLS DoH handler).
	if r.Method == http.MethodGet {
		dnsParam := r.URL.Query().Get("dns")
		if dnsParam == "" {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		// Compare the DECODED length: base64url inflates 4/3, so a raw
		// comparison would 400 legitimate wire messages between ~49KB and
		// the 65535 cap (tls/https.go decodes first for the same reason).
		raw, err := base64.RawURLEncoding.DecodeString(dnsParam)
		if err != nil || len(raw) > config.DefaultDOHMaxRequestSize {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
	}
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, config.DefaultDOHMaxRequestSize)
	}

	msg, err := dnshttp.Request(r)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	host, _, _ := net.SplitHostPort(r.RemoteAddr) // _ = port, _ = error: SplitHostPort for IP extraction; empty host handled below by net.ParseIP
	clientIP := net.ParseIP(host)

	resp := s.handler.ServeDNS(msg, clientIP, true, config.ProtoHTTPTLCP)
	if resp == nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	defer pool.DefaultMessage.Put(resp)

	if err := resp.Pack(); err != nil {
		log.Debugf("TLCP: DoH pack error: %v", err)
		http.Error(w, "pack error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", dnshttp.MimeType)
	// NOTE(M12): Write error is intentionally ignored — partial response cannot be
	// recovered. Client will detect truncation via connection close.
	_, _ = w.Write(resp.Data) //nolint:gosec // G705: DNS wire format bytes, not HTML
}
