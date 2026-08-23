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
		tlcpCfg.NextProtos = config.NextProtoDOH
		tlcpListener := tlcp.NewListener(keepAliveListener, tlcpCfg)

		dohSrv := &http.Server{
			Handler:           http.HandlerFunc(s.serveDOH),
			ReadHeaderTimeout: config.DefaultHTTPReadHeaderTimeout,
			WriteTimeout:      config.DefaultHTTPServerWriteTimeout,
			IdleTimeout:       config.DefaultHTTPServerIdleTimeout,
			TLSNextProto:      make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
		}
		s.listenerMu.Lock()
		s.dohListeners = append(s.dohListeners, tlcpListener)
		s.dohServers = append(s.dohServers, dohSrv)
		s.listenerMu.Unlock()

		s.serverGroup.Go(func() error {
			defer zdnsutil.HandlePanic("TLCP DoH server")
			if err := dohSrv.Serve(tlcpListener); err != nil && err != http.ErrServerClosed {
				log.Warnf("TLCP: DoH serve error: %v", err)
			}
			return nil
		})
	}
	return nil
}

// ServeDOH handles HTTPoverTLCP requests (exported for shared-port Manager).
func (s *Server) ServeDOH(w http.ResponseWriter, r *http.Request) {
	s.serveDOH(w, r)
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

	// Validate GET request size before delegation — the base64url parameter
	// must be DECODED first (base64 expands ~4/3): comparing the encoded
	// length rejects valid messages between ~49KB and 64KB that the POST
	// path and the TLS DoH handler accept (mirrors tls/https.go, R3-L18).
	if r.Method == http.MethodGet {
		dnsParam := r.URL.Query().Get("dns")
		decoded, err := base64.RawURLEncoding.DecodeString(dnsParam)
		if err != nil || len(decoded) > config.DefaultDOHMaxRequestSize {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
	}
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, config.DefaultDOHMaxRequestSize)
	}

	msg, err := dnshttp.Request(r)
	if err != nil {
		// RFC 8484 §4.2.1: POST with a non-dns-message Content-Type → 415
		// (mirrors the TLS DoH handler, tls/https.go).
		if r.Method == http.MethodPost && r.Header.Get("Content-Type") != "" &&
			!strings.HasPrefix(r.Header.Get("Content-Type"), dnshttp.MimeType) {
			http.Error(w, http.StatusText(http.StatusUnsupportedMediaType), http.StatusUnsupportedMediaType)
			return
		}
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	host, _, _ := net.SplitHostPort(r.RemoteAddr) // _ = port, _ = error: SplitHostPort for IP extraction; empty host handled below by net.ParseIP
	clientIP := net.ParseIP(host)

	resp := s.handler.ServeDNS(msg, clientIP, true, config.ProtoHTTPTLCP)
	if resp == msg { //nolint:revive // identity guard: ServeDNS must never return the request (L5)
		resp = nil
	}
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
