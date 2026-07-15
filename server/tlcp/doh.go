package tlcp

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"zjdns/config"
	zdnsutil "zjdns/internal/dnsutil"
	"zjdns/internal/log"

	"codeberg.org/miekg/dns"
	"gitee.com/Trisia/gotlcp/tlcp"
)

func (s *Server) startDOHServer() error {
	addrs, err := zdnsutil.ResolveBindAddrs("tcp", s.dohPort)
	if err != nil {
		return fmt.Errorf("resolve bind addrs: %w", err)
	}

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

		s.dohListeners = append(s.dohListeners, tlcpListener)

		dohSrv := &http.Server{
			Handler:           http.HandlerFunc(s.serveDOH),
			ReadHeaderTimeout: config.DefaultHTTPReadHeaderTimeout,
			IdleTimeout:       config.DefaultHTTPServerIdleTimeout,
			TLSNextProto:      make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
		}
		s.dohServers = append(s.dohServers, dohSrv)
		log.Infof("TLCP: DoH server started on %s (TLCP HTTP/1.1)", addr)

		go func(srv *http.Server, l net.Listener) {
			defer zdnsutil.HandlePanic("TLCP DoH server")
			if err := srv.Serve(l); err != nil && err != http.ErrServerClosed {
				log.Errorf("TLCP: DoH serve error: %v", err)
			}
		}(dohSrv, tlcpListener)
	}
	return nil
}

func (s *Server) serveDOH(w http.ResponseWriter, r *http.Request) {
	endpoint := s.dohEndpoint
	if endpoint == "" {
		endpoint = config.DefaultQueryPath
	}

	if r.URL.Path != endpoint {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	msg := new(dns.Msg)

	switch r.Method {
	case http.MethodGet:
		dnsParam := r.URL.Query().Get("dns")
		if dnsParam == "" {
			http.Error(w, "missing dns parameter", http.StatusBadRequest)
			return
		}
		raw, err := base64.RawURLEncoding.DecodeString(dnsParam)
		if err != nil {
			http.Error(w, "invalid dns parameter", http.StatusBadRequest)
			return
		}
		msg.Data = raw
		if err := msg.Unpack(); err != nil {
			http.Error(w, "invalid dns message", http.StatusBadRequest)
			return
		}
	case http.MethodPost:
		if r.Header.Get("Content-Type") != config.DOHContentType {
			http.Error(w, "unsupported media type", http.StatusUnsupportedMediaType)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read body error", http.StatusBadRequest)
			return
		}
		msg.Data = body
		if err := msg.Unpack(); err != nil {
			http.Error(w, "invalid dns message", http.StatusBadRequest)
			return
		}
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	clientIP := net.ParseIP(host)

	resp := s.handler.ServeDNS(msg, clientIP, true, config.ProtoHTTPTLCP)
	if resp == nil {
		return
	}

	if err := resp.Pack(); err != nil {
		log.Debugf("TLCP: DoH pack error: %v", err)
		http.Error(w, "pack error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", config.DOHContentType)
	_, _ = w.Write(resp.Data) //nolint:gosec // G705: DNS wire format bytes, not HTML
}
