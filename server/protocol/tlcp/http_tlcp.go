package tlcp

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"zjdns/config"
	zdnsutil "zjdns/internal/dnsutil"
	"zjdns/internal/log"

	"codeberg.org/miekg/dns/dnshttp"
	"gitee.com/Trisia/gotlcp/tlcp"
)

func (s *Server) startDOHServer() error {
	// Use external shared listener (port-sharing mode) if set.
	// The shared.DoH serve loop handles both TLS and TLCP connections.
	if s.extDoHListener != nil {
		s.dohListeners = append(s.dohListeners, s.extDoHListener)
		log.Debugf("TLCP: DoH using shared listener on %s", s.extDoHListener.Addr())
		return nil
	}

	addrs, err := zdnsutil.ResolveBindAddrs("tcp", s.dohPort)
	if err != nil {
		return fmt.Errorf("resolve bind addrs: %w", err)
	}

	dnshttp.MsgAcceptFunc = zdnsutil.ServerDOHMsgAccept

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

		s.dohListeners = append(s.dohListeners, tlcpListener)

		dohSrv := &http.Server{
			Handler:           http.HandlerFunc(s.serveDOH),
			ReadHeaderTimeout: config.DefaultHTTPReadHeaderTimeout,
			IdleTimeout:       config.DefaultHTTPServerIdleTimeout,
			TLSNextProto:      make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
		}
		s.dohServers = append(s.dohServers, dohSrv)

		s.serverGroup.Go(func() error {
			defer zdnsutil.HandlePanic("TLCP DoH server")
			if err := dohSrv.Serve(tlcpListener); err != nil && err != http.ErrServerClosed {
				log.Errorf("TLCP: DoH serve error: %v", err)
			}
			return nil
		})
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

	msg, err := dnshttp.Request(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
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

	w.Header().Set("Content-Type", dnshttp.MimeType)
	_, _ = w.Write(resp.Data) //nolint:gosec // G705: DNS wire format bytes, not HTML
}
