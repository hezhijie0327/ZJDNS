package server

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"zjdns/config"
	"zjdns/internal/dnsutil"
	"zjdns/internal/log"
	"zjdns/internal/pool"
)

// startDOHServer starts the DNS over HTTPS server (HTTP/2).
func (tm *TLSManager) startDOHServer(port string) error {
	listener, err := net.Listen("tcp", ":"+port)
	if err != nil {
		return fmt.Errorf("DoH listen: %w", err)
	}

	tlsConfig := tm.tlsConfig.Clone()
	tlsConfig.NextProtos = NextProtoDoH

	tm.httpsListener = tls.NewListener(listener, tlsConfig)
	log.Infof("TLS: DoH server started on port %s", port)

	tm.httpsServer = &http.Server{
		Handler:           tm,
		ReadHeaderTimeout: OperationTimeout,
		WriteTimeout:      OperationTimeout,
		IdleTimeout:       config.IdleTimeout,
	}

	tm.serverGroup.Go(func() error {
		defer dnsutil.HandlePanic("DoH server")
		if err := tm.httpsServer.Serve(tm.httpsListener); err != nil && err != http.ErrServerClosed {
			log.Errorf("TLS: DoH server error: %v", err)
			return err
		}
		return nil
	})

	return nil
}

// startDoH3Server starts the DNS over HTTPS server (HTTP/3).
func (tm *TLSManager) startDoH3Server(port string) error {
	addr := ":" + port

	tlsConfig := tm.tlsConfig.Clone()
	tlsConfig.NextProtos = NextProtoDoH3

	quicConfig := &quic.Config{
		MaxIdleTimeout:        config.IdleTimeout,
		MaxIncomingStreams:    MaxIncomingStreams,
		MaxIncomingUniStreams: MaxIncomingStreams,
		Allow0RTT:             true,
		EnableDatagrams:       true,
	}

	quicListener, err := quic.ListenAddrEarly(addr, tlsConfig, quicConfig)
	if err != nil {
		return fmt.Errorf("DoH3 listen: %w", err)
	}

	tm.h3Listener = quicListener
	log.Infof("TLS: DoH3 server started on port %s", port)

	tm.h3Server = &http3.Server{Handler: tm}

	tm.serverGroup.Go(func() error {
		defer dnsutil.HandlePanic("DoH3 server")
		if err := tm.h3Server.ServeListener(tm.h3Listener); err != nil && err != http.ErrServerClosed {
			log.Errorf("TLS: DoH3 server error: %v", err)
			return err
		}
		return nil
	})

	return nil
}

// ServeHTTP handles HTTP requests for DoH/DoH3 servers.
func (tm *TLSManager) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if tm == nil || tm.server == nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	// Check endpoint path
	expectedPath := tm.server.config.Server.TLS.HTTPS.Endpoint
	if expectedPath == "" {
		expectedPath = config.DefaultQueryPath
	}
	if !strings.HasPrefix(expectedPath, "/") {
		expectedPath = "/" + expectedPath
	}

	if r.URL.Path != expectedPath {
		http.NotFound(w, r)
		return
	}

	// Parse the DNS request
	req, statusCode := tm.parseDoHRequest(r, w)
	if req == nil {
		http.Error(w, http.StatusText(statusCode), statusCode)
		return
	}

	// Extract client IP from the HTTP request
	var clientIP net.IP
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		clientIP = net.ParseIP(host)
	}
	// Process the query
	protocol := "DoH"
	if strings.HasPrefix(r.Proto, "HTTP/3") {
		protocol = "DoH3"
	}
	response := tm.server.processDNSQuery(req, clientIP, true, protocol)
	pool.DefaultMessagePool.Put(req)

	if err := tm.respondDoH(w, response); err != nil {
		log.Errorf("TLS: DoH response failed: %v", err)
	}
	if response != nil {
		pool.DefaultMessagePool.Put(response)
	}
}

// parseDoHRequest parses a DNS request from an HTTP request.
// It supports both GET (with base64url encoded dns parameter) and POST methods.
func (tm *TLSManager) parseDoHRequest(r *http.Request, w http.ResponseWriter) (*dns.Msg, int) {
	var buf []byte
	var err error

	switch r.Method {
	case http.MethodGet:
		dnsParam := r.URL.Query().Get("dns")
		if dnsParam == "" || len(dnsParam) > DoHMaxRequestSize {
			return nil, http.StatusBadRequest
		}
		buf, err = base64.RawURLEncoding.DecodeString(dnsParam)
		if err != nil {
			return nil, http.StatusBadRequest
		}

	case http.MethodPost:
		if r.Header.Get("Content-Type") != "application/dns-message" {
			return nil, http.StatusUnsupportedMediaType
		}
		r.Body = http.MaxBytesReader(w, r.Body, DoHMaxRequestSize)
		buf, err = io.ReadAll(r.Body)
		defer func() { _ = r.Body.Close() }()
		if err != nil {
			return nil, http.StatusBadRequest
		}

	default:
		return nil, http.StatusMethodNotAllowed
	}

	if len(buf) == 0 {
		return nil, http.StatusBadRequest
	}

	req := pool.DefaultMessagePool.Get()
	if err := req.Unpack(buf); err != nil {
		pool.DefaultMessagePool.Put(req)
		return nil, http.StatusBadRequest
	}

	return req, http.StatusOK
}

// respondDoH sends a DNS response as an HTTP response.
func (tm *TLSManager) respondDoH(w http.ResponseWriter, response *dns.Msg) error {
	if response == nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return nil
	}

	bytes, err := response.Pack()
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return fmt.Errorf("pack response: %w", err)
	}

	w.Header().Set("Content-Type", "application/dns-message")
	w.Header().Set("Cache-Control", "max-age=0")
	_, err = w.Write(bytes)
	return err
}
