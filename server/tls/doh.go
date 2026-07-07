package tls

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	stdlog "log"
	"net"
	"net/http"
	"strings"
	"time"
	"zjdns/config"
	"zjdns/internal/dnsutil"
	"zjdns/internal/log"
	"zjdns/internal/pool"

	"codeberg.org/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	eTLS "gitlab.com/go-extension/tls"
	"golang.org/x/net/http2"
)

// http2LogWriter routes http2.Server errors to ZJDNS's internal/log,
// detecting KTLS "bad record MAC" errors and suggesting kernel_rx=false.
type http2LogWriter struct{}

func (w http2LogWriter) Write(p []byte) (n int, err error) {
	msg := strings.TrimSpace(string(p))
	if strings.Contains(msg, "bad record MAC") {
		log.Warnf("TLS: %s — try setting server.tls.ktls.kernel_rx=false to disable kernel RX offload", msg)
	} else {
		log.Warnf("TLS: %s", msg)
	}
	return len(p), nil
}

func (s *Server) startDOHServer(port string) error {
	addrs, err := dnsutil.ResolveBindAddrs("tcp", port)
	if err != nil {
		return fmt.Errorf("DoH address resolution: %w", err)
	}

	s.dohServer = new(http2.Server)
	baseCfg := &http.Server{
		ReadHeaderTimeout: config.DefaultHTTPReadHeaderTimeout,
		WriteTimeout:      config.DefaultHTTPServerWriteTimeout,
		IdleTimeout:       config.DefaultHTTPServerIdleTimeout,
		ErrorLog:          stdlog.New(http2LogWriter{}, "", 0),
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
		log.Infof("TLS: DoH server started on %s", addr)

		capturedDoH := httpsListener
		s.serverGroup.Go(func() error {
			defer dnsutil.HandlePanic("DoH server")
			for {
				conn, err := capturedDoH.Accept()
				if err != nil {
					if s.ctx.Err() != nil {
						return nil
					}
					log.Warnf("TLS: DoH Accept failed: %v (type=%T)", err, err)
					time.Sleep(config.DefaultAcceptRetryDelay)
					continue
				}

				log.Debugf("TLS: DoH TCP accepted from %s, TLS handshake pending", conn.RemoteAddr())

				s.serverGroup.Go(func() error {
					defer dnsutil.HandlePanic("DoH connection handler")
					log.Debugf("TLS: DoH starting HTTP/2 ServeConn for %s", conn.RemoteAddr())
					s.dohServer.ServeConn(conn, &http2.ServeConnOpts{
						Handler:    s,
						BaseConfig: baseCfg,
					})
					return nil
				})
			}
		})

	}
	return nil
}

func (s *Server) startDOH3Server(port string) error {
	addrs, err := dnsutil.ResolveBindAddrs("udp", port)
	if err != nil {
		return fmt.Errorf("DoH3 address resolution: %w", err)
	}

	s.h3Validator = newQUICAddrValidator()

	tlsConfig := s.QUICTLSConfig().Clone()
	tlsConfig.NextProtos = config.NextProtoDOH3

	quicConfig := &quic.Config{
		MaxIdleTimeout:        config.DefaultQUICServerIdleTimeout,
		MaxIncomingStreams:    config.DefaultMaxIncomingStreams,
		MaxIncomingUniStreams: config.DefaultMaxIncomingStreams,
		Allow0RTT:             true,
		EnableDatagrams:       true,
		KeepAlivePeriod:       config.DefaultQUICKeepAlive,
	}

	s.h3Server = &http3.Server{Handler: s}

	for _, addr := range addrs {
		udpAddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			return fmt.Errorf("resolve UDP address %s: %w", addr, err)
		}

		conn, err := net.ListenUDP("udp", udpAddr)
		if err != nil {
			return fmt.Errorf("UDP listen on %s: %w", addr, err)
		}
		s.h3Conns = append(s.h3Conns, conn)

		transport := &quic.Transport{
			Conn:                conn,
			VerifySourceAddress: s.h3Validator.requiresValidation,
		}
		s.h3Transports = append(s.h3Transports, transport)

		listener, err := transport.ListenEarly(tlsConfig, quicConfig)
		if err != nil {
			_ = conn.Close()
			return fmt.Errorf("DoH3 listen on %s: %w", addr, err)
		}
		s.h3Listeners = append(s.h3Listeners, listener)

		log.Infof("TLS: DoH3 server started on %s", addr)

		capturedH3 := listener
		s.serverGroup.Go(func() error {
			defer dnsutil.HandlePanic("DoH3 server")
			for {
				conn, err := capturedH3.Accept(s.ctx)
				if err != nil {
					if s.ctx.Err() != nil {
						return nil
					}
					log.Errorf("TLS: DoH3 Accept error: %v", err)
					time.Sleep(config.DefaultAcceptRetryDelay)
					continue
				}

				s.serverGroup.Go(func() error {
					defer dnsutil.HandlePanic("DoH3 connection handler")
					if err := s.h3Server.ServeQUICConn(conn); err != nil && !errors.Is(err, http.ErrServerClosed) {
						log.Debugf("TLS: DoH3 connection error: %v", err)
					}
					return nil
				})
			}
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

	if r.URL.Path != expectedPath {
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

	protocol := "DoH"
	if strings.HasPrefix(r.Proto, "HTTP/3") {
		protocol = "DoH3"
	}
	response := s.handler.ServeDNS(req, clientIP, true, protocol)
	pool.DefaultMessagePool.Put(req)

	if err := s.respondDOH(w, response); err != nil {
		log.Errorf("TLS: DoH response failed: %v", err)
	}
	if response != nil {
		pool.DefaultMessagePool.Put(response)
	}
}

func (s *Server) parseDOHRequest(r *http.Request, w http.ResponseWriter) (msg *dns.Msg, statusCode int) {
	var buf []byte
	var err error

	switch r.Method {
	case http.MethodGet:
		dnsParam := r.URL.Query().Get("dns")
		if dnsParam == "" || len(dnsParam) > config.DefaultDOHMaxRequestSize {
			return nil, http.StatusBadRequest
		}
		buf, err = base64.RawURLEncoding.DecodeString(dnsParam)
		if err != nil {
			return nil, http.StatusBadRequest
		}

	case http.MethodPost:
		if r.Header.Get("Content-Type") != config.DOHContentType {
			return nil, http.StatusUnsupportedMediaType
		}
		r.Body = http.MaxBytesReader(w, r.Body, config.DefaultDOHMaxRequestSize)
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
	req.Data = buf
	if err := req.Unpack(); err != nil {
		pool.DefaultMessagePool.Put(req)
		return nil, http.StatusBadRequest
	}

	return req, http.StatusOK
}

func (s *Server) respondDOH(w http.ResponseWriter, response *dns.Msg) error {
	if response == nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return nil
	}

	err := response.Pack()
	bytes := response.Data
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return fmt.Errorf("pack response: %w", err)
	}

	w.Header().Set("Content-Type", config.DOHContentType)
	w.Header().Set("Cache-Control", "max-age=0")
	n, err := w.Write(bytes) //nolint:gosec // G705: DNS wire format, not user-facing HTML
	if n != len(bytes) {
		return fmt.Errorf("short write: %d/%d bytes", n, len(bytes))
	}
	return err
}
