package tls

import (
	"encoding/base64"
	"fmt"
	"io"
	stdlog "log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	cryptotls "gitlab.com/go-extension/tls"
	"golang.org/x/net/http2"

	"zjdns/config"
	"zjdns/internal/dnsutil"
	"zjdns/internal/log"
	"zjdns/internal/pool"
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
	listener, err := net.Listen("tcp", ":"+port)
	if err != nil {
		return err
	}

	// Wrap raw listener to log every TCP connection before TLS handshake,
	// so we can distinguish "never reached us" from "reached us but TLS failed".
	rawListener := &debugListener{Listener: &TCPKeepAliveListener{Listener: listener}, name: "DoH"}

	tlsConfig := s.tlsConfig.Clone()
	tlsConfig.NextProtos = config.NextProtoDOH
	tlsConfig.GetConfigForClient = s.getConfigForClient(config.NextProtoDOH)

	s.httpsListener = cryptotls.NewListener(rawListener, tlsConfig)
	log.Infof("TLS: DoH server started on port %s", port)

	// Warn if only loopback is reachable — helps diagnose LAN access issues.
	log.Infof("TLS: DoH accepting on all interfaces (0.0.0.0:%s, [::]:%s)", port, port)

	// Go's net/http only detects TLS on standard *tls.Conn, not
	// *cryptotls.Conn, so HTTP/2 is silently disabled. We serve
	// HTTP/2 explicitly via an accept loop so KTLS remains active.
	s.dohServer = new(http2.Server)
	baseCfg := &http.Server{
		ReadHeaderTimeout: config.DefaultHTTPReadHeaderTimeout,
		WriteTimeout:      config.DefaultHTTPServerWriteTimeout,
		IdleTimeout:       config.DefaultHTTPServerIdleTimeout,
		ErrorLog:          stdlog.New(http2LogWriter{}, "", 0),
	}

	s.serverGroup.Go(func() error {
		defer dnsutil.HandlePanic("DoH server")
		for {
			conn, err := s.httpsListener.Accept()
			if err != nil {
				if s.ctx.Err() != nil {
					return nil
				}
				log.Warnf("TLS: DoH Accept failed: %v (type=%T)", err, err)
				time.Sleep(config.DefaultAcceptRetryDelay)
				continue
			}

			log.Debugf("TLS: DoH TCP accepted from %s, TLS handshake pending", conn.RemoteAddr())

			go func(c net.Conn) {
				defer dnsutil.HandlePanic("DoH connection handler")
				log.Debugf("TLS: DoH starting HTTP/2 ServeConn for %s", c.RemoteAddr())
				s.dohServer.ServeConn(c, &http2.ServeConnOpts{
					Handler:    s,
					BaseConfig: baseCfg,
				})
			}(conn)
		}
	})

	return nil
}

func (s *Server) startDoH3Server(port string) error {
	addr := ":" + port

	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return fmt.Errorf("resolve UDP address: %w", err)
	}

	s.h3Conn, err = net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("UDP listen: %w", err)
	}

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

	s.h3Validator = newQUICAddrValidator()
	s.h3Transport = &quic.Transport{
		Conn:                s.h3Conn,
		VerifySourceAddress: s.h3Validator.requiresValidation,
	}
	s.h3Listener, err = s.h3Transport.ListenEarly(tlsConfig, quicConfig)
	if err != nil {
		_ = s.h3Conn.Close()
		return fmt.Errorf("DoH3 listen: %w", err)
	}

	log.Infof("TLS: DoH3 server started on port %s", port)

	s.h3Server = &http3.Server{Handler: s}

	s.serverGroup.Go(func() error {
		defer dnsutil.HandlePanic("DoH3 server")
		for {
			conn, err := s.h3Listener.Accept(s.ctx)
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
				if err := s.h3Server.ServeQUICConn(conn); err != nil && err != http.ErrServerClosed {
					log.Debugf("TLS: DoH3 connection error: %v", err)
				}
				return nil
			})
		}
	})

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

	req, statusCode := s.parseDoHRequest(r, w)
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

	if err := s.respondDoH(w, response); err != nil {
		log.Errorf("TLS: DoH response failed: %v", err)
	}
	if response != nil {
		pool.DefaultMessagePool.Put(response)
	}
}

func (s *Server) parseDoHRequest(r *http.Request, w http.ResponseWriter) (*dns.Msg, int) {
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
	if err := req.Unpack(buf); err != nil {
		pool.DefaultMessagePool.Put(req)
		return nil, http.StatusBadRequest
	}

	return req, http.StatusOK
}

func (s *Server) respondDoH(w http.ResponseWriter, response *dns.Msg) error {
	if response == nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return nil
	}

	bytes, err := response.Pack()
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return fmt.Errorf("pack response: %w", err)
	}

	w.Header().Set("Content-Type", config.DOHContentType)
	w.Header().Set("Cache-Control", "max-age=0")
	_, err = w.Write(bytes)
	return err
}
