package tls

import (
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"

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

func (s *Server) startDOHServer(port string) error {
	listener, err := net.Listen("tcp", ":"+port)
	if err != nil {
		return err
	}

	tlsConfig := s.tlsConfig.Clone()
	tlsConfig.NextProtos = config.NextProtoDOH
	tlsConfig.GetConfigForClient = s.getConfigForClient(config.NextProtoDOH)

	s.httpsListener = cryptotls.NewListener(listener, tlsConfig)
	log.Infof("TLS: DoH server started on port %s", port)

	// Go's net/http only detects TLS on standard *tls.Conn, not
	// *cryptotls.Conn, so HTTP/2 is silently disabled. We serve
	// HTTP/2 explicitly via an accept loop so KTLS remains active.
	s.dohServer = new(http2.Server)
	baseCfg := &http.Server{
		ReadHeaderTimeout: config.DefaultHTTPReadHeaderTimeout,
		WriteTimeout:      config.DefaultHTTPServerWriteTimeout,
		IdleTimeout:       config.DefaultHTTPServerIdleTimeout,
	}

	s.serverGroup.Go(func() error {
		defer dnsutil.HandlePanic("DoH server")
		const maxConnsPerIP = config.DefaultMaxConnsPerIP
		for {
			conn, err := s.httpsListener.Accept()
			if err != nil {
				return nil // listener closed
			}

			// Per-IP DoH connection limit (matches DoT/DoQ policy).
			var ipCount *atomic.Int32
			if host, _, err := net.SplitHostPort(conn.RemoteAddr().String()); err == nil {
				val, _ := s.dohIPCounts.LoadOrStore(host, new(atomic.Int32))
				ipCount = val.(*atomic.Int32)
				if ipCount.Add(1) > maxConnsPerIP {
					ipCount.Add(-1)
					_ = conn.Close()
					log.Debugf("TLS: DoH per-IP connection limit reached for %s, rejecting", host)
					continue
				}
			}

			go func(c net.Conn) {
				if ipCount != nil {
					defer ipCount.Add(-1)
				}
				defer dnsutil.HandlePanic("DoH connection handler")
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

	tlsConfig := s.QUICTLSConfig().Clone()
	tlsConfig.NextProtos = config.NextProtoDOH3

	quicConfig := &quic.Config{
		MaxIdleTimeout:        config.DefaultQUICServerIdleTimeout,
		MaxIncomingStreams:    config.DefaultMaxIncomingStreams,
		MaxIncomingUniStreams: config.DefaultMaxIncomingStreams,
		Allow0RTT:             true,
		EnableDatagrams:       true,
	}

	quicListener, err := quic.ListenAddrEarly(addr, tlsConfig, quicConfig)
	if err != nil {
		return err
	}

	s.h3Listener = quicListener
	log.Infof("TLS: DoH3 server started on port %s", port)

	s.h3Server = &http3.Server{Handler: s}

	s.serverGroup.Go(func() error {
		defer dnsutil.HandlePanic("DoH3 server")
		const maxConnsPerIP = config.DefaultMaxConnsPerIP
		for {
			conn, err := s.h3Listener.Accept(s.ctx)
			if err != nil {
				if s.ctx.Err() != nil {
					return nil
				}
				log.Errorf("TLS: DoH3 Accept error: %v", err)
				continue
			}

			// Per-IP DoH3 connection limit (matches DoT/DoQ/DoH policy).
			var ipCount *atomic.Int32
			if host, _, err := net.SplitHostPort(conn.RemoteAddr().String()); err == nil {
				val, _ := s.doh3IPCounts.LoadOrStore(host, new(atomic.Int32))
				ipCount = val.(*atomic.Int32)
				if ipCount.Add(1) > maxConnsPerIP {
					ipCount.Add(-1)
					_ = conn.CloseWithError(0, "too many connections")
					log.Debugf("TLS: DoH3 per-IP connection limit reached for %s, rejecting", host)
					continue
				}
			}

			s.serverGroup.Go(func() error {
				if ipCount != nil {
					defer ipCount.Add(-1)
				}
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
		if dnsParam == "" || len(dnsParam) > config.DefaultDoHMaxRequestSize {
			return nil, http.StatusBadRequest
		}
		buf, err = base64.RawURLEncoding.DecodeString(dnsParam)
		if err != nil {
			return nil, http.StatusBadRequest
		}

	case http.MethodPost:
		if r.Header.Get("Content-Type") != config.DoHContentType {
			return nil, http.StatusUnsupportedMediaType
		}
		r.Body = http.MaxBytesReader(w, r.Body, config.DefaultDoHMaxRequestSize)
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

	w.Header().Set("Content-Type", config.DoHContentType)
	w.Header().Set("Cache-Control", "max-age=0")
	_, err = w.Write(bytes)
	return err
}
