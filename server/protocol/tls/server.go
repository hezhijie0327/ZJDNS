// Package tls provides TLS-based secure DNS server implementation supporting DoT,
// DoQ, DoH, and DoH3 protocols.
package tls

import (
	"context"
	stdtls "crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
	"zjdns/config"
	"zjdns/edns"
	zdnsutil "zjdns/internal/dnsutil"
	"zjdns/internal/log"
	"zjdns/internal/lrumap"

	"github.com/pion/dtls/v3"
	dtlsnet "github.com/pion/dtls/v3/pkg/net"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	eHTTP "gitlab.com/go-extension/http"
	eTLS "gitlab.com/go-extension/tls"
	"golang.org/x/sync/errgroup"
)

// KTLSSettings configures kernel TLS offload for DoT/DoH server listeners.
type KTLSSettings struct {
	KernelTX bool // kernel TLS TX offload (default false)
	KernelRX bool // kernel TLS RX offload (default false)
}

// Config holds the configuration for the TLS server including ports,
// certificate paths, and endpoint settings.
type Config struct {
	TLSPort       string // DoT
	QUICPort      string // DoQ
	DTLSPort      string // DTLS (RFC 8094)
	HTTPSPort     string // DoH
	HTTP3Port     string // DoH3
	HTTPSEndpoint string
	HTTP3Endpoint string
	SelfSigned    bool
	CertFile      string
	KeyFile       string
	Domain        string
	KTLS          *KTLSSettings
	SkipHTTPS     bool // skip standalone HTTPS listener (shared port handled by TLCP demux)
	SkipDOT       bool // skip standalone DoT listener (shared TCP port with TLCP DoT)
	SkipDTLS      bool // skip standalone DTLS listener (shared UDP port with DTLCP)
	SkipDOQ       bool // skip standalone DoQ listener (shared UDP port with DTLCP)
}

// Server manages TLS-based secure DNS protocol listeners and their lifecycle.
type Server struct {
	cfg           *Config
	handler       edns.DNSHandler
	tlsConfig     *eTLS.Config   // TCP-based TLS (DoT, DoH) with KTLS
	baseTLSConfig *eTLS.Config   // base config for per-listener GetConfigForClient clones
	quicTLSConfig *stdtls.Config // QUIC-based protocols (DoQ, DoH3)
	dohHandler    eHTTP.Handler  // shared-port DOH handler (wraps ServeHTTP for eHTTP)
	ctx           context.Context
	cancel        context.CancelCauseFunc
	serverGroup   *errgroup.Group
	quicConnSem   chan struct{} // admission cap for concurrent QUIC connections (DoQ/DoH3) — half the errgroup limit so a QUIC flood cannot starve the DoT/DTLS/DoH listeners of goroutine slots (M-low)

	listenerMu     sync.Mutex // protects all listener/conn slice fields below
	dotListeners   []net.Listener
	dotConns       map[net.Conn]struct{} // active DoT conns — woken on Shutdown (M-3-5)
	doqConns       []*net.UDPConn
	doqTransports  []*quic.Transport
	doqListeners   []*quic.EarlyListener
	dohServers     []*eHTTP.Server
	h3Server       *http3.Server
	httpsListeners []net.Listener
	h3Conns        []*net.UDPConn
	h3Transports   []*quic.Transport
	h3Listeners    []*quic.EarlyListener
	stdCert        stdtls.Certificate // for DTLS server
	dtlsListeners  []net.Listener
}

// debugListener wraps a net.Listener to log every raw TCP connection before
// the TLS handshake. This helps distinguish "TCP never reached us" from
// "TCP connected but TLS handshake failed/hung".
type debugListener struct {
	net.Listener
	name string
}

const (
	// TLSConnBufferSize is the buffer size for TLS connection readers.
	TLSConnBufferSize = 4096
)

func (d *debugListener) Accept() (net.Conn, error) {
	conn, err := d.Listener.Accept()
	if err != nil {
		log.Debugf("TLS: %s raw Accept error: %v", d.name, err)
		return nil, err
	}
	log.Debugf("TLS: %s raw TCP connection from %s", d.name, conn.RemoteAddr())
	return conn, nil
}

// New creates a new TLS Server with the given DNS handler and configuration,
// loading or generating the TLS certificate as specified.
func New(dnsHandler edns.DNSHandler, cfg *Config) (*Server, error) {
	if dnsHandler == nil {
		return nil, errors.New("tls: nil DNS handler")
	}
	if cfg == nil {
		return nil, errors.New("tls: nil config")
	}
	var eCert eTLS.Certificate
	var sCert stdtls.Certificate
	var err error

	if cfg.SelfSigned {
		eCert, err = generateSelfSignedCert(cfg.Domain)
		if err != nil {
			return nil, fmt.Errorf("generate self-signed certificate: %w", err)
		}
		// Build standard crypto/tls certificate from the same DER + key.
		sCert = stdtls.Certificate{Certificate: eCert.Certificate, PrivateKey: eCert.PrivateKey}
		log.Infof("TLS: Using self-signed certificate for domain: %s", cfg.Domain)
	} else {
		eCert, err = eTLS.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("load certificate: %w", err)
		}
		sCert, err = stdtls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("load certificate (std): %w", err)
		}
		log.Debugf("TLS: Using certificate from files: %s, %s", cfg.CertFile, cfg.KeyFile)
	}

	// TCP-based TLS config (DoT, DoH).
	// KTLS defaults to off. Enable kernel_tx for TX offload (usually
	// safe); enable kernel_rx only if your kernel/NIC combination
	// does not produce "bad record MAC" errors.
	baseConfig := &eTLS.Config{
		KernelTX:         cfg.KTLS != nil && cfg.KTLS.KernelTX,
		KernelRX:         cfg.KTLS != nil && cfg.KTLS.KernelRX,
		Certificates:     []eTLS.Certificate{eCert},
		CurvePreferences: []eTLS.CurveID{},
		MinVersion:       eTLS.VersionTLS13,
	}

	// QUIC-based TLS config (DoQ, DoH3) — KTLS does not apply.
	baseQUICConfig := &stdtls.Config{
		Certificates:     []stdtls.Certificate{sCert},
		CurvePreferences: []stdtls.CurveID{},
		MinVersion:       stdtls.VersionTLS13,
		VerifyConnection: func(cs stdtls.ConnectionState) error {
			zdnsutil.LogHandshake(&zdnsutil.HandshakeInfo{
				Role:       "TLS",
				Direction:  "QUIC handshake from",
				RemoteAddr: "client",
				Version:    cs.Version,
				Cipher:     stdtls.CipherSuiteName(cs.CipherSuite),
				Group:      cs.CurveID.String(),
				Resumed:    cs.DidResume,
			})
			return nil
		},
	}

	// tlsConfig is the default per-connection TLS config for DoT/DoH.
	// Each listener sets its own GetConfigForClient via getConfigForClient()
	// so that NextProtos is scoped to the correct ALPN protocol (dot vs h2).
	tlsConfig := baseConfig.Clone()

	ctx, cancel := context.WithCancelCause(context.Background())
	// The derived context is deliberately unused: goroutines derive from
	// s.ctx (cancelled with an error cause on Shutdown), and errgroup's
	// first-error cancellation would cancel the whole group on any single
	// handler error — the per-connection ctxs already handle that.
	serverGroup, _ := errgroup.WithContext(ctx)
	serverGroup.SetLimit(config.DefaultServerGoroutineLimit)

	s := &Server{
		cfg:           cfg,
		handler:       dnsHandler,
		tlsConfig:     tlsConfig,
		baseTLSConfig: baseConfig,
		quicTLSConfig: baseQUICConfig,
		stdCert:       sCert,
		ctx:           ctx,
		cancel:        cancel,
		serverGroup:   serverGroup,
		quicConnSem:   make(chan struct{}, config.DefaultServerGoroutineLimit/2),
		dotConns:      make(map[net.Conn]struct{}),
	}

	// Pre-build the eHTTP handler so the TLCP server can reuse it for
	// shared-port HTTPS+HTTPoverTLCP demux (server.go constructs the
	// demux and passes this handler to the TLS side).
	s.dohHandler = eHTTP.HandlerFunc(func(w eHTTP.ResponseWriter, r *eHTTP.Request) {
		s.ServeHTTP(&dohResponseWriter{w}, eHTTP.FromRequest(r))
	})

	s.displayCertificateInfo(&eCert)

	return s, nil
}

// QUICTLSConfig returns the TLS config for QUIC-based protocols (DoQ, DoH3).
// KTLS does not apply to QUIC, so this uses the standard crypto/tls.
func (s *Server) QUICTLSConfig() *stdtls.Config {
	return s.quicTLSConfig
}

// Start launches all secure DNS protocol listeners (DoT, DoQ, DoH, DoH3) and
// blocks until all servers have exited or an error occurs.  Each protocol is
// independently controlled by its port in Config.
func (s *Server) Start() error {
	errChan := make(chan error, 1)

	g, ctx := errgroup.WithContext(s.ctx)

	if s.cfg.HTTPSPort != "" && !s.cfg.SkipHTTPS {
		g.Go(func() error {
			defer zdnsutil.HandlePanic("DoH server")
			if err := s.startDOHServer(s.cfg.HTTPSPort); err != nil {
				return fmt.Errorf("DoH startup: %w", err)
			}
			<-ctx.Done()
			return nil
		})
	}

	if s.cfg.HTTP3Port != "" {
		g.Go(func() error {
			defer zdnsutil.HandlePanic("DoH3 server")
			if err := s.startDOH3Server(s.cfg.HTTP3Port); err != nil {
				return fmt.Errorf("DoH3 startup: %w", err)
			}
			<-ctx.Done()
			return nil
		})
	}

	if s.cfg.TLSPort != "" && !s.cfg.SkipDOT {
		g.Go(func() error {
			defer zdnsutil.HandlePanic("DoT server")
			if err := s.startDOTServer(); err != nil {
				return fmt.Errorf("DoT startup: %w", err)
			}
			<-ctx.Done()
			return nil
		})
	}

	if s.cfg.QUICPort != "" && !s.cfg.SkipDOQ {
		g.Go(func() error {
			defer zdnsutil.HandlePanic("DoQ server")
			if err := s.startDOQServer(); err != nil {
				return fmt.Errorf("DoQ startup: %w", err)
			}
			<-ctx.Done()
			return nil
		})
	}

	if s.cfg.DTLSPort != "" && !s.cfg.SkipDTLS {
		g.Go(func() error {
			defer zdnsutil.HandlePanic("DTLS server")
			if err := s.startDTLSServer(); err != nil {
				return fmt.Errorf("DTLS startup: %w", err)
			}
			<-ctx.Done()
			return nil
		})
	}

	go func() {
		defer zdnsutil.HandlePanic("TLS server coordinator")
		if err := g.Wait(); err != nil {
			select {
			case errChan <- err:
			default:
			}
		}
		close(errChan)
	}()

	for err := range errChan {
		if err != nil {
			// Only the first protocol startup error matters — it triggers
			// cancellation of all other listeners that may have already
			// started accepting connections, preventing partial startup.
			s.cancel(fmt.Errorf("tls startup failed: %w", err))
			// Close the listeners bound so far: their accept loops do not
			// observe ctx, so without this the coordinator's g.Wait() never
			// returns and Start (and the whole process) hangs on a partial
			// startup failure.
			s.closeListeners()
			return err
		}
	}

	return nil
}

// closeListeners closes all bound listeners and UDP sockets. Used by the
// startup-error path in Start to unblock accept loops that do not observe
// context cancellation.
func (s *Server) closeListeners() {
	s.listenerMu.Lock()
	defer s.listenerMu.Unlock()
	for _, l := range s.dotListeners {
		if l != nil {
			_ = l.Close()
		}
	}
	for _, l := range s.doqListeners {
		if l != nil {
			_ = l.Close()
		}
	}
	for _, c := range s.doqConns {
		if c != nil {
			_ = c.Close()
		}
	}
	for _, l := range s.httpsListeners {
		if l != nil {
			_ = l.Close()
		}
	}
	for _, l := range s.h3Listeners {
		if l != nil {
			_ = l.Close()
		}
	}
	for _, c := range s.h3Conns {
		if c != nil {
			_ = c.Close()
		}
	}
	for _, l := range s.dtlsListeners {
		if l != nil {
			_ = l.Close()
		}
	}
}

// Shutdown gracefully stops all secure DNS listeners and waits for server
// goroutines to finish.
func (s *Server) Shutdown() error {
	log.Infof("TLS: Shutting down secure DNS server")

	s.cancel(errors.New("tls server shutdown"))

	// Snapshot the listener/conn references under listenerMu: Start's
	// protocol goroutines append to these slices under the same lock
	// (tls.go:41, https.go:52, quic.go:56, http3.go:38, dtls.go:60), and the
	// signal handler is armed before Start, so a signal arriving during
	// listener startup runs Shutdown concurrently with those appends —
	// iterating without the lock is a data race on the slice headers.
	// The close calls themselves run outside the lock: h3Server/dohServers
	// Shutdown block for up to DefaultShutdownTimeout and must not hold it.
	s.listenerMu.Lock()
	dotListeners := append([]net.Listener(nil), s.dotListeners...)
	doqListeners := append([]*quic.EarlyListener(nil), s.doqListeners...)
	doqConns := append([]*net.UDPConn(nil), s.doqConns...)
	doqTransports := append([]*quic.Transport(nil), s.doqTransports...)
	dohServers := append([]*eHTTP.Server(nil), s.dohServers...)
	httpsListeners := append([]net.Listener(nil), s.httpsListeners...)
	h3Listeners := append([]*quic.EarlyListener(nil), s.h3Listeners...)
	h3Transports := append([]*quic.Transport(nil), s.h3Transports...)
	h3Conns := append([]*net.UDPConn(nil), s.h3Conns...)
	dtlsListeners := append([]net.Listener(nil), s.dtlsListeners...)
	h3Server := s.h3Server
	s.listenerMu.Unlock()

	for _, l := range dotListeners {
		if l != nil {
			zdnsutil.CloseWithLog(l, "DoT listener", "TLS")
		}
	}
	// Wake active DoT connections: their read loops block in io.ReadFull
	// with a 60s idle deadline refreshed only on success, so serverGroup.Wait
	// below would otherwise stall up to 60s per connection. A zero deadline
	// makes every blocked Read return a timeout immediately (M-3-5).
	s.listenerMu.Lock()
	for conn := range s.dotConns {
		_ = conn.SetReadDeadline(time.Unix(1, 0))
	}
	s.listenerMu.Unlock()
	for _, l := range doqListeners {
		if l != nil {
			zdnsutil.CloseWithLog(l, "DoQ listener", "TLS")
		}
	}
	for _, c := range doqConns {
		if c != nil {
			zdnsutil.CloseWithLog(c, "DoQ socket", "TLS")
		}
	}
	for _, t := range doqTransports {
		if t != nil {
			_ = t.Close()
		}
	}
	if h3Server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), config.DefaultShutdownTimeout)
		defer cancel()
		_ = h3Server.Shutdown(ctx)
	}
	for _, srv := range dohServers {
		if srv != nil {
			ctx, cancel := context.WithTimeout(context.Background(), config.DefaultShutdownTimeout)
			_ = srv.Shutdown(ctx)
			cancel()
		}
	}
	for _, l := range httpsListeners {
		if l != nil {
			zdnsutil.CloseWithLog(l, "HTTPS listener", "TLS")
		}
	}
	for _, l := range h3Listeners {
		if l != nil {
			zdnsutil.CloseWithLog(l, "HTTP/3 listener", "TLS")
		}
	}
	for _, t := range h3Transports {
		if t != nil {
			_ = t.Close()
		}
	}
	for _, c := range h3Conns {
		if c != nil {
			zdnsutil.CloseWithLog(c, "DoH3 socket", "TLS")
		}
	}
	for _, l := range dtlsListeners {
		if l != nil {
			zdnsutil.CloseWithLog(l, "DTLS listener", "TLS")
		}
	}

	if err := s.serverGroup.Wait(); err != nil {
		log.Errorf("TLS: Server goroutines finished with error: %v", err)
	}

	log.Infof("TLS: Secure DNS server shut down")
	return nil
}

// DOHHandler returns the eHTTP.Handler used for DOH requests.
// This is consumed by the TLCP server's shared-port demux to serve
// HTTPS connections on the same TCP port as HTTPoverTLCP.
func (s *Server) DOHHandler() eHTTP.Handler {
	return s.dohHandler
}

// ETLSConfigForDOH returns a cloned eTLS.Config suitable for a shared-port
// DOH demux: NextProtos is set to ["h2", "http/1.1"] and per-connection
// handshake logging is wired via GetConfigForClient.
func (s *Server) ETLSConfigForDOH() *eTLS.Config {
	cfg := s.baseTLSConfig.Clone()
	cfg.NextProtos = []string{"h2", "http/1.1"}
	cfg.GetConfigForClient = s.getConfigForClient(cfg.NextProtos)
	return cfg
}

// HandleDOTFromListener serves DoT connections from an external listener.
// Used by the TLCP server for shared TCP port (TLS DoT + TLCP DoT on 853).
// The caller provides a listener whose connections are already wrapped with
// eTLS (e.g. via eTLS.NewListener wrapping a demux queue).
func (s *Server) HandleDOTFromListener(listener net.Listener) error {
	s.handleDOTConnections(listener)
	return nil
}

// HandleDOQFromPacketConn serves DoQ connections from an external PacketConn.
// Used by the TLCP server for shared UDP port (QUIC DoQ + DTLS + DTLCP on 853).
// The caller provides a net.PacketConn fed by the dispatch loop.
func (s *Server) HandleDOQFromPacketConn(pc net.PacketConn) error {
	addrCache := lrumap.New[string, time.Time](config.DefaultQUICAddrCacheSize)

	transport := &quic.Transport{
		Conn:                pc,
		VerifySourceAddress: makeAddrValidator(addrCache),
	}
	s.listenerMu.Lock()
	s.doqTransports = append(s.doqTransports, transport)
	s.listenerMu.Unlock()

	quicTLSConfig := s.QUICTLSConfig().Clone()
	quicTLSConfig.NextProtos = config.NextProtoDOQ

	quicConfig := &quic.Config{
		MaxIdleTimeout:        config.DefaultQUICServerIdleTimeout,
		MaxIncomingStreams:    config.DefaultMaxIncomingStreams,
		MaxIncomingUniStreams: config.DefaultMaxIncomingStreams,
		Allow0RTT:             true,
		EnableDatagrams:       true,
		KeepAlivePeriod:       config.DefaultQUICKeepAlive,
	}

	listener, err := transport.ListenEarly(quicTLSConfig, quicConfig)
	if err != nil {
		return err
	}

	s.listenerMu.Lock()
	s.doqListeners = append(s.doqListeners, listener)
	s.listenerMu.Unlock()

	s.handleDOQConnections(listener)
	return nil
}

// HandleDTLSFromPacketListener serves DTLS connections from an external
// PacketListener.  Used by the TLCP server for shared UDP port (DTLS +
// DTLCP on 853).  The caller provides a dtlsnet.PacketListener whose
// per-client PacketConns deliver demuxed DTLS datagrams.
func (s *Server) HandleDTLSFromPacketListener(pl dtlsnet.PacketListener) error {
	listener, err := dtls.NewListenerWithOptions(pl,
		dtls.WithMinVersion(protocol.Version1_3),
		dtls.WithMaxVersion(protocol.Version1_3),
		dtls.WithCertificates(s.stdCert),
		dtls.WithSessionStore(lrumap.NewDTLSSessionStore(config.DefaultDTLSSessionCacheSize)),
		dtls.WithVerifyConnection(func(state *dtls.State) error {
			zdnsutil.LogHandshake(&zdnsutil.HandshakeInfo{
				Role:       "TLS",
				Direction:  "DTLS handshake from",
				RemoteAddr: "client",
				Cipher:     dtls.CipherSuiteName(state.CipherSuiteID),
			})
			return nil
		}),
	)
	if err != nil {
		return err
	}

	s.listenerMu.Lock()
	s.dtlsListeners = append(s.dtlsListeners, listener)
	s.listenerMu.Unlock()

	s.handleDTLSConnections(listener)
	return nil
}

// getConfigForClient returns a GetConfigForClient callback that clones the
// server's base TLS config, scopes NextProtos to the given listener-specific
// protocols, and logs the negotiated TLS parameters once per handshake.
func (s *Server) getConfigForClient(nextProtos []string) func(*eTLS.ClientHelloInfo) (*eTLS.Config, error) {
	return func(info *eTLS.ClientHelloInfo) (*eTLS.Config, error) {
		remoteAddr := info.Conn.RemoteAddr().String()
		sni := info.ServerName
		if sni == "" {
			sni = "(empty)"
		}
		log.Debugf("TLS: ClientHello from %s, SNI=%s, supported curves=%d", remoteAddr, sni, len(info.SupportedCurves))
		cfg := s.baseTLSConfig.Clone()
		cfg.NextProtos = nextProtos
		cfg.VerifyConnection = func(cs eTLS.ConnectionState) error {
			zdnsutil.LogHandshake(&zdnsutil.HandshakeInfo{
				Role:       "TLS",
				Direction:  "handshake from",
				RemoteAddr: remoteAddr,
				Version:    cs.Version,
				Cipher:     eTLS.CipherSuiteName(cs.CipherSuite),
				Group:      cs.CurveID.String(),
				Resumed:    cs.DidResume,
			})
			return nil
		}
		return cfg, nil
	}
}

func (s *Server) displayCertificateInfo(cert *eTLS.Certificate) {
	if len(cert.Certificate) == 0 {
		log.Errorf("TLS: No certificate found")
		return
	}

	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		log.Errorf("TLS: Failed to parse certificate: %v", err)
		return
	}

	log.Infof("TLS: Certificate: Subject: %s | Issuer: %s | Valid: %s -> %s | Algorithm: %s",
		x509Cert.Subject.CommonName,
		x509Cert.Issuer.String(),
		x509Cert.NotBefore.Format(time.DateOnly),
		x509Cert.NotAfter.Format(time.DateOnly),
		x509Cert.SignatureAlgorithm.String())

	daysUntilExpiry := int(time.Until(x509Cert.NotAfter).Hours() / 24)
	if daysUntilExpiry < 0 {
		log.Warnf("TLS: Certificate has EXPIRED for %d days!", -daysUntilExpiry)
	} else if daysUntilExpiry <= config.DefaultCertExpiryWarnDays {
		log.Warnf("TLS: Certificate expires in %d days!", daysUntilExpiry)
	}
}
