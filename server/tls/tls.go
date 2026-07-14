// Package tls provides TLS-based secure DNS server implementation supporting DoT,
// DoQ, DoH, and DoH3 protocols.
package tls

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	stdtls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"
	"zjdns/config"
	zdnsutil "zjdns/internal/dnsutil"
	"zjdns/internal/log"

	"codeberg.org/miekg/dns"
	"github.com/cloudflare/circl/ecc/p384"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	eHTTP "gitlab.com/go-extension/http"
	eTLS "gitlab.com/go-extension/tls"
	"golang.org/x/sync/errgroup"
)

// TCPKeepAliveListener wraps a net.Listener to enable TCP keep-alive on every
// accepted connection. This ensures both server-side and client-side keep-alive
// are active, preventing unilateral connection teardown by intermediate NAT or
// firewall state timeouts.
type TCPKeepAliveListener struct {
	net.Listener
}

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
	HTTPSPort     string // DoH
	HTTP3Port     string // DoH3
	HTTPSEndpoint string
	HTTP3Endpoint string
	SelfSigned    bool
	CertFile      string
	KeyFile       string
	Domain        string
	KTLS          *KTLSSettings
}

// DNSHandler is the interface for processing incoming DNS queries.
type DNSHandler interface {
	ServeDNS(req *dns.Msg, clientIP net.IP, isSecure bool, protocol string) *dns.Msg
}

// Server manages TLS-based secure DNS protocol listeners and their lifecycle.
type Server struct {
	cfg            *Config
	handler        DNSHandler
	tlsConfig      *eTLS.Config   // TCP-based TLS (DoT, DoH) with KTLS
	baseTLSConfig  *eTLS.Config   // base config for per-listener GetConfigForClient clones
	quicTLSConfig  *stdtls.Config // QUIC-based protocols (DoQ, DoH3)
	ctx            context.Context
	cancel         context.CancelCauseFunc
	serverGroup    *errgroup.Group
	serverCtx      context.Context
	dotListeners   []net.Listener
	doqConns       []*net.UDPConn
	doqTransports  []*quic.Transport
	doqListeners   []*quic.EarlyListener
	doqValidator   *quicAddrValidator
	dohServers     []*eHTTP.Server
	h3Server       *http3.Server
	httpsListeners []net.Listener
	h3Conns        []*net.UDPConn
	h3Transports   []*quic.Transport
	h3Listeners    []*quic.EarlyListener
	h3Validator    *quicAddrValidator
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

func (k *TCPKeepAliveListener) Accept() (net.Conn, error) {
	conn, err := k.Listener.Accept()
	if err != nil {
		return nil, err
	}
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		_ = tcpConn.SetKeepAlive(true)
		_ = tcpConn.SetKeepAlivePeriod(config.DefaultTCPKeepAlivePeriod)
	}
	return conn, nil
}

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
func New(handler DNSHandler, cfg *Config, operationTimeout time.Duration) (*Server, error) {
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
	}

	// tlsConfig is the default per-connection TLS config for DoT/DoH.
	// Each listener sets its own GetConfigForClient via getConfigForClient()
	// so that NextProtos is scoped to the correct ALPN protocol (dot vs h2).
	tlsConfig := baseConfig.Clone()

	ctx, cancel := context.WithCancelCause(context.Background())
	serverGroup, serverCtx := errgroup.WithContext(ctx)
	serverGroup.SetLimit(config.DefaultServerGoroutineLimit)

	s := &Server{
		cfg:           cfg,
		handler:       handler,
		tlsConfig:     tlsConfig,
		baseTLSConfig: baseConfig,
		quicTLSConfig: baseQUICConfig,
		ctx:           ctx,
		cancel:        cancel,
		serverGroup:   serverGroup,
		serverCtx:     serverCtx,
	}

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

	if s.cfg.HTTPSPort != "" {
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

	if s.cfg.TLSPort != "" {
		g.Go(func() error {
			defer zdnsutil.HandlePanic("DoT server")
			if err := s.startDOTServer(); err != nil {
				return fmt.Errorf("DoT startup: %w", err)
			}
			<-ctx.Done()
			return nil
		})
	}

	if s.cfg.QUICPort != "" {
		g.Go(func() error {
			defer zdnsutil.HandlePanic("DoQ server")
			if err := s.startDOQServer(); err != nil {
				return fmt.Errorf("DoQ startup: %w", err)
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
			// Cancel server context to stop accept loops that may have
			// already started in other listeners before this one failed.
			s.cancel(fmt.Errorf("tls startup failed: %w", err))
			return err
		}
	}

	return nil
}

// Shutdown gracefully stops all secure DNS listeners and waits for server
// goroutines to finish.
func (s *Server) Shutdown() error {
	log.Infof("TLS: Shutting down secure DNS server")

	s.cancel(errors.New("tls server shutdown"))

	for _, l := range s.dotListeners {
		if l != nil {
			zdnsutil.CloseWithLog(l, "DoT listener", "TLS")
		}
	}
	for _, l := range s.doqListeners {
		if l != nil {
			zdnsutil.CloseWithLog(l, "DoQ listener", "TLS")
		}
	}
	for _, c := range s.doqConns {
		if c != nil {
			zdnsutil.CloseWithLog(c, "DoQ socket", "TLS")
		}
	}
	if s.doqValidator != nil {
		s.doqValidator.close()
	}
	if s.h3Server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), config.DefaultShutdownTimeout)
		defer cancel()
		_ = s.h3Server.Shutdown(ctx)
	}
	for _, srv := range s.dohServers {
		if srv != nil {
			ctx, cancel := context.WithTimeout(context.Background(), config.DefaultShutdownTimeout)
			_ = srv.Shutdown(ctx)
			cancel()
		}
	}
	for _, l := range s.httpsListeners {
		if l != nil {
			zdnsutil.CloseWithLog(l, "HTTPS listener", "TLS")
		}
	}
	for _, l := range s.h3Listeners {
		if l != nil {
			zdnsutil.CloseWithLog(l, "HTTP/3 listener", "TLS")
		}
	}
	for _, t := range s.h3Transports {
		if t != nil {
			_ = t.Close()
		}
	}
	for _, c := range s.h3Conns {
		if c != nil {
			zdnsutil.CloseWithLog(c, "DoH3 socket", "TLS")
		}
	}
	if s.h3Validator != nil {
		s.h3Validator.close()
	}

	if err := s.serverGroup.Wait(); err != nil {
		log.Errorf("TLS: Server goroutines finished with error: %v", err)
	}

	log.Infof("TLS: Secure DNS server shut down")
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
			zdnsutil.LogTLSConnectionState("TLS", "handshake from", remoteAddr, cs.Version, cs.CipherSuite, cs.CurveID)
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
		log.Errorf("TLS: Certificate has EXPIRED for %d days!", -daysUntilExpiry)
	} else if daysUntilExpiry <= config.DefaultCertExpiryWarnDays {
		log.Warnf("TLS: Certificate expires in %d days!", daysUntilExpiry)
	}
}

func generateSelfSignedCert(domain string) (eTLS.Certificate, error) {
	caPrivKey, err := ecdsa.GenerateKey(p384.P384(), rand.Reader)
	if err != nil {
		return eTLS.Certificate{}, fmt.Errorf("generate CA EC key: %w", err)
	}

	serverPrivKey, err := ecdsa.GenerateKey(p384.P384(), rand.Reader)
	if err != nil {
		return eTLS.Certificate{}, fmt.Errorf("generate server EC key: %w", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	caSerialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return eTLS.Certificate{}, fmt.Errorf("generate CA serial number: %w", err)
	}

	serverSerialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return eTLS.Certificate{}, fmt.Errorf("generate server serial number: %w", err)
	}

	caTemplate := x509.Certificate{
		SerialNumber: caSerialNumber,
		Subject: pkix.Name{
			CommonName:   "ZJDNS ECC Domain Secure Site CA",
			Organization: []string{"ZJDNS"},
			Country:      []string{"CN"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(config.DefaultCACertValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	serverTemplate := x509.Certificate{
		SerialNumber: serverSerialNumber,
		Subject: pkix.Name{
			CommonName: domain,
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(config.DefaultServerCertValidity),
		KeyUsage:    x509.KeyUsageDigitalSignature, // ECDSA — KeyEncipherment is RSA-only
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(domain); ip != nil {
		serverTemplate.IPAddresses = []net.IP{ip}
	} else {
		serverTemplate.DNSNames = []string{domain}
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return eTLS.Certificate{}, fmt.Errorf("create CA certificate: %w", err)
	}

	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return eTLS.Certificate{}, fmt.Errorf("parse CA certificate: %w", err)
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &serverTemplate, caCert, &serverPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return eTLS.Certificate{}, fmt.Errorf("create server certificate: %w", err)
	}

	cert := eTLS.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  serverPrivKey,
	}

	return cert, nil
}

// isTemporaryError returns true if the error is a temporary network error
// (net.Error with Timeout() true) or contains "timeout"/"temporary" in its
// message.
func isTemporaryError(err error) bool {
	if err == nil {
		return false
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	return strings.Contains(err.Error(), "timeout") || strings.Contains(err.Error(), "temporary")
}

// secureClientIP extracts the client IP address from a connection, supporting
// both TCP and UDP remote addresses.
func secureClientIP(conn any) net.IP {
	c, ok := conn.(interface{ RemoteAddr() net.Addr })
	if ok {
		if addr, ok := c.RemoteAddr().(*net.TCPAddr); ok {
			return addr.IP
		}
		if addr, ok := c.RemoteAddr().(*net.UDPAddr); ok {
			return addr.IP
		}
	}
	return nil
}
