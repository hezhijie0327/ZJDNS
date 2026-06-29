// Package tls provides TLS-based secure DNS server implementation supporting DoT,
// DoQ, DoH, and DoH3 protocols.
package tls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	stdtls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	eTLS "gitlab.com/go-extension/tls"
	"math/big"
	"net"
	"strings"
	"time"

	"zjdns/internal/perip"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
	"golang.org/x/sync/errgroup"

	"zjdns/config"
	"zjdns/internal/dnsutil"
	"zjdns/internal/log"
)

const (
	// TLSConnBufferSize is the buffer size for TLS connection readers.
	TLSConnBufferSize = 4096
)

// Config holds the configuration for the TLS server including ports,
// certificate paths, and endpoint settings.
type Config struct {
	Port          string
	HTTPSPort     string
	HTTPSEndpoint string
	SelfSigned    bool
	CertFile      string
	KeyFile       string
	Domain        string
}

// DNSHandler is the interface for processing incoming DNS queries.
type DNSHandler interface {
	ServeDNS(req *dns.Msg, clientIP net.IP, isSecure bool, protocol string) *dns.Msg
}

// Server manages TLS-based secure DNS protocol listeners and their lifecycle.
type Server struct {
	cfg           Config
	handler       DNSHandler
	tlsConfig     *eTLS.Config   // TCP-based TLS (DoT, DoH) with KTLS
	baseTLSConfig *eTLS.Config   // base config for per-listener GetConfigForClient clones
	quicTLSConfig *stdtls.Config // QUIC-based protocols (DoQ, DoH3)
	ctx           context.Context
	cancel        context.CancelCauseFunc
	serverGroup   *errgroup.Group
	serverCtx     context.Context
	dotListener   net.Listener
	doqConn       *net.UDPConn
	doqListener   *quic.EarlyListener
	doqTransport  *quic.Transport
	dohServer     *http2.Server
	h3Server      *http3.Server
	httpsListener net.Listener
	h3Listener    *quic.EarlyListener
	doqLimiter    *perip.Limiter // per-IP DoQ connection limit
	dotLimiter    *perip.Limiter // per-IP DoT connection limit
	dohLimiter    *perip.Limiter // per-IP DoH connection limit
	doh3Limiter   *perip.Limiter // per-IP DoH3 connection limit
}

func generateSelfSignedCert(domain string) (eTLS.Certificate, error) {
	caPrivKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return eTLS.Certificate{}, fmt.Errorf("generate CA EC key: %w", err)
	}

	serverPrivKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
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
		DNSNames:    []string{domain},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(config.DefaultServerCertValidity),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
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

// isTemporaryError returns true if the error is a temporary network error or
// contains timeout or temporary in its message.
func isTemporaryError(err error) bool {
	if err == nil {
		return false
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return true
	}
	return strings.Contains(err.Error(), "timeout") || strings.Contains(err.Error(), "temporary")
}

// secureClientIP extracts the client IP address from a connection, supporting
// both TCP and UDP remote addresses.
func secureClientIP(conn any) net.IP {
	switch c := conn.(type) {
	case interface{ RemoteAddr() net.Addr }:
		if addr, ok := c.RemoteAddr().(*net.TCPAddr); ok {
			return addr.IP
		}
		if addr, ok := c.RemoteAddr().(*net.UDPAddr); ok {
			return addr.IP
		}
	}
	return nil
}

// New creates a new TLS Server with the given DNS handler and configuration,
// loading or generating the TLS certificate as specified.
func New(handler DNSHandler, cfg Config, operationTimeout time.Duration) (*Server, error) {
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
		log.Infof("TLS: Using certificate from files: %s, %s", cfg.CertFile, cfg.KeyFile)
	}

	// TCP-based TLS config (DoT, DoH) with kernel TLS offload.
	baseConfig := &eTLS.Config{
		KernelTX:         true,
		KernelRX:         true,
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
		doqLimiter:    &perip.Limiter{},
		dotLimiter:    &perip.Limiter{},
		dohLimiter:    &perip.Limiter{},
		doh3Limiter:   &perip.Limiter{},
	}

	s.displayCertificateInfo(eCert)

	return s, nil
}

// QUICTLSConfig returns the TLS config for QUIC-based protocols (DoQ, DoH3).
// KTLS does not apply to QUIC, so this uses the standard crypto/tls.
func (s *Server) QUICTLSConfig() *stdtls.Config {
	return s.quicTLSConfig
}

// getConfigForClient returns a GetConfigForClient callback that clones the
// server's base TLS config, scopes NextProtos to the given listener-specific
// protocols, and logs the negotiated TLS parameters once per handshake.
func (s *Server) getConfigForClient(nextProtos []string) func(*eTLS.ClientHelloInfo) (*eTLS.Config, error) {
	return func(info *eTLS.ClientHelloInfo) (*eTLS.Config, error) {
		remoteAddr := info.Conn.RemoteAddr().String()
		cfg := s.baseTLSConfig.Clone()
		cfg.NextProtos = nextProtos
		cfg.VerifyConnection = func(cs eTLS.ConnectionState) error {
			dnsutil.LogTLSConnectionState("TLS", "handshake from", remoteAddr, cs.Version, cs.CipherSuite, cs.CurveID)
			return nil
		}
		return cfg, nil
	}
}

func (s *Server) displayCertificateInfo(cert eTLS.Certificate) {
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
		x509Cert.NotBefore.Format("2006-01-02"),
		x509Cert.NotAfter.Format("2006-01-02"),
		x509Cert.SignatureAlgorithm.String())

	daysUntilExpiry := int(time.Until(x509Cert.NotAfter).Hours() / 24)
	if daysUntilExpiry < 0 {
		log.Errorf("TLS: Certificate has EXPIRED for %d days!", -daysUntilExpiry)
	} else if daysUntilExpiry <= config.DefaultCertExpiryWarnDays {
		log.Warnf("TLS: Certificate expires in %d days!", daysUntilExpiry)
	}
}

// Start launches all secure DNS protocol listeners (DoT, DoQ, DoH, DoH3) and
// blocks until all servers have exited or an error occurs.
func (s *Server) Start(httpsPort string) error {
	errChan := make(chan error, 1)

	g, ctx := errgroup.WithContext(s.ctx)

	if httpsPort != "" {
		g.Go(func() error {
			defer dnsutil.HandlePanic("DoH server")
			if err := s.startDOHServer(httpsPort); err != nil {
				return fmt.Errorf("DoH startup: %w", err)
			}
			<-ctx.Done()
			return nil
		})

		g.Go(func() error {
			defer dnsutil.HandlePanic("DoH3 server")
			if err := s.startDoH3Server(httpsPort); err != nil {
				return fmt.Errorf("DoH3 startup: %w", err)
			}
			<-ctx.Done()
			return nil
		})
	}

	g.Go(func() error {
		defer dnsutil.HandlePanic("DoT server")
		if err := s.startDOTServer(); err != nil {
			return fmt.Errorf("DoT startup: %w", err)
		}
		<-ctx.Done()
		return nil
	})

	g.Go(func() error {
		defer dnsutil.HandlePanic("DoQ server")
		if err := s.startDOQServer(); err != nil {
			return fmt.Errorf("DoQ startup: %w", err)
		}
		<-ctx.Done()
		return nil
	})

	// Periodic sweep of per-IP connection limiters to prevent unbounded
	// growth from unique client IPs over long-running deployments.
	g.Go(func() error {
		defer dnsutil.HandlePanic("perip sweep")
		ticker := time.NewTicker(config.DefaultSweepInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				s.doqLimiter.Sweep()
				s.dotLimiter.Sweep()
				s.dohLimiter.Sweep()
				s.doh3Limiter.Sweep()
			case <-ctx.Done():
				return nil
			}
		}
	})

	go func() {
		defer dnsutil.HandlePanic("TLS server coordinator")
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

	if s.dotListener != nil {
		dnsutil.CloseWithLog(s.dotListener, "DoT listener")
	}
	if s.doqListener != nil {
		dnsutil.CloseWithLog(s.doqListener, "DoQ listener")
	}
	if s.h3Server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), config.DefaultShutdownTimeout)
		defer cancel()
		_ = s.h3Server.Shutdown(ctx)
	}
	if s.httpsListener != nil {
		dnsutil.CloseWithLog(s.httpsListener, "HTTPS listener")
	}
	if s.h3Listener != nil {
		dnsutil.CloseWithLog(s.h3Listener, "HTTP/3 listener")
	}

	if err := s.serverGroup.Wait(); err != nil {
		log.Errorf("TLS: Server goroutines finished with error: %v", err)
	}

	log.Infof("TLS: Secure DNS server shut down")
	return nil
}
