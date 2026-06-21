// Package tls provides TLS-based secure DNS server implementation supporting DoT,
// DoQ, DoH, and DoH3 protocols.
package tls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	cryptotls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/sync/errgroup"

	"zjdns/config"
	"zjdns/internal/dnsutil"
	"zjdns/internal/log"
)

const (
	// TLSConnBufferSize is the buffer size for TLS connection readers.
	TLSConnBufferSize = 4096

	// DoHMaxRequestSize is the maximum allowed DoH request size in bytes.
	DoHMaxRequestSize = 8192

	// MaxIncomingStreams is the maximum number of concurrent incoming QUIC
	// streams per connection.
	MaxIncomingStreams = 256

	// QUICCodeNoError indicates a normal QUIC connection closure.
	QUICCodeNoError quic.ApplicationErrorCode = 0

	// QUICCodeInternalError indicates an internal server error in QUIC.
	QUICCodeInternalError quic.ApplicationErrorCode = 1

	// QUICCodeProtocolError indicates a protocol violation in QUIC.
	QUICCodeProtocolError quic.ApplicationErrorCode = 2
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
	tlsConfig     *cryptotls.Config
	ctx           context.Context
	cancel        context.CancelCauseFunc
	serverGroup   *errgroup.Group
	serverCtx     context.Context
	dotListener   net.Listener
	doqConn       *net.UDPConn
	doqListener   *quic.EarlyListener
	doqTransport  *quic.Transport
	httpsServer   *http.Server
	h3Server      *http3.Server
	httpsListener net.Listener
	h3Listener    *quic.EarlyListener
	doqIPCounts   sync.Map // IP string → *atomic.Int32, per-IP DoQ connection limit
}

func generateSelfSignedCert(domain string) (cryptotls.Certificate, error) {
	caPrivKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return cryptotls.Certificate{}, fmt.Errorf("generate CA EC key: %w", err)
	}

	serverPrivKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return cryptotls.Certificate{}, fmt.Errorf("generate server EC key: %w", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	caSerialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return cryptotls.Certificate{}, fmt.Errorf("generate CA serial number: %w", err)
	}

	serverSerialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return cryptotls.Certificate{}, fmt.Errorf("generate server serial number: %w", err)
	}

	caTemplate := x509.Certificate{
		SerialNumber: caSerialNumber,
		Subject: pkix.Name{
			CommonName:   "ZJDNS ECC Domain Secure Site CA",
			Organization: []string{"ZJDNS"},
			Country:      []string{"CN"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
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
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return cryptotls.Certificate{}, fmt.Errorf("create CA certificate: %w", err)
	}

	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return cryptotls.Certificate{}, fmt.Errorf("parse CA certificate: %w", err)
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &serverTemplate, caCert, &serverPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return cryptotls.Certificate{}, fmt.Errorf("create server certificate: %w", err)
	}

	cert := cryptotls.Certificate{
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
	var cert cryptotls.Certificate
	var err error

	if cfg.SelfSigned {
		cert, err = generateSelfSignedCert(cfg.Domain)
		if err != nil {
			return nil, fmt.Errorf("generate self-signed certificate: %w", err)
		}
		log.Infof("TLS: Using self-signed certificate for domain: %s", cfg.Domain)
	} else {
		cert, err = cryptotls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("load certificate: %w", err)
		}
		log.Infof("TLS: Using certificate from files: %s, %s", cfg.CertFile, cfg.KeyFile)
	}

	tlsConfig := &cryptotls.Config{
		Certificates:     []cryptotls.Certificate{cert},
		CurvePreferences: []cryptotls.CurveID{},
		MinVersion:       cryptotls.VersionTLS13,
	}

	ctx, cancel := context.WithCancelCause(context.Background())
	serverGroup, serverCtx := errgroup.WithContext(ctx)
	serverGroup.SetLimit(1024)

	s := &Server{
		cfg:         cfg,
		handler:     handler,
		tlsConfig:   tlsConfig,
		ctx:         ctx,
		cancel:      cancel,
		serverGroup: serverGroup,
		serverCtx:   serverCtx,
	}

	s.displayCertificateInfo(cert)

	return s, nil
}

// TLSConfig returns the underlying crypto/tls configuration used by the server.
func (s *Server) TLSConfig() *cryptotls.Config {
	return s.tlsConfig
}

func (s *Server) displayCertificateInfo(cert cryptotls.Certificate) {
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
	} else if daysUntilExpiry <= 30 {
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
	if s.httpsServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), config.IdleTimeout)
		defer cancel()
		_ = s.httpsServer.Shutdown(ctx)
	}
	if s.h3Server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), config.IdleTimeout)
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
