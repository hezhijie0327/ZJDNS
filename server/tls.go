// Package main implements ZJDNS - High Performance DNS Server
package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/sync/errgroup"

	"zjdns/config"
	"zjdns/internal/dnsutil"
	"zjdns/internal/log"
)

const (
	TLSConnBufferSize = 4096 // Buffer size for TLS connections (matches pool.TCPBufferSize)

	DoHMaxRequestSize = 8192 // Maximum request size for DoH (8 KB)

	MaxIncomingStreams = 256 // Per-connection QUIC stream limit (RFC 7766 DoS mitigation)

	QUICCodeNoError       quic.ApplicationErrorCode = 0
	QUICCodeInternalError quic.ApplicationErrorCode = 1
	QUICCodeProtocolError quic.ApplicationErrorCode = 2
)

var (
	NextProtoDOT  = []string{"dot"}
	NextProtoDoQ  = []string{"doq"}
	NextProtoDoH3 = []string{"h3"}
	NextProtoDoH  = []string{"h2"}
)

// TLSManager manages all TLS-related functionality, including certificate management and secure server handling for DoT, DoQ, DoH, and DoH3. It encapsulates the logic for starting and stopping secure servers, handling incoming connections, and processing DNS queries over secure protocols.
type TLSManager struct {
	server        *DNSServer
	tlsConfig     *tls.Config
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
}

// generateSelfSignedCert generates a self-signed ECDSA certificate for the given domain.
// It creates a CA certificate and uses it to sign a server certificate.
func generateSelfSignedCert(domain string) (tls.Certificate, error) {
	// Generate CA private key using ECDSA P-384
	caPrivKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate CA EC key: %w", err)
	}

	// Generate server private key using ECDSA P-384
	serverPrivKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate server EC key: %w", err)
	}

	// Generate random serial numbers
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	caSerialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate CA serial number: %w", err)
	}

	serverSerialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate server serial number: %w", err)
	}

	// Create CA certificate template
	caTemplate := x509.Certificate{
		SerialNumber: caSerialNumber,
		Subject: pkix.Name{
			CommonName:   "ZJDNS ECC Domain Secure Site CA",
			Organization: []string{"ZJDNS"},
			Country:      []string{"CN"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // 365 days validity for self-signed CA
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	// Create server certificate template
	serverTemplate := x509.Certificate{
		SerialNumber: serverSerialNumber,
		Subject: pkix.Name{
			CommonName: domain,
		},
		DNSNames:    []string{domain},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour), // 365 days validity for self-signed cert
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	// Create and sign CA certificate
	caCertDER, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create CA certificate: %w", err)
	}

	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("parse CA certificate: %w", err)
	}

	// Create and sign server certificate using CA
	certDER, err := x509.CreateCertificate(rand.Reader, &serverTemplate, caCert, &serverPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create server certificate: %w", err)
	}

	// Create tls.Certificate
	cert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  serverPrivKey,
	}

	return cert, nil
}

// IsTemporaryError checks if an error is temporary/recoverable.
func IsTemporaryError(err error) bool {
	if err == nil {
		return false
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return true
	}
	return strings.Contains(err.Error(), "timeout") || strings.Contains(err.Error(), "temporary")
}

// SecureClientIP extracts client IP from secure connection.
func SecureClientIP(conn any) net.IP {
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

// NewTLSManager creates a new TLSManager with the given server and configuration.
// It loads or generates TLS certificates and initializes the TLS configuration.
func NewTLSManager(server *DNSServer, config *config.ServerConfig) (*TLSManager, error) {
	var cert tls.Certificate
	var err error

	// Load or generate certificate
	if config.Server.TLS.SelfSigned {
		cert, err = generateSelfSignedCert(config.Server.Features.DDR.Domain)
		if err != nil {
			return nil, fmt.Errorf("generate self-signed certificate: %w", err)
		}
		log.Infof("TLS: Using self-signed certificate for domain: %s", config.Server.Features.DDR.Domain)
	} else {
		cert, err = tls.LoadX509KeyPair(config.Server.TLS.CertFile, config.Server.TLS.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("load certificate: %w", err)
		}
		log.Infof("TLS: Using certificate from files: %s, %s", config.Server.TLS.CertFile, config.Server.TLS.KeyFile)
	}

	// Create TLS configuration
	tlsConfig := &tls.Config{
		Certificates:     []tls.Certificate{cert},
		CurvePreferences: []tls.CurveID{}, // empty = use Go defaults (X25519, P-256, P-384, P-521)
		MinVersion:       tls.VersionTLS13,
	}

	// Create context and error group for server management
	ctx, cancel := context.WithCancelCause(context.Background())
	serverGroup, serverCtx := errgroup.WithContext(ctx)
	serverGroup.SetLimit(1024) // Cap concurrent DoT/DoQ connection handlers

	tm := &TLSManager{
		server:      server,
		tlsConfig:   tlsConfig,
		ctx:         ctx,
		cancel:      cancel,
		serverGroup: serverGroup,
		serverCtx:   serverCtx,
	}

	// Display certificate information
	tm.displayCertificateInfo(cert)

	return tm, nil
}

// displayCertificateInfo logs information about the TLS certificate.
func (tm *TLSManager) displayCertificateInfo(cert tls.Certificate) {
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

	// Check and warn about certificate expiry
	daysUntilExpiry := int(time.Until(x509Cert.NotAfter).Hours() / 24)
	if daysUntilExpiry < 0 {
		log.Errorf("TLS: Certificate has EXPIRED for %d days!", -daysUntilExpiry)
	} else if daysUntilExpiry <= 30 {
		log.Warnf("TLS: Certificate expires in %d days!", daysUntilExpiry)
	}
}

// Start starts all secure DNS servers (DoT, DoQ, DoH, DoH3).
// It launches each server in a separate goroutine and coordinates their lifecycle.
func (tm *TLSManager) Start(httpsPort string) error {
	errChan := make(chan error, 1)

	g, ctx := errgroup.WithContext(tm.ctx)

	// Start DoH server if HTTPS port is configured
	if httpsPort != "" {
		g.Go(func() error {
			defer dnsutil.HandlePanic("DoH server")
			if err := tm.startDOHServer(httpsPort); err != nil {
				return fmt.Errorf("DoH startup: %w", err)
			}
			<-ctx.Done()
			return nil
		})

		// Start DoH3 server
		g.Go(func() error {
			defer dnsutil.HandlePanic("DoH3 server")
			if err := tm.startDoH3Server(httpsPort); err != nil {
				return fmt.Errorf("DoH3 startup: %w", err)
			}
			<-ctx.Done()
			return nil
		})
	}

	// Start DoT server
	g.Go(func() error {
		defer dnsutil.HandlePanic("DoT server")
		if err := tm.startDOTServer(); err != nil {
			return fmt.Errorf("DoT startup: %w", err)
		}
		<-ctx.Done()
		return nil
	})

	// Start DoQ server
	g.Go(func() error {
		defer dnsutil.HandlePanic("DoQ server")
		if err := tm.startDOQServer(); err != nil {
			return fmt.Errorf("DoQ startup: %w", err)
		}
		<-ctx.Done()
		return nil
	})

	// Coordinate server goroutines
	go func() {
		defer dnsutil.HandlePanic("TLS manager coordinator")
		if err := g.Wait(); err != nil {
			select {
			case errChan <- err:
			default:
			}
		}
		close(errChan)
	}()

	// Wait for errors
	for err := range errChan {
		if err != nil {
			return err
		}
	}

	return nil
}

func (tm *TLSManager) shutdown() error {
	log.Infof("TLS: Shutting down secure DNS server")

	// Cancel context to signal all goroutines
	tm.cancel(errors.New("tls manager shutdown"))

	// Close DoT listener
	if tm.dotListener != nil {
		dnsutil.CloseWithLog(tm.dotListener, "DoT listener")
	}

	// Close DoQ listener (also closes the underlying UDP conn).
	if tm.doqListener != nil {
		dnsutil.CloseWithLog(tm.doqListener, "DoQ listener")
	}

	// Shutdown HTTPS server
	if tm.httpsServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), DefaultTimeout)
		defer cancel()
		_ = tm.httpsServer.Shutdown(ctx)
	}

	// Shutdown HTTP/3 server
	if tm.h3Server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), DefaultTimeout)
		defer cancel()
		_ = tm.h3Server.Shutdown(ctx)
	}

	// Close listeners
	if tm.httpsListener != nil {
		dnsutil.CloseWithLog(tm.httpsListener, "HTTPS listener")
	}
	if tm.h3Listener != nil {
		dnsutil.CloseWithLog(tm.h3Listener, "HTTP/3 listener")
	}

	// Wait for all server goroutines to finish
	if err := tm.serverGroup.Wait(); err != nil {
		log.Errorf("TLS: Server goroutines finished with error: %v", err)
	}

	log.Infof("TLS: Secure DNS server shut down")
	return nil
}
