// Package tlcp provides a TLCP (国密 SSL, GB/T 38636-2020) server listener
// supporting DoT and DoH over TLCP.
package tlcp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"
	"zjdns/config"
	"zjdns/edns"
	zdnsutil "zjdns/internal/dnsutil"
	"zjdns/internal/log"

	"gitee.com/Trisia/gotlcp/dtlcp"
	"gitee.com/Trisia/gotlcp/tlcp"
	"github.com/emmansun/gmsm/smx509"
	"golang.org/x/sync/errgroup"
)

// Server manages TLCP-based secure DNS protocol listeners and their lifecycle.
type Server struct {
	dotPort        string
	dohPort        string
	dohEndpoint    string
	dtlcpPort      string
	handler        edns.DNSHandler
	tlcpConfig     *tlcp.Config
	dtlcpConfig    *dtlcp.Config
	ctx            context.Context
	cancel         context.CancelCauseFunc
	dotListeners   []net.Listener
	dohListeners   []net.Listener
	dohServers     []*http.Server
	dtlcpListeners []net.Listener
	serverGroup    *errgroup.Group
	serverCtx      context.Context
}

// New creates a TLCP Server, loading or generating SM2 certificate pairs.
// dotPort, dohPort, dohEndpoint, and dtlcpPort come from the protocol config section.
func New(certificateCfg *config.TLCPCertificate, dotPort, dohPort, dohEndpoint, dtlcpPort string) (*Server, error) {
	var signCert, encCert tlcp.Certificate
	var dtlcpSignCert, dtlcpEncCert dtlcp.Certificate
	var err error

	if certificateCfg.SelfSigned {
		signCert, encCert, dtlcpSignCert, dtlcpEncCert, err = generateSelfSignedSMCerts()
		if err != nil {
			return nil, fmt.Errorf("generate self-signed SM2 certificates: %w", err)
		}
		log.Infof("TLCP: Using self-signed SM2 certificates")
	} else {
		signCert, err = tlcp.LoadX509KeyPair(certificateCfg.SignCertFile, certificateCfg.SignKeyFile)
		if err != nil {
			return nil, fmt.Errorf("load tlcp sign certificate: %w", err)
		}
		encCert, err = tlcp.LoadX509KeyPair(certificateCfg.EncCertFile, certificateCfg.EncKeyFile)
		if err != nil {
			return nil, fmt.Errorf("load tlcp enc certificate: %w", err)
		}
		dtlcpSignCert, err = dtlcp.LoadX509KeyPair(certificateCfg.SignCertFile, certificateCfg.SignKeyFile)
		if err != nil {
			return nil, fmt.Errorf("load dtlcp sign certificate: %w", err)
		}
		dtlcpEncCert, err = dtlcp.LoadX509KeyPair(certificateCfg.EncCertFile, certificateCfg.EncKeyFile)
		if err != nil {
			return nil, fmt.Errorf("load dtlcp enc certificate: %w", err)
		}
		log.Debugf("TLCP: Using SM2 certificates from files")
	}

	tlcpConfig := &tlcp.Config{
		Certificates:     []tlcp.Certificate{signCert, encCert},
		CurvePreferences: []tlcp.CurveID{tlcp.CurveSM2},
		VerifyConnection: func(cs tlcp.ConnectionState) error {
			zdnsutil.LogHandshake(&zdnsutil.HandshakeInfo{
				Role:       "TLCP",
				Direction:  "handshake from",
				RemoteAddr: "client",
				Version:    cs.Version,
				Cipher:     tlcp.CipherSuiteName(cs.CipherSuite),
				Group:      "SM2",
				Resumed:    cs.DidResume,
				ALPN:       cs.NegotiatedProtocol,
			})
			return nil
		},
	}

	dtlcpConfig := &dtlcp.Config{
		Certificates:     []dtlcp.Certificate{dtlcpSignCert, dtlcpEncCert},
		CurvePreferences: []dtlcp.CurveID{dtlcp.CurveSM2},
		SessionCache:     dtlcp.NewLRUSessionCache(128),
		VerifyConnection: func(cs dtlcp.ConnectionState) error {
			zdnsutil.LogHandshake(&zdnsutil.HandshakeInfo{
				Role:       "TLCP",
				Direction:  "DTLCP handshake from",
				RemoteAddr: "client",
				Version:    cs.Version,
				Cipher:     dtlcp.CipherSuiteName(cs.CipherSuite),
				Group:      "SM2",
				Resumed:    cs.DidResume,
				ALPN:       cs.NegotiatedProtocol,
			})
			return nil
		},
	}

	ctx, cancel := context.WithCancelCause(context.Background())
	serverGroup, serverCtx := errgroup.WithContext(ctx)
	serverGroup.SetLimit(config.DefaultServerGoroutineLimit)

	s := &Server{
		dotPort:     dotPort,
		dohPort:     dohPort,
		dohEndpoint: dohEndpoint,
		dtlcpPort:   dtlcpPort,
		tlcpConfig:  tlcpConfig,
		dtlcpConfig: dtlcpConfig,
		ctx:         ctx,
		cancel:      cancel,
		serverGroup: serverGroup,
		serverCtx:   serverCtx,
	}

	displayCertificateInfo(&signCert)

	return s, nil
}

// displayCertificateInfo logs the SM2 signing certificate details.
func displayCertificateInfo(cert *tlcp.Certificate) {
	if len(cert.Certificate) == 0 {
		log.Errorf("TLCP: No certificate found")
		return
	}

	x509Cert, err := smx509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		log.Errorf("TLCP: Failed to parse certificate: %v", err)
		return
	}

	log.Infof("TLCP: Certificate: Subject: %s | Issuer: %s | Valid: %s -> %s | Algorithm: %s",
		x509Cert.Subject.CommonName,
		x509Cert.Issuer.String(),
		x509Cert.NotBefore.Format(time.DateOnly),
		x509Cert.NotAfter.Format(time.DateOnly),
		x509Cert.SignatureAlgorithm.String())

	daysUntilExpiry := int(time.Until(x509Cert.NotAfter).Hours() / 24)
	if daysUntilExpiry <= 0 {
		log.Errorf("TLCP: Certificate has already expired!")
	} else if daysUntilExpiry <= config.DefaultCertExpiryWarnDays {
		log.Warnf("TLCP: Certificate expires in %d days!", daysUntilExpiry)
	}
}

// Start launches all TLCP protocol listeners and blocks until all servers have
// exited or an error occurs.
func (s *Server) Start(dnsHandler edns.DNSHandler) error {
	s.handler = dnsHandler

	if s.dotPort != "" {
		if err := s.startDOTServer(); err != nil {
			return fmt.Errorf("TLCP DoT startup: %w", err)
		}
	}

	if s.dohPort != "" {
		if err := s.startDOHServer(); err != nil {
			return fmt.Errorf("TLCP DoH startup: %w", err)
		}
	}

	if s.dtlcpPort != "" {
		if err := s.startDTLCPServer(); err != nil {
			return fmt.Errorf("TLCP DTLCP startup: %w", err)
		}
	}

	return nil
}

// Shutdown gracefully stops all TLCP listeners and HTTP servers.
func (s *Server) Shutdown() error {
	log.Infof("TLCP: Shutting down TLCP server")

	s.cancel(errors.New("tlcp server shutdown"))

	for _, l := range s.dotListeners {
		if l != nil {
			zdnsutil.CloseWithLog(l, "TLCP DoT listener", "TLCP")
		}
	}
	for _, srv := range s.dohServers {
		if srv != nil {
			ctx, cancel := context.WithTimeout(context.Background(), config.DefaultShutdownTimeout)
			_ = srv.Shutdown(ctx)
			cancel()
		}
	}
	for _, l := range s.dohListeners {
		if l != nil {
			zdnsutil.CloseWithLog(l, "TLCP DoH listener", "TLCP")
		}
	}
	for _, l := range s.dtlcpListeners {
		if l != nil {
			zdnsutil.CloseWithLog(l, "TLCP DTLCP listener", "TLCP")
		}
	}
	if err := s.serverGroup.Wait(); err != nil {
		log.Errorf("TLCP: server goroutines finished with error: %v", err)
	}
	log.Infof("TLCP: TLCP server shut down")
	return nil
}
