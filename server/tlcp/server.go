// Package tlcp provides a TLCP (国密 SSL, GB/T 38636-2020) server listener
// supporting DoT and DoH over TLCP.
package tlcp

import (
	"context"
	"crypto/rand"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"time"
	"zjdns/config"
	zdnsutil "zjdns/internal/dnsutil"
	"zjdns/internal/log"

	"codeberg.org/miekg/dns"
	"gitee.com/Trisia/gotlcp/tlcp"
	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"
)

// DNSHandler is the interface for processing incoming DNS queries.
type DNSHandler interface {
	ServeDNS(req *dns.Msg, clientIP net.IP, isSecure bool, protocol string) *dns.Msg
}

// Server manages TLCP-based secure DNS protocol listeners and their lifecycle.
type Server struct {
	dotPort      string
	dohPort      string
	dohEndpoint  string
	handler      DNSHandler
	tlcpConfig   *tlcp.Config
	ctx          context.Context
	cancel       context.CancelCauseFunc
	dotListeners []net.Listener
	dohListeners []net.Listener
	dohServers   []*http.Server
}

// New creates a TLCP Server, loading or generating SM2 certificate pairs.
// dotPort, dohPort, dohEndpoint come from the protocol config section.
func New(certificateCfg *config.TLCPCertificate, dotPort, dohPort, dohEndpoint string) (*Server, error) {
	var signCert, encCert tlcp.Certificate
	var err error

	if certificateCfg.SelfSigned {
		signCert, encCert, err = generateSelfSignedSMCerts()
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
		log.Debugf("TLCP: Using SM2 certificates from files")
	}

	tlcpConfig := &tlcp.Config{
		Certificates:     []tlcp.Certificate{signCert, encCert},
		CurvePreferences: []tlcp.CurveID{tlcp.CurveSM2},
	}

	ctx, cancel := context.WithCancelCause(context.Background())

	s := &Server{
		dotPort:     dotPort,
		dohPort:     dohPort,
		dohEndpoint: dohEndpoint,
		tlcpConfig:  tlcpConfig,
		ctx:         ctx,
		cancel:      cancel,
	}

	return s, nil
}

// Start launches all TLCP protocol listeners and blocks until all servers have
// exited or an error occurs.
func (s *Server) Start(handler DNSHandler) error {
	s.handler = handler

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
	log.Infof("TLCP: TLCP server shut down")
	return nil
}

// generateSelfSignedSMCerts creates a self-signed SM2 CA and two server
// certificates (signing + encryption) for TLCP use.
func generateSelfSignedSMCerts() (signCert, encCert tlcp.Certificate, err error) {
	caKey, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		err = fmt.Errorf("generate CA SM2 key: %w", err)
		return signCert, encCert, err
	}
	signKey, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		err = fmt.Errorf("generate sign SM2 key: %w", err)
		return signCert, encCert, err
	}
	encKey, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		err = fmt.Errorf("generate enc SM2 key: %w", err)
		return signCert, encCert, err
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	caSerial, _ := rand.Int(rand.Reader, serialLimit)
	signSerial, _ := rand.Int(rand.Reader, serialLimit)
	encSerial, _ := rand.Int(rand.Reader, serialLimit)

	caTemplate := &smx509.Certificate{
		SerialNumber:          caSerial,
		Subject:               pkix.Name{CommonName: "ZJDNS TLCP CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(config.DefaultCACertValidity),
		KeyUsage:              smx509.KeyUsageDigitalSignature | smx509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            1,
	}
	serverTemplate := func() *smx509.Certificate {
		return &smx509.Certificate{
			SerialNumber: new(big.Int),
			Subject:      pkix.Name{CommonName: config.DefaultProjectName + " TLCP"},
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(config.DefaultServerCertValidity),
			KeyUsage:     smx509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []smx509.ExtKeyUsage{smx509.ExtKeyUsageServerAuth},
		}
	}

	caDER, err := smx509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		err = fmt.Errorf("create CA cert: %w", err)
		return signCert, encCert, err
	}
	caCert, _ := smx509.ParseCertificate(caDER)

	signSerial.Set(signSerial)
	signTmpl := serverTemplate()
	signTmpl.SerialNumber = signSerial
	signDER, err := smx509.CreateCertificate(rand.Reader, signTmpl, caCert, &signKey.PublicKey, caKey)
	if err != nil {
		err = fmt.Errorf("create sign cert: %w", err)
		return signCert, encCert, err
	}

	encSerial.Set(encSerial)
	encTmpl := serverTemplate()
	encTmpl.SerialNumber = encSerial
	encDER, err := smx509.CreateCertificate(rand.Reader, encTmpl, caCert, &encKey.PublicKey, caKey)
	if err != nil {
		err = fmt.Errorf("create enc cert: %w", err)
		return signCert, encCert, err
	}

	signCert = tlcp.Certificate{
		Certificate: [][]byte{signDER},
		PrivateKey:  signKey,
	}
	encCert = tlcp.Certificate{
		Certificate: [][]byte{encDER},
		PrivateKey:  encKey,
	}
	return signCert, encCert, err
}
