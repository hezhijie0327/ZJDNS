// Package tlcp provides a TLCP (国密 SSL, GB/T 38636-2020) server listener
// supporting DoT and DoH over TLCP.
package tlcp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"zjdns/config"
	"zjdns/edns"
	zdnsutil "zjdns/internal/dnsutil"
	"zjdns/internal/log"

	"gitee.com/Trisia/gotlcp/dtlcp"
	"gitee.com/Trisia/gotlcp/tlcp"
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

	// External listeners set by the port-sharing layer.
	// When non-nil, startDOTServer / startDOHServer skip binding
	// and use the provided listener instead.
	extDoTListener   net.Listener
	extDoHListener   net.Listener
	extDTLCPListener net.Listener
}

// SetExternalDoTListener injects a pre-created DoT listener, skipping the
// normal bind-and-wrap path.  Used for port sharing (TLS + TLCP on :853).
func (s *Server) SetExternalDoTListener(l net.Listener) { s.extDoTListener = l }

// SetExternalDoHListener injects a pre-created DoH listener, skipping the
// normal bind-and-wrap path.  Used for port sharing (HTTPS + TLCP DoH on :443).
func (s *Server) SetExternalDoHListener(l net.Listener) { s.extDoHListener = l }

// SetExternalDTLCPListener injects a pre-created DTLCP listener.  Used for
// port sharing (DTLS + DTLCP on :853 UDP).
func (s *Server) SetExternalDTLCPListener(l net.Listener) { s.extDTLCPListener = l }

// SharedTLCPConfig returns a cloned TLCP config for use by the port-sharing
// shared listener.  alpn sets NextProtos (["dot"] for DoT, ["h2"] for DoH).
// DTLCPConfig returns the DTLCP config for use by the port-sharing
// UDP listener.
func (s *Server) DTLCPConfig() *dtlcp.Config { return s.dtlcpConfig }

func (s *Server) SharedTLCPConfig(alpn []string) *tlcp.Config {
	cfg := s.tlcpConfig.Clone()
	cfg.NextProtos = alpn
	return cfg
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
	}

	dtlcpConfig := &dtlcp.Config{
		Certificates:     []dtlcp.Certificate{dtlcpSignCert, dtlcpEncCert},
		CurvePreferences: []dtlcp.CurveID{dtlcp.CurveSM2},
		SessionCache:     dtlcp.NewLRUSessionCache(128),
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

	return s, nil
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
