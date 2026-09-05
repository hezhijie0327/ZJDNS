// Package tlcp provides a TLCP (国密 SSL, GB/T 38636-2020) server listener
// supporting DoT and DoH over TLCP.
package tlcp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
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
	// Skip standalone listeners when the shared-port mux owns the bind
	// (set by the wiring in server/protocols.go at the same place the mux
	// route is registered).
	SkipDOT   bool
	SkipDOH   bool
	SkipDTLCP bool

	dotPort     string
	dohPort     string
	dohEndpoint string
	dtlcpPort   string
	handler     edns.DNSHandler
	tlcpConfig  *tlcp.Config
	dtlcpConfig *dtlcp.Config
	ctx         context.Context
	cancel      context.CancelCauseFunc
	// listenerMu protects the listener/server slices below. Start's start*
	// functions append under it and Shutdown snapshots under it; the signal
	// handler is armed before Start, so a signal during listener startup
	// runs Shutdown concurrently with the appends.
	listenerMu     sync.Mutex
	dotListeners   []net.Listener
	dotConns       map[net.Conn]struct{} // active TLCP DoT conns — woken on Shutdown (M-3-5)
	dohListeners   []net.Listener
	dohServers     []*http.Server
	dtlcpListeners []*dtlcpListener
	serverGroup    *errgroup.Group
	serverCtx      context.Context
}

// New creates a TLCP Server, loading or generating SM2 certificate pairs.
// dotPort, dohPort, dohEndpoint, and dtlcpPort come from the protocol config section.
func New(certificateCfg *config.TLCPCertificate, dotPort, dohPort, dohEndpoint, dtlcpPort string) (*Server, error) {
	if certificateCfg == nil {
		return nil, errors.New("tlcp: nil certificate config")
	}
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
		SessionCache:     tlcp.NewLRUSessionCache(config.DefaultTLCPSessionCacheSize),
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
		SessionCache:     dtlcp.NewLRUSessionCache(config.DefaultDTLCPSessionCacheSize),
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
		dotConns:    make(map[net.Conn]struct{}),
	}

	displayCertificateInfo(&signCert)

	return s, nil
}

// WrapTLCPConn wraps a raw net.Conn with the TLCP protocol handshake
// (exported for shared-port Manager).
func (s *Server) WrapTLCPConn(c net.Conn, nextProtos []string) net.Conn {
	cfg := s.tlcpConfig.Clone()
	cfg.NextProtos = nextProtos
	return tlcp.Server(c, cfg)
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
		log.Warnf("TLCP: Certificate has already expired!")
	} else if daysUntilExpiry <= config.DefaultCertExpiryWarnDays {
		log.Warnf("TLCP: Certificate expires in %d days!", daysUntilExpiry)
	}
}

// Start launches all TLCP protocol listeners and blocks until all servers have
// exited or an error occurs.
func (s *Server) Start(dnsHandler edns.DNSHandler) error {
	if dnsHandler == nil {
		return errors.New("tlcp: nil DNS handler")
	}
	s.handler = dnsHandler

	// The Skip* flags are set by the shared-port wiring when the mux owns
	// the port's bind (mirrors tls.Server's Skip flags).  A standalone
	// bind attempt on an already-owned port would fail with EADDRINUSE
	// and the returned error tears down the whole server errgroup —
	// which silently kills every plain-TCP connection (their per-conn
	// contexts derive from the same errgroup context).
	if s.dotPort != "" && !s.SkipDOT {
		if err := s.startDOTServer(); err != nil {
			return fmt.Errorf("TLCP DoT startup: %w", err)
		}
	}

	if s.dohPort != "" && !s.SkipDOH {
		if err := s.startDOHServer(); err != nil {
			return fmt.Errorf("TLCP DoH startup: %w", err)
		}
	}

	if s.dtlcpPort != "" && !s.SkipDTLCP {
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

	// Snapshot under listenerMu (Start's start* functions append under the
	// same lock); the close calls run outside it — dohServer Shutdown blocks
	// for up to DefaultShutdownTimeout.
	s.listenerMu.Lock()
	dotListeners := append([]net.Listener(nil), s.dotListeners...)
	dohServers := append([]*http.Server(nil), s.dohServers...)
	dohListeners := append([]net.Listener(nil), s.dohListeners...)
	dtlcpListeners := append([]*dtlcpListener(nil), s.dtlcpListeners...)
	s.listenerMu.Unlock()

	for _, l := range dotListeners {
		if l != nil {
			zdnsutil.CloseWithLog(l, "TLCP DoT listener", "TLCP")
		}
	}
	// Wake active TLCP DoT connections — their read loops block in
	// io.ReadFull with a 60s idle deadline (M-3-5).
	s.listenerMu.Lock()
	for conn := range s.dotConns {
		_ = conn.SetReadDeadline(time.Unix(1, 0))
	}
	s.listenerMu.Unlock()
	for _, srv := range dohServers {
		if srv != nil {
			ctx, cancel := context.WithTimeout(context.Background(), config.DefaultShutdownTimeout)
			_ = srv.Shutdown(ctx)
			cancel()
		}
	}
	for _, l := range dohListeners {
		if l != nil {
			zdnsutil.CloseWithLog(l, "TLCP DoH listener", "TLCP")
		}
	}
	for _, l := range dtlcpListeners {
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
