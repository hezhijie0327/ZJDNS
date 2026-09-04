// Per-protocol serving handlers: DoT from a listener, DoQ/HTTP3/DTLS from
// packet conns, the DoH HTTP handler, and TLS config selection per ALPN.

package tls

import (
	stdtls "crypto/tls"
	"crypto/x509"
	"net"
	"time"
	"zjdns/config"
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
)

// QUICTLSConfig returns the TLS config for QUIC-based protocols (DoQ, DoH3).
// KTLS does not apply to QUIC, so this uses the standard crypto/tls.
func (s *Server) QUICTLSConfig() *stdtls.Config {
	return s.quicTLSConfig
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

// HandleHTTP3FromPacketConn serves DoH3 connections from an external
// PacketConn.  Used by the shared-port Manager when HTTP3 shares a UDP
// port with DNSCrypt.  The caller provides a net.PacketConn fed by the
// UDP dispatch loop.
func (s *Server) HandleHTTP3FromPacketConn(pc net.PacketConn) error {
	addrCache := lrumap.New[string, time.Time](config.DefaultQUICAddrCacheSize)

	transport := &quic.Transport{
		Conn:                pc,
		VerifySourceAddress: makeAddrValidator(addrCache),
	}
	s.listenerMu.Lock()
	s.h3Transports = append(s.h3Transports, transport)
	s.listenerMu.Unlock()

	tlsConfig := s.QUICTLSConfig().Clone()
	tlsConfig.NextProtos = config.NextProtoDOH3

	quicConfig := &quic.Config{
		MaxIdleTimeout:        config.DefaultQUICServerIdleTimeout,
		MaxIncomingStreams:    config.DefaultHTTP3MaxIncomingStreams,
		MaxIncomingUniStreams: config.DefaultHTTP3MaxIncomingStreams,
		Allow0RTT:             true,
		KeepAlivePeriod:       config.DefaultQUICKeepAlive,
	}

	s.listenerMu.Lock()
	if s.h3Server == nil {
		// Same stream bounds and HTTP-layer idle timeout as the standalone
		// path — a shared-port client could otherwise open 64k streams per
		// connection, exactly what DefaultHTTP3MaxIncomingStreams was
		// added to prevent (P-M1).
		s.h3Server = &http3.Server{Handler: s, IdleTimeout: config.DefaultQUICServerIdleTimeout}
	}
	s.listenerMu.Unlock()

	listener, err := transport.ListenEarly(tlsConfig, quicConfig)
	if err != nil {
		return err
	}

	s.listenerMu.Lock()
	s.h3Listeners = append(s.h3Listeners, listener)
	s.listenerMu.Unlock()

	s.handleHTTP3Connections(listener)
	return nil
}

// HandleDTLSFromPacketListener serves DTLS connections from an external
// PacketListener.  Used by the TLCP server for shared UDP port (DTLS +
// DTLCP on 853).  The caller provides a dtlsnet.PacketListener whose
// per-client PacketConns deliver demuxed DTLS datagrams.
func (s *Server) HandleDTLSFromPacketListener(pl dtlsnet.PacketListener) error {
	listener, err := dtls.NewListener(pl,
		dtls.WithMinVersion(protocol.Version1_3),
		dtls.WithMaxVersion(protocol.Version1_3),
		dtls.WithCertificates(s.stdCert),
		dtls.WithSessionStore(lrumap.NewDTLSSessionStore(config.DefaultDTLSSessionCacheSize)),
		dtls.WithVerifyConnection(func(state *dtls.State) error {
			zdnsutil.LogHandshake(&zdnsutil.HandshakeInfo{
				Role:       "TLS",
				Direction:  "DTLS handshake from",
				RemoteAddr: "client",
				Cipher:     state.CipherSuiteID.String(),
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
