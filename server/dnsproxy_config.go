package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/AdguardTeam/dnscrypt"
	"github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/AdguardTeam/dnsproxy/upstream"

	"zjdns/config"
	"zjdns/internal/log"
	"zjdns/internal/pool"
)

func addrPort(port string) netip.AddrPort {
	return netip.MustParseAddrPort("0.0.0.0:" + port)
}

// buildProxyConfig converts our ServerConfig into a dnsproxy proxy.Config.
func (s *Server) buildProxyConfig() (*proxy.Config, error) {
	cfg := s.config

	pc := &proxy.Config{
		UDPBufferSize: pool.UDPBufferSize,
		CacheEnabled:  false,
		DNSSECEnabled: true,
		RefuseAny:     true,
		UpstreamMode:  proxy.UpstreamModeParallel,
	}

	pc.UDPListenAddr = []*net.UDPAddr{net.UDPAddrFromAddrPort(addrPort(cfg.Server.Port))}
	pc.TCPListenAddr = []*net.TCPAddr{net.TCPAddrFromAddrPort(addrPort(cfg.Server.Port))}

	if cfg.Server.TLS.CertFile != "" && cfg.Server.TLS.KeyFile != "" {
		tlsCfg, err := buildTLSConfig(cfg)
		if err != nil {
			return nil, fmt.Errorf("TLS config: %w", err)
		}
		pc.TLSConfig = tlsCfg
		pc.TLSListenAddr = []*net.TCPAddr{net.TCPAddrFromAddrPort(addrPort(cfg.Server.TLS.Port))}
		pc.QUICListenAddr = []*net.UDPAddr{net.UDPAddrFromAddrPort(addrPort(cfg.Server.TLS.Port))}
		if cfg.Server.TLS.HTTPS.Port != "" {
			pc.HTTPConfig = httpsConfig(cfg)
		}
	} else if cfg.Server.TLS.SelfSigned {
		tlsCfg, err := buildSelfSignedTLSConfig(cfg)
		if err != nil {
			return nil, fmt.Errorf("self-signed TLS: %w", err)
		}
		pc.TLSConfig = tlsCfg
		pc.TLSListenAddr = []*net.TCPAddr{net.TCPAddrFromAddrPort(addrPort(cfg.Server.TLS.Port))}
		pc.QUICListenAddr = []*net.UDPAddr{net.UDPAddrFromAddrPort(addrPort(cfg.Server.TLS.Port))}
		if cfg.Server.TLS.HTTPS.Port != "" {
			pc.HTTPConfig = httpsConfig(cfg)
		}
	}

	if cfg.Server.DNSCrypt.Port != "" {
		if err := setupDNSCryptConfig(pc, cfg); err != nil {
			return nil, fmt.Errorf("DNSCrypt config: %w", err)
		}
	}

	upstreamOpts := &upstream.Options{Timeout: config.DefaultDNSQueryTimeout}
	pc.UpstreamConfig, pc.Fallbacks = s.buildUpstreamConfig(cfg, upstreamOpts)

	return pc, nil
}

func httpsConfig(cfg *config.ServerConfig) *proxy.HTTPConfig {
	endpoint := cfg.Server.TLS.HTTPS.Endpoint
	if endpoint == "" {
		endpoint = config.DefaultQueryPath
	}
	return &proxy.HTTPConfig{
		ListenAddresses: []netip.AddrPort{addrPort(cfg.Server.TLS.HTTPS.Port)},
		Routes:          []string{endpoint},
		HTTP3Enabled:    true,
	}
}

func buildTLSConfig(cfg *config.ServerConfig) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(cfg.Server.TLS.CertFile, cfg.Server.TLS.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("load cert: %w", err)
	}
	log.Infof("TLS: Using certificate from %s", cfg.Server.TLS.CertFile)
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}, nil
}

func buildSelfSignedTLSConfig(cfg *config.ServerConfig) (*tls.Config, error) {
	domain := cfg.Server.Features.DDR.Domain
	if domain == "" {
		domain = "zjdns.local"
	}
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, _ := rand.Int(rand.Reader, serialLimit)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(config.DefaultServerCertValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}
	log.Infof("TLS: Using self-signed certificate for %s", domain)
	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: priv}},
		MinVersion:   tls.VersionTLS13,
	}, nil
}

func setupDNSCryptConfig(pc *proxy.Config, cfg *config.ServerConfig) error {
	providerName := cfg.Server.DNSCrypt.ProviderName
	if !strings.HasPrefix(providerName, dnscrypt.DNSCryptV2Prefix) {
		providerName = dnscrypt.DNSCryptV2Prefix + providerName
	}
	certTTL := config.DefaultDNSCryptCertValidity
	if cfg.Server.DNSCrypt.CertTTL > 0 {
		certTTL = time.Duration(cfg.Server.DNSCrypt.CertTTL) * time.Second
	}
	esVersion := dnscrypt.XSalsa20Poly1305
	if cfg.Server.DNSCrypt.ESVersion == 2 {
		esVersion = dnscrypt.XChacha20Poly1305
	}

	var rc dnscrypt.ResolverConfig
	var err error
	if cfg.Server.DNSCrypt.PrivateKey != "" {
		rc = dnscrypt.ResolverConfig{
			ProviderName:   providerName,
			PrivateKey:     cfg.Server.DNSCrypt.PrivateKey,
			PublicKey:      cfg.Server.DNSCrypt.PublicKey,
			ResolverSk:     cfg.Server.DNSCrypt.ResolverSk,
			ResolverPk:     cfg.Server.DNSCrypt.ResolverPk,
			ESVersion:      esVersion,
			CertificateTTL: certTTL,
		}
		if err = rc.Validate(); err != nil {
			return fmt.Errorf("validate resolver config: %w", err)
		}
	} else {
		rc, err = dnscrypt.GenerateResolverConfig(providerName, nil, certTTL)
		if err != nil {
			return fmt.Errorf("generate resolver config: %w", err)
		}
		rc.ESVersion = esVersion
		log.Warnf("DNSCRYPT: auto-generated keys:\n%s",
			buildKeysJSON(cfg.Server.DNSCrypt.Port, cfg.Server.DNSCrypt.ProviderName,
				providerName, rc, int(certTTL/time.Second), cfg.Server.DNSCrypt.ESVersion))
	}

	cert, err := rc.NewCert()
	if err != nil {
		return fmt.Errorf("create certificate: %w", err)
	}
	pc.DNSCryptResolverCert = cert
	pc.DNSCryptProviderName = providerName
	pc.DNSCryptUDPListenAddr = []*net.UDPAddr{net.UDPAddrFromAddrPort(addrPort(cfg.Server.DNSCrypt.Port))}
	pc.DNSCryptTCPListenAddr = []*net.TCPAddr{net.TCPAddrFromAddrPort(addrPort(cfg.Server.DNSCrypt.Port))}
	return nil
}

func (s *Server) buildUpstreamConfig(cfg *config.ServerConfig, opts *upstream.Options) (main, fallback *proxy.UpstreamConfig) {
	main = s.serversToUpstreamConfig(cfg.Upstream, opts)
	if len(cfg.Fallback) > 0 {
		fallback = s.serversToUpstreamConfig(cfg.Fallback, opts)
	}
	return
}

func (s *Server) serversToUpstreamConfig(servers []config.UpstreamServer, opts *upstream.Options) *proxy.UpstreamConfig {
	uc := &proxy.UpstreamConfig{}
	for _, srv := range servers {
		if srv.IsRecursive() {
			uc.Upstreams = append(uc.Upstreams, &recursiveUpstream{server: s})
			continue
		}
		u, err := upstream.AddressToUpstream(upstreamURL(srv), opts)
		if err != nil {
			log.Warnf("UPSTREAM: skip %s: %v", srv.Address, err)
			continue
		}
		uc.Upstreams = append(uc.Upstreams, u)
	}
	if len(uc.Upstreams) == 0 {
		return nil
	}
	return uc
}

func buildKeysJSON(port, bareProvider, fullProvider string, rc dnscrypt.ResolverConfig, certTTLSec, esv int) string {
	srv := config.DNSCryptSettings{
		Port:         port,
		ProviderName: bareProvider,
		PrivateKey:   rc.PrivateKey,
		PublicKey:    rc.PublicKey,
		ResolverSk:   rc.ResolverSk,
		ResolverPk:   rc.ResolverPk,
		CertTTL:      certTTLSec,
		ESVersion:    esv,
	}
	return fmt.Sprintf(
		"{\n  \"server\": {\n    \"dnscrypt\": {\n      \"port\": \"%s\",\n      \"provider_name\": \"%s\",\n      \"private_key\": \"%s\",\n      \"public_key\": \"%s\",\n      \"resolver_sk\": \"%s\",\n      \"resolver_pk\": \"%s\",\n      \"cert_ttl\": %d\n    }\n  },\n  \"upstream\": [{\n    \"address\": \"127.0.0.1:%s\",\n    \"protocol\": \"dnscrypt\",\n    \"dnscrypt_public_key\": \"%s\",\n    \"dnscrypt_provider_name\": \"%s\"\n  }]\n}",
		srv.Port, srv.ProviderName, srv.PrivateKey, srv.PublicKey, srv.ResolverSk, srv.ResolverPk, srv.CertTTL,
		srv.Port, srv.PublicKey, fullProvider)
}

func upstreamURL(srv config.UpstreamServer) string {
	switch strings.ToLower(srv.Protocol) {
	case "tls", "dot":
		return "tls://" + srv.Address
	case "quic", "doq":
		return "quic://" + srv.Address
	case "https", "doh":
		return "https://" + srv.Address
	case "http3", "doh3":
		return "h3://" + srv.Address
	case "tcp":
		return "tcp://" + srv.Address
	default:
		return srv.Address
	}
}
