package dnscrypt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"time"

	"github.com/AdguardTeam/dnscrypt"
	"golang.org/x/sync/errgroup"

	"zjdns/config"
	"zjdns/internal/dnsutil"
	"zjdns/internal/log"
)

// ESVersion constants for use by callers that cannot import the dnscrypt library.
const (
	ESVersionXSalsa20Poly1305  = 1
	ESVersionXChacha20Poly1305 = 2
)

// Config holds the configuration for the DNSCrypt server wrapper.
type Config struct {
	Port         string
	ProviderName string
	// Keys are hex-encoded. If PrivateKey is empty, keys are auto-generated
	// and logged — copy them into the config to persist across restarts.
	PrivateKey string
	PublicKey  string
	ResolverSk string
	ResolverPk string
	CertTTL    time.Duration
	ESVersion  int // 1=XSalsa20Poly1305, 2=XChacha20Poly1305; 0 = default (XSalsa20Poly1305)
}

// esVersion converts the int config value to the library's CryptoConstruction.
func esVersion(v int) dnscrypt.CryptoConstruction {
	switch v {
	case ESVersionXChacha20Poly1305:
		return dnscrypt.XChacha20Poly1305
	default:
		return dnscrypt.XSalsa20Poly1305
	}
}

// Server manages DNSCrypt v2 protocol listeners (UDP + TCP) and their lifecycle.
type Server struct {
	cfg         Config
	handler     DNSHandler
	udpServer   *dnscrypt.Server
	tcpServer   *dnscrypt.Server
	ctx         context.Context
	cancel      context.CancelCauseFunc
	serverGroup *errgroup.Group
	serverCtx   context.Context
}

// New creates a DNSCrypt Server with the given handler and configuration.
func New(handler DNSHandler, cfg Config) (*Server, error) {
	if cfg.Port == "" {
		return nil, errors.New("dnscrypt: port must not be empty")
	}
	if cfg.ProviderName == "" {
		return nil, errors.New("dnscrypt: provider_name must not be empty")
	}

	// Ensure provider name has the DNSCrypt v2 prefix.
	providerName := cfg.ProviderName
	if !strings.HasPrefix(providerName, dnscrypt.DNSCryptV2Prefix) {
		providerName = dnscrypt.DNSCryptV2Prefix + providerName
	}

	certTTL := cfg.CertTTL
	if certTTL <= 0 {
		certTTL = config.DefaultDNSCryptCertValidity
	}

	// Build or generate resolver configuration.
	resolverCfg, cert, generated, err := buildResolverConfig(providerName, cfg, certTTL)
	if err != nil {
		return nil, fmt.Errorf("dnscrypt: build resolver config: %w", err)
	}

	if generated {
		log.Warnf("DNSCRYPT: auto-generated keys:\n%s",
			BuildKeysJSON(cfg.Port, cfg.ProviderName, providerName,
				resolverCfg.PrivateKey, resolverCfg.PublicKey,
				resolverCfg.ResolverSk, resolverCfg.ResolverPk,
				int(certTTL/time.Second), cfg.ESVersion))
	}

	ctx, cancel := context.WithCancelCause(context.Background())
	serverGroup, serverCtx := errgroup.WithContext(ctx)

	h := &handlerAdapter{inner: handler}
	dnscryptLogger := slog.New(slogHandler{})

	addrPort, err := netip.ParseAddrPort(netip.IPv4Unspecified().String() + ":" + cfg.Port)
	if err != nil {
		cancel(errors.New("dnscrypt: invalid address"))
		return nil, fmt.Errorf("dnscrypt: parse address: %w", err)
	}

	udpSrv, err := dnscrypt.NewServer(&dnscrypt.ServerConfig{
		Handler:      h,
		ResolverCert: cert,
		ProviderName: resolverCfg.ProviderName,
		Addr:         addrPort,
		Proto:        dnscrypt.ProtoUDP,
		Logger:       dnscryptLogger,
	})
	if err != nil {
		cancel(errors.New("dnscrypt: create UDP server"))
		return nil, fmt.Errorf("dnscrypt: create UDP server: %w", err)
	}

	tcpSrv, err := dnscrypt.NewServer(&dnscrypt.ServerConfig{
		Handler:      h,
		ResolverCert: cert,
		ProviderName: resolverCfg.ProviderName,
		Addr:         addrPort,
		Proto:        dnscrypt.ProtoTCP,
		Logger:       dnscryptLogger,
	})
	if err != nil {
		cancel(errors.New("dnscrypt: create TCP server"))
		return nil, fmt.Errorf("dnscrypt: create TCP server: %w", err)
	}

	s := &Server{
		cfg:         cfg,
		handler:     handler,
		udpServer:   udpSrv,
		tcpServer:   tcpSrv,
		ctx:         ctx,
		cancel:      cancel,
		serverGroup: serverGroup,
		serverCtx:   serverCtx,
	}

	log.Infof("DNSCRYPT: DNSCrypt server configured — provider=%s port=%s es_version=%s",
		providerName, cfg.Port, esVersion(cfg.ESVersion))

	return s, nil
}

// Start launches the DNSCrypt UDP and TCP listeners. It blocks until both
// servers have exited or an error occurs.
func (s *Server) Start() error {
	errChan := make(chan error, 1)

	g, ctx := errgroup.WithContext(s.ctx)

	g.Go(func() error {
		defer dnsutil.HandlePanic("DNSCrypt UDP server")
		log.Infof("DNSCRYPT: DNSCrypt UDP listener starting on port %s", s.cfg.Port)
		if err := s.udpServer.Start(ctx); err != nil {
			return fmt.Errorf("DNSCrypt UDP: %w", err)
		}
		<-ctx.Done()
		return nil
	})

	g.Go(func() error {
		defer dnsutil.HandlePanic("DNSCrypt TCP server")
		log.Infof("DNSCRYPT: DNSCrypt TCP listener starting on port %s", s.cfg.Port)
		if err := s.tcpServer.Start(ctx); err != nil {
			return fmt.Errorf("DNSCrypt TCP: %w", err)
		}
		<-ctx.Done()
		return nil
	})

	go func() {
		defer dnsutil.HandlePanic("DNSCrypt server coordinator")
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

// Shutdown gracefully stops both DNSCrypt listeners and waits for server
// goroutines to finish.
func (s *Server) Shutdown() error {
	log.Infof("DNSCRYPT: Shutting down DNSCrypt server")

	s.cancel(errors.New("dnscrypt server shutdown"))

	shutdownCtx, cancel := context.WithTimeout(context.Background(), config.DefaultShutdownTimeout)
	defer cancel()

	if s.udpServer != nil {
		if err := s.udpServer.Shutdown(shutdownCtx); err != nil {
			log.Warnf("DNSCRYPT: DNSCrypt UDP shutdown: %v", err)
		}
	}
	if s.tcpServer != nil {
		if err := s.tcpServer.Shutdown(shutdownCtx); err != nil {
			log.Warnf("DNSCRYPT: DNSCrypt TCP shutdown: %v", err)
		}
	}

	if err := s.serverGroup.Wait(); err != nil {
		log.Errorf("DNSCRYPT: DNSCrypt server goroutines finished with error: %v", err)
	}

	log.Infof("DNSCRYPT: DNSCrypt server shut down")
	return nil
}

// GeneratedKeys holds a generated DNSCrypt key set ready for config inclusion.
type GeneratedKeys struct {
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
	ResolverSk string `json:"resolver_sk"`
	ResolverPk string `json:"resolver_pk"`
}

// KeysOutput is the top-level JSON structure output by BuildKeysJSON,
// containing both server-side DNSCrypt settings and a client upstream entry.
type KeysOutput struct {
	Server   KeysServerConfig `json:"server"`
	Upstream []KeysUpstream   `json:"upstream"`
}

// KeysServerConfig wraps the DNSCrypt server settings.
type KeysServerConfig struct {
	DNSCrypt config.DNSCryptSettings `json:"dnscrypt"`
}

// KeysUpstream is a client upstream entry pointing to this DNSCrypt server.
type KeysUpstream struct {
	Address              string `json:"address"`
	Protocol             string `json:"protocol"`
	DNSCryptPublicKey    string `json:"dnscrypt_public_key"`
	DNSCryptProviderName string `json:"dnscrypt_provider_name"`
}

// BuildKeysJSON builds the canonical JSON config snippet for a DNSCrypt key
// set, covering both server.dnscrypt settings and a client upstream entry.
func BuildKeysJSON(port, bareProvider, fullProvider, privateKey, publicKey, resolverSk, resolverPk string, certTTLSec, esv int) string {
	srv := config.DNSCryptSettings{
		Port:         port,
		ProviderName: bareProvider,
		PrivateKey:   privateKey,
		PublicKey:    publicKey,
		ResolverSk:   resolverSk,
		ResolverPk:   resolverPk,
		CertTTL:      certTTLSec,
	}
	if esv != 0 {
		srv.ESVersion = esv
	}

	out := KeysOutput{
		Server: KeysServerConfig{DNSCrypt: srv},
		Upstream: []KeysUpstream{
			{
				Address:              "127.0.0.1:" + port,
				Protocol:             "dnscrypt",
				DNSCryptPublicKey:    publicKey,
				DNSCryptProviderName: fullProvider,
			},
		},
	}

	data, _ := json.MarshalIndent(out, "", "  ")
	return string(data)
}

// GenerateKeys generates a new DNSCrypt resolver key set for the given provider
// name and ES version. providerName should be the bare domain (e.g. "example.com")
// — the "2.dnscrypt-cert." prefix is added automatically.
func GenerateKeys(providerName string, esv int, certTTL time.Duration) (*GeneratedKeys, error) {
	if providerName == "" {
		return nil, errors.New("dnscrypt: provider_name must not be empty")
	}
	if !strings.HasPrefix(providerName, dnscrypt.DNSCryptV2Prefix) {
		providerName = dnscrypt.DNSCryptV2Prefix + providerName
	}
	if certTTL <= 0 {
		certTTL = config.DefaultDNSCryptCertValidity
	}

	rc, err := dnscrypt.GenerateResolverConfig(providerName, nil, certTTL)
	if err != nil {
		return nil, fmt.Errorf("generate resolver config: %w", err)
	}

	cryptoConstruction := esVersion(esv)
	if cryptoConstruction != dnscrypt.UndefinedConstruction {
		rc.ESVersion = cryptoConstruction
	}

	// Validate by creating a cert.
	_, err = rc.NewCert()
	if err != nil {
		return nil, fmt.Errorf("create certificate: %w", err)
	}

	return &GeneratedKeys{
		PrivateKey: rc.PrivateKey,
		PublicKey:  rc.PublicKey,
		ResolverSk: rc.ResolverSk,
		ResolverPk: rc.ResolverPk,
	}, nil
}

// buildResolverConfig creates a ResolverConfig from the Config, auto-generating
// keys when PrivateKey is empty. The third return value is true when keys were
// auto-generated (caller should log them for the admin to persist).
func buildResolverConfig(
	providerName string,
	cfg Config,
	certTTL time.Duration,
) (dnscrypt.ResolverConfig, *dnscrypt.Certificate, bool, error) {
	cryptoConstruction := esVersion(cfg.ESVersion)
	generated := false
	var rc dnscrypt.ResolverConfig
	var err error

	if cfg.PrivateKey != "" {
		rc = dnscrypt.ResolverConfig{
			ProviderName:   providerName,
			PrivateKey:     cfg.PrivateKey,
			PublicKey:      cfg.PublicKey,
			ResolverSk:     cfg.ResolverSk,
			ResolverPk:     cfg.ResolverPk,
			ESVersion:      cryptoConstruction,
			CertificateTTL: certTTL,
		}
		if err = rc.Validate(); err != nil {
			return rc, nil, false, fmt.Errorf("validate resolver config: %w", err)
		}
	} else {
		rc, err = dnscrypt.GenerateResolverConfig(providerName, nil, certTTL)
		if err != nil {
			return rc, nil, false, fmt.Errorf("generate resolver config: %w", err)
		}
		if cryptoConstruction != dnscrypt.UndefinedConstruction {
			rc.ESVersion = cryptoConstruction
		}
		generated = true
	}

	cert, err := rc.NewCert()
	if err != nil {
		return rc, nil, false, fmt.Errorf("create certificate: %w", err)
	}

	log.Infof("DNSCRYPT: DNSCrypt certificate — serial=%d es_version=%s valid=%s→%s",
		cert.Serial, cert.ESVersion,
		time.Unix(int64(cert.NotBefore), 0).Format(time.RFC3339),
		time.Unix(int64(cert.NotAfter), 0).Format(time.RFC3339))

	return rc, cert, generated, nil
}
