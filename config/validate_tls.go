// TLS/TLCP certificate validation: per-protocol certificate settings,
// cert/key file existence, and certificate domain checks.

package config

import (
	"errors"
	"fmt"
	"os"
	"zjdns/internal/log"

	zdnsutil "zjdns/internal/dnsutil"

	"gitee.com/Trisia/gotlcp/tlcp"
	eTLS "gitlab.com/go-extension/tls"
)

func validateTLSCertificateConfig(cfg *ServerConfig) error {
	tlsCert := &cfg.Server.Certificate.TLS
	if !tlsCert.IsEnabled() {
		return nil
	}

	// Only require cert validation if at least one TLS-based protocol is enabled.
	proto := &cfg.Server.Protocol
	tlsEnabled := proto.TLS != "" || proto.QUIC != "" || proto.HTTPS.Port != "" || proto.HTTP3.Port != ""
	if !tlsEnabled {
		return nil
	}

	if tlsCert.SelfSigned {
		if tlsCert.CertFile != "" || tlsCert.KeyFile != "" {
			log.Warnf("CONFIG: TLS: Self-signed enabled, ignoring cert/key files")
		}
		return nil
	}

	if tlsCert.CertFile == "" || tlsCert.KeyFile == "" {
		return errors.New("config: certificate.tls.cert_file and certificate.tls.key_file must be configured together, or enable self_signed")
	}
	if !zdnsutil.IsValidFilePath(tlsCert.CertFile) {
		return fmt.Errorf("config: TLS cert file not found: %s", tlsCert.CertFile)
	}
	if !zdnsutil.IsValidFilePath(tlsCert.KeyFile) {
		return fmt.Errorf("config: TLS key file not found: %s", tlsCert.KeyFile)
	}
	if info, err := os.Stat(tlsCert.KeyFile); err == nil {
		if info.Mode().Perm()&GroupOtherPermMask != 0 {
			log.Warnf("CONFIG: TLS key file has insecure permissions (%04o). Consider 'chmod 600 %s'",
				info.Mode().Perm(), tlsCert.KeyFile)
		}
	}
	if _, err := eTLS.LoadX509KeyPair(tlsCert.CertFile, tlsCert.KeyFile); err != nil {
		return fmt.Errorf("config: load TLS certificate: %w", err)
	}
	return nil
}

func validateTLCPCertificateConfig(cfg *ServerConfig) error {
	tlcpCert := &cfg.Server.Certificate.TLCP
	if !tlcpCert.IsEnabled() {
		return nil
	}

	// Only require cert validation if at least one TLCP protocol is enabled.
	proto := &cfg.Server.Protocol
	tlcpEnabled := proto.TLCP != "" || proto.HTTPTLCP.Port != ""
	if !tlcpEnabled {
		return nil
	}

	if tlcpCert.SelfSigned {
		return nil
	}
	if !zdnsutil.IsValidFilePath(tlcpCert.SignCertFile) {
		return fmt.Errorf("config: TLCP sign cert file not found: %s", tlcpCert.SignCertFile)
	}
	if !zdnsutil.IsValidFilePath(tlcpCert.SignKeyFile) {
		return fmt.Errorf("config: TLCP sign key file not found: %s", tlcpCert.SignKeyFile)
	}
	if !zdnsutil.IsValidFilePath(tlcpCert.EncCertFile) {
		return fmt.Errorf("config: TLCP enc cert file not found: %s", tlcpCert.EncCertFile)
	}
	if !zdnsutil.IsValidFilePath(tlcpCert.EncKeyFile) {
		return fmt.Errorf("config: TLCP enc key file not found: %s", tlcpCert.EncKeyFile)
	}
	if info, err := os.Stat(tlcpCert.SignKeyFile); err == nil {
		if info.Mode().Perm()&GroupOtherPermMask != 0 {
			log.Warnf("CONFIG: TLCP sign key file has insecure permissions (%04o). Consider 'chmod 600 %s'",
				info.Mode().Perm(), tlcpCert.SignKeyFile)
		}
	}
	if info, err := os.Stat(tlcpCert.EncKeyFile); err == nil {
		if info.Mode().Perm()&GroupOtherPermMask != 0 {
			log.Warnf("CONFIG: TLCP enc key file has insecure permissions (%04o). Consider 'chmod 600 %s'",
				info.Mode().Perm(), tlcpCert.EncKeyFile)
		}
	}
	// Verify certificates are loadable.
	if _, err := tlcp.LoadX509KeyPair(tlcpCert.SignCertFile, tlcpCert.SignKeyFile); err != nil {
		return fmt.Errorf("config: load TLCP sign certificate: %w", err)
	}
	if _, err := tlcp.LoadX509KeyPair(tlcpCert.EncCertFile, tlcpCert.EncKeyFile); err != nil {
		return fmt.Errorf("config: load TLCP enc certificate: %w", err)
	}
	return nil
}

func validateCertDomain(cfg *ServerConfig) error {
	proto := &cfg.Server.Protocol
	cert := &cfg.Server.Certificate

	needsDomain := proto.TLS != "" || proto.QUIC != "" || proto.HTTPS.Port != "" || proto.HTTP3.Port != "" ||
		proto.TLCP != "" || proto.HTTPTLCP.Port != "" || proto.DTLS != "" || proto.DTLCP != "" || proto.DNSCrypt != ""
	if !needsDomain {
		return nil
	}

	if cert.Domain == "" {
		return errors.New("config: certificate.domain is required when secure protocols (tls/quic/https/http3/tlcp/http_tlcp/dtls/dtlcp/dnscrypt) are enabled")
	}
	return nil
}
