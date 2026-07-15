package tls

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"time"
	"zjdns/config"

	"github.com/cloudflare/circl/ecc/p384"
	eTLS "gitlab.com/go-extension/tls"
)

// generateSelfSignedCert creates a self-signed ECC P-384 CA and a server
// certificate for the given domain, suitable for DoT and DoH use.
func generateSelfSignedCert(domain string) (eTLS.Certificate, error) {
	caPrivKey, err := ecdsa.GenerateKey(p384.P384(), rand.Reader)
	if err != nil {
		return eTLS.Certificate{}, fmt.Errorf("generate CA EC key: %w", err)
	}

	serverPrivKey, err := ecdsa.GenerateKey(p384.P384(), rand.Reader)
	if err != nil {
		return eTLS.Certificate{}, fmt.Errorf("generate server EC key: %w", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	caSerialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return eTLS.Certificate{}, fmt.Errorf("generate CA serial number: %w", err)
	}

	serverSerialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return eTLS.Certificate{}, fmt.Errorf("generate server serial number: %w", err)
	}

	caTemplate := x509.Certificate{
		SerialNumber: caSerialNumber,
		Subject: pkix.Name{
			CommonName:   "ZJDNS ECC Domain Secure Site CA",
			Organization: []string{"ZJDNS"},
			Country:      []string{"CN"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(config.DefaultCACertValidity),
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
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(config.DefaultServerCertValidity),
		KeyUsage:    x509.KeyUsageDigitalSignature, // ECDSA — KeyEncipherment is RSA-only
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(domain); ip != nil {
		serverTemplate.IPAddresses = []net.IP{ip}
	} else {
		serverTemplate.DNSNames = []string{domain}
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return eTLS.Certificate{}, fmt.Errorf("create CA certificate: %w", err)
	}

	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return eTLS.Certificate{}, fmt.Errorf("parse CA certificate: %w", err)
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &serverTemplate, caCert, &serverPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return eTLS.Certificate{}, fmt.Errorf("create server certificate: %w", err)
	}

	cert := eTLS.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  serverPrivKey,
	}

	return cert, nil
}
