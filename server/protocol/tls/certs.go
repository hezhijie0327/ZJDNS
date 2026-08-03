package tls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"time"
	"zjdns/config"

	eTLS "gitlab.com/go-extension/tls"
)

// generateSelfSignedCert creates a self-signed ECC P-384 CA and a server
// certificate for the given domain, suitable for DoT and DoH use.
func generateSelfSignedCert(domain string) (eTLS.Certificate, error) {
	caPrivKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return eTLS.Certificate{}, fmt.Errorf("generate CA EC key: %w", err)
	}

	serverPrivKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
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

	// Evaluate now once: separate time.Now() calls per template would make
	// the CA's NotAfter always slightly earlier than the leaf's even with
	// equal validity durations.
	now := time.Now()
	caNotAfter := now.Add(config.DefaultCACertValidity)

	caTemplate := x509.Certificate{
		SerialNumber: caSerialNumber,
		Subject: pkix.Name{
			CommonName:   config.DefaultProjectName + " ECC Self-Signed Secure DNS CA",
			Organization: []string{config.DefaultProjectName},
			Country:      []string{"CN"},
		},
		NotBefore:             now,
		NotAfter:              caNotAfter,
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
		NotBefore: now,
		// The leaf must never outlive its signer: clamp to the CA's expiry
		// even if DefaultServerCertValidity ever exceeds
		// DefaultCACertValidity — an untrusted chain before the advertised
		// leaf expiry would be worse than an early rotation.
		NotAfter:    leafNotAfter(now, caNotAfter),
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

// leafNotAfter returns the leaf certificate's expiry: the configured server
// validity clamped to the CA's expiry so the leaf never outlives its signer.
func leafNotAfter(now, caNotAfter time.Time) time.Time {
	leaf := now.Add(config.DefaultServerCertValidity)
	if caNotAfter.Before(leaf) {
		return caNotAfter
	}
	return leaf
}
