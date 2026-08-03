package tlcp

import (
	"crypto/rand"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"time"
	"zjdns/config"

	"gitee.com/Trisia/gotlcp/dtlcp"
	"gitee.com/Trisia/gotlcp/tlcp"
	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"
)

// generateSelfSignedSMCerts creates a self-signed SM2 CA and two server
// certificates (signing + encryption) for both TLCP (TCP) and DTLCP (UDP) use.
func generateSelfSignedSMCerts(domain string) (signCert, encCert tlcp.Certificate, dtlcpSignCert, dtlcpEncCert dtlcp.Certificate, err error) {
	caKey, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		err = fmt.Errorf("generate CA SM2 key: %w", err)
		return signCert, encCert, dtlcpSignCert, dtlcpEncCert, err
	}
	signKey, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		err = fmt.Errorf("generate sign SM2 key: %w", err)
		return signCert, encCert, dtlcpSignCert, dtlcpEncCert, err
	}
	encKey, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		err = fmt.Errorf("generate enc SM2 key: %w", err)
		return signCert, encCert, dtlcpSignCert, dtlcpEncCert, err
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	caSerial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		err = fmt.Errorf("generate CA serial: %w", err)
		return signCert, encCert, dtlcpSignCert, dtlcpEncCert, err
	}
	signSerial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		err = fmt.Errorf("generate sign serial: %w", err)
		return signCert, encCert, dtlcpSignCert, dtlcpEncCert, err
	}
	encSerial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		err = fmt.Errorf("generate enc serial: %w", err)
		return signCert, encCert, dtlcpSignCert, dtlcpEncCert, err
	}

	caTemplate := &smx509.Certificate{
		SerialNumber: caSerial,
		Subject: pkix.Name{
			CommonName:   config.DefaultProjectName + " SM2 Self-Signed Secure DNS CA",
			Organization: []string{config.DefaultProjectName},
			Country:      []string{"CN"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(config.DefaultCACertValidity),
		KeyUsage:              smx509.KeyUsageDigitalSignature | smx509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            1,
	}
	// Modern clients verify hostnames/IPs against the SubjectAltName
	// (RFC 6125) and ignore CN — certs without SANs fail every verification.
	// Clamp the leaf validity to the CA's NotAfter: a leaf issued after the
	// CA expires breaks the chain. With equal constants today the clamp is a
	// no-op; it keeps the invariant if DefaultCACertValidity is ever lowered
	// (mirrors server/protocol/tls/certs.go's leafNotAfter).
	leafNotAfter := time.Now().Add(config.DefaultServerCertValidity)
	if caNotAfter := time.Now().Add(config.DefaultCACertValidity); leafNotAfter.After(caNotAfter) {
		leafNotAfter = caNotAfter
	}
	serverTemplate := func(keyUsage smx509.KeyUsage) *smx509.Certificate {
		tmpl := &smx509.Certificate{
			SerialNumber: new(big.Int),
			Subject:      pkix.Name{CommonName: config.DefaultProjectName + " TLCP"},
			NotBefore:    time.Now(),
			NotAfter:     leafNotAfter,
			KeyUsage:     keyUsage,
			ExtKeyUsage:  []smx509.ExtKeyUsage{smx509.ExtKeyUsageServerAuth},
		}
		if domain != "" {
			tmpl.DNSNames = []string{domain}
			if ip := net.ParseIP(domain); ip != nil {
				tmpl.IPAddresses = []net.IP{ip}
			}
		}
		return tmpl
	}

	caDER, err := smx509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		err = fmt.Errorf("create CA cert: %w", err)
		return signCert, encCert, dtlcpSignCert, dtlcpEncCert, err
	}
	caCert, err := smx509.ParseCertificate(caDER)
	if err != nil {
		err = fmt.Errorf("parse CA cert: %w", err)
		return signCert, encCert, dtlcpSignCert, dtlcpEncCert, err
	}

	signTmpl := serverTemplate(smx509.KeyUsageDigitalSignature)
	signTmpl.SerialNumber = signSerial
	signDER, err := smx509.CreateCertificate(rand.Reader, signTmpl, caCert, &signKey.PublicKey, caKey)
	if err != nil {
		err = fmt.Errorf("create sign cert: %w", err)
		return signCert, encCert, dtlcpSignCert, dtlcpEncCert, err
	}

	// The encryption certificate is presented for key agreement/key
	// transport (GM/T 0024) — strict peers validate key usage on it.
	encTmpl := serverTemplate(smx509.KeyUsageKeyAgreement | smx509.KeyUsageKeyEncipherment | smx509.KeyUsageDataEncipherment)
	encTmpl.SerialNumber = encSerial
	encDER, err := smx509.CreateCertificate(rand.Reader, encTmpl, caCert, &encKey.PublicKey, caKey)
	if err != nil {
		err = fmt.Errorf("create enc cert: %w", err)
		return signCert, encCert, dtlcpSignCert, dtlcpEncCert, err
	}

	// Include the self-signed CA in the served chain so clients can validate
	// the leaf; the CA is also returned for persistence/distribution.
	signCert = tlcp.Certificate{
		Certificate: [][]byte{signDER, caDER},
		PrivateKey:  signKey,
	}
	encCert = tlcp.Certificate{
		Certificate: [][]byte{encDER, caDER},
		PrivateKey:  encKey,
	}
	dtlcpSignCert = dtlcp.Certificate{
		Certificate: [][]byte{signDER, caDER},
		PrivateKey:  signKey,
	}
	dtlcpEncCert = dtlcp.Certificate{
		Certificate: [][]byte{encDER},
		PrivateKey:  encKey,
	}
	return signCert, encCert, dtlcpSignCert, dtlcpEncCert, err
}
