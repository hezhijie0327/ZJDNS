package tlcp

import (
	"crypto/rand"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"time"
	"zjdns/config"

	"gitee.com/Trisia/gotlcp/dtlcp"
	"gitee.com/Trisia/gotlcp/tlcp"
	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"
)

// generateSelfSignedSMCerts creates a self-signed SM2 CA and two server
// certificates (signing + encryption) for both TLCP (TCP) and DTLCP (UDP) use.
func generateSelfSignedSMCerts() (signCert, encCert tlcp.Certificate, dtlcpSignCert, dtlcpEncCert dtlcp.Certificate, err error) {
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
		return signCert, encCert, dtlcpSignCert, dtlcpEncCert, err
	}
	caCert, _ := smx509.ParseCertificate(caDER)

	signSerial.Set(signSerial)
	signTmpl := serverTemplate()
	signTmpl.SerialNumber = signSerial
	signDER, err := smx509.CreateCertificate(rand.Reader, signTmpl, caCert, &signKey.PublicKey, caKey)
	if err != nil {
		err = fmt.Errorf("create sign cert: %w", err)
		return signCert, encCert, dtlcpSignCert, dtlcpEncCert, err
	}

	encSerial.Set(encSerial)
	encTmpl := serverTemplate()
	encTmpl.SerialNumber = encSerial
	encDER, err := smx509.CreateCertificate(rand.Reader, encTmpl, caCert, &encKey.PublicKey, caKey)
	if err != nil {
		err = fmt.Errorf("create enc cert: %w", err)
		return signCert, encCert, dtlcpSignCert, dtlcpEncCert, err
	}

	signCert = tlcp.Certificate{
		Certificate: [][]byte{signDER},
		PrivateKey:  signKey,
	}
	encCert = tlcp.Certificate{
		Certificate: [][]byte{encDER},
		PrivateKey:  encKey,
	}
	dtlcpSignCert = dtlcp.Certificate{
		Certificate: [][]byte{signDER},
		PrivateKey:  signKey,
	}
	dtlcpEncCert = dtlcp.Certificate{
		Certificate: [][]byte{encDER},
		PrivateKey:  encKey,
	}
	return signCert, encCert, dtlcpSignCert, dtlcpEncCert, err
}
