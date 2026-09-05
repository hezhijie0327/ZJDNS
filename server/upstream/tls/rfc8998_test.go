package tls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
	"zjdns/config"

	eTLS "gitlab.com/go-extension/tls"
)

// selfSignedETLSCert mints a throwaway ECDSA certificate for the SM-only
// test server.
func selfSignedETLSCert(t *testing.T) eTLS.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "upstream-sm-test.local"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"upstream-sm-test.local"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return eTLS.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// TestUpstreamClientNegotiatesRFC8998SM: the production upstream client
// config must complete a handshake against a server that accepts only an SM
// suite and CurveSM2 (RFC 8998 default-on). TCP loopback is used rather than
// net.Pipe — the synchronous pipe deadlocks the HelloRetryRequest flight.
func TestUpstreamClientNegotiatesRFC8998SM(t *testing.T) {
	c := &Client{}
	upstream := &config.UpstreamServer{
		Address:       "127.0.0.1:853",
		ServerName:    "upstream-sm-test.local",
		SkipTLSVerify: true, // self-signed test certificate
	}

	for _, suite := range []uint16{eTLS.TLS_SM4_GCM_SM3, eTLS.TLS_SM4_CCM_SM3} {
		t.Run(eTLS.CipherSuiteName(suite), func(t *testing.T) {
			serverCfg := &eTLS.Config{
				MinVersion:       eTLS.VersionTLS13,
				CipherSuites:     []uint16{suite},
				CurvePreferences: []eTLS.CurveID{eTLS.CurveSM2},
				Certificates:     []eTLS.Certificate{selfSignedETLSCert(t)},
			}
			ln, err := eTLS.Listen("tcp", "127.0.0.1:0", serverCfg)
			if err != nil {
				t.Fatalf("listen: %v", err)
			}
			defer func() { _ = ln.Close() }()

			srvErr := make(chan error, 1)
			go func() {
				conn, err := ln.Accept()
				if err != nil {
					srvErr <- err
					return
				}
				srvErr <- conn.(*eTLS.Conn).Handshake()
			}()

			client, err := eTLS.Dial("tcp", ln.Addr().String(), c.eTLSClientConfig(upstream))
			if err != nil {
				t.Fatalf("client handshake: %v", err)
			}
			if err := <-srvErr; err != nil {
				t.Fatalf("server handshake: %v", err)
			}
			state := client.ConnectionState()
			_ = client.Close()
			if state.CipherSuite != suite {
				t.Errorf("cipher = %s, want %s", eTLS.CipherSuiteName(state.CipherSuite), eTLS.CipherSuiteName(suite))
			}
			if state.CurveID != eTLS.CurveSM2 {
				t.Errorf("group = %s, want CurveSM2", state.CurveID)
			}
		})
	}
}
