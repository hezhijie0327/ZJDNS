package tls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	eTLS "gitlab.com/go-extension/tls"
)

// countConn counts socket bytes received from the peer — on the client side
// of a handshake that is the server flight, whose size shrinks when the
// certificate message is compressed.
type countConn struct {
	net.Conn
	read int
}

func (c *countConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.read += n
	return n, err
}

// newRFC8879Server builds a production Server whose certificate is large
// enough for compression to be visible in the flight size: 96 repetitive
// DNS SANs (~2.5 KB DER that compresses well).
func newRFC8879Server(t *testing.T) *Server {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "rfc8879.test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	for i := range 96 {
		tmpl.DNSNames = append(tmpl.DNSNames, fmt.Sprintf("host%03d.rfc8879.test", i))
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	certPath := filepath.Join(t.TempDir(), "cert.pem")
	keyPath := filepath.Join(t.TempDir(), "key.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	srv, err := New(rfc8998TestHandler{}, &Config{Domain: "rfc8879.test", CertFile: certPath, KeyFile: keyPath})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	return srv
}

// handshakeCounted connects with clientCfg through a byte-counting conn and
// returns the number of server-flight bytes read during the handshake.
func handshakeCounted(t *testing.T, addr net.Addr, clientCfg *eTLS.Config) int {
	t.Helper()
	raw, err := net.Dial("tcp", addr.String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = raw.Close() }()
	cc := &countConn{Conn: raw}
	cli := eTLS.Client(cc, clientCfg)
	if err := cli.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	return cc.read
}

// TestServerCompressesCertificateRFC8879 pins the inbound side of RFC 8879
// against the production base config: a client that advertises
// compress_certificate must receive a smaller server flight than a client
// that does not. AllSupportedExtensions puts the extension on the wire and
// the default eTLS preferences (zlib/brotli/zstd) drive server-side
// compression — no per-feature switch exists, this is default-on.
func TestServerCompressesCertificateRFC8879(t *testing.T) {
	srv := newRFC8879Server(t)
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = raw.Close() }()
	ln := eTLS.NewListener(raw, srv.baseTLSConfig)

	serveOnce := func() {
		go func() {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.(*eTLS.Conn).Handshake()
			_ = conn.Close()
		}()
	}

	compressing := &eTLS.Config{
		MinVersion:             eTLS.VersionTLS13,
		ServerName:             "rfc8879.test",
		InsecureSkipVerify:     true, //nolint:gosec // self-signed test certificate
		Defaults:               eTLS.Defaults{AllSupportedExtensions: true},
		SessionTicketsDisabled: true,
	}
	// The default extension list omits compress_certificate, so the server
	// must answer this client with an uncompressed Certificate message.
	// Built literally — eTLS.Config embeds a mutex and must not be copied.
	plain := &eTLS.Config{
		MinVersion:             eTLS.VersionTLS13,
		ServerName:             "rfc8879.test",
		InsecureSkipVerify:     true, //nolint:gosec // self-signed test certificate
		SessionTicketsDisabled: true,
	}

	serveOnce()
	compressed := handshakeCounted(t, ln.Addr(), compressing)
	serveOnce()
	uncompressed := handshakeCounted(t, ln.Addr(), plain)

	if compressed >= uncompressed {
		t.Errorf("server flight with compress_certificate advertised (%d B) >= without (%d B) — RFC 8879 compression not in effect", compressed, uncompressed)
	}
	t.Logf("server flight: %d B compressed vs %d B uncompressed (%d SAN certificate)", compressed, uncompressed, 96)
}
