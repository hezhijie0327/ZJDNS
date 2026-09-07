package tls

import (
	"encoding/binary"
	"net"
	"testing"
	"zjdns/config"

	eTLS "gitlab.com/go-extension/tls"
)

// readClientHello reads exactly one ClientHello record from a raw TCP conn
// and returns the handshake body (without record/handshake headers).
func readClientHello(t *testing.T, conn net.Conn) []byte {
	t.Helper()
	buf := make([]byte, 0, 4096)
	chunk := make([]byte, 4096)
	for {
		if len(buf) >= 5 {
			if recLen := int(binary.BigEndian.Uint16(buf[3:5])); len(buf) >= 5+recLen {
				rec := buf[5 : 5+recLen]
				if rec[0] != 0x01 {
					t.Fatalf("first handshake message type = %d, want ClientHello (1)", rec[0])
				}
				hsLen := int(rec[1])<<16 | int(rec[2])<<8 | int(rec[3])
				return rec[4 : 4+hsLen]
			}
		}
		n, err := conn.Read(chunk)
		buf = append(buf, chunk[:n]...)
		if err != nil {
			t.Fatalf("read ClientHello: %v", err)
		}
	}
}

// clientHelloCompressionAlgorithms walks the ClientHello extension list and
// returns the algorithms advertised in compress_certificate (RFC 8879),
// or nil when the extension is absent.
func clientHelloCompressionAlgorithms(hello []byte) []uint16 {
	pos := 2 + 32 // legacy_version + random
	pos += 1 + int(hello[pos])
	pos += 2 + int(binary.BigEndian.Uint16(hello[pos:pos+2]))
	pos += 1 + int(hello[pos])
	extEnd := pos + 2 + int(binary.BigEndian.Uint16(hello[pos:pos+2]))
	pos += 2
	for pos+4 <= extEnd {
		extType := binary.BigEndian.Uint16(hello[pos : pos+2])
		extLen := int(binary.BigEndian.Uint16(hello[pos+2 : pos+4]))
		if extType == 27 { // compress_certificate
			data := hello[pos+4 : pos+4+extLen]
			// RFC 8879 §4: the 1-byte prefix is the list length in BYTES
			// (2 per algorithm), not the algorithm count.
			listLen := int(data[0])
			algs := make([]uint16, 0, listLen/2)
			for off := 1; off+2 <= 1+listLen; off += 2 {
				algs = append(algs, binary.BigEndian.Uint16(data[off:off+2]))
			}
			return algs
		}
		pos += 4 + extLen
	}
	return nil
}

// TestUpstreamClientOffersCertCompression pins the outbound side of
// RFC 8879 at the byte level: the production eTLSClientConfig must
// advertise compress_certificate with zlib/brotli/zstd in its ClientHello,
// letting RFC 8879-capable DoH/DoT upstreams shrink their certificate
// flights to us.
func TestUpstreamClientOffersCertCompression(t *testing.T) {
	c := &Client{}
	upstream := &config.UpstreamServer{
		Address:       "127.0.0.1:853",
		ServerName:    "rfc8879.test",
		SkipTLSVerify: true,
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	handshakeErr := make(chan error, 1)
	go func() {
		// The raw listener never answers, so the handshake cannot complete —
		// only the ClientHello it emits matters here.
		cli, err := eTLS.Dial("tcp", ln.Addr().String(), c.eTLSClientConfig(upstream))
		if cli != nil {
			_ = cli.Close()
		}
		handshakeErr <- err
	}()

	srv, err := ln.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	hello := readClientHello(t, srv)
	_ = srv.Close()
	<-handshakeErr

	algs := clientHelloCompressionAlgorithms(hello)
	want := []uint16{uint16(eTLS.Zlib), uint16(eTLS.Brotli), uint16(eTLS.Zstd)}
	if len(algs) != len(want) {
		t.Fatalf("compress_certificate algorithms = %v, want %v (zlib/brotli/zstd)", algs, want)
	}
	for i, alg := range algs {
		if alg != want[i] {
			t.Fatalf("compress_certificate algorithms = %v, want %v (zlib/brotli/zstd)", algs, want)
		}
	}
}
