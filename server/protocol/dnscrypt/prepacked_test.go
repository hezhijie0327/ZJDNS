package dnscrypt

import (
	"bytes"
	"net/netip"
	"testing"

	dnscryptcrypto "zjdns/internal/dnscryptcrypto"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"
)

// TestEncrypt_PrePackedResponse covers C2: a pre-packed cache-hit response
// (Data carries the full wire, RR sections nil) must be encrypted with its
// complete content.  Previously encrypt() unconditionally called m.Pack(),
// which rebuilt from the empty RR fields — truncating the response to
// header+question before encryption.
//
// The assertion is a decrypt round-trip against the client-side shared key:
// the pre-packed plaintext must be byte-identical to the fields path
// plaintext, and at least as long as the original wire.
func TestEncrypt_PrePackedResponse(t *testing.T) {
	srv, err := New(testCfg(), "0", "2.dnscrypt-cert.example.com", nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Client keypair + shared key (client-side derivation: X25519(clientSk,
	// resolverPk) — the same shared secret the server derives).
	clientSk, clientPk, err := dnscryptcrypto.GenerateRandomKeyPair()
	if err != nil {
		t.Fatalf("GenerateRandomKeyPair: %v", err)
	}
	sharedKey, err := dnscryptcrypto.ComputeSharedKey(dnscryptcrypto.XChacha20Poly1305, &clientSk, &srv.current().Classical.ResolverPk)
	if err != nil {
		t.Fatalf("ComputeSharedKey: %v", err)
	}

	// Build the full response a resolver would produce on a cache miss.
	msg := new(dns.Msg)
	dnsutil.SetQuestion(msg, "www.example.com.", dns.TypeA)
	msg.Response = true
	msg.RecursionAvailable = true
	msg.Answer = []dns.RR{
		&dns.A{Hdr: dns.Header{Name: "www.example.com.", Class: dns.ClassINET, TTL: 300}, A: rdata.A{Addr: netip.MustParseAddr("192.0.2.1")}},
		&dns.A{Hdr: dns.Header{Name: "www.example.com.", Class: dns.ClassINET, TTL: 300}, A: rdata.A{Addr: netip.MustParseAddr("192.0.2.2")}},
	}
	if err := msg.Pack(); err != nil {
		t.Fatalf("pack response: %v", err)
	}
	wire := msg.Data

	// Fields path (Data nil): the control — Pack rebuilds from the sections.
	fieldsMsg := new(dns.Msg)
	fieldsMsg.Question = msg.Question
	fieldsMsg.ID = msg.ID
	fieldsMsg.Response = true
	fieldsMsg.RecursionAvailable = true
	fieldsMsg.RecursionDesired = true // SetQuestion sets RD on the original
	fieldsMsg.Answer = msg.Answer

	// Pre-packed path: Data carries the wire, sections nil — exactly the
	// shape CacheLookup produces on a cache hit.
	prePacked := new(dns.Msg)
	prePacked.Data = wire

	query := &dnscryptcrypto.EncryptedQuery{
		ESVersion: dnscryptcrypto.XChacha20Poly1305,
		ClientPk:  clientPk,
		SharedKey: sharedKey,
	}
	// Client nonce half — any bytes; Encrypt randomizes the server half.
	copy(query.Nonce[:12], []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc})

	decrypt := func(enc []byte) []byte {
		t.Helper()
		var r dnscryptcrypto.EncryptedResponse
		r.ESVersion = dnscryptcrypto.XChacha20Poly1305
		packet, err := r.Decrypt(enc, sharedKey, query.Nonce)
		if err != nil {
			t.Fatalf("Decrypt: %v", err)
		}
		return packet
	}

	t.Run("TCP", func(t *testing.T) {
		encControl, err := srv.encrypt(fieldsMsg, query, false)
		if err != nil {
			t.Fatalf("encrypt (fields): %v", err)
		}
		encPrePacked, err := srv.encrypt(prePacked, query, false)
		if err != nil {
			t.Fatalf("encrypt (pre-packed): %v", err)
		}

		controlPacket := decrypt(encControl)
		prePackedPacket := decrypt(encPrePacked)
		if !bytes.Equal(controlPacket, prePackedPacket) {
			t.Errorf("pre-packed plaintext (%d bytes) != fields plaintext (%d bytes) — pre-packed response truncated (C2)",
				len(prePackedPacket), len(controlPacket))
		}
		if len(prePackedPacket) < len(wire) {
			t.Errorf("pre-packed plaintext %d bytes < full wire %d bytes", len(prePackedPacket), len(wire))
		}
	})

	t.Run("UDP", func(t *testing.T) {
		// Generous anti-amplification budget: 4096 bytes fits the response
		// plus padding, so no truncation should occur.
		udpQuery := *query
		udpQuery.ClientQueryLen = 4096

		encControl, err := srv.encrypt(fieldsMsg, &udpQuery, true)
		if err != nil {
			t.Fatalf("encrypt (fields, UDP): %v", err)
		}
		encPrePacked, err := srv.encrypt(prePacked, &udpQuery, true)
		if err != nil {
			t.Fatalf("encrypt (pre-packed, UDP): %v", err)
		}

		controlPacket := decrypt(encControl)
		prePackedPacket := decrypt(encPrePacked)
		if !bytes.Equal(controlPacket, prePackedPacket) {
			t.Errorf("UDP pre-packed plaintext (%d bytes) != fields plaintext (%d bytes) — pre-packed response truncated (C2)",
				len(prePackedPacket), len(controlPacket))
		}
		if len(prePackedPacket) < len(wire) {
			t.Errorf("UDP pre-packed plaintext %d bytes < full wire %d bytes", len(prePackedPacket), len(wire))
		}
	})
}
