// Package dnscrypt implements the DNSCrypt v2 protocol (draft-denis-dprive-dnscrypt).
//
// This package provides the full DNSCrypt protocol stack for both server-side
// (listener, certificate management, key rotation) and client-side (query
// encryption, response decryption) use.  The public API defined in this file
// is consumed by:
//
//   - server/upstream/dnscrypt — upstream client, uses crypto primitives
//   - server/server.go — server lifecycle (New, Start, Shutdown)
//   - cmd/zjdns/cli — sdns:// stamp configuration generator
//
// The dependency server/upstream/dnscrypt → server/protocol/dnscrypt is
// intentional: the protocol package acts as the canonical source of truth
// for DNSCrypt wire-format types, cryptographic constructions, and interop
// helpers shared between client and server.
package dnscrypt

import (
	"net"
)

// Public API — types and functions consumed by server/upstream/dnscrypt and
// other external packages.

// EncryptedQuery wraps the encrypted query parameters for client use.
type EncryptedQuery struct {
	ESVersion   CryptoConstruction
	ClientMagic [ClientMagicSize]byte
	ClientPk    [KeySize]byte

	// PQ fields — only used when ESVersion.IsPQ().
	PQCiphertext  []byte // X-Wing ciphertext (1120 bytes) for initial queries
	PQTicket      []byte // Resumption ticket for resumed queries
	PQCertContext []byte // HKDF cert context for key binding

	// ClientNonce is an optional pre-generated nonce.  When set (non-zero),
	// EncryptQuery uses it instead of generating a fresh one.  Callers
	// who need the nonce before encryption (e.g. to derive a resumed
	// PQ shared key) must set this field.
	ClientNonce Nonce

	// MinQueryLen is the minimum padded query length for UDP queries.  It
	// must be a multiple of 64.  Per §5.4.2 of draft-denis-dprive-dnscrypt-10,
	// clients escalate this by 64 bytes on each truncated response to reduce
	// fragmentation risk.  Zero means use the default (256).
	MinQueryLen int

	// IsTCP indicates the query will be sent over TCP.  When true, padding
	// uses the random-length TCP profile (§5.4.3) instead of the UDP
	// anti-amplification minimum.
	IsTCP bool
}

// EncryptedResponse wraps the encrypted response parameters for client use.
type EncryptedResponse struct {
	ESVersion CryptoConstruction

	// PQControl is the raw response control block carrying a resumption
	// ticket.  Only set for PQ responses from servers that issued a ticket.
	PQControl []byte
}

// EncryptQuery encrypts a DNS query packet for sending to a DNSCrypt server.
func EncryptQuery(q *EncryptedQuery, packet []byte, sharedKey [SharedKeySize]byte) (encrypted []byte, clientNonce Nonce, err error) {
	eq := &encryptedQuery{
		esVersion:   q.ESVersion,
		clientMagic: q.ClientMagic,
		clientPk:    q.ClientPk,
		nonce:       q.ClientNonce,
		minQueryLen: q.MinQueryLen,
		isTCP:       q.IsTCP,
	}
	if q.ESVersion.IsPQ() {
		eq.pqCiphertext = q.PQCiphertext
		eq.pqTicket = q.PQTicket
		eq.pqCertContext = q.PQCertContext
	}
	return eq.encrypt(packet, sharedKey)
}

// DecryptResponse decrypts a DNSCrypt server response.
func DecryptResponse(r *EncryptedResponse, response []byte, sharedKey [SharedKeySize]byte, clientNonce Nonce) (packet []byte, err error) {
	er := &encryptedResponse{
		esVersion: r.ESVersion,
	}
	packet, err = er.decrypt(response, sharedKey, clientNonce)
	if err != nil {
		return nil, err
	}
	r.PQControl = er.pqControl
	return packet, nil
}

// ComputeSharedKey computes the shared secret from a key pair.
func ComputeSharedKey(esVersion CryptoConstruction, secretKey, publicKey *[KeySize]byte) ([SharedKeySize]byte, error) {
	return computeSharedKey(esVersion, secretKey, publicKey)
}

// GenerateKeyPairRaw generates a new X25519 key pair and returns the raw byte
// arrays.
func GenerateKeyPairRaw() (secretKey, publicKey [KeySize]byte) {
	return generateRandomKeyPair()
}

// ReadPrefixed reads a 2-byte length-prefixed message from a net.Conn.
func ReadPrefixed(conn net.Conn) ([]byte, error) {
	return readPrefixed(conn)
}

// WritePrefixed writes a byte slice with a 2-byte length prefix to a net.Conn.
func WritePrefixed(b []byte, conn net.Conn) error {
	return writePrefixed(b, conn)
}

// UnpackTxtString unpacks a DNS TXT record value into binary.
func UnpackTxtString(s string) []byte {
	return unpackTxtString(s)
}

// PQEncapsulate wraps xwing.Encapsulate for external callers.
func PQEncapsulate(pk []byte) (kemSS, ct []byte, err error) {
	return pqEncapsulate(pk)
}

// PQGenKeyPair generates a new X-Wing key pair.
func PQGenKeyPair() (publicKey, privateKey []byte, err error) {
	return pqGenKeyPair()
}

// PQDeriveSharedKey derives the shared key for a PQ query carrying an X-Wing
// ciphertext.
func PQDeriveSharedKey(kemSS []byte, clientMagic [ClientMagicSize]byte, certContext, ct []byte) [SharedKeySize]byte {
	return pqDeriveSharedKey(kemSS, clientMagic, certContext, ct)
}

// PQResumeSecret derives the resumption secret from a PQ shared key.
func PQResumeSecret(sharedKey [SharedKeySize]byte, clientMagic [ClientMagicSize]byte, clientNonce []byte) [SharedKeySize]byte {
	return pqResumeSecret(sharedKey, clientMagic, clientNonce)
}

// PQResumedSharedKey derives the per-query key for a resumed PQ query.
func PQResumedSharedKey(resumeSecret [SharedKeySize]byte, clientMagic [ClientMagicSize]byte, clientNonce, ticket []byte) [SharedKeySize]byte {
	return pqResumedSharedKey(resumeSecret, clientMagic, clientNonce, ticket)
}

// PQParseControlBlock extracts the ticket and lifetime from a PQ response
// control block.
func PQParseControlBlock(control []byte) (ticket []byte, lifetime uint32, err error) {
	return pqParseControlBlock(control)
}
