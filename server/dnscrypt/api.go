package dnscrypt

import (
	"net"
	"time"
)

// Public API for use by external packages (e.g., server/client).

// EncryptedQuery wraps the encrypted query parameters for client use.
type EncryptedQuery struct {
	ESVersion   CryptoConstruction
	ClientMagic [ClientMagicSize]byte
	ClientPk    [KeySize]byte

	// PQ fields — only used when ESVersion.IsPQ().
	PQCiphertext  []byte // X-Wing ciphertext (1120 bytes) for initial queries
	PQTicket      []byte // Resumption ticket for resumed queries
	PQCertContext []byte // HKDF cert context for key binding
}

// EncryptedResponse wraps the encrypted response parameters for client use.
type EncryptedResponse struct {
	ESVersion CryptoConstruction
}

// EncryptQuery encrypts a DNS query packet for sending to a DNSCrypt server.
func EncryptQuery(q *EncryptedQuery, packet []byte, sharedKey [SharedKeySize]byte) (encrypted []byte, clientNonce Nonce, err error) {
	eq := &encryptedQuery{
		esVersion:   q.ESVersion,
		clientMagic: q.ClientMagic,
		clientPk:    q.ClientPk,
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
	return er.decrypt(response, sharedKey, clientNonce)
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

// PQDecapsulate wraps xwing.Decapsulate for external callers.
func PQDecapsulate(ct, sk []byte) []byte {
	return pqDecapsulate(ct, sk)
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

// NewPqResumptionState creates a new PQ resumption state for client use.
func NewPqResumptionState() *pqResumptionState {
	return newPqResumptionState()
}

// PQParseControlBlock extracts the ticket and lifetime from a PQ response
// control block.
func PQParseControlBlock(control []byte) (ticket []byte, lifetime uint32, err error) {
	return pqParseControlBlock(control)
}

// PQResumptionStore stores a resumption ticket in the given state.
func PQResumptionStore(s *pqResumptionState, ticket []byte, resumeSecret [SharedKeySize]byte, expiry time.Time, epoch uint64) {
	s.store(ticket, resumeSecret, expiry, epoch)
}

// PQResumptionGet retrieves a valid resumption ticket from the given state.
func PQResumptionGet(s *pqResumptionState, currentEpoch uint64) (ticket []byte, resumeSecret [SharedKeySize]byte, ok bool) {
	return s.get(currentEpoch)
}

// PQParseResumedHeader extracts ticket and nonce from a resumed PQ query
// wire format.
func PQParseResumedHeader(query []byte) (ticket, nonceHalf []byte, payloadOffset int, err error) {
	return parsePQResumedHeader(query)
}
