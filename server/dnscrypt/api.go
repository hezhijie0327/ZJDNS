package dnscrypt

import "net"

// Public API for use by external packages (e.g., server/client).

// EncryptedQuery wraps the encrypted query parameters for client use.
type EncryptedQuery struct {
	ESVersion   CryptoConstruction
	ClientMagic [ClientMagicSize]byte
	ClientPk    [KeySize]byte
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
