package dnscryptcrypto

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
	"time"

	"github.com/cloudflare/circl/dh/x25519"
	"github.com/cloudflare/circl/sign/ed25519"
)

// HexEncodeKey encodes a byte slice as an uppercase hex string.
func HexEncodeKey(b []byte) string {
	return strings.ToUpper(hex.EncodeToString(b))
}

// HexDecodeKey decodes a hex-encoded string (with optional colon separators)
// into a byte slice.
func HexDecodeKey(str string) ([]byte, error) {
	return hex.DecodeString(strings.ReplaceAll(str, ":", ""))
}

// GenerateRandomKeyPair generates a new X25519 key pair.
func GenerateRandomKeyPair() (secretKey, publicKey [KeySize]byte) {
	var sk, pk x25519.Key
	_, _ = rand.Read(sk[:])
	x25519.KeyGen(&pk, &sk)
	secretKey = [KeySize]byte(sk)
	publicKey = [KeySize]byte(pk)
	return secretKey, publicKey
}

// GenerateEd25519Keypair generates a new Ed25519 key pair for provider signing.
func GenerateEd25519Keypair() (publicKey, privateKey []byte, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return pub, priv, nil
}

// NowUnix32 returns the current Unix time as uint32.  The DNSCrypt protocol
// uses 32-bit timestamps throughout (certificates, tickets), and Unix epoch
// values fit in uint32 until year 2106.
func NowUnix32() uint32 {
	return uint32(time.Now().Unix()) //nolint:gosec // G115: see doc comment
}
