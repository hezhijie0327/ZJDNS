package dnscryptcrypto

import (
	"crypto/rand"
)

// Prior to encryption, queries are padded using the ISO/IEC 7816-4 format.
// The padding starts with a byte valued 0x80 followed by a variable number
// of NUL bytes.
//
// Pad() pads to at least minLen bytes (must be a multiple of 64; 0 = align
// to next 64-byte boundary).  The caller is responsible for choosing an
// appropriate minimum: 256 for UDP anti-amplification, 0 for TCP.

// pad applies ISO/IEC 7816-4 padding to the packet.  minLen is the minimum
// total padded length; when zero it defaults to the next multiple of 64.
// minLen must be a multiple of 64 (caller's responsibility).
func Pad(packet []byte, minLen int) (padded []byte) {
	// Closest multiple of 64 >= (len(packet) + 1).
	minSize := max(minLen, len(packet)+1+(64-(len(packet)+1)%64)%64)

	packet = append(packet, 0x80)
	if n := minSize - len(packet); n > 0 {
		packet = append(packet, make([]byte, n)...)
	}

	return packet
}

// padTCP applies ISO/IEC 7816-4 padding with a randomly chosen length for
// client queries over TCP, per §5.4.3 of draft-denis-dprive-dnscrypt-10.
// The padding length is randomly selected from 1 to 256 bytes (including the
// leading 0x80), and the total length is rounded up to a multiple of 64.
func PadTCP(packet []byte) (padded []byte) {
	// Pick a random padding length between 1 and 256 bytes (incl. 0x80).
	padLen := 1 + CryptoRandIntn(256)
	packet = append(packet, 0x80)
	if padLen > 1 {
		padding := make([]byte, padLen-1)
		packet = append(packet, padding...)
	}
	// Round up to multiple of 64.
	for len(packet)&63 != 0 {
		packet = append(packet, 0)
	}
	return packet
}

// CryptoRandIntn returns a cryptographic random integer in [0, n).
// n must be a power of 2 and ≤ 256.  The function uses a simple mask (not
// rejection sampling), so non-power-of-2 n would produce biased output.
func CryptoRandIntn(n int) int {
	if n <= 0 || n > 256 || n&(n-1) != 0 {
		panic("CryptoRandIntn: n must be a power of 2 ≤ 256")
	}
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	// Simple rejection sampling; n <= 256 so bias is negligible.
	return int(uint64(b[0])|uint64(b[1])<<8) % n //nolint:gosec // G115: n <= 256, result fits in int
}

// PadWithin is like Pad but never exceeds maxLen.  When the padded packet
// would exceed maxLen, the padding shrinks down to the lone 0x80 delimiter.
// Returns ErrNoRoomForPadding when even the delimiter would not fit — the
// caller should either withhold optional data (e.g. a PQ ticket) or truncate
// the DNS response.
func PadWithin(packet []byte, minLen, maxLen int) ([]byte, error) {
	if len(packet) >= maxLen {
		return nil, ErrNoRoomForPadding
	}
	padded := Pad(packet, minLen)
	if len(padded) > maxLen {
		padded = padded[:maxLen]
	}
	return padded, nil
}

// unpad removes ISO/IEC 7816-4 padding from the packet.
func UnPad(packet []byte) (unpadded []byte, err error) {
	for i := len(packet); ; {
		if i == 0 {
			return nil, ErrInvalidPadding
		}
		i--
		if packet[i] == 0x80 {
			if i < MinDNSPacketSize {
				return nil, ErrInvalidPadding
			}
			return packet[:i], nil
		} else if packet[i] != 0x00 {
			return nil, ErrInvalidPadding
		}
	}
}

// computeSharedKey derives the shared secret key from the X25519 keypair using
// the specified cryptographic construction.
func ComputeSharedKey(
	cryptoConstruction CryptoConstruction,
	secretKey *[KeySize]byte,
	publicKey *[KeySize]byte,
) (sharedKey [SharedKeySize]byte, err error) {
	switch cryptoConstruction {
	case XChacha20Poly1305:
		sk, err := XchachaSharedKey(*secretKey, *publicKey)
		if err != nil {
			return sharedKey, err
		}
		return sk, nil
	case XWingPQ:
		// PQ uses separate KEM (X-Wing) — shared key is derived from
		// decapsulation, not from X25519.  Callers must use pqDecapsulate
		// and pqDeriveSharedKey instead.
		return [SharedKeySize]byte{}, ErrESVersion
	default:
		return [SharedKeySize]byte{}, ErrESVersion
	}
}
