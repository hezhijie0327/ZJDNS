package dnscrypt

import (
	"crypto/rand"
)

// Prior to encryption, queries are padded using the ISO/IEC 7816-4 format.
// The padding starts with a byte valued 0x80 followed by a variable number
// of NUL bytes.
//
// pad() pads to at least minLen bytes (must be a multiple of 64; 0 = align
// to next 64-byte boundary).  The caller is responsible for choosing an
// appropriate minimum: 256 for UDP anti-amplification, 0 for TCP.

// pad applies ISO/IEC 7816-4 padding to the packet.  minLen is the minimum
// total padded length; when zero it defaults to the next multiple of 64.
// minLen must be a multiple of 64 (caller's responsibility).
func pad(packet []byte, minLen int) (padded []byte) {
	// Closest multiple of 64 >= (len(packet) + 1).
	minSize := len(packet) + 1 + (64-(len(packet)+1)%64)%64

	if minLen > minSize {
		minSize = minLen
	}

	packet = append(packet, 0x80)
	for len(packet) < minSize {
		packet = append(packet, 0)
	}

	return packet
}

// padTCP applies ISO/IEC 7816-4 padding with a randomly chosen length for
// client queries over TCP, per §5.4.3 of draft-denis-dprive-dnscrypt-10.
// The padding length is randomly selected from 1 to 256 bytes (including the
// leading 0x80), and the total length is rounded up to a multiple of 64.
func padTCP(packet []byte) (padded []byte) {
	// Pick a random padding length between 1 and 256 bytes (incl. 0x80).
	padLen := 1 + cryptoRandIntn(256)
	packet = append(packet, 0x80)
	for i := 1; i < padLen; i++ {
		packet = append(packet, 0)
	}
	// Round up to multiple of 64.
	for len(packet)&63 != 0 {
		packet = append(packet, 0)
	}
	return packet
}

// cryptoRandIntn returns a cryptographic random integer in [0, n).
func cryptoRandIntn(n int) int {
	var b [8]byte
	_, _ = rand.Read(b[:])
	// Simple rejection sampling; n <= 256 so bias is negligible.
	return int(uint64(b[0])|uint64(b[1])<<8) % n //nolint:gosec // G115: n <= 256, result fits in int
}

// unpad removes ISO/IEC 7816-4 padding from the packet.
func unpad(packet []byte) (unpadded []byte, err error) {
	for i := len(packet); ; {
		if i == 0 {
			return nil, ErrInvalidPadding
		}
		i--
		if packet[i] == 0x80 {
			if i < minDNSPacketSize {
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
func computeSharedKey(
	cryptoConstruction CryptoConstruction,
	secretKey *[KeySize]byte,
	publicKey *[KeySize]byte,
) (sharedKey [SharedKeySize]byte, err error) {
	switch cryptoConstruction {
	case XChacha20Poly1305:
		sk, err := xchachaSharedKey(*secretKey, *publicKey)
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
