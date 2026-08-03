package dnscryptcrypto

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
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
	minSize := max(minLen, (len(packet)+1+63)&^63)

	packet = append(packet, 0x80)
	if n := minSize - len(packet); n > 0 {
		packet = append(packet, make([]byte, n)...)
	}

	return packet
}

// padTCP applies ISO/IEC 7816-4 padding with a randomly chosen length for
// client queries over TCP, per §5.4.3 of draft-denis-dprive-dnscrypt-11.
// The padding length is randomly selected from 1 to 256 bytes (including the
// leading 0x80), and the total length is rounded up to a multiple of 64.
func PadTCP(packet []byte) (padded []byte, err error) {
	// Pick a random padding length between 1 and 256 bytes (incl. 0x80).
	n, err := CryptoRandIntn(256)
	if err != nil {
		return nil, fmt.Errorf("CryptoRandIntn: %w", err)
	}
	padLen := 1 + n
	packet = append(packet, 0x80)
	if padLen > 1 {
		padding := make([]byte, padLen-1)
		packet = append(packet, padding...)
	}
	// Round up to multiple of 64.
	for len(packet)&63 != 0 {
		packet = append(packet, 0)
	}
	return packet, nil
}

// PadResponse deterministically pads a server response per §5.4.5 of
// draft-denis-dprive-dnscrypt-11.  The padding length is derived from
// SHA-256(sharedKey || clientNonce) so that retransmitted queries receive
// identically padded responses — preventing padding from becoming a
// linkable server behaviour.  Matches encrypted-dns-server's SipHash-based
// approach (crypto.rs encrypt_into).
func PadResponse(packet []byte, sharedKey *[SharedKeySize]byte, clientNonce []byte) []byte {
	if sharedKey == nil {
		return packet
	}
	h := sha256.Sum256(append(sharedKey[:], clientNonce...))
	padSize := 1 + int(h[0])                     // 1–256 bytes (§5.4.5)
	target := (len(packet) + padSize + 63) &^ 63 // next 64-byte boundary
	packet = append(packet, 0x80)
	packet = append(packet, make([]byte, target-len(packet))...)
	return packet
}

// PadResponseWithin is like PadResponse but never grows the plaintext beyond
// maxLen: when the preferred size does not fit, the padding shrinks, down to
// the lone 0x80 delimiter.  Fails when even that one byte would not fit.
// Ref: encrypted-dns-server pq.rs pad7816_within().
func PadResponseWithin(packet []byte, sharedKey *[SharedKeySize]byte, clientNonce []byte, maxLen int) ([]byte, error) {
	if sharedKey == nil {
		return nil, errors.New("dnscrypt: nil shared key")
	}
	if len(packet) >= maxLen {
		return nil, ErrNoRoomForPadding
	}
	h := sha256.Sum256(append(sharedKey[:], clientNonce...))
	padSize := 1 + int(h[0])
	target := min((len(packet)+padSize+63)&^63, maxLen)
	packet = append(packet, 0x80)
	packet = append(packet, make([]byte, target-len(packet))...)
	return packet, nil
}

// CryptoRandIntn returns a cryptographic random integer in [0, n).
// n must be a power of 2 and ≤ 256.  Returns an error if n is invalid.
// Uses modulo reduction (equivalent to masking for power-of-2 n).
func CryptoRandIntn(n int) (int, error) {
	if n <= 0 || n > 256 || n&(n-1) != 0 {
		return 0, errors.New("CryptoRandIntn: n must be a power of 2 ≤ 256")
	}
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, fmt.Errorf("crypto rand read failed: %w", err)
	}
	// Simple modulo reduction; n <= 256 so bias is negligible.
	return int(uint64(b[0])|uint64(b[1])<<8) % n, nil //nolint:gosec // G115: n <= 256, result fits in int
}

// encryptPadding computes the target wire query size and pads the plaintext
// DNS packet so the encrypted query reaches that size.  Aligned with
// dnscrypt-proxy's dynamic sizing:
//
//	minWire = roundup64(max(minWireSize, QueryOverhead + len(packet) + 1))
//	targetWire = min(minWire, MaxDNSUDPPacketSize)
//	paddedLen  = min(targetWire - QueryOverhead, roundup64(len(packet)+1))
//
// The +1 accounts for the 0x80 padding delimiter (ISO/IEC 7816-4).
//
// Ref: dnscrypt-proxy crypto.go Encrypt() — paddedLength formula
func encryptPadding(packet []byte, minWireSize int) []byte {
	minWire := max(
		// +1 for 0x80 delimiter
		minWireSize, QueryOverhead+len(packet)+1)
	minWire = min((minWire+63)&^63, MaxDNSUDPPacketSize)
	// The final padding must not push the sealed UDP query past the cap:
	// Pad re-rounds len(packet)+1 up to the next 64-byte boundary, so the
	// requested length is clamped to MaxDNSUDPPacketSize - QueryOverhead.
	paddedLen := min(max(minWire-QueryOverhead, (len(packet)+1+63)&^63), MaxDNSUDPPacketSize-QueryOverhead)
	return Pad(packet, paddedLen)
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
	if secretKey == nil || publicKey == nil {
		return [SharedKeySize]byte{}, errors.New("dnscrypt: nil key parameter")
	}
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
