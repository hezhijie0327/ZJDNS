package dnscrypt

import (
	"golang.org/x/crypto/nacl/box"
)

// Prior to encryption, queries are padded using the ISO/IEC 7816-4 format.
// The padding starts with a byte valued 0x80 followed by a variable number
// of NUL bytes.
//
// For UDP: the padded length must be at least minUDPQuestionSize (256 bytes)
// and must be a multiple of 64 bytes.
//
// For TCP: the padding length is randomly chosen between 1 and 256 bytes
// (including the leading 0x80), and the total length must be a multiple of
// 64 bytes.

// pad applies ISO/IEC 7816-4 padding to the packet.
func pad(packet []byte) (padded []byte) {
	// Closest multiple of 64 >= (len(packet) + 1).
	minSize := len(packet) + 1 + (64-(len(packet)+1)%64)%64

	if minUDPQuestionSize > minSize {
		minSize = minUDPQuestionSize
	}

	packet = append(packet, 0x80)
	for len(packet) < minSize {
		packet = append(packet, 0)
	}

	return packet
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
	case XSalsa20Poly1305:
		box.Precompute(&sharedKey, publicKey, secretKey)
		return sharedKey, nil
	default:
		return [SharedKeySize]byte{}, ErrESVersion
	}
}
