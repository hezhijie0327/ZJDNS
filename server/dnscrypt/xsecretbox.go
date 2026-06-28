package dnscrypt

import (
	"crypto/subtle"
	"fmt"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/poly1305" //nolint:staticcheck // NaCl secretbox construction
)

const (
	// xchachaKeySize is the XChaCha20 key size (32 bytes).
	xchachaKeySize = chacha20.KeySize

	// xchachaNonceSize is the XChaCha20 nonce size (24 bytes).
	xchachaNonceSize = chacha20.NonceSizeX

	// poly1305TagSize is the Poly1305 authentication tag size (16 bytes).
	poly1305TagSize = poly1305.TagSize
)

// xchachaSharedKey computes the XChacha20-Poly1305 shared key via X25519 ECDH
// followed by HChaCha20.  Equivalent to libsodium crypto_box_xchacha20poly1305
// key exchange.
func xchachaSharedKey(secretKey, publicKey *[KeySize]byte) (sharedKey [KeySize]byte, err error) {
	sk, err := curve25519.X25519(secretKey[:], publicKey[:])
	if err != nil {
		return sharedKey, fmt.Errorf("x25519: %w", err)
	}

	var zero byte
	for i := 0; i < KeySize; i++ {
		zero |= sk[i]
	}
	if zero == 0 {
		return sharedKey, fmt.Errorf("dnscrypt: weak x25519 public key")
	}

	var nonce [16]byte
	h, err := chacha20.HChaCha20(sk, nonce[:])
	if err != nil {
		return sharedKey, fmt.Errorf("hchacha20: %w", err)
	}
	copy(sharedKey[:], h)

	return sharedKey, nil
}

// XChachaSeal encrypts and authenticates message using XChaCha20-Poly1305.
// nonce must be xchachaNonceSize (24) bytes, key must be KeySize (32) bytes.
func XChachaSeal(out, nonce, message, key []byte) []byte {
	if len(nonce) != xchachaNonceSize || len(key) != xchachaKeySize {
		panic("xchachaSeal: invalid nonce or key size")
	}

	var firstBlock [64]byte
	cipher, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		panic(err)
	}
	cipher.XORKeyStream(firstBlock[:], firstBlock[:])

	var polyKey [KeySize]byte
	copy(polyKey[:], firstBlock[:KeySize])

	ret, tail := sliceForAppend(out, poly1305TagSize+len(message))

	firstMsgBlock := message
	if len(firstMsgBlock) > KeySize {
		firstMsgBlock = firstMsgBlock[:KeySize]
	}

	tagOut := tail
	out = tail[poly1305TagSize:]
	for i := range firstMsgBlock {
		out[i] = firstBlock[KeySize+i] ^ firstMsgBlock[i]
	}
	message = message[len(firstMsgBlock):]
	out = out[len(firstMsgBlock):]

	cipher.SetCounter(1)
	cipher.XORKeyStream(out, message)

	var tag [poly1305TagSize]byte
	hash := poly1305.New(&polyKey)
	_, _ = hash.Write(tagOut[poly1305TagSize:])
	hash.Sum(tag[:0])
	copy(tagOut, tag[:])

	return ret
}

// XChachaOpen decrypts and authenticates box using XChaCha20-Poly1305.
func XChachaOpen(out, nonce, box, key []byte) ([]byte, error) {
	if len(nonce) != xchachaNonceSize || len(key) != xchachaKeySize {
		panic("xchachaOpen: invalid nonce or key size")
	}
	if len(box) < poly1305TagSize {
		return nil, fmt.Errorf("dnscrypt: ciphertext too short")
	}

	var firstBlock [64]byte
	cipher, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		panic(err)
	}
	cipher.XORKeyStream(firstBlock[:], firstBlock[:])

	var polyKey [KeySize]byte
	copy(polyKey[:], firstBlock[:KeySize])

	var tag [poly1305TagSize]byte
	ciphertext := box[poly1305TagSize:]
	hash := poly1305.New(&polyKey)
	_, _ = hash.Write(ciphertext)
	hash.Sum(tag[:0])

	if subtle.ConstantTimeCompare(tag[:], box[:poly1305TagSize]) != 1 {
		return nil, fmt.Errorf("dnscrypt: authentication failed")
	}

	ret, tail := sliceForAppend(out, len(ciphertext))

	firstMsgBlock := ciphertext
	out = tail
	if len(firstMsgBlock) > KeySize {
		firstMsgBlock = firstMsgBlock[:KeySize]
	}
	for i := range firstMsgBlock {
		out[i] = firstBlock[KeySize+i] ^ firstMsgBlock[i]
	}
	ciphertext = ciphertext[len(firstMsgBlock):]
	out = out[len(firstMsgBlock):]

	cipher.SetCounter(1)
	cipher.XORKeyStream(out, ciphertext)

	return ret, nil
}

// sliceForAppend extends in by n bytes.
func sliceForAppend(in []byte, n int) (head, tail []byte) {
	if total := len(in) + n; cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}
	tail = head[len(in):]
	return head, tail
}
