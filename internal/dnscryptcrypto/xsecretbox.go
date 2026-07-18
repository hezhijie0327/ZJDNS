// Package dnscrypt provides XChaCha20-Poly1305 AEAD primitives for DNSCrypt v2.
//
// This file implements Seal, Open, and SharedKey using the XChaCha20-Poly1305
// construction (X25519 key exchange + HChaCha20 key derivation + ChaCha20-Poly1305
// AEAD).
package dnscryptcrypto

import (
	"crypto/subtle"
	"errors"
	"fmt"

	"github.com/cloudflare/circl/dh/x25519"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/poly1305" //nolint:staticcheck // SA1019: Required for custom XChaCha20-Poly1305 construction per DNSCrypt v2 spec
)

const (
	// XchachaKeySize is the size of the encryption key.
	XchachaKeySize = chacha20.KeySize

	// XchachaNonceSize is the size of the XChaCha20 nonce.
	XchachaNonceSize = chacha20.NonceSizeX

	// XchachaBlockSize is the size of the cipher block.
	XchachaBlockSize = 64
)

var (
	errCipherTextTooShort           = errors.New("ciphertext too short")
	errCipherTextAuthenticationFail = errors.New("ciphertext authentication failed")
	errWeakPublicKey                = errors.New("weak public key")
)

// xchachaSharedKey computes a shared secret using X25519 followed by HChaCha20.
func XchachaSharedKey(secretKey, publicKey [x25519.Size]byte) (sharedKey [XchachaKeySize]byte, err error) {
	var shared x25519.Key
	sk := x25519.Key(secretKey)
	pk := x25519.Key(publicKey)
	if !x25519.Shared(&shared, &sk, &pk) {
		return sharedKey, errWeakPublicKey
	}

	var nonce [16]byte
	hRes, err := chacha20.HChaCha20(shared[:], nonce[:])
	if err != nil {
		return [XchachaKeySize]byte{}, fmt.Errorf("computing hchacha20: %w", err)
	}

	return [XchachaKeySize]byte(hRes), nil
}

// xchachaSeal encrypts and authenticates message using XChaCha20-Poly1305,
// appending the result to out.  nonce must be XchachaNonceSize bytes long.
// key must be XchachaKeySize bytes long.
func XchachaSeal(out, nonce, message, key []byte) (res []byte) {
	if len(nonce) != XchachaNonceSize {
		panic("unsupported nonce size")
	}
	if len(key) != XchachaKeySize {
		panic("unsupported key size")
	}

	var firstBlock [XchachaBlockSize]byte
	cipher, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		panic(err)
	}
	cipher.XORKeyStream(firstBlock[:], firstBlock[:])
	var polyKey [XchachaKeySize]byte
	copy(polyKey[:], firstBlock[:XchachaKeySize])

	res, out = SliceForAppend(out, poly1305.TagSize+len(message))
	firstMessageBlock := message
	if len(firstMessageBlock) > (XchachaBlockSize - XchachaKeySize) {
		firstMessageBlock = firstMessageBlock[:(XchachaBlockSize - XchachaKeySize)]
	}
	tagOut := out
	out = out[poly1305.TagSize:]
	for i, x := range firstMessageBlock {
		out[i] = firstBlock[(XchachaBlockSize-XchachaKeySize)+i] ^ x //nolint:gosec // G602: Slice bounds checked by caller (headerLength check)
	}
	message = message[len(firstMessageBlock):]
	ciphertext := out
	out = out[len(firstMessageBlock):]

	cipher.SetCounter(1)
	cipher.XORKeyStream(out, message)

	var tag [poly1305.TagSize]byte
	hash := poly1305.New(&polyKey)
	_, _ = hash.Write(ciphertext)
	hash.Sum(tag[:0])
	copy(tagOut, tag[:])

	return res
}

// xchachaOpen decrypts and authenticates a box using XChaCha20-Poly1305.
// nonce must be XchachaNonceSize bytes, key must be XchachaKeySize bytes.
func XchachaOpen(out, nonce, ciphertext, key []byte) (res []byte, err error) {
	if len(nonce) != XchachaNonceSize {
		panic("unsupported nonce size")
	}
	if len(key) != XchachaKeySize {
		panic("unsupported key size")
	}
	if len(ciphertext) < poly1305.TagSize {
		return nil, errCipherTextTooShort
	}

	var firstBlock [XchachaBlockSize]byte
	cipher, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		panic(err)
	}
	cipher.XORKeyStream(firstBlock[:], firstBlock[:])
	var polyKey [XchachaKeySize]byte
	copy(polyKey[:], firstBlock[:XchachaKeySize])

	var tag [poly1305.TagSize]byte
	msg := ciphertext[poly1305.TagSize:]
	hash := poly1305.New(&polyKey)
	_, _ = hash.Write(msg)
	hash.Sum(tag[:0])

	if subtle.ConstantTimeCompare(tag[:], ciphertext[:poly1305.TagSize]) != 1 {
		return nil, errCipherTextAuthenticationFail
	}

	res, out = SliceForAppend(out, len(msg))
	firstMessageBlock := msg
	if len(firstMessageBlock) > (XchachaBlockSize - XchachaKeySize) {
		firstMessageBlock = firstMessageBlock[:(XchachaBlockSize - XchachaKeySize)]
	}
	for i, x := range firstMessageBlock {
		out[i] = firstBlock[(XchachaBlockSize-XchachaKeySize)+i] ^ x //nolint:gosec // G602: Slice bounds checked by caller (headerLength check)
	}
	msg = msg[len(firstMessageBlock):]
	out = out[len(firstMessageBlock):]

	cipher.SetCounter(1)
	cipher.XORKeyStream(out, msg)

	return res, nil
}

// sliceForAppend extends the input slice by n bytes and returns the extended
// slice and the tail slice pointing to the appended region.
func SliceForAppend(in []byte, n int) (head, tail []byte) {
	if total := len(in) + n; cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}
	tail = head[len(in):]
	return head, tail
}
