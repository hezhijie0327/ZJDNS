// Package dnscrypt provides XChaCha20-Poly1305 AEAD primitives for DNSCrypt v2.
//
// This file implements Seal, Open, and SharedKey using the XChaCha20-Poly1305
// construction (X25519 key exchange + HChaCha20 key derivation + ChaCha20-Poly1305
// AEAD).
package dnscrypt

import (
	"crypto/subtle"
	"errors"
	"fmt"

	"github.com/cloudflare/circl/dh/x25519"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/poly1305" //nolint:staticcheck // SA1019: Required for custom XChaCha20-Poly1305 construction per DNSCrypt v2 spec
)

const (
	// xchachaKeySize is the size of the encryption key.
	xchachaKeySize = chacha20.KeySize

	// xchachaNonceSize is the size of the XChaCha20 nonce.
	xchachaNonceSize = chacha20.NonceSizeX

	// xchachaBlockSize is the size of the cipher block.
	xchachaBlockSize = 64
)

var (
	errCipherTextTooShort           = errors.New("ciphertext too short")
	errCipherTextAuthenticationFail = errors.New("ciphertext authentication failed")
	errWeakPublicKey                = errors.New("weak public key")
)

// xchachaSharedKey computes a shared secret using X25519 followed by HChaCha20.
func xchachaSharedKey(secretKey, publicKey [x25519.Size]byte) (sharedKey [xchachaKeySize]byte, err error) {
	var shared x25519.Key
	sk := x25519.Key(secretKey)
	pk := x25519.Key(publicKey)
	if !x25519.Shared(&shared, &sk, &pk) {
		return sharedKey, errWeakPublicKey
	}

	var nonce [16]byte
	hRes, err := chacha20.HChaCha20(shared[:], nonce[:])
	if err != nil {
		return [xchachaKeySize]byte{}, fmt.Errorf("computing hchacha20: %w", err)
	}

	return [xchachaKeySize]byte(hRes), nil
}

// xchachaSeal encrypts and authenticates message using XChaCha20-Poly1305,
// appending the result to out.  nonce must be xchachaNonceSize bytes long.
// key must be xchachaKeySize bytes long.
func xchachaSeal(out, nonce, message, key []byte) (res []byte) {
	if len(nonce) != xchachaNonceSize {
		panic("unsupported nonce size")
	}
	if len(key) != xchachaKeySize {
		panic("unsupported key size")
	}

	var firstBlock [xchachaBlockSize]byte
	cipher, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		panic(err)
	}
	cipher.XORKeyStream(firstBlock[:], firstBlock[:])
	var polyKey [xchachaKeySize]byte
	copy(polyKey[:], firstBlock[:xchachaKeySize])

	res, out = sliceForAppend(out, poly1305.TagSize+len(message))
	firstMessageBlock := message
	if len(firstMessageBlock) > (xchachaBlockSize - xchachaKeySize) {
		firstMessageBlock = firstMessageBlock[:(xchachaBlockSize - xchachaKeySize)]
	}
	tagOut := out
	out = out[poly1305.TagSize:]
	for i, x := range firstMessageBlock {
		out[i] = firstBlock[(xchachaBlockSize-xchachaKeySize)+i] ^ x //nolint:gosec // G602: Slice bounds checked by caller (headerLength check)
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
// nonce must be xchachaNonceSize bytes, key must be xchachaKeySize bytes.
func xchachaOpen(out, nonce, ciphertext, key []byte) (res []byte, err error) {
	if len(nonce) != xchachaNonceSize {
		panic("unsupported nonce size")
	}
	if len(key) != xchachaKeySize {
		panic("unsupported key size")
	}
	if len(ciphertext) < poly1305.TagSize {
		return nil, errCipherTextTooShort
	}

	var firstBlock [xchachaBlockSize]byte
	cipher, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		panic(err)
	}
	cipher.XORKeyStream(firstBlock[:], firstBlock[:])
	var polyKey [xchachaKeySize]byte
	copy(polyKey[:], firstBlock[:xchachaKeySize])

	var tag [poly1305.TagSize]byte
	msg := ciphertext[poly1305.TagSize:]
	hash := poly1305.New(&polyKey)
	_, _ = hash.Write(msg)
	hash.Sum(tag[:0])

	if subtle.ConstantTimeCompare(tag[:], ciphertext[:poly1305.TagSize]) != 1 {
		return nil, errCipherTextAuthenticationFail
	}

	res, out = sliceForAppend(out, len(msg))
	firstMessageBlock := msg
	if len(firstMessageBlock) > (xchachaBlockSize - xchachaKeySize) {
		firstMessageBlock = firstMessageBlock[:(xchachaBlockSize - xchachaKeySize)]
	}
	for i, x := range firstMessageBlock {
		out[i] = firstBlock[(xchachaBlockSize-xchachaKeySize)+i] ^ x //nolint:gosec // G602: Slice bounds checked by caller (headerLength check)
	}
	msg = msg[len(firstMessageBlock):]
	out = out[len(firstMessageBlock):]

	cipher.SetCounter(1)
	cipher.XORKeyStream(out, msg)

	return res, nil
}

// sliceForAppend extends the input slice by n bytes and returns the extended
// slice and the tail slice pointing to the appended region.
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
