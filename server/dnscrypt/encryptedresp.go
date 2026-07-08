package dnscrypt

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"time"

	"golang.org/x/crypto/nacl/secretbox"
)

// encryptedResponse handles encryption and decryption of DNSCrypt server
// responses.
//
// Wire format:
//
//	<dnscrypt-response> ::= <resolver-magic> <nonce> <encrypted-response>
//	<encrypted-response> ::= AE(<shared-key>, <nonce>,
//	                           <resolver-response> <resolver-response-pad>)
type encryptedResponse struct {
	// esVersion is the cryptographic construction to use.
	esVersion CryptoConstruction

	// nonce is the 24-byte nonce.  The first 12 bytes come from the client
	// query; the remaining 12 bytes are filled by the server.
	nonce Nonce
}

// encrypt encrypts the DNS response packet and returns the wire-format
// response.  r.esVersion and r.nonce must be set beforehand.
func (r *encryptedResponse) encrypt(
	packet []byte,
	sharedKey [SharedKeySize]byte,
) (response []byte, err error) {
	_, _ = rand.Read(r.nonce[12:16])
	binary.BigEndian.PutUint64(r.nonce[16:NonceSize], uint64(time.Now().UnixNano()))

	response = append(response, ResolverMagic...)
	response = append(response, r.nonce[:]...)

	padded := pad(packet)
	serverNonce := r.nonce

	switch r.esVersion {
	case XChacha20Poly1305:
		response = xchachaSeal(response, serverNonce[:], padded, sharedKey[:])
	case XSalsa20Poly1305:
		var xsalsaNonce Nonce
		copy(xsalsaNonce[:], serverNonce[:])
		response = secretbox.Seal(response, padded, &xsalsaNonce, &sharedKey)
	default:
		return nil, ErrESVersion
	}

	return response, nil
}

// decrypt decrypts a wire-format server response and returns the original DNS
// packet.  r.esVersion must be set beforehand.
func (r *encryptedResponse) decrypt(
	response []byte,
	sharedKey [SharedKeySize]byte,
	clientNonce Nonce,
) (packet []byte, err error) {
	headerLength := len(ResolverMagic) + NonceSize
	if len(response) < headerLength+TagSize+minDNSPacketSize {
		return nil, ErrInvalidResponse
	}

	magic := [ResolverMagicSize]byte{}
	copy(magic[:], response[:ResolverMagicSize])
	if !bytes.Equal(magic[:], ResolverMagic) {
		return nil, ErrInvalidResolverMagic
	}

	copy(r.nonce[:], response[ResolverMagicSize:NonceSize+ResolverMagicSize])

	// Verify that the server nonce contains the client's half — this prevents
	// response forgery across different queries.
	if !bytes.Equal(r.nonce[:NonceSize/2], clientNonce[:NonceSize/2]) {
		return nil, ErrUnexpectedNonce
	}

	encrypted := response[NonceSize+ResolverMagicSize:]

	switch r.esVersion {
	case XChacha20Poly1305:
		packet, err = xchachaOpen(nil, r.nonce[:], encrypted, sharedKey[:])
		if err != nil {
			return nil, fmt.Errorf("decrypting response: %s: %w", r.esVersion, err)
		}
	case XSalsa20Poly1305:
		var xsalsaNonce Nonce
		copy(xsalsaNonce[:], r.nonce[:])
		var ok bool
		packet, ok = secretbox.Open(nil, encrypted, &xsalsaNonce, &sharedKey)
		if !ok {
			return nil, fmt.Errorf("decrypting response: %s: %w", r.esVersion, ErrInvalidResponse)
		}
	default:
		return nil, ErrESVersion
	}

	packet, err = unpad(packet)
	if err != nil {
		return nil, fmt.Errorf("removing packet padding: %w", err)
	}

	return packet, nil
}
