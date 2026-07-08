package dnscrypt

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"time"

	"golang.org/x/crypto/nacl/secretbox"
)

// encryptedQuery handles encryption and decryption of DNSCrypt client queries.
//
// Wire format:
//
//	<dnscrypt-query> ::= <client-magic> <client-pk> <client-nonce> <encrypted-query>
//	<encrypted-query> ::= AE(<shared-key>, <client-nonce> <client-nonce-pad>,
//	                        <client-query> <client-query-pad>)
type encryptedQuery struct {
	// esVersion is the cryptographic construction to use.
	esVersion CryptoConstruction

	// clientMagic identifies the resolver certificate chosen by the client.
	clientMagic [ClientMagicSize]byte

	// clientPk is the client's short-term X25519 public key.
	clientPk [KeySize]byte

	// nonce is the 24-byte nonce used for encryption.  The first 12 bytes
	// are chosen by the client (including a timestamp); the remaining 12
	// bytes are zero-filled (the server fills them for the response).
	nonce Nonce
}

// encrypt encrypts the DNS query packet and returns the wire-format query
// along with the client nonce (needed later to verify the server response).
func (q *encryptedQuery) encrypt(
	packet []byte,
	sharedKey [SharedKeySize]byte,
) (query []byte, clientNonce Nonce, err error) {
	binary.BigEndian.PutUint64(q.nonce[:8], uint64(time.Now().UnixNano()))
	_, _ = rand.Read(q.nonce[8:12])

	query = append(query, q.clientMagic[:]...)
	query = append(query, q.clientPk[:]...)
	query = append(query, q.nonce[:NonceSize/2]...)

	padded := pad(packet)
	clientNonce = q.nonce

	switch q.esVersion {
	case XChacha20Poly1305:
		query = xchachaSeal(query, clientNonce[:], padded, sharedKey[:])
	case XSalsa20Poly1305:
		var xsalsaNonce Nonce
		copy(xsalsaNonce[:], clientNonce[:])
		query = secretbox.Seal(query, padded, &xsalsaNonce, &sharedKey)
	default:
		return nil, Nonce{}, ErrESVersion
	}

	return query, clientNonce, nil
}

// decrypt decrypts a wire-format client query and returns the original DNS
// packet.  q.clientMagic and q.esVersion must be set beforehand.
func (q *encryptedQuery) decrypt(
	query []byte,
	serverSecretKey [KeySize]byte,
) (packet []byte, err error) {
	headerLength := ClientMagicSize + KeySize + NonceSize/2
	if len(query) < headerLength+TagSize+minDNSPacketSize {
		return nil, ErrInvalidQuery
	}

	clientMagic := [ClientMagicSize]byte{}
	copy(clientMagic[:], query[:ClientMagicSize])
	if !bytes.Equal(clientMagic[:], q.clientMagic[:]) {
		return nil, ErrInvalidClientMagic
	}

	idx := ClientMagicSize
	copy(q.clientPk[:KeySize], query[idx:idx+KeySize])

	sharedKey, err := computeSharedKey(q.esVersion, &serverSecretKey, &q.clientPk)
	if err != nil {
		return nil, fmt.Errorf("computing shared key: %w", err)
	}

	idx += KeySize
	copy(q.nonce[:NonceSize/2], query[idx:idx+NonceSize/2])

	idx += NonceSize / 2
	encrypted := query[idx:]

	packet, err = q.decryptPayload(encrypted, sharedKey)
	if err != nil {
		return nil, err
	}

	packet, err = unpad(packet)
	if err != nil {
		return nil, fmt.Errorf("removing packet padding: %w", err)
	}

	return packet, nil
}

// decryptPayload decrypts the encrypted portion of the query using the
// pre-computed shared key.
func (q *encryptedQuery) decryptPayload(
	encrypted []byte,
	sharedKey [SharedKeySize]byte,
) (packet []byte, err error) {
	switch q.esVersion {
	case XChacha20Poly1305:
		packet, err = xchachaOpen(nil, q.nonce[:], encrypted, sharedKey[:])
		if err != nil {
			return nil, fmt.Errorf("decrypting query: %s: %w", q.esVersion, err)
		}
	case XSalsa20Poly1305:
		var xsalsaNonce Nonce
		copy(xsalsaNonce[:], q.nonce[:])
		var ok bool
		packet, ok = secretbox.Open(nil, encrypted, &xsalsaNonce, &sharedKey)
		if !ok {
			return nil, fmt.Errorf("decrypting query: %s: %w", q.esVersion, ErrInvalidQuery)
		}
	default:
		return nil, ErrESVersion
	}
	return packet, nil
}
