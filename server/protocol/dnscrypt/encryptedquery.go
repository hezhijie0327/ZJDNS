package dnscrypt

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
)

// encryptedQuery handles encryption and decryption of DNSCrypt client queries.
//
// Classical wire format:
//
//	<dnscrypt-query> ::= <client-magic> <client-pk> <client-nonce> <encrypted-query>
//	<encrypted-query> ::= AE(<shared-key>, <client-nonce> <client-nonce-pad>,
//	                        <client-query> <client-query-pad>)
//
// PQ initial wire format:
//
//	<pq-query> ::= <client-magic> <pq-ciphertext> <client-nonce> <encrypted-query>
//
// PQ resumed wire format:
//
//	<pq-resumed-query> ::= <pq-resume-magic> <ticket-len> <ticket>
//	                       <client-nonce> <encrypted-query>
type encryptedQuery struct {
	// esVersion is the cryptographic construction to use.
	esVersion CryptoConstruction

	// clientMagic identifies the resolver certificate chosen by the client.
	clientMagic [ClientMagicSize]byte

	// clientPk is the client's short-term X25519 public key.  For PQ queries
	// this is zero-filled — the key material is in pqCiphertext.
	clientPk [KeySize]byte

	// nonce is the 24-byte nonce used for encryption.  The first 12 bytes
	// are chosen by the client (including a timestamp); the remaining 12
	// bytes are zero-filled (the server fills them for the response).
	nonce Nonce

	// pqCiphertext is the 1120-byte X-Wing ciphertext carried in an initial
	// PQ query.  Only set when esVersion == XWingPQ and the query is not
	// a resumed query.
	pqCiphertext []byte

	// pqTicket is the resumption ticket carried in a resumed PQ query.
	pqTicket []byte

	// pqCertContext is the HKDF context from the server certificate.  Set
	// by the server before decrypt/encrypt for PQ queries.
	pqCertContext []byte

	// sharedKey is the derived shared key for this query.  For resumed PQ
	// queries it is set during decrypt and consumed during encrypt so the
	// response uses the correct key.  For classical queries it is left
	// zero — the encrypt path re-derives it from clientPk.
	sharedKey [SharedKeySize]byte

	// minQueryLen is the minimum padded query length for UDP.  Must be a
	// multiple of 64.  Per §5.4.2, escalated by 64 on each TC response.
	minQueryLen int

	// isTCP indicates the query will be sent over TCP (§5.4.3 random padding).
	isTCP bool
}

// encrypt encrypts the DNS query packet and returns the wire-format query
// along with the client nonce (needed later to verify the server response).
func (q *encryptedQuery) encrypt(
	packet []byte,
	sharedKey [SharedKeySize]byte,
) (query []byte, clientNonce Nonce, err error) {
	// Only generate a fresh nonce if the caller didn't pre-set one.
	// The client nonce (first 12 bytes) is fully random, per §7.2 of
	// draft-denis-dprive-dnscrypt-10: clients SHOULD NOT include
	// unencrypted timestamps or other stable client state in nonce values.
	if q.nonce == ([24]byte{}) {
		_, _ = rand.Read(q.nonce[:NonceSize/2])
	}

	if q.esVersion.IsPQ() {
		return q.encryptPQ(packet, sharedKey)
	}

	query = append(query, q.clientMagic[:]...)
	query = append(query, q.clientPk[:]...)
	query = append(query, q.nonce[:NonceSize/2]...)

	var padded []byte
	if q.isTCP {
		padded = padTCP(packet)
	} else {
		padded = pad(packet, q.minQueryLen)
	}
	clientNonce = q.nonce

	switch q.esVersion {
	case XChacha20Poly1305:
		query = xchachaSeal(query, clientNonce[:], padded, sharedKey[:])
	default:
		return nil, Nonce{}, ErrESVersion
	}

	return query, clientNonce, nil
}

// encryptPQ builds a PQ query.  When a resumption ticket is available it
// produces a resumed query (skipping the expensive KEM); otherwise it
// encapsulates a fresh X-Wing ciphertext.
func (q *encryptedQuery) encryptPQ(
	packet []byte,
	sharedKey [SharedKeySize]byte,
) (query []byte, clientNonce Nonce, err error) {
	clientNonce = q.nonce

	// Resumed query: carry the ticket, derive the per-query key.
	if len(q.pqTicket) > 0 {
		var padded []byte
		if q.isTCP {
			padded = padTCP(packet)
		} else {
			floor := max(q.minQueryLen, pqMinPaddingResumed)
			padded = pqPad(packet, floor)
		}
		ct := xchachaSeal(nil, clientNonce[:], padded, sharedKey[:])
		query = append(query, PQResumeMagic[:]...)
		var tl [2]byte
		binary.BigEndian.PutUint16(tl[:], uint16(len(q.pqTicket))) //nolint:gosec // G115: ticket bounded
		query = append(query, tl[:]...)
		query = append(query, q.pqTicket...)
		query = append(query, clientNonce[:NonceSize/2]...)
		query = append(query, ct...)
		return query, clientNonce, nil
	}

	// Initial query: encapsulate X-Wing ciphertext.
	if len(q.pqCiphertext) == 0 {
		return nil, Nonce{}, ErrInvalidQuery
	}
	padded := pqPad(packet, pqMinPaddingInitial)
	ct := xchachaSeal(nil, clientNonce[:], padded, sharedKey[:])
	query = append(query, q.clientMagic[:]...)
	query = append(query, q.pqCiphertext...)
	query = append(query, clientNonce[:NonceSize/2]...)
	query = append(query, ct...)
	return query, clientNonce, nil
}

// decrypt decrypts a wire-format client query and returns the original DNS
// packet.  q.clientMagic and q.esVersion must be set beforehand.
//
// For PQ initial queries, q.pqCertContext must also be set and serverSecretKey
// must be the 32-byte X-Wing seed.
func (q *encryptedQuery) decrypt(
	query []byte,
	serverSecretKey [KeySize]byte,
) (packet []byte, err error) {
	// PQ initial query: client magic, X-Wing ciphertext (1120), nonce/2, encrypted.
	if q.esVersion.IsPQ() {
		return q.decryptPQInitial(query, serverSecretKey[:])
	}

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

// decryptPQInitial decrypts a PQ initial query carrying an X-Wing ciphertext.
//
// Wire format: <client-magic> (8) <xwing-ciphertext> (1120) <nonce/2> (12) <encrypted>
func (q *encryptedQuery) decryptPQInitial(query, serverPrivateKey []byte) (packet []byte, err error) {
	headerLength := ClientMagicSize + PQCiphertextSize + NonceSize/2
	if len(query) < headerLength+TagSize+minDNSPacketSize {
		return nil, ErrInvalidQuery
	}

	if !bytes.Equal(query[:ClientMagicSize], q.clientMagic[:]) {
		return nil, ErrInvalidClientMagic
	}

	idx := ClientMagicSize
	ct := make([]byte, PQCiphertextSize)
	copy(ct, query[idx:idx+PQCiphertextSize])
	q.pqCiphertext = ct

	idx += PQCiphertextSize
	copy(q.nonce[:NonceSize/2], query[idx:idx+NonceSize/2])

	idx += NonceSize / 2
	encrypted := query[idx:]

	// Decapsulate X-Wing to get KEM shared secret.
	kemSS := pqDecapsulate(ct, serverPrivateKey)
	sharedKey := pqDeriveSharedKey(kemSS, q.clientMagic, q.pqCertContext, ct)
	q.sharedKey = sharedKey

	packet, err = q.decryptPayload(encrypted, sharedKey)
	if err != nil {
		return nil, err
	}

	packet, err = unpad(packet)
	if err != nil {
		return nil, fmt.Errorf("removing PQ padding: %w", err)
	}

	return packet, nil
}

// parsePQResumedHeader extracts the ticket and client nonce from a resumed PQ
// query.  Returns the ticket, the nonce half, and the offset of the encrypted
// payload.
//
// Wire format: <PQResumeMagic> (8) <ticket-len> (2) <ticket> (N) <nonce/2> (12) <encrypted>
func parsePQResumedHeader(query []byte) (ticket, nonceHalf []byte, payloadOffset int, err error) {
	if len(query) < PQResumeMagicLen+PQTicketLenSize+NonceSize/2+TagSize+minDNSPacketSize {
		return nil, nil, 0, ErrInvalidQuery
	}

	idx := PQResumeMagicLen
	ticketLen := int(binary.BigEndian.Uint16(query[idx : idx+PQTicketLenSize]))
	idx += PQTicketLenSize
	if idx+ticketLen+NonceSize/2 > len(query) {
		return nil, nil, 0, ErrPQInvalidTicket
	}
	ticket = make([]byte, ticketLen)
	copy(ticket, query[idx:idx+ticketLen])

	idx += ticketLen
	nonceHalf = make([]byte, NonceSize/2)
	copy(nonceHalf, query[idx:idx+NonceSize/2])

	return ticket, nonceHalf, idx + NonceSize/2, nil
}

// decryptPQResumedPayload decrypts the payload of a resumed PQ query after
// the caller has extracted the shared key.  q.nonce must be set.
func (q *encryptedQuery) decryptPQResumedPayload(encrypted []byte, sharedKey [SharedKeySize]byte) (packet []byte, err error) {
	packet, err = q.decryptPayload(encrypted, sharedKey)
	if err != nil {
		return nil, err
	}
	packet, err = unpad(packet)
	if err != nil {
		return nil, fmt.Errorf("removing PQ resumed padding: %w", err)
	}
	return packet, nil
}

// decryptPayload decrypts the encrypted portion of the query using the
// pre-computed shared key.  For XWingPQ the same XChaCha20-Poly1305 AEAD is
// used.
func (q *encryptedQuery) decryptPayload(
	encrypted []byte,
	sharedKey [SharedKeySize]byte,
) (packet []byte, err error) {
	switch q.esVersion {
	case XChacha20Poly1305, XWingPQ:
		packet, err = xchachaOpen(nil, q.nonce[:], encrypted, sharedKey[:])
		if err != nil {
			return nil, fmt.Errorf("decrypting query: %s: %w", q.esVersion, err)
		}
	default:
		return nil, ErrESVersion
	}
	return packet, nil
}
