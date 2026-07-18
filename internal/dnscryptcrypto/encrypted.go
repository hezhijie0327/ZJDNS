package dnscryptcrypto

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
type EncryptedQuery struct {
	// ESVersion is the cryptographic construction to use.
	ESVersion CryptoConstruction

	// ClientMagic identifies the resolver certificate chosen by the client.
	ClientMagic [ClientMagicSize]byte

	// ClientPk is the client's short-term X25519 public key.  For PQ queries
	// this is zero-filled — the key material is in PQCiphertext.
	ClientPk [KeySize]byte

	// nonce is the 24-byte nonce used for encryption.  The first 12 bytes
	// are chosen by the client (including a timestamp); the remaining 12
	// bytes are zero-filled (the server fills them for the response).
	Nonce Nonce

	// PQCiphertext is the 1120-byte X-Wing ciphertext carried in an initial
	// PQ query.  Only set when ESVersion == XWingPQ and the query is not
	// a resumed query.
	PQCiphertext []byte

	// PQTicket is the resumption ticket carried in a resumed PQ query.
	PQTicket []byte

	// PQCertContext is the HKDF context from the server certificate.  Set
	// by the server before decrypt/encrypt for PQ queries.
	PQCertContext []byte

	// sharedKey is the derived shared key for this query.  For resumed PQ
	// queries it is set during decrypt and consumed during encrypt so the
	// response uses the correct key.  For classical queries it is left
	// zero — the encrypt path re-derives it from ClientPk.
	SharedKey [SharedKeySize]byte

	// MinQueryLen is the minimum padded query length for UDP.  Must be a
	// multiple of 64.  Per §5.4.2, escalated by 64 on each TC response.
	MinQueryLen int

	// IsTCP indicates the query will be sent over TCP (§5.4.3 random padding).
	IsTCP bool
}

// encryptedResponse handles encryption and decryption of DNSCrypt server
// responses.
//
// Classical wire format:
//
//	<dnscrypt-response> ::= <resolver-magic> <nonce> <encrypted-response>
//	<encrypted-response> ::= AE(<shared-key>, <nonce>,
//	                           <resolver-response> <resolver-response-pad>)
//
// PQ wire format:
//
//	<pq-response> ::= <resolver-magic> <nonce> <encrypted-response>
//	<encrypted-response> ::= AE(<shared-key>, <nonce>,
//	                           <control-block> <resolver-response> <resolver-response-pad>)
type EncryptedResponse struct {
	// ESVersion is the cryptographic construction to use.
	ESVersion CryptoConstruction

	// nonce is the 24-byte nonce.  The first 12 bytes come from the client
	// query; the remaining 12 bytes are filled by the server.
	Nonce Nonce

	// PQControl is the optional PQ response control block (carries a
	// resumption ticket).  Only set for PQ responses.
	PQControl []byte
}

// encrypt encrypts the DNS response packet and returns the wire-format
// response.  r.ESVersion and r.Nonce must be set beforehand.
func (r *EncryptedResponse) Encrypt(
	packet []byte,
	sharedKey [SharedKeySize]byte,
	isUDP bool,
) (response []byte, err error) {
	// The resolver nonce (bytes 12-23) is fully random, per §7.2 of
	// draft-denis-dprive-dnscrypt-10.
	_, _ = rand.Read(r.Nonce[NonceSize/2:])

	response = append(response, ResolverMagic...)
	response = append(response, r.Nonce[:]...)

	// For PQ responses, always prepend a 2-byte control-length prefix before the
	// DNS payload (even when there is no control block).  The client always
	// reads these two bytes to locate the control block; without them DNS header
	// bytes would be misinterpreted as the control length.
	if r.ESVersion.IsPQ() {
		controlLen := make([]byte, 2)
		binary.BigEndian.PutUint16(controlLen, uint16(len(r.PQControl))) //nolint:gosec // G115: bounded
		paddedPayload := make([]byte, 0, 2+len(r.PQControl)+len(packet))
		paddedPayload = append(paddedPayload, controlLen...)
		paddedPayload = append(paddedPayload, r.PQControl...)
		paddedPayload = append(paddedPayload, packet...)
		packet = paddedPayload
	}

	// UDP responses get a 256-byte minimum to match client expectations;
	// TCP responses only align to 64 bytes.
	respMinLen := 0
	if isUDP {
		respMinLen = MinUDPQuestionSize
	}
	padded := Pad(packet, respMinLen)
	serverNonce := r.Nonce

	switch r.ESVersion {
	case XChacha20Poly1305, XWingPQ:
		response = XchachaSeal(response, serverNonce[:], padded, sharedKey[:])
	default:
		return nil, ErrESVersion
	}

	return response, nil
}

// decrypt decrypts a wire-format server response and returns the original DNS
// packet.  r.ESVersion must be set beforehand.
//
// For PQ responses, the decrypted payload may include a control block which is
// stripped.  The caller can inspect r.PQControl after return.
func (r *EncryptedResponse) Decrypt(
	response []byte,
	sharedKey [SharedKeySize]byte,
	clientNonce Nonce,
) (packet []byte, err error) {
	headerLength := len(ResolverMagic) + NonceSize
	if len(response) < headerLength+TagSize+MinDNSPacketSize {
		return nil, ErrInvalidResponse
	}

	magic := [ResolverMagicSize]byte{}
	copy(magic[:], response[:ResolverMagicSize])
	if !bytes.Equal(magic[:], ResolverMagic) {
		return nil, ErrInvalidResolverMagic
	}

	copy(r.Nonce[:], response[ResolverMagicSize:NonceSize+ResolverMagicSize])

	// Verify that the server nonce contains the client's half — this prevents
	// response forgery across different queries.
	if !bytes.Equal(r.Nonce[:NonceSize/2], clientNonce[:NonceSize/2]) {
		return nil, ErrUnexpectedNonce
	}

	encrypted := response[NonceSize+ResolverMagicSize:]

	switch r.ESVersion {
	case XChacha20Poly1305, XWingPQ:
		packet, err = XchachaOpen(nil, r.Nonce[:], encrypted, sharedKey[:])
		if err != nil {
			return nil, fmt.Errorf("decrypting response: %s: %w", r.ESVersion, err)
		}
	default:
		return nil, ErrESVersion
	}

	// Strip PQ control block if present.  For resumed responses the server
	// emits \x00\x00 as a zero-length control prefix; initial responses
	// carry a full PQDR control block.  We only strip when controlLen is
	// zero or the magic validates — otherwise the packet lacks the prefix
	// the packet has no control prefix and the DNS payload starts at offset 0.
	if r.ESVersion.IsPQ() && len(packet) >= 2 {
		controlLen := int(binary.BigEndian.Uint16(packet[0:2]))
		if 2+controlLen <= len(packet) {
			hasMagic := controlLen >= PQMinControlBlockLen &&
				bytes.Equal(packet[2:2+len(PQControlMagic)], PQControlMagic[:])
			if controlLen == 0 || hasMagic {
				if controlLen > 0 {
					r.PQControl = make([]byte, controlLen)
					copy(r.PQControl, packet[2:2+controlLen])
				}
				packet = packet[2+controlLen:]
			}
		}
	}

	packet, err = UnPad(packet)
	if err != nil {
		return nil, fmt.Errorf("removing packet padding: %w", err)
	}

	return packet, nil
}

// encrypt encrypts the DNS query packet and returns the wire-format query
// along with the client nonce (needed later to verify the server response).
func (q *EncryptedQuery) Encrypt(
	packet []byte,
	sharedKey [SharedKeySize]byte,
) (query []byte, clientNonce Nonce, err error) {
	// Only generate a fresh nonce if the caller didn't pre-set one.
	// The client nonce (first 12 bytes) is fully random, per §7.2 of
	// draft-denis-dprive-dnscrypt-10: clients SHOULD NOT include
	// unencrypted timestamps or other stable client state in nonce values.
	if q.Nonce == ([24]byte{}) {
		_, _ = rand.Read(q.Nonce[:NonceSize/2])
	}

	if q.ESVersion.IsPQ() {
		return q.EncryptPQ(packet, sharedKey)
	}

	query = append(query, q.ClientMagic[:]...)
	query = append(query, q.ClientPk[:]...)
	query = append(query, q.Nonce[:NonceSize/2]...)

	var padded []byte
	if q.IsTCP {
		padded = PadTCP(packet)
	} else {
		padded = Pad(packet, q.MinQueryLen)
	}
	clientNonce = q.Nonce

	switch q.ESVersion {
	case XChacha20Poly1305:
		query = XchachaSeal(query, clientNonce[:], padded, sharedKey[:])
	default:
		return nil, Nonce{}, ErrESVersion
	}

	return query, clientNonce, nil
}

// encryptPQ builds a PQ query.  When a resumption ticket is available it
// produces a resumed query (skipping the expensive KEM); otherwise it
// encapsulates a fresh X-Wing ciphertext.
func (q *EncryptedQuery) EncryptPQ(
	packet []byte,
	sharedKey [SharedKeySize]byte,
) (query []byte, clientNonce Nonce, err error) {
	clientNonce = q.Nonce

	// Resumed query: carry the ticket, derive the per-query key.
	if len(q.PQTicket) > 0 {
		var padded []byte
		if q.IsTCP {
			padded = PadTCP(packet)
		} else {
			floor := max(q.MinQueryLen, PQMinPaddingResumed)
			padded = PQPad(packet, floor)
		}
		ct := XchachaSeal(nil, clientNonce[:], padded, sharedKey[:])
		query = append(query, PQResumeMagic[:]...)
		var tl [2]byte
		binary.BigEndian.PutUint16(tl[:], uint16(len(q.PQTicket))) //nolint:gosec // G115: ticket bounded
		query = append(query, tl[:]...)
		query = append(query, q.PQTicket...)
		query = append(query, clientNonce[:NonceSize/2]...)
		query = append(query, ct...)
		return query, clientNonce, nil
	}

	// Initial query: encapsulate X-Wing ciphertext.
	if len(q.PQCiphertext) == 0 {
		return nil, Nonce{}, ErrInvalidQuery
	}
	padded := PQPad(packet, PQMinPaddingInitial)
	ct := XchachaSeal(nil, clientNonce[:], padded, sharedKey[:])
	query = append(query, q.ClientMagic[:]...)
	query = append(query, q.PQCiphertext...)
	query = append(query, clientNonce[:NonceSize/2]...)
	query = append(query, ct...)
	return query, clientNonce, nil
}

// decrypt decrypts a wire-format client query and returns the original DNS
// packet.  q.ClientMagic and q.ESVersion must be set beforehand.
//
// For PQ initial queries, q.PQCertContext must also be set and serverSecretKey
// must be the 32-byte X-Wing seed.
func (q *EncryptedQuery) Decrypt(
	query []byte,
	serverSecretKey [KeySize]byte,
) (packet []byte, err error) {
	// PQ initial query: client magic, X-Wing ciphertext (1120), nonce/2, encrypted.
	if q.ESVersion.IsPQ() {
		return q.DecryptPQInitial(query, serverSecretKey[:])
	}

	headerLength := ClientMagicSize + KeySize + NonceSize/2
	if len(query) < headerLength+TagSize+MinDNSPacketSize {
		return nil, ErrInvalidQuery
	}

	ClientMagic := [ClientMagicSize]byte{}
	copy(ClientMagic[:], query[:ClientMagicSize])
	if !bytes.Equal(ClientMagic[:], q.ClientMagic[:]) {
		return nil, ErrInvalidClientMagic
	}

	idx := ClientMagicSize
	copy(q.ClientPk[:KeySize], query[idx:idx+KeySize])

	sharedKey, err := ComputeSharedKey(q.ESVersion, &serverSecretKey, &q.ClientPk)
	if err != nil {
		return nil, fmt.Errorf("computing shared key: %w", err)
	}

	idx += KeySize
	copy(q.Nonce[:NonceSize/2], query[idx:idx+NonceSize/2])

	idx += NonceSize / 2
	encrypted := query[idx:]

	packet, err = q.DecryptPayload(encrypted, sharedKey)
	if err != nil {
		return nil, err
	}

	packet, err = UnPad(packet)
	if err != nil {
		return nil, fmt.Errorf("removing packet padding: %w", err)
	}

	return packet, nil
}

// decryptPQInitial decrypts a PQ initial query carrying an X-Wing ciphertext.
//
// Wire format: <client-magic> (8) <xwing-ciphertext> (1120) <nonce/2> (12) <encrypted>
func (q *EncryptedQuery) DecryptPQInitial(query, serverPrivateKey []byte) (packet []byte, err error) {
	headerLength := ClientMagicSize + PQCiphertextSize + NonceSize/2
	if len(query) < headerLength+TagSize+MinDNSPacketSize {
		return nil, ErrInvalidQuery
	}

	if !bytes.Equal(query[:ClientMagicSize], q.ClientMagic[:]) {
		return nil, ErrInvalidClientMagic
	}

	idx := ClientMagicSize
	ct := make([]byte, PQCiphertextSize)
	copy(ct, query[idx:idx+PQCiphertextSize])
	q.PQCiphertext = ct

	idx += PQCiphertextSize
	copy(q.Nonce[:NonceSize/2], query[idx:idx+NonceSize/2])

	idx += NonceSize / 2
	encrypted := query[idx:]

	// Decapsulate X-Wing to get KEM shared secret.
	kemSS := PQDecapsulate(ct, serverPrivateKey)
	sharedKey := PQDeriveSharedKey(kemSS, q.ClientMagic, q.PQCertContext, ct)
	q.SharedKey = sharedKey

	packet, err = q.DecryptPayload(encrypted, sharedKey)
	if err != nil {
		return nil, err
	}

	packet, err = UnPad(packet)
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
func ParsePQResumedHeader(query []byte) (ticket, nonceHalf []byte, payloadOffset int, err error) {
	if len(query) < PQResumeMagicLen+PQTicketLenSize+NonceSize/2+TagSize+MinDNSPacketSize {
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
// the caller has extracted the shared key.  q.Nonce must be set.
func (q *EncryptedQuery) DecryptPQResumedPayload(encrypted []byte, sharedKey [SharedKeySize]byte) (packet []byte, err error) {
	packet, err = q.DecryptPayload(encrypted, sharedKey)
	if err != nil {
		return nil, err
	}
	packet, err = UnPad(packet)
	if err != nil {
		return nil, fmt.Errorf("removing PQ resumed padding: %w", err)
	}
	return packet, nil
}

// decryptPayload decrypts the encrypted portion of the query using the
// pre-computed shared key.  For XWingPQ the same XChaCha20-Poly1305 AEAD is
// used.
func (q *EncryptedQuery) DecryptPayload(
	encrypted []byte,
	sharedKey [SharedKeySize]byte,
) (packet []byte, err error) {
	switch q.ESVersion {
	case XChacha20Poly1305, XWingPQ:
		packet, err = XchachaOpen(nil, q.Nonce[:], encrypted, sharedKey[:])
		if err != nil {
			return nil, fmt.Errorf("decrypting query: %s: %w", q.ESVersion, err)
		}
	default:
		return nil, ErrESVersion
	}
	return packet, nil
}

// EncryptQuery encrypts a DNS query packet for sending to a DNSCrypt server.
func EncryptQuery(q *EncryptedQuery, packet []byte, sharedKey [SharedKeySize]byte) (encrypted []byte, clientNonce Nonce, err error) {
	return q.Encrypt(packet, sharedKey)
}

// DecryptResponse decrypts a DNSCrypt server response.
func DecryptResponse(r *EncryptedResponse, response []byte, sharedKey [SharedKeySize]byte, clientNonce Nonce) (packet []byte, err error) {
	return r.Decrypt(response, sharedKey, clientNonce)
}

// GenerateKeyPairRaw generates a new X25519 key pair.
func GenerateKeyPairRaw() (secretKey, publicKey [KeySize]byte) {
	return GenerateRandomKeyPair()
}
