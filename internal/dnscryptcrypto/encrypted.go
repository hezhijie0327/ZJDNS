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

	// ClientQueryLen is the wire size of the client query.  Over UDP the
	// encrypted response must not be larger than this value (§10.3).  Set
	// by the server during decryption.  Zero means unlimited (TCP).
	ClientQueryLen int

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
//
// maxWireLen is the UDP anti-amplification budget (§10.3): the wire response
// (ResolverMagic + Nonce + encrypted) must not exceed this value.  Zero means
// unlimited (TCP).
func (r *EncryptedResponse) Encrypt(
	packet []byte,
	sharedKey [SharedKeySize]byte,
	maxWireLen int,
) (response []byte, err error) {
	// The resolver nonce (bytes 12-23) is fully random, per §7.2 of
	// draft-denis-dprive-dnscrypt-10.
	if _, err := rand.Read(r.Nonce[NonceSize/2:]); err != nil {
		return nil, fmt.Errorf("generating resolver nonce: %w", err)
	}

	response = append(response, ResolverMagic[:]...)
	response = append(response, r.Nonce[:]...)

	if r.ESVersion.IsPQ() {
		return r.encryptPQResponse(packet, sharedKey, maxWireLen, response)
	}

	// Classical path: deterministic padding per §5.4.5 — derived from
	// SHA-256(sharedKey || clientNonce) so retransmitted queries get
	// identical padding.  Matches encrypted-dns-server's SipHash approach.
	clientNonce := r.Nonce[:NonceSize/2]
	var padded []byte
	if maxWireLen > 0 {
		maxPlaintext := maxWireLen - ResolverMagicSize - NonceSize - TagSize
		if maxPlaintext < len(packet)+1 {
			return nil, ErrResponseTooLarge
		}
		padded, err = PadResponseWithin(packet, &sharedKey, clientNonce, maxPlaintext)
		if err != nil {
			return nil, fmt.Errorf("padding classical response: %w", err)
		}
	} else {
		// TCP: bound the plaintext like the PQ path — a DNS payload beyond
		// MaxDNSUDPPacketSize cannot be served by any DNSCrypt transport
		// (R3-M22).  The server-side truncation loop shrinks responses
		// before this point, so this is a defense-in-depth guard.
		if len(packet) > MaxDNSUDPPacketSize {
			return nil, ErrResponseTooLarge
		}
		padded = PadResponse(packet, &sharedKey, clientNonce)
	}

	switch r.ESVersion {
	case XChacha20Poly1305, XWingPQ:
		response, err = XchachaSeal(response, r.Nonce[:], padded, sharedKey[:])
		if err != nil {
			return nil, err
		}
	default:
		return nil, ErrESVersion
	}

	return response, nil
}

// encryptPQResponse handles the PQ encrypted-response path with UDP budget
// awareness.  When the control block (resumption ticket) prevents the response
// from fitting in maxWireLen, it is withheld — the ticket is an optimisation
// and should never cause the DNS payload to be dropped.
func (r *EncryptedResponse) encryptPQResponse(
	packet []byte,
	sharedKey [SharedKeySize]byte,
	maxWireLen int,
	response []byte,
) ([]byte, error) {
	// Build the plaintext: <control-len>(2) <control> <dns-payload>.  The
	// control-len field is always present for PQ responses — even when
	// zero-length — so the client has a stable offset to the DNS payload.
	buildPlaintext := func(withControl bool) []byte {
		controlLen := make([]byte, 2)
		if withControl && len(r.PQControl) > 0 {
			binary.BigEndian.PutUint16(controlLen, uint16(len(r.PQControl))) //nolint:gosec // G115: bounded
		}
		payload := make([]byte, 0, 2+len(r.PQControl)+len(packet))
		payload = append(payload, controlLen...)
		if withControl {
			payload = append(payload, r.PQControl...)
		}
		payload = append(payload, packet...)
		return payload
	}

	clientNonce := r.Nonce[:NonceSize/2]
	if maxWireLen > 0 {
		// Maximum plaintext bytes after accounting for the AEAD tag and the
		// unencrypted response header (ResolverMagic + Nonce).
		maxPlaintext := maxWireLen - ResolverMagicSize - NonceSize - TagSize

		// First, try with the control block.  When the ticket is small (or
		// the budget is roomy) the response fits with the preferred padding.
		payload := buildPlaintext(len(r.PQControl) > 0)
		if len(payload)+1 <= maxPlaintext {
			padded, err := PadResponseWithin(payload, &sharedKey, clientNonce, maxPlaintext)
			if err == nil {
				switch r.ESVersion {
				case XWingPQ:
					response, err = XchachaSeal(response, r.Nonce[:], padded, sharedKey[:])
					if err != nil {
						return nil, err
					}
					return response, nil
				case XChacha20Poly1305:
					return nil, ErrESVersion
				default:
					return nil, ErrESVersion
				}
			}
		}

		// Control block does not fit — withhold it so the DNS response is
		// delivered.  The ticket is only an optimisation; the client does a
		// fresh key exchange next time.
		if len(r.PQControl) > 0 {
			payload = buildPlaintext(false)
			if len(payload)+1 <= maxPlaintext {
				padded, err := PadResponseWithin(payload, &sharedKey, clientNonce, maxPlaintext)
				if err == nil {
					r.PQControl = nil // already withheld
					switch r.ESVersion {
					case XWingPQ:
						response, err = XchachaSeal(response, r.Nonce[:], padded, sharedKey[:])
						if err != nil {
							return nil, err
						}
						return response, nil
					case XChacha20Poly1305:
						return nil, ErrESVersion
					default:
						return nil, ErrESVersion
					}
				}
			}
		}

		// Even without a ticket the response is too large for the UDP budget.
		// The DNS layer above may truncate the payload before calling us.
		return nil, fmt.Errorf("PQ response plaintext %d bytes exceeds UDP budget %d: %w",
			len(payload), maxPlaintext, ErrResponseTooLarge)
	}

	// TCP: no budget constraint.
	payload := buildPlaintext(len(r.PQControl) > 0)
	padded := PadResponse(payload, &sharedKey, clientNonce)
	switch r.ESVersion {
	case XWingPQ:
		sealed, sealErr := XchachaSeal(response, r.Nonce[:], padded, sharedKey[:])
		if sealErr != nil {
			return nil, sealErr
		}
		response = sealed
	case XChacha20Poly1305:
		return nil, ErrESVersion
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
	if !bytes.Equal(magic[:], ResolverMagic[:]) {
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
	// emits a zero-length control prefix; initial responses carry a full
	// PQDR control block.  We only strip when controlLen is
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
				} else {
					// A reused EncryptedResponse must not re-report a stale
					// ticket from a previous response.
					r.PQControl = nil
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
		if _, err := rand.Read(q.Nonce[:NonceSize/2]); err != nil {
			return nil, Nonce{}, fmt.Errorf("generating client nonce: %w", err)
		}
	}

	if q.ESVersion.IsPQ() {
		query, clientNonce, err = q.EncryptPQ(packet, sharedKey)
		// MaxDNSUDPPacketSize is a UDP anti-fragmentation limit; TCP
		// DNSCrypt queries may be up to 65535 bytes.
		if err == nil && !q.IsTCP && len(query) > MaxDNSUDPPacketSize {
			err = ErrQueryTooLarge
		}
		return query, clientNonce, err
	}

	query = append(query, q.ClientMagic[:]...)
	query = append(query, q.ClientPk[:]...)
	query = append(query, q.Nonce[:NonceSize/2]...)

	var padded []byte
	if q.IsTCP {
		padded, err = PadTCP(packet)
		if err != nil {
			return nil, Nonce{}, err
		}
	} else {
		padded = encryptPadding(packet, q.MinQueryLen)
	}
	clientNonce = q.Nonce

	switch q.ESVersion {
	case XChacha20Poly1305:
		query, err = XchachaSeal(query, clientNonce[:], padded, sharedKey[:])
		if err != nil {
			return nil, Nonce{}, err
		}
	case XWingPQ:
		return nil, Nonce{}, ErrESVersion
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
			padded, err = PadTCP(packet)
			if err != nil {
				return nil, Nonce{}, err
			}
		} else {
			floor := max(q.MinQueryLen, PQMinPaddingResumed)
			padded = PQPad(packet, floor)
		}
		var ct []byte
		ct, err = XchachaSeal(nil, clientNonce[:], padded, sharedKey[:])
		if err != nil {
			return nil, Nonce{}, err
		}
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
	// Per §5.4.3, client queries over TCP must use random 1–256 byte padding
	// (PadTCP), mirroring the resumed path.
	var padded []byte
	if q.IsTCP {
		padded, err = PadTCP(packet)
		if err != nil {
			return nil, Nonce{}, err
		}
	} else {
		padded = PQPad(packet, PQMinPaddingInitial)
	}
	var ct []byte
	ct, err = XchachaSeal(nil, clientNonce[:], padded, sharedKey[:])
	if err != nil {
		return nil, Nonce{}, err
	}
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

	// Derive the classical key unconditionally: q.SharedKey may hold a stale
	// PQ-derived key from a reused EncryptedQuery, which would authenticate
	// under the wrong key. The classical key is always derivable from
	// ClientPk + serverSecretKey.
	var sharedKey [SharedKeySize]byte
	sharedKey, err = ComputeSharedKey(q.ESVersion, &serverSecretKey, &q.ClientPk)
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
	kemSS, kemErr := PQDecapsulate(ct, serverPrivateKey)
	if kemErr != nil {
		return nil, fmt.Errorf("decapsulating PQ ciphertext: %w", kemErr)
	}
	sharedKey, err := PQDeriveSharedKey(kemSS, q.ClientMagic, q.PQCertContext, ct)
	if err != nil {
		return nil, fmt.Errorf("deriving PQ shared key: %w", err)
	}
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
	// The minimum-length guard above assumes a zero-length ticket; an
	// attacker-controlled ticketLen can leave an arbitrarily short encrypted
	// payload. Enforce the declared minimum after parsing the ticket so the
	// AEAD open sees a valid ciphertext.
	if len(query)-(idx+ticketLen+NonceSize/2) < TagSize+MinDNSPacketSize {
		return nil, nil, 0, ErrInvalidQuery
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
