// PQ encrypt/decrypt exchange paths for queries and responses (initial and
// resumed handshakes); the underlying X-Wing KEM helpers live in pq.go.

package dnscryptcrypto

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

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
			padded, err := PadResponse(payload, &sharedKey, clientNonce, maxPlaintext)
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
				padded, err := PadResponse(payload, &sharedKey, clientNonce, maxPlaintext)
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
	padded, err := PadResponse(payload, &sharedKey, clientNonce, 0)
	if err != nil {
		return nil, err
	}
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

// DecryptPQInitial decrypts a PQ initial query carrying an X-Wing ciphertext.
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

// DecryptPQResumedPayload decrypts the payload of a resumed PQ query after
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
