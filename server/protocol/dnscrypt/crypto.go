package dnscrypt

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"time"
	"zjdns/config"
	"zjdns/internal/log"

	"codeberg.org/miekg/dns"
)

func (s *Server) encrypt(m *dns.Msg, q *encryptedQuery, isUDP bool) (encrypted []byte, err error) {
	r := &encryptedResponse{
		esVersion: q.esVersion,
		nonce:     q.nonce,
	}
	err = m.Pack()
	if err != nil {
		return nil, fmt.Errorf("packing dns message: %w", err)
	}
	packet := m.Data

	if q.esVersion.IsPQ() {
		return s.encryptPQ(packet, q, r, isUDP)
	}

	curr := s.current()
	sharedKey, err := computeSharedKey(XChacha20Poly1305, &curr.Classical.ResolverSk, &q.clientPk)
	if err != nil {
		return nil, fmt.Errorf("computing shared key: %w", err)
	}
	return r.encrypt(packet, sharedKey, isUDP)
}

// encryptPQ encrypts a DNS response for a PQ query.  For initial queries it
// issues a resumption ticket in the response control block.
func (s *Server) encryptPQ(packet []byte, q *encryptedQuery, r *encryptedResponse, isUDP bool) ([]byte, error) {
	var sharedKey [SharedKeySize]byte
	curr := s.current()

	if len(q.pqCiphertext) > 0 {
		// Reuse the shared key from decrypt when available — the client
		// reuses encapsulations and decryptPQInitial has already derived
		// it from the same (ct, serverPrivateKey) pair.
		if q.sharedKey != [SharedKeySize]byte{} {
			sharedKey = q.sharedKey
		} else {
			kemSS := pqDecapsulate(q.pqCiphertext, curr.PQ.PqPrivateKey)
			sharedKey = pqDeriveSharedKey(kemSS, q.clientMagic, curr.PQ.PqCertContext, q.pqCiphertext)
		}

		// Issue a resumption ticket.
		resumeSecret := pqResumeSecret(sharedKey, q.clientMagic, q.nonce[:NonceSize/2])
		ticketExpiry := nowUnix32() + uint32(config.DefaultDNSCryptPQTicketLifetime/time.Second)
		peHash := profileExtensionHash()
		plaintext := encodeTicketPlaintext(
			resumeSecret, q.clientMagic, curr.Classical.Serial,
			curr.Classical.NotAfter, ticketExpiry, peHash,
		)
		var nonce [xchachaNonceSize]byte
		if _, randErr := rand.Read(nonce[:]); randErr != nil {
			return nil, fmt.Errorf("generating ticket nonce: %w", randErr)
		}
		sealed := pqSealTicket(&s.ticketKey, &s.ticketKeyID, &nonce, plaintext)
		r.pqControl = pqBuildControlBlock(sealed, uint32(config.DefaultDNSCryptPQTicketLifetime/time.Second))
		log.Debugf("DNSCRYPT: PQ ticket issued (expires in %ds)", config.DefaultDNSCryptPQTicketLifetime/time.Second)
	} else {
		// Resumed query: use the shared key derived during decrypt.
		sharedKey = q.sharedKey
		log.Debugf("DNSCRYPT: PQ resumed response")
	}

	return r.encrypt(packet, sharedKey, isUDP)
}

// decrypt tries to decrypt the query: PQ resumed → PQ ciphertext → classical.
// Keys are tried newest-first to handle rotation overlap (§8).
func (s *Server) decrypt(b []byte) (msg *dns.Msg, query *encryptedQuery, err error) {
	// PQ resumed queries don't carry a client magic — try them first.
	if len(b) >= PQResumeMagicLen && bytes.Equal(b[:PQResumeMagicLen], PQResumeMagic[:]) {
		log.Debugf("DNSCRYPT: PQ resumed query")
		return s.decryptPQResumed(b)
	}

	// Snapshot keys under read lock — rotateKeys() writes under write lock.
	s.mu.RLock()
	keysSnapshot := s.keys
	s.mu.RUnlock()

	// Try each key pair newest-first: PQ first, then classical.
	for _, k := range keysSnapshot {
		// Try PQ ciphertext.
		if bytes.Equal(b[:ClientMagicSize], k.pair.PQ.ClientMagic[:]) {
			log.Debugf("DNSCRYPT: PQ initial query")
			query = &encryptedQuery{
				esVersion:     XWingPQ,
				clientMagic:   k.pair.PQ.ClientMagic,
				pqCertContext: k.pair.PQ.PqCertContext,
			}
			var resolverSk [KeySize]byte
			copy(resolverSk[:], k.pair.PQ.PqPrivateKey)
			decrypted, decErr := query.decrypt(b, resolverSk)
			if decErr == nil {
				msg = &dns.Msg{}
				msg.Data = decrypted
				if unpackErr := msg.Unpack(); unpackErr != nil {
					return nil, nil, fmt.Errorf("unpacking dns message: %w", unpackErr)
				}
				return msg, query, nil
			}
		}

		// Try classical.
		if bytes.Equal(b[:ClientMagicSize], k.pair.Classical.ClientMagic[:]) {
			log.Debugf("DNSCRYPT: classical query")
			query = &encryptedQuery{
				esVersion:   XChacha20Poly1305,
				clientMagic: k.pair.Classical.ClientMagic,
			}
			decrypted, decErr := query.decrypt(b, k.pair.Classical.ResolverSk)
			if decErr == nil {
				msg = &dns.Msg{}
				msg.Data = decrypted
				if unpackErr := msg.Unpack(); unpackErr != nil {
					return nil, nil, fmt.Errorf("unpacking dns message: %w", unpackErr)
				}
				return msg, query, nil
			}
		}
	}
	return nil, nil, fmt.Errorf("decrypting query: no matching key (tried %d pairs)", len(keysSnapshot))
}

// decryptPQResumed handles a resumed PQ query.  It tries each key pair's
// PQ certificate metadata (client magic, serial, NotAfter) to validate the ticket.
func (s *Server) decryptPQResumed(b []byte) (msg *dns.Msg, query *encryptedQuery, err error) {
	ticket, nonceHalf, payloadOff, err := parsePQResumedHeader(b)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing PQ resumed query: %w", err)
	}

	ticketPlain, err := pqOpenTicket(&s.ticketKey, &s.ticketKeyID, ticket)
	if err != nil {
		return nil, nil, fmt.Errorf("opening PQ ticket: %w", err)
	}
	clientMagic, resumeSecret, ticketExpiry, err := decodeTicketPlaintext(ticketPlain)
	if err != nil {
		return nil, nil, fmt.Errorf("decoding PQ ticket: %w", err)
	}
	if ticketExpiry < nowUnix32() {
		return nil, nil, ErrPQTicketExpired
	}

	peHash := profileExtensionHash()

	// Snapshot keys under read lock — rotateKeys() writes under write lock.
	s.mu.RLock()
	keysSnapshot := s.keys
	s.mu.RUnlock()

	var matchedPair *CertPair
	for _, k := range keysSnapshot {
		if clientMagic == k.pair.PQ.ClientMagic &&
			bytes.Equal(ticketPlain[ticketPlaintextESOff:ticketPlaintextESOff+ticketPlaintextESLen], PQESVersion[:]) &&
			binary.BigEndian.Uint32(ticketPlain[ticketPlaintextSerialOff:ticketPlaintextSerialOff+ticketPlaintextSerialLen]) == k.pair.Classical.Serial &&
			binary.BigEndian.Uint32(ticketPlain[ticketPlaintextTSEndOff:ticketPlaintextTSEndOff+ticketPlaintextTSEndLen]) == k.pair.Classical.NotAfter &&
			bytes.Equal(ticketPlain[ticketPlaintextPEHashOff:ticketPlaintextPEHashOff+ticketPlaintextPEHashLen], peHash[:]) {
			matchedPair = k.pair
			break
		}
	}
	if matchedPair == nil {
		return nil, nil, ErrPQInvalidTicket
	}

	sharedKey := pqResumedSharedKey(resumeSecret, matchedPair.PQ.ClientMagic, nonceHalf, ticket)

	query = &encryptedQuery{
		esVersion:   XWingPQ,
		clientMagic: matchedPair.PQ.ClientMagic,
		sharedKey:   sharedKey,
	}
	copy(query.nonce[:NonceSize/2], nonceHalf)
	query.pqTicket = ticket

	encrypted := b[payloadOff:]
	decrypted, err := query.decryptPQResumedPayload(encrypted, sharedKey)
	if err != nil {
		return nil, nil, fmt.Errorf("decrypting resumed payload: %w", err)
	}
	msg = &dns.Msg{}
	msg.Data = decrypted
	err = msg.Unpack()
	if err != nil {
		return nil, nil, fmt.Errorf("unpacking dns message: %w", err)
	}
	return msg, query, nil
}
