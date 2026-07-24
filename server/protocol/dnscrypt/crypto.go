package dnscrypt

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"time"
	"zjdns/config"
	dnscryptcrypto "zjdns/internal/dnscryptcrypto"
	"zjdns/internal/log"

	"codeberg.org/miekg/dns"
)

func (s *Server) encrypt(m *dns.Msg, q *dnscryptcrypto.EncryptedQuery, isUDP bool) (encrypted []byte, err error) {
	r := &dnscryptcrypto.EncryptedResponse{
		ESVersion: q.ESVersion,
		Nonce:     q.Nonce,
	}
	err = m.Pack()
	if err != nil {
		return nil, fmt.Errorf("packing dns message: %w", err)
	}
	packet := m.Data

	if q.ESVersion.IsPQ() {
		return s.encryptPQ(packet, q, r, isUDP)
	}

	curr := s.current()
	sharedKey, err := dnscryptcrypto.ComputeSharedKey(dnscryptcrypto.XChacha20Poly1305, &curr.Classical.ResolverSk, &q.ClientPk)
	if err != nil {
		return nil, fmt.Errorf("computing shared key: %w", err)
	}
	return r.Encrypt(packet, sharedKey, isUDP)
}

// encryptPQ encrypts a DNS response for a PQ query.  For initial queries it
// issues a resumption ticket in the response control block.
func (s *Server) encryptPQ(packet []byte, q *dnscryptcrypto.EncryptedQuery, r *dnscryptcrypto.EncryptedResponse, isUDP bool) ([]byte, error) {
	var sharedKey [dnscryptcrypto.SharedKeySize]byte
	curr := s.current()

	if len(q.PQCiphertext) > 0 {
		// Reuse the shared key from decrypt when available — the client
		// reuses encapsulations and decryptPQInitial has already derived
		// it from the same (ct, serverPrivateKey) pair.
		if q.SharedKey != [dnscryptcrypto.SharedKeySize]byte{} {
			sharedKey = q.SharedKey
		} else {
			kemSS := dnscryptcrypto.PQDecapsulate(q.PQCiphertext, curr.PQ.PqPrivateKey)
			sharedKey = dnscryptcrypto.PQDeriveSharedKey(kemSS, q.ClientMagic, curr.PQ.PqCertContext, q.PQCiphertext)
		}

		// Issue a resumption ticket.
		resumeSecret := dnscryptcrypto.PQResumeSecret(sharedKey, q.ClientMagic, q.Nonce[:dnscryptcrypto.NonceSize/2])
		ticketExpiry := dnscryptcrypto.NowUnix32() + uint32(config.DefaultDNSCryptPQTicketLifetime/time.Second)
		peHash := dnscryptcrypto.ProfileExtensionHash()
		plaintext := dnscryptcrypto.EncodeTicketPlaintext(
			resumeSecret, q.ClientMagic, curr.Classical.Serial,
			curr.Classical.NotAfter, ticketExpiry, peHash,
		)
		var nonce [dnscryptcrypto.XchachaNonceSize]byte
		if _, randErr := rand.Read(nonce[:]); randErr != nil {
			return nil, fmt.Errorf("generating ticket nonce: %w", randErr)
		}
		sealed := dnscryptcrypto.PQSealTicket(&s.ticketKey, &s.ticketKeyID, &nonce, plaintext)
		r.PQControl = dnscryptcrypto.PQBuildControlBlock(sealed, uint32(config.DefaultDNSCryptPQTicketLifetime/time.Second))
		log.Debugf("DNSCRYPT: PQ ticket issued (expires in %ds)", config.DefaultDNSCryptPQTicketLifetime/time.Second)
	} else {
		// Resumed query: use the shared key derived during decrypt.
		sharedKey = q.SharedKey
		log.Debugf("DNSCRYPT: PQ resumed response")
	}

	return r.Encrypt(packet, sharedKey, isUDP)
}

// decrypt tries to decrypt the query: PQ resumed → PQ ciphertext → classical.
// Keys are tried newest-first to handle rotation overlap (§8).
func (s *Server) decrypt(b []byte) (msg *dns.Msg, query *dnscryptcrypto.EncryptedQuery, err error) {
	// PQ resumed queries don't carry a client magic — try them first.
	if len(b) >= dnscryptcrypto.PQResumeMagicLen && bytes.Equal(b[:dnscryptcrypto.PQResumeMagicLen], dnscryptcrypto.PQResumeMagic[:]) {
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
		if bytes.Equal(b[:dnscryptcrypto.ClientMagicSize], k.pair.PQ.ClientMagic[:]) {
			log.Debugf("DNSCRYPT: PQ initial query")
			query = &dnscryptcrypto.EncryptedQuery{
				ESVersion:     dnscryptcrypto.XWingPQ,
				ClientMagic:   k.pair.PQ.ClientMagic,
				PQCertContext: k.pair.PQ.PqCertContext,
			}
			var resolverSk [dnscryptcrypto.KeySize]byte
			copy(resolverSk[:], k.pair.PQ.PqPrivateKey)
			decrypted, decErr := query.Decrypt(b, resolverSk)
			if decErr == nil {
				// NOTE(L10): could use pool.DefaultMessage.Get() here — left as &dns.Msg{}
				// because pool ownership semantics differ for decrypt-shortlived messages.
				msg = &dns.Msg{}
				msg.Data = decrypted
				if unpackErr := msg.Unpack(); unpackErr != nil {
					return nil, nil, fmt.Errorf("unpacking dns message: %w", unpackErr)
				}
				return msg, query, nil
			}
		}

		// Try classical.
		if bytes.Equal(b[:dnscryptcrypto.ClientMagicSize], k.pair.Classical.ClientMagic[:]) {
			log.Debugf("DNSCRYPT: classical query")
			query = &dnscryptcrypto.EncryptedQuery{
				ESVersion:   dnscryptcrypto.XChacha20Poly1305,
				ClientMagic: k.pair.Classical.ClientMagic,
			}
			decrypted, decErr := query.Decrypt(b, k.pair.Classical.ResolverSk)
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
func (s *Server) decryptPQResumed(b []byte) (msg *dns.Msg, query *dnscryptcrypto.EncryptedQuery, err error) {
	ticket, nonceHalf, payloadOff, err := dnscryptcrypto.ParsePQResumedHeader(b)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing PQ resumed query: %w", err)
	}

	ticketPlain, err := dnscryptcrypto.PQOpenTicket(&s.ticketKey, &s.ticketKeyID, ticket)
	if err != nil {
		return nil, nil, fmt.Errorf("opening PQ ticket: %w", err)
	}
	clientMagic, resumeSecret, ticketExpiry, err := dnscryptcrypto.DecodeTicketPlaintext(ticketPlain)
	if err != nil {
		return nil, nil, fmt.Errorf("decoding PQ ticket: %w", err)
	}
	if ticketExpiry < dnscryptcrypto.NowUnix32() {
		return nil, nil, dnscryptcrypto.ErrPQTicketExpired
	}

	peHash := dnscryptcrypto.ProfileExtensionHash()

	// Snapshot keys under read lock — rotateKeys() writes under write lock.
	s.mu.RLock()
	keysSnapshot := s.keys
	s.mu.RUnlock()

	var matchedPair *dnscryptcrypto.CertPair
	for _, k := range keysSnapshot {
		if clientMagic == k.pair.PQ.ClientMagic &&
			bytes.Equal(ticketPlain[dnscryptcrypto.TicketPlaintextESOff:dnscryptcrypto.TicketPlaintextESOff+dnscryptcrypto.TicketPlaintextESLen], dnscryptcrypto.PQESVersion[:]) &&
			binary.BigEndian.Uint32(ticketPlain[dnscryptcrypto.TicketPlaintextSerialOff:dnscryptcrypto.TicketPlaintextSerialOff+dnscryptcrypto.TicketPlaintextSerialLen]) == k.pair.Classical.Serial &&
			binary.BigEndian.Uint32(ticketPlain[dnscryptcrypto.TicketPlaintextTSEndOff:dnscryptcrypto.TicketPlaintextTSEndOff+dnscryptcrypto.TicketPlaintextTSEndLen]) == k.pair.Classical.NotAfter &&
			bytes.Equal(ticketPlain[dnscryptcrypto.TicketPlaintextPEHashOff:dnscryptcrypto.TicketPlaintextPEHashOff+dnscryptcrypto.TicketPlaintextPEHashLen], peHash[:]) {
			matchedPair = k.pair
			break
		}
	}
	if matchedPair == nil {
		return nil, nil, dnscryptcrypto.ErrPQInvalidTicket
	}

	sharedKey := dnscryptcrypto.PQResumedSharedKey(resumeSecret, matchedPair.PQ.ClientMagic, nonceHalf, ticket)

	query = &dnscryptcrypto.EncryptedQuery{
		ESVersion:   dnscryptcrypto.XWingPQ,
		ClientMagic: matchedPair.PQ.ClientMagic,
		SharedKey:   sharedKey,
	}
	copy(query.Nonce[:dnscryptcrypto.NonceSize/2], nonceHalf)
	query.PQTicket = ticket

	encrypted := b[payloadOff:]
	decrypted, err := query.DecryptPQResumedPayload(encrypted, sharedKey)
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
