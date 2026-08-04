package dnscrypt

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"time"
	"zjdns/config"
	dnscryptcrypto "zjdns/internal/dnscryptcrypto"
	"zjdns/internal/log"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// tcpMaxPaddingBudget is the worst-case TCP padding overhead of PadResponse:
// up to 256 bytes (§5.4.5, 1+sha256[0]) plus 64-byte alignment.
const tcpMaxPaddingBudget = 256 + 64

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

	maxWireLen := 0
	if isUDP {
		maxWireLen = q.ClientQueryLen
	}

	// §5.4.6 (UDP) & §5.4.7 (TCP) & §11.3 (PQ cert): truncate the DNS response
	// (TC=1) if the encrypted form won't fit within the transport budget.
	// The response MUST NOT be silently dropped — the client needs the TC
	// signal to retry (§5.4.6: "A resolver MUST NOT stay silent instead").
	budget := maxWireLen
	if !isUDP && budget == 0 {
		// §5.4.7: TCP encrypted responses MUST be < 4096 bytes.
		budget = dnscryptcrypto.MaxDNSUDPPacketSize
	}
	if budget > 0 {
		// TCP responses use PadResponse (up to 256 bytes + 64-byte alignment) —
		// the actual wire size can be minOverhead + maxPadding larger than the
		// plaintext.  Reserve worst-case padding budget to stay under the 4096 cap.
		paddingBudget := 0
		if !isUDP {
			paddingBudget = tcpMaxPaddingBudget
		}
		for {
			minOverhead := dnscryptcrypto.MinResponseOverhead(q.ESVersion)
			if len(packet)+minOverhead+paddingBudget <= budget {
				break // fits
			}
			if m.Truncated {
				return nil, fmt.Errorf("%w: plaintext %d + overhead %d exceeds budget %d",
					dnscryptcrypto.ErrResponseTooLarge, len(packet), minOverhead, budget)
			}
			log.Debugf("DNSCRYPT: response (%d bytes + %d overhead) exceeds budget (%d bytes) — truncating with TC",
				len(packet), minOverhead, budget)
			dnsutil.Truncate(m)
			if packErr := m.Pack(); packErr != nil {
				return nil, fmt.Errorf("packing truncated dns message: %w", packErr)
			}
			packet = m.Data
		}
	}

	if q.ESVersion.IsPQ() {
		return s.encryptPQ(packet, q, r, maxWireLen)
	}

	// Reuse the shared key from decrypt when available — the query may
	// have matched a previous key pair during rotation overlap. Computing
	// with s.current() would encrypt with the wrong key (audit finding A).
	sharedKey := q.SharedKey
	if sharedKey == [dnscryptcrypto.SharedKeySize]byte{} {
		curr := s.current()
		if curr == nil {
			return nil, errors.New("dnscrypt: no active key pair")
		}
		var err error
		sharedKey, err = dnscryptcrypto.ComputeSharedKey(dnscryptcrypto.XChacha20Poly1305, &curr.Classical.ResolverSk, &q.ClientPk)
		if err != nil {
			return nil, fmt.Errorf("computing shared key: %w", err)
		}
	}
	return r.Encrypt(packet, sharedKey, maxWireLen)
}

// encryptPQ encrypts a DNS response for a PQ query.  For initial queries it
// issues a resumption ticket in the response control block.
func (s *Server) encryptPQ(packet []byte, q *dnscryptcrypto.EncryptedQuery, r *dnscryptcrypto.EncryptedResponse, maxWireLen int) ([]byte, error) {
	var sharedKey [dnscryptcrypto.SharedKeySize]byte
	curr := s.current()
	if curr == nil {
		return nil, errors.New("dnscrypt: no active key pair")
	}

	var err error
	if len(q.PQCiphertext) > 0 {
		// Reuse the shared key from decrypt when available — the client
		// reuses encapsulations and decryptPQInitial has already derived
		// it from the same (ct, serverPrivateKey) pair.
		if q.SharedKey != [dnscryptcrypto.SharedKeySize]byte{} {
			sharedKey = q.SharedKey
		} else {
			kemSS, kemErr := dnscryptcrypto.PQDecapsulate(q.PQCiphertext, curr.PQ.PqPrivateKey)
			if kemErr != nil {
				return nil, fmt.Errorf("decapsulating PQ ciphertext: %w", kemErr)
			}
			sharedKey, err = dnscryptcrypto.PQDeriveSharedKey(kemSS, q.ClientMagic, curr.PQ.PqCertContext, q.PQCiphertext)
			if err != nil {
				return nil, fmt.Errorf("deriving PQ shared key: %w", err)
			}
		}

		// Issue a resumption ticket.
		var resumeSecret [dnscryptcrypto.SharedKeySize]byte
		var pqErr error
		resumeSecret, pqErr = dnscryptcrypto.PQResumeSecret(sharedKey, q.ClientMagic, q.Nonce[:dnscryptcrypto.NonceSize/2])
		if pqErr != nil {
			return nil, fmt.Errorf("deriving PQ resume secret: %w", pqErr)
		}
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
		// Snapshot ticket keys under read lock — rotateKeys() writes them
		// under write lock; a torn key/ID pair would seal a ticket the
		// server itself cannot open.
		s.mu.RLock()
		ticketKey := s.ticketKey
		ticketKeyID := s.ticketKeyID
		s.mu.RUnlock()
		sealed, err := dnscryptcrypto.PQSealTicket(ticketKey, ticketKeyID, nonce, plaintext)
		if err != nil {
			return nil, fmt.Errorf("sealing PQ ticket: %w", err)
		}
		r.PQControl = dnscryptcrypto.PQBuildControlBlock(sealed, uint32(config.DefaultDNSCryptPQTicketLifetime/time.Second))
		log.Debugf("DNSCRYPT: PQ ticket issued (expires in %ds)", config.DefaultDNSCryptPQTicketLifetime/time.Second)
	} else {
		// Resumed query: use the shared key derived during decrypt.
		sharedKey = q.SharedKey
		log.Debugf("DNSCRYPT: PQ resumed response")
	}

	return r.Encrypt(packet, sharedKey, maxWireLen)
}

// decrypt tries to decrypt the query: PQ resumed → PQ ciphertext → classical.
// Keys are tried newest-first to handle rotation overlap (§8).
func (s *Server) decrypt(b []byte) (msg *dns.Msg, query *dnscryptcrypto.EncryptedQuery, err error) {
	if len(b) < dnscryptcrypto.ClientMagicSize {
		return nil, nil, fmt.Errorf("dnscrypt: packet too short (%d bytes)", len(b))
	}
	// PQ resumed queries don't carry a client magic — try them first.
	if len(b) >= dnscryptcrypto.PQResumeMagicLen && bytes.Equal(b[:dnscryptcrypto.PQResumeMagicLen], dnscryptcrypto.PQResumeMagic[:]) {
		log.Debugf("DNSCRYPT: PQ resumed query")
		return s.decryptPQResumed(b)
	}

	// Snapshot keys and shared key cache under read lock — rotateKeys()
	// writes both under write lock.
	s.mu.RLock()
	keysSnapshot := s.keys
	cacheSnapshot := s.sharedKeyCache
	s.mu.RUnlock()

	// Try each key pair newest-first: PQ first, then classical.
	for _, k := range keysSnapshot {
		// Try PQ ciphertext.
		if bytes.Equal(b[:dnscryptcrypto.ClientMagicSize], k.pair.PQ.ClientMagic[:]) {
			log.Debugf("DNSCRYPT: PQ initial query")
			query = &dnscryptcrypto.EncryptedQuery{
				ESVersion:      dnscryptcrypto.XWingPQ,
				ClientMagic:    k.pair.PQ.ClientMagic,
				PQCertContext:  k.pair.PQ.PqCertContext,
				ClientQueryLen: len(b),
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
				ESVersion:      dnscryptcrypto.XChacha20Poly1305,
				ClientMagic:    k.pair.Classical.ClientMagic,
				ClientQueryLen: len(b),
			}
			decrypted, decErr := query.Decrypt(b, k.pair.Classical.ResolverSk)
			if decErr == nil {
				// RFC §8: cache shared keys to avoid X25519 per query.
				// ClientPk is populated by Decrypt — read after return.
				cpk := query.ClientPk
				if query.SharedKey == [dnscryptcrypto.SharedKeySize]byte{} {
					if cached, ok := cacheSnapshot.Get(cpk); ok {
						query.SharedKey = cached
					} else {
						sk, skErr := dnscryptcrypto.ComputeSharedKey(dnscryptcrypto.XChacha20Poly1305, &k.pair.Classical.ResolverSk, &cpk)
						if skErr == nil {
							cacheSnapshot.Set(cpk, sk)
							query.SharedKey = sk
						}
					}
				}
			}
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

	// Snapshot ticket keys under read lock — rotateKeys() writes them under
	// write lock; a torn key/ID pair would spuriously fail PQ ticket opens.
	s.mu.RLock()
	ticketKey := s.ticketKey
	ticketKeyID := s.ticketKeyID
	prevTicketKey := s.prevTicketKey
	prevTicketKeyID := s.prevTicketKeyID
	s.mu.RUnlock()

	ticketPlain, err := dnscryptcrypto.PQOpenTicket(&ticketKey, &ticketKeyID, &prevTicketKey, &prevTicketKeyID, ticket)
	if err != nil {
		return nil, nil, fmt.Errorf("opening PQ ticket: %w", err)
	}
	ticketInfo, err := dnscryptcrypto.DecodeTicketPlaintext(ticketPlain)
	if err != nil {
		return nil, nil, fmt.Errorf("decoding PQ ticket: %w", err)
	}
	// Enforce the ticket's profile/version binding here instead of
	// re-indexing the raw plaintext.
	if !bytes.Equal(ticketInfo.ESVersion[:], dnscryptcrypto.PQESVersion[:]) {
		return nil, nil, dnscryptcrypto.ErrPQInvalidTicket
	}
	if ticketInfo.Expiry < dnscryptcrypto.NowUnix32() {
		return nil, nil, dnscryptcrypto.ErrPQTicketExpired
	}

	peHash := dnscryptcrypto.ProfileExtensionHash()

	// Snapshot keys under read lock — rotateKeys() writes under write lock.
	s.mu.RLock()
	keysSnapshot := s.keys
	s.mu.RUnlock()

	var matchedPair *dnscryptcrypto.CertPair
	for _, k := range keysSnapshot {
		if ticketInfo.ClientMagic == k.pair.PQ.ClientMagic &&
			ticketInfo.Serial == k.pair.Classical.Serial &&
			ticketInfo.TSEnd == k.pair.Classical.NotAfter &&
			bytes.Equal(ticketInfo.ProfileExtHash[:], peHash[:]) {
			matchedPair = k.pair
			break
		}
	}
	if matchedPair == nil {
		return nil, nil, dnscryptcrypto.ErrPQInvalidTicket
	}

	sharedKey, err := dnscryptcrypto.PQResumedSharedKey(ticketInfo.ResumeSecret, matchedPair.PQ.ClientMagic, nonceHalf, ticket)
	if err != nil {
		return nil, nil, fmt.Errorf("deriving PQ resumed shared key: %w", err)
	}

	query = &dnscryptcrypto.EncryptedQuery{
		ESVersion:      dnscryptcrypto.XWingPQ,
		ClientMagic:    matchedPair.PQ.ClientMagic,
		SharedKey:      sharedKey,
		ClientQueryLen: len(b),
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
