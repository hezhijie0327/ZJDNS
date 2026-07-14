package dnscrypt

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"zjdns/config"

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

	sharedKey, err := computeSharedKey(q.esVersion, &s.cert.ResolverSk, &q.clientPk)
	if err != nil {
		return nil, fmt.Errorf("computing shared key: %w", err)
	}
	return r.encrypt(packet, sharedKey, isUDP)
}

// encryptPQ encrypts a DNS response for a PQ query.  For initial queries it
// issues a resumption ticket in the response control block.
func (s *Server) encryptPQ(packet []byte, q *encryptedQuery, r *encryptedResponse, isUDP bool) ([]byte, error) {
	var sharedKey [SharedKeySize]byte

	if len(q.pqCiphertext) > 0 {
		// Reuse the shared key from decrypt when available — the client
		// reuses encapsulations and decryptPQInitial has already derived
		// it from the same (ct, serverPrivateKey) pair.
		if q.sharedKey != [SharedKeySize]byte{} {
			sharedKey = q.sharedKey
		} else {
			kemSS := pqDecapsulate(q.pqCiphertext, s.cert.PqPrivateKey)
			sharedKey = pqDeriveSharedKey(kemSS, q.clientMagic, s.cert.PqCertContext, q.pqCiphertext)
		}

		// Issue a resumption ticket.
		resumeSecret := pqResumeSecret(sharedKey, q.clientMagic, q.nonce[:NonceSize/2])
		ticketExpiry := nowUnix32() + uint32(config.DefaultDNSCryptPQTicketLifetime)
		peHash := profileExtensionHash()
		plaintext := encodeTicketPlaintext(
			resumeSecret, q.clientMagic, s.cert.Serial,
			s.cert.NotAfter, ticketExpiry, peHash,
		)
		var nonce [xchachaNonceSize]byte
		if _, randErr := rand.Read(nonce[:]); randErr != nil {
			return nil, fmt.Errorf("generating ticket nonce: %w", randErr)
		}
		sealed := pqSealTicket(&s.ticketKey, &s.ticketKeyID, &nonce, plaintext)
		r.pqControl = pqBuildControlBlock(sealed, config.DefaultDNSCryptPQTicketLifetime)
	} else {
		// Resumed query: use the shared key derived during decrypt.
		sharedKey = q.sharedKey
	}

	return r.encrypt(packet, sharedKey, isUDP)
}

func (s *Server) decrypt(b []byte) (msg *dns.Msg, query *encryptedQuery, err error) {
	query = &encryptedQuery{
		esVersion:   s.esVersion,
		clientMagic: s.cert.ClientMagic,
	}

	// PQ resumed query: PQResumeMagic, ticket, nonce/2, encrypted.
	if s.esVersion.IsPQ() && len(b) >= PQResumeMagicLen && bytes.Equal(b[:PQResumeMagicLen], PQResumeMagic[:]) {
		return s.decryptPQResumed(b)
	}

	var decrypted []byte
	if s.esVersion.IsPQ() {
		query.pqCertContext = s.cert.PqCertContext
		var resolverSk [KeySize]byte
		copy(resolverSk[:], s.cert.PqPrivateKey)
		decrypted, err = query.decrypt(b, resolverSk)
	} else {
		decrypted, err = query.decrypt(b, s.cert.ResolverSk)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("decrypting query: %w", err)
	}
	msg = &dns.Msg{}
	msg.Data = decrypted
	err = msg.Unpack()
	if err != nil {
		return nil, nil, fmt.Errorf("unpacking dns message: %w", err)
	}
	return msg, query, nil
}

// decryptPQResumed handles a resumed PQ query.
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
	if clientMagic != s.cert.ClientMagic ||
		!bytes.Equal(ticketPlain[ticketPlaintextESOff:ticketPlaintextESOff+ticketPlaintextESLen], PQESVersion[:]) ||
		binary.BigEndian.Uint32(ticketPlain[ticketPlaintextSerialOff:ticketPlaintextSerialOff+ticketPlaintextSerialLen]) != s.cert.Serial ||
		binary.BigEndian.Uint32(ticketPlain[ticketPlaintextTSEndOff:ticketPlaintextTSEndOff+ticketPlaintextTSEndLen]) != s.cert.NotAfter ||
		!bytes.Equal(ticketPlain[ticketPlaintextPEHashOff:ticketPlaintextPEHashOff+ticketPlaintextPEHashLen], peHash[:]) {
		return nil, nil, ErrPQInvalidTicket
	}

	sharedKey := pqResumedSharedKey(resumeSecret, s.cert.ClientMagic, nonceHalf, ticket)

	query = &encryptedQuery{
		esVersion:   s.esVersion,
		clientMagic: s.cert.ClientMagic,
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
