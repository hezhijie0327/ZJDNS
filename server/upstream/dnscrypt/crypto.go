package dnscrypt

import (
	"crypto/rand"
	"fmt"
	"time"
	dnscryptcrypto "zjdns/internal/dnscryptcrypto"
	"zjdns/internal/log"
)

// prepareQuery handles both classical and PQ query encryption.
func prepareQuery(state *State, q *dnscryptcrypto.EncryptedQuery, packet []byte) (encrypted []byte, clientNonce dnscryptcrypto.Nonce, err error) {
	if !state.esVersion.IsPQ() {
		return dnscryptcrypto.EncryptQuery(q, packet, state.sharedKey)
	}

	// PQ: try resumed query first, fall back to fresh encapsulation.
	if len(state.pqTicket) > 0 && time.Now().Before(state.pqTicketExpiry) {
		q.Nonce = newNonce()
		sharedKey, err := dnscryptcrypto.PQResumedSharedKey(state.pqResumeSecret, state.clientMagic, q.Nonce[:dnscryptcrypto.NonceSize/2], state.pqTicket)
		if err != nil {
			return nil, dnscryptcrypto.Nonce{}, fmt.Errorf("deriving PQ resumed shared key: %w", err)
		}
		state.sharedKey = sharedKey
		q.PQTicket = state.pqTicket
		log.Debugf("UPSTREAM: DNSCrypt PQ resumed query to %s", state.serverAddress)
		return dnscryptcrypto.EncryptQuery(q, packet, sharedKey)
	}

	// Try cached encapsulation first to avoid expensive X-Wing KEM.
	if len(state.pqCiphertext) > 0 {
		state.sharedKey = state.pqEncapsulatedKey
		q.PQCiphertext = state.pqCiphertext
		log.Debugf("UPSTREAM: DNSCrypt PQ query (cached encapsulation) to %s", state.serverAddress)
		return dnscryptcrypto.EncryptQuery(q, packet, state.sharedKey)
	}

	// Fresh PQ query: encapsulate X-Wing.
	kemSS, ct, encapErr := dnscryptcrypto.PQEncapsulate(state.pqPublicKey)
	if encapErr != nil {
		return nil, dnscryptcrypto.Nonce{}, fmt.Errorf("X-Wing encapsulate: %w", encapErr)
	}
	sharedKey, err := dnscryptcrypto.PQDeriveSharedKey(kemSS, state.clientMagic, state.pqCertContext, ct)
	if err != nil {
		return nil, dnscryptcrypto.Nonce{}, fmt.Errorf("deriving PQ shared key: %w", err)
	}
	state.sharedKey = sharedKey
	state.pqCiphertext = ct
	state.pqEncapsulatedKey = sharedKey
	q.PQCiphertext = ct
	log.Debugf("UPSTREAM: DNSCrypt PQ query (fresh X-Wing encapsulation) to %s", state.serverAddress)
	return dnscryptcrypto.EncryptQuery(q, packet, sharedKey)
}

// newNonce generates a fresh 24-byte client nonce.
func newNonce() dnscryptcrypto.Nonce {
	var n dnscryptcrypto.Nonce
	_, _ = rand.Read(n[:dnscryptcrypto.NonceSize/2])
	return n
}
