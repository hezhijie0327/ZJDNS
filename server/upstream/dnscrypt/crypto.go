package dnscrypt

import (
	"crypto/rand"
	"fmt"
	"time"
	dnscryptcrypto "zjdns/internal/dnscryptcrypto"
)

// prepareQuery handles both classical and PQ query encryption.
func prepareQuery(state *State, q *dnscryptcrypto.EncryptedQuery, packet []byte) (encrypted []byte, clientNonce dnscryptcrypto.Nonce, err error) {
	if !state.esVersion.IsPQ() {
		return dnscryptcrypto.EncryptQuery(q, packet, state.sharedKey)
	}

	// PQ: try resumed query first, fall back to fresh encapsulation.
	if len(state.pqTicket) > 0 && time.Now().Before(state.pqTicketExpiry) {
		q.Nonce = newNonce()
		sharedKey := dnscryptcrypto.PQResumedSharedKey(state.pqResumeSecret, state.clientMagic, q.Nonce[:dnscryptcrypto.NonceSize/2], state.pqTicket)
		state.sharedKey = sharedKey
		q.PQTicket = state.pqTicket
		return dnscryptcrypto.EncryptQuery(q, packet, sharedKey)
	}

	// Try cached encapsulation first to avoid expensive X-Wing KEM.
	if len(state.pqCiphertext) > 0 {
		state.sharedKey = state.pqEncapsulatedKey
		q.PQCiphertext = state.pqCiphertext
		return dnscryptcrypto.EncryptQuery(q, packet, state.sharedKey)
	}

	// Fresh PQ query: encapsulate X-Wing.
	kemSS, ct, encapErr := dnscryptcrypto.PQEncapsulate(state.pqPublicKey)
	if encapErr != nil {
		return nil, dnscryptcrypto.Nonce{}, fmt.Errorf("X-Wing encapsulate: %w", encapErr)
	}
	sharedKey := dnscryptcrypto.PQDeriveSharedKey(kemSS, state.clientMagic, state.pqCertContext, ct)
	state.sharedKey = sharedKey
	state.pqCiphertext = ct
	state.pqEncapsulatedKey = sharedKey
	q.PQCiphertext = ct
	return dnscryptcrypto.EncryptQuery(q, packet, sharedKey)
}

// newNonce generates a fresh 24-byte client nonce.
func newNonce() dnscryptcrypto.Nonce {
	var n dnscryptcrypto.Nonce
	_, _ = rand.Read(n[:dnscryptcrypto.NonceSize/2])
	return n
}
