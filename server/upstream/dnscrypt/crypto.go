package dnscrypt

import (
	"crypto/rand"
	"fmt"
	"time"
	serverdnscrypt "zjdns/server/protocol/dnscrypt"
)

// prepareQuery handles both classical and PQ query encryption.
func prepareQuery(state *State, q *serverdnscrypt.EncryptedQuery, packet []byte) (encrypted []byte, clientNonce serverdnscrypt.Nonce, err error) {
	if !state.esVersion.IsPQ() {
		return serverdnscrypt.EncryptQuery(q, packet, state.sharedKey)
	}

	// PQ: try resumed query first, fall back to fresh encapsulation.
	if len(state.pqTicket) > 0 && time.Now().Before(state.pqTicketExpiry) {
		q.ClientNonce = newNonce()
		sharedKey := serverdnscrypt.PQResumedSharedKey(state.pqResumeSecret, state.clientMagic, q.ClientNonce[:serverdnscrypt.NonceSize/2], state.pqTicket)
		state.sharedKey = sharedKey
		q.PQTicket = state.pqTicket
		return serverdnscrypt.EncryptQuery(q, packet, sharedKey)
	}

	// Try cached encapsulation first to avoid expensive X-Wing KEM.
	if len(state.pqCiphertext) > 0 {
		state.sharedKey = state.pqEncapsulatedKey
		q.PQCiphertext = state.pqCiphertext
		return serverdnscrypt.EncryptQuery(q, packet, state.sharedKey)
	}

	// Fresh PQ query: encapsulate X-Wing.
	kemSS, ct, encapErr := serverdnscrypt.PQEncapsulate(state.pqPublicKey)
	if encapErr != nil {
		return nil, serverdnscrypt.Nonce{}, fmt.Errorf("X-Wing encapsulate: %w", encapErr)
	}
	sharedKey := serverdnscrypt.PQDeriveSharedKey(kemSS, state.clientMagic, state.pqCertContext, ct)
	state.sharedKey = sharedKey
	state.pqCiphertext = ct
	state.pqEncapsulatedKey = sharedKey
	q.PQCiphertext = ct
	return serverdnscrypt.EncryptQuery(q, packet, sharedKey)
}

// newNonce generates a fresh 24-byte client nonce.
func newNonce() serverdnscrypt.Nonce {
	var n serverdnscrypt.Nonce
	_, _ = rand.Read(n[:serverdnscrypt.NonceSize/2])
	return n
}
