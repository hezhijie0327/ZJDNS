package dnscrypt

import (
	"crypto/rand"
	"crypto/sha512"
	"fmt"
	"time"
	dnscryptcrypto "zjdns/internal/dnscryptcrypto"
	"zjdns/internal/log"
)

// prepareQuery handles both classical and PQ query encryption.
// Returns the shared key used for encryption so the caller can decrypt
// the response without reading state.sharedKey outside the lock.
func prepareQuery(state *State, q *dnscryptcrypto.EncryptedQuery, packet []byte) (encrypted []byte, clientNonce dnscryptcrypto.Nonce, sharedKey [dnscryptcrypto.SharedKeySize]byte, err error) {
	if !state.esVersion.IsPQ() {
		sk := state.sharedKey
		if state.ephemeralKeys {
			// Pre-generate nonce so we can derive the ephemeral key from it.
			// SHA-512/256 is used here as a KDF to derive an X25519 seed from
			// (nonce || secretKey).  This is NOT password hashing — secretKey is
			// an X25519 private key, and the construction must match dnscrypt-proxy
			// for interoperability.
			q.Nonce = newNonce()
			seed := sha512.Sum512_256(append(q.Nonce[:dnscryptcrypto.NonceSize/2], state.secretKey[:]...))
			epSk, epPk, epErr := dnscryptcrypto.X25519KeyPairFromSeed(seed)
			if epErr != nil {
				return nil, dnscryptcrypto.Nonce{}, [dnscryptcrypto.SharedKeySize]byte{}, fmt.Errorf("ephemeral key: %w", epErr)
			}
			q.ClientPk = epPk
			epSharedKey, epErr := dnscryptcrypto.ComputeSharedKey(dnscryptcrypto.XChacha20Poly1305, &epSk, &state.resolverPK)
			if epErr != nil {
				return nil, dnscryptcrypto.Nonce{}, [dnscryptcrypto.SharedKeySize]byte{}, fmt.Errorf("ephemeral shared key: %w", epErr)
			}
			sk = epSharedKey
		}
		enc, nonce, err := q.Encrypt(packet, sk)
		return enc, nonce, sk, err
	}

	// PQ: try resumed query first, fall back to fresh encapsulation.
	if len(state.pqTicket) > 0 && time.Now().Before(state.pqTicketExpiry) {
		q.Nonce = newNonce()
		sharedKey, err := dnscryptcrypto.PQResumedSharedKey(state.pqResumeSecret, state.clientMagic, q.Nonce[:dnscryptcrypto.NonceSize/2], state.pqTicket)
		if err != nil {
			return nil, dnscryptcrypto.Nonce{}, [dnscryptcrypto.SharedKeySize]byte{}, fmt.Errorf("deriving PQ resumed shared key: %w", err)
		}
		state.sharedKey = sharedKey
		q.PQTicket = state.pqTicket
		log.Debugf("UPSTREAM: DNSCrypt PQ resumed query to %s", state.serverAddress)
		enc, nonce, err := q.Encrypt(packet, sharedKey)
		return enc, nonce, sharedKey, err
	}

	// RFC §11.10: cached encapsulation trades per-query forward secrecy
	// for performance (§11.10 fresh-per-query is ideal). Encapsulation
	// rotates on cert refresh, bounding linkability to cert lifetime.
	if len(state.pqCiphertext) > 0 {
		state.sharedKey = state.pqEncapsulatedKey
		q.PQCiphertext = state.pqCiphertext
		log.Debugf("UPSTREAM: DNSCrypt PQ query (cached encapsulation) to %s", state.serverAddress)
		enc, nonce, err := q.Encrypt(packet, state.sharedKey)
		return enc, nonce, state.sharedKey, err
	}

	// Fresh PQ query: encapsulate X-Wing.
	kemSS, ct, encapErr := dnscryptcrypto.PQEncapsulate(state.pqPublicKey)
	if encapErr != nil {
		return nil, dnscryptcrypto.Nonce{}, [dnscryptcrypto.SharedKeySize]byte{}, fmt.Errorf("X-Wing encapsulate: %w", encapErr)
	}
	derivedKey, err := dnscryptcrypto.PQDeriveSharedKey(kemSS, state.clientMagic, state.pqCertContext, ct)
	if err != nil {
		return nil, dnscryptcrypto.Nonce{}, [dnscryptcrypto.SharedKeySize]byte{}, fmt.Errorf("deriving PQ shared key: %w", err)
	}
	state.sharedKey = derivedKey
	state.pqCiphertext = ct
	state.pqEncapsulatedKey = derivedKey
	q.PQCiphertext = ct
	log.Debugf("UPSTREAM: DNSCrypt PQ query (fresh X-Wing encapsulation) to %s", state.serverAddress)
	enc, nonce, err := q.Encrypt(packet, derivedKey)
	return enc, nonce, derivedKey, err
}

// newNonce generates a fresh 24-byte client nonce.
func newNonce() dnscryptcrypto.Nonce {
	var n dnscryptcrypto.Nonce
	_, _ = rand.Read(n[:dnscryptcrypto.NonceSize/2]) // _ = error: crypto/rand.Read never fails on modern kernels
	return n
}
