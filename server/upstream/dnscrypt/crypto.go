package dnscrypt

import (
	"crypto/rand"
	"crypto/sha512"
	"fmt"
	"time"
	"zjdns/config"
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
			// The ephemeral key pair rotates on a time window instead of per
			// query: the per-query pair cost two X25519 operations per query
			// (keygen + shared-key derivation) while serializing every query
			// to this upstream behind state.mu.
			//
			// Security tradeoff of the window: the seed derivation
			// SHA-512/256(nonce || secretKey) is DETERMINISTIC — anyone who
			// later learns state.secretKey can re-derive every past
			// ephemeral key either way, so per-query keys never provided
			// forward secrecy against secretKey compromise.  The window only
			// widens the exposure of a narrow case (the ephemeral shared key
			// leaking alone, e.g. a memory-scrape of exactly this buffer)
			// from one query to at most DefaultDNSCryptEphemeralKeyWindow of
			// traffic to one resolver — still strictly tighter than the
			// non-ephemeral long-term shared key (state.sharedKey), which
			// never rotates.
			//
			// The client nonce stays fresh per query; only the key pair is
			// windowed.  A stable ClientPk per window also lets the
			// resolver-side shared-key cache (decrypt path) actually hit.
			if now := time.Now(); now.After(state.ephemeralEnd) {
				// Pre-generate a fresh nonce so the key derivation matches
				// dnscrypt-proxy's ephemeralKeys construction.  SHA-512/256
				// is used here as a KDF to derive an X25519 seed from
				// (nonce || secretKey).  This is NOT password hashing —
				// secretKey is an X25519 private key, and the construction
				// must match dnscrypt-proxy for interoperability.  (CodeQL
				// false positive: go/weak-sensitive-data-hashing)
				rotateNonce := newNonce()
				seed := sha512.Sum512_256(append(rotateNonce[:dnscryptcrypto.NonceSize/2], state.secretKey[:]...))
				epSk, epPk := dnscryptcrypto.X25519KeyPairFromSeed(seed)
				epSharedKey, epErr := dnscryptcrypto.ComputeSharedKey(dnscryptcrypto.XChacha20Poly1305, &epSk, &state.resolverPK)
				if epErr != nil {
					return nil, dnscryptcrypto.Nonce{}, [dnscryptcrypto.SharedKeySize]byte{}, fmt.Errorf("ephemeral shared key: %w", epErr)
				}
				state.ephemeralSK, state.ephemeralPK, state.ephemeralShared = epSk, epPk, epSharedKey
				state.ephemeralEnd = now.Add(config.DefaultDNSCryptEphemeralKeyWindow)
			}
			q.Nonce = newNonce()
			q.ClientPk = state.ephemeralPK
			sk = state.ephemeralShared
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

	// Try cached encapsulation first to avoid expensive X-Wing KEM.
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
