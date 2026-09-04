// DNSCrypt certificate lifecycle: key-pair generation, rotation, renewal
// loop, persistence, and the certificate TXT records served for resolver
// discovery.

package dnscrypt

import (
	"errors"
	"fmt"
	"time"
	"zjdns/config"
	"zjdns/dnscert"
	dnscryptcrypto "zjdns/internal/dnscryptcrypto"
	"zjdns/internal/log"
	"zjdns/internal/lrumap"

	zdnsutil "zjdns/internal/dnsutil"

	"github.com/cloudflare/circl/sign/ed25519"
)

// keyEntry holds a pair of classical and PQ certificates for one key window.
// Window expiry is judged by the cert's NotAfter (24h validity); keyEntry
// itself carries no timestamps.  Certificates are immutable once minted —
// handshake marshals them on demand.
type keyEntry struct {
	pair *dnscryptcrypto.CertPair

	// Precomputed handshake artifacts: the certificate is immutable once
	// minted, but every cert fetch used to re-marshal (~1.3 KB PQ cert),
	// backslash-escape and re-chunk it per query.
	classicalTXT []string
	pqTXT        []string
	pqWireSize   int
}

// newKeyEntry precomputes the pair's TXT chunks (classical and PQ) and the
// PQ wire size — they are served on every certificate fetch.
func newKeyEntry(pair *dnscryptcrypto.CertPair) keyEntry {
	return keyEntry{
		pair:         pair,
		classicalTXT: buildCertTXTForCert(pair.Classical),
		pqTXT:        buildCertTXTForCert(pair.PQ),
		pqWireSize:   certTXTWireSize(pair.PQ),
	}
}

// ResetKeys regenerates the DNSCrypt crypto state from fresh random keys:
// a single new cert window replaces all current windows and the state is
// persisted immediately (CHAOS zjdns.dnscrypt.clear).  The provider identity
// (signingSK) comes from config and is unchanged — the sdns:// stamp stays
// valid, but clients must fetch the new certificate to reconnect.
func (s *Server) ResetKeys() error {
	now := dnscryptcrypto.NowUnix32()
	// Serialized with updateKeys (renewal ticker) under s.mu — concurrent
	// minting from the same previous produced duplicate windows (M-3-5).
	s.mu.Lock()
	// Passing nil previous breaks the seed chain: the reset window starts
	// a new chain from a fresh random seed.
	entries := s.deriveAndSign(nil, now)
	if len(entries) == 0 {
		s.mu.Unlock()
		return errors.New("dnscrypt: reset: failed to generate fresh key pair")
	}

	// Clear old shared key cache before replacing to release cached keys.
	s.sharedKeyCache.Clear()
	s.sharedKeyCache = lrumap.New[[32]byte, [32]byte](config.DefaultDNSCryptSharedKeyCacheSize)
	// The PQ ticket key is fixed (derived from the signing key at startup);
	// it is not rotated alongside cert keys.
	serial := entries[0].pair.Classical.Serial
	s.keys = entries
	s.mu.Unlock()

	if err := s.Save(); err != nil {
		return fmt.Errorf("dnscrypt: persist reset state: %w", err)
	}
	log.Infof("DNSCRYPT: keys reset (serial=%d)", serial)
	return nil
}

// Save persists the current identity + windows via the StateStore.
// No-op when no store is configured.  Safe to call concurrently with queries.
func (s *Server) Save() error {
	if s.store == nil {
		return nil
	}
	identity := encodeIdentity(s.signingSK)
	if identity == nil {
		return errors.New("dnscrypt: signing key is not Ed25519")
	}
	s.mu.RLock()
	windows := encodeWindows(stateWindows(s.keys))
	s.mu.RUnlock()
	return s.store.SaveDNSCryptState(identity, windows)
}

// renewalLoop renews the resolver short-term keys on a fixed renewal
// interval (matching the reference encrypted-dns-server's 8h ticker) and
// purges expired windows on a short safety-net sweep.  Renewal timing is
// deliberately NOT anchored to window boundaries: updateKeys() runs at
// startup and walks the seed chain forward, so a missed boundary is always
// caught up on the next call.
func (s *Server) renewalLoop() {
	defer zdnsutil.HandlePanic("DNSCRYPT key rotation")
	renewal := time.NewTicker(config.DefaultDNSCryptCertificateRenewal)
	defer renewal.Stop()
	purge := time.NewTicker(config.DefaultDNSCryptKeyPurgeInterval)
	defer purge.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-renewal.C:
			s.updateKeys()
		case <-purge.C:
			s.purgeExpiredKeys()
		case <-s.rotateCh:
			return
		}
	}
}

// purgeExpiredKeys removes key windows whose NotAfter has passed, always
// keeping the newest entry so the key list is never empty.  The
// authoritative purge happens inside updateKeys(); this short-interval sweep
// only makes removal prompt between renewals.
func (s *Server) purgeExpiredKeys() {
	now := dnscryptcrypto.NowUnix32()
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, k := range s.keys {
		if n > 0 && k.pair.Classical.NotAfter < now {
			continue
		}
		s.keys[n] = k
		n++
	}
	removed := len(s.keys) - n
	if removed > 0 {
		s.keys = s.keys[:n]
		log.Debugf("DNSCRYPT: purged %d expired key window(s), active=%d", removed, n)
	}
}

// current returns the newest key pair (the one used for encrypting responses).
// Returns nil when no window is active — updateKeys() briefly holds no keys
// between purging expired windows and minting replacements.
func (s *Server) current() *dnscryptcrypto.CertPair {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.keys) == 0 {
		return nil
	}
	return s.keys[0].pair
}

// updateKeys renews the certificate windows, mirroring the reference
// encrypted-dns-server update(): windows past NotAfter are purged, then the
// seed chain is walked forward from the newest surviving window to mint every
// window whose start falls within now+renewal.  Called on the renewal ticker
// and once at startup to catch up on renewals missed while stopped.
func (s *Server) updateKeys() {
	now := dnscryptcrypto.NowUnix32()

	// Window minting is serialized under s.mu: ResetKeys (CHAOS handler)
	// and the renewal ticker can otherwise run concurrently, both deriving
	// from the same previous and minting duplicate windows for the same
	// tsStart (M-3-5).  deriveAndSign is ~ms-scale (signing) and runs at
	// startup/ticker frequency — blocking decrypts briefly is acceptable.
	s.mu.Lock()

	// Purge windows past NotAfter (no overlap grace).
	n := 0
	for _, k := range s.keys {
		if k.pair.Classical.NotAfter >= now {
			s.keys[n] = k
			n++
		}
	}
	s.keys = s.keys[:n]
	var previous *dnscryptcrypto.CertPair
	if len(s.keys) > 0 {
		previous = s.keys[0].pair // newest-first order
	}

	newEntries := s.deriveAndSign(previous, now)
	if len(newEntries) == 0 && len(s.keys) == 0 {
		// Nothing usable at all (e.g. chain generation failed): mint an
		// emergency window from a fresh random seed.
		newEntries = s.deriveAndSign(nil, now)
	}
	if len(newEntries) > 0 {
		s.keys = append(newEntries, s.keys...)
		// Clear old shared key cache before replacing to release cached keys.
		s.sharedKeyCache.Clear()
		s.sharedKeyCache = lrumap.New[[32]byte, [32]byte](config.DefaultDNSCryptSharedKeyCacheSize)
		// The PQ ticket key is fixed (derived from the signing key at
		// startup); it is not rotated alongside cert keys.
	}
	active := len(s.keys)
	s.mu.Unlock()

	// Persist the new window set outside the lock: Save() takes RLock
	// itself, and holding the write lock would deadlock.
	if err := s.Save(); err != nil {
		log.Warnf("DNSCRYPT: failed to persist rotated state: %v", err)
	}

	log.Debugf("DNSCRYPT: renewed certificates (active=%d)", active)
}

// deriveAndSign walks the seed chain forward from previous and returns every
// window whose start falls within [now, now+renewal], newest first.  Each
// window's X25519 resolver key is derived from the previous window's secret
// key (ratchet: seed_0 → kp_0 → sk_0-as-seed_1 → kp_1 → …), matching the
// reference encrypted-dns-server.  A nil previous mints a single window from
// a fresh random seed — the start of a new chain.
func (s *Server) deriveAndSign(previous *dnscryptcrypto.CertPair, now uint32) []keyEntry {
	rc := dnscert.ResolverConfig{
		ProviderName: s.providerName,
		PublicKey:    dnscryptcrypto.HexEncodeKey(s.signingSK.Public().(ed25519.PublicKey)),
		PrivateKey:   dnscryptcrypto.HexEncodeKey(s.signingSK),
	}

	renewalSec := uint32(config.DefaultDNSCryptCertificateRenewal / time.Second)
	ttlSec := uint32(config.DefaultDNSCryptCertificateTTL / time.Second)

	var (
		tsStart uint32
		seed    [32]byte
	)
	if previous == nil {
		sk, _, err := dnscryptcrypto.GenerateRandomKeyPair()
		if err != nil {
			log.Warnf("DNSCRYPT: generating fresh resolver keys: %v", err)
			return nil
		}
		seed = sk
		tsStart = now
	} else {
		seed = previous.Classical.ResolverSk
		tsStart = previous.Classical.NotBefore + renewalSec
	}

	var entries []keyEntry // newest first
	for tsStart <= now+renewalSec {
		sk, pk := dnscryptcrypto.X25519KeyPairFromSeed(seed)
		seed = sk // chain: this window's SK seeds the next

		if now >= tsStart {
			rc.ResolverSk = dnscryptcrypto.HexEncodeKey(sk[:])
			rc.ResolverPk = dnscryptcrypto.HexEncodeKey(pk[:])
			pair, err := rc.NewCertPair(tsStart, tsStart+ttlSec)
			if err != nil {
				log.Warnf("DNSCRYPT: generating cert pair (ts_start=%d): %v", tsStart, err)
				tsStart += renewalSec
				continue
			}
			entries = append([]keyEntry{newKeyEntry(pair)}, entries...)
		}
		tsStart += renewalSec
	}
	return entries
}

func buildCertTXTForCert(cert *dnscryptcrypto.Certificate) []string {
	certBytes, err := cert.MarshalBinary()
	if err != nil {
		log.Warnf("DNSCRYPT: marshal cert failed: %v", err)
		return nil
	}
	escaped := escapeBackslash(certBytes)
	// Maximum length of a single DNS TXT character-string per RFC 1035 §3.3.
	const maxChunk = 255
	var chunks []string
	for i := 0; i < len(escaped); i += maxChunk {
		end := min(i+maxChunk, len(escaped))
		chunks = append(chunks, string(escaped[i:end]))
	}
	return chunks
}

func certTXTWireSize(cert *dnscryptcrypto.Certificate) int {
	certBytes, err := cert.MarshalBinary()
	if err != nil {
		return 0
	}
	escaped := escapeBackslash(certBytes)
	nChunks := (len(escaped) + 254) / 255
	// RR header (pointer compressed name): type(2) + class(2) + ttl(4) + rdlength(2)
	// Rdata: 1-byte length prefix per chunk + chunk data
	rdataLen := nChunks + len(escaped)
	return 12 + rdataLen
}

func escapeBackslash(b []byte) []byte {
	n := 0
	for _, c := range b {
		if c == '\\' {
			n++
		}
	}
	if n == 0 {
		return b
	}
	out := make([]byte, 0, len(b)+n)
	for _, c := range b {
		if c == '\\' {
			out = append(out, '\\', '\\')
		} else {
			out = append(out, c)
		}
	}
	return out
}
