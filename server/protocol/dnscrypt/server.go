package dnscrypt

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
	"zjdns/config"
	"zjdns/edns"
	dnscryptcrypto "zjdns/internal/dnscryptcrypto"
	"zjdns/internal/log"
	"zjdns/internal/lrumap"
	"zjdns/internal/pool"

	zdnsutil "zjdns/internal/dnsutil"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"
	"github.com/cloudflare/circl/sign/ed25519"
)

// keyEntry holds a pair of classical and PQ certificates for one key window.
// Window expiry is judged by the cert's NotAfter (24h validity); keyEntry
// itself carries no timestamps.  Certificates are immutable once minted —
// handshake marshals them on demand.
type keyEntry struct {
	pair *dnscryptcrypto.CertPair
}

// Server is a DNSCrypt v2 server that listens on UDP and TCP.
type Server struct {
	keys []keyEntry // [current, previous, ...], newest first

	handler        edns.DNSHandler
	port           string
	providerName   string
	certificateCfg *config.DNSCryptCertificate
	udpConns       []*net.UDPConn
	tcpListeners   []net.Listener
	wg             *sync.WaitGroup
	tcpConns       map[net.Conn]struct{}
	mu             sync.RWMutex
	started        bool
	ctx            context.Context
	cancel         context.CancelCauseFunc

	// signingSK is the Ed25519 provider identity key.  It stays fixed across
	// resolver-key rotations — the sdns:// stamp encodes only this key.
	signingSK ed25519.PrivateKey

	// ticketKey / ticketKeyID seal PQ resumption tickets.  They are derived
	// from the Ed25519 signing key and NEVER rotate (matching the reference
	// encrypted-dns-server), so a client's ticket stays valid for its whole
	// lifetime regardless of cert-window renewals.
	ticketKey   [dnscryptcrypto.XchachaKeySize]byte
	ticketKeyID [dnscryptcrypto.TicketKeyIDSize]byte

	// Rotation goroutine control.
	rotateCh chan struct{} // closed when rotation goroutine should stop

	// workerCap limits concurrent handler goroutines to prevent unbounded
	// goroutine creation under high load.
	workerCap chan struct{}

	// store persists the identity + cert windows across restarts; nil disables
	// persistence.
	store StateStore

	// sharedKeyCache avoids recomputing X25519 per query for classical
	// DNSCrypt (RFC §8).  Cleared on key rotation.
	sharedKeyCache *lrumap.Map[[32]byte, [32]byte]
}

// New creates a new DNSCrypt Server from the given configuration.
// port is the listener port, providerName is auto-derived as "2.dnscrypt-cert.<ddr.domain>".
// store persists the cert windows across restarts; nil disables persistence.
func New(certificateCfg *config.DNSCryptCertificate, port, providerName string, store StateStore) (*Server, error) {
	// ── Signing identity ───────────────────────────────────────────────────
	// Explicit keys are required — like TLS requires a certificate.  The
	// Ed25519 identity is pinned in config so the sdns:// stamp stays valid
	// across restarts.  Generate one with `zjdns --generate dnscrypt`.
	if certificateCfg.PublicKey == "" || certificateCfg.PrivateKey == "" {
		return nil, errors.New("dnscrypt: certificate.dnscrypt.public_key and private_key are required — generate them with `zjdns --generate dnscrypt`")
	}
	skBytes, err := dnscryptcrypto.HexDecodeKey(certificateCfg.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("decoding ed25519 private key: %w", err)
	}
	signingSK := ed25519.PrivateKey(skBytes)
	signingPK, ok := signingSK.Public().(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("dnscrypt: signing key is not Ed25519")
	}
	rc := ResolverConfig{
		ProviderName: providerName,
		PublicKey:    dnscryptcrypto.HexEncodeKey(signingPK),
		PrivateKey:   certificateCfg.PrivateKey,
	}

	// ── Restore or create cert windows ─────────────────────────────────────
	// Persisted windows are only reused while the identity matches: a config
	// key change means the old windows are re-signed under a new identity,
	// so a fresh window is minted instead.
	var persistedWindows []windowRecord
	if store != nil {
		identity, windowsBlob, err := store.LoadDNSCryptState()
		if err != nil {
			log.Warnf("DNSCRYPT: state load failed (starting fresh): %v", err)
		} else if len(identity) == 96 {
			if !bytes.Equal(signingPK, identity[64:96]) {
				log.Warnf("DNSCRYPT: config public_key changed, dropping old persisted state")
			} else {
				// _ = error: corrupt persisted windows fall back to a fresh
				// generation below (windowsFromState returns nil) — logged,
				// not fatal (R3-L21).
				persistedWindows, err = decodeWindows(windowsBlob)
				if err != nil {
					log.Warnf("DNSCRYPT: corrupt persisted windows, starting fresh: %v", err)
				} else {
					log.Infof("DNSCRYPT: loaded persisted identity (%d cert window(s))", len(persistedWindows))
				}
			}
		}
	}

	var entries []keyEntry
	if windows := windowsFromState(persistedWindows); len(windows) > 0 {
		restored, err := windowsToKeyEntries(&rc, windows)
		if err != nil {
			log.Warnf("DNSCRYPT: restoring windows failed (starting fresh): %v", err)
		} else {
			entries = restored
			log.Infof("DNSCRYPT: restored %d cert window(s)", len(restored))
		}
	}
	if len(entries) == 0 {
		// Mint a fresh window from a random seed; the seed chain extends it
		// forward on each renewal.  Generate the resolver keys explicitly:
		// NewCertPair derives PQ keys from rc.ResolverSk, so an empty rc
		// would silently produce a PQ cert derived from nothing (classical
		// keys random, PQ keys unrelated).
		sk, pk, err := dnscryptcrypto.GenerateRandomKeyPair()
		if err != nil {
			return nil, fmt.Errorf("generating resolver keys: %w", err)
		}
		rc.ResolverSk = dnscryptcrypto.HexEncodeKey(sk[:])
		rc.ResolverPk = dnscryptcrypto.HexEncodeKey(pk[:])
		now := dnscryptcrypto.NowUnix32()
		pair, err := rc.NewCertPair(now, now+uint32(config.DefaultDNSCryptCertificateTTL/time.Second))
		if err != nil {
			return nil, fmt.Errorf("creating certificate pair: %w", err)
		}
		entries = []keyEntry{{pair: pair}}
		log.Debugf("DNSCRYPT: generated initial key pair (serial=%d)", pair.Classical.Serial)
	}

	if port == "" {
		port = config.DefaultDNSCryptPort
	}
	ctx, cancel := context.WithCancelCause(context.Background())

	s := &Server{
		keys:           entries,
		port:           port,
		providerName:   providerName,
		certificateCfg: certificateCfg,
		tcpConns:       make(map[net.Conn]struct{}),
		wg:             &sync.WaitGroup{},
		ctx:            ctx,
		cancel:         cancel,
		signingSK:      signingSK,
		rotateCh:       make(chan struct{}),
		workerCap:      make(chan struct{}, config.DefaultMaxConcurrentStreams),
		sharedKeyCache: lrumap.New[[32]byte, [32]byte](config.DefaultDNSCryptSharedKeyCacheSize),
		store:          store,
	}

	// Derive ticket key from the Ed25519 signing key for PQ resumption.
	// Same derivation as the reference implementation (encrypted-dns-server).
	{
		input := make([]byte, 0, 25+len(signingSK))
		input = append(input, "DNSCrypt-PQ-ticket-key-v1"...)
		input = append(input, signingSK...)
		h := sha256.Sum256(input)
		copy(s.ticketKey[:], h[:])
		s.ticketKeyID = [dnscryptcrypto.TicketKeyIDSize]byte{0x00, 0x00, 0x00, 0x01}
	}

	// Catch up renewals missed while the server was stopped: purge expired
	// windows and mint every window up to now+renewal from the seed chain,
	// persisting the result (ref: updater.update() at startup).
	s.updateKeys()

	return s, nil
}

// ResetKeys regenerates the DNSCrypt crypto state from fresh random keys:
// a single new cert window replaces all current windows and the state is
// persisted immediately (CHAOS zjdns.dnscrypt.clear).  The provider identity
// (signingSK) comes from config and is unchanged — the sdns:// stamp stays
// valid, but clients must fetch the new certificate to reconnect.
func (s *Server) ResetKeys() error {
	now := dnscryptcrypto.NowUnix32()
	// Passing nil previous breaks the seed chain: the reset window starts
	// a new chain from a fresh random seed.
	entries := s.deriveAndSign(nil, now)
	if len(entries) == 0 {
		return errors.New("dnscrypt: reset: failed to generate fresh key pair")
	}

	s.mu.Lock()
	// Clear old shared key cache before replacing to release cached keys.
	s.sharedKeyCache.Clear()
	s.sharedKeyCache = lrumap.New[[32]byte, [32]byte](config.DefaultDNSCryptSharedKeyCacheSize)
	// The PQ ticket key is fixed (derived from the signing key at startup);
	// it is not rotated alongside cert keys.
	s.keys = entries
	s.mu.Unlock()

	if err := s.Save(); err != nil {
		return fmt.Errorf("dnscrypt: persist reset state: %w", err)
	}
	log.Infof("DNSCRYPT: keys reset (serial=%d)", s.keys[0].pair.Classical.Serial)
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

// Start begins listening for DNSCrypt queries on UDP and TCP.
func (s *Server) Start(dnsHandler edns.DNSHandler) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.started {
		return dnscryptcrypto.ErrServerAlreadyStarted
	}

	s.handler = dnsHandler
	s.started = true

	udpAddrs, err := zdnsutil.ResolveBindAddrs("udp", s.port)
	if err != nil {
		return fmt.Errorf("resolving UDP bind addresses: %w", err)
	}
	log.Infof("DNSCRYPT: Listening on UDP %v", udpAddrs)
	for _, addr := range udpAddrs {
		uaddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			return fmt.Errorf("resolving UDP address %s: %w", addr, err)
		}
		conn, err := net.ListenUDP("udp", uaddr)
		if err != nil {
			return fmt.Errorf("listening UDP on %s: %w", addr, err)
		}
		s.udpConns = append(s.udpConns, conn)
		go s.serveUDP(s.ctx, conn)
	}

	tcpAddrs, err := zdnsutil.ResolveBindAddrs("tcp", s.port)
	if err != nil {
		for _, c := range s.udpConns {
			_ = c.Close()
		}
		return fmt.Errorf("resolving TCP bind addresses: %w", err)
	}
	log.Infof("DNSCRYPT: Listening on TCP %v", tcpAddrs)
	for _, addr := range tcpAddrs {
		tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
		if err != nil {
			for _, c := range s.udpConns {
				_ = c.Close()
			}
			for _, l := range s.tcpListeners {
				_ = l.Close()
			}
			return fmt.Errorf("resolving TCP address %s: %w", addr, err)
		}
		listener, err := net.ListenTCP("tcp", tcpAddr)
		if err != nil {
			for _, c := range s.udpConns {
				_ = c.Close()
			}
			for _, l := range s.tcpListeners {
				_ = l.Close()
			}
			return fmt.Errorf("listening TCP on %s: %w", addr, err)
		}
		s.tcpListeners = append(s.tcpListeners, listener)
		go s.serveTCP(s.ctx, listener)
	}

	log.Infof("DNSCRYPT: Provider: %s", s.providerName)

	// Start background key renewal goroutine.
	go s.renewalLoop()

	return nil
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

// Shutdown gracefully stops the DNSCrypt server.
// The cancel and WaitGroup swap are performed under s.mu without
// releasing the lock, so serveUDP/serveTCP always see a consistent
// (cancelled ctx, correct wg) pair.  Any handler that reads s.wg
// after the swap sees the fresh WaitGroup and exits immediately
// because the context is already cancelled.
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	if !s.started {
		s.mu.Unlock()
		return dnscryptcrypto.ErrServerNotStarted
	}
	s.started = false

	close(s.rotateCh)

	for _, c := range s.udpConns {
		_ = c.Close()
	}
	for _, l := range s.tcpListeners {
		_ = l.Close()
	}
	for conn := range s.tcpConns {
		_ = conn.SetReadDeadline(time.Unix(1, 0))
	}
	// Cancel the context and swap the WaitGroup atomically under s.mu.
	// Handlers that read s.wg after this point see a fresh WaitGroup;
	// because the context is already cancelled, they return immediately
	// rather than joining a WaitGroup that will never be waited on.
	s.cancel(errors.New("dnscrypt server shutdown"))
	prevWg := s.wg
	s.wg = &sync.WaitGroup{}
	s.mu.Unlock()

	done := make(chan struct{})
	go func() {
		defer zdnsutil.HandlePanic("DNSCrypt shutdown wait")
		prevWg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-ctx.Done():
		return ctx.Err()
	}

	return nil
}

func (s *Server) isStarted() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.started
}

// current returns the newest key pair (the one used for encrypting responses).
func (s *Server) current() *dnscryptcrypto.CertPair {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.keys[0].pair
}

// hasClientMagic checks whether b matches any active cert's client magic
// (checks both classical and PQ certs in every key window).
func (s *Server) hasClientMagic(b []byte) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, k := range s.keys {
		if bytes.Equal(b, k.pair.Classical.ClientMagic[:]) {
			return true
		}
		if bytes.Equal(b, k.pair.PQ.ClientMagic[:]) {
			return true
		}
	}
	return false
}

// updateKeys renews the certificate windows, mirroring the reference
// encrypted-dns-server update(): windows past NotAfter are purged, then the
// seed chain is walked forward from the newest surviving window to mint every
// window whose start falls within now+renewal.  Called on the renewal ticker
// and once at startup to catch up on renewals missed while stopped.
func (s *Server) updateKeys() {
	now := dnscryptcrypto.NowUnix32()

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
	s.mu.Unlock()

	newEntries := s.deriveAndSign(previous, now)
	if len(newEntries) == 0 && len(s.keys) == 0 {
		// Nothing usable at all (e.g. chain generation failed): mint an
		// emergency window from a fresh random seed.
		newEntries = s.deriveAndSign(nil, now)
	}
	if len(newEntries) > 0 {
		s.mu.Lock()
		s.keys = append(newEntries, s.keys...)
		// Clear old shared key cache before replacing to release cached keys.
		s.sharedKeyCache.Clear()
		s.sharedKeyCache = lrumap.New[[32]byte, [32]byte](config.DefaultDNSCryptSharedKeyCacheSize)
		// The PQ ticket key is fixed (derived from the signing key at
		// startup); it is not rotated alongside cert keys.
		s.mu.Unlock()
	}

	// Persist the new window set outside the lock to avoid blocking queries.
	if err := s.Save(); err != nil {
		log.Warnf("DNSCRYPT: failed to persist rotated state: %v", err)
	}

	log.Debugf("DNSCRYPT: renewed certificates (active=%d)", len(s.keys))
}

// deriveAndSign walks the seed chain forward from previous and returns every
// window whose start falls within [now, now+renewal], newest first.  Each
// window's X25519 resolver key is derived from the previous window's secret
// key (ratchet: seed_0 → kp_0 → sk_0-as-seed_1 → kp_1 → …), matching the
// reference encrypted-dns-server.  A nil previous mints a single window from
// a fresh random seed — the start of a new chain.
func (s *Server) deriveAndSign(previous *dnscryptcrypto.CertPair, now uint32) []keyEntry {
	rc := ResolverConfig{ProviderName: s.providerName}
	rc.PublicKey = dnscryptcrypto.HexEncodeKey(s.signingSK.Public().(ed25519.PublicKey))
	rc.PrivateKey = dnscryptcrypto.HexEncodeKey(s.signingSK)

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
		sk, pk, err := dnscryptcrypto.X25519KeyPairFromSeed(seed)
		if err != nil {
			log.Warnf("DNSCRYPT: deriving resolver key from seed: %v", err)
			break
		}
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
			entries = append([]keyEntry{{pair: pair}}, entries...)
		}
		tsStart += renewalSec
	}
	return entries
}

func (s *Server) handleHandshake(b []byte, isUDP bool) (res []byte, err error) {
	m := pool.DefaultMessage.Get()
	defer func() {
		if m != nil {
			pool.DefaultMessage.Put(m)
		}
	}()
	m.Data = b
	err = m.Unpack()
	if err != nil {
		return nil, fmt.Errorf("unpacking handshake message: %w", err)
	}

	if len(m.Question) != 1 || m.Response {
		return nil, dnscryptcrypto.ErrInvalidQuery
	}

	q := m.Question[0]
	providerName := dnsutil.Fqdn(s.providerName)

	qName := dnsutil.Fqdn(q.Header().Name)
	if dns.RRToType(q) != dns.TypeTXT || qName != providerName {
		return nil, dnscryptcrypto.ErrInvalidQuery
	}

	// Serve only the newest window's certificates (ref: serve_certificates
	// picks the cert with the highest ts_end).  Older windows remain in
	// s.keys only for decrypting client queries that still use them.
	s.mu.RLock()
	newest := s.keys[0]
	s.mu.RUnlock()

	// Static TTL: the renewal interval (ref: DNSCRYPT_CERTS_RENEWAL).  The
	// cert's NotAfter is up to 24h away, so clients re-fetch well before the
	// certificate expires.
	ttl := uint32(config.DefaultDNSCryptCertificateRenewal / time.Second)

	// The PQ cert (~1.3 KB) is included over UDP only when the response fits
	// within the client query size (§10.3 anti-amplification); over TCP it is
	// always included.  When omitted, set TC so the PQ-capable client retries
	// over TCP.  The classical cert is always included.
	classicalTXT := buildCertTXTForCert(newest.pair.Classical)
	pqTXT := buildCertTXTForCert(newest.pair.PQ)

	pqFits := true
	if isUDP {
		// Pack a temporary classical-only response to measure the wire size.
		// Use m (still alive — not yet returned to the pool) for SetReply.
		tmp := pool.DefaultMessage.Get()
		dnsutil.SetReply(tmp, m)
		tmp.Answer = append(tmp.Answer, &dns.TXT{
			Hdr: dns.Header{
				Name:  q.Header().Name,
				TTL:   ttl,
				Class: dns.ClassINET,
			},
			TXT: rdata.TXT{Txt: classicalTXT},
		})
		tmp.Authoritative = true
		tmp.RecursionAvailable = true
		if packErr := tmp.Pack(); packErr != nil {
			pool.DefaultMessage.Put(tmp)
			return nil, fmt.Errorf("packing handshake response: %w", packErr)
		}
		baseSize := len(tmp.Data)
		pool.DefaultMessage.Put(tmp)
		pqFits = baseSize+certTXTWireSize(newest.pair.PQ) <= len(b)
	}

	// Build the actual reply.
	reply := pool.DefaultMessage.Get()
	dnsutil.SetReply(reply, m)
	pool.DefaultMessage.Put(m)
	m = nil // prevent defer from double-Put

	reply.Answer = append(reply.Answer, &dns.TXT{
		Hdr: dns.Header{
			Name:  q.Header().Name,
			TTL:   ttl,
			Class: dns.ClassINET,
		},
		TXT: rdata.TXT{Txt: classicalTXT},
	})
	if pqFits {
		reply.Answer = append(reply.Answer, &dns.TXT{
			Hdr: dns.Header{
				Name:  q.Header().Name,
				TTL:   ttl,
				Class: dns.ClassINET,
			},
			TXT: rdata.TXT{Txt: pqTXT},
		})
	}

	reply.Authoritative = true
	reply.RecursionAvailable = true

	if !pqFits {
		reply.Truncated = true
	}

	log.Debugf("DNSCRYPT: handshake response — 1 cert window (%d TXT records, TC=%v)%s",
		len(reply.Answer), reply.Truncated, map[bool]string{true: " (UDP)", false: ""}[isUDP])

	err = reply.Pack()
	if err != nil {
		pool.DefaultMessage.Put(reply)
		return nil, fmt.Errorf("packing handshake response: %w", err)
	}
	// NOTE(M14): res must be a copy of reply.Data, not an alias.  After
	// pool.DefaultMessage.Put(reply), reply.Data's backing memory is zeroed
	// and available for reuse by another goroutine.
	res = make([]byte, len(reply.Data))
	copy(res, reply.Data)
	pool.DefaultMessage.Put(reply)
	return res, nil
}

func (s *Server) serveDNS(ctx context.Context, rw responseWriter, m *dns.Msg, protocol string) error {
	if m == nil || len(m.Question) != 1 || m.Response {
		return dnscryptcrypto.ErrInvalidQuery
	}
	log.Debugf("DNSCRYPT: handling query for %s from %s", m.Question[0].Header().Name, rw.RemoteAddr())

	clientIP := zdnsutil.ClientIPFromAddr(rw.RemoteAddr())
	resp := s.handler.ServeDNS(m, clientIP, false, protocol)
	if resp == nil {
		return nil
	}
	defer pool.DefaultMessage.Put(resp)
	return rw.WriteMsg(ctx, resp)
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
