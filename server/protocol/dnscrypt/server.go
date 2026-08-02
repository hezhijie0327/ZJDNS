package dnscrypt

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
	"zjdns/cache"
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
type keyEntry struct {
	pair      *dnscryptcrypto.CertPair
	createdAt time.Time
	cachedTXT [2][]string // pre-built TXT chunks: [0]=classical, [1]=PQ
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
	tcpConns       map[net.Conn]struct{}
	mu             sync.RWMutex
	started        bool
	ctx            context.Context
	wg             *sync.WaitGroup
	cancel         context.CancelCauseFunc

	// signingSK is the Ed25519 provider identity key.  It stays fixed across
	// resolver-key rotations — the sdns:// stamp encodes only this key.
	signingSK ed25519.PrivateKey

	// ticketKey / ticketKeyID seal PQ resumption tickets.  They are
	// derived from the Ed25519 signing key and stay fixed across rotations
	// so that tickets survive a key rotation.
	ticketKey       [dnscryptcrypto.XchachaKeySize]byte
	ticketKeyID     [dnscryptcrypto.TicketKeyIDSize]byte
	prevTicketKey   [dnscryptcrypto.XchachaKeySize]byte // previous TK for overlap validation
	prevTicketKeyID [dnscryptcrypto.TicketKeyIDSize]byte

	// Rotation goroutine control.
	rotateCh chan struct{} // closed when rotation goroutine should stop

	// workerCap limits concurrent handler goroutines to prevent unbounded
	// goroutine creation under high load.
	workerCap chan struct{}

	// stateSaver persists identity + cert windows across restarts (the cache
	// implements it). Nil when persistence is not available.
	stateSaver StateSaver
	// seed is the X25519 secret key used to derive the next cert window's
	// resolver key.  It forms a deterministic chain: each new window's
	// resolver secret key becomes the seed for the one after it.
	seed [32]byte

	// sharedKeyCache avoids recomputing X25519 per query for classical
	// DNSCrypt (RFC §8).  Cleared on key rotation.
	sharedKeyCache *lrumap.Map[[32]byte, [32]byte]
}

// remainingTTL returns the remaining TTL in seconds for this key entry.
func (k *keyEntry) remainingTTL() uint32 {
	d := time.Until(k.createdAt.Add(config.DefaultDNSCryptCertificateTTL + config.DefaultDNSCryptKeyOverlap))
	if d <= 0 {
		return 0
	}
	return uint32(d.Seconds())
}

// New creates a new DNSCrypt Server from the given configuration.
// port is the listener port, providerName is auto-derived as "2.dnscrypt-cert.<ddr.domain>".
// state is the persisted identity + windows loaded by the cache (nil on first
// run); stateSaver persists them back (the cache). Nil stateSaver disables
// persistence.
func New(state *cache.DNSCrypt, stateSaver StateSaver, certificateCfg *config.DNSCryptCertificate, port, providerName string) (*Server, error) {
	// ── Resolve signing identity ──────────────────────────────────────────
	// Require explicit keys in config — like TLS requires a certificate.
	if certificateCfg.PublicKey == "" || certificateCfg.PrivateKey == "" {
		return nil, errors.New("dnscrypt: public_key and private_key are required in config certificate.dnscrypt")
	}

	// Try loading the persisted identity; auto-switch if config keys changed.
	signingSK, err := decodeIdentity(state)
	if err == nil {
		cfgPKBytes, derr := dnscryptcrypto.HexDecodeKey(certificateCfg.PublicKey)
		if derr != nil || !bytes.Equal(cfgPKBytes, []byte(signingSK.Public().(ed25519.PublicKey))) {
			log.Warnf("DNSCRYPT: config public_key changed, dropping old persisted state and switching identity")
			state = nil
			signingSK = nil
		}
	}
	if signingSK == nil {
		rc, rcErr := buildResolverConfig(certificateCfg, providerName)
		if rcErr != nil {
			return nil, fmt.Errorf("building resolver config: %w", rcErr)
		}
		signingSK, err = dnscryptcrypto.HexDecodeKey(rc.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("decoding ed25519 private key: %w", err)
		}
		log.Infof("DNSCRYPT: identity generated from config")
	} else {
		log.Infof("DNSCRYPT: loaded persisted identity")
	}

	signingPK, ok := signingSK.Public().(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("dnscrypt: signing key is not Ed25519")
	}
	rc := ResolverConfig{
		ProviderName: providerName,
		PublicKey:    dnscryptcrypto.HexEncodeKey(signingPK),
		PrivateKey:   dnscryptcrypto.HexEncodeKey(signingSK),
	}

	// ── Restore or create cert windows ────────────────────────────────────
	var entries []keyEntry
	var seed [32]byte

	if windows := windowsFromState(state); len(windows) > 0 {
		var wErr error
		entries, wErr = windowsToKeyEntries(&rc, windows)
		if wErr == nil && len(entries) > 0 {
			copy(seed[:], windows[len(windows)-1].ResolverSk)
			log.Infof("DNSCRYPT: restored %d cert window(s)", len(entries))
		}
	}

	if len(entries) == 0 {
		if seed == [32]byte{} {
			var err error
			seed, err = newRandomSeed()
			if err != nil {
				return nil, fmt.Errorf("generating initial seed: %w", err)
			}
		}

		now := dnscryptcrypto.NowUnix32()
		pair, err := rc.generateNextPair(&seed, now)
		if err != nil {
			return nil, fmt.Errorf("creating initial certificate pair: %w", err)
		}

		entry := keyEntry{
			pair:      pair,
			createdAt: time.Now(),
			cachedTXT: [2][]string{
				buildCertTXTForCert(pair.Classical),
				buildCertTXTForCert(pair.PQ),
			},
		}
		entries = append(entries, entry)

		log.Debugf("DNSCRYPT: generated initial key pair (serial=%d)", pair.Classical.Serial)
	}

	if port == "" {
		port = config.DefaultDNSCryptPort
	}
	ctx, cancel := context.WithCancelCause(context.Background())

	s := &Server{
		stateSaver:     stateSaver,
		seed:           seed,
		keys:           entries,
		port:           port,
		providerName:   providerName,
		certificateCfg: certificateCfg,
		tcpConns:       make(map[net.Conn]struct{}),
		ctx:            ctx,
		wg:             &sync.WaitGroup{},
		cancel:         cancel,
		signingSK:      signingSK,
		rotateCh:       make(chan struct{}),
		workerCap:      make(chan struct{}, config.DefaultMaxConcurrentStreams),
		sharedKeyCache: lrumap.New[[32]byte, [32]byte](config.DefaultDNSCryptSharedKeyCacheSize),
	}

	// Persist the (possibly fresh) identity + windows so a restart resumes
	// from this state.
	s.persistState()

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

	return s, nil
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

	// Start background key rotation goroutine.
	go s.rotationLoop()

	return nil
}

// rotationLoop periodically rotates the resolver short-term keys.
func (s *Server) rotationLoop() {
	defer zdnsutil.HandlePanic("DNSCRYPT key rotation")
	ticker := time.NewTicker(config.DefaultDNSCryptCertificateTTL)
	defer ticker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.rotateKeys()
		case <-s.rotateCh:
			return
		}
	}
}

// Shutdown gracefully stops the DNSCrypt server.  Connections are closed
// and the context is cancelled to signal accept loops to exit.  s.wg is
// read under s.mu via the getWG helper to avoid data races with serveTCP/
// serveUDP which also access it.
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
	s.cancel(errors.New("dnscrypt server shutdown"))
	wg := s.wg
	s.mu.Unlock()

	done := make(chan struct{})
	go func() {
		defer zdnsutil.HandlePanic("DNSCrypt shutdown wait")
		wg.Wait()
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

// rotateKeys generates a fresh resolver key pair, creates a new certificate
// pair signed with the same Ed25519 identity key, and prepends it to the key
// list.  Entries older than key lifetime + overlap are purged.
//
// This is called periodically by the rotation goroutine to comply with the
// ≤24h short-term key rotation requirement (§7.2 / §8).
func (s *Server) rotateKeys() {
	s.mu.Lock()
	seed := s.seed
	rc := ResolverConfig{
		ProviderName: s.providerName,
	}
	signingPK, ok := s.signingSK.Public().(ed25519.PublicKey)
	if !ok {
		s.mu.Unlock()
		log.Warnf("DNSCRYPT: key rotation failed — signing key is not Ed25519")
		return
	}
	rc.PublicKey = dnscryptcrypto.HexEncodeKey(signingPK)
	rc.PrivateKey = dnscryptcrypto.HexEncodeKey(s.signingSK)

	now := dnscryptcrypto.NowUnix32()
	newPair, err := rc.generateNextPair(&seed, now)
	if err != nil {
		s.mu.Unlock()
		log.Warnf("DNSCRYPT: key rotation failed: %v", err)
		return
	}

	entry := keyEntry{
		pair:      newPair,
		createdAt: time.Now(),
		cachedTXT: [2][]string{
			buildCertTXTForCert(newPair.Classical),
			buildCertTXTForCert(newPair.PQ),
		},
	}
	// Clear old shared key cache before replacing to release cached keys.
	s.sharedKeyCache.Clear()
	s.sharedKeyCache = lrumap.New[[32]byte, [32]byte](config.DefaultDNSCryptSharedKeyCacheSize)
	// RFC §11.7: rotate ticket keys alongside cert keys.
	s.prevTicketKey = s.ticketKey
	s.prevTicketKeyID = s.ticketKeyID
	if _, randErr := rand.Read(s.ticketKey[:]); randErr == nil {
		s.ticketKeyID[3]++
	}
	s.keys = append([]keyEntry{entry}, s.keys...)

	// Purge expired keys (defence in depth — the persist dump also skips
	// windows past NotAfter + overlap).
	cutoff := time.Now().Add(-(config.DefaultDNSCryptCertificateTTL + config.DefaultDNSCryptKeyOverlap))
	n := 0
	for _, k := range s.keys {
		if k.createdAt.After(cutoff) {
			s.keys[n] = k
			n++
		}
	}
	s.keys = s.keys[:n]

	s.seed = seed // advance the seed chain
	s.mu.Unlock()

	// Persist the new window set outside the lock to avoid blocking queries.
	s.persistState()

	log.Debugf("DNSCRYPT: rotated resolver keys (serial=%d, active=%d)", newPair.Classical.Serial, len(s.keys))
}

// persistState hands the current identity + windows to the state saver
// (the cache), which writes the persist file. Called on startup and rotation.
func (s *Server) persistState() {
	if s.stateSaver == nil {
		return
	}
	identity := encodeIdentity(s.signingSK)
	if identity == nil {
		log.Warnf("DNSCRYPT: cannot persist identity — signing key is not Ed25519")
		return
	}
	s.mu.RLock()
	windows := windowsFromKeys(s.keys)
	s.mu.RUnlock()
	s.stateSaver.SetDNSCrypt(identity, windows)
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

	// Snapshot the key window under the read lock — the per-entry created-at
	// timestamp is immutable after rotation, so remainingTTL stays correct.
	s.mu.RLock()
	keys := s.keys
	s.mu.RUnlock()

	// Pre-compute which PQ certs fit over UDP.  Classical certs are always
	// included; PQ certs (~1.3 KB each) are only included when the client
	// padded the query large enough (§10.3 anti-amplification).
	pqFits := make([]bool, len(keys))
	if isUDP {
		// Pack a temporary classical-only response to measure the wire size.
		// Use m (still alive — not yet returned to the pool) for SetReply.
		tmp := pool.DefaultMessage.Get()
		dnsutil.SetReply(tmp, m)
		for _, k := range keys {
			txt := &dns.TXT{
				Hdr: dns.Header{
					Name:  q.Header().Name,
					TTL:   k.remainingTTL(),
					Class: dns.ClassINET,
				},
				TXT: rdata.TXT{
					Txt: buildCertTXTForCert(k.pair.Classical),
				},
			}
			tmp.Answer = append(tmp.Answer, txt)
		}
		tmp.Authoritative = true
		tmp.RecursionAvailable = true
		if packErr := tmp.Pack(); packErr != nil {
			pool.DefaultMessage.Put(tmp)
			return nil, fmt.Errorf("packing handshake response: %w", packErr)
		}
		baseSize := len(tmp.Data)
		pool.DefaultMessage.Put(tmp)
		// RFC §11.3: check total size with all PQ certs, not per-window.
		// If the sum exceeds the query size, omit all PQ certs and set TC
		// so the client retries over TCP (rather than truncating to empty).
		totalPQLen := 0
		for _, k := range keys {
			totalPQLen += certTXTWireSize(k.pair.PQ)
		}
		for i := range keys {
			pqFits[i] = baseSize+totalPQLen <= len(b)
		}
	} else {
		for i := range keys {
			pqFits[i] = true
		}
	}

	// Build the actual reply.
	reply := pool.DefaultMessage.Get()
	dnsutil.SetReply(reply, m)
	pool.DefaultMessage.Put(m)
	m = nil // prevent defer from double-Put

	// Build answer in per-window order: Classical[i] then PQ[i] (if it fits).
	// When a PQ cert is omitted due to the UDP anti-amplification budget,
	// set TC so the PQ-capable client retries over TCP (sec10.3).  Classical
	// certs are always included even in a truncated response.
	anyPQOmitted := false
	for i, k := range keys {
		remainingTTL := k.remainingTTL()
		txt := &dns.TXT{
			Hdr: dns.Header{
				Name:  q.Header().Name,
				TTL:   remainingTTL,
				Class: dns.ClassINET,
			},
			TXT: rdata.TXT{
				Txt: buildCertTXTForCert(k.pair.Classical),
			},
		}
		reply.Answer = append(reply.Answer, txt)
		if pqFits[i] {
			txt := &dns.TXT{
				Hdr: dns.Header{
					Name:  q.Header().Name,
					TTL:   remainingTTL,
					Class: dns.ClassINET,
				},
				TXT: rdata.TXT{
					Txt: buildCertTXTForCert(k.pair.PQ),
				},
			}
			reply.Answer = append(reply.Answer, txt)
		} else {
			anyPQOmitted = true
		}
	}

	reply.Authoritative = true
	reply.RecursionAvailable = true

	if anyPQOmitted {
		reply.Truncated = true
	}

	log.Debugf("DNSCRYPT: handshake response — %d cert window(s) (%d TXT records, TC=%v)%s",
		len(keys), len(reply.Answer), reply.Truncated, map[bool]string{true: " (UDP)", false: ""}[isUDP])

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

func buildResolverConfig(certificateCfg *config.DNSCryptCertificate, providerName string) (ResolverConfig, error) {
	rc := ResolverConfig{
		ProviderName: providerName,
		PublicKey:    certificateCfg.PublicKey,
		PrivateKey:   certificateCfg.PrivateKey,
	}

	sk, pk, err := dnscryptcrypto.GenerateRandomKeyPair()
	if err != nil {
		return rc, fmt.Errorf("generating resolver keys: %w", err)
	}
	rc.ResolverSk = dnscryptcrypto.HexEncodeKey(sk[:])
	rc.ResolverPk = dnscryptcrypto.HexEncodeKey(pk[:])

	return rc, nil
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
