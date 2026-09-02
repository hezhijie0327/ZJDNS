package dnscrypt

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/rand/v2"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"zjdns/config"
	dnscryptcrypto "zjdns/internal/dnscryptcrypto"
	"zjdns/internal/log"
	zstamp "zjdns/internal/stamp"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// certPair holds the best PQ and classical certificates from a server.
type certPair struct {
	pq        *dnscryptcrypto.Certificate
	classical *dnscryptcrypto.Certificate
}

// State caches per-upstream DNSCrypt resolver state.
type State struct {
	mu sync.Mutex

	serverAddress string
	sharedKey     [dnscryptcrypto.SharedKeySize]byte
	secretKey     [dnscryptcrypto.KeySize]byte
	publicKey     [dnscryptcrypto.KeySize]byte
	serverPK      []byte
	clientMagic   [dnscryptcrypto.ClientMagicSize]byte
	esVersion     dnscryptcrypto.CryptoConstruction
	expires       time.Time

	// minQueryLen is the padded UDP query budget.  Grows on TC (blindAdjust),
	// shrinks when responses stay well below it (adjustQuerySize) — the
	// "MAY increase or decrease this value over time" of draft §5.4.2.  Atomic:
	// the estimator runs lock-free on the per-response hot path while the rest
	// of State stays behind mu.
	minQueryLen atomic.Int32
	// ewmaQuerySize holds the EWMA of encrypted response wire sizes as
	// float64 bits (sync/atomic has no float type).
	ewmaQuerySize atomic.Uint64
	ephemeralKeys bool                         // per-query X25519 keys for forward secrecy (default true)
	resolverPK    [dnscryptcrypto.KeySize]byte // resolver X25519 public key

	// PQ fields — only set when the server offers a PQ certificate.
	pqPublicKey       []byte
	pqCertContext     []byte
	pqTicket          []byte
	pqResumeSecret    [dnscryptcrypto.SharedKeySize]byte
	pqTicketExpiry    time.Time
	pqCiphertext      []byte
	pqEncapsulatedKey [dnscryptcrypto.SharedKeySize]byte
}

// ewmaDecay is the SimpleEWMA decay factor of the response-size estimator.
// Mirrors dnscrypt-proxy's VividCortex/ewma DECAY = 2/(age+1) with the
// default 30-sample window (estimators.go).
const ewmaDecay = 2.0 / 31.0

// adjustQuerySize feeds the observed encrypted response wire size into the
// EWMA and shrinks minQueryLen when responses stay well below the padded
// query budget — the "decrease over time" branch of draft §5.4.2
// (dnscrypt-proxy QuestionSizeEstimator.adjust).  Shrink only fires once the
// average is below half the current budget (hysteresis) and never below the
// initial 512-byte floor.  Lock-free: a CAS loop keeps the per-response hot
// path free of mutex contention (responses arrive on the read path, which
// otherwise never touches state.mu).
// adjustQuerySize shrinks the padded query budget toward the EWMA.  The
// non-CAS Store may race a concurrent blindAdjust escalation computed
// against the pre-reset EWMA — self-healing (the next TC re-escalates), one
// lost padding escalation in a rare interleaving (U18).
func (s *State) adjustQuerySize(wireLen int) {
	for {
		old := math.Float64frombits(s.ewmaQuerySize.Load())
		next := old*(1-ewmaDecay) + float64(wireLen)*ewmaDecay
		if !s.ewmaQuerySize.CompareAndSwap(math.Float64bits(old), math.Float64bits(next)) {
			continue
		}
		if budget := s.minQueryLen.Load(); next > float64(config.DefaultDNSCryptMinQueryLen) && next < float64(budget)/2 {
			s.minQueryLen.Store(max(config.DefaultDNSCryptMinQueryLen, budget/2))
		}
		return
	}
}

// blindAdjust doubles minQueryLen on a truncated response and resets the EWMA
// to the new value, so a shrink cannot immediately undo the growth — the
// "increase" branch of draft §5.4.2 (dnscrypt-proxy QuestionSizeEstimator
// blindAdjust).  Returns false when already at the transport cap; the caller
// then falls back to TCP (draft §5.4.2 item 1).
func (s *State) blindAdjust() bool {
	for {
		cur := s.minQueryLen.Load()
		next := min(max(cur*2, cur+64), int32(dnscryptcrypto.MaxDNSUDPPacketSize))
		if next == cur {
			return false
		}
		if s.minQueryLen.CompareAndSwap(cur, next) {
			s.ewmaQuerySize.Store(math.Float64bits(float64(next)))
			return true
		}
	}
}

// resolveStamp extracts the server address, provider name, and public key from
// the upstream server configuration.
func (c *Client) resolveStamp(server *config.UpstreamServer) (addr, providerName string, publicKey []byte, err error) {
	if strings.HasPrefix(server.Address, "sdns://") {
		s, parseErr := zstamp.Parse(server.Address)
		if parseErr != nil {
			return "", "", nil, fmt.Errorf("parsing stamp: %w", parseErr)
		}
		if s.Proto != zstamp.ProtoDNSCrypt {
			return "", "", nil, fmt.Errorf("stamp is not DNSCrypt (proto=%d)", s.Proto)
		}
		return s.Address, s.ProviderName, s.PublicKey, nil
	}

	addr = server.Address
	providerName = server.ServerName
	if server.PublicKey != "" {
		var pkErr error
		publicKey, pkErr = dnscryptcrypto.HexDecodeKey(server.PublicKey)
		if pkErr != nil {
			return "", "", nil, fmt.Errorf("decoding public key: %w", pkErr)
		}
	}

	if addr == "" {
		return "", "", nil, errors.New("address is empty")
	}
	if providerName == "" {
		return "", "", nil, errors.New("provider_name is required for non-stamp DNSCrypt servers")
	}
	if len(publicKey) == 0 {
		return "", "", nil, errors.New("public_key is required for non-stamp DNSCrypt servers")
	}

	return addr, providerName, publicKey, nil
}

// state fetches and caches the DNSCrypt certificate and shared key for the
// given resolver.
func (c *Client) state(
	ctx context.Context,
	addr string,
	providerName string,
	publicKey []byte,
	server *config.UpstreamServer,
	preferTCP bool,
) (*State, error) {
	providerName = dnsutil.Fqdn(providerName)
	cacheKey := addr + "|" + providerName

	c.cacheMu.Lock()
	if c.cache == nil {
		c.cacheMu.Unlock()
		return nil, errors.New("dnscrypt client shutting down")
	}
	state, ok := c.cache.Get(cacheKey)
	c.cacheMu.Unlock()
	if ok && time.Now().Before(state.expires) {
		log.Debugf("UPSTREAM: DNSCrypt cert cache hit for %s", cacheKey)
		return state, nil
	}
	log.Debugf("UPSTREAM: DNSCrypt cert cache miss for %s", cacheKey)

	// Singleflight: under a burst of new queries every miss used to re-fetch
	// the certificate independently (2 RTTs each — UDP then TCP).  One
	// in-flight fetch serves the whole batch; failures are not cached, so the
	// next query retries naturally.
	state, err, _ := c.stateGroup.Do(ctx, cacheKey, func(workCtx context.Context) (*State, error) {
		// Another goroutine may have populated the cache while we queued.
		c.cacheMu.Lock()
		state, ok := c.cache.Get(cacheKey)
		c.cacheMu.Unlock()
		if ok && time.Now().Before(state.expires) {
			return state, nil
		}
		// Hard budget for the fetch itself: a promoted follower's workCtx is
		// context.WithoutCancel(ctx) — no cancellation, no deadline — and
		// fetchCertOverUDP/TCP apply their own socket deadline (cert.go),
		// so both leader and promoted runs are always bounded.  Without this
		// wrapper a blackholed upstream leaks one goroutine per promoted
		// follower (each waits on conn.Read forever).
		fetchCtx, fetchCancel := context.WithTimeout(workCtx, certFetchTimeout)
		defer fetchCancel()
		return c.fetchState(fetchCtx, addr, providerName, publicKey, server, preferTCP)
	})
	if err != nil {
		return nil, err
	}
	return state, nil
}

// fetchState performs the certificate fetch and state construction for one
// resolver.  Called from state() under a singleflight — never concurrently
// for the same cacheKey.
func (c *Client) fetchState(
	ctx context.Context,
	addr, providerName string,
	publicKey []byte,
	server *config.UpstreamServer,
	preferTCP bool,
) (*State, error) {
	certQuery := &dns.Msg{}
	certQuery.RecursionDesired = true
	// Random ID: the pooled TCP cert fetch routes responses by the echoed
	// message ID (2-byte key in the raw pool), so a fixed zero ID would make
	// sequential fetches on the same connection indistinguishable from stale.
	certQuery.ID = uint16(rand.Uint32()) //nolint:gosec // G404: DNS message ID — not cryptographic
	txtRR := new(dns.TXT)
	txtRR.Hdr = dns.Header{Name: providerName, Class: dns.ClassINET}
	certQuery.Question = []dns.RR{txtRR}
	err := certQuery.Pack()
	if err != nil {
		return nil, fmt.Errorf("packing cert query: %w", err)
	}

	resp, err := c.fetchCert(ctx, addr, certQuery.Data, preferTCP, server)
	if err != nil {
		return nil, fmt.Errorf("fetching dnscrypt cert from %s: %w", addr, err)
	}

	if resp.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("fetching dnscrypt cert: server returned %s", dns.RcodeToString[resp.Rcode])
	}

	cert, err := parseCert(resp.Answer, publicKey, providerName)
	if err != nil {
		return nil, fmt.Errorf("parsing dnscrypt cert: %w", err)
	}

	// Prefer PQ by default (matching official dnscrypt-proxy).
	// Set "pqdnscrypt": false to use classical XChacha20Poly1305 only.
	preferPQ := true
	if server.PQDNSCrypt != nil {
		preferPQ = *server.PQDNSCrypt
	}

	state, err := c.buildState(addr, providerName, publicKey, cert, preferPQ)
	if err != nil {
		return nil, err
	}
	// Per-query X25519 ephemeral keys for forward secrecy (default true).
	// Set "ephemeral_keys": false to reuse the same key pair across queries.
	ephemeralKeys := true
	if server.EphemeralKeys != nil {
		ephemeralKeys = *server.EphemeralKeys
	}
	state.ephemeralKeys = ephemeralKeys
	return state, nil
}

// buildState constructs a State from parsed certificates.  When preferPQ is
// true and a PQ cert is available, the state uses PQ; otherwise classical.
// The shared key is always derived from the classical cert's X25519 public key.
func (c *Client) buildState(
	addr, providerName string,
	publicKey []byte,
	cert *certPair,
	preferPQ bool,
) (*State, error) {
	var esVersion dnscryptcrypto.CryptoConstruction
	var selectedCert *dnscryptcrypto.Certificate
	switch {
	case preferPQ && cert.pq != nil:
		esVersion = dnscryptcrypto.XWingPQ
		selectedCert = cert.pq
		log.Debugf("UPSTREAM: DNSCrypt PQ selected for %s (serial=%d)", addr, selectedCert.Serial)
	case cert.classical != nil:
		esVersion = dnscryptcrypto.XChacha20Poly1305
		selectedCert = cert.classical
		log.Debugf("UPSTREAM: DNSCrypt classical selected for %s (serial=%d)", addr, selectedCert.Serial)
	default:
		return nil, fmt.Errorf("no valid dnscrypt certificate for %q", providerName)
	}

	var sharedKey [dnscryptcrypto.SharedKeySize]byte
	var secretKey, clientPK [dnscryptcrypto.KeySize]byte
	var err error
	if cert.classical != nil {
		secretKey, clientPK, err = dnscryptcrypto.GenerateRandomKeyPair()
		if err != nil {
			return nil, fmt.Errorf("generating key pair: %w", err)
		}
		sharedKey, err = dnscryptcrypto.ComputeSharedKey(
			dnscryptcrypto.XChacha20Poly1305, &secretKey, &cert.classical.ResolverPk,
		)
		if err != nil {
			return nil, fmt.Errorf("computing shared key: %w", err)
		}
	}

	state := &State{
		serverAddress: addr,
		sharedKey:     sharedKey,
		secretKey:     secretKey,
		publicKey:     clientPK,
		serverPK:      publicKey,
		clientMagic:   selectedCert.ClientMagic,
		esVersion:     esVersion,
		expires:       time.Now().Add(config.DefaultDNSCryptCertificateCacheTTL),
	}
	state.minQueryLen.Store(int32(config.DefaultDNSCryptMinQueryLen))
	state.ewmaQuerySize.Store(math.Float64bits(float64(config.DefaultDNSCryptMinQueryLen)))

	if cert.classical != nil {
		state.resolverPK = cert.classical.ResolverPk
	}
	if esVersion.IsPQ() && len(cert.pq.PqPublicKey) > 0 {
		state.pqPublicKey = cert.pq.PqPublicKey
		state.pqCertContext = cert.pq.PqCertContext
	}

	cacheKey := addr + "|" + providerName
	c.cacheMu.Lock()
	if c.cache == nil {
		c.cacheMu.Unlock()
		return nil, errors.New("dnscrypt client closed")
	}
	c.cache.Set(cacheKey, state)
	c.cacheMu.Unlock()

	return state, nil
}

// deleteState removes a cached state entry so the next query re-fetches the
// certificate.  Called when a query fails — the server may have rotated its
// certificate, making the cached shared key and client magic invalid.
func (c *Client) deleteState(addr, providerName string) {
	providerName = dnsutil.Fqdn(providerName)
	cacheKey := addr + "|" + providerName
	c.cacheMu.Lock()
	if c.cache != nil {
		c.cache.Delete(cacheKey)
	}
	c.cacheMu.Unlock()
	log.Debugf("UPSTREAM: DNSCrypt cert cache invalidated for %s", cacheKey)
}

// parseCert parses and verifies DNSCrypt certificates from DNS TXT answer
// records, returning the best PQ and classical certs separately.
func parseCert(
	answer []dns.RR,
	serverPK []byte,
	providerName string,
) (*certPair, error) {
	var bestPQ, bestClassical *dnscryptcrypto.Certificate
	var bestPQSerial, bestClSerial uint32
	for _, rr := range answer {
		txt, ok := rr.(*dns.TXT)
		if !ok {
			continue
		}
		certStr := strings.Join(txt.Txt, "")
		cert := &dnscryptcrypto.Certificate{}
		if unmarshalErr := cert.UnmarshalBinary(dnscryptcrypto.UnpackTxtString(certStr)); unmarshalErr != nil {
			continue
		}
		if !cert.IsDateValid() {
			continue
		}
		if !cert.VerifySignature(serverPK) {
			continue
		}
		if cert.ESVersion.IsPQ() {
			if bestPQ == nil || cert.Serial > bestPQSerial {
				bestPQ = cert
				bestPQSerial = cert.Serial
			}
		} else {
			if bestClassical == nil || cert.Serial > bestClSerial {
				bestClassical = cert
				bestClSerial = cert.Serial
			}
		}
	}
	if bestPQ == nil && bestClassical == nil {
		return nil, fmt.Errorf("no valid dnscrypt certificate for %q", providerName)
	}
	return &certPair{pq: bestPQ, classical: bestClassical}, nil
}
