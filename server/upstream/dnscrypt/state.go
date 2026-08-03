package dnscrypt

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
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

	minQueryLen   int
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

// minTime returns the earlier of two times.
func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
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

	// Per-server knobs are part of the cached state: derive them before any
	// cache access so two upstreams sharing addr|providerName but differing
	// in ephemeral_keys/pqdnscrypt never inherit each other's state, and so
	// they are set before the State is published to the cache.
	preferPQ := true
	explicitPQ := false
	if server.PQDNSCrypt != nil {
		preferPQ = *server.PQDNSCrypt
		explicitPQ = *server.PQDNSCrypt // RFC §11.9: MUST NOT fall back when explicitly provisioned
	}
	ephemeralKeys := true
	if server.EphemeralKeys != nil {
		ephemeralKeys = *server.EphemeralKeys
	}
	cacheKey := stateCacheKey(addr, providerName, ephemeralKeys, preferPQ)

	c.cacheMu.Lock()
	if c.cache == nil {
		c.cacheMu.Unlock()
		return nil, errors.New("dnscrypt client closed")
	}
	state, ok := c.cache.Get(cacheKey)
	c.cacheMu.Unlock()
	if ok && time.Now().Before(state.expires) {
		log.Debugf("UPSTREAM: DNSCrypt cert cache hit for %s", cacheKey)
		return state, nil
	}
	log.Debugf("UPSTREAM: DNSCrypt cert cache miss for %s", cacheKey)

	certQuery := &dns.Msg{}
	certQuery.RecursionDesired = true
	txtRR := new(dns.TXT)
	txtRR.Hdr = dns.Header{Name: providerName, Class: dns.ClassINET}
	certQuery.Question = []dns.RR{txtRR}
	certQuery.Security = true
	certQuery.UDPSize = dnscryptcrypto.MaxDNSUDPPacketSize // RFC §11.3: query padding for PQ cert fit
	err := certQuery.Pack()
	if err != nil {
		return nil, fmt.Errorf("packing cert query: %w", err)
	}

	resp, err := FetchCert(ctx, addr, certQuery.Data, preferTCP)
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

	state, err = c.buildState(addr, providerName, publicKey, cert, preferPQ, explicitPQ, ephemeralKeys)
	if err != nil {
		return nil, err
	}
	return state, nil
}

// buildState constructs a State from parsed certificates.  When preferPQ is
// true and a PQ cert is available, the state uses PQ; otherwise classical.
// The shared key is always derived from the classical cert's X25519 public key.
func (c *Client) buildState(
	addr, providerName string,
	publicKey []byte,
	cert *certPair,
	preferPQ, explicitPQ, ephemeralKeys bool,
) (*State, error) {
	if explicitPQ && cert.pq == nil {
		return nil, fmt.Errorf("DNSCrypt: pqdnscrypt provisioned but resolver %q returned no PQ certificate (RFC §11.9 MUST NOT fall back)", providerName)
	}
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

	// Derive the client X25519 pair UNCONDITIONALLY: a PQ-only server's
	// state must still carry real key material (the PQ paths derive their
	// per-query key from the KEM, but any fallback to the classical
	// construction would silently encrypt with all-zero keys).
	var sharedKey [dnscryptcrypto.SharedKeySize]byte
	var secretKey, clientPK [dnscryptcrypto.KeySize]byte
	var err error
	secretKey, clientPK, err = dnscryptcrypto.GenerateRandomKeyPair()
	if err != nil {
		return nil, fmt.Errorf("generating key pair: %w", err)
	}
	if cert.classical != nil {
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
		expires:       minTime(time.Now().Add(config.DefaultDNSCryptCertificateCacheTTL), time.Unix(int64(selectedCert.NotAfter), 0)),
		minQueryLen:   config.DefaultDNSCryptMinQueryLen,
		ephemeralKeys: ephemeralKeys,
	}

	if cert.classical != nil {
		state.resolverPK = cert.classical.ResolverPk
	}
	if esVersion.IsPQ() && len(cert.pq.PqPublicKey) > 0 {
		state.pqPublicKey = cert.pq.PqPublicKey
		state.pqCertContext = cert.pq.PqCertContext
	}

	cacheKey := stateCacheKey(addr, providerName, ephemeralKeys, preferPQ)
	c.cacheMu.Lock()
	if c.cache == nil {
		c.cacheMu.Unlock()
		return nil, errors.New("dnscrypt client closed")
	}
	c.cache.Set(cacheKey, state)
	c.cacheMu.Unlock()

	return state, nil
}

// stateCacheKey builds the cache key for a resolver state. The per-server
// knobs are part of the key so upstreams sharing addr|providerName but
// differing in ephemeral_keys/pqdnscrypt never share (and mutate) each
// other's cached state.
func stateCacheKey(addr, providerName string, ephemeralKeys, preferPQ bool) string {
	return addr + "|" + providerName + fmt.Sprintf("|ephemeral=%t|pq=%t", ephemeralKeys, preferPQ)
}

// deleteState removes cached state entries so the next query re-fetches the
// certificate.  Called when a query fails — the server may have rotated its
// certificate, making the cached shared key and client magic invalid.  All
// knob variants are removed because the caller has no server config here.
func (c *Client) deleteState(addr, providerName string) {
	providerName = dnsutil.Fqdn(providerName)
	c.cacheMu.Lock()
	if c.cache != nil {
		for _, ephemeral := range []bool{true, false} {
			for _, pq := range []bool{true, false} {
				c.cache.Delete(stateCacheKey(addr, providerName, ephemeral, pq))
			}
		}
	}
	c.cacheMu.Unlock()
	log.Debugf("UPSTREAM: DNSCrypt cert cache invalidated for %s", addr+"|"+providerName)
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
