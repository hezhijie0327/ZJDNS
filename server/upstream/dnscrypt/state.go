package dnscrypt

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"zjdns/config"
	zstamp "zjdns/internal/stamp"
	serverdnscrypt "zjdns/server/protocol/dnscrypt"

	"codeberg.org/miekg/dns"
)

// State caches per-upstream DNSCrypt resolver state.
type State struct {
	serverAddress string
	sharedKey     [serverdnscrypt.SharedKeySize]byte
	secretKey     [serverdnscrypt.KeySize]byte
	publicKey     [serverdnscrypt.KeySize]byte
	serverPK      []byte
	clientMagic   [serverdnscrypt.ClientMagicSize]byte
	esVersion     serverdnscrypt.CryptoConstruction
	expires       time.Time

	minQueryLen int

	// PQ fields — only set when the server offers a PQ certificate.
	pqPublicKey       []byte
	pqCertContext     []byte
	pqTicket          []byte
	pqResumeSecret    [serverdnscrypt.SharedKeySize]byte
	pqTicketExpiry    time.Time
	pqCiphertext      []byte
	pqEncapsulatedKey [serverdnscrypt.SharedKeySize]byte
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
		publicKey, pkErr = serverdnscrypt.HexDecodeKey(server.PublicKey)
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

// getState fetches and caches the DNSCrypt certificate and shared key for the
// given resolver.
func (c *Client) getState(
	ctx context.Context,
	addr string,
	providerName string,
	publicKey []byte,
	server *config.UpstreamServer,
) (*State, error) {
	cacheKey := addr + "|" + providerName

	c.cacheMu.RLock()
	if state, ok := c.cache[cacheKey]; ok && time.Now().Before(state.expires) {
		c.cacheMu.RUnlock()
		return state, nil
	}
	c.cacheMu.RUnlock()

	if !strings.HasSuffix(providerName, ".") {
		providerName += "."
	}

	certQuery := &dns.Msg{}
	certQuery.RecursionDesired = true
	txtRR := new(dns.TXT)
	txtRR.Hdr = dns.Header{Name: providerName, Class: dns.ClassINET, TTL: 0}
	certQuery.Question = []dns.RR{txtRR}
	err := certQuery.Pack()
	if err != nil {
		return nil, fmt.Errorf("packing cert query: %w", err)
	}

	resp, err := FetchCert(ctx, addr, certQuery.Data)
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

	esVersion := cert.ESVersion
	var sharedKey [serverdnscrypt.SharedKeySize]byte
	var secretKey, clientPK [serverdnscrypt.KeySize]byte
	if !esVersion.IsPQ() {
		secretKey, clientPK = serverdnscrypt.GenerateKeyPairRaw()
		sharedKey, err = serverdnscrypt.ComputeSharedKey(esVersion, &secretKey, &cert.ResolverPk)
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
		clientMagic:   cert.ClientMagic,
		esVersion:     esVersion,
		expires:       time.Now().Add(config.DefaultDNSCryptCertificateCacheTTL),
		minQueryLen:   256,
	}

	if esVersion.IsPQ() && len(cert.PqPublicKey) > 0 {
		state.pqPublicKey = cert.PqPublicKey
		state.pqCertContext = cert.PqCertContext
	}

	c.cacheMu.Lock()
	c.cache[cacheKey] = state
	if len(c.cache) > config.DefaultTransportMax {
		for k := range c.cache {
			delete(c.cache, k)
			break
		}
	}
	c.cacheMu.Unlock()

	return state, nil
}

// parseCert parses and verifies a DNSCrypt certificate from DNS TXT answer
// records.
func parseCert(
	answer []dns.RR,
	serverPK []byte,
	providerName string,
) (*serverdnscrypt.Certificate, error) {
	var bestCert *serverdnscrypt.Certificate
	var bestSerial uint32
	for _, rr := range answer {
		txt, ok := rr.(*dns.TXT)
		if !ok {
			continue
		}
		certStr := strings.Join(txt.Txt, "")
		cert := &serverdnscrypt.Certificate{}
		if err := cert.UnmarshalBinary(serverdnscrypt.UnpackTxtString(certStr)); err != nil {
			continue
		}
		if !cert.IsDateValid() {
			continue
		}
		if !cert.VerifySignature(serverPK) {
			continue
		}
		if cert.Serial > bestSerial ||
			(cert.Serial == bestSerial && cert.ESVersion.IsPQ() && (bestCert == nil || !bestCert.ESVersion.IsPQ())) {
			bestCert = cert
			bestSerial = cert.Serial
		}
	}
	if bestCert == nil {
		return nil, fmt.Errorf("no valid dnscrypt certificate for provider %q", providerName)
	}
	return bestCert, nil
}
