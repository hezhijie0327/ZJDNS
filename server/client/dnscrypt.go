package client

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
	"zjdns/config"

	serverdnscrypt "zjdns/server/dnscrypt"

	"codeberg.org/miekg/dns"
)

// dnscryptState caches per-upstream DNSCrypt resolver state.
type dnscryptState struct {
	serverAddress string
	sharedKey     [serverdnscrypt.SharedKeySize]byte
	secretKey     [serverdnscrypt.KeySize]byte
	publicKey     [serverdnscrypt.KeySize]byte
	serverPK      []byte // Ed25519 public key for certificate verification
	clientMagic   [serverdnscrypt.ClientMagicSize]byte
	esVersion     serverdnscrypt.CryptoConstruction
	expires       time.Time
}

// executeDNSCrypt sends an encrypted DNS query to a DNSCrypt resolver.
func (c *Client) executeDNSCrypt(ctx context.Context, msg *dns.Msg, server *config.UpstreamServer) (*dns.Msg, error) {
	// Resolve stamp: parse sdns:// from Address, or build from ProviderName+PublicKey.
	stampAddr, providerName, publicKey, err := c.resolveDNSCryptStamp(server)
	if err != nil {
		return nil, fmt.Errorf("resolving dnscrypt stamp: %w", err)
	}

	state, err := c.getDNSCryptState(ctx, stampAddr, providerName, publicKey, server)
	if err != nil {
		return nil, fmt.Errorf("dnscrypt resolver state: %w", err)
	}

	// Pack the DNS query.
	err = msg.Pack()
	if err != nil {
		return nil, fmt.Errorf("packing dns query: %w", err)
	}
	queryBytes := make([]byte, len(msg.Data))
	copy(queryBytes, msg.Data)

	// Encrypt the query.
	q := &serverdnscrypt.EncryptedQuery{
		ClientMagic: state.clientMagic,
		ClientPk:    state.publicKey,
		ESVersion:   state.esVersion,
	}
	encrypted, clientNonce, err := serverdnscrypt.EncryptQuery(q, queryBytes, state.sharedKey)
	if err != nil {
		return nil, fmt.Errorf("encrypting dnscrypt query: %w", err)
	}

	// Dial UDP to the server.
	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(ctx, "udp", state.serverAddress)
	if err != nil {
		return nil, fmt.Errorf("dialing dnscrypt server %s: %w", state.serverAddress, err)
	}
	defer func() { _ = conn.Close() }()

	deadline, ok := ctx.Deadline()
	if ok {
		_ = conn.SetDeadline(deadline)
	}

	// Write encrypted query.
	_, err = conn.Write(encrypted)
	if err != nil {
		return nil, fmt.Errorf("writing dnscrypt query: %w", err)
	}

	// Read encrypted response.
	respBuf := make([]byte, config.DefaultDNSCryptUDPSize)
	n, err := conn.Read(respBuf)
	if err != nil {
		return nil, fmt.Errorf("reading dnscrypt response: %w", err)
	}

	// Decrypt response.
	resp := &serverdnscrypt.EncryptedResponse{
		ESVersion: state.esVersion,
	}
	decrypted, err := serverdnscrypt.DecryptResponse(resp, respBuf[:n], state.sharedKey, clientNonce)
	if err != nil {
		return nil, fmt.Errorf("decrypting dnscrypt response: %w", err)
	}

	// Unpack DNS response.
	response := &dns.Msg{}
	response.Data = decrypted
	err = response.Unpack()
	if err != nil {
		return nil, fmt.Errorf("unpacking dnscrypt response: %w", err)
	}

	return response, nil
}

// resolveDNSCryptStamp extracts the server address, provider name, and public
// key from the upstream server configuration.
func (c *Client) resolveDNSCryptStamp(server *config.UpstreamServer) (addr, providerName string, publicKey []byte, err error) {
	// If address is an sdns:// stamp, parse it.
	if strings.HasPrefix(server.Address, "sdns://") {
		addr, providerName, publicKey, err = serverdnscrypt.ParseStamp(server.Address)
		if err != nil {
			return "", "", nil, fmt.Errorf("parsing stamp: %w", err)
		}
		return addr, providerName, publicKey, nil
	}

	// Otherwise, use explicit fields.  ServerName doubles as the DNSCrypt
	// provider name; PublicKey is the resolver's Ed25519 public key.
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
		return "", "", nil, fmt.Errorf("address is empty") //nolint
	}
	if providerName == "" {
		return "", "", nil, fmt.Errorf("provider_name is required for non-stamp DNSCrypt servers") //nolint
	}
	if len(publicKey) == 0 {
		return "", "", nil, fmt.Errorf("public_key is required for non-stamp DNSCrypt servers") //nolint
	}

	return addr, providerName, publicKey, nil
}

// getDNSCryptState fetches and caches the DNSCrypt certificate and shared key
// for the given resolver.  On first use, it performs a plain DNS TXT query to
// retrieve the server certificate and verifies its signature.
func (c *Client) getDNSCryptState(
	ctx context.Context,
	addr string,
	providerName string,
	publicKey []byte,
	server *config.UpstreamServer,
) (*dnscryptState, error) {
	cacheKey := addr + "|" + providerName

	c.dnscryptCacheMu.RLock()
	if state, ok := c.dnscryptCache[cacheKey]; ok && time.Now().Before(state.expires) {
		c.dnscryptCacheMu.RUnlock()
		return state, nil
	}
	c.dnscryptCacheMu.RUnlock()

	// Generate client X25519 keypair.
	secretKey, clientPK := serverdnscrypt.GenerateKeyPairRaw()

	// Ensure provider name is fully qualified.
	if !strings.HasSuffix(providerName, ".") {
		providerName += "."
	}

	// Fetch the certificate via a plain DNS TXT query over UDP.  The
	// DNSCrypt server responds to unencrypted UDP queries on the DNSCrypt
	// port (e.g. 8443) with the certificate.  TCP cert queries are not
	// universally supported (e.g. Quad9 requires UDP).
	certQuery := &dns.Msg{}
	certQuery.RecursionDesired = true
	txtRR := new(dns.TXT)
	txtRR.Hdr = dns.Header{Name: providerName, Class: dns.ClassINET, TTL: 0}
	certQuery.Question = []dns.RR{txtRR}
	err := certQuery.Pack()
	if err != nil {
		return nil, fmt.Errorf("packing cert query: %w", err)
	}

	// Dial UDP — DNS over UDP has no length prefixing.
	rawConn, dialErr := net.Dial("udp", addr)
	if dialErr != nil {
		return nil, fmt.Errorf("fetching dnscrypt cert from %s: dial: %w", addr, dialErr)
	}
	defer func() { _ = rawConn.Close() }()

	deadline, ok := ctx.Deadline()
	if ok {
		_ = rawConn.SetDeadline(deadline)
	}

	_, err = rawConn.Write(certQuery.Data)
	if err != nil {
		return nil, fmt.Errorf("fetching dnscrypt cert from %s: write: %w", addr, err)
	}

	respBuf := make([]byte, config.DefaultDNSCryptResponseBuffer)
	n, err := rawConn.Read(respBuf)
	if err != nil {
		return nil, fmt.Errorf("fetching dnscrypt cert from %s: read: %w", addr, err)
	}

	resp := &dns.Msg{}
	resp.Data = respBuf[:n]
	err = resp.Unpack()
	if err != nil {
		return nil, fmt.Errorf("fetching dnscrypt cert from %s: unpack: %w", addr, err)
	}

	if resp.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("fetching dnscrypt cert: server returned %s", dns.RcodeToString[resp.Rcode])
	}

	// Parse and verify the certificate.
	cert, err := parseDNSCryptCert(resp.Answer, publicKey, providerName)
	if err != nil {
		return nil, fmt.Errorf("parsing dnscrypt cert: %w", err)
	}

	// Compute shared key.
	esVersion := cert.ESVersion
	sharedKey, err := serverdnscrypt.ComputeSharedKey(esVersion, &secretKey, &cert.ResolverPk)
	if err != nil {
		return nil, fmt.Errorf("computing shared key: %w", err)
	}

	state := &dnscryptState{
		serverAddress: addr,
		sharedKey:     sharedKey,
		secretKey:     secretKey,
		publicKey:     clientPK,
		serverPK:      publicKey,
		clientMagic:   cert.ClientMagic,
		esVersion:     esVersion,
		expires:       time.Now().Add(config.DefaultDNSCryptCertCacheTTL),
	}

	c.dnscryptCacheMu.Lock()
	c.dnscryptCache[cacheKey] = state
	if len(c.dnscryptCache) > config.DefaultTransportMax {
		for k := range c.dnscryptCache {
			delete(c.dnscryptCache, k)
			break
		}
	}
	c.dnscryptCacheMu.Unlock()

	return state, nil
}

// parseDNSCryptCert parses the certificate from DNS TXT answer records and
// verifies its signature.
func parseDNSCryptCert(
	answer []dns.RR,
	serverPK []byte,
	providerName string,
) (*serverdnscrypt.Certificate, error) {
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
		return cert, nil
	}
	return nil, fmt.Errorf("no valid dnscrypt certificate for provider %q", providerName)
}

// warmUpDNSCrypt pre-fetches the DNSCrypt certificate for the given server.
func (c *Client) warmUpDNSCrypt(ctx context.Context, server *config.UpstreamServer) {
	addr, providerName, publicKey, err := c.resolveDNSCryptStamp(server)
	if err != nil {
		return
	}
	_, _ = c.getDNSCryptState(ctx, addr, providerName, publicKey, server)
}
