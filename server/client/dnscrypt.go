package client

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
	"zjdns/config"
	"zjdns/internal/log"
	zstamp "zjdns/internal/stamp"

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

	// minQueryLen is the minimum padded query length for UDP.  Per §5.4.2 of
	// draft-denis-dprive-dnscrypt-10, escalated by 64 on each TC response.
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

// executeDNSCrypt sends an encrypted DNS query to a DNSCrypt resolver.
func (c *Client) executeDNSCrypt(ctx context.Context, msg *dns.Msg, server *config.UpstreamServer, useTCP bool) (*dns.Msg, error) {
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
	// Encrypt the query.
	q := &serverdnscrypt.EncryptedQuery{
		ESVersion:   state.esVersion,
		ClientMagic: state.clientMagic,
		ClientPk:    state.publicKey,
		MinQueryLen: state.minQueryLen,
		IsTCP:       useTCP,
	}
	if state.esVersion.IsPQ() {
		q.PQCertContext = state.pqCertContext
	}
	encrypted, clientNonce, err := prepareAndEncryptQuery(state, q, msg.Data)
	if err != nil {
		return nil, fmt.Errorf("encrypting dnscrypt query: %w", err)
	}

	// Dial to the server -- UDP (raw packets) or TCP (length-prefixed).
	// When a SOCKS5 proxy is configured, route through it: TCP uses
	// CONNECT, UDP uses UDP ASSOCIATE (matching dnscrypt-proxy).
	proxyDialer := c.getProxyDialer(server)
	network := "udp"
	if useTCP {
		network = "tcp"
	}
	var conn net.Conn
	if proxyDialer != nil {
		if useTCP {
			conn, err = proxyDialer.DialContext(ctx, "tcp", state.serverAddress)
		} else {
			conn, err = proxyDialer.DialUDP(ctx, state.serverAddress)
		}
	} else {
		dialer := &net.Dialer{}
		conn, err = dialer.DialContext(ctx, network, state.serverAddress)
	}
	if err != nil {
		return nil, fmt.Errorf("dialing dnscrypt server %s: %w", state.serverAddress, err)
	}
	defer func() { _ = conn.Close() }()

	deadline, ok := ctx.Deadline()
	if ok {
		_ = conn.SetDeadline(deadline)
	}

	var respPayload []byte
	if useTCP {
		// TCP: length-prefixed frames (2-byte big-endian length).
		if err := serverdnscrypt.WritePrefixed(encrypted, conn); err != nil {
			return nil, fmt.Errorf("writing dnscrypt TCP query: %w", err)
		}
		respPayload, err = serverdnscrypt.ReadPrefixed(conn)
		if err != nil {
			return nil, fmt.Errorf("reading dnscrypt TCP response: %w", err)
		}
	} else {
		// UDP: raw datagrams.
		_, err = conn.Write(encrypted)
		if err != nil {
			return nil, fmt.Errorf("writing dnscrypt query: %w", err)
		}
		respBuf := make([]byte, config.DefaultDNSCryptUDPSize)
		n, udpErr := conn.Read(respBuf)
		if udpErr != nil {
			return nil, fmt.Errorf("reading dnscrypt response: %w", udpErr)
		}
		respPayload = respBuf[:n]
	}

	// Decrypt response.
	resp := &serverdnscrypt.EncryptedResponse{
		ESVersion: state.esVersion,
	}
	decrypted, err := serverdnscrypt.DecryptResponse(resp, respPayload, state.sharedKey, clientNonce)
	if err != nil {
		return nil, fmt.Errorf("decrypting dnscrypt response: %w", err)
	}

	// Store PQ resumption ticket from the response control block.
	if len(resp.PQControl) > 0 {
		ticket, lifetime, parseErr := serverdnscrypt.PQParseControlBlock(resp.PQControl)
		if parseErr == nil && len(ticket) > 0 {
			state.pqTicket = ticket
			state.pqTicketExpiry = time.Now().Add(time.Duration(lifetime) * time.Second)
			state.pqResumeSecret = serverdnscrypt.PQResumeSecret(state.sharedKey, state.clientMagic, clientNonce[:serverdnscrypt.NonceSize/2])
			log.Debugf("UPSTREAM: DNSCrypt PQ resumption ticket stored (expires in %ds)", lifetime)
		}
	}

	log.Debugf("UPSTREAM: DNSCrypt decrypted response from %s (%d bytes)", state.serverAddress, len(decrypted))
	// Unpack DNS response.
	response := &dns.Msg{}
	response.Data = decrypted
	err = response.Unpack()
	if err != nil {
		return nil, fmt.Errorf("unpacking dnscrypt response: %w", err)
	}

	// §5.4.2: Escalate min-query-len by 64 on truncated UDP responses so
	// the next query is more likely to avoid fragmentation.
	if response.Truncated && !useTCP {
		const maxQueryLen = 4096
		if state.minQueryLen+64 <= maxQueryLen {
			state.minQueryLen += 64
			log.Debugf("UPSTREAM: DNSCrypt min-query-len escalated to %d after TC", state.minQueryLen)
		}
	}

	return response, nil
}

// prepareAndEncryptQuery handles both classical and PQ query encryption.
func prepareAndEncryptQuery(state *dnscryptState, q *serverdnscrypt.EncryptedQuery, packet []byte) (encrypted []byte, clientNonce serverdnscrypt.Nonce, err error) {
	if !state.esVersion.IsPQ() {
		return serverdnscrypt.EncryptQuery(q, packet, state.sharedKey)
	}

	// PQ: try resumed query first, fall back to fresh encapsulation.
	if len(state.pqTicket) > 0 && time.Now().Before(state.pqTicketExpiry) {
		// Generate nonce first — PQResumedSharedKey needs the client
		// nonce half for key derivation, and EncryptQuery must use the
		// same nonce for encryption.
		q.ClientNonce = newClientNonce()
		sharedKey := serverdnscrypt.PQResumedSharedKey(state.pqResumeSecret, state.clientMagic, q.ClientNonce[:serverdnscrypt.NonceSize/2], state.pqTicket)
		state.sharedKey = sharedKey
		q.PQTicket = state.pqTicket
		return serverdnscrypt.EncryptQuery(q, packet, sharedKey)
	}

	// Try cached encapsulation first to avoid expensive X-Wing KEM on every
	// query. The cache is valid until the state expires (cert re-fetch).
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

// newClientNonce generates a fresh 24-byte client nonce with fully random
// bytes in the client-chosen half, per §7.2 of draft-denis-dprive-dnscrypt-10:
// clients SHOULD NOT include unencrypted timestamps or other stable client
// state in nonce values.
func newClientNonce() serverdnscrypt.Nonce {
	var n serverdnscrypt.Nonce
	_, _ = rand.Read(n[:serverdnscrypt.NonceSize/2])
	return n
}

// resolveDNSCryptStamp extracts the server address, provider name, and public
// key from the upstream server configuration.
func (c *Client) resolveDNSCryptStamp(server *config.UpstreamServer) (addr, providerName string, publicKey []byte, err error) {
	// If address is an sdns:// stamp, parse it.
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

	// Ensure provider name is fully qualified.
	if !strings.HasSuffix(providerName, ".") {
		providerName += "."
	}

	// Fetch the certificate via a plain DNS TXT query.  UDP is tried first;
	// if the response has the TC flag set (e.g. the PQ certificate set is too
	// large for the unpadded request), the query is retried over TCP per
	// §10.3 of draft-denis-dprive-dnscrypt-10.
	certQuery := &dns.Msg{}
	certQuery.RecursionDesired = true
	txtRR := new(dns.TXT)
	txtRR.Hdr = dns.Header{Name: providerName, Class: dns.ClassINET, TTL: 0}
	certQuery.Question = []dns.RR{txtRR}
	err := certQuery.Pack()
	if err != nil {
		return nil, fmt.Errorf("packing cert query: %w", err)
	}

	resp, err := fetchCert(ctx, addr, certQuery.Data)
	if err != nil {
		return nil, fmt.Errorf("fetching dnscrypt cert from %s: %w", addr, err)
	}

	if resp.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("fetching dnscrypt cert: server returned %s", dns.RcodeToString[resp.Rcode])
	}

	// Parse and verify the certificate.
	cert, err := parseDNSCryptCert(resp.Answer, publicKey, providerName)
	if err != nil {
		return nil, fmt.Errorf("parsing dnscrypt cert: %w", err)
	}

	// Compute shared key.  For PQ, the shared key is derived per-query via
	// X-Wing encapsulate — no X25519 keypair is needed.
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

	state := &dnscryptState{
		serverAddress: addr,
		sharedKey:     sharedKey,
		secretKey:     secretKey,
		publicKey:     clientPK,
		serverPK:      publicKey,
		clientMagic:   cert.ClientMagic,
		esVersion:     esVersion,
		expires:       time.Now().Add(config.DefaultDNSCryptCertCacheTTL),
		minQueryLen:   256,
	}

	if esVersion.IsPQ() && len(cert.PqPublicKey) > 0 {
		state.pqPublicKey = cert.PqPublicKey
		state.pqCertContext = cert.PqCertContext
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
// verifies its signature.  It prefers PQ certificates (es-version 0x0003) over
// classical ones when both are available (matching the dnscrypt-proxy
// behaviour).
func parseDNSCryptCert(
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
		// Prefer PQ over classical at same serial.
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

// warmUpDNSCrypt pre-fetches the DNSCrypt certificate for the given server.
func (c *Client) warmUpDNSCrypt(ctx context.Context, server *config.UpstreamServer) {
	addr, providerName, publicKey, err := c.resolveDNSCryptStamp(server)
	if err != nil {
		return
	}
	_, _ = c.getDNSCryptState(ctx, addr, providerName, publicKey, server)
}

// fetchCert sends a plain DNS query to addr and returns the unpacked response.
// UDP is tried first; if the response has the TC flag set, the query is
// retried over TCP per §10.3 of draft-denis-dprive-dnscrypt-10.
func fetchCert(ctx context.Context, addr string, query []byte) (*dns.Msg, error) {
	// Try UDP first.
	resp, err := fetchCertOverUDP(ctx, addr, query)
	if err != nil {
		return nil, err
	}
	if !resp.Truncated {
		return resp, nil
	}

	// TC set — retry over TCP.
	log.Debugf("UPSTREAM: DNSCrypt cert response truncated, retrying over TCP")
	tcpResp, tcpErr := fetchCertOverTCP(ctx, addr, query)
	if tcpErr != nil {
		// If TCP fails, return the truncated UDP response so the caller
		// can still extract classical certificates from it.
		log.Debugf("UPSTREAM: DNSCrypt cert TCP retry failed: %v", tcpErr)
		return resp, nil
	}
	return tcpResp, nil
}

// fetchCertOverUDP sends a single UDP DNS query and returns the unpacked response.
func fetchCertOverUDP(ctx context.Context, addr string, query []byte) (*dns.Msg, error) {
	conn, err := net.Dial("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial udp: %w", err)
	}
	defer func() { _ = conn.Close() }()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	if _, err := conn.Write(query); err != nil {
		return nil, fmt.Errorf("write: %w", err)
	}

	buf := make([]byte, config.DefaultDNSCryptResponseBuffer)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}

	resp := &dns.Msg{}
	resp.Data = buf[:n]
	if err := resp.Unpack(); err != nil {
		return nil, fmt.Errorf("unpack: %w", err)
	}
	return resp, nil
}

// fetchCertOverTCP sends a DNS query over TCP (2-byte length prefix) and
// returns the unpacked response.
func fetchCertOverTCP(ctx context.Context, addr string, query []byte) (*dns.Msg, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial tcp: %w", err)
	}
	defer func() { _ = conn.Close() }()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	// TCP DNS: 2-byte big-endian length prefix.
	frame := make([]byte, 2+len(query))
	frame[0] = byte(len(query) >> 8) //nolint:gosec // G115: DNS query bounded by MaxMsgSize (65535)
	frame[1] = byte(len(query))      //nolint:gosec // G115: DNS query bounded by MaxMsgSize (65535)
	copy(frame[2:], query)
	if _, err := conn.Write(frame); err != nil {
		return nil, fmt.Errorf("write: %w", err)
	}

	respLen := make([]byte, 2)
	if _, err := io.ReadFull(conn, respLen); err != nil {
		return nil, fmt.Errorf("read length: %w", err)
	}
	packetLen := int(respLen[0])<<8 | int(respLen[1])
	if packetLen > dns.MaxMsgSize {
		return nil, fmt.Errorf("response too large: %d", packetLen)
	}
	buf := make([]byte, packetLen)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	resp := &dns.Msg{}
	resp.Data = buf
	if err := resp.Unpack(); err != nil {
		return nil, fmt.Errorf("unpack: %w", err)
	}
	return resp, nil
}
