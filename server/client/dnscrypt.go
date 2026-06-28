package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/mlkem"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/crypto/nacl/secretbox"

	"zjdns/config"
	"zjdns/internal/log"
	"zjdns/internal/pool"
	dnscrypt "zjdns/server/dnscrypt"
)

const (
	// dnscryptSessionTTL is how long a cached session (ephemeral key pair +
	// shared key) is reused before rotating for forward secrecy.
	dnscryptSessionTTL = 1 * time.Hour
)

// dnscryptSession holds a cached DNSCrypt session with pre-computed shared key
// and a persistent UDP socket for stable SO_REUSEPORT routing.
type dnscryptSession struct {
	esVersion       dnscrypt.CryptoConstruction
	clientMagic     [8]byte
	clientSk        [32]byte
	clientPk        [32]byte
	serverPk        [32]byte
	sharedKey       [32]byte
	mlkemCiphertext [1088]byte // ML-KEM-768 ciphertext (PQ only)
	cachedAt        time.Time
	udpConn         *net.UDPConn // persistent UDP socket per upstream
}

// queryHeaderLen returns the wire header size for this session.
func (s *dnscryptSession) queryHeaderLen() int {
	if s.esVersion.IsPQ() {
		return dnscrypt.QueryHeaderLenPQ
	}
	return dnscrypt.QueryHeaderLen
}

// dnscryptCacheEntry is the per-upstream cached session.
type dnscryptCacheEntry struct {
	session  *dnscryptSession
	cachedAt time.Time
}

// executeDNSCrypt sends a DNS query to a DNSCrypt v2 upstream server.
func (c *Client) executeDNSCrypt(ctx context.Context, msg *dns.Msg, server *config.UpstreamServer) (*dns.Msg, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	if server.ServerName == "" {
		return nil, fmt.Errorf("DNSCRYPT: server_name (provider name) required for %s", server.Address)
	}
	if server.DNSCryptPublicKey == "" {
		return nil, fmt.Errorf("DNSCRYPT: dnscrypt_public_key required for %s", server.Address)
	}

	providerName := config.NormalizeDNSCryptProviderName(server.ServerName)
	if len(providerName) > 253 {
		return nil, fmt.Errorf("DNSCRYPT: provider_name too long (%d bytes, max 253)", len(providerName))
	}

	serverAddr := server.Address
	if _, _, err := net.SplitHostPort(serverAddr); err != nil {
		serverAddr = net.JoinHostPort(serverAddr, config.DefaultDNSCryptPort)
	}

	session, err := c.getDNSCryptSession(ctx, serverAddr, providerName, server.DNSCryptPublicKey, server.DNSCryptMlkemPublicKey)
	if err != nil {
		return nil, err
	}

	// Encrypt and send the query.  Save/restore DNS message ID for privacy.
	originalID := msg.Id
	msg.Id = 0

	var response *dns.Msg
	if server.DNSCryptTCP {
		response, err = c.exchangeDNSCryptTCP(ctx, msg, session, serverAddr)
	} else {
		response, err = c.exchangeDNSCryptUDP(ctx, msg, session, serverAddr)
	}

	msg.Id = originalID
	if response != nil {
		response.Id = originalID
	}

	if err != nil {
		return nil, fmt.Errorf("DNSCRYPT: exchange with %s: %w", serverAddr, err)
	}
	return response, nil
}

// getDNSCryptSession returns a cached or newly-established DNSCrypt session.
// mlkemPubkeyHex is optional — the ML-KEM PK is read from the certificate.
func (c *Client) getDNSCryptSession(ctx context.Context, serverAddr, providerName, pubkeyHex, mlkemPubkeyHex string) (*dnscryptSession, error) {
	cacheKey := serverAddr + "|" + providerName

	c.dnscryptResolverMu.Lock()
	entry, ok := c.dnscryptResolvers[cacheKey]
	if ok && entry != nil && time.Since(entry.cachedAt) < dnscryptSessionTTL {
		session := entry.session
		c.dnscryptResolverMu.Unlock()
		return session, nil
	}
	c.dnscryptResolverMu.Unlock()

	// Deduplicate concurrent fetches: if another goroutine is already
	// fetching this cert, wait for it and retry the cache lookup.
	c.dnscryptResolverMu.Lock()
	if wait, ok := c.dnscryptPending[cacheKey]; ok {
		c.dnscryptResolverMu.Unlock()
		select {
		case <-wait:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		// Retry cache after the in-flight fetch completes.
		c.dnscryptResolverMu.Lock()
		entry, ok := c.dnscryptResolvers[cacheKey]
		if ok && entry != nil && time.Since(entry.cachedAt) < dnscryptSessionTTL {
			session := entry.session
			c.dnscryptResolverMu.Unlock()
			return session, nil
		}
		c.dnscryptResolverMu.Unlock()
	} else {
		done := make(chan struct{})
		c.dnscryptPending[cacheKey] = done
		c.dnscryptResolverMu.Unlock()
		defer func() {
			c.dnscryptResolverMu.Lock()
			delete(c.dnscryptPending, cacheKey)
			close(done)
			c.dnscryptResolverMu.Unlock()
		}()
	}

	// Decode public key (only on cache miss).
	pkStr := strings.ReplaceAll(pubkeyHex, ":", "")
	providerPK, err := hex.DecodeString(pkStr)
	if err != nil {
		return nil, fmt.Errorf("DNSCRYPT: invalid dnscrypt_public_key: %w", err)
	}
	if len(providerPK) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("DNSCRYPT: dnscrypt_public_key must be %d bytes, got %d",
			ed25519.PublicKeySize, len(providerPK))
	}

	// Fetch and verify the server certificate.
	cert, err := fetchCert(ctx, serverAddr, providerName, providerPK)
	if err != nil {
		return nil, fmt.Errorf("DNSCRYPT: fetch cert from %s: %w", serverAddr, err)
	}

	// Optional: pin the ML-KEM public key for PQ constructions.
	if cert.ESVersion.IsPQ() && mlkemPubkeyHex != "" {
		expectedPK, _ := hex.DecodeString(strings.ReplaceAll(mlkemPubkeyHex, ":", ""))
		if !bytes.Equal(expectedPK, cert.ResolverMlkemPk[:]) {
			return nil, fmt.Errorf("DNSCRYPT: ML-KEM public key mismatch for %s", serverAddr)
		}
	}

	// Generate ephemeral X25519 key pair (pub, secret).
	clientPk, clientSk, err := dnscrypt.GenerateX25519KeyPair()
	if err != nil {
		return nil, fmt.Errorf("DNSCRYPT: generate key pair: %w", err)
	}

	// Compute shared key: classic X25519 ECDH or hybrid X25519 + ML-KEM-768.
	var sharedKey [32]byte
	var mlkemCt [1088]byte
	if cert.ESVersion.IsPQ() {
		// ML-KEM-768: encapsulate against the server's public key.
		ek, err := mlkem.NewEncapsulationKey768(cert.ResolverMlkemPk[:])
		if err != nil {
			return nil, fmt.Errorf("DNSCRYPT: parse ML-KEM public key: %w", err)
		}
		mlkemSS, ciphertext := ek.Encapsulate()
		copy(mlkemCt[:], ciphertext)

		sharedKey, err = dnscrypt.ComputeSharedKeyPQ(&clientSk, &cert.ResolverPk, mlkemSS)
		if err != nil {
			return nil, fmt.Errorf("DNSCRYPT: compute PQ shared key: %w", err)
		}
	} else {
		sharedKey, err = dnscrypt.ComputeSharedKey(cert.ESVersion, &clientSk, &cert.ResolverPk)
		if err != nil {
			return nil, fmt.Errorf("DNSCRYPT: compute shared key: %w", err)
		}
	}

	session := &dnscryptSession{
		esVersion:       cert.ESVersion,
		clientMagic:     cert.ClientMagic,
		clientSk:        clientSk,
		clientPk:        clientPk,
		serverPk:        cert.ResolverPk,
		sharedKey:       sharedKey,
		mlkemCiphertext: mlkemCt,
		cachedAt:        time.Now(),
	}

	c.dnscryptResolverMu.Lock()
	if len(c.dnscryptResolvers) >= config.DefaultTransportMax {
		for k := range c.dnscryptResolvers {
			if entry := c.dnscryptResolvers[k]; entry != nil && entry.session != nil && entry.session.udpConn != nil {
				_ = entry.session.udpConn.Close()
			}
			delete(c.dnscryptResolvers, k)
			break
		}
	}
	c.dnscryptResolvers[cacheKey] = &dnscryptCacheEntry{
		session:  session,
		cachedAt: time.Now(),
	}
	c.dnscryptResolverMu.Unlock()

	log.Debugf("DNSCRYPT: established session with %s (%s)", serverAddr, providerName)
	return session, nil
}

// fetchCertViaUDP sends a cert TXT query over UDP and returns the raw
// response bytes.
func fetchCertViaUDP(serverAddr string, query []byte) ([]byte, error) {
	conn, err := net.DialTimeout("udp", serverAddr, config.DefaultDNSQueryTimeout)
	if err != nil {
		return nil, fmt.Errorf("UDP dial: %w", err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetWriteDeadline(time.Now().Add(config.DefaultDNSQueryTimeout))
	if _, err := conn.Write(query); err != nil {
		return nil, fmt.Errorf("UDP write: %w", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(config.DefaultDNSQueryTimeout))
	buf := make([]byte, pool.SecureBufferSize)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("UDP read: %w", err)
	}
	return buf[:n], nil
}

// fetchCertViaTCP sends a cert TXT query over TCP (2-byte length prefix)
// and returns the raw response bytes.  Used as fallback when UDP cert
// queries get routed to the wrong SO_REUSEPORT socket (e.g. DoH3).
func fetchCertViaTCP(serverAddr string, query []byte) ([]byte, error) {
	conn, err := net.DialTimeout("tcp", serverAddr, config.DefaultDNSQueryTimeout)
	if err != nil {
		return nil, fmt.Errorf("TCP dial: %w", err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetWriteDeadline(time.Now().Add(config.DefaultDNSQueryTimeout))
	if err := binary.Write(conn, binary.BigEndian, uint16(len(query))); err != nil {
		return nil, fmt.Errorf("TCP write length: %w", err)
	}
	if _, err := conn.Write(query); err != nil {
		return nil, fmt.Errorf("TCP write: %w", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(config.DefaultDNSQueryTimeout))
	var respLen uint16
	if err := binary.Read(conn, binary.BigEndian, &respLen); err != nil {
		return nil, fmt.Errorf("TCP read length: %w", err)
	}
	if respLen == 0 || int(respLen) > pool.SecureBufferSize {
		return nil, fmt.Errorf("TCP invalid response length: %d", respLen)
	}
	buf := make([]byte, respLen)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, fmt.Errorf("TCP read: %w", err)
	}
	return buf, nil
}

// fetchCert fetches and verifies the DNSCrypt server certificate via a plain
// DNS TXT query.  Uses raw wire parsing to avoid miekg's TXT string conversion
// which corrupts binary certificate data.
func fetchCert(ctx context.Context, serverAddr, providerName string, providerPK ed25519.PublicKey) (*dnscrypt.Certificate, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(providerName), dns.TypeTXT)
	msg.RecursionDesired = true

	// Try UDP first, fall back to TCP.  On port-shared servers
	// (SO_REUSEPORT with DoH3), UDP cert queries may be routed to
	// the QUIC socket and dropped — TCP avoids this because the
	// DNSCrypt TCP handler does protocol detection.
	query, _ := msg.Pack()
	certBytes, err := fetchCertViaUDP(serverAddr, query)
	if err != nil {
		certBytes, err = fetchCertViaTCP(serverAddr, query)
		if err != nil {
			return nil, fmt.Errorf("cert query (UDP+TCP): %w", err)
		}
	}

	// Parse raw DNS response to extract TXT record bytes directly.
	resp := new(dns.Msg)
	if err := resp.Unpack(certBytes); err != nil {
		return nil, fmt.Errorf("cert query unpack: %w", err)
	}
	if len(resp.Answer) == 0 {
		return nil, fmt.Errorf("no cert TXT record at %s", providerName)
	}
	txt, ok := resp.Answer[0].(*dns.TXT)
	if !ok || len(txt.Txt) == 0 {
		return nil, fmt.Errorf("invalid cert TXT response")
	}

	// Extract raw cert bytes, handling both hex and raw binary.  Concatentate
	// all TXT segments before decoding.
	certRaw := strings.Join(txt.Txt, "")

	var certRawBytes []byte
	if isHex(certRaw) {
		certRawBytes, err = hex.DecodeString(certRaw)
		if err != nil {
			return nil, fmt.Errorf("decode cert hex: %w", err)
		}
	} else {
		// Raw binary — reconstruct from the DNS wire directly.
		certRawBytes, err = extractTXTBytes(certBytes)
		if err != nil {
			return nil, fmt.Errorf("extract cert bytes: %w", err)
		}
	}

	cert := &dnscrypt.Certificate{}
	if err := cert.Deserialize(certRawBytes); err != nil {
		return nil, fmt.Errorf("deserialize cert (%d bytes): %w", len(certRawBytes), err)
	}
	if !cert.VerifyDate() {
		return nil, fmt.Errorf("cert expired or not yet valid")
	}
	if !cert.VerifySignature(providerPK) {
		return nil, fmt.Errorf("cert signature verification failed")
	}

	return cert, nil
}

// extractTXTBytes extracts raw TXT record bytes from a DNS response packet.
// Used when miekg's string conversion would corrupt binary cert data.
func extractTXTBytes(packet []byte) ([]byte, error) {
	if len(packet) < 12 {
		return nil, fmt.Errorf("packet too short")
	}
	// Skip DNS header (12 bytes) + question section.
	offset := 12
	// Skip question: QNAME + QTYPE(2) + QCLASS(2).
	for offset < len(packet) && packet[offset] != 0 {
		if packet[offset]&0xC0 == 0xC0 {
			offset += 2 // compression pointer
			break
		}
		offset += int(packet[offset]) + 1
	}
	offset += 5 // past QTYPE+QCLASS or compression terminator

	// Parse answer section to find TXT record.
	if offset+10 >= len(packet) {
		return nil, fmt.Errorf("no answer section")
	}
	// Skip name (could be pointer).
	if packet[offset]&0xC0 == 0xC0 {
		offset += 2
	} else {
		for offset < len(packet) && packet[offset] != 0 {
			offset += int(packet[offset]) + 1
		}
		offset++ // null terminator
	}
	if offset+10 > len(packet) {
		return nil, fmt.Errorf("answer too short")
	}
	offset += 2 // TYPE
	offset += 2 // CLASS
	offset += 4 // TTL
	rdLen := int(binary.BigEndian.Uint16(packet[offset : offset+2]))
	offset += 2
	if offset+rdLen > len(packet) {
		return nil, fmt.Errorf("RDLENGTH exceeds packet")
	}
	// TXT RDATA: one or more <length><data> character-strings.
	txtData := packet[offset : offset+rdLen]
	var result []byte
	for i := 0; i < len(txtData); {
		if i >= len(txtData) {
			break
		}
		chunkLen := int(txtData[i])
		i++
		if i+chunkLen > len(txtData) {
			break
		}
		result = append(result, txtData[i:i+chunkLen]...)
		i += chunkLen
	}
	return result, nil
}

// exchangeDNSCryptUDP encrypts a query, sends it over UDP, and decrypts the
// response.  Uses a persistent UDP socket per session so the 5-tuple
// (and thus SO_REUSEPORT routing) is stable across queries.
func (c *Client) exchangeDNSCryptUDP(ctx context.Context, msg *dns.Msg, session *dnscryptSession, serverAddr string) (*dns.Msg, error) {
	encrypted, nonce, err := encryptQuery(msg, session, session.esVersion)
	if err != nil {
		return nil, err
	}

	conn, err := c.getDNSCryptUDPConn(session, serverAddr)
	if err != nil {
		return nil, err
	}

	_ = conn.SetWriteDeadline(time.Now().Add(config.DefaultDNSQueryTimeout))
	if _, err := conn.Write(encrypted); err != nil {
		return nil, fmt.Errorf("write: %w", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(config.DefaultDNSQueryTimeout))
	buf := make([]byte, pool.SecureBufferSize)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}

	return decryptResponse(buf[:n], &session.sharedKey, nonce, session.esVersion)
}

// getDNSCryptUDPConn returns the persistent UDP socket for this session,
// creating one lazily on first use.
func (c *Client) getDNSCryptUDPConn(session *dnscryptSession, serverAddr string) (*net.UDPConn, error) {
	if session.udpConn != nil {
		return session.udpConn, nil
	}
	addr, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		return nil, fmt.Errorf("resolve UDP addr: %w", err)
	}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return nil, fmt.Errorf("dial UDP: %w", err)
	}
	session.udpConn = conn
	return conn, nil
}

// exchangeDNSCryptTCP encrypts a query, sends it over TCP (with 2-byte length
// prefix), and decrypts the response.
func (c *Client) exchangeDNSCryptTCP(ctx context.Context, msg *dns.Msg, session *dnscryptSession, serverAddr string) (*dns.Msg, error) {
	encrypted, nonce, err := encryptQuery(msg, session, session.esVersion)
	if err != nil {
		return nil, err
	}

	conn, err := net.DialTimeout("tcp", serverAddr, config.DefaultDNSQueryTimeout)
	if err != nil {
		return nil, fmt.Errorf("dial TCP: %w", err)
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetWriteDeadline(time.Now().Add(config.DefaultDNSQueryTimeout))
	// TCP: prepend 2-byte length prefix.
	if err := binary.Write(conn, binary.BigEndian, uint16(len(encrypted))); err != nil {
		return nil, fmt.Errorf("write length: %w", err)
	}
	if _, err := conn.Write(encrypted); err != nil {
		return nil, fmt.Errorf("write: %w", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(config.DefaultDNSQueryTimeout))
	var respLen uint16
	if err := binary.Read(conn, binary.BigEndian, &respLen); err != nil {
		return nil, fmt.Errorf("read length: %w", err)
	}
	if respLen == 0 || int(respLen) > pool.SecureBufferSize {
		return nil, fmt.Errorf("invalid response length: %d", respLen)
	}
	buf := make([]byte, respLen)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}

	return decryptResponse(buf, &session.sharedKey, nonce, session.esVersion)
}

// encryptQuery builds an encrypted DNSCrypt query packet.
func encryptQuery(msg *dns.Msg, session *dnscryptSession, esVersion dnscrypt.CryptoConstruction) ([]byte, *[24]byte, error) {
	packet, err := msg.Pack()
	if err != nil {
		return nil, nil, fmt.Errorf("pack: %w", err)
	}

	// Generate query nonce: 8 bytes timestamp + 4 bytes random + 12 zero.
	var nonce [24]byte
	binary.BigEndian.PutUint64(nonce[:8], uint64(time.Now().UnixNano()))
	if _, err := rand.Read(nonce[8:12]); err != nil {
		return nil, nil, err
	}

	padded := dnscrypt.PadPacket(packet)

	hdrLen := session.queryHeaderLen()
	encrypted := make([]byte, 0, hdrLen+len(padded)+16)
	encrypted = append(encrypted, session.clientMagic[:]...)
	encrypted = append(encrypted, session.clientPk[:]...)
	if esVersion.IsPQ() {
		encrypted = append(encrypted, session.mlkemCiphertext[:]...)
	}
	encrypted = append(encrypted, nonce[:12]...)

	aead := esVersion
	if esVersion.IsPQ() {
		aead = esVersion.AEAD()
	}
	switch aead {
	case dnscrypt.XSalsa20Poly1305:
		var xsalsaNonce [24]byte
		copy(xsalsaNonce[:], nonce[:])
		encrypted = secretbox.Seal(encrypted, padded, &xsalsaNonce, &session.sharedKey)
	case dnscrypt.XChacha20Poly1305:
		encrypted = dnscrypt.XChachaSeal(encrypted, nonce[:], padded, session.sharedKey[:])
	default:
		return nil, nil, fmt.Errorf("DNSCRYPT: unknown crypto construction %d", aead)
	}

	return encrypted, &nonce, nil
}

// decryptResponse decrypts a DNSCrypt response packet.
func decryptResponse(packet []byte, sharedKey *[32]byte, queryNonce *[24]byte, esVersion dnscrypt.CryptoConstruction) (*dns.Msg, error) {
	// Response format: resolverMagic(8) + nonce(24) + encrypted
	const respHeaderLen = 8 + 24
	if len(packet) < respHeaderLen+16+dnscrypt.MinDNSPacketSize {
		return nil, fmt.Errorf("DNSCRYPT: response too short")
	}

	if !bytes.Equal(packet[:8], dnscrypt.ResolverMagic) {
		return nil, fmt.Errorf("DNSCRYPT: invalid resolver magic")
	}

	var nonce [24]byte
	copy(nonce[:], packet[8:32])

	var decrypted []byte
	aead := esVersion
	if esVersion.IsPQ() {
		aead = esVersion.AEAD()
	}
	switch aead {
	case dnscrypt.XSalsa20Poly1305:
		var ok bool
		decrypted, ok = secretbox.Open(nil, packet[32:], &nonce, sharedKey)
		if !ok {
			return nil, fmt.Errorf("DNSCRYPT: decryption failed")
		}
	case dnscrypt.XChacha20Poly1305:
		var derr error
		decrypted, derr = dnscrypt.XChachaOpen(nil, nonce[:], packet[32:], sharedKey[:])
		if derr != nil {
			return nil, fmt.Errorf("DNSCRYPT: xchacha open: %w", derr)
		}
	default:
		return nil, fmt.Errorf("DNSCRYPT: unknown crypto construction %d", aead)
	}

	unpadded, err := dnscrypt.Unpad(decrypted)
	if err != nil {
		return nil, fmt.Errorf("DNSCRYPT: unpad: %w", err)
	}

	resp := &dns.Msg{}
	if err := resp.Unpack(unpadded); err != nil {
		return nil, fmt.Errorf("DNSCRYPT: unpack: %w", err)
	}
	return resp, nil
}

func isHex(s string) bool {
	if len(s) == 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}
