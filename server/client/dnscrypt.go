package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/cloudflare/circl/kem/xwing"
	"github.com/miekg/dns"
	"golang.org/x/crypto/hkdf"
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

// dnscryptSession holds a cached DNSCrypt session with pre-computed shared key.
type dnscryptSession struct {
	esVersion       dnscrypt.CryptoConstruction
	clientMagic     [8]byte
	clientSk        [32]byte // X25519 secret key (classic only)
	clientPk        [32]byte // X25519 public key (classic only)
	serverPk        [32]byte // X25519 server public key (classic only)
	sharedKey       [32]byte
	xwingCiphertext [1120]byte // X-Wing ciphertext (PQ only)
	cachedAt        time.Time
}

// queryHeaderLen returns the wire header size for this session.
func (s *dnscryptSession) queryHeaderLen() int {
	if s.esVersion == dnscrypt.XWingPQ {
		return dnscrypt.QueryHeaderLenXWing // 1140
	}
	return dnscrypt.QueryHeaderLen // 52
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

	certAddr := serverAddr
	if server.CertFetchAddress != "" {
		certAddr = server.CertFetchAddress
		if _, _, err := net.SplitHostPort(certAddr); err != nil {
			certAddr = net.JoinHostPort(certAddr, config.DefaultDNSPort)
		}
	}

	session, err := c.getDNSCryptSession(ctx, serverAddr, certAddr, providerName, server.DNSCryptPublicKey)
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
func (c *Client) getDNSCryptSession(ctx context.Context, serverAddr, certAddr, providerName, pubkeyHex string) (*dnscryptSession, error) {
	cacheKey := serverAddr + "|" + providerName

	c.dnscryptResolverMu.Lock()
	entry, ok := c.dnscryptResolvers[cacheKey]
	if ok && entry != nil && time.Since(entry.cachedAt) < dnscryptSessionTTL {
		session := entry.session
		c.dnscryptResolverMu.Unlock()
		return session, nil
	}
	c.dnscryptResolverMu.Unlock()

	// Deduplicate concurrent fetches.
	c.dnscryptResolverMu.Lock()
	if wait, ok := c.dnscryptPending[cacheKey]; ok {
		c.dnscryptResolverMu.Unlock()
		select {
		case <-wait:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
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
	cert, err := fetchCert(ctx, certAddr, providerName, providerPK)
	if err != nil {
		return nil, fmt.Errorf("DNSCRYPT: fetch cert from %s: %w", serverAddr, err)
	}

	// Compute shared key: classic X25519 ECDH or X-Wing hybrid KEM.
	var sharedKey [32]byte
	var xwingCT [1120]byte
	var clientPk, clientSk, serverPk [32]byte

	if cert.ESVersion == dnscrypt.XWingPQ {
		xwingPK := cert.XWingPublicKey()
		ss, ct, err := xwing.Encapsulate(xwingPK, nil)
		if err != nil {
			return nil, fmt.Errorf("DNSCRYPT: xwing encapsulate: %w", err)
		}
		copy(xwingCT[:], ct)
		certCtx := cert.CertContext()
		sharedKey = dnscryptXWingDeriveSharedKey(cert.ESVersion, cert.ClientMagic[:], ss, ct, certCtx)
	} else {
		clientPk, clientSk, err = dnscrypt.GenerateX25519KeyPair()
		if err != nil {
			return nil, fmt.Errorf("DNSCRYPT: generate key pair: %w", err)
		}
		copy(serverPk[:], cert.ResolverPk[:32])
		sharedKey, err = dnscrypt.ComputeSharedKey(cert.ESVersion, &clientSk, &serverPk)
		if err != nil {
			return nil, fmt.Errorf("DNSCRYPT: compute shared key: %w", err)
		}
	}

	session := &dnscryptSession{
		esVersion:       cert.ESVersion,
		clientMagic:     cert.ClientMagic,
		clientSk:        clientSk,
		clientPk:        clientPk,
		serverPk:        serverPk,
		sharedKey:       sharedKey,
		xwingCiphertext: xwingCT,
		cachedAt:        time.Now(),
	}

	c.dnscryptResolverMu.Lock()
	if len(c.dnscryptResolvers) >= config.DefaultTransportMax {
		for k := range c.dnscryptResolvers {
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

// dnscryptXWingDeriveSharedKey derives the per-query symmetric key from an
// X-Wing shared secret.
func dnscryptXWingDeriveSharedKey(esVersion dnscrypt.CryptoConstruction, clientMagic, xwingSS, xwingCT, certCtx []byte) [32]byte {
	salt := make([]byte, 2+len(clientMagic))
	binary.BigEndian.PutUint16(salt[:2], uint16(esVersion))
	copy(salt[2:], clientMagic)

	info := make([]byte, len(certCtx)+len(xwingCT))
	copy(info, certCtx)
	copy(info[len(certCtx):], xwingCT)

	var key [32]byte
	kdf := hkdf.New(sha256.New, xwingSS, salt, info)
	if _, err := io.ReadFull(kdf, key[:]); err != nil {
		panic("dnscrypt: hkdf: " + err.Error())
	}
	return key
}

// fetchCert fetches and verifies the DNSCrypt server certificate via a plain
// DNS TXT query using standard dns.Client (UDP with automatic TCP fallback).
func fetchCert(ctx context.Context, serverAddr, providerName string, providerPK ed25519.PublicKey) (*dnscrypt.Certificate, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(providerName), dns.TypeTXT)
	msg.RecursionDesired = true

	log.Debugf("DNSCRYPT: fetching cert for %s from %s", providerName, serverAddr)

	client := dns.Client{Net: "udp"}
	resp, _, err := client.ExchangeContext(ctx, msg, serverAddr)
	if err != nil {
		return nil, fmt.Errorf("cert TXT query: %w", err)
	}
	if resp.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("cert TXT query returned %s", dns.RcodeToString[resp.Rcode])
	}

	// Collect TXT records.  Multiple TXT answers may be present (different
	// certificates); pick the first valid one.
	for _, rr := range resp.Answer {
		txt, ok := rr.(*dns.TXT)
		if !ok || len(txt.Txt) == 0 {
			continue
		}

		certRawBytes := parseCertTXT(txt.Txt)
		if len(certRawBytes) == 0 {
			continue
		}

		cert := &dnscrypt.Certificate{}
		if err := cert.Deserialize(certRawBytes); err != nil {
			log.Debugf("DNSCRYPT: deserialize cert (%d bytes): %v", len(certRawBytes), err)
			continue
		}
		if !cert.VerifyDate() {
			log.Debugf("DNSCRYPT: cert expired or not yet valid")
			continue
		}
		if !cert.VerifySignature(providerPK) {
			log.Debugf("DNSCRYPT: cert signature verification failed")
			continue
		}
		return cert, nil
	}

	return nil, fmt.Errorf("no valid cert TXT record at %s", providerName)
}

// parseCertTXT extracts raw certificate bytes from miekg TXT strings.
// Handles both hex-encoded (legacy) and raw binary (standard) formats.
func parseCertTXT(txt []string) []byte {
	raw := strings.Join(txt, "")
	if isHex(raw) {
		b, err := hex.DecodeString(raw)
		if err != nil {
			return nil
		}
		return b
	}
	// Raw binary — miekg stores TXT in \DDD presentation format.
	var buf []byte
	for _, s := range txt {
		buf = append(buf, unpackTxtString(s)...)
	}
	return buf
}

// exchangeDNSCryptUDP encrypts a query, sends it over UDP, and decrypts the
// response.  Each query uses a fresh UDP connection (matching the approach
// of dnscrypt-proxy and AdGuardTeam/dnscrypt).
func (c *Client) exchangeDNSCryptUDP(ctx context.Context, msg *dns.Msg, session *dnscryptSession, serverAddr string) (*dns.Msg, error) {
	encrypted, _, err := encryptQuery(msg, session, session.esVersion)
	if err != nil {
		return nil, err
	}

	dialer := &net.Dialer{Timeout: config.DefaultDNSQueryTimeout}
	conn, err := dialer.DialContext(ctx, "udp", serverAddr)
	if err != nil {
		return nil, fmt.Errorf("dial UDP: %w", err)
	}
	defer func() { _ = conn.Close() }()

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

	return decryptResponse(buf[:n], &session.sharedKey, session.esVersion)
}

// exchangeDNSCryptTCP encrypts a query, sends it over TCP, and decrypts the response.
func (c *Client) exchangeDNSCryptTCP(ctx context.Context, msg *dns.Msg, session *dnscryptSession, serverAddr string) (*dns.Msg, error) {
	encrypted, _, err := encryptQuery(msg, session, session.esVersion)
	if err != nil {
		return nil, err
	}

	dialer := &net.Dialer{Timeout: config.DefaultDNSQueryTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", serverAddr)
	if err != nil {
		return nil, fmt.Errorf("dial TCP: %w", err)
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetWriteDeadline(time.Now().Add(config.DefaultDNSQueryTimeout))
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

	return decryptResponse(buf, &session.sharedKey, session.esVersion)
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

	aead := esVersion.AEAD()
	hdrLen := session.queryHeaderLen()
	encrypted := make([]byte, 0, hdrLen+len(padded)+16)

	if esVersion == dnscrypt.XWingPQ {
		encrypted = append(encrypted, session.clientMagic[:]...)
		encrypted = append(encrypted, session.xwingCiphertext[:]...)
		encrypted = append(encrypted, nonce[:12]...)
	} else {
		encrypted = append(encrypted, session.clientMagic[:]...)
		encrypted = append(encrypted, session.clientPk[:]...)
		encrypted = append(encrypted, nonce[:12]...)
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
func decryptResponse(packet []byte, sharedKey *[32]byte, esVersion dnscrypt.CryptoConstruction) (*dns.Msg, error) {
	const respHeaderLen = 8 + 24
	if len(packet) < respHeaderLen+16+dnscrypt.MinDNSPacketSize {
		return nil, fmt.Errorf("DNSCRYPT: response too short")
	}

	if !bytes.Equal(packet[:8], dnscrypt.ResolverMagic) {
		return nil, fmt.Errorf("DNSCRYPT: invalid resolver magic")
	}

	var nonce [24]byte
	copy(nonce[:], packet[8:32])

	aead := esVersion.AEAD()

	var decrypted []byte
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

	// Strip control block from X-Wing responses.
	if esVersion == dnscrypt.XWingPQ {
		if len(unpadded) < 2 {
			return nil, fmt.Errorf("DNSCRYPT: PQ response too short for control block")
		}
		cbLen := int(binary.BigEndian.Uint16(unpadded[:2]))
		offset := 2 + cbLen
		if offset > len(unpadded) {
			return nil, fmt.Errorf("DNSCRYPT: PQ control block overflows response")
		}
		unpadded = unpadded[offset:]
	}

	resp := &dns.Msg{}
	if err := resp.Unpack(unpadded); err != nil {
		return nil, fmt.Errorf("DNSCRYPT: unpack: %w", err)
	}
	return resp, nil
}

// unpackTxtString unpacks a TXT string by unescaping \DDD sequences back to bytes.
func unpackTxtString(s string) []byte {
	buf := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) && isDDD(s[i+1:]) {
			buf = append(buf, dddToByte(s[i+1:]))
			i += 3
		} else if s[i] == '\\' && i+1 < len(s) {
			i++
			buf = append(buf, s[i])
		} else {
			buf = append(buf, s[i])
		}
	}
	return buf
}

func isDDD(s string) bool {
	return len(s) >= 3 && s[0] >= '0' && s[0] <= '9' && s[1] >= '0' && s[1] <= '9' && s[2] >= '0' && s[2] <= '9'
}

func dddToByte(s string) byte {
	return (s[0]-'0')*100 + (s[1]-'0')*10 + (s[2] - '0')
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
