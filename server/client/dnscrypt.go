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
	"sync"
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
	dnscryptSessionTTL = 1 * time.Hour
)

// dnscryptSession holds a cached DNSCrypt session with a persistent UDP socket.
// A single reader goroutine demuxes responses by nonce to waiting query goroutines.
//
// For classic constructions the sharedKey is pre-computed from the global client
// key pair (matching dnscrypt-proxy), not from a per-session ephemeral key.
// For XWingPQ the sharedKey is derived from a fresh X-Wing encapsulation.
type dnscryptSession struct {
	esVersion       dnscrypt.CryptoConstruction
	clientMagic     [8]byte
	sharedKey       [32]byte
	proxyPublicKey  [32]byte   // snapshot of Client.proxyPublicKey
	xwingCiphertext [1120]byte // PQ only: per-session X-Wing ciphertext
	cachedAt        time.Time

	udpConn    *net.UDPConn
	pending    map[[12]byte]chan []byte
	pendingMu  sync.Mutex
	readerOnce sync.Once
}

// queryHeaderLen returns the wire header size for this session.
func (s *dnscryptSession) queryHeaderLen() int {
	if s.esVersion == dnscrypt.XWingPQ {
		return dnscrypt.QueryHeaderLenXWing
	}
	return dnscrypt.QueryHeaderLen
}

// startReader launches the background goroutine that reads UDP responses and
// dispatches them to waiting query goroutines by nonce.  Blocks until the
// reader goroutine is ready.
func (s *dnscryptSession) startReader() {
	s.readerOnce.Do(func() {
		ready := make(chan struct{})
		go func() {
			defer func() { _ = recover() }()
			close(ready)
			buf := make([]byte, pool.SecureBufferSize)
			for {
				n, err := s.udpConn.Read(buf)
				if err != nil {
					if !isConnClosed(err) {
						log.Debugf("DNSCRYPT: reader read error: %v", err)
					}
					return
				}
				// Response: resolverMagic(8) + nonce(24) + encrypted.
				if n < 32 {
					continue
				}
				var nonceKey [12]byte
				copy(nonceKey[:], buf[8:20])

				s.pendingMu.Lock()
				ch := s.pending[nonceKey]
				delete(s.pending, nonceKey)
				s.pendingMu.Unlock()

				if ch != nil {
					resp := make([]byte, n)
					copy(resp, buf[:n])
					select {
					case ch <- resp:
					default:
					}
				}
			}
		}()
		<-ready
	})
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

	pkStr := strings.ReplaceAll(pubkeyHex, ":", "")
	providerPK, err := hex.DecodeString(pkStr)
	if err != nil {
		return nil, fmt.Errorf("DNSCRYPT: invalid dnscrypt_public_key: %w", err)
	}
	if len(providerPK) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("DNSCRYPT: dnscrypt_public_key must be %d bytes, got %d",
			ed25519.PublicKeySize, len(providerPK))
	}

	cert, err := fetchCert(ctx, certAddr, providerName, providerPK)
	if err != nil {
		return nil, fmt.Errorf("DNSCRYPT: fetch cert from %s: %w", serverAddr, err)
	}

	var sharedKey [32]byte
	var xwingCT [1120]byte
	var sessionPPK [32]byte

	if cert.ESVersion == dnscrypt.XWingPQ {
		xwingPK := cert.XWingPublicKey()
		ss, ct, err := xwing.Encapsulate(xwingPK, nil)
		if err != nil {
			return nil, fmt.Errorf("DNSCRYPT: xwing encapsulate: %w", err)
		}
		copy(xwingCT[:], ct)
		sharedKey = dnscryptXWingDeriveSharedKey(cert.ESVersion, cert.ClientMagic[:], ss, ct, cert.CertContext())
	} else {
		var serverPk [32]byte
		copy(serverPk[:], cert.ResolverPk[:32])
		c.cryptoKeyMu.RLock()
		sharedKey = computeSharedKey(cert.ESVersion, &c.proxySecretKey, &serverPk)
		copy(sessionPPK[:], c.proxyPublicKey[:])
		c.cryptoKeyMu.RUnlock()
	}

	session := &dnscryptSession{
		esVersion:       cert.ESVersion,
		clientMagic:     cert.ClientMagic,
		sharedKey:       sharedKey,
		proxyPublicKey:  sessionPPK,
		xwingCiphertext: xwingCT,
		cachedAt:        time.Now(),
		pending:         make(map[[12]byte]chan []byte),
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
// DNS TXT query using standard dns.Client.
func fetchCert(ctx context.Context, serverAddr, providerName string, providerPK ed25519.PublicKey) (*dnscrypt.Certificate, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(providerName), dns.TypeTXT)
	msg.RecursionDesired = true

	log.Debugf("DNSCRYPT: fetching cert for %s from %s", providerName, serverAddr)

	client := dns.Client{Net: "udp", UDPSize: pool.SecureBufferSize}
	resp, _, err := client.ExchangeContext(ctx, msg, serverAddr)
	if err != nil {
		return nil, fmt.Errorf("cert TXT query: %w", err)
	}
	if resp.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("cert TXT query returned %s", dns.RcodeToString[resp.Rcode])
	}

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
			continue
		}
		if !cert.VerifyDate() {
			continue
		}
		if !cert.VerifySignature(providerPK) {
			continue
		}
		return cert, nil
	}
	return nil, fmt.Errorf("no valid cert TXT record at %s", providerName)
}

func parseCertTXT(txt []string) []byte {
	raw := strings.Join(txt, "")
	if isHex(raw) {
		b, _ := hex.DecodeString(raw)
		return b
	}
	var buf []byte
	for _, s := range txt {
		buf = append(buf, unpackTxtString(s)...)
	}
	return buf
}

// exchangeDNSCryptUDP encrypts a query, sends it over UDP via a persistent
// socket, and waits for the matching response by nonce.  A background reader
// goroutine demuxes responses to the correct caller.
func (c *Client) exchangeDNSCryptUDP(ctx context.Context, msg *dns.Msg, session *dnscryptSession, serverAddr string) (*dns.Msg, error) {
	encrypted, nonce, err := encryptQuery(msg, session, session.esVersion)
	if err != nil {
		return nil, err
	}

	conn, err := c.getDNSCryptUDPConn(session, serverAddr)
	if err != nil {
		return nil, err
	}
	session.startReader()

	// Register nonce → response channel.
	var nonceKey [12]byte
	copy(nonceKey[:], nonce[:12])
	ch := make(chan []byte, 1)
	session.pendingMu.Lock()
	session.pending[nonceKey] = ch
	session.pendingMu.Unlock()

	defer func() {
		session.pendingMu.Lock()
		delete(session.pending, nonceKey)
		session.pendingMu.Unlock()
	}()

	_ = conn.SetWriteDeadline(time.Now().Add(config.DefaultDNSQueryTimeout))
	if _, err := conn.Write(encrypted); err != nil {
		return nil, fmt.Errorf("write: %w", err)
	}

	select {
	case resp := <-ch:
		return decryptResponse(resp, &session.sharedKey, session.esVersion)
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

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

// computeSharedKey pre-computes the shared key from the global client secret key
// and the server's public key.  Matches dnscrypt-proxy's design.
func computeSharedKey(esVersion dnscrypt.CryptoConstruction, secretKey, serverPk *[32]byte) [32]byte {
	sk, err := dnscrypt.ComputeSharedKey(esVersion, secretKey, serverPk)
	if err != nil {
		log.Warnf("DNSCRYPT: weak public key for %s", esVersion)
		if _, randErr := rand.Read(sk[:]); randErr != nil {
			panic("dnscrypt: random fallback: " + randErr.Error())
		}
	}
	return sk
}

func encryptQuery(msg *dns.Msg, session *dnscryptSession, esVersion dnscrypt.CryptoConstruction) ([]byte, *[24]byte, error) {
	packet, err := msg.Pack()
	if err != nil {
		return nil, nil, fmt.Errorf("pack: %w", err)
	}

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
		encrypted = append(encrypted, session.proxyPublicKey[:]...)
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

// isConnClosed reports whether err is due to a closed network connection.
func isConnClosed(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "use of closed network connection")
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
