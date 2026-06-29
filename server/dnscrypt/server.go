package dnscrypt

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cloudflare/circl/kem/xwing"
	"github.com/miekg/dns"

	"zjdns/config"
	"zjdns/internal/dnsutil"
	"zjdns/internal/log"
	"zjdns/internal/perip"
	"zjdns/internal/pool"
)

// DNSHandler is the interface for processing incoming DNS queries.
type DNSHandler interface {
	ServeDNS(req *dns.Msg, clientIP net.IP, isSecure bool, protocol string) *dns.Msg
}

// Server manages a DNSCrypt v2 protocol listener and its lifecycle.
type Server struct {
	handler      DNSHandler
	cfg          config.DNSCryptSettings
	cert         *Certificate
	certBytes    []byte
	providerName string

	// xwingSK is the X-Wing private key for XWingPQ constructions.
	// It is nil for classic (non-PQ) certificates.
	xwingSK *xwing.PrivateKey

	udpConn     *net.UDPConn
	tcpListener net.Listener
	udpSem      chan struct{}
	tcpLimiter  *perip.Limiter // per-IP TCP connection limit
	udpLimiter  *perip.Limiter // per-IP UDP concurrent packet limit

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	closed atomic.Bool
}

// New creates a new DNSCrypt server with the given handler and configuration.
func New(handler DNSHandler, dnsCfg config.DNSCryptSettings) (*Server, error) {
	if dnsCfg.Port == "" {
		return nil, errors.New("dnscrypt: port is required")
	}
	if dnsCfg.ProviderName == "" {
		return nil, errors.New("dnscrypt: provider_name is required")
	}
	if dnsCfg.PrivateKey == "" {
		return nil, errors.New("dnscrypt: private_key is required")
	}

	keyStr := strings.ReplaceAll(dnsCfg.PrivateKey, ":", "")
	providerKey, err := hex.DecodeString(keyStr)
	if err != nil {
		return nil, fmt.Errorf("dnscrypt: decode private key: %w", err)
	}
	if len(providerKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("dnscrypt: private key length %d, expected %d",
			len(providerKey), ed25519.PrivateKeySize)
	}

	providerName := config.NormalizeDNSCryptProviderName(dnsCfg.ProviderName)
	if len(providerName) > 253 {
		return nil, fmt.Errorf("dnscrypt: provider_name too long (%d bytes, max 253)", len(providerName))
	}

	certTTL := time.Duration(dnsCfg.CertTTL) * time.Second
	if certTTL <= 0 {
		certTTL = config.DefaultDNSCryptCertTTL
	}

	esVersion := XSalsa20Poly1305
	switch strings.ToLower(dnsCfg.ESVersion) {
	case "xchacha20", "xchacha20poly1305":
		esVersion = XChacha20Poly1305
	case "xwing":
		esVersion = XWingPQ
	}

	cert, err := GenerateCertificate(ed25519.PrivateKey(providerKey), esVersion, certTTL)
	if err != nil {
		return nil, fmt.Errorf("dnscrypt: generate certificate: %w", err)
	}

	log.Infof("DNSCRYPT: Certificate generated — provider=%s serial=%d es_version=%s valid=%s→%s",
		providerName,
		cert.Serial,
		cert.ESVersion.String(),
		time.Unix(int64(cert.NotBefore), 0).UTC().Format(time.RFC3339),
		time.Unix(int64(cert.NotAfter), 0).UTC().Format(time.RFC3339),
	)
	log.Infof("DNSCRYPT: PublicKey=%s", hex.EncodeToString(ed25519.PrivateKey(providerKey).Public().(ed25519.PublicKey)))

	ctx, cancel := context.WithCancel(context.Background())

	s := &Server{
		handler:      handler,
		cfg:          dnsCfg,
		cert:         cert,
		certBytes:    cert.CertBytes(),
		providerName: providerName,
		udpSem:       make(chan struct{}, config.DefaultMinConcurrencyLimit),
		tcpLimiter:   &perip.Limiter{},
		udpLimiter:   &perip.Limiter{},
		ctx:          ctx,
		cancel:       cancel,
	}

	if esVersion == XWingPQ {
		xwingSK, xwingPK := xwing.DeriveKeyPair(cert.XWingSeed[:])
		_ = xwingPK // public key is in the certificate already
		s.xwingSK = xwingSK
		log.Infof("DNSCRYPT: X-Wing post-quantum key exchange enabled")
	}

	return s, nil
}

// StartUDP launches the DNSCrypt UDP listener.  Blocks until ctx is cancelled
// or the listener fails.
func (s *Server) StartUDP(ctx context.Context) error {
	conn, err := net.ListenPacket("udp", ":"+s.cfg.Port)
	if err != nil {
		return fmt.Errorf("dnscrypt: UDP listen: %w", err)
	}
	s.udpConn = conn.(*net.UDPConn)

	log.Infof("DNSCRYPT: UDP server started on port %s", s.cfg.Port)

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer dnsutil.HandlePanic("DNSCrypt UDP start")
		s.serveUDP(ctx)
	}()

	<-ctx.Done()
	return nil
}

// StartTCP launches the DNSCrypt TCP listener.  Blocks until ctx is cancelled
// or the listener fails.
func (s *Server) StartTCP(ctx context.Context) error {
	listener, err := net.Listen("tcp", ":"+s.cfg.Port)
	if err != nil {
		return fmt.Errorf("dnscrypt: TCP listen: %w", err)
	}
	s.tcpListener = listener

	log.Infof("DNSCRYPT: TCP server started on port %s", s.cfg.Port)

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer dnsutil.HandlePanic("DNSCrypt TCP start")
		s.serveTCP(ctx)
	}()

	<-ctx.Done()
	return nil
}

// serveUDP reads and processes UDP packets with per-IP concurrency limiting.
func (s *Server) serveUDP(ctx context.Context) {
	defer dnsutil.HandlePanic("DNSCrypt UDP server")
	buf := pool.DefaultBufferPool.Get()
	defer pool.DefaultBufferPool.Put(buf)

	// The perip sweeper is started in serveTCP. If DNSCrypt is UDP-only
	// there would be no sweeper, so start a dedicated one here.
	go func() {
		defer dnsutil.HandlePanic("DNSCrypt perip sweep (UDP)")
		ticker := time.NewTicker(config.DefaultSweepInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				s.udpLimiter.Sweep()
			case <-ctx.Done():
				return
			}
		}
	}()

	const maxConcurrentPerIP = config.DefaultMinConcurrencyLimit

	for {
		if s.closed.Load() {
			return
		}
		_ = s.udpConn.SetReadDeadline(time.Now().Add(config.DefaultDNSCryptUDPReadTimeout))
		n, addr, err := s.udpConn.ReadFromUDP(buf)
		if err != nil {
			if s.closed.Load() || errors.Is(err, net.ErrClosed) {
				return
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			log.Debugf("DNSCRYPT: UDP read error: %v", err)
			continue
		}

		// Per-IP UDP concurrency limit.
		cleanup := s.udpLimiter.Allow(addr.IP.String(), maxConcurrentPerIP)
		if cleanup == nil {
			continue
		}

		// Copy packet from shared buffer, then dispatch.
		packet := make([]byte, n)
		copy(packet, buf[:n])

		s.wg.Add(1)
		go func() {
			defer cleanup()
			s.udpSem <- struct{}{}
			defer func() { <-s.udpSem }()
			defer s.wg.Done()
			defer dnsutil.HandlePanic("DNSCrypt UDP handler")
			s.handleUDPPacket(ctx, packet, addr)
		}()
	}
}

// handleUDPPacket dispatches a UDP packet. DNSCrypt encrypted queries
// (starting with the client magic) are processed as encrypted DNS.
// Plain DNS TXT queries for the provider name are answered with the
// certificate (standard DNSCrypt cert retrieval). Everything else is
// silently dropped.
func (s *Server) handleUDPPacket(ctx context.Context, packet []byte, addr *net.UDPAddr) {
	if len(packet) >= clientMagicSize && bytes.Equal(packet[:clientMagicSize], s.cert.ClientMagic[:]) {
		log.Debugf("DNSCRYPT: received encrypted query from %s (%d bytes)", addr, len(packet))
		s.handleEncryptedQuery(ctx, packet, addr)
		return
	}
	// Try cert TXT query (plain DNS).
	if resp := s.serveCertTXT(packet); resp != nil {
		_, _ = s.udpConn.WriteToUDP(resp, addr)
		return
	}
	// Not an encrypted query or cert TXT — drop silently.
	if len(packet) > 0 {
		log.Debugf("DNSCRYPT: dropped non-DNSCrypt packet from %s (%d bytes, first byte 0x%02x)", addr, len(packet), packet[0])
	}
}

// handleEncryptedQuery decrypts and processes a DNSCrypt encrypted query.
func (s *Server) handleEncryptedQuery(ctx context.Context, packet []byte, addr *net.UDPAddr) {
	query, xq, encrypted, err := parseQuery(packet, s.cert)
	if err != nil {
		log.Debugf("DNSCRYPT: parse query from %s: %v", addr, err)
		return
	}

	var decrypted []byte
	var sharedKey [SharedKeySize]byte
	var nonce [nonceSize]byte

	if s.cert.ESVersion == XWingPQ && xq != nil && s.xwingSK != nil {
		copy(nonce[:], xq.Nonce[:])
		decrypted, sharedKey, err = xq.decrypt(encrypted, s.cert, s.xwingSK)
	} else {
		copy(nonce[:], query.Nonce[:])
		decrypted, sharedKey, err = query.decrypt(encrypted, s.cert)
	}
	if err != nil {
		log.Debugf("DNSCRYPT: decrypt query from %s: %v", addr, err)
		return
	}

	req := pool.DefaultMessagePool.Get()
	defer pool.DefaultMessagePool.Put(req)
	if err := req.Unpack(decrypted); err != nil {
		log.Debugf("DNSCRYPT: unpack query from %s: %v", addr, err)
		return
	}

	response := s.handler.ServeDNS(req, addr.IP, true, "DNSCrypt")
	if response == nil {
		return
	}
	defer pool.DefaultMessagePool.Put(response)

	respPacket, err := response.Pack()
	if err != nil {
		log.Debugf("DNSCRYPT: pack response: %v", err)
		return
	}

	encryptedResp, err := encryptResponse(s.cert.ESVersion, respPacket, &sharedKey, &nonce, nil)
	if err != nil {
		log.Debugf("DNSCRYPT: encrypt response: %v", err)
		return
	}

	_, _ = s.udpConn.WriteToUDP(encryptedResp, addr)
}

// serveTCP accepts and processes TCP connections with per-IP limiting.
func (s *Server) serveTCP(ctx context.Context) {
	defer dnsutil.HandlePanic("DNSCrypt TCP server")

	// Periodic sweep of per-IP limiters.
	go func() {
		defer dnsutil.HandlePanic("DNSCrypt perip sweep")
		ticker := time.NewTicker(config.DefaultSweepInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				s.tcpLimiter.Sweep()
				s.udpLimiter.Sweep()
			case <-ctx.Done():
				return
			}
		}
	}()

	const maxConnsPerIP = config.DefaultMaxConnsPerIP
	for {
		if s.closed.Load() {
			return
		}
		conn, err := s.tcpListener.Accept()
		if err != nil {
			if s.closed.Load() {
				return
			}
			time.Sleep(config.DefaultAcceptRetryDelay)
			continue
		}

		var cleanup func()
		if host, _, err := net.SplitHostPort(conn.RemoteAddr().String()); err == nil {
			cleanup = s.tcpLimiter.Allow(host, maxConnsPerIP)
			if cleanup == nil {
				_ = conn.Close()
				log.Debugf("DNSCRYPT: per-IP connection limit reached for %s, rejecting", host)
				continue
			}
		}

		s.wg.Add(1)
		go func() {
			if cleanup != nil {
				defer cleanup()
			}
			defer s.wg.Done()
			defer func() { _ = conn.Close() }()
			defer dnsutil.HandlePanic("DNSCrypt TCP handler")
			s.handleTCPConn(ctx, conn)
		}()
	}
}

func (s *Server) handleTCPConn(ctx context.Context, conn net.Conn) {
	firstRead := true
	for {
		if s.closed.Load() {
			return
		}
		timeout := config.DefaultDNSCryptTCPReadTimeout
		if !firstRead {
			timeout = config.DefaultDNSCryptTCPIdleTimeout
		}
		firstRead = false
		_ = conn.SetReadDeadline(time.Now().Add(timeout))

		var length uint16
		if err := binary.Read(conn, binary.BigEndian, &length); err != nil {
			return
		}
		if length == 0 || int(length) > pool.SecureBufferSize {
			return
		}

		packet := make([]byte, length)
		if _, err := io.ReadFull(conn, packet); err != nil {
			return
		}

		// TCP also supports encrypted DNSCrypt queries.
		if len(packet) < clientMagicSize || !bytes.Equal(packet[:clientMagicSize], s.cert.ClientMagic[:]) {
			// Try cert TXT query (plain DNS).
			if resp := s.serveCertTXT(packet); resp != nil {
				_ = conn.SetWriteDeadline(time.Now().Add(config.DefaultDNSQueryTimeout))
				if err := binary.Write(conn, binary.BigEndian, uint16(len(resp))); err != nil {
					return
				}
				if _, err := conn.Write(resp); err != nil {
					return
				}
			}
			continue // not encrypted — drop silently
		}

		query, xq, encrypted, err := parseQuery(packet, s.cert)
		if err != nil {
			continue
		}

		var decrypted []byte
		var sharedKey [SharedKeySize]byte
		var nonce [nonceSize]byte

		if s.cert.ESVersion == XWingPQ && xq != nil && s.xwingSK != nil {
			copy(nonce[:], xq.Nonce[:])
			decrypted, sharedKey, err = xq.decrypt(encrypted, s.cert, s.xwingSK)
		} else {
			copy(nonce[:], query.Nonce[:])
			decrypted, sharedKey, err = query.decrypt(encrypted, s.cert)
		}
		if err != nil {
			continue
		}

		req := pool.DefaultMessagePool.Get()
		if err := req.Unpack(decrypted); err != nil {
			pool.DefaultMessagePool.Put(req)
			continue
		}

		var clientIP net.IP
		if tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
			clientIP = tcpAddr.IP
		}
		response := s.handler.ServeDNS(req, clientIP, true, "DNSCrypt")
		pool.DefaultMessagePool.Put(req)
		if response == nil {
			continue
		}

		respPacket, err := response.Pack()
		pool.DefaultMessagePool.Put(response)
		if err != nil {
			continue
		}

		encryptedResp, err := encryptResponse(s.cert.ESVersion, respPacket, &sharedKey, &nonce, nil)
		if err != nil {
			continue
		}

		// TCP: prepend 2-byte length prefix.
		_ = conn.SetWriteDeadline(time.Now().Add(config.DefaultDNSQueryTimeout))
		if err := binary.Write(conn, binary.BigEndian, uint16(len(encryptedResp))); err != nil {
			return
		}
		if _, err := conn.Write(encryptedResp); err != nil {
			return
		}
	}
}

// serveCertTXT answers a plain DNS TXT query for the provider's certificate.
// Returns the packed DNS response, or nil if the packet is not a cert TXT query.
// The certificate is stored as raw binary (like OpenDNS/Quad9), split into
// 255-byte chunks per the DNS TXT character-string limit.
func (s *Server) serveCertTXT(packet []byte) []byte {
	req := pool.DefaultMessagePool.Get()
	defer pool.DefaultMessagePool.Put(req)
	if err := req.Unpack(packet); err != nil {
		return nil
	}
	if len(req.Question) != 1 {
		return nil
	}
	q := req.Question[0]
	if q.Qtype != dns.TypeTXT || q.Qclass != dns.ClassINET {
		return nil
	}
	if !strings.EqualFold(q.Name, dns.Fqdn(s.providerName)) {
		return nil
	}

	log.Debugf("DNSCRYPT: serving cert TXT for %s (%d bytes)", s.providerName, len(s.certBytes))

	// Split raw cert bytes into 255-byte chunks (DNS TXT character-string
	// limit).  miekg stores TXT strings in presentation format with \DDD
	// escape sequences, so we must escape non-printable bytes before Pack
	// converts them back to wire format.
	const txtChunkSize = 255
	var chunks []string
	for i := 0; i < len(s.certBytes); i += txtChunkSize {
		end := i + txtChunkSize
		if end > len(s.certBytes) {
			end = len(s.certBytes)
		}
		chunks = append(chunks, escapeTXT(s.certBytes[i:end]))
	}

	resp := pool.DefaultMessagePool.Get()
	resp.SetReply(req)
	resp.RecursionAvailable = true
	resp.Answer = append(resp.Answer, &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   q.Name,
			Rrtype: dns.TypeTXT,
			Class:  dns.ClassINET,
			Ttl:    config.DefaultTTL,
		},
		Txt: chunks,
	})

	packed, err := resp.Pack()
	pool.DefaultMessagePool.Put(resp)
	if err != nil {
		return nil
	}
	return packed
}

// Shutdown gracefully stops both listeners.
func (s *Server) Shutdown(ctx context.Context) error {
	log.Infof("DNSCRYPT: Shutting down server")
	s.closed.Store(true)
	s.cancel()

	if s.tcpListener != nil {
		_ = s.tcpListener.Close()
	}
	if s.udpConn != nil {
		_ = s.udpConn.Close()
	}

	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
		return ctx.Err()
	}
	return nil
}

// Config returns the DNSCrypt server configuration.
func (s *Server) Config() config.DNSCryptSettings {
	return s.cfg
}

// ProviderName returns the normalized provider name (e.g. 2.dnscrypt-cert.zjdns).
func (s *Server) ProviderName() string {
	return s.providerName
}

// escapeTXT converts raw bytes to a miekg/dns TXT presentation-format string.
// Non-printable bytes and backslash are escaped as \DDD so that miekg's Pack
// correctly writes them to the wire as single bytes.
func escapeTXT(b []byte) string {
	buf := make([]byte, 0, len(b))
	for _, c := range b {
		switch {
		case c == '\\':
			buf = append(buf, '\\', '\\')
		case c < 0x20 || c > 0x7e:
			buf = append(buf, '\\', '0'+c/100, '0'+(c/10)%10, '0'+c%10)
		default:
			buf = append(buf, c)
		}
	}
	return string(buf)
}

// CertBytes returns the raw certificate bytes suitable for a DNS TXT record.
func (s *Server) CertBytes() []byte {
	return s.certBytes
}
