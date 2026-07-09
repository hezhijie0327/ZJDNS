package dnscrypt

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
	"zjdns/config"
	"zjdns/internal/log"

	zdnsutil "zjdns/internal/dnsutil"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"
)

// DNSHandler is the interface for processing decrypted DNS queries.
type DNSHandler interface {
	ServeDNS(req *dns.Msg, clientIP net.IP, isSecure bool, protocol string) *dns.Msg
}

// Server is a DNSCrypt v2 server that listens on UDP and TCP.
type Server struct {
	cert         *Certificate
	certTXT      []string
	handler      DNSHandler
	cfg          *config.DNSCryptSettings
	udpConns     []*net.UDPConn
	tcpListeners []net.Listener
	esVersion    CryptoConstruction
	wg           *sync.WaitGroup
	tcpConns     map[net.Conn]struct{}
	mu           sync.RWMutex
	started      bool
	ctx          context.Context
	cancel       context.CancelCauseFunc

	// ticketKey is the server-wide key for sealing/opening PQ resumption
	// tickets.  Derived from the Ed25519 signing key via SHA-256.
	ticketKey [xchachaKeySize]byte
}

var (
	errNotADayDuration = errors.New("not a day duration")
	errInvalidDayCount = errors.New("invalid day count")
)

// New creates a new DNSCrypt Server from the given configuration.
func New(cfg *config.DNSCryptSettings) (*Server, error) {
	esVersion, err := ParseESVersion(cfg.ESVersion)
	if err != nil {
		return nil, fmt.Errorf("parsing es_version: %w", err)
	}

	rc, err := buildResolverConfig(cfg, esVersion)
	if err != nil {
		return nil, fmt.Errorf("building resolver config: %w", err)
	}

	cert, err := rc.NewCert()
	if err != nil {
		return nil, fmt.Errorf("creating certificate: %w", err)
	}

	if cfg.Port == "" {
		cfg.Port = config.DefaultDNSCryptPort
	}
	ctx, cancel := context.WithCancelCause(context.Background())

	s := &Server{
		cert:     cert,
		cfg:      cfg,
		tcpConns: make(map[net.Conn]struct{}),
		wg:       &sync.WaitGroup{},
		ctx:      ctx,
		cancel:   cancel,
	}

	s.certTXT = s.buildCertTXT()
	s.esVersion = esVersion

	// Derive ticket key from the Ed25519 signing key for PQ resumption.
	if esVersion.IsPQ() {
		privateKeyBytes, _ := hexDecodeKey(cfg.PrivateKey)
		if len(privateKeyBytes) > 0 {
			h := sha256.Sum256(privateKeyBytes)
			copy(s.ticketKey[:], h[:])
		}
	}

	return s, nil
}

func buildResolverConfig(cfg *config.DNSCryptSettings, esVersion CryptoConstruction) (ResolverConfig, error) {
	rc := ResolverConfig{
		ProviderName: cfg.ProviderName,
		PublicKey:    cfg.PublicKey,
		PrivateKey:   cfg.PrivateKey,
		ResolverSk:   cfg.ResolverSk,
		ResolverPk:   cfg.ResolverPk,
		ESVersion:    esVersion,
		CertTTL:      parseCertTTL(cfg.CertTTL),
	}

	if rc.PublicKey == "" || rc.PrivateKey == "" {
		pub, priv, err := GenerateEd25519Keypair()
		if err != nil {
			return rc, fmt.Errorf("generating ed25519 keypair: %w", err)
		}
		rc.PublicKey = hexEncodeKey(pub)
		rc.PrivateKey = hexEncodeKey(priv)
		log.Warnf("DNSCRYPT: Ed25519 keypair auto-generated — save these keys for persistence")
	}

	if esVersion.IsPQ() {
		if rc.ResolverPk == "" || rc.ResolverSk == "" {
			pk, sk, err := pqGenKeyPair()
			if err != nil {
				return rc, fmt.Errorf("generating X-Wing keypair: %w", err)
			}
			rc.ResolverPk = hexEncodeKey(pk)
			rc.ResolverSk = hexEncodeKey(sk)
		}
	} else if rc.ResolverSk == "" || rc.ResolverPk == "" {
		sk, pk := generateRandomKeyPair()
		rc.ResolverSk = hexEncodeKey(sk[:])
		rc.ResolverPk = hexEncodeKey(pk[:])
	}

	return rc, nil
}

// parseCertTTL parses a TTL duration string into a time.Duration.  An empty
// string returns the default (365 days).  Supported units: h (hour), d (day),
// standard Go duration suffixes (s, m, h).
func parseCertTTL(s string) time.Duration {
	if s == "" {
		return config.DefaultDNSCryptCertTTL
	}
	// Accept "d" (day) suffix which Go's time.ParseDuration doesn't support.
	if d, err := parseDays(s); err == nil {
		return d
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		log.Warnf("DNSCRYPT: invalid cert_ttl %q, using default %s", s, config.DefaultDNSCryptCertTTL)
		return config.DefaultDNSCryptCertTTL
	}

	return d
}

// parseDays parses a duration string ending with "d" (e.g. "30d", "365d").
func parseDays(s string) (time.Duration, error) {
	if !strings.HasSuffix(s, "d") {
		return 0, errNotADayDuration
	}
	n, err := strconv.Atoi(s[:len(s)-1])
	if err != nil || n <= 0 {
		return 0, errInvalidDayCount
	}
	return time.Duration(n) * 24 * time.Hour, nil
}

// Start begins listening for DNSCrypt queries on UDP and TCP.
func (s *Server) Start(handler DNSHandler) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.started {
		return ErrServerAlreadyStarted
	}

	s.handler = handler
	s.started = true

	udpAddrs, err := zdnsutil.ResolveBindAddrs("udp", s.cfg.Port)
	if err != nil {
		return fmt.Errorf("resolving UDP bind addresses: %w", err)
	}
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
		log.Infof("DNSCRYPT: Listening on UDP %s", conn.LocalAddr())
	}

	tcpAddrs, err := zdnsutil.ResolveBindAddrs("tcp", s.cfg.Port)
	if err != nil {
		for _, c := range s.udpConns {
			_ = c.Close()
		}
		return fmt.Errorf("resolving TCP bind addresses: %w", err)
	}
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
		log.Infof("DNSCRYPT: Listening on TCP %s", listener.Addr())
	}

	log.Infof("DNSCRYPT: Provider: %s", s.cfg.ProviderName)

	return nil
}

// Shutdown gracefully stops the DNSCrypt server.
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	if !s.started {
		s.mu.Unlock()
		return ErrServerNotStarted
	}
	s.started = false

	for _, c := range s.udpConns {
		_ = c.Close()
	}
	for _, l := range s.tcpListeners {
		_ = l.Close()
	}
	for conn := range s.tcpConns {
		_ = conn.SetReadDeadline(time.Unix(1, 0))
	}
	// Snapshot the WaitGroup for in-flight handlers and install a
	// fresh one for a potential future Start() call. Per-packet
	// and per-connection goroutines Add/Done on the WaitGroup that
	// was current when serveUDP/serveTCP spawned them.
	prevWg := s.wg
	s.wg = &sync.WaitGroup{}
	s.mu.Unlock()

	s.cancel(errors.New("dnscrypt server shutdown"))

	done := make(chan struct{})
	go func() {
		prevWg.Wait()
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

func (s *Server) buildCertTXT() []string {
	certBytes, _ := s.cert.MarshalBinary()
	// Escape only backslash bytes (0x5C → "\\") to prevent miekg/dns's
	// pack.String from interpreting raw cert bytes as \DDD escape sequences.
	// The library's unpack.String reverses this: non-printable bytes (including
	// 0x5C) become \DDD/\\ escapes, and the client's PackTXTRT reverses again.
	escaped := escapeBackslash(certBytes)
	const maxChunk = 255
	var chunks []string
	for i := 0; i < len(escaped); i += maxChunk {
		end := i + maxChunk
		if end > len(escaped) {
			end = len(escaped)
		}
		chunks = append(chunks, string(escaped[i:end]))
	}
	return chunks
}

// escapeBackslash replaces each 0x5C byte with "\\" so that miekg/dns
// pack.String's escape handling won't misinterpret raw cert bytes.
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

func (s *Server) encrypt(m *dns.Msg, q *encryptedQuery, isUDP bool) (encrypted []byte, err error) {
	r := &encryptedResponse{
		esVersion: q.esVersion,
		nonce:     q.nonce,
	}
	err = m.Pack()
	if err != nil {
		return nil, fmt.Errorf("packing dns message: %w", err)
	}
	packet := m.Data

	if q.esVersion.IsPQ() {
		return s.encryptPQ(packet, q, r, isUDP)
	}

	sharedKey, err := computeSharedKey(q.esVersion, &s.cert.ResolverSk, &q.clientPk)
	if err != nil {
		return nil, fmt.Errorf("computing shared key: %w", err)
	}
	return r.encrypt(packet, sharedKey, isUDP)
}

// encryptPQ encrypts a DNS response for a PQ query.  For initial queries it
// issues a resumption ticket in the response control block.
func (s *Server) encryptPQ(packet []byte, q *encryptedQuery, r *encryptedResponse, isUDP bool) ([]byte, error) {
	var sharedKey [SharedKeySize]byte

	if len(q.pqCiphertext) > 0 {
		// Initial query: decapsulate X-Wing to get shared secret, derive key.
		kemSS := pqDecapsulate(q.pqCiphertext, s.cert.PqPrivateKey)
		sharedKey = pqDeriveSharedKey(kemSS, q.clientMagic, s.cert.PqCertContext, q.pqCiphertext)

		// Issue a resumption ticket.
		resumeSecret := pqResumeSecret(sharedKey, q.clientMagic, q.nonce[:NonceSize/2])
		expiry := time.Now().Add(config.DefaultDNSCryptPQTicketLifetime * time.Second)
		plaintext := encodeTicketPlaintext(q.clientMagic, resumeSecret, expiry)
		var nonce [xchachaNonceSize]byte
		if _, randErr := rand.Read(nonce[:]); randErr != nil {
			return nil, fmt.Errorf("generating ticket nonce: %w", randErr)
		}
		sealed := pqSealTicket(&s.ticketKey, &nonce, plaintext)
		r.pqControl = pqBuildControlBlock(sealed, config.DefaultDNSCryptPQTicketLifetime)
	} else {
		// Resumed query: use the shared key derived during decrypt.
		sharedKey = q.sharedKey
	}

	return r.encrypt(packet, sharedKey, isUDP)
}

func (s *Server) decrypt(b []byte) (msg *dns.Msg, query *encryptedQuery, err error) {
	query = &encryptedQuery{
		esVersion:   s.esVersion,
		clientMagic: s.cert.ClientMagic,
	}

	// PQ resumed query: PQResumeMagic, ticket, nonce/2, encrypted.
	if s.esVersion.IsPQ() && len(b) >= PQResumeMagicLen && bytes.Equal(b[:PQResumeMagicLen], PQResumeMagic[:]) {
		return s.decryptPQResumed(b)
	}

	var decrypted []byte
	if s.esVersion.IsPQ() {
		query.pqCertContext = s.cert.PqCertContext
		var resolverSk [KeySize]byte
		copy(resolverSk[:], s.cert.PqPrivateKey)
		decrypted, err = query.decrypt(b, resolverSk)
	} else {
		decrypted, err = query.decrypt(b, s.cert.ResolverSk)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("decrypting query: %w", err)
	}
	msg = &dns.Msg{}
	msg.Data = decrypted
	err = msg.Unpack()
	if err != nil {
		return nil, nil, fmt.Errorf("unpacking dns message: %w", err)
	}
	return msg, query, nil
}

// decryptPQResumed handles a resumed PQ query: opens the ticket, derives the
// per-query shared key, and decrypts the DNS payload.
func (s *Server) decryptPQResumed(b []byte) (msg *dns.Msg, query *encryptedQuery, err error) {
	ticket, nonceHalf, payloadOff, err := parsePQResumedHeader(b)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing PQ resumed query: %w", err)
	}

	// Open the sealed ticket to recover the resume secret.
	ticketPlain, err := pqOpenTicket(&s.ticketKey, ticket)
	if err != nil {
		return nil, nil, fmt.Errorf("opening PQ ticket: %w", err)
	}
	clientMagic, resumeSecret, expiry, err := decodeTicketPlaintext(ticketPlain)
	if err != nil {
		return nil, nil, fmt.Errorf("decoding PQ ticket: %w", err)
	}
	if !time.Now().Before(expiry) {
		return nil, nil, ErrPQTicketExpired
	}
	// Validate that the ticket was issued for this certificate.
	if clientMagic != s.cert.ClientMagic {
		return nil, nil, ErrPQInvalidTicket
	}

	// Derive the per-query shared key.
	sharedKey := pqResumedSharedKey(resumeSecret, s.cert.ClientMagic, nonceHalf, ticket)

	query = &encryptedQuery{
		esVersion:   s.esVersion,
		clientMagic: s.cert.ClientMagic,
		sharedKey:   sharedKey,
	}
	copy(query.nonce[:NonceSize/2], nonceHalf)
	query.pqTicket = ticket

	encrypted := b[payloadOff:]
	decrypted, err := query.decryptPQResumedPayload(encrypted, sharedKey)
	if err != nil {
		return nil, nil, fmt.Errorf("decrypting resumed payload: %w", err)
	}
	msg = &dns.Msg{}
	msg.Data = decrypted
	err = msg.Unpack()
	if err != nil {
		return nil, nil, fmt.Errorf("unpacking dns message: %w", err)
	}
	return msg, query, nil
}

func (s *Server) handleHandshake(b []byte) (res []byte, err error) {
	m := &dns.Msg{}
	m.Data = b
	err = m.Unpack()
	if err != nil {
		return nil, fmt.Errorf("unpacking handshake message: %w", err)
	}

	if len(m.Question) != 1 || m.Response {
		return nil, ErrInvalidQuery
	}

	q := m.Question[0]
	providerName := dnsutil.Fqdn(s.cfg.ProviderName)

	qName := dnsutil.Fqdn(q.Header().Name)
	if dns.RRToType(q) != dns.TypeTXT || qName != providerName {
		return nil, ErrInvalidQuery
	}

	reply := dnsutil.SetReply(new(dns.Msg), m)
	txt := &dns.TXT{
		Hdr: dns.Header{
			Name:  q.Header().Name,
			TTL:   60,
			Class: dns.ClassINET,
		},
		TXT: rdata.TXT{
			Txt: s.certTXT,
		},
	}
	reply.Answer = append(reply.Answer, txt)
	reply.Authoritative = true
	reply.RecursionAvailable = true

	err = reply.Pack()
	if err != nil {
		return nil, fmt.Errorf("packing handshake response: %w", err)
	}
	return reply.Data, nil
}

func (s *Server) serveDNS(ctx context.Context, rw responseWriter, m *dns.Msg, protocol string) error {
	if m == nil || len(m.Question) != 1 || m.Response {
		return ErrInvalidQuery
	}
	log.Debugf("DNSCRYPT: handling query for %s from %s", m.Question[0].Header().Name, rw.RemoteAddr())

	clientIP := clientIPFromAddr(rw.RemoteAddr())
	resp := s.handler.ServeDNS(m, clientIP, true, protocol)
	if resp == nil {
		return nil
	}
	return rw.WriteMsg(ctx, resp)
}

func clientIPFromAddr(addr net.Addr) net.IP {
	switch a := addr.(type) {
	case *net.UDPAddr:
		return a.IP
	case *net.TCPAddr:
		return a.IP
	}
	return nil
}
