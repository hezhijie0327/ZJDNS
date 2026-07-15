package dnscrypt

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
	"zjdns/config"
	"zjdns/internal/log"

	zdnsutil "zjdns/internal/dnsutil"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"
	"github.com/cloudflare/circl/sign/ed25519"
)

// DNSHandler is the interface for processing decrypted DNS queries.
type DNSHandler interface {
	ServeDNS(req *dns.Msg, clientIP net.IP, isSecure bool, protocol string) *dns.Msg
}

// keyEntry holds a resolver encryption key and its signed certificate.
type keyEntry struct {
	cert      *Certificate
	certTXT   []string
	createdAt time.Time
}

// Server is a DNSCrypt v2 server that listens on UDP and TCP.
type Server struct {
	keys []keyEntry // [current, previous, ...], newest first

	handler        DNSHandler
	port           string
	providerName   string
	certificateCfg *config.DNSCryptCertificate
	udpConns       []*net.UDPConn
	tcpListeners   []net.Listener
	esVersion      CryptoConstruction
	wg             *sync.WaitGroup
	tcpConns       map[net.Conn]struct{}
	mu             sync.RWMutex
	started        bool
	ctx            context.Context
	cancel         context.CancelCauseFunc

	// signingSK is the Ed25519 provider identity key.  It stays fixed across
	// resolver-key rotations — the sdns:// stamp encodes only this key.
	signingSK ed25519.PrivateKey

	// ticketKey / ticketKeyID seal PQ resumption tickets.  They are
	// derived from the Ed25519 signing key and stay fixed across rotations
	// so that tickets survive a key rotation.
	ticketKey   [xchachaKeySize]byte
	ticketKeyID [ticketKeyIDSize]byte

	// Rotation goroutine control.
	rotateCh chan struct{} // closed when rotation goroutine should stop
}

// New creates a new DNSCrypt Server from the given configuration.
// port is the listener port, providerName is auto-derived as "2.dnscrypt-cert.<ddr.domain>".
func New(certificateCfg *config.DNSCryptCertificate, port, providerName string) (*Server, error) {
	esVersion, err := ParseESVersion(certificateCfg.ESVersion)
	if err != nil {
		return nil, fmt.Errorf("parsing es_version: %w", err)
	}

	rc, err := buildResolverConfig(certificateCfg, providerName, esVersion)
	if err != nil {
		return nil, fmt.Errorf("building resolver config: %w", err)
	}

	// Extract the Ed25519 signing key — it's the long-term provider identity.
	signingSK, err := hexDecodeKey(rc.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("decoding ed25519 private key: %w", err)
	}

	cert, err := rc.NewCert()
	if err != nil {
		return nil, fmt.Errorf("creating certificate: %w", err)
	}

	if port == "" {
		port = config.DefaultDNSCryptPort
	}
	ctx, cancel := context.WithCancelCause(context.Background())

	entry := keyEntry{
		cert:      cert,
		certTXT:   buildCertTXTForCert(cert),
		createdAt: time.Now(),
	}

	s := &Server{
		keys:           []keyEntry{entry},
		port:           port,
		providerName:   providerName,
		certificateCfg: certificateCfg,
		tcpConns:       make(map[net.Conn]struct{}),
		wg:             &sync.WaitGroup{},
		ctx:            ctx,
		cancel:         cancel,
		signingSK:      signingSK,
		esVersion:      esVersion,
		rotateCh:       make(chan struct{}),
	}

	// Derive ticket key from the Ed25519 signing key for PQ resumption.
	// Same derivation as the reference implementation (encrypted-dns-server).
	if esVersion.IsPQ() {
		input := make([]byte, 0, 25+len(signingSK))
		input = append(input, "DNSCrypt-PQ-ticket-key-v1"...)
		input = append(input, signingSK...)
		h := sha256.Sum256(input)
		copy(s.ticketKey[:], h[:])
		s.ticketKeyID = [ticketKeyIDSize]byte{0x00, 0x00, 0x00, 0x01}
	}

	log.Debugf("DNSCRYPT: generated initial resolver key (serial=%d)", cert.Serial)
	return s, nil
}

func buildResolverConfig(certificateCfg *config.DNSCryptCertificate, providerName string, esVersion CryptoConstruction) (ResolverConfig, error) {
	rc := ResolverConfig{
		ProviderName: providerName,
		PublicKey:    certificateCfg.PublicKey,
		PrivateKey:   certificateCfg.PrivateKey,
		ESVersion:    esVersion,
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

	// Resolver encryption keys are always auto-generated.  They are short-term
	// keys rotated every 24h (§7.2); config values would be overwritten on the
	// first rotation.
	if esVersion.IsPQ() {
		pk, sk, err := pqGenKeyPair()
		if err != nil {
			return rc, fmt.Errorf("generating X-Wing keypair: %w", err)
		}
		rc.ResolverPk = hexEncodeKey(pk)
		rc.ResolverSk = hexEncodeKey(sk)
	} else {
		sk, pk := generateRandomKeyPair()
		rc.ResolverSk = hexEncodeKey(sk[:])
		rc.ResolverPk = hexEncodeKey(pk[:])
	}

	return rc, nil
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

	udpAddrs, err := zdnsutil.ResolveBindAddrs("udp", s.port)
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

	tcpAddrs, err := zdnsutil.ResolveBindAddrs("tcp", s.port)
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

	log.Infof("DNSCRYPT: Provider: %s", s.providerName)

	// Start background key rotation goroutine.
	go s.rotationLoop()

	return nil
}

// rotationLoop periodically rotates the resolver short-term keys.
func (s *Server) rotationLoop() {
	ticker := time.NewTicker(config.DefaultDNSCryptCertificateTTL)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.rotateKeys()
		case <-s.rotateCh:
			return
		}
	}
}

// Shutdown gracefully stops the DNSCrypt server.
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	if !s.started {
		s.mu.Unlock()
		return ErrServerNotStarted
	}
	s.started = false

	close(s.rotateCh)

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

// current returns the newest key entry (the one used for encrypting responses).
func (s *Server) current() keyEntry { return s.keys[0] }

// hasClientMagic checks whether b matches any active cert's client magic.
func (s *Server) hasClientMagic(b []byte) bool {
	for _, k := range s.keys {
		if bytes.Equal(b, k.cert.ClientMagic[:]) {
			return true
		}
	}
	return false
}

// buildCertTXTForCert serialises a single certificate into TXT chunks.
func buildCertTXTForCert(cert *Certificate) []string {
	certBytes, _ := cert.MarshalBinary()
	escaped := escapeBackslash(certBytes)
	const maxChunk = 255
	var chunks []string
	for i := 0; i < len(escaped); i += maxChunk {
		end := min(i+maxChunk, len(escaped))
		chunks = append(chunks, string(escaped[i:end]))
	}
	return chunks
}

// allCertTXT concatenates TXT chunks from all valid certificates so that
// clients receive both the current and previous certs during a rotation.
func (s *Server) allCertTXT() []string {
	var all []string
	for _, k := range s.keys {
		all = append(all, k.certTXT...)
	}
	return all
}

// rotateKeys generates a fresh resolver key pair, creates a new certificate
// signed with the same Ed25519 identity key, and prepends it to the key list.
// Entries older than key lifetime + overlap are purged.
//
// This is called periodically by the rotation goroutine to comply with the
// ≤24h short-term key rotation requirement (§7.2 / §8).
func (s *Server) rotateKeys() {
	newCert, err := s.generateNewCert()
	if err != nil {
		log.Errorf("DNSCRYPT: key rotation failed: %v", err)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	entry := keyEntry{
		cert:      newCert,
		certTXT:   buildCertTXTForCert(newCert),
		createdAt: time.Now(),
	}
	s.keys = append([]keyEntry{entry}, s.keys...)

	// Purge expired keys.
	cutoff := time.Now().Add(-(config.DefaultDNSCryptCertificateTTL + config.DefaultDNSCryptKeyOverlap))
	n := 0
	for _, k := range s.keys {
		if k.createdAt.After(cutoff) {
			s.keys[n] = k
			n++
		}
	}
	s.keys = s.keys[:n]

	log.Debugf("DNSCRYPT: rotated resolver keys (serial=%d, active=%d)", newCert.Serial, len(s.keys))
}

// generateNewCert creates a signed certificate with fresh resolver keys.
func (s *Server) generateNewCert() (*Certificate, error) {
	rc := ResolverConfig{
		ProviderName: s.providerName,
		ESVersion:    s.esVersion,
	}
	rc.PublicKey = hexEncodeKey(s.signingSK.Public().(ed25519.PublicKey))
	rc.PrivateKey = hexEncodeKey(s.signingSK)

	if s.esVersion.IsPQ() {
		pk, sk, err := pqGenKeyPair()
		if err != nil {
			return nil, fmt.Errorf("generating X-Wing keypair: %w", err)
		}
		rc.ResolverPk = hexEncodeKey(pk)
		rc.ResolverSk = hexEncodeKey(sk)
	} else {
		sk, pk := generateRandomKeyPair()
		rc.ResolverSk = hexEncodeKey(sk[:])
		rc.ResolverPk = hexEncodeKey(pk[:])
	}

	return rc.NewCert()
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
	providerName := dnsutil.Fqdn(s.providerName)

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
			Txt: s.allCertTXT(),
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
	resp := s.handler.ServeDNS(m, clientIP, false, protocol)
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
