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
	"zjdns/dnscert"
	"zjdns/edns"
	dnscryptcrypto "zjdns/internal/dnscryptcrypto"
	"zjdns/internal/log"
	"zjdns/internal/lrumap"
	"zjdns/internal/pool"

	zdnsutil "zjdns/internal/dnsutil"

	"codeberg.org/miekg/dns"
	"github.com/cloudflare/circl/sign/ed25519"
)

// Server is a DNSCrypt v2 server that listens on UDP and TCP.
type Server struct {
	keys []keyEntry // [current, previous, ...], newest first

	handler        edns.DNSHandler
	port           string
	providerName   string
	certificateCfg *config.DNSCryptCertificate
	udpConns       []*net.UDPConn
	tcpListeners   []net.Listener
	wg             *sync.WaitGroup
	tcpConns       map[net.Conn]struct{}
	mu             sync.RWMutex
	started        bool
	ctx            context.Context
	cancel         context.CancelCauseFunc

	// signingSK is the Ed25519 provider identity key.  It stays fixed across
	// resolver-key rotations — the sdns:// stamp encodes only this key.
	signingSK ed25519.PrivateKey

	// ticketKey / ticketKeyID seal PQ resumption tickets.  They are derived
	// from the Ed25519 signing key and NEVER rotate (matching the reference
	// encrypted-dns-server), so a client's ticket stays valid for its whole
	// lifetime regardless of cert-window renewals.
	ticketKey   [dnscryptcrypto.XchachaKeySize]byte
	ticketKeyID [dnscryptcrypto.TicketKeyIDSize]byte

	// Rotation goroutine control.
	rotateCh chan struct{} // closed when rotation goroutine should stop

	// workerCap limits concurrent handler goroutines to prevent unbounded
	// goroutine creation under high load.  UDP per-packet + TCP per-connection
	// handlers share the cap.
	workerCap chan struct{}

	// store persists the identity + cert windows across restarts; nil disables
	// persistence.
	store StateStore

	// sharedKeyCache avoids recomputing X25519 per query for classical
	// DNSCrypt (RFC §8).  Cleared on key rotation.
	sharedKeyCache *lrumap.Map[[32]byte, [32]byte]

	// replayCache bounds repeated identical encrypted queries per
	// (client magic, client nonce half, client key prefix): UDP
	// retransmits are legitimate, a flood repeating one captured datagram
	// is not — occurrences beyond DefaultDNSCryptReplayAllow inside the
	// window are dropped.
	replayCache *lrumap.Map[string, replayEntry]
}

// New creates a new DNSCrypt Server from the given configuration.
// port is the listener port; providerName is auto-derived as
// "2.dnscrypt-cert.<ddr.domain>" when empty; store persists the cert
// windows across restarts (nil disables persistence).
func New(certificateCfg *config.DNSCryptCertificate, port, providerName string, store StateStore) (*Server, error) {
	// ── Signing identity ───────────────────────────────────────────────────
	// Explicit keys are required — like TLS requires a certificate.  The
	// Ed25519 identity is pinned in config so the sdns:// stamp stays valid
	// across restarts.  Generate one with `zjdns --generate dnscrypt`.
	if certificateCfg.PublicKey == "" || certificateCfg.PrivateKey == "" {
		return nil, errors.New("dnscrypt: certificate.dnscrypt.public_key and private_key are required — generate them with `zjdns --generate dnscrypt`")
	}
	skBytes, err := dnscryptcrypto.HexDecodeKey(certificateCfg.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("decoding ed25519 private key: %w", err)
	}
	// circl ed25519.Sign panics on wrong-length keys and Public() silently
	// truncates short ones — validate before constructing (H6).
	if len(skBytes) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("dnscrypt: ed25519 private key must be %d bytes, got %d", ed25519.PrivateKeySize, len(skBytes))
	}
	signingSK := ed25519.PrivateKey(skBytes)
	signingPK, ok := signingSK.Public().(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("dnscrypt: signing key is not Ed25519")
	}
	rc := dnscert.ResolverConfig{
		ProviderName: providerName,
		PublicKey:    dnscryptcrypto.HexEncodeKey(signingPK),
		PrivateKey:   certificateCfg.PrivateKey,
	}

	// ── Restore or create cert windows ─────────────────────────────────────
	// Persisted windows are only reused while the identity matches: a config
	// key change means the old windows are re-signed under a new identity,
	// so a fresh window is minted instead.
	var persistedWindows []windowRecord
	if store != nil {
		identity, windowsBlob, err := store.LoadDNSCryptState()
		if err != nil {
			log.Warnf("DNSCRYPT: state load failed (starting fresh): %v", err)
		} else if len(identity) == 96 {
			if !bytes.Equal(signingPK, identity[64:96]) {
				log.Warnf("DNSCRYPT: config public_key changed, dropping old persisted state")
			} else {
				// _ = error: corrupt persisted windows fall back to a fresh
				// generation below (windowsFromState returns nil) — logged,
				// not fatal (R3-L21).
				persistedWindows, err = decodeWindows(windowsBlob)
				if err != nil {
					log.Warnf("DNSCRYPT: corrupt persisted windows, starting fresh: %v", err)
				} // else: window count is logged once below (restored N from snapshot)
			}
		}
	}

	var entries []keyEntry
	if windows := windowsFromState(persistedWindows); len(windows) > 0 {
		restored, err := windowsToKeyEntries(&rc, windows)
		if err != nil {
			log.Warnf("DNSCRYPT: restoring windows failed (starting fresh): %v", err)
		} else {
			entries = restored
			log.Infof("DNSCRYPT: restored %d cert window(s) from snapshot", len(restored))
		}
	}
	if len(entries) == 0 {
		// Mint a fresh window from a random seed; the seed chain extends it
		// forward on each renewal.  Generate the resolver keys explicitly:
		// NewCertPair derives PQ keys from rc.ResolverSk, so an empty rc
		// would silently produce a PQ cert derived from nothing (classical
		// keys random, PQ keys unrelated).
		sk, pk, err := dnscryptcrypto.GenerateRandomKeyPair()
		if err != nil {
			return nil, fmt.Errorf("generating resolver keys: %w", err)
		}
		rc.ResolverSk = dnscryptcrypto.HexEncodeKey(sk[:])
		rc.ResolverPk = dnscryptcrypto.HexEncodeKey(pk[:])
		now := dnscryptcrypto.NowUnix32()
		pair, err := rc.NewCertPair(now, now+uint32(config.DefaultDNSCryptCertificateTTL/time.Second))
		if err != nil {
			return nil, fmt.Errorf("creating certificate pair: %w", err)
		}
		entries = []keyEntry{newKeyEntry(pair)}
		log.Debugf("DNSCRYPT: generated initial key pair (serial=%d)", pair.Classical.Serial)
	}

	if port == "" {
		port = config.DefaultDNSCryptPort
	}
	ctx, cancel := context.WithCancelCause(context.Background())

	s := &Server{
		keys:           entries,
		port:           port,
		providerName:   providerName,
		certificateCfg: certificateCfg,
		tcpConns:       make(map[net.Conn]struct{}),
		wg:             &sync.WaitGroup{},
		ctx:            ctx,
		cancel:         cancel,
		signingSK:      signingSK,
		rotateCh:       make(chan struct{}),
		// Shares DefaultServerGoroutineLimit with the other listeners — the
		// unified server-side concurrency cap (defaults.go).
		workerCap:      make(chan struct{}, config.DefaultServerGoroutineLimit),
		sharedKeyCache: lrumap.New[[32]byte, [32]byte](config.DefaultDNSCryptSharedKeyCacheSize),
		replayCache:    lrumap.New[string, replayEntry](config.DefaultDNSCryptReplayCacheSize),
		store:          store,
	}

	// Derive ticket key from the Ed25519 signing key for PQ resumption.
	// Same derivation as the reference implementation (encrypted-dns-server).
	{
		input := make([]byte, 0, 25+len(signingSK))
		input = append(input, "DNSCrypt-PQ-ticket-key-v1"...)
		input = append(input, signingSK...)
		h := sha256.Sum256(input)
		copy(s.ticketKey[:], h[:])
		s.ticketKeyID = [dnscryptcrypto.TicketKeyIDSize]byte{0x00, 0x00, 0x00, 0x01}
	}

	// Catch up renewals missed while the server was stopped: purge expired
	// windows and mint every window up to now+renewal from the seed chain,
	// persisting the result (ref: updater.update() at startup).
	s.updateKeys()

	return s, nil
}

// SetHandler configures the DNS handler used for resolving decrypted
// queries.  Must be called before StartBackground (shared-port mode) or
// Start (standalone mode).  In standalone mode Start sets it implicitly.
func (s *Server) SetHandler(h edns.DNSHandler) {
	s.mu.Lock()
	s.handler = h
	s.mu.Unlock()
}

// StartBackground launches the key renewal loop without creating any
// listeners.  Used in shared-port mode where the shared Manager routes
// packets to the DNSCrypt Server instead of the Server owning its own
// UDP/TCP sockets.  The caller must ensure StartBackground is called
// before any packets are routed.
func (s *Server) StartBackground() {
	s.mu.Lock()
	s.started = true
	s.mu.Unlock()
	go s.renewalLoop()
}

// HasClientMagic reports whether data begins with a recognised DNSCrypt
// client magic prefix (any active cert's classical or PQ magic, or the
// PQ resumption magic).  Used by the shared-port dispatch loop to
// classify incoming datagrams before QUIC/DTLS/DTLCP detection.
func (s *Server) HasClientMagic(data []byte) bool {
	if len(data) < dnscryptcrypto.ClientMagicSize {
		return false
	}
	return s.hasClientMagic(data[:dnscryptcrypto.ClientMagicSize]) ||
		bytes.Equal(data[:dnscryptcrypto.PQResumeMagicLen], dnscryptcrypto.PQResumeMagic[:])
}

// Start begins listening for DNSCrypt queries on UDP and TCP.
func (s *Server) Start(dnsHandler edns.DNSHandler) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.started {
		return dnscryptcrypto.ErrServerAlreadyStarted
	}

	s.handler = dnsHandler
	s.started = true

	udpAddrs, err := zdnsutil.ResolveBindAddrs("udp", s.port)
	if err != nil {
		return fmt.Errorf("resolving UDP bind addresses: %w", err)
	}
	log.Infof("DNSCRYPT: Listening on UDP %v", udpAddrs)
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
	}

	tcpAddrs, err := zdnsutil.ResolveBindAddrs("tcp", s.port)
	if err != nil {
		for _, c := range s.udpConns {
			_ = c.Close()
		}
		return fmt.Errorf("resolving TCP bind addresses: %w", err)
	}
	log.Infof("DNSCRYPT: Listening on TCP %v", tcpAddrs)
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
	}

	log.Infof("DNSCRYPT: Provider: %s", s.providerName)

	// Start background key renewal goroutine.
	go s.renewalLoop()

	return nil
}

// Shutdown gracefully stops the DNSCrypt server.
// The cancel and WaitGroup swap are performed under s.mu without
// releasing the lock, so serveUDP/serveTCP always see a consistent
// (cancelled ctx, correct wg) pair.  Any handler that reads s.wg
// after the swap sees the fresh WaitGroup and exits immediately
// because the context is already cancelled.
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	if !s.started {
		s.mu.Unlock()
		return dnscryptcrypto.ErrServerNotStarted
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
	// Cancel the context and swap the WaitGroup atomically under s.mu.
	// Handlers that read s.wg after this point see a fresh WaitGroup;
	// because the context is already cancelled, they return immediately
	// rather than joining a WaitGroup that will never be waited on.
	s.cancel(errors.New("dnscrypt server shutdown"))
	prevWg := s.wg
	s.wg = &sync.WaitGroup{}
	s.mu.Unlock()

	done := make(chan struct{})
	go func() {
		defer zdnsutil.HandlePanic("DNSCrypt shutdown wait")
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

// hasClientMagic checks whether b matches any active cert's client magic
// (checks both classical and PQ certs in every key window).
func (s *Server) hasClientMagic(b []byte) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, k := range s.keys {
		if bytes.Equal(b, k.pair.Classical.ClientMagic[:]) {
			return true
		}
		if bytes.Equal(b, k.pair.PQ.ClientMagic[:]) {
			return true
		}
	}
	return false
}

func (s *Server) serveDNS(ctx context.Context, rw responseWriter, m *dns.Msg, protocol string) error {
	if m == nil || len(m.Question) != 1 || m.Response {
		return dnscryptcrypto.ErrInvalidQuery
	}
	log.Debugf("DNSCRYPT: handling query for %s from %s", m.Question[0].Header().Name, rw.RemoteAddr())

	clientIP := zdnsutil.ClientIPFromAddr(rw.RemoteAddr())
	resp := s.handler.ServeDNS(m, clientIP, false, protocol)
	if resp == m { //nolint:revive // identity guard: ServeDNS must never return the request (L5)
		resp = nil
	}
	if resp == nil {
		return nil
	}
	defer pool.DefaultMessage.Put(resp)
	return rw.WriteMsg(ctx, resp)
}
