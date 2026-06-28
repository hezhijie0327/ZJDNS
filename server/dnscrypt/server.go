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

	"github.com/miekg/dns"

	"zjdns/config"
	"zjdns/internal/dnsutil"
	"zjdns/internal/log"
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
	certTXT      string
	providerName string

	udpConn     *net.UDPConn
	tcpListener net.Listener
	udpSem      chan struct{}

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

	return &Server{
		handler:      handler,
		cfg:          dnsCfg,
		cert:         cert,
		certTXT:      cert.TXTString(),
		providerName: providerName,
		udpSem:       make(chan struct{}, config.DefaultMinConcurrencyLimit),
		ctx:          ctx,
		cancel:       cancel,
	}, nil
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

// serveUDP reads and processes UDP packets.
func (s *Server) serveUDP(ctx context.Context) {
	defer dnsutil.HandlePanic("DNSCrypt UDP server")
	buf := pool.DefaultBufferPool.Get()
	defer pool.DefaultBufferPool.Put(buf)

	for {
		if s.closed.Load() {
			return
		}
		_ = s.udpConn.SetReadDeadline(time.Now().Add(config.DefaultDNSCryptTCPReadTimeout))
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

		// Copy packet from shared buffer, then dispatch.
		packet := make([]byte, n)
		copy(packet, buf[:n])

		s.wg.Add(1)
		go func() {
			s.udpSem <- struct{}{}
			defer func() { <-s.udpSem }()
			defer s.wg.Done()
			defer dnsutil.HandlePanic("DNSCrypt UDP handler")
			s.handleUDPPacket(ctx, packet, addr)
		}()
	}
}

// handleUDPPacket dispatches a UDP packet: encrypted query, cert TXT request,
// plain DNS query, or unknown (dropped — QUIC/DoH3).
func (s *Server) handleUDPPacket(ctx context.Context, packet []byte, addr *net.UDPAddr) {
	// DNSCrypt encrypted query: starts with client-magic.
	if len(packet) >= clientMagicSize && bytes.Equal(packet[:clientMagicSize], s.cert.ClientMagic[:]) {
		s.handleEncryptedQuery(ctx, packet, addr)
		return
	}

	// Try to parse as DNS — handles both cert TXT requests and plain DNS.
	msg := pool.DefaultMessagePool.Get()
	defer pool.DefaultMessagePool.Put(msg)
	if err := msg.Unpack(packet); err != nil {
		return // not DNS, drop silently (e.g. QUIC/DoH3)
	}

	// Cert TXT query for our provider name.
	if len(msg.Question) == 1 && msg.Question[0].Qtype == dns.TypeTXT &&
		strings.EqualFold(msg.Question[0].Name, dns.Fqdn(s.providerName)) {
		s.handleCertQuery(ctx, msg, addr)
		return
	}

	// Plain DNS query — forward to the DNS handler (enables port sharing with :53).
	response := s.handler.ServeDNS(msg, addr.IP, false, "UDP")
	if response == nil {
		return
	}
	respPacket, err := response.Pack()
	pool.DefaultMessagePool.Put(response)
	if err != nil {
		return
	}
	_, _ = s.udpConn.WriteToUDP(respPacket, addr)
}

// handleEncryptedQuery decrypts and processes a DNSCrypt encrypted query.
func (s *Server) handleEncryptedQuery(ctx context.Context, packet []byte, addr *net.UDPAddr) {
	query, encrypted, err := parseQuery(packet, s.cert)
	if err != nil {
		log.Debugf("DNSCRYPT: parse query from %s: %v", addr, err)
		return
	}

	decrypted, err := query.decrypt(encrypted, s.cert)
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

	sharedKey, err := ComputeSharedKey(s.cert.ESVersion, &s.cert.ResolverSk, &query.ClientPk)
	if err != nil {
		log.Debugf("DNSCRYPT: shared key: %v", err)
		return
	}

	encryptedResp, err := encryptResponse(s.cert.ESVersion, respPacket, &sharedKey, &query.Nonce)
	if err != nil {
		log.Debugf("DNSCRYPT: encrypt response: %v", err)
		return
	}

	_, _ = s.udpConn.WriteToUDP(encryptedResp, addr)
}

// handleCertQuery responds to a certificate TXT query.
func (s *Server) handleCertQuery(ctx context.Context, msg *dns.Msg, addr *net.UDPAddr) {
	reply := new(dns.Msg)
	reply.SetReply(msg)
	reply.Authoritative = true
	reply.RecursionAvailable = true
	reply.Answer = append(reply.Answer, &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   msg.Question[0].Name,
			Rrtype: dns.TypeTXT,
			Ttl:    60,
			Class:  dns.ClassINET,
		},
		Txt: []string{s.certTXT},
	})
	resp, _ := reply.Pack()
	_, _ = s.udpConn.WriteToUDP(resp, addr)
}

// serveTCP accepts and processes TCP connections.
func (s *Server) serveTCP(ctx context.Context) {
	defer dnsutil.HandlePanic("DNSCrypt TCP server")
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
		s.wg.Add(1)
		go func() {
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

		// TCP also supports cert TXT queries.
		if len(packet) >= clientMagicSize && bytes.Equal(packet[:clientMagicSize], s.cert.ClientMagic[:]) {
			query, encrypted, err := parseQuery(packet, s.cert)
			if err != nil {
				continue
			}
			decrypted, err := query.decrypt(encrypted, s.cert)
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

			sharedKey, err := ComputeSharedKey(s.cert.ESVersion, &s.cert.ResolverSk, &query.ClientPk)
			if err != nil {
				continue
			}
			encryptedResp, err := encryptResponse(s.cert.ESVersion, respPacket, &sharedKey, &query.Nonce)
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
		} else {
			// Cert TXT or plain DNS query over TCP.
			msg := &dns.Msg{}
			if err := msg.Unpack(packet); err != nil {
				continue
			}

			var clientIP net.IP
			if tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
				clientIP = tcpAddr.IP
			}

			if len(msg.Question) == 1 && msg.Question[0].Qtype == dns.TypeTXT &&
				strings.EqualFold(msg.Question[0].Name, dns.Fqdn(s.providerName)) {
				reply := new(dns.Msg)
				reply.SetReply(msg)
				reply.Authoritative = true
				reply.RecursionAvailable = true
				reply.Answer = append(reply.Answer, &dns.TXT{
					Hdr: dns.RR_Header{
						Name: msg.Question[0].Name, Rrtype: dns.TypeTXT,
						Ttl: 60, Class: dns.ClassINET,
					},
					Txt: []string{s.certTXT},
				})
				resp, _ := reply.Pack()
				_ = conn.SetWriteDeadline(time.Now().Add(config.DefaultDNSQueryTimeout))
				_ = binary.Write(conn, binary.BigEndian, uint16(len(resp)))
				_, _ = conn.Write(resp)
				continue
			}

			// Plain DNS query — forward to handler (port sharing with :53).
			response := s.handler.ServeDNS(msg, clientIP, false, "TCP")
			if response == nil {
				continue
			}
			respPacket, err := response.Pack()
			pool.DefaultMessagePool.Put(response)
			if err != nil {
				continue
			}
			_ = conn.SetWriteDeadline(time.Now().Add(config.DefaultDNSQueryTimeout))
			_ = binary.Write(conn, binary.BigEndian, uint16(len(respPacket)))
			_, _ = conn.Write(respPacket)
		}
	}
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
