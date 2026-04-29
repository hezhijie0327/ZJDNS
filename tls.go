// Package main implements ZJDNS - High Performance DNS Server
package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/sync/errgroup"
)

const (
	TLSConnBufferSize = 128 // Buffer size for TLS connections

	DoHMaxRequestSize = 8192 // Maximum request size for DoH (8 KB)

	MaxIncomingStreams = math.MaxUint16 // Maximum number of incoming streams for QUIC servers

	QUICCodeNoError       quic.ApplicationErrorCode = 0
	QUICCodeInternalError quic.ApplicationErrorCode = 1
	QUICCodeProtocolError quic.ApplicationErrorCode = 2
)

var (
	NextProtoDOT  = []string{"dot"}
	NextProtoDoQ  = []string{"doq"}
	NextProtoDoH3 = []string{"h3"}
	NextProtoDoH  = []string{"h2"}
)

// TLSManager manages all TLS-related functionality, including certificate management and secure server handling for DoT, DoQ, DoH, and DoH3. It encapsulates the logic for starting and stopping secure servers, handling incoming connections, and processing DNS queries over secure protocols.
type TLSManager struct {
	server        *DNSServer
	tlsConfig     *tls.Config
	ctx           context.Context
	cancel        context.CancelCauseFunc
	serverGroup   *errgroup.Group
	serverCtx     context.Context
	dotListener   net.Listener
	doqConn       *net.UDPConn
	doqListener   *quic.EarlyListener
	doqTransport  *quic.Transport
	httpsServer   *http.Server
	h3Server      *http3.Server
	httpsListener net.Listener
	h3Listener    *quic.EarlyListener
}

// generateSelfSignedCert generates a self-signed ECDSA certificate for the given domain.
// It creates a CA certificate and uses it to sign a server certificate.
func generateSelfSignedCert(domain string) (tls.Certificate, error) {
	// Generate CA private key using ECDSA P-384
	caPrivKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate CA EC key: %w", err)
	}

	// Generate server private key using ECDSA P-384
	serverPrivKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate server EC key: %w", err)
	}

	// Generate random serial numbers
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	caSerialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate CA serial number: %w", err)
	}

	serverSerialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate server serial number: %w", err)
	}

	// Create CA certificate template
	caTemplate := x509.Certificate{
		SerialNumber: caSerialNumber,
		Subject: pkix.Name{
			CommonName:   "ZJDNS ECC Domain Secure Site CA",
			Organization: []string{"ZJDNS"},
			Country:      []string{"CN"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(90 * 24 * time.Hour), // 90 days validity
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	// Create server certificate template
	serverTemplate := x509.Certificate{
		SerialNumber: serverSerialNumber,
		Subject: pkix.Name{
			CommonName: domain,
		},
		DNSNames:    []string{domain},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(90 * 24 * time.Hour), // 90 days validity
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	// Create and sign CA certificate
	caCertDER, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create CA certificate: %w", err)
	}

	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("parse CA certificate: %w", err)
	}

	// Create and sign server certificate using CA
	certDER, err := x509.CreateCertificate(rand.Reader, &serverTemplate, caCert, &serverPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create server certificate: %w", err)
	}

	// Create tls.Certificate
	cert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  serverPrivKey,
	}

	return cert, nil
}

// IsTemporaryError checks if an error is temporary/recoverable.
func IsTemporaryError(err error) bool {
	if err == nil {
		return false
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return true
	}
	return strings.Contains(err.Error(), "timeout") || strings.Contains(err.Error(), "temporary")
}

// GetSecureClientIP extracts client IP from secure connection.
func GetSecureClientIP(conn any) net.IP {
	switch c := conn.(type) {
	case *net.Conn:
		if addr, ok := (*c).RemoteAddr().(*net.TCPAddr); ok {
			return addr.IP
		}
	case interface{ RemoteAddr() net.Addr }:
		if addr, ok := c.RemoteAddr().(*net.TCPAddr); ok {
			return addr.IP
		}
	}
	return nil
}

// NewTLSManager creates a new TLSManager with the given server and configuration.
// It loads or generates TLS certificates and initializes the TLS configuration.
func NewTLSManager(server *DNSServer, config *ServerConfig) (*TLSManager, error) {
	var cert tls.Certificate
	var err error

	// Load or generate certificate
	if config.Server.TLS.SelfSigned {
		cert, err = generateSelfSignedCert(config.Server.Features.DDR.Domain)
		if err != nil {
			return nil, fmt.Errorf("generate self-signed certificate: %w", err)
		}
		LogInfo("TLS: Using self-signed certificate for domain: %s", config.Server.Features.DDR.Domain)
	} else {
		cert, err = tls.LoadX509KeyPair(config.Server.TLS.CertFile, config.Server.TLS.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("load certificate: %w", err)
		}
		LogInfo("TLS: Using certificate from files: %s, %s", config.Server.TLS.CertFile, config.Server.TLS.KeyFile)
	}

	// Create TLS configuration
	tlsConfig := &tls.Config{
		Certificates:     []tls.Certificate{cert},
		CurvePreferences: []tls.CurveID{},
		MinVersion:       tls.VersionTLS13,
	}

	// Create context and error group for server management
	ctx, cancel := context.WithCancelCause(context.Background())
	serverGroup, serverCtx := errgroup.WithContext(ctx)

	tm := &TLSManager{
		server:      server,
		tlsConfig:   tlsConfig,
		ctx:         ctx,
		cancel:      cancel,
		serverGroup: serverGroup,
		serverCtx:   serverCtx,
	}

	// Display certificate information
	tm.displayCertificateInfo(cert)

	return tm, nil
}

// displayCertificateInfo logs information about the TLS certificate.
func (tm *TLSManager) displayCertificateInfo(cert tls.Certificate) {
	if len(cert.Certificate) == 0 {
		LogError("TLS: No certificate found")
		return
	}

	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		LogError("TLS: Failed to parse certificate: %v", err)
		return
	}

	LogInfo("TLS: Certificate: Subject: %s | Issuer: %s | Valid: %s -> %s | Algorithm: %s",
		x509Cert.Subject.CommonName,
		x509Cert.Issuer.String(),
		x509Cert.NotBefore.Format("2006-01-02"),
		x509Cert.NotAfter.Format("2006-01-02"),
		x509Cert.SignatureAlgorithm.String())

	// Check and warn about certificate expiry
	daysUntilExpiry := int(time.Until(x509Cert.NotAfter).Hours() / 24)
	if daysUntilExpiry < 0 {
		LogError("TLS: Certificate has EXPIRED for %d days!", -daysUntilExpiry)
	} else if daysUntilExpiry <= 30 {
		LogWarn("TLS: Certificate expires in %d days!", daysUntilExpiry)
	}
}

// Start starts all secure DNS servers (DoT, DoQ, DoH, DoH3).
// It launches each server in a separate goroutine and coordinates their lifecycle.
func (tm *TLSManager) Start(httpsPort string) error {
	errChan := make(chan error, 1)

	g, ctx := errgroup.WithContext(context.Background())

	// Start DoH server if HTTPS port is configured
	if httpsPort != "" {
		g.Go(func() error {
			defer HandlePanic("DoH server")
			if err := tm.startDOHServer(httpsPort); err != nil {
				return fmt.Errorf("DoH startup: %w", err)
			}
			<-ctx.Done()
			return nil
		})

		// Start DoH3 server
		g.Go(func() error {
			defer HandlePanic("DoH3 server")
			if err := tm.startDoH3Server(httpsPort); err != nil {
				return fmt.Errorf("DoH3 startup: %w", err)
			}
			<-ctx.Done()
			return nil
		})
	}

	// Start DoT server
	g.Go(func() error {
		defer HandlePanic("DoT server")
		if err := tm.startDOTServer(); err != nil {
			return fmt.Errorf("DoT startup: %w", err)
		}
		<-ctx.Done()
		return nil
	})

	// Start DoQ server
	g.Go(func() error {
		defer HandlePanic("DoQ server")
		if err := tm.startDOQServer(); err != nil {
			return fmt.Errorf("DoQ startup: %w", err)
		}
		<-ctx.Done()
		return nil
	})

	// Coordinate server goroutines
	go func() {
		defer HandlePanic("TLS manager coordinator")
		if err := g.Wait(); err != nil {
			select {
			case errChan <- err:
			default:
			}
		}
		close(errChan)
	}()

	// Wait for errors
	for err := range errChan {
		if err != nil {
			return err
		}
	}

	return nil
}

// startDOTServer starts the DNS over TLS server.
func (tm *TLSManager) startDOTServer() error {
	listener, err := net.Listen("tcp", ":"+tm.server.config.Server.TLS.Port)
	if err != nil {
		return fmt.Errorf("DoT listen: %w", err)
	}

	// Configure TLS for DoT
	dotTLSConfig := tm.tlsConfig.Clone()
	dotTLSConfig.NextProtos = NextProtoDOT

	tm.dotListener = tls.NewListener(listener, dotTLSConfig)
	LogInfo("DOT: DoT server started on port %s", tm.server.config.Server.TLS.Port)

	tm.serverGroup.Go(func() error {
		defer HandlePanic("DoT server")
		tm.handleDOTConnections()
		return nil
	})

	return nil
}

// handleDOTConnections accepts and handles incoming DoT connections.
func (tm *TLSManager) handleDOTConnections() {
	for {
		select {
		case <-tm.ctx.Done():
			return
		default:
		}

		conn, err := tm.dotListener.Accept()
		if err != nil {
			if tm.ctx.Err() != nil {
				return
			}
			LogError("DOT: Accept error: %v", err)
			continue
		}

		tm.serverGroup.Go(func() error {
			defer HandlePanic("DoT connection handler")
			defer func() { _ = conn.Close() }()
			tm.handleDOTConnection(conn)
			return nil
		})
	}
}

// handleDOTConnection handles a single DoT connection.
func (tm *TLSManager) handleDOTConnection(conn net.Conn) {
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return
	}

	_ = tlsConn.SetReadDeadline(time.Now().Add(OperationTimeout))
	_ = tlsConn.SetWriteDeadline(time.Now().Add(OperationTimeout))

	reader := bufio.NewReaderSize(tlsConn, TLSConnBufferSize)

	for {
		select {
		case <-tm.ctx.Done():
			return
		default:
		}

		_ = tlsConn.SetReadDeadline(time.Now().Add(OperationTimeout))
		_ = tlsConn.SetWriteDeadline(time.Now().Add(OperationTimeout))

		// Read message length (2 bytes)
		lengthBuf := make([]byte, 2)
		n, err := io.ReadFull(reader, lengthBuf)
		if err != nil {
			if err != io.EOF && !IsTemporaryError(err) {
				LogDebug("DOT: Read length error: %v", err)
			}
			return
		}
		if n != 2 {
			LogDebug("DOT: Invalid length read: %d bytes", n)
			return
		}

		msgLength := binary.BigEndian.Uint16(lengthBuf)
		if msgLength == 0 || msgLength > TCPBufferSize {
			LogDebug("DOT: Invalid message length: %d", msgLength)
			return
		}

		// Read message body
		msgBuf := make([]byte, msgLength)
		n, err = io.ReadFull(reader, msgBuf)
		if err != nil {
			LogDebug("DOT: Read message error: %v", err)
			return
		}
		if n != int(msgLength) {
			LogDebug("DOT: Incomplete message read: %d/%d bytes", n, msgLength)
			return
		}

		// Parse DNS message
		req := messagePool.Get()
		if err := req.Unpack(msgBuf); err != nil {
			LogDebug("DOT: DNS message unpack error: %v", err)
			messagePool.Put(req)
			continue
		}

		// Get client IP
		var clientIP net.IP
		if addr := tlsConn.RemoteAddr(); addr != nil {
			clientIP = addr.(*net.TCPAddr).IP
		}

		// Process query
		response := tm.server.processDNSQuery(req, clientIP, true, "DoT")
		messagePool.Put(req)

		if response != nil {
			respBuf, err := response.Pack()
			if err != nil {
				LogDebug("DOT: Response pack error: %v", err)
				messagePool.Put(response)
				return
			}

			// Write response with length prefix
			lengthBuf := make([]byte, 2)
			binary.BigEndian.PutUint16(lengthBuf, uint16(len(respBuf)))

			if _, err := tlsConn.Write(lengthBuf); err != nil {
				LogDebug("DOT: Write length error: %v", err)
				messagePool.Put(response)
				return
			}

			if _, err := tlsConn.Write(respBuf); err != nil {
				LogDebug("DOT: Write response error: %v", err)
				messagePool.Put(response)
				return
			}

			messagePool.Put(response)
		}
	}
}

// startDOQServer starts the DNS over QUIC server.
func (tm *TLSManager) startDOQServer() error {
	addr := ":" + tm.server.config.Server.TLS.Port

	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return fmt.Errorf("resolve UDP address: %w", err)
	}

	tm.doqConn, err = net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("UDP listen: %w", err)
	}

	tm.doqTransport = &quic.Transport{
		Conn: tm.doqConn,
	}

	// Configure TLS for DoQ
	quicTLSConfig := tm.tlsConfig.Clone()
	quicTLSConfig.NextProtos = NextProtoDoQ

	quicConfig := &quic.Config{
		MaxIdleTimeout:        IdleTimeout,
		MaxIncomingStreams:    MaxIncomingStreams,
		MaxIncomingUniStreams: MaxIncomingStreams,
		Allow0RTT:             false,
		EnableDatagrams:       true,
	}

	tm.doqListener, err = tm.doqTransport.ListenEarly(quicTLSConfig, quicConfig)
	if err != nil {
		_ = tm.doqConn.Close()
		return fmt.Errorf("DoQ listen: %w", err)
	}

	LogInfo("DOQ: DoQ server started on port %s", tm.server.config.Server.TLS.Port)

	tm.serverGroup.Go(func() error {
		defer HandlePanic("DoQ server")
		tm.handleDOQConnections()
		return nil
	})

	return nil
}

// handleDOQConnections accepts and handles incoming DoQ connections.
func (tm *TLSManager) handleDOQConnections() {
	for {
		select {
		case <-tm.ctx.Done():
			return
		default:
		}

		conn, err := tm.doqListener.Accept(tm.ctx)
		if err != nil {
			if tm.ctx.Err() != nil {
				return
			}
			continue
		}

		if conn == nil {
			continue
		}

		tm.serverGroup.Go(func() error {
			defer HandlePanic("DoQ connection handler")
			tm.handleDOQConnection(conn)
			return nil
		})
	}
}

// handleDOQConnection handles a single DoQ connection.
func (tm *TLSManager) handleDOQConnection(conn *quic.Conn) {
	if conn == nil {
		return
	}

	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), DefaultTimeout)
		defer cancel()

		_ = conn.CloseWithError(QUICCodeNoError, "")

		done := make(chan struct{})
		go func() {
			<-conn.Context().Done()
			close(done)
		}()

		select {
		case <-done:
		case <-ctx.Done():
			LogDebug("QUIC: Connection close timeout")
		}
	}()

	streamGroup, _ := errgroup.WithContext(tm.ctx)

	for {
		select {
		case <-tm.ctx.Done():
			if err := streamGroup.Wait(); err != nil {
				LogError("DoQ: Stream group finished with error: %v", err)
			}
			return
		case <-conn.Context().Done():
			if err := streamGroup.Wait(); err != nil {
				LogError("DoQ: Stream group finished with error: %v", err)
			}
			return
		default:
		}

		stream, err := conn.AcceptStream(tm.ctx)
		if err != nil {
			if err := streamGroup.Wait(); err != nil {
				LogError("DoQ: Stream group finished with error: %v", err)
			}
			return
		}

		if stream == nil {
			continue
		}

		streamGroup.Go(func() error {
			defer HandlePanic("DoQ stream handler")
			if stream != nil {
				defer func() { _ = stream.Close() }()
				tm.handleDOQStream(stream, conn)
			}
			return nil
		})
	}
}

// handleDOQStream handles a single DoQ stream.
func (tm *TLSManager) handleDOQStream(stream *quic.Stream, conn *quic.Conn) {
	buf := bufferPool.Get()
	defer bufferPool.Put(buf)

	// Read message length
	n, err := io.ReadFull(stream, buf[:2])
	if err != nil || n < 2 {
		return
	}

	msgLen := binary.BigEndian.Uint16(buf[:2])
	if msgLen == 0 || msgLen > SecureBufferSize-2 {
		_ = conn.CloseWithError(QUICCodeProtocolError, "invalid length")
		return
	}

	// Read message body
	n, err = io.ReadFull(stream, buf[2:2+msgLen])
	if err != nil || n != int(msgLen) {
		return
	}

	// Parse DNS message
	req := messagePool.Get()
	if err := req.Unpack(buf[2 : 2+msgLen]); err != nil {
		_ = conn.CloseWithError(QUICCodeProtocolError, "invalid DNS message")
		messagePool.Put(req)
		return
	}

	// Get client IP and process query
	clientIP := GetSecureClientIP(conn)
	response := tm.server.processDNSQuery(req, clientIP, true, "DoQ")
	// Send response
	if err := tm.respondQUIC(stream, response); err != nil {
		LogDebug("PROTOCOL: DoQ response failed: %v", err)
	}
	if response != nil {
		messagePool.Put(response)
	}
}

// respondQUIC sends a DNS response over a QUIC stream.
func (tm *TLSManager) respondQUIC(stream *quic.Stream, response *dns.Msg) error {
	if response == nil {
		return errors.New("response is nil")
	}

	respBuf, err := response.Pack()
	if err != nil {
		return fmt.Errorf("pack response: %w", err)
	}

	buf := bufferPool.Get()
	defer bufferPool.Put(buf)

	if len(buf) < 2+len(respBuf) {
		buf = make([]byte, 2+len(respBuf))
	}

	binary.BigEndian.PutUint16(buf[:2], uint16(len(respBuf)))
	copy(buf[2:], respBuf)

	n, err := stream.Write(buf[:2+len(respBuf)])
	if err != nil {
		return fmt.Errorf("stream write: %w", err)
	}
	if n != len(buf[:2+len(respBuf)]) {
		return fmt.Errorf("write length mismatch: %d != %d", n, len(buf))
	}

	return nil
}

// startDOHServer starts the DNS over HTTPS server (HTTP/2).
func (tm *TLSManager) startDOHServer(port string) error {
	listener, err := net.Listen("tcp", ":"+port)
	if err != nil {
		return fmt.Errorf("DoH listen: %w", err)
	}

	tlsConfig := tm.tlsConfig.Clone()
	tlsConfig.NextProtos = NextProtoDoH

	tm.httpsListener = tls.NewListener(listener, tlsConfig)
	LogInfo("DOH: DoH server started on port %s", port)

	tm.httpsServer = &http.Server{
		Handler:           tm,
		ReadHeaderTimeout: OperationTimeout,
		WriteTimeout:      OperationTimeout,
		IdleTimeout:       IdleTimeout,
	}

	tm.serverGroup.Go(func() error {
		defer HandlePanic("DoH server")
		if err := tm.httpsServer.Serve(tm.httpsListener); err != nil && err != http.ErrServerClosed {
			LogError("DOH: DoH server error: %v", err)
			return err
		}
		return nil
	})

	return nil
}

// startDoH3Server starts the DNS over HTTPS server (HTTP/3).
func (tm *TLSManager) startDoH3Server(port string) error {
	addr := ":" + port

	tlsConfig := tm.tlsConfig.Clone()
	tlsConfig.NextProtos = NextProtoDoH3

	quicConfig := &quic.Config{
		MaxIdleTimeout:        IdleTimeout,
		MaxIncomingStreams:    MaxIncomingStreams,
		MaxIncomingUniStreams: MaxIncomingStreams,
		Allow0RTT:             false,
		EnableDatagrams:       true,
	}

	quicListener, err := quic.ListenAddrEarly(addr, tlsConfig, quicConfig)
	if err != nil {
		return fmt.Errorf("DoH3 listen: %w", err)
	}

	tm.h3Listener = quicListener
	LogInfo("DOH3: DoH3 server started on port %s", port)

	tm.h3Server = &http3.Server{Handler: tm}

	tm.serverGroup.Go(func() error {
		defer HandlePanic("DoH3 server")
		if err := tm.h3Server.ServeListener(tm.h3Listener); err != nil && err != http.ErrServerClosed {
			LogError("DOH3: DoH3 server error: %v", err)
			return err
		}
		return nil
	})

	return nil
}

// ServeHTTP handles HTTP requests for DoH/DoH3 servers.
func (tm *TLSManager) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if tm == nil || tm.server == nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	// Check endpoint path
	expectedPath := tm.server.config.Server.TLS.HTTPS.Endpoint
	if expectedPath == "" {
		expectedPath = DefaultQueryPath
	}
	if !strings.HasPrefix(expectedPath, "/") {
		expectedPath = "/" + expectedPath
	}

	if r.URL.Path != expectedPath {
		http.NotFound(w, r)
		return
	}

	// Parse the DNS request
	req, statusCode := tm.parseDoHRequest(r)
	if req == nil {
		http.Error(w, http.StatusText(statusCode), statusCode)
		return
	}

	// Process the query
	protocol := "DoH"
	if strings.HasPrefix(r.Proto, "HTTP/3") {
		protocol = "DoH3"
	}
	response := tm.server.processDNSQuery(req, nil, true, protocol)

	if err := tm.respondDoH(w, response); err != nil {
		LogError("DOH: DoH response failed: %v", err)
	}
	if response != nil {
		messagePool.Put(response)
	}
}

// parseDoHRequest parses a DNS request from an HTTP request.
// It supports both GET (with base64url encoded dns parameter) and POST methods.
func (tm *TLSManager) parseDoHRequest(r *http.Request) (*dns.Msg, int) {
	var buf []byte
	var err error

	switch r.Method {
	case http.MethodGet:
		dnsParam := r.URL.Query().Get("dns")
		if dnsParam == "" {
			return nil, http.StatusBadRequest
		}
		buf, err = base64.RawURLEncoding.DecodeString(dnsParam)
		if err != nil {
			return nil, http.StatusBadRequest
		}

	case http.MethodPost:
		if r.Header.Get("Content-Type") != "application/dns-message" {
			return nil, http.StatusUnsupportedMediaType
		}
		r.Body = http.MaxBytesReader(nil, r.Body, DoHMaxRequestSize)
		buf, err = io.ReadAll(r.Body)
		defer func() { _ = r.Body.Close() }()
		if err != nil {
			return nil, http.StatusBadRequest
		}

	default:
		return nil, http.StatusMethodNotAllowed
	}

	if len(buf) == 0 {
		return nil, http.StatusBadRequest
	}

	req := messagePool.Get()
	if err := req.Unpack(buf); err != nil {
		messagePool.Put(req)
		return nil, http.StatusBadRequest
	}

	return req, http.StatusOK
}

// respondDoH sends a DNS response as an HTTP response.
func (tm *TLSManager) respondDoH(w http.ResponseWriter, response *dns.Msg) error {
	if response == nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return nil
	}

	bytes, err := response.Pack()
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return fmt.Errorf("pack response: %w", err)
	}

	w.Header().Set("Content-Type", "application/dns-message")
	w.Header().Set("Cache-Control", "max-age=0")
	_, err = w.Write(bytes)
	return err
}

// shutdown gracefully shuts down all TLS services.
func (tm *TLSManager) shutdown() error {
	LogInfo("TLS: Shutting down secure DNS server")

	// Cancel context to signal all goroutines
	tm.cancel(errors.New("tls manager shutdown"))

	// Close DoT listener
	if tm.dotListener != nil {
		CloseWithLog(tm.dotListener, "DoT listener")
	}

	// Close DoQ listener and connection
	if tm.doqListener != nil {
		CloseWithLog(tm.doqListener, "DoQ listener")
	}
	if tm.doqConn != nil {
		CloseWithLog(tm.doqConn, "DoQ connection")
	}

	// Shutdown HTTPS server
	if tm.httpsServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), DefaultTimeout)
		defer cancel()
		_ = tm.httpsServer.Shutdown(ctx)
	}

	// Shutdown HTTP/3 server
	if tm.h3Server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), DefaultTimeout)
		defer cancel()
		_ = tm.h3Server.Shutdown(ctx)
	}

	// Close listeners
	if tm.httpsListener != nil {
		CloseWithLog(tm.httpsListener, "HTTPS listener")
	}
	if tm.h3Listener != nil {
		CloseWithLog(tm.h3Listener, "HTTP/3 listener")
	}

	// Wait for all server goroutines to finish
	if err := tm.serverGroup.Wait(); err != nil {
		LogError("TLS: Server goroutines finished with error: %v", err)
	}

	LogInfo("TLS: Secure DNS server shut down")
	return nil
}
