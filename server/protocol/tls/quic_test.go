package tls

import (
	"context"
	stdtls "crypto/tls"
	"net"
	"testing"
	"time"
	"zjdns/config"
	zdnsutil "zjdns/internal/dnsutil"
	"zjdns/internal/lrumap"

	"github.com/quic-go/quic-go"
)

// TestDOQZombieConnectionDoesNotPinAdmission pins the Round 6 audit P11
// property: a zombie DoQ client — handshake complete, then silently vanished
// without ever ACKing the server's CONNECTION_CLOSE — must not hold its
// quicConnSem admission slot beyond the serving loop's exit.  The handler
// now closes with fire-and-forget (quic-go's transport-owned drain finishes
// on its own) instead of waiting out the drain while holding the slot;
// ~13 slot-pinning handshakes/s would otherwise exhaust the 128-slot cap
// and lock out every later DoQ/DoH3 connection.  Note: on loopback the
// drain timer is only ~3x PTO (milliseconds), so this asserts the
// structural slot lifecycle (acquired at admission, released at handler
// exit) rather than a multi-second timing difference.
func TestDOQZombieConnectionDoesNotPinAdmission(t *testing.T) {
	s, err := New(rfc8998TestHandler{}, &Config{SelfSigned: true, Domain: "doq.test"})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen UDP: %v", err)
	}
	defer func() { _ = udpConn.Close() }()

	addrCache := lrumap.New[string, time.Time](config.DefaultQUICAddrCacheSize)
	transport := &quic.Transport{
		Conn:                udpConn,
		VerifySourceAddress: makeAddrValidator(addrCache),
	}
	defer func() { _ = transport.Close() }()

	quicTLSConfig := s.QUICTLSConfig().Clone()
	quicTLSConfig.NextProtos = config.NextProtoDOQ
	listener, err := transport.ListenEarly(quicTLSConfig, &quic.Config{
		MaxIdleTimeout: config.DefaultQUICServerIdleTimeout,
	})
	if err != nil {
		t.Fatalf("listen early: %v", err)
	}
	defer func() { _ = listener.Close() }()

	s.groups.quic.Go(func() error {
		defer zdnsutil.HandlePanic("DoQ server")
		s.handleDOQConnections(listener, addrCache)
		return nil
	})

	// Zombie client: completes the QUIC handshake, then vanishes by closing
	// the raw UDP socket underneath quic-go — no CONNECTION_CLOSE is ever
	// sent or ACKed.
	cliUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen client UDP: %v", err)
	}
	cliTr := &quic.Transport{Conn: cliUDP}
	conn, err := cliTr.Dial(context.Background(), listener.Addr(), &stdtls.Config{
		NextProtos:         config.NextProtoDOQ,
		InsecureSkipVerify: true, //nolint:gosec // self-signed test certificate
		MinVersion:         stdtls.VersionTLS13,
	}, &quic.Config{MaxIdleTimeout: config.DefaultQUICServerIdleTimeout})
	if err != nil {
		t.Fatalf("client dial: %v", err)
	}
	select {
	case <-conn.HandshakeComplete():
	case <-time.After(5 * time.Second):
		t.Fatal("client handshake timeout")
	}

	// Admission: the accepted zombie holds exactly one sem slot.
	deadline := time.Now().Add(2 * time.Second)
	for len(s.quicConnSem) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := len(s.quicConnSem); got != 1 {
		t.Fatalf("admission slots held after handshake = %d, want 1", got)
	}
	_ = cliUDP.Close() // vanish silently

	// Shutdown: the handler's deferred CloseWithError goes into the void; the
	// goroutine (and its quicConnSem slot) must be released without waiting
	// for a drain that will never be ACKed.
	s.cancel(nil)
	done := make(chan struct{})
	go func() {
		_ = s.groups.quic.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("DoQ handler still running 5s after shutdown — graceful-close drain pins the admission slot")
	}
	if got := len(s.quicConnSem); got != 0 {
		t.Errorf("admission slots still held after handler exit = %d, want 0", got)
	}
}
