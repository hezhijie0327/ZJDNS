// Shared test scaffolding: a minimal Host, a per-shard runtime launcher
// mirroring startUDPGroup's shard wiring (minus ResolveBindAddrs), fake
// protocol handlers, and datagram builders for the dispatch tests.

package shared

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"
	"zjdns/internal/demux"
	"zjdns/internal/pool"

	dtlsnet "github.com/pion/dtls/v4/pkg/net"
)

// recvPacket is one datagram observed by a fake handler, copied out of the
// pooled dispatch buffer before it returns to the pool.
type recvPacket struct {
	data []byte
	addr net.Addr
}

// testHost is the minimal Host the Mux needs: a lifecycle context plus a
// WaitGroup so tests can assert every scheduled goroutine exits at shutdown.
type testHost struct {
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// testMagic is a DNSCrypt client-magic prefix whose first byte (0xC3) and
// 1200+ byte packets also satisfy the QUIC long-header rule — the collision
// the classification priority (ClassifyDNSCrypt before DetectUDPProtocol)
// must resolve in DNSCrypt's favour.
var testMagic = []byte{0xC3, 0x7a, 0x00, 0x00, 'Z', 'J', 'D', 'N'}

func newTestHost() *testHost {
	ctx, cancel := context.WithCancel(context.Background())
	return &testHost{ctx: ctx, cancel: cancel}
}

func (h *testHost) Go(f func() error) {
	h.wg.Go(func() {
		_ = f()
	})
}

func (h *testHost) Ctx() context.Context { return h.ctx }

// wait reports whether every scheduled goroutine exited within timeout.
func (h *testHost) wait(timeout time.Duration) bool {
	done := make(chan struct{})
	go func() {
		h.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-time.After(timeout):
		return false
	}
}

// newTestMux creates a Mux on a testHost with full shutdown wired into
// t.Cleanup (idempotent — tests may shut down explicitly beforehand).
func newTestMux(t *testing.T) (*Mux, *testHost) {
	t.Helper()
	host := newTestHost()
	m := New(host, &Config{})
	t.Cleanup(func() {
		m.Shutdown()
		host.cancel()
		if !host.wait(3 * time.Second) {
			t.Error("shared-port goroutines did not exit within 3s of shutdown")
		}
	})
	return m, host
}

// launchUDPShardRuntime is the per-shard equivalent of startUDPGroup's inner
// loop (socket + per-protocol state + handler goroutines + dispatch loop),
// parameterised by bind address so tests can pick a random port or build
// multi-shard SO_REUSEPORT groups.  The per-client flood semaphore is passed
// by the caller, exactly as production shares it across shards.
func launchUDPShardRuntime(t *testing.T, m *Mux, host *testHost, g *UDPGroup, bindAddr string, clientSem chan struct{}) *udpRuntime {
	t.Helper()

	var lc net.ListenConfig
	if ReusePortSupported() {
		lc = net.ListenConfig{Control: ReusePortControl()}
	}
	pc, err := lc.ListenPacket(m.groupCtx, "udp", bindAddr)
	if err != nil {
		t.Fatalf("listen udp %s: %v", bindAddr, err)
	}
	conn := pc.(*net.UDPConn)

	rt := &udpRuntime{cfg: g, conn: conn, clientSem: clientSem}
	if g.DTLSHandler != nil {
		rt.dtlsPL = newDTLSPacketListener(conn)
	}
	if g.ServeDNSCrypt != nil {
		rt.dcState = &sharedDNSCryptClient{conns: make(map[addrKey]*DemuxPacketConn)}
	}
	if g.ServeDTLCP != nil {
		rt.dtlcpState = &sharedDTLSClient{conns: make(map[addrKey]*DemuxPacketConn)}
	}

	if g.DOQHandler != nil {
		rt.quicPC = newQUICPacketConn(conn)
		capturedQUIC, capturedHandler := rt.quicPC, g.DOQHandler
		host.Go(func() error {
			_ = capturedHandler(capturedQUIC)
			return nil
		})
	}
	if g.HTTP3Handler != nil {
		rt.h3PC = newQUICPacketConn(conn)
		capturedH3, capturedHandler := rt.h3PC, g.HTTP3Handler
		host.Go(func() error {
			_ = capturedHandler(capturedH3)
			return nil
		})
	}
	if g.DTLSHandler != nil {
		capturedDTLS, capturedHandler := rt.dtlsPL, g.DTLSHandler
		host.Go(func() error {
			_ = capturedHandler(capturedDTLS)
			return nil
		})
	}

	m.mu.Lock()
	m.udpRuntimes = append(m.udpRuntimes, rt)
	m.mu.Unlock()

	capturedRT := rt
	host.Go(func() error {
		m.udpDispatchLoop(capturedRT)
		return nil
	})
	return rt
}

// fakeQUICReader returns a DoQ/DoH3 handler that copies every datagram it
// reads off the shard's QUIC packet conn into recv.
func fakeQUICReader(recv chan<- recvPacket) func(net.PacketConn) error {
	return func(pc net.PacketConn) error {
		buf := make([]byte, pool.SecureBufferSize)
		// Read until the conn is closed at shutdown; the close error is the
		// expected exit, not a failure.
		n, addr, err := pc.ReadFrom(buf)
		for err == nil {
			data := make([]byte, n)
			copy(data, buf[:n])
			recv <- recvPacket{data: data, addr: addr}
			n, addr, err = pc.ReadFrom(buf)
		}
		return nil
	}
}

// fakeDNSCryptHandler records every datagram handed to ServeDNSCrypt.  The
// data slice is pool-owned, so it is copied before it escapes.
func fakeDNSCryptHandler(recv chan<- recvPacket) func(context.Context, []byte, net.Addr, net.PacketConn) {
	return func(_ context.Context, data []byte, src net.Addr, _ net.PacketConn) {
		cp := make([]byte, len(data))
		copy(cp, data)
		recv <- recvPacket{data: cp, addr: src}
	}
}

// fakeDTLSHandler accepts per-client conns from the DTLS packet listener and
// copies every datagram each one delivers into recv.
func fakeDTLSHandler(recv chan<- recvPacket) func(dtlsnet.PacketListener) error {
	return func(pl dtlsnet.PacketListener) error {
		// Accept until the listener is closed at shutdown; the close error is
		// the expected exit, not a failure.
		conn, addr, err := pl.Accept()
		for err == nil {
			go func(pc net.PacketConn, remote net.Addr) {
				buf := make([]byte, pool.SecureBufferSize)
				for {
					n, _, err := pc.ReadFrom(buf)
					if err != nil {
						return
					}
					data := make([]byte, n)
					copy(data, buf[:n])
					recv <- recvPacket{data: data, addr: remote}
				}
			}(conn, addr)
			conn, addr, err = pl.Accept()
		}
		return nil
	}
}

// fakeDTLCPHandler serves one DTLCP client: every datagram is recorded, and
// the conn is forgotten via cleanup once it goes silent.
func fakeDTLCPHandler(recv chan<- recvPacket) func(net.PacketConn, *net.UDPAddr, func()) {
	return func(pc net.PacketConn, src *net.UDPAddr, cleanup func()) {
		defer cleanup()
		buf := make([]byte, pool.SecureBufferSize)
		for {
			n, _, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			data := make([]byte, n)
			copy(data, buf[:n])
			recv <- recvPacket{data: data, addr: src}
		}
	}
}

// testClassifier mirrors the production ClassifyDNSCrypt wiring
// (HasClientMagic → ProtoDNSCrypt): it recognises testMagic and leaves
// everything else to the standard QUIC/DTLS/DTLCP detection.
func testClassifier(data []byte) string {
	if len(data) >= len(testMagic) && bytes.Equal(data[:len(testMagic)], testMagic) {
		return demux.ProtoDNSCrypt
	}
	return ""
}

// quicLongPacket builds a ≥1200-byte datagram shaped like a QUIC Initial
// (long header: first byte ≥ 0xC0) — the only form DetectUDPProtocol
// classifies as QUIC.
func quicLongPacket(size int) []byte {
	pkt := make([]byte, size)
	pkt[0] = 0xC3
	for i := 1; i < size; i++ {
		pkt[i] = byte(i)
	}
	return pkt
}

// dnscryptMagicPacket builds a datagram prefixed with testMagic.
func dnscryptMagicPacket(size int) []byte {
	pkt := make([]byte, size)
	copy(pkt, testMagic)
	return pkt
}

// plainDNSQueryMinimal builds a structurally valid plain DNS query for
// "a.b. A IN" whose ID high byte (0xC0) collides with the QUIC long-header
// first-byte range.
func plainDNSQueryMinimal() []byte {
	return []byte{
		0xC0, 0x12, // ID — high byte ≥ 0xC0 on purpose
		0x01, 0x00, // flags: RD
		0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // counts
		0x01, 'a', 0x01, 'b', 0x00,
		0x00, 0x01, // QTYPE A
		0x00, 0x01, // QCLASS IN
	}
}

// plainDNSQueryPadded builds a structurally valid EDNS query padded via the
// OPT rdata to exactly 1200 bytes.  Its ID high byte (0xC0) and size both
// satisfy the QUIC long-header rule, so without the plain-DNS structural
// negative check it would be misrouted to QUIC instead of the DNSCrypt
// cert-fetch fallback.
//
// The OPT TTL's high 16 bits are set to rdlen as well: the production check
// reads its rdlength at data[pos+9:pos+11] (the TTL field's first two bytes
// by wire format — rdlength actually sits at pos+13).  Setting both fields
// to rdlen keeps this query valid under the current code AND under the
// corrected offset, so the test survives either way.
func plainDNSQueryPadded() []byte {
	const total = 1200
	const rdlen = total - 32 // header(12)+qname(5)+qtype/qclass(4)+OPT fixed(11)
	pkt := make([]byte, total)
	pkt[0], pkt[1] = 0xC0, 0x12               // ID — high byte ≥ 0xC0 on purpose
	pkt[2], pkt[3] = 0x01, 0x00               // flags: RD
	binary.BigEndian.PutUint16(pkt[4:6], 1)   // QDCOUNT
	binary.BigEndian.PutUint16(pkt[10:12], 1) // ARCOUNT (one OPT)
	copy(pkt[12:], []byte{0x01, 'a', 0x01, 'b', 0x00})
	binary.BigEndian.PutUint16(pkt[17:19], 1)        // QTYPE A
	binary.BigEndian.PutUint16(pkt[19:21], 1)        // QCLASS IN
	const off = 21                                   // OPT record start
	pkt[off] = 0                                     // root name
	binary.BigEndian.PutUint16(pkt[off+1:off+3], 41) // OPT type
	binary.BigEndian.PutUint16(pkt[off+3:off+5], 1232)
	binary.BigEndian.PutUint16(pkt[off+5:off+7], rdlen)  // TTL high 16 bits (see note above)
	binary.BigEndian.PutUint16(pkt[off+9:off+11], rdlen) // OPT rdlength (wire offset)
	for i := off + 11; i < total; i++ {
		pkt[i] = byte(i)
	}
	return pkt
}

// recvOne waits for one recorded packet (positives arrive in milliseconds;
// the 2s bound only catches dead paths).
func recvOne(t *testing.T, ch <-chan recvPacket, what string) recvPacket {
	t.Helper()
	select {
	case p := <-ch:
		return p
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for %s packet", what)
		return recvPacket{}
	}
}

// recvNone asserts ch stays silent for a bounded window — the negative arm
// of classification checks.
func recvNone(t *testing.T, ch <-chan recvPacket, what string) {
	t.Helper()
	select {
	case p := <-ch:
		t.Fatalf("unexpected %s packet: % x", what, p.data)
	case <-time.After(150 * time.Millisecond):
	}
}

// dialUDP creates a connected client socket (unique source port → unique
// dispatch peer key) and closes it at the end of the (sub)test.
func dialUDP(t *testing.T, addr string) net.Conn {
	t.Helper()
	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatalf("dial udp %s: %v", addr, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}
