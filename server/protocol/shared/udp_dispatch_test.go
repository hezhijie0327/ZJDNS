// Dispatch-layer tests over a real UDP socket + udpDispatchLoop: the
// classification ladder (DNSCrypt magic priority, plain-DNS structural
// negative check, QUIC long/short headers, DTLS/DTLCP records, unknown drop,
// per-peer caching), and the two-shard SO_REUSEPORT group semantics of
// startUDPGroup (dual-protocol routing, cross-shard reachability, per-client
// affinity, shared flood semaphore, shutdown).

package shared

import (
	"bytes"
	"context"
	"net"
	"runtime"
	"strconv"
	"testing"
	"time"
	"zjdns/config"
	"zjdns/internal/demux"
)

// TestUDPDispatchClassification walks the classification ladder on a live
// shard.  Each subtest uses its own client socket, so every case exercises
// first-datagram classification (the per-peer cache is covered explicitly).
func TestUDPDispatchClassification(t *testing.T) {
	m, host := newTestMux(t)
	sem := make(chan struct{}, config.DefaultServerGoroutineLimit)

	quicRecv := make(chan recvPacket, 64)
	dcRecv := make(chan recvPacket, 64)
	dtlsRecv := make(chan recvPacket, 64)
	dtlcpRecv := make(chan recvPacket, 64)

	g := &UDPGroup{
		Port:             "classification-test",
		DOQHandler:       fakeQUICReader(quicRecv),
		DTLSHandler:      fakeDTLSHandler(dtlsRecv),
		ServeDTLCP:       fakeDTLCPHandler(dtlcpRecv),
		ServeDNSCrypt:    fakeDNSCryptHandler(dcRecv),
		ClassifyDNSCrypt: testClassifier,
	}
	rt := launchUDPShardRuntime(t, m, host, g, "127.0.0.1:0", sem)
	srvAddr := rt.conn.LocalAddr().String()

	// A second, HTTP3-only group (no DoQ handler, no DNSCrypt fallback) for
	// the QUIC→H3 fallback branch and the unknown-protocol drop.
	h3Recv := make(chan recvPacket, 64)
	h3g := &UDPGroup{
		Port:         "h3-fallback-test",
		HTTP3Handler: fakeQUICReader(h3Recv),
	}
	h3rt := launchUDPShardRuntime(t, m, host, h3g, "127.0.0.1:0", sem)
	h3Addr := h3rt.conn.LocalAddr().String()

	t.Run("dnscrypt magic beats quic long header", func(t *testing.T) {
		// 1300-byte magic packet whose first byte (0xC3 ≥ 0xC0) and size
		// satisfy the QUIC long-header rule — the ClassifyDNSCrypt priority
		// must route it to DNSCrypt, not QUIC.
		c := dialUDP(t, srvAddr)
		if _, err := c.Write(dnscryptMagicPacket(1300)); err != nil {
			t.Fatalf("write: %v", err)
		}
		p := recvOne(t, dcRecv, "DNSCrypt")
		if !bytes.Equal(p.data[:len(testMagic)], testMagic) {
			t.Fatalf("payload missing magic prefix: % x", p.data[:len(testMagic)])
		}
		recvNone(t, quicRecv, "QUIC")
	})

	t.Run("quic long header routed to doq", func(t *testing.T) {
		c := dialUDP(t, srvAddr)
		if _, err := c.Write(quicLongPacket(1200)); err != nil {
			t.Fatalf("write: %v", err)
		}
		p := recvOne(t, quicRecv, "QUIC")
		if len(p.data) != 1200 || p.data[0] != 0xC3 {
			t.Fatalf("payload mismatch: len=%d first=%#x", len(p.data), p.data[0])
		}
		recvNone(t, dcRecv, "DNSCrypt")
	})

	t.Run("quic short header is not quic", func(t *testing.T) {
		// First byte 0x40 (short header form) must not classify as QUIC;
		// with DNSCrypt configured it takes the fallback route.
		c := dialUDP(t, srvAddr)
		if _, err := c.Write([]byte{0x40, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19}); err != nil {
			t.Fatalf("write: %v", err)
		}
		recvOne(t, dcRecv, "DNSCrypt fallback")
		recvNone(t, quicRecv, "QUIC")
	})

	t.Run("plain dns padded to quic size stays out of quic", func(t *testing.T) {
		// A structurally valid EDNS query padded to exactly 1200 bytes with
		// ID high byte 0xC0: without the plain-DNS negative check it would
		// classify as QUIC (cert-fetch misroute); it must reach the DNSCrypt
		// fallback intact.
		q := plainDNSQueryPadded()
		if got := demux.DetectUDPProtocol(q); got != "" {
			t.Fatalf("sanity: DetectUDPProtocol classified the padded query as %q", got)
		}
		c := dialUDP(t, srvAddr)
		if _, err := c.Write(q); err != nil {
			t.Fatalf("write: %v", err)
		}
		p := recvOne(t, dcRecv, "DNSCrypt cert-fetch fallback")
		if !bytes.Equal(p.data, q) {
			t.Fatalf("fallback payload mismatch: got %d bytes, want %d", len(p.data), len(q))
		}
		recvNone(t, quicRecv, "QUIC")
	})

	t.Run("minimal plain dns query routed to dnscrypt fallback", func(t *testing.T) {
		c := dialUDP(t, srvAddr)
		if _, err := c.Write(plainDNSQueryMinimal()); err != nil {
			t.Fatalf("write: %v", err)
		}
		recvOne(t, dcRecv, "DNSCrypt cert-fetch fallback")
		recvNone(t, quicRecv, "QUIC")
	})

	t.Run("dtls handshake routed to dtls handler", func(t *testing.T) {
		c := dialUDP(t, srvAddr)
		if _, err := c.Write([]byte{0x16, 0xFE, 0xFD, 0x00, 0x00, 'h', 'e', 'l', 'l', 'o'}); err != nil {
			t.Fatalf("write: %v", err)
		}
		recvOne(t, dtlsRecv, "DTLS")
		recvNone(t, dcRecv, "DNSCrypt")
	})

	t.Run("dtlcp handshake routed to dtlcp handler", func(t *testing.T) {
		c := dialUDP(t, srvAddr)
		if _, err := c.Write([]byte{0x16, 0x01, 0x01, 0x00, 0x00, 't', 'l', 'c', 'p'}); err != nil {
			t.Fatalf("write: %v", err)
		}
		recvOne(t, dtlcpRecv, "DTLCP")
		recvNone(t, dcRecv, "DNSCrypt")
	})

	t.Run("classification cached per peer", func(t *testing.T) {
		// The first datagram classifies the peer as DNSCrypt; a subsequent
		// QUIC-shaped datagram from the SAME source must stay on the cached
		// protocol.
		c := dialUDP(t, srvAddr)
		if _, err := c.Write(dnscryptMagicPacket(64)); err != nil {
			t.Fatalf("write 1: %v", err)
		}
		recvOne(t, dcRecv, "DNSCrypt")
		if _, err := c.Write(quicLongPacket(1200)); err != nil {
			t.Fatalf("write 2: %v", err)
		}
		recvOne(t, dcRecv, "DNSCrypt (cached classification)")
		recvNone(t, quicRecv, "QUIC")
	})

	t.Run("quic without doq handler falls back to http3", func(t *testing.T) {
		c := dialUDP(t, h3Addr)
		if _, err := c.Write(quicLongPacket(1200)); err != nil {
			t.Fatalf("write: %v", err)
		}
		recvOne(t, h3Recv, "HTTP3 (QUIC fallback)")
	})

	t.Run("unknown protocol dropped without dnscrypt fallback", func(t *testing.T) {
		c := dialUDP(t, h3Addr)
		junk := make([]byte, 200)
		junk[0], junk[2] = 0x30, 0x77 // not record-shaped, not plain DNS
		if _, err := c.Write(junk); err != nil {
			t.Fatalf("write: %v", err)
		}
		recvNone(t, h3Recv, "HTTP3")
	})
}

// TestUDPGroup_TwoShardRouting exercises startUDPGroup's shard semantics on
// a shared SO_REUSEPORT port with two shards and two protocols (DoQ +
// DNSCrypt): every datagram reaches the right protocol handler regardless of
// shard, both shards receive traffic, and one client's datagrams never
// migrate between shards (per-client affinity — the property per-shard
// protocol state relies on).
func TestUDPGroup_TwoShardRouting(t *testing.T) {
	if !ReusePortSupported() {
		t.Skip("SO_REUSEPORT unavailable — dispatch collapses to a single shard")
	}
	m, host := newTestMux(t)
	sem := make(chan struct{}, 16)

	var quicShards, dcShards [2]chan recvPacket
	for i := range quicShards {
		quicShards[i] = make(chan recvPacket, 256)
		dcShards[i] = make(chan recvPacket, 64)
	}

	base := UDPGroup{Port: "two-shard-test", ClassifyDNSCrypt: testClassifier}
	g0 := base
	g0.DOQHandler = fakeQUICReader(quicShards[0])
	g0.ServeDNSCrypt = fakeDNSCryptHandler(dcShards[0])
	g1 := base
	g1.DOQHandler = fakeQUICReader(quicShards[1])
	g1.ServeDNSCrypt = fakeDNSCryptHandler(dcShards[1])

	rt0 := launchUDPShardRuntime(t, m, host, &g0, "127.0.0.1:0", sem)
	port := rt0.conn.LocalAddr().(*net.UDPAddr).Port
	launchUDPShardRuntime(t, m, host, &g1, net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), sem)
	srvAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))

	// 32 distinct QUIC clients: every packet must arrive, across both shards.
	for range 32 {
		c := dialUDP(t, srvAddr)
		if _, err := c.Write(quicLongPacket(1200)); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	var shardHits [2]int
	for received := 0; received < 32; {
		select {
		case p := <-quicShards[0]:
			shardHits[0]++
			received++
			if p.data[0] != 0xC3 {
				t.Fatalf("shard 0 received a non-QUIC datagram: %#x", p.data[0])
			}
		case p := <-quicShards[1]:
			shardHits[1]++
			received++
			if p.data[0] != 0xC3 {
				t.Fatalf("shard 1 received a non-QUIC datagram: %#x", p.data[0])
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("received %d/32 QUIC packets (shards: %d/%d)", received, shardHits[0], shardHits[1])
		}
	}
	// Cross-shard coverage: Linux hashes each 4-tuple across the reuseport
	// group, so both shards must see traffic.  Darwin collapses reuseport
	// delivery to a single socket (verified empirically), so coverage is only
	// logged there.
	if runtime.GOOS == "linux" && (shardHits[0] == 0 || shardHits[1] == 0) {
		t.Fatalf("one shard received no traffic (%d/%d) — sharding broken", shardHits[0], shardHits[1])
	}
	t.Logf("QUIC shard distribution: %d/%d", shardHits[0], shardHits[1])

	// 8 DNSCrypt clients land across the shards; the payload round-trips.
	for i := range 8 {
		c := dialUDP(t, srvAddr)
		if _, err := c.Write(dnscryptMagicPacket(64 + i)); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	for range 8 {
		var p recvPacket
		select {
		case p = <-dcShards[0]:
		case p = <-dcShards[1]:
		case <-time.After(2 * time.Second):
			t.Fatal("timeout waiting for DNSCrypt packet across shards")
		}
		if !bytes.Equal(p.data[:len(testMagic)], testMagic) {
			t.Fatalf("DNSCrypt payload missing magic: % x", p.data[:len(testMagic)])
		}
	}

	// Per-client affinity: six datagrams from one socket all land on the
	// same shard's handler.
	affinity := dialUDP(t, srvAddr)
	for range 6 {
		if _, err := affinity.Write(quicLongPacket(1250)); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	var affShard [2]int
	for received := 0; received < 6; {
		select {
		case <-quicShards[0]:
			affShard[0]++
			received++
		case <-quicShards[1]:
			affShard[1]++
			received++
		case <-time.After(2 * time.Second):
			t.Fatalf("affinity: received %d/6", received)
		}
	}
	if affShard[0] != 6 && affShard[1] != 6 {
		t.Fatalf("client migrated between shards: %d/%d", affShard[0], affShard[1])
	}
}

// TestUDPGroup_ClientSemSharedAcrossShards pins the flood-bound contract:
// the per-client admission semaphore is shared across shards, so with two
// slots and three clients the third client's datagram is dropped no matter
// which shard its 4-tuple hashes to.  Each admission is awaited before the
// next client fires, making the drop deterministic.
func TestUDPGroup_ClientSemSharedAcrossShards(t *testing.T) {
	if !ReusePortSupported() {
		t.Skip("SO_REUSEPORT unavailable — dispatch collapses to a single shard")
	}
	m, host := newTestMux(t)
	sem := make(chan struct{}, 2)

	admitted := make(chan string, 4)
	handler := func(ctx context.Context, _ []byte, src net.Addr, _ net.PacketConn) {
		admitted <- src.String()
		<-ctx.Done() // hold the per-client slot until teardown
	}
	base := UDPGroup{Port: "sem-test", ServeDNSCrypt: handler, ClassifyDNSCrypt: testClassifier}
	g0, g1 := base, base
	rt0 := launchUDPShardRuntime(t, m, host, &g0, "127.0.0.1:0", sem)
	port := rt0.conn.LocalAddr().(*net.UDPAddr).Port
	launchUDPShardRuntime(t, m, host, &g1, net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), sem)
	srvAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))

	for i := range 3 {
		c := dialUDP(t, srvAddr)
		if _, err := c.Write(dnscryptMagicPacket(64)); err != nil {
			t.Fatalf("client %d write: %v", i, err)
		}
		if i < 2 {
			select {
			case <-admitted:
			case <-time.After(2 * time.Second):
				t.Fatalf("client %d not admitted within 2s", i)
			}
		}
	}
	select {
	case src := <-admitted:
		t.Fatalf("third client admitted despite a full shared semaphore: %v", src)
	case <-time.After(200 * time.Millisecond):
	}
}

// TestUDPGroup_ShutdownStopsAllGoroutines verifies the shutdown chain on a
// two-shard group with live per-client state: closing the runtimes unblocks
// the dispatch loops (whose exit sweep closes every per-client conn) and the
// protocol handlers, so the host's WaitGroup drains without hanging.
func TestUDPGroup_ShutdownStopsAllGoroutines(t *testing.T) {
	if !ReusePortSupported() {
		t.Skip("SO_REUSEPORT unavailable — dispatch collapses to a single shard")
	}
	m, host := newTestMux(t)
	sem := make(chan struct{}, 8)

	quicRecv := make(chan recvPacket, 16)
	dcRecv := make(chan recvPacket, 16)
	base := UDPGroup{
		Port:             "shutdown-test",
		ClassifyDNSCrypt: testClassifier,
		DOQHandler:       fakeQUICReader(quicRecv),
		ServeDNSCrypt:    fakeDNSCryptHandler(dcRecv),
	}
	g0, g1 := base, base
	rt0 := launchUDPShardRuntime(t, m, host, &g0, "127.0.0.1:0", sem)
	port := rt0.conn.LocalAddr().(*net.UDPAddr).Port
	launchUDPShardRuntime(t, m, host, &g1, net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), sem)
	srvAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))

	// One QUIC client plus two DNSCrypt clients (the second leaves its
	// per-client drain goroutine parked on the queue — the exit sweep must
	// close it).
	c := dialUDP(t, srvAddr)
	if _, err := c.Write(quicLongPacket(1200)); err != nil {
		t.Fatalf("write QUIC: %v", err)
	}
	recvOne(t, quicRecv, "QUIC")
	for range 2 {
		dc := dialUDP(t, srvAddr)
		if _, err := dc.Write(dnscryptMagicPacket(80)); err != nil {
			t.Fatalf("write DNSCrypt: %v", err)
		}
		recvOne(t, dcRecv, "DNSCrypt")
	}

	m.Shutdown()
	host.cancel()
	if !host.wait(2 * time.Second) {
		t.Fatal("shared-port goroutines still running 2s after shutdown")
	}
}
