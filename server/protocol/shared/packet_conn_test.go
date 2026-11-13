// DemuxPacketConn unit tests: Send/Close race guards (sendMu + closed CAS),
// queue-full drop, deadline semantics (expiry, clear, replacement), the
// copyPacket short-buffer pool restoration, writes through the shared
// socket, and idle-client reaping across the per-protocol client maps.

package shared

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"zjdns/internal/pool"
)

func TestDemuxPacketConn_SendReceiveRoundTrip(t *testing.T) {
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5353}
	dc := &DemuxPacketConn{Remote: addr, Ch: make(chan DemuxPacket, 4)}

	pb := PacketBufPool.Get().(*[]byte)
	payload := []byte("demux-payload")
	copy(*pb, payload)
	if !dc.Send(DemuxPacket{Data: (*pb)[:len(payload)], Addr: addr}) {
		t.Fatal("Send on an open conn with queue space must succeed")
	}

	buf := make([]byte, 64)
	n, from, err := dc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if !bytes.Equal(buf[:n], payload) {
		t.Fatalf("payload mismatch: got %q, want %q", buf[:n], payload)
	}
	if from.String() != addr.String() {
		t.Fatalf("addr mismatch: got %v, want %v", from, addr)
	}
}

func TestDemuxPacketConn_CloseThenSendFails(t *testing.T) {
	dc := &DemuxPacketConn{Ch: make(chan DemuxPacket, 1)}
	if err := dc.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	pb := PacketBufPool.Get().(*[]byte)
	if dc.Send(DemuxPacket{Data: (*pb)[:10]}) {
		t.Fatal("Send after Close must report false, not panic")
	}
	PacketBufPool.Put(pb)

	if _, _, err := dc.ReadFrom(make([]byte, 8)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("ReadFrom after Close: got %v, want net.ErrClosed", err)
	}
	// Double close is idempotent (CAS guard).
	if err := dc.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

// sendPoolPayload Sends a payload backed by a fresh PacketBufPool buffer,
// honouring the DemuxPacketConn ownership contract: every queued Data slice
// must alias a pool buffer, because consumers return it to the pool via
// copyPacket/Close unconditionally.
func sendPoolPayload(t *testing.T, dc *DemuxPacketConn, payload []byte, addr net.Addr) {
	t.Helper()
	pb := PacketBufPool.Get().(*[]byte)
	copy(*pb, payload)
	if !dc.Send(DemuxPacket{Data: (*pb)[:len(payload)], Addr: addr}) {
		PacketBufPool.Put(pb)
		t.Fatal("Send must succeed")
	}
}

func TestDemuxPacketConn_FullQueueDrops(t *testing.T) {
	dc := &DemuxPacketConn{Ch: make(chan DemuxPacket, 1)}
	sendPoolPayload(t, dc, []byte("first"), nil)
	pb := PacketBufPool.Get().(*[]byte)
	if dc.Send(DemuxPacket{Data: (*pb)[:6]}) {
		t.Fatal("Send on a full queue must report false (drop, never block)")
	}
	PacketBufPool.Put(pb)
}

func TestDemuxPacketConn_CloseDrainsQueue(t *testing.T) {
	dc := &DemuxPacketConn{Ch: make(chan DemuxPacket, 8)}
	for range 4 {
		pb := PacketBufPool.Get().(*[]byte)
		copy(*pb, "queued")
		if !dc.Send(DemuxPacket{Data: (*pb)[:6]}) {
			t.Fatal("Send must succeed while the queue has room")
		}
	}
	if err := dc.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if queued := len(dc.Ch); queued != 0 {
		t.Fatalf("Close left %d queued packets behind, want 0 (drained to the pool)", queued)
	}
}

// TestDemuxPacketConn_ConcurrentSendAndClose drives Send, ReadFrom and Close
// concurrently: the sendMu + closed-CAS guard must keep every Send either
// landed or reported false — an unguarded send on the closed channel would
// panic (the bug the guard exists for), which -race and the crash itself
// surface.
func TestDemuxPacketConn_ConcurrentSendAndClose(t *testing.T) {
	dc := &DemuxPacketConn{Ch: make(chan DemuxPacket, 16)}

	const senders = 8
	const perSender = 64
	var sent, processed atomic.Int64
	var wg sync.WaitGroup
	for range senders {
		wg.Go(func() {
			for range perSender {
				pb := PacketBufPool.Get().(*[]byte)
				if dc.Send(DemuxPacket{Data: *pb}) {
					sent.Add(1)
				} else {
					PacketBufPool.Put(pb)
				}
				processed.Add(1)
			}
		})
	}

	// A concurrent reader drains the queue so most Sends succeed and truly
	// interleave with the closer; it exits once Close shuts the channel.
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		buf := make([]byte, pool.SecureBufferSize)
		for {
			if _, _, err := dc.ReadFrom(buf); err != nil {
				return
			}
		}
	}()

	// Close once a healthy amount of concurrency has been generated.
	go func() {
		for processed.Load() < 128 {
			time.Sleep(time.Millisecond)
		}
		_ = dc.Close()
	}()

	wg.Wait()
	<-readerDone

	// Two further concurrent Closes must both be absorbed by the CAS guard.
	var closers sync.WaitGroup
	for range 2 {
		closers.Go(func() {
			_ = dc.Close()
		})
	}
	closers.Wait()

	if _, _, err := dc.ReadFrom(make([]byte, 8)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("ReadFrom after concurrent Close: got %v, want net.ErrClosed", err)
	}
}

func TestDemuxPacketConn_ReadDeadline(t *testing.T) {
	dc := &DemuxPacketConn{Ch: make(chan DemuxPacket, 1)}

	// Expiry surfaces as os.ErrDeadlineExceeded.
	if err := dc.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	if _, _, err := dc.ReadFrom(make([]byte, 16)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("ReadFrom under an expired deadline: got %v, want os.ErrDeadlineExceeded", err)
	}

	// Clearing the deadline restores blocking reads.
	if err := dc.SetReadDeadline(time.Time{}); err != nil {
		t.Fatalf("SetReadDeadline(zero): %v", err)
	}
	sendPoolPayload(t, dc, []byte("after-clear"), nil)
	buf := make([]byte, 16)
	n, _, err := dc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom after deadline clear: %v", err)
	}
	if string(buf[:n]) != "after-clear" {
		t.Fatalf("payload mismatch: got %q", buf[:n])
	}

	// SetDeadline aliases the read deadline.
	if err := dc.SetDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	if _, _, err := dc.ReadFrom(buf); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("ReadFrom under an expired SetDeadline: got %v, want os.ErrDeadlineExceeded", err)
	}
}

// TestDemuxPacketConn_ReplacedDeadlineDoesNotAbortRead pins the `still`
// guard in ReadFrom.  A deadline whose channel closes AFTER it was replaced
// must not abort the read: the parked reader re-checks that the closed
// deadline channel is still the current one and loops onto the replacement.
// The injected deadline channel is closed by hand because the production
// reset path Stops the old timer — only a fire racing the replacement can
// produce a stale close, a window too narrow to orchestrate via timers.
func TestDemuxPacketConn_ReplacedDeadlineDoesNotAbortRead(t *testing.T) {
	dc := &DemuxPacketConn{Ch: make(chan DemuxPacket, 1)}

	staleDL := make(chan struct{})
	dc.dlMu.Lock()
	dc.dlCh = staleDL // no production timer — the test fires it manually
	dc.dlMu.Unlock()

	started := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		close(started)
		_, _, err := dc.ReadFrom(make([]byte, 32)) // parks on the injected deadline
		result <- err
	}()
	<-started
	time.Sleep(5 * time.Millisecond) // let the reader park before the swap

	// Replace the deadline, THEN fire the stale one.
	if err := dc.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline replacement: %v", err)
	}
	close(staleDL)

	sendPoolPayload(t, dc, []byte("still-alive"), nil)
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("ReadFrom returned %v — a replaced (stale) deadline leaked through", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ReadFrom never returned after the deadline replacement")
	}
}

// TestDemuxPacketConn_ShortBufferRestoresPoolBuffer covers copyPacket's two
// exits: the short-buffer error path and the happy path must both return the
// pooled datagram buffer at full SecureBufferSize length (restored from
// offset 0 via pkt.Data[:cap(pkt.Data)]).  A broken restoration surfaces in
// the drain sweep below as a short pool buffer.
func TestDemuxPacketConn_ShortBufferRestoresPoolBuffer(t *testing.T) {
	dc := &DemuxPacketConn{Ch: make(chan DemuxPacket, 8)}
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53}

	for range 8 {
		pb := PacketBufPool.Get().(*[]byte)
		const n = 1234
		for i := range n {
			(*pb)[i] = byte(i)
		}
		if !dc.Send(DemuxPacket{Data: (*pb)[:n], Addr: addr}) {
			t.Fatal("Send must succeed")
		}
		_, gotAddr, err := dc.ReadFrom(make([]byte, 64))
		if !errors.Is(err, io.ErrShortBuffer) {
			t.Fatalf("short read: got %v, want io.ErrShortBuffer", err)
		}
		if gotAddr.String() != addr.String() {
			t.Fatalf("addr mismatch on short buffer: got %v, want %v", gotAddr, addr)
		}
	}

	// Happy path restores too, and the data round-trips intact.
	pb := PacketBufPool.Get().(*[]byte)
	want := quicLongPacket(40)
	copy(*pb, want)
	if !dc.Send(DemuxPacket{Data: (*pb)[:len(want)], Addr: addr}) {
		t.Fatal("Send must succeed")
	}
	buf := make([]byte, 64)
	n, _, err := dc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if !bytes.Equal(buf[:n], want) {
		t.Fatalf("payload mismatch: got % x, want % x", buf[:n], want)
	}

	// Every buffer the pool hands back must be full-length: a restoration
	// bug (Put of the [:1234] sub-slice) leaks short buffers into the pool.
	for range 64 {
		b := PacketBufPool.Get().(*[]byte)
		if len(*b) != pool.SecureBufferSize {
			t.Fatalf("pool returned a %d-length buffer, want %d", len(*b), pool.SecureBufferSize)
		}
	}
}

func TestDemuxPacketConn_WriteToSendsViaSharedSocket(t *testing.T) {
	shared, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen shared: %v", err)
	}
	t.Cleanup(func() { _ = shared.Close() })
	peer, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen peer: %v", err)
	}
	t.Cleanup(func() { _ = peer.Close() })

	dc := &DemuxPacketConn{
		Shared: shared,
		Remote: peer.LocalAddr(),
		Ch:     make(chan DemuxPacket, 1),
	}
	if _, err := dc.WriteTo([]byte("reply"), peer.LocalAddr()); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if err := peer.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("peer SetReadDeadline: %v", err)
	}
	buf := make([]byte, 32)
	n, from, err := peer.ReadFrom(buf)
	if err != nil {
		t.Fatalf("peer ReadFrom: %v", err)
	}
	if string(buf[:n]) != "reply" {
		t.Fatalf("payload mismatch: got %q", buf[:n])
	}
	// The reply must carry the shared listener's address — the client always
	// sees the shared port, never an ephemeral one.
	if from.String() != shared.LocalAddr().String() {
		t.Fatalf("reply source %v, want shared socket %v", from, shared.LocalAddr())
	}
	if dc.LocalAddr().String() != shared.LocalAddr().String() {
		t.Errorf("LocalAddr: got %v, want %v", dc.LocalAddr(), shared.LocalAddr())
	}
	if dc.RemoteAddr().String() != peer.LocalAddr().String() {
		t.Errorf("RemoteAddr: got %v, want %v", dc.RemoteAddr(), peer.LocalAddr())
	}
}

// TestReapIdleUDPClients covers the dispatch-loop reaper across all three
// per-client maps: conns silent since before the cutoff are closed and
// forgotten (their queued pool buffers drained), fresh conns survive and
// stay usable.
func TestReapIdleUDPClients(t *testing.T) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	dtlsPL := newDTLSPacketListener(conn)
	dcState := &sharedDNSCryptClient{conns: make(map[addrKey]*DemuxPacketConn)}
	dtlcpState := &sharedDTLSClient{conns: make(map[addrKey]*DemuxPacketConn)}

	now := time.Now().Unix()
	stale := now - int64(clientIdleTimeout/time.Second) - 5
	remote := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}

	newDemux := func(lastSeen int64, queuePacket bool) *DemuxPacketConn {
		dc := &DemuxPacketConn{Shared: conn, Remote: remote, Ch: make(chan DemuxPacket, 4)}
		dc.lastSeen.Store(lastSeen)
		if queuePacket {
			pb := PacketBufPool.Get().(*[]byte)
			copy(*pb, "queued-datagram")
			dc.Ch <- DemuxPacket{Data: (*pb)[:16], Addr: remote}
		}
		return dc
	}
	peerKey := func(port int) addrKey {
		return makeAddrKey(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	}

	dcStale := newDemux(stale, true)
	dcFresh := newDemux(now, false)
	dcState.conns[peerKey(1111)] = dcStale
	dcState.conns[peerKey(1112)] = dcFresh

	tlStale := newDemux(stale, true)
	tlFresh := newDemux(now, false)
	dtlcpState.conns[peerKey(2111)] = tlStale
	dtlcpState.conns[peerKey(2112)] = tlFresh

	dtlsStale := &dtlsClientConn{ch: make(chan packetBuf, 4), shared: conn, remote: remote}
	dtlsStale.lastSeen.Store(stale)
	pb := PacketBufPool.Get().(*[]byte)
	dtlsStale.ch <- packetBuf{data: *pb, src: remote, n: 32}
	dtlsFresh := &dtlsClientConn{ch: make(chan packetBuf, 4), shared: conn, remote: remote}
	dtlsFresh.lastSeen.Store(now)
	dtlsPL.clients[peerKey(3333)] = dtlsStale
	dtlsPL.clients[peerKey(3334)] = dtlsFresh

	reapIdleUDPClients(dtlcpState, dcState, dtlsPL, now-int64(clientIdleTimeout/time.Second))

	if len(dcState.conns) != 1 || len(dtlcpState.conns) != 1 || len(dtlsPL.clients) != 1 {
		t.Fatalf("reap left %d/%d/%d conns, want 1/1/1 (stale must go, fresh must stay)",
			len(dcState.conns), len(dtlcpState.conns), len(dtlsPL.clients))
	}
	if _, _, err := dcStale.ReadFrom(make([]byte, 8)); !errors.Is(err, net.ErrClosed) {
		t.Errorf("stale DNSCrypt conn not closed: %v", err)
	}
	if _, _, err := tlStale.ReadFrom(make([]byte, 8)); !errors.Is(err, net.ErrClosed) {
		t.Errorf("stale DTLCP conn not closed: %v", err)
	}
	if _, ok := <-dtlsStale.ch; ok {
		t.Error("stale DTLS conn channel not closed")
	}

	sendPoolPayload(t, dcFresh, []byte("alive"), remote)
	sendPoolPayload(t, tlFresh, []byte("alive"), remote)
	select {
	case dtlsFresh.ch <- packetBuf{}:
	default:
		t.Error("fresh DTLS conn channel must remain open after reap")
	}
}
