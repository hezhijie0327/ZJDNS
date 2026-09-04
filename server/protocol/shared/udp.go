package shared

import (
	"net"
	"sync"
	"sync/atomic"
	"zjdns/internal/log"
)

type dtlsAcceptResult struct {
	conn net.PacketConn
	addr net.Addr
}

type dtlsPacketListener struct {
	udpConn  *net.UDPConn
	acceptCh chan dtlsAcceptResult
	mu       sync.Mutex
	clients  map[addrKey]*dtlsClientConn
	closed   atomic.Bool
	done     chan struct{}
}

type sharedDTLSClient struct {
	mu    sync.Mutex
	conns map[addrKey]*DemuxPacketConn
}

type sharedDNSCryptClient struct {
	mu    sync.Mutex
	conns map[addrKey]*DemuxPacketConn
}

// ---------------------------------------------------------------------------
// Vars
// ---------------------------------------------------------------------------

func newDTLSPacketListener(udpConn *net.UDPConn) *dtlsPacketListener {
	return &dtlsPacketListener{
		udpConn:  udpConn,
		acceptCh: make(chan dtlsAcceptResult, 64),
		clients:  make(map[addrKey]*dtlsClientConn),
		done:     make(chan struct{}),
	}
}

func (l *dtlsPacketListener) Accept() (net.PacketConn, net.Addr, error) {
	select {
	case r, ok := <-l.acceptCh:
		if !ok {
			return nil, nil, net.ErrClosed
		}
		return r.conn, r.addr, nil
	case <-l.done:
		return nil, nil, net.ErrClosed
	}
}

func (l *dtlsPacketListener) Close() error {
	if l.closed.CompareAndSwap(false, true) {
		close(l.done)
		l.mu.Lock()
		for _, c := range l.clients {
			_ = c.Close()
		}
		l.mu.Unlock()
	}
	return nil
}

func (l *dtlsPacketListener) Addr() net.Addr { return l.udpConn.LocalAddr() }

// dispatch routes a DTLS datagram to the per-client channel, creating a
// new client connection (and Accept entry) on first sight.
// Ownership of the pooled buffer pb transfers to the client channel (no
// second copy); pb is returned to the pool only on drop/closed paths.
func (l *dtlsPacketListener) dispatch(src *net.UDPAddr, pb *[]byte, n int) {
	key := makeAddrKey(src)

	l.mu.Lock()
	cc, ok := l.clients[key]
	if !ok {
		cc = &dtlsClientConn{
			ch:     make(chan packetBuf, 32),
			shared: l.udpConn,
			remote: src,
		}
		l.clients[key] = cc
		l.mu.Unlock()

		select {
		case l.acceptCh <- dtlsAcceptResult{conn: cc, addr: src}:
		default:
		}
	} else {
		l.mu.Unlock()
	}

	cc.lastSeen.Store(log.NowUnix())
	cc.sendMu.Lock()
	if cc.closed.Load() {
		cc.sendMu.Unlock()
		PacketBufPool.Put(pb)
		return
	}
	select {
	case cc.ch <- packetBuf{data: *pb, src: src, n: n}:
	default:
		PacketBufPool.Put(pb)
	}
	cc.sendMu.Unlock()
}

// ---------------------------------------------------------------------------
// QUIC packet conn
// ---------------------------------------------------------------------------
