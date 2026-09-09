package plain

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"zjdns/config"
	zdnsutil "zjdns/internal/dnsutil"
	"zjdns/internal/log"
	"zjdns/internal/pool"
	shared "zjdns/server/protocol/shared"

	"codeberg.org/miekg/dns"
)

// udpDatagram is one received datagram handed from a shard read loop to a
// worker.  buf is a shared.PacketBufPool buffer — ownership moves with the
// struct; the worker returns it after serving.
type udpDatagram struct {
	conn *net.UDPConn
	buf  *[]byte
	n    int
	src  *net.UDPAddr
}

// udpListener serves plain DNS over UDP on sharded REUSEPORT sockets feeding
// a fixed worker pool — replacing the fork dns.Server loop (single-socket
// read + goroutine per datagram), whose measured ceiling was ~108k QPS with
// ~40% of CPU in per-packet goroutine scheduling.  The kernel hashes each
// client 4-tuple to one shard, so per-client affinity holds.
type udpListener struct {
	handler dns.Handler
	ctx     context.Context

	conns     []*net.UDPConn
	readWG    sync.WaitGroup
	workerWG  sync.WaitGroup
	work      chan udpDatagram
	drops     atomic.Uint64
	closeOnce sync.Once
}

// udpResponseWriter adapts a shard socket + per-query session to the fork's
// dns.ResponseWriter so the server bridge (pack, EDNS size clamp, TC
// truncation, response write) runs unchanged on the hand-rolled path.
// Worker-local: conn and sess fields are swapped per datagram.
type udpResponseWriter struct {
	conn *net.UDPConn
	sess *dns.Session
}

// startUDP launches the hand-rolled sharded UDP listener serving udpHandler
// (the server bridge).  The listener's design rationale lives in udpListener.
func (s *Server) startUDP(g Group, ctx context.Context, handler dns.Handler) error {
	if s.config.Server.Protocol.UDP == "" {
		return nil
	}

	addrs, err := zdnsutil.ResolveBindAddrs(config.ProtoUDP, s.config.Server.Protocol.UDP)
	if err != nil {
		return fmt.Errorf("UDP address resolution: %w", err)
	}
	shards := 1
	if shared.ReusePortSupported() {
		shards = config.DefaultUDPDispatchShards
	}

	l := &udpListener{
		handler: handler,
		ctx:     ctx,
		work:    make(chan udpDatagram, config.DefaultServerGoroutineLimit),
	}
	for _, addr := range addrs {
		for range shards {
			var lc net.ListenConfig
			if shards > 1 {
				lc = net.ListenConfig{Control: shared.ReusePortControl()}
			}
			pc, err := lc.ListenPacket(ctx, "udp", addr)
			if err != nil {
				l.stop()
				return fmt.Errorf("UDP listen on %s: %w", addr, err)
			}
			l.conns = append(l.conns, pc.(*net.UDPConn))
		}
	}
	s.udp = l
	l.start(g)
	log.Infof("PLAIN: UDP server started on %v (shards=%d workers=%d)", addrs, shards, config.DefaultServerGoroutineLimit)
	return nil
}

// start launches the read loops (one per shard socket) and the shared worker
// pool.  Must be called once; stop must be called on ctx cancellation.
func (l *udpListener) start(g Group) {
	for range config.DefaultServerGoroutineLimit {
		l.workerWG.Go(func() {
			l.workerLoop()
		})
	}
	for _, conn := range l.conns {
		l.readWG.Add(1)
		go func(conn *net.UDPConn) {
			defer l.readWG.Done()
			l.readLoop(conn)
		}(conn)
	}
	g.Go(func() error {
		defer zdnsutil.HandlePanic("UDP server")
		<-l.ctx.Done()
		l.stop()
		return nil
	})
}

// stop closes the shard sockets (unblocking the read loops), then closes the
// work channel once every read loop has exited so workers drain in-flight
// datagrams before exiting.
func (l *udpListener) stop() {
	l.closeOnce.Do(func() {
		for _, conn := range l.conns {
			_ = conn.Close()
		}
		l.readWG.Wait()
		close(l.work)
		l.workerWG.Wait()
		if n := l.drops.Load(); n > 0 {
			log.Warnf("PLAIN: UDP dispatch dropped %d datagrams under worker saturation", n)
		}
		log.Infof("PLAIN: UDP server(s) shut down")
	})
}

// readLoop reads datagrams directly into pooled buffers and hands them to the
// worker pool.  Read bound is pool.SecureBufferSize (8 KiB) — Go's
// ReadFromUDP silently truncates larger datagrams and the parse then fails to
// a silent drop, matching (and exceeding) the fork's 1232-byte read bound.
func (l *udpListener) readLoop(conn *net.UDPConn) {
	for {
		select {
		case <-l.ctx.Done():
			return
		default:
		}
		pb := shared.PacketBufPool.Get().(*[]byte)
		n, src, err := conn.ReadFromUDP(*pb)
		if err != nil {
			shared.PacketBufPool.Put(pb)
			select {
			case <-l.ctx.Done():
				return
			default:
			}
			if zdnsutil.IsTemporaryError(err) {
				continue
			}
			log.Debugf("PLAIN: UDP read error: %v", err)
			return
		}
		select {
		case l.work <- udpDatagram{conn: conn, buf: pb, n: n, src: src}:
		default:
			// Worker pool saturated — drop; a DNS client retransmits.
			shared.PacketBufPool.Put(pb)
			l.drops.Add(1)
		}
	}
}

// workerLoop serves datagrams until the work channel closes.
func (l *udpListener) workerLoop() {
	w := &udpResponseWriter{}
	sess := &dns.Session{}
	for d := range l.work {
		l.process(d, w, sess)
	}
}

// process serves one datagram, recovering panics so a bad query cannot kill
// a pool worker; the buffer returns to the pool on every path.
func (l *udpListener) process(d udpDatagram, w *udpResponseWriter, sess *dns.Session) {
	defer zdnsutil.HandlePanic("UDP query worker")
	defer shared.PacketBufPool.Put(d.buf)
	w.conn, w.sess = d.conn, sess
	sess.Addr, sess.OOB = d.src, nil
	l.serveDatagram(w, (*d.buf)[:d.n])
}

// serveDatagram runs the accept/reject semantics of the fork's serveDNS on a
// fully parsed message and hands accepted queries to the server bridge.
func (l *udpListener) serveDatagram(w *udpResponseWriter, data []byte) {
	req := pool.DefaultMessage.Get()
	req.Data = data
	if err := req.Unpack(); err != nil {
		// Unparseable: the fork's DefaultMsgInvalidFunc is a noop — drop.
		pool.DefaultMessage.Put(req)
		return
	}
	switch action := dns.DefaultMsgAcceptFunc(req); action {
	case dns.MsgAccept:
	case dns.MsgIgnore:
		pool.DefaultMessage.Put(req)
		return
	case dns.MsgReject, dns.MsgRejectNotImplemented, dns.MsgRejectRefused:
		switch action {
		case dns.MsgRejectNotImplemented:
			req.Rcode = dns.RcodeNotImplemented
		case dns.MsgRejectRefused:
			req.Rcode = dns.RcodeRefused
		default:
			req.Rcode = dns.RcodeFormatError
		}
		req.Response = true
		req.Authoritative = false
		req.Zero = false
		req.Reset() // clears the RR sections; header (ID/opcode/QR) survives
		if err := req.Pack(); err != nil {
			pool.DefaultMessage.Put(req)
			return
		}
		_, _ = req.WriteTo(w)
		pool.DefaultMessage.Put(req)
		return
	}
	l.handler.ServeDNS(l.ctx, w, req)
	// The bridge is synchronous and retains nothing past ServeDNS, so both
	// the message and its wire (a PacketBufPool buffer) recycle here.
	pool.DefaultMessage.Put(req)
}

func (w *udpResponseWriter) LocalAddr() net.Addr   { return w.conn.LocalAddr() }
func (w *udpResponseWriter) RemoteAddr() net.Addr  { return w.sess.Addr }
func (w *udpResponseWriter) Conn() net.Conn        { return w.conn }
func (w *udpResponseWriter) Session() *dns.Session { return w.sess }
func (w *udpResponseWriter) Close() error          { return nil }
func (w *udpResponseWriter) Hijack()               {}

// Write routes through WriteMsgUDP with the session address; OOB is nil —
// the kernel selects the reply source (same as the shared-port dispatch).
func (w *udpResponseWriter) Write(b []byte) (int, error) {
	n, _, err := w.conn.WriteMsgUDP(b, nil, w.sess.Addr)
	return n, err
}
