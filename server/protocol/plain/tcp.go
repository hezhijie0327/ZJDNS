package plain

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
	"zjdns/config"
	"zjdns/edns"
	zdnsutil "zjdns/internal/dnsutil"
	"zjdns/internal/log"
	"zjdns/internal/pool"

	"codeberg.org/miekg/dns"
)

// tcpConnBufferSize is the buffer size for TCP connection readers (mirrors
// the DoT reader buffer).
const tcpConnBufferSize = 4096

// startTCP runs a hand-rolled DNS-over-TCP accept/read loop modelled on the
// DoT implementation (server/protocol/tls): pooled frame buffers, a dedicated
// writer goroutine per connection, and bounded per-query workers — so
// pipelined TCP clients get out-of-order responses and zero per-frame
// allocations. The former miekg/dns-managed listener processed each
// connection strictly inline (read→serve→write), capping single-client
// throughput at ~1/5 of DoT.
func (s *Server) startTCP(g Group, ctx context.Context, handler edns.DNSHandler) error {
	if s.config.Server.Protocol.TCP == "" {
		return nil
	}

	addrs, err := zdnsutil.ResolveBindAddrs("tcp", s.config.Server.Protocol.TCP)
	if err != nil {
		return fmt.Errorf("TCP address resolution: %w", err)
	}
	log.Infof("PLAIN: TCP server started on %v", addrs)
	s.tcpMu.Lock()
	s.tcpConns = make(map[net.Conn]struct{})
	s.tcpMu.Unlock()
	// Note: if one bind address fails, previously started listeners continue
	// serving. The caller should cancel the context to stop them.
	for _, addr := range addrs {
		listener, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("TCP listen on %s: %w", addr, err)
		}
		// The accept loop below spawns one goroutine per connection — cap
		// concurrent connections at the listener (new connections queue in
		// the kernel backlog at the cap).
		limited := zdnsutil.NewLimitListener(&zdnsutil.TCPKeepAliveListener{Listener: listener}, config.DefaultServerGoroutineLimit)
		s.tcpMu.Lock()
		s.tcpListeners = append(s.tcpListeners, listener)
		s.tcpMu.Unlock()
		captured := limited
		g.Go(func() error {
			defer zdnsutil.HandlePanic("TCP server")
			s.acceptTCP(ctx, captured, handler)
			return nil
		})
	}
	return nil
}

// acceptTCP accepts connections until ctx is cancelled.
func (s *Server) acceptTCP(ctx context.Context, listener net.Listener, handler edns.DNSHandler) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Debugf("PLAIN: TCP Accept failed: %v (type=%T)", err, err)
			time.Sleep(config.DefaultAcceptRetryDelay)
			continue
		}

		if tcpConn, ok := conn.(*net.TCPConn); ok {
			_ = tcpConn.SetKeepAlive(true)
			_ = tcpConn.SetKeepAlivePeriod(config.DefaultTCPKeepAlivePeriod)
		}

		s.tcpMu.Lock()
		if s.tcpClosed {
			// Shutdown won between the Accept and this insert — the map is
			// gone; close the conn here or its fd leaks.
			s.tcpMu.Unlock()
			_ = conn.Close()
			return
		}
		s.tcpConns[conn] = struct{}{}
		s.tcpMu.Unlock()

		go func() {
			defer zdnsutil.HandlePanic("TCP connection handler")
			defer func() {
				s.tcpMu.Lock()
				delete(s.tcpConns, conn)
				s.tcpMu.Unlock()
				_ = conn.Close()
			}()
			s.handleTCPConnection(ctx, conn, handler)
		}()
	}
}

// handleTCPConnection reads length-prefixed DNS frames and serves each query
// on a bounded worker goroutine; responses go through a dedicated writer
// goroutine (full RFC 7766 pipelining).
func (s *Server) handleTCPConnection(ctx context.Context, conn net.Conn, handler edns.DNSHandler) {
	reader := bufio.NewReaderSize(conn, tcpConnBufferSize)
	connCtx, connCancel := context.WithCancel(ctx)
	defer connCancel()

	type writeTask struct {
		data   []byte
		pooled bool // true if data aliases a pool.DefaultBuffer allocation
	}
	writeCh := make(chan writeTask, config.DefaultDOTWriteChannelSize)

	writerDone := make(chan struct{})
	go func() {
		defer zdnsutil.HandlePanic("TCP writer")
		defer close(writerDone)
		// Write coalescing: when several pipelined responses are already
		// queued, flush them in ONE writev syscall instead of one Write per
		// frame — the loaded-server profile is syscall-bound, and pipelined
		// bursts otherwise pay a syscall per 2-byte-framed packet.
		const maxWriteBatch = 16
		frames := make(net.Buffers, 0, maxWriteBatch)
		tasks := make([]writeTask, 0, maxWriteBatch)
		flush := func() error {
			_ = conn.SetWriteDeadline(time.Now().Add(config.DefaultDNSQueryTimeout))
			_, err := frames.WriteTo(conn)
			for _, t := range tasks {
				if t.pooled {
					pool.DefaultBuffer.Put(t.data)
				}
			}
			frames = frames[:0]
			tasks = tasks[:0]
			return err
		}
		for task := range writeCh {
			frames = append(frames, task.data)
			tasks = append(tasks, task)
		drain:
			for len(frames) < maxWriteBatch {
				select {
				case t, ok := <-writeCh:
					if !ok {
						break drain
					}
					frames = append(frames, t.data)
					tasks = append(tasks, t)
				default:
					break drain
				}
			}
			if err := flush(); err != nil {
				log.Debugf("PLAIN: TCP write error: %v", err)
				connCancel()
				return
			}
		}
	}()

	var wg sync.WaitGroup
	// readClean marks a client half-close (io.EOF after complete frames):
	// responses to already-received queries must still flush, so the
	// workers' writeCh sends are not raced against connCancel. A non-clean
	// exit (error, reset) cancels first — the connection cannot carry the
	// responses anyway.
	readClean := false
	defer func() {
		if !readClean {
			connCancel()
		}
		wg.Wait()
		connCancel()

		// Drain any remaining write tasks — the writer goroutine may have
		// exited early on a write error, leaving pooled buffers in the
		// channel. Return those buffers to the pool.
		draining := true
		for draining {
			select {
			case task, ok := <-writeCh:
				if !ok {
					draining = false
				} else if task.pooled {
					pool.DefaultBuffer.Put(task.data)
				}
			default:
				draining = false
			}
		}
		close(writeCh)
		<-writerDone
	}()

	workerCap := make(chan struct{}, config.DefaultMaxPipe)

	lengthBuf := make([]byte, zdnsutil.DNSFramePrefixLen)
	for {
		if connCtx.Err() != nil {
			return
		}

		_ = conn.SetReadDeadline(time.Now().Add(config.DefaultTCPIdleTimeout)) // RFC 7766 §6.2.3

		_, err := io.ReadFull(reader, lengthBuf)
		if err != nil {
			if errors.Is(err, io.EOF) {
				readClean = true
			} else if !zdnsutil.IsTemporaryError(err) {
				log.Debugf("PLAIN: TCP read length error remote=%s: %v", conn.RemoteAddr(), err)
			}
			return
		}

		msgLength := binary.BigEndian.Uint16(lengthBuf)
		if msgLength == 0 || msgLength > dns.MaxMsgSize {
			return
		}

		var pooledBuf []byte // non-nil when using a pool buffer, for later Put
		var msgBuf []byte
		if int(msgLength) <= pool.SecureBufferSize {
			pooledBuf = pool.DefaultBuffer.Get()
			msgBuf = pooledBuf[:msgLength]
		} else {
			msgBuf = make([]byte, msgLength)
		}
		_, err = io.ReadFull(reader, msgBuf)
		if err != nil {
			if pooledBuf != nil {
				pool.DefaultBuffer.Put(pooledBuf)
			}
			return
		}

		req := pool.DefaultMessage.Get()
		req.Data = msgBuf
		if err := req.Unpack(); err != nil {
			pool.DefaultMessage.Put(req)
			if pooledBuf != nil {
				pool.DefaultBuffer.Put(pooledBuf)
			}
			continue
		}
		isPooled := pooledBuf != nil

		var clientIP net.IP
		if addr := conn.RemoteAddr(); addr != nil {
			if tcpAddr, ok := addr.(*net.TCPAddr); ok {
				clientIP = tcpAddr.IP
			}
		}

		select {
		case workerCap <- struct{}{}:
		case <-connCtx.Done():
			pool.DefaultMessage.Put(req)
			if pooledBuf != nil {
				pool.DefaultBuffer.Put(pooledBuf)
			}
			return
		}

		wg.Add(1)
		go func(query *dns.Msg, ip net.IP, pooledBuf []byte, isPooled bool) {
			defer func() { <-workerCap }()
			defer zdnsutil.HandlePanic("TCP query worker")
			defer wg.Done()
			defer pool.DefaultMessage.Put(query)
			defer func() {
				if isPooled {
					pool.DefaultBuffer.Put(pooledBuf)
				}
			}()

			response := handler.ServeDNS(query, edns.RequestMeta{ClientIP: ip, Protocol: config.ProtoTCP})
			if response == query { //nolint:revive // identity guard: ServeDNS must never return the request
				response = nil
			}
			if response == nil {
				return
			}
			defer pool.DefaultMessage.Put(response)

			// Build the framed wire: pack straight into the frame's spare
			// capacity, or copy a pre-packed cache-hit wire verbatim (Pack
			// would re-serialize its nil RR sections into a header-only
			// frame).  A pooled frame is released exactly once — after the
			// writer's writev (Message.Put's ReleaseWire skips cleared Data).
			frameBuf := pool.DefaultBuffer.Get()
			writeBuf, pooled, ok := zdnsutil.PackStreamFrame(frameBuf, response)
			if !ok {
				log.Debugf("PLAIN: TCP response pack/size error")
				pool.DefaultBuffer.Put(frameBuf)
				return
			}
			if !pooled {
				pool.DefaultBuffer.Put(frameBuf) // response outgrew the frame — heap frame in use
			}

			select {
			case writeCh <- writeTask{data: writeBuf, pooled: pooled}:
			case <-connCtx.Done():
				// Abnormal in every normal flow (idle closes happen after
				// writes flush): the connection's context died with a
				// response in hand — e.g. a server errgroup cancellation
				// (a startup error elsewhere tears down this ctx).
				if log.IsDebug() {
					log.Debugf("PLAIN: TCP response for %s discarded — connection context cancelled", query.Question[0].Header().Name)
				}
				if pooled {
					pool.DefaultBuffer.Put(writeBuf)
				}
			}
		}(req, clientIP, pooledBuf, isPooled)
	}
}

// shutdownTCP closes the TCP listeners and all live connections.
func (s *Server) shutdownTCP() {
	s.tcpMu.Lock()
	defer s.tcpMu.Unlock()
	s.tcpClosed = true
	for _, l := range s.tcpListeners {
		_ = l.Close()
	}
	s.tcpListeners = nil
	for conn := range s.tcpConns {
		_ = conn.Close()
	}
	s.tcpConns = nil
}
