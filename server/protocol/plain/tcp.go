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
		for task := range writeCh {
			_ = conn.SetWriteDeadline(time.Now().Add(config.DefaultDNSQueryTimeout))
			_, err := conn.Write(task.data)
			if task.pooled {
				pool.DefaultBuffer.Put(task.data)
			}
			if err != nil {
				log.Debugf("PLAIN: TCP write error: %v", err)
				connCancel()
				return
			}
		}
	}()

	var wg sync.WaitGroup
	defer func() {
		connCancel()
		wg.Wait()

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
			if !errors.Is(err, io.EOF) && !zdnsutil.IsTemporaryError(err) {
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

			response := handler.ServeDNS(query, ip, false, config.ProtoTCP)
			if response == query { //nolint:revive // identity guard: ServeDNS must never return the request (L5)
				response = nil
			}
			if response == nil {
				return
			}
			defer pool.DefaultMessage.Put(response)

			err := response.Pack()
			respBuf := response.Data
			if err != nil {
				log.Debugf("PLAIN: TCP response pack error: %v", err)
				return
			}

			poolBuf := pool.DefaultBuffer.Get()
			// Record whether poolBuf was large enough BEFORE any Put call,
			// so the error path does not read metadata of a buffer that may
			// already be reused by another goroutine.
			poolBufOK := len(poolBuf) >= zdnsutil.DNSFramePrefixLen+len(respBuf)
			var writeBuf []byte
			if poolBufOK {
				writeBuf = poolBuf[:zdnsutil.DNSFramePrefixLen+len(respBuf)]
			} else {
				writeBuf = make([]byte, zdnsutil.DNSFramePrefixLen+len(respBuf))
				pool.DefaultBuffer.Put(poolBuf)
			}
			if len(respBuf) > dns.MaxMsgSize {
				// A 16-bit length prefix cannot represent this response; a
				// wrapped length would desync the whole TCP stream. Drop it.
				log.Debugf("PLAIN: dropping TCP response of %d bytes (exceeds 16-bit frame)", len(respBuf))
				if poolBufOK {
					pool.DefaultBuffer.Put(writeBuf)
				}
				return
			}
			binary.BigEndian.PutUint16(writeBuf[:zdnsutil.DNSFramePrefixLen], uint16(len(respBuf))) //nolint:gosec // G115: bounded by the MaxMsgSize check above
			copy(writeBuf[zdnsutil.DNSFramePrefixLen:], respBuf)

			select {
			case writeCh <- writeTask{data: writeBuf, pooled: poolBufOK}:
			case <-connCtx.Done():
				// Abnormal in every normal flow (idle closes happen after
				// writes flush): the connection's context died with a
				// response in hand — e.g. a server errgroup cancellation
				// (a startup error elsewhere tears down this ctx).
				if log.IsDebug() {
					log.Debugf("PLAIN: TCP response for %s discarded — connection context cancelled", query.Question[0].Header().Name)
				}
				if poolBufOK {
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
	for _, l := range s.tcpListeners {
		_ = l.Close()
	}
	s.tcpListeners = nil
	for conn := range s.tcpConns {
		_ = conn.Close()
	}
	s.tcpConns = nil
}
