package tlcp

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
	zdnsutil "zjdns/internal/dnsutil"
	"zjdns/internal/log"
	"zjdns/internal/pool"

	"codeberg.org/miekg/dns"
	"gitee.com/Trisia/gotlcp/tlcp"
)

// tcpKeepAliveListener wraps a net.Listener to enable TCP keep-alive.
type tcpKeepAliveListener struct {
	net.Listener
}

// dotWriteTask is one queued response frame; pooled reports whether data
// aliases a pool.DefaultBuffer allocation.
type dotWriteTask struct {
	data   []byte
	pooled bool
}

// dotConnBufferSize is the reader buffer size (mirrors the TLS DoT reader).
const dotConnBufferSize = 4096

func (k *tcpKeepAliveListener) Accept() (net.Conn, error) {
	conn, err := k.Listener.Accept()
	if err != nil {
		return nil, err
	}
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		_ = tcpConn.SetKeepAlive(true)
		_ = tcpConn.SetKeepAlivePeriod(config.DefaultTCPKeepAlivePeriod)
	}
	return conn, nil
}

func (s *Server) startDOTServer() error {
	addrs, err := zdnsutil.ResolveBindAddrs("tcp", s.dotPort)
	if err != nil {
		return fmt.Errorf("resolve bind addrs: %w", err)
	}

	log.Infof("TLCP: DoT server started on %v (TLCP)", addrs)
	for _, addr := range addrs {
		rawListener, err := net.Listen("tcp", addr)
		if err != nil {
			// Fail fast, matching tls/tls.go and the server's own policy —
			// a configured endpoint that cannot bind is a configuration
			// error, not something to skip silently: the previous Warn+
			// continue let a TLCP DoT listener come up dead while Start
			// reported success (P-M3).
			return fmt.Errorf("TLCP DoT listen on %s: %w", addr, err)
		}

		tlcpCfg := s.tlcpConfig.Clone()
		tlcpCfg.NextProtos = config.NextProtoDOT
		tlcpListener := tlcp.NewListener(&tcpKeepAliveListener{Listener: rawListener}, tlcpCfg)

		s.listenerMu.Lock()
		s.dotListeners = append(s.dotListeners, tlcpListener)
		s.listenerMu.Unlock()

		s.serverGroup.Go(func() error {
			defer zdnsutil.HandlePanic("TLCP DoT server")
			s.serveDOT(tlcpListener)
			return nil
		})
	}
	return nil
}

// ServeDOT accepts TLCP DoT connections from a listener (exported for shared-port Manager).
func (s *Server) ServeDOT(listener net.Listener) {
	s.serveDOT(listener)
}

func (s *Server) serveDOT(listener net.Listener) {
	defer zdnsutil.HandlePanic("TLCP DoT server")
	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			log.Debugf("TLCP: DoT accept error: %v", err)
			time.Sleep(config.DefaultAcceptRetryDelay)
			continue
		}
		// Track the conn so Shutdown can close it and unblock the blocking
		// read loop (M-3-5).
		s.listenerMu.Lock()
		s.dotConns[conn] = struct{}{}
		s.listenerMu.Unlock()

		s.serverGroup.Go(func() error {
			defer zdnsutil.HandlePanic("TLCP DoT handler")
			defer func() {
				s.listenerMu.Lock()
				delete(s.dotConns, conn)
				s.listenerMu.Unlock()
			}()
			s.handleDOTConn(conn)
			return nil
		})
	}
}

func (s *Server) handleDOTConn(conn net.Conn) {
	defer zdnsutil.HandlePanic("TLCP DoT handler")
	defer func() { _ = conn.Close() }()

	clientIP := zdnsutil.ClientIPFromAddr(conn.RemoteAddr())

	// Short pre-handshake deadline for the first read: a flood of idle TLCP
	// connections must not hold a shared serverGroup slot for the full 60s
	// idle timeout (mirrors the TLS package, tls.go:81).
	_ = conn.SetReadDeadline(time.Now().Add(config.DefaultTLSHandshakeTimeout))

	reader := bufio.NewReaderSize(conn, dotConnBufferSize)
	connCtx, connCancel := context.WithCancel(s.ctx)
	defer connCancel()

	writeCh := make(chan dotWriteTask, config.DefaultDOTWriteChannelSize)

	writerDone := make(chan struct{})
	go func() {
		defer zdnsutil.HandlePanic("TLCP DoT writer")
		defer close(writerDone)
		for task := range writeCh {
			_ = conn.SetWriteDeadline(time.Now().Add(config.DefaultDNSQueryTimeout))
			_, err := conn.Write(task.data)
			if task.pooled {
				pool.DefaultBuffer.Put(task.data)
			}
			if err != nil {
				log.Debugf("TLCP: DoT write error to %s: %v", clientIP, err)
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

	var lengthBuf [zdnsutil.DNSFramePrefixLen]byte
	firstRead := true
	for {
		if connCtx.Err() != nil {
			return
		}

		if firstRead {
			_ = conn.SetReadDeadline(time.Now().Add(config.DefaultTLSHandshakeTimeout))
		}
		if _, err := io.ReadFull(reader, lengthBuf[:]); err != nil {
			if !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.EOF) {
				log.Debugf("TLCP: DoT read error from %s: %v", clientIP, err)
			}
			return
		}
		firstRead = false

		// First read succeeded — extend to the regular idle timeout.
		_ = conn.SetReadDeadline(time.Now().Add(config.DefaultTCPPoolIdleTimeout))

		msgLength := binary.BigEndian.Uint16(lengthBuf[:])
		if msgLength == 0 || msgLength > dns.MaxMsgSize {
			return
		}

		// Pooled read path (mirrors tls.go): the pooled buffer outlives
		// ServeDNS because the pre-packed pipeline re-reads req.Data
		// inside processing (P-M5).
		var pooledBuf []byte
		var msgBuf []byte
		if int(msgLength) <= pool.SecureBufferSize {
			pooledBuf = pool.DefaultBuffer.Get()
			msgBuf = pooledBuf[:msgLength]
		} else {
			msgBuf = make([]byte, msgLength)
		}
		if _, err := io.ReadFull(reader, msgBuf); err != nil {
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
		go func(query *dns.Msg, pooledBuf []byte, isPooled bool) {
			defer func() { <-workerCap }()
			defer zdnsutil.HandlePanic("TLCP DoT query worker")
			defer wg.Done()
			defer pool.DefaultMessage.Put(query)
			defer func() {
				if isPooled {
					pool.DefaultBuffer.Put(pooledBuf)
				}
			}()

			resp := s.handler.ServeDNS(query, clientIP, true, config.ProtoTLCP)
			if resp == query { //nolint:revive // identity guard: ServeDNS must never return the request (L5)
				resp = nil
			}
			if resp == nil {
				return
			}

			frame, frameOK, ok := buildDOTFrame(resp)
			defer pool.DefaultMessage.Put(resp)
			if !ok {
				return // pack error or oversize — drop this response, keep the connection
			}
			select {
			case writeCh <- dotWriteTask{data: frame, pooled: frameOK}:
			case <-connCtx.Done():
				if frameOK {
					pool.DefaultBuffer.Put(frame)
				}
			}
		}(req, pooledBuf, isPooled)
	}
}

// buildDOTFrame packs resp (skipping Pack for pre-packed cache-hit wires) and
// wraps it in a 2-byte length-prefixed frame from the buffer pool. Returns
// (frame, frameFromPool, ok).
func buildDOTFrame(resp *dns.Msg) (frame []byte, fromPool, ok bool) {
	// Pre-packed wire (cache-hit direct-send path) skips the Pack entirely;
	// only synthetic responses pack here.  The 2-byte frame comes out of the
	// buffer pool instead of a per-response allocation (P-M5).
	wire := resp.Data
	if len(wire) == 0 {
		if err := resp.Pack(); err != nil {
			log.Debugf("TLCP: DoT response pack error: %v", err)
			return nil, false, false
		}
		wire = resp.Data
	}
	if len(wire) > dns.MaxMsgSize {
		log.Debugf("TLCP: dropping DoT response of %d bytes (exceeds 16-bit frame)", len(wire))
		return nil, false, false
	}

	poolBuf := pool.DefaultBuffer.Get()
	frameOK := len(poolBuf) >= zdnsutil.DNSFramePrefixLen+len(wire)
	if frameOK {
		frame = poolBuf[:zdnsutil.DNSFramePrefixLen+len(wire)]
	} else {
		frame = make([]byte, zdnsutil.DNSFramePrefixLen+len(wire))
		pool.DefaultBuffer.Put(poolBuf)
	}
	binary.BigEndian.PutUint16(frame[:zdnsutil.DNSFramePrefixLen], uint16(len(wire))) //nolint:gosec // G115: bounded by the MaxMsgSize check above
	copy(frame[zdnsutil.DNSFramePrefixLen:], wire)
	return frame, frameOK, true
}
