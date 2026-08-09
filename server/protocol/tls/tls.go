package tls

import (
	"bufio"
	"context"
	"encoding/binary"
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
	eTLS "gitlab.com/go-extension/tls"
)

func (s *Server) startDOTServer() error {
	addrs, err := zdnsutil.ResolveBindAddrs("tcp", s.cfg.TLSPort)
	if err != nil {
		return fmt.Errorf("DoT address resolution: %w", err)
	}

	log.Infof("TLS: DoT server started on %v", addrs)
	for _, addr := range addrs {
		listener, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("TCP listen on %s: %w", addr, err)
		}

		rawListener := &debugListener{Listener: &zdnsutil.TCPKeepAliveListener{Listener: listener, KeepAlivePeriod: config.DefaultTCPKeepAlivePeriod}, name: "DoT"}

		dotTLSConfig := s.tlsConfig.Clone()
		dotTLSConfig.NextProtos = config.NextProtoDOT
		dotTLSConfig.GetConfigForClient = s.getConfigForClient(config.NextProtoDOT)

		dotListener := eTLS.NewListener(rawListener, dotTLSConfig)
		s.listenerMu.Lock()
		s.dotListeners = append(s.dotListeners, dotListener)
		s.listenerMu.Unlock()

		capturedDot := dotListener
		s.serverGroup.Go(func() error {
			defer zdnsutil.HandlePanic("DoT server")
			s.handleDOTConnections(capturedDot)
			return nil
		})
	}

	return nil
}

func (s *Server) handleDOTConnections(dotListener net.Listener) {
	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		conn, err := dotListener.Accept()
		if err != nil {
			if s.ctx.Err() != nil {
				return
			}
			log.Debugf("TLS: DoT Accept failed: %v (type=%T)", err, err)
			time.Sleep(config.DefaultAcceptRetryDelay)
			continue
		}

		log.Debugf("TLS: DoT TCP accepted from %s, TLS handshake pending", conn.RemoteAddr())

		// Bound the pre-handshake phase: a flood of idle TCP connections
		// that never complete the TLS handshake would otherwise hold a
		// shared errgroup slot for the full DefaultTCPPoolIdleTimeout,
		// starving the other TLS-family listeners. The handler clears the
		// deadline once the handshake completes.
		_ = conn.SetDeadline(time.Now().Add(config.DefaultTLSHandshakeTimeout))

		// Track the conn so Shutdown can wake it (the read loop blocks in
		// io.ReadFull with a 60s idle deadline — without this, Shutdown
		// waits up to 60s per active connection; M-3-5).
		s.listenerMu.Lock()
		s.dotConns[conn] = struct{}{}
		s.listenerMu.Unlock()

		s.serverGroup.Go(func() error {
			defer zdnsutil.HandlePanic("DoT connection handler")
			defer func() {
				s.listenerMu.Lock()
				delete(s.dotConns, conn)
				s.listenerMu.Unlock()
				_ = conn.Close()
			}()
			log.Debugf("TLS: DoT starting connection handler for %s", conn.RemoteAddr())
			s.handleDOTConnection(conn)
			return nil
		})
	}
}

func (s *Server) handleDOTConnection(conn net.Conn) {
	tlsConn, ok := conn.(*eTLS.Conn)
	if !ok {
		log.Debugf("TLS: DoT connection is not *eTLS.Conn, type=%T, remote=%s", conn, conn.RemoteAddr())
		return
	}

	// Enable TCP keep-alive on the underlying connection so idle DoT
	// connections are not silently torn down by intermediate NAT/firewall
	// state timeouts. The keep-alive probes maintain the network path;
	// the per-message read deadline (SetReadDeadline below) handles
	// application-level idle connection cleanup.
	if tcpConn, ok := tlsConn.NetConn().(*net.TCPConn); ok {
		_ = tcpConn.SetKeepAlive(true)
		_ = tcpConn.SetKeepAlivePeriod(config.DefaultTCPKeepAlivePeriod)
	}

	reader := bufio.NewReaderSize(tlsConn, TLSConnBufferSize)
	connCtx, connCancel := context.WithCancel(s.ctx)

	type writeTask struct {
		data   []byte
		pooled bool // true if data aliases a pool.DefaultBuffer allocation
	}
	writeCh := make(chan writeTask, config.DefaultDOTWriteChannelSize)

	writerDone := make(chan struct{})
	go func() {
		defer zdnsutil.HandlePanic("DoT writer")
		defer close(writerDone)
		for task := range writeCh {
			_ = tlsConn.SetWriteDeadline(time.Now().Add(config.DefaultDNSQueryTimeout))
			_, err := tlsConn.Write(task.data)
			if task.pooled {
				pool.DefaultBuffer.Put(task.data)
			}
			if err != nil {
				log.Debugf("TLS: write error: %v", err)
				connCancel()
				return
			}
		}
	}()

	var wg sync.WaitGroup
	defer func() {
		connCancel() // signal workers to stop
		wg.Wait()    // wait for workers to finish

		// Drain any remaining write tasks — the writer goroutine may
		// have exited early on a write error, leaving pooled buffers
		// in the channel. Return those buffers to the pool.
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
		close(writeCh) // now close writer channel
		<-writerDone   // wait for writer to drain
	}()

	workerCap := make(chan struct{}, config.DefaultMaxPipe)

	lengthBuf := make([]byte, zdnsutil.DNSFramePrefixLen)
	firstRead := true
	for {
		if connCtx.Err() != nil {
			return
		}

		// The first ReadFull triggers the TLS handshake (lazy handshake in
		// crypto/tls). Use the HANDSHAKE timeout for that first read only —
		// re-arming it every iteration overwrote the 60s idle deadline below
		// before it ever governed a read, disconnecting clients that poll
		// every 15-55s six times more often than designed (M5).
		if firstRead {
			_ = tlsConn.SetReadDeadline(time.Now().Add(config.DefaultTLSHandshakeTimeout))
		}

		_, err := io.ReadFull(reader, lengthBuf)
		if err != nil {
			if err != io.EOF && !zdnsutil.IsTemporaryError(err) {
				log.Debugf("TLS: read length error remote=%s: %v",
					tlsConn.RemoteAddr(), err)
			}
			return
		}
		firstRead = false

		// The first read succeeded — the TLS handshake is complete. Switch
		// to the long idle deadline for the rest of the connection.
		_ = tlsConn.SetReadDeadline(time.Now().Add(config.DefaultTCPPoolIdleTimeout))

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
		// pooledBuf must NOT be returned to the pool here: req.Data points
		// into it and the query worker calls req.Unpack() again during
		// processing. Instead, ownership transfers to the worker goroutine.
		isPooled := pooledBuf != nil

		var clientIP net.IP
		if addr := tlsConn.RemoteAddr(); addr != nil {
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
			defer zdnsutil.HandlePanic("DoT query worker")
			defer wg.Done()
			defer pool.DefaultMessage.Put(query)
			defer func() {
				if isPooled {
					pool.DefaultBuffer.Put(pooledBuf)
				}
			}()

			response := s.handler.ServeDNS(query, ip, true, config.ProtoTLS)
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
				log.Debugf("TLS: response pack error: %v", err)
				return
			}

			poolBuf := pool.DefaultBuffer.Get()
			// Record whether poolBuf was large enough BEFORE any Put call,
			// so the error path does not read metadata of a buffer that
			// may already be reused by another goroutine.
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
				log.Debugf("TLS: dropping DoT response of %d bytes (exceeds 16-bit frame)", len(respBuf))
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
				if poolBufOK {
					pool.DefaultBuffer.Put(writeBuf)
				}
				// else: poolBuf was already returned, and writeBuf is a
				// separately allocated slice that will be GC'd.
			}
		}(req, clientIP, pooledBuf, isPooled)
	}
}
