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
	"zjdns/internal/dnsutil"
	"zjdns/internal/log"
	"zjdns/internal/pool"

	"codeberg.org/miekg/dns"
	eTLS "gitlab.com/go-extension/tls"
)

func (s *Server) startDOTServer() error {
	addrs, err := dnsutil.ResolveBindAddrs("tcp", s.cfg.Port)
	if err != nil {
		return fmt.Errorf("DoT address resolution: %w", err)
	}

	for _, addr := range addrs {
		listener, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("TCP listen on %s: %w", addr, err)
		}

		rawListener := &debugListener{Listener: &TCPKeepAliveListener{Listener: listener}, name: "DoT"}

		dotTLSConfig := s.tlsConfig.Clone()
		dotTLSConfig.NextProtos = config.NextProtoDOT
		dotTLSConfig.GetConfigForClient = s.getConfigForClient(config.NextProtoDOT)

		dotListener := eTLS.NewListener(rawListener, dotTLSConfig)
		s.dotListeners = append(s.dotListeners, dotListener)
		log.Infof("TLS: DoT server started on %s", addr)

		capturedDot := dotListener
		s.serverGroup.Go(func() error {
			defer dnsutil.HandlePanic("DoT server")
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
			log.Warnf("TLS: DoT Accept failed: %v (type=%T)", err, err)
			time.Sleep(config.DefaultAcceptRetryDelay)
			continue
		}

		log.Debugf("TLS: DoT TCP accepted from %s, TLS handshake pending", conn.RemoteAddr())

		s.serverGroup.Go(func() error {
			defer dnsutil.HandlePanic("DoT connection handler")
			defer func() { _ = conn.Close() }()
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
	// state timeouts. The read deadline handles idle connection cleanup.
	if tcpConn, ok := tlsConn.NetConn().(*net.TCPConn); ok {
		_ = tcpConn.SetKeepAlive(true)
		_ = tcpConn.SetKeepAlivePeriod(config.DefaultTCPKeepAlivePeriod)
	}

	reader := bufio.NewReaderSize(tlsConn, TLSConnBufferSize)
	connCtx, connCancel := context.WithCancel(s.ctx)

	type writeTask struct{ data []byte }
	writeCh := make(chan writeTask, config.DefaultDOTWriteChannelSize)

	writerDone := make(chan struct{})
	go func() {
		defer dnsutil.HandlePanic("DoT writer")
		defer close(writerDone)
		for task := range writeCh {
			_ = tlsConn.SetWriteDeadline(time.Now().Add(config.DefaultDNSQueryTimeout))
			_, err := tlsConn.Write(task.data)
			pool.DefaultBufferPool.Put(task.data)
			if err != nil {
				log.Debugf("TLS: write error: %v", err)
				connCancel()
				return
			}
		}
	}()

	var wg sync.WaitGroup
	defer func() {
		connCancel()   // signal workers to stop
		wg.Wait()      // wait for workers to finish
		close(writeCh) // now close writer channel
		<-writerDone   // wait for writer to drain
	}()

	workerCap := make(chan struct{}, config.DefaultMaxPipe)

	lengthBuf := make([]byte, dnsutil.DNSFramePrefixLen)
	for {
		if connCtx.Err() != nil {
			return
		}

		// The first ReadFull triggers the TLS handshake (lazy handshake in
		// crypto/tls). After a successful handshake, kTLS may be negotiated.
		// Use a long read deadline for idle-connection detection; the
		// per-message I/O is bounded by TCP keep-alive (DefaultTCPKeepAlivePeriod)
		// and client-side query timeouts.
		_ = tlsConn.SetReadDeadline(time.Now().Add(config.DefaultTCPPoolIdleTimeout))

		_, err := io.ReadFull(reader, lengthBuf)
		if err != nil {
			if err != io.EOF && !isTemporaryError(err) {
				log.Debugf("TLS: read length error remote=%s: %v",
					tlsConn.RemoteAddr(), err)
			}
			return
		}

		msgLength := binary.BigEndian.Uint16(lengthBuf)
		if msgLength == 0 || msgLength > pool.SecureBufferSize-dnsutil.DNSFramePrefixLen {
			return
		}

		buf := pool.DefaultBufferPool.Get()
		msgBuf := buf
		if cap(msgBuf) < int(msgLength) {
			msgBuf = make([]byte, msgLength)
		} else {
			msgBuf = msgBuf[:msgLength]
		}
		_, err = io.ReadFull(reader, msgBuf)
		if err != nil {
			pool.DefaultBufferPool.Put(buf)
			return
		}

		req := pool.DefaultMessagePool.Get()
		req.Data = msgBuf
		if err := req.Unpack(); err != nil {
			pool.DefaultMessagePool.Put(req)
			pool.DefaultBufferPool.Put(buf)
			continue
		}
		// buf must NOT be returned to the pool here: req.Data points into it
		// and the query worker calls req.Unpack() again during processing.
		// Returning buf early would zero req.Data, corrupting the re-unpack.
		// Instead, buf ownership transfers to the worker goroutine.
		pooled := cap(msgBuf) >= cap(buf)

		var clientIP net.IP
		if addr := tlsConn.RemoteAddr(); addr != nil {
			if tcpAddr, ok := addr.(*net.TCPAddr); ok {
				clientIP = tcpAddr.IP
			}
		}

		select {
		case workerCap <- struct{}{}:
		case <-connCtx.Done():
			pool.DefaultMessagePool.Put(req)
			pool.DefaultBufferPool.Put(buf)
			return
		}

		wg.Add(1)
		go func(query *dns.Msg, ip net.IP, pooledBuf []byte, isPooled bool) {
			defer func() { <-workerCap }()
			defer dnsutil.HandlePanic("DoT query worker")
			defer wg.Done()
			defer pool.DefaultMessagePool.Put(query)
			defer func() {
				if isPooled {
					pool.DefaultBufferPool.Put(pooledBuf)
				}
			}()

			response := s.handler.ServeDNS(query, ip, true, "DoT")
			if response == nil {
				return
			}
			defer pool.DefaultMessagePool.Put(response)

			err := response.Pack()
			respBuf := response.Data
			if err != nil {
				log.Debugf("TLS: response pack error: %v", err)
				return
			}

			poolBuf := pool.DefaultBufferPool.Get()
			// Record whether poolBuf was large enough BEFORE any Put call,
			// so the error path does not read metadata of a buffer that
			// may already be reused by another goroutine.
			poolBufOK := len(poolBuf) >= dnsutil.DNSFramePrefixLen+len(respBuf)
			var writeBuf []byte
			if poolBufOK {
				writeBuf = poolBuf[:dnsutil.DNSFramePrefixLen+len(respBuf)]
			} else {
				writeBuf = make([]byte, dnsutil.DNSFramePrefixLen+len(respBuf))
				pool.DefaultBufferPool.Put(poolBuf)
			}
			binary.BigEndian.PutUint16(writeBuf[:dnsutil.DNSFramePrefixLen], uint16(len(respBuf))) //nolint:gosec // G115: DNS length prefix — max 65535 fits uint16
			copy(writeBuf[dnsutil.DNSFramePrefixLen:], respBuf)

			select {
			case writeCh <- writeTask{data: writeBuf}:
			case <-connCtx.Done():
				if poolBufOK {
					pool.DefaultBufferPool.Put(writeBuf)
				}
				// else: poolBuf was already returned, and writeBuf is a
				// separately allocated slice that will be GC'd.
			}
		}(req, clientIP, buf, pooled)
	}
}
