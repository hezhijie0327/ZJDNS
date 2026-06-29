package tls

import (
	"bufio"
	"context"
	"encoding/binary"
	cryptotls "gitlab.com/go-extension/tls"
	"io"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"

	"zjdns/config"
	"zjdns/internal/dnsutil"
	"zjdns/internal/log"
	"zjdns/internal/pool"
)

func (s *Server) startDOTServer() error {
	listener, err := net.Listen("tcp", ":"+s.cfg.Port)
	if err != nil {
		return err
	}

	// Wrap raw listener to log every TCP connection before TLS handshake,
	// so we can distinguish "never reached us" from "reached us but TLS failed".
	rawListener := &debugListener{Listener: listener, name: "DoT"}

	dotTLSConfig := s.tlsConfig.Clone()
	dotTLSConfig.NextProtos = config.NextProtoDOT
	dotTLSConfig.GetConfigForClient = s.getConfigForClient(config.NextProtoDOT)

	s.dotListener = cryptotls.NewListener(rawListener, dotTLSConfig)
	log.Infof("TLS: DoT server started on port %s", s.cfg.Port)
	log.Infof("TLS: DoT accepting on all interfaces (0.0.0.0:%s, [::]:%s)", s.cfg.Port, s.cfg.Port)

	s.serverGroup.Go(func() error {
		defer dnsutil.HandlePanic("DoT server")
		s.handleDOTConnections()
		return nil
	})

	return nil
}

func (s *Server) handleDOTConnections() {
	// Per-IP DoT connection limit to prevent a single client from
	// flooding the server with connections, matching DoQ's per-IP policy.
	const maxConnsPerIP = config.DefaultMaxConnsPerIP

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		conn, err := s.dotListener.Accept()
		if err != nil {
			if s.ctx.Err() != nil {
				return
			}
			log.Warnf("TLS: DoT Accept failed: %v (type=%T)", err, err)
			time.Sleep(config.DefaultAcceptRetryDelay)
			continue
		}

		log.Debugf("TLS: DoT TCP accepted from %s, TLS handshake pending", conn.RemoteAddr())

		var cleanup func()
		if host, _, err := net.SplitHostPort(conn.RemoteAddr().String()); err == nil {
			cleanup = s.dotLimiter.Allow(host, maxConnsPerIP)
			if cleanup == nil {
				_ = conn.Close()
				log.Debugf("TLS: DoT per-IP connection limit reached for %s, rejecting", host)
				continue
			}
		}

		s.serverGroup.Go(func() error {
			if cleanup != nil {
				defer cleanup()
			}
			defer dnsutil.HandlePanic("DoT connection handler")
			defer func() { _ = conn.Close() }()
			log.Debugf("TLS: DoT starting connection handler for %s", conn.RemoteAddr())
			s.handleDOTConnection(conn)
			return nil
		})
	}
}

func (s *Server) handleDOTConnection(conn net.Conn) {
	tlsConn, ok := conn.(*cryptotls.Conn)
	if !ok {
		log.Debugf("TLS: DoT connection is not *cryptotls.Conn, type=%T, remote=%s", conn, conn.RemoteAddr())
		return
	}

	reader := bufio.NewReaderSize(tlsConn, TLSConnBufferSize)
	connCtx, connCancel := context.WithCancel(s.ctx)

	type writeTask struct{ data []byte }
	writeCh := make(chan writeTask, config.DefaultDoTWriteChannelSize)

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
		_ = tlsConn.SetReadDeadline(time.Now().Add(config.DefaultDNSQueryTimeout))

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
		if err := req.Unpack(msgBuf); err != nil {
			pool.DefaultMessagePool.Put(req)
			pool.DefaultBufferPool.Put(buf)
			continue
		}
		pool.DefaultBufferPool.Put(buf)

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
			return
		}

		wg.Add(1)
		go func(query *dns.Msg, ip net.IP) {
			defer func() { <-workerCap }()
			defer dnsutil.HandlePanic("DoT query worker")
			defer wg.Done()
			defer pool.DefaultMessagePool.Put(query)

			response := s.handler.ServeDNS(query, ip, true, "DoT")
			if response == nil {
				return
			}
			defer pool.DefaultMessagePool.Put(response)

			respBuf, err := response.Pack()
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
				poolBuf = nil // prevent accidental reuse below
			}
			binary.BigEndian.PutUint16(writeBuf[:dnsutil.DNSFramePrefixLen], uint16(len(respBuf)))
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
		}(req, clientIP)
	}
}
