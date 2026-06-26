package tls

import (
	"bufio"
	"context"
	cryptotls "crypto/tls"
	"encoding/binary"
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

	dotTLSConfig := s.tlsConfig.Clone()
	dotTLSConfig.NextProtos = config.NextProtoDOT

	s.dotListener = cryptotls.NewListener(listener, dotTLSConfig)
	log.Infof("TLS: DoT server started on port %s", s.cfg.Port)

	s.serverGroup.Go(func() error {
		defer dnsutil.HandlePanic("DoT server")
		s.handleDOTConnections()
		return nil
	})

	return nil
}

func (s *Server) handleDOTConnections() {
	// Per-listener connection semaphore to prevent unbounded goroutine
	// growth from DoT connection flooding.
	sem := make(chan struct{}, config.DefaultMaxConnsPerIP)

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
			log.Errorf("TLS: Accept error: %v", err)
			time.Sleep(config.DefaultAcceptRetryDelay)
			continue
		}

		select {
		case sem <- struct{}{}:
		default:
			_ = conn.Close()
			log.Debugf("TLS: DoT connection limit reached, rejecting new connection")
			continue
		}

		s.serverGroup.Go(func() error {
			defer func() { <-sem }()
			defer dnsutil.HandlePanic("DoT connection handler")
			defer func() { _ = conn.Close() }()
			s.handleDOTConnection(conn)
			return nil
		})
	}
}

func (s *Server) handleDOTConnection(conn net.Conn) {
	tlsConn, ok := conn.(*cryptotls.Conn)
	if !ok {
		return
	}

	reader := bufio.NewReaderSize(tlsConn, TLSConnBufferSize)
	connCtx, connCancel := context.WithCancel(s.ctx)
	defer connCancel()

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
		close(writeCh)
		<-writerDone
		wg.Wait()
	}()

	workerCap := make(chan struct{}, config.DefaultMaxPipe)

	for {
		if connCtx.Err() != nil {
			return
		}

		_ = tlsConn.SetReadDeadline(time.Now().Add(config.DefaultDNSQueryTimeout))

		lengthBuf := make([]byte, 2)
		_, err := io.ReadFull(reader, lengthBuf)
		if err != nil {
			if err != io.EOF && !isTemporaryError(err) {
				log.Debugf("TLS: read length error: %v", err)
			}
			return
		}

		msgLength := binary.BigEndian.Uint16(lengthBuf)
		if msgLength == 0 || msgLength > pool.SecureBufferSize-2 {
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
			poolBufOK := len(poolBuf) >= 2+len(respBuf)
			var writeBuf []byte
			if poolBufOK {
				writeBuf = poolBuf[:2+len(respBuf)]
			} else {
				writeBuf = make([]byte, 2+len(respBuf))
				pool.DefaultBufferPool.Put(poolBuf)
				poolBuf = nil // prevent accidental reuse below
			}
			binary.BigEndian.PutUint16(writeBuf[:2], uint16(len(respBuf)))
			copy(writeBuf[2:], respBuf)

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
