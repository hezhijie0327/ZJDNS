package server

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"

	"zjdns/internal/dnsutil"
	"zjdns/internal/log"
	"zjdns/internal/pool"
)

// startDOTServer starts the DNS over TLS server.
func (tm *TLSManager) startDOTServer() error {
	listener, err := net.Listen("tcp", ":"+tm.server.config.Server.TLS.Port)
	if err != nil {
		return fmt.Errorf("DoT listen: %w", err)
	}

	// Configure TLS for DoT
	dotTLSConfig := tm.tlsConfig.Clone()
	dotTLSConfig.NextProtos = NextProtoDOT

	tm.dotListener = tls.NewListener(listener, dotTLSConfig)
	log.Infof("TLS: DoT server started on port %s", tm.server.config.Server.TLS.Port)

	tm.serverGroup.Go(func() error {
		defer dnsutil.HandlePanic("DoT server")
		tm.handleDOTConnections()
		return nil
	})

	return nil
}

// handleDOTConnections accepts and handles incoming DoT connections.
func (tm *TLSManager) handleDOTConnections() {
	for {
		select {
		case <-tm.ctx.Done():
			return
		default:
		}

		conn, err := tm.dotListener.Accept()
		if err != nil {
			if tm.ctx.Err() != nil {
				return
			}
			log.Errorf("TLS: Accept error: %v", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}

		tm.serverGroup.Go(func() error {
			defer dnsutil.HandlePanic("DoT connection handler")
			defer func() { _ = conn.Close() }()
			tm.handleDOTConnection(conn)
			return nil
		})
	}
}

// handleDOTConnection handles a single DoT connection with RFC 7766 query
// pipelining: queries are processed concurrently and responses are written
// out of order through a dedicated writer goroutine.
func (tm *TLSManager) handleDOTConnection(conn net.Conn) {
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return
	}

	reader := bufio.NewReaderSize(tlsConn, TLSConnBufferSize)
	connCtx, connCancel := context.WithCancel(tm.ctx)
	defer connCancel()

	// Writer channel: worker goroutines send packed responses here for
	// serialized writing to the TLS connection.
	type writeTask struct {
		data []byte
	}
	writeCh := make(chan writeTask, 64)

	// Writer goroutine — single owner of the TLS socket for writes.
	writerDone := make(chan struct{})
	go func() {
		defer dnsutil.HandlePanic("DoT writer")
		defer close(writerDone)
		for task := range writeCh {
			_ = tlsConn.SetWriteDeadline(time.Now().Add(OperationTimeout))
			if _, err := tlsConn.Write(task.data); err != nil {
				log.Debugf("TLS: write error: %v", err)
				connCancel()
				return
			}
		}
	}()

	// Cleanup: close write channel → wait for writer → connection teardown.
	defer func() {
		close(writeCh)
		<-writerDone
	}()

	// Track in-flight workers for clean shutdown.
	var wg sync.WaitGroup
	defer wg.Wait()

	// Per-connection worker capacity — bounds concurrent query processing
	// per DoT connection (mirrors client-side defaultMaxPipe).
	workerCap := make(chan struct{}, defaultMaxPipe)

	// Reader loop — processes queries sequentially on this goroutine
	// (bufio.Reader is not goroutine-safe) and dispatches processing
	// to worker goroutines.
	for {
		if connCtx.Err() != nil {
			return
		}

		_ = tlsConn.SetReadDeadline(time.Now().Add(OperationTimeout))

		// Read 2-byte length prefix.
		lengthBuf := make([]byte, 2)
		n, err := io.ReadFull(reader, lengthBuf)
		if err != nil {
			if err != io.EOF && !IsTemporaryError(err) {
				log.Debugf("TLS: read length error: %v", err)
			}
			return
		}
		if n != 2 {
			log.Debugf("TLS: invalid length read: %d bytes", n)
			return
		}

		msgLength := binary.BigEndian.Uint16(lengthBuf)
		if msgLength == 0 || msgLength > pool.SecureBufferSize-2 {
			log.Debugf("TLS: invalid message length: %d", msgLength)
			return
		}

		// Read message body using buffer pool (msgLength ≤ TCPBufferSize ≤ SecureBufferSize).
		buf := pool.DefaultBufferPool.Get()
		msgBuf := buf
		if cap(msgBuf) < int(msgLength) {
			msgBuf = make([]byte, msgLength)
		} else {
			msgBuf = msgBuf[:msgLength]
		}
		n, err = io.ReadFull(reader, msgBuf)
		if err != nil {
			log.Debugf("TLS: read message error: %v", err)
			pool.DefaultBufferPool.Put(buf)
			return
		}
		if n != int(msgLength) {
			log.Debugf("TLS: incomplete message read: %d/%d bytes", n, msgLength)
			pool.DefaultBufferPool.Put(buf)
			return
		}

		// Parse DNS message.
		req := pool.DefaultMessagePool.Get()
		if err := req.Unpack(msgBuf); err != nil {
			log.Debugf("TLS: DNS message unpack error: %v", err)
			pool.DefaultMessagePool.Put(req)
			pool.DefaultBufferPool.Put(buf)
			continue
		}
		pool.DefaultBufferPool.Put(buf)

		// Get client IP.
		var clientIP net.IP
		if addr := tlsConn.RemoteAddr(); addr != nil {
			clientIP = addr.(*net.TCPAddr).IP
		}

		// Acquire per-connection worker slot; block if at capacity to
		// provide backpressure and bound memory under load.
		select {
		case workerCap <- struct{}{}:
		case <-connCtx.Done():
			pool.DefaultMessagePool.Put(req)
			return
		}

		// Process query asynchronously — responses may complete out of order.
		wg.Add(1)
		go func(query *dns.Msg, ip net.IP) {
			defer func() { <-workerCap }()
			defer dnsutil.HandlePanic("DoT query worker")
			defer wg.Done()
			defer pool.DefaultMessagePool.Put(query)

			response := tm.server.processDNSQuery(query, ip, true, "DoT")
			if response == nil {
				return
			}
			defer pool.DefaultMessagePool.Put(response)

			respBuf, err := response.Pack()
			if err != nil {
				log.Debugf("TLS: response pack error: %v", err)
				return
			}

			buf := make([]byte, 2+len(respBuf))
			binary.BigEndian.PutUint16(buf[:2], uint16(len(respBuf)))
			copy(buf[2:], respBuf)

			select {
			case writeCh <- writeTask{data: buf}:
			case <-connCtx.Done():
			}
		}(req, clientIP)
	}
}
