package tlcp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
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
		// Track the conn so Shutdown can wake it (the read loop blocks in
		// ReadTCPMsg with a 60s idle deadline — M-3-5).
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

	var lengthBuf [zdnsutil.DNSFramePrefixLen]byte
	for {
		if _, err := io.ReadFull(conn, lengthBuf[:]); err != nil {
			if !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.EOF) {
				log.Debugf("TLCP: DoT read error from %s: %v", clientIP, err)
			}
			return
		}

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
		if _, err := io.ReadFull(conn, msgBuf); err != nil {
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

		resp := s.handler.ServeDNS(req, clientIP, true, config.ProtoTLCP)
		pool.DefaultMessage.Put(req)
		if pooledBuf != nil {
			pool.DefaultBuffer.Put(pooledBuf)
		}
		if resp == req { //nolint:revive // identity guard: ServeDNS must never return the request (L5)
			resp = nil
		}
		if !s.sendDOTResponse(conn, resp, clientIP) {
			return
		}
	}
}

// sendDOTResponse writes a TLCP DoT response. Returns true to continue the
// connection loop, false to close. The response is always returned to the pool
// (defer-protected).
func (s *Server) sendDOTResponse(conn net.Conn, resp *dns.Msg, clientIP net.IP) bool {
	if resp == nil {
		return true
	}
	defer pool.DefaultMessage.Put(resp)

	// Write deadline matching the other protocol handlers (tls.go,
	// dnscrypt/tcp.go, dtlcp.go): a peer that stops reading (full receive
	// window) must not block this connection goroutine forever.
	if err := conn.SetWriteDeadline(time.Now().Add(config.DefaultDNSQueryTimeout)); err != nil {
		log.Debugf("TLCP: DoT SetWriteDeadline error to %s: %v", clientIP, err)
	}

	// Pre-packed wire (cache-hit direct-send path) skips the Pack entirely;
	// only synthetic responses pack here.  The 2-byte frame comes out of the
	// buffer pool instead of a per-response allocation (P-M5).
	wire := resp.Data
	if len(wire) == 0 {
		if err := resp.Pack(); err != nil {
			log.Debugf("TLCP: DoT response pack error to %s: %v", clientIP, err)
			return true // drop this response, keep the connection
		}
		wire = resp.Data
	}
	if len(wire) > dns.MaxMsgSize {
		log.Debugf("TLCP: dropping DoT response of %d bytes (exceeds 16-bit frame)", len(wire))
		return true
	}

	poolBuf := pool.DefaultBuffer.Get()
	frameOK := len(poolBuf) >= zdnsutil.DNSFramePrefixLen+len(wire)
	var frame []byte
	if frameOK {
		frame = poolBuf[:zdnsutil.DNSFramePrefixLen+len(wire)]
	} else {
		frame = make([]byte, zdnsutil.DNSFramePrefixLen+len(wire))
		pool.DefaultBuffer.Put(poolBuf)
	}
	binary.BigEndian.PutUint16(frame[:zdnsutil.DNSFramePrefixLen], uint16(len(wire))) //nolint:gosec // G115: bounded by the MaxMsgSize check above
	copy(frame[zdnsutil.DNSFramePrefixLen:], wire)
	_, err := conn.Write(frame)
	if frameOK {
		pool.DefaultBuffer.Put(frame)
	}
	if err != nil {
		log.Debugf("TLCP: DoT write error to %s: %v", clientIP, err)
		return false
	}
	return true
}
