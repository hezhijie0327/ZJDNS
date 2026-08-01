package tlcp

import (
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

	bound := 0
	for _, addr := range addrs {
		rawListener, err := net.Listen("tcp", addr)
		if err != nil {
			log.Warnf("TLCP: skipping tcp address %s: %v", addr, err)
			continue
		}
		bound++

		tlcpCfg := s.tlcpConfig.Clone()
		tlcpCfg.NextProtos = config.NextProtoDOT
		tlcpListener := tlcp.NewListener(&tcpKeepAliveListener{Listener: rawListener}, tlcpCfg)

		s.dotListeners = append(s.dotListeners, tlcpListener)

		s.serverGroup.Go(func() error {
			defer zdnsutil.HandlePanic("TLCP DoT server")
			s.serveDOT(tlcpListener)
			return nil
		})
	}
	if bound == 0 {
		return errors.New("tlcp: no DoT addresses could be bound")
	}
	log.Infof("TLCP: DoT server started on %v (TLCP)", addrs)
	return nil
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
		s.serverGroup.Go(func() error { defer zdnsutil.HandlePanic("TLCP DoT handler"); s.handleDOTConn(conn); return nil })
	}
}

func (s *Server) handleDOTConn(conn net.Conn) {
	defer zdnsutil.HandlePanic("TLCP DoT handler")
	defer func() { _ = conn.Close() }()

	clientIP := zdnsutil.ClientIPFromAddr(conn.RemoteAddr())

	for {
		_ = conn.SetReadDeadline(time.Now().Add(config.DefaultTCPPoolIdleTimeout))

		msg, err := zdnsutil.ReadTCPMsg(conn)
		if err != nil {
			if !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.EOF) {
				log.Debugf("TLCP: DoT read error from %s: %v", clientIP, err)
			}
			return
		}

		resp := s.handler.ServeDNS(msg, clientIP, true, config.ProtoTLCP)
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

	if err := zdnsutil.WriteTCPMsg(conn, resp); err != nil {
		log.Debugf("TLCP: DoT write error to %s: %v", clientIP, err)
		return false
	}
	return true
}
