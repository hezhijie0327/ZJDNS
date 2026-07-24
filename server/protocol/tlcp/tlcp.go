package tlcp

import (
	"errors"
	"fmt"
	"io"
	"net"
	"zjdns/config"
	zdnsutil "zjdns/internal/dnsutil"
	"zjdns/internal/log"
	"zjdns/internal/pool"

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
			log.Warnf("TLCP: skipping tcp address %s: %v", addr, err)
			continue
		}

		tlcpCfg := s.tlcpConfig.Clone()
		tlcpCfg.NextProtos = config.NextProtoDOT
		tlcpListener := tlcp.NewListener(&tcpKeepAliveListener{Listener: rawListener}, tlcpCfg)

		s.dotListeners = append(s.dotListeners, tlcpListener)

		s.serverGroup.Go(func() error {
			s.serveDOT(tlcpListener)
			return nil
		})
	}
	return nil
}

func (s *Server) serveDOT(listener net.Listener) {
	defer zdnsutil.HandlePanic("TLCP DoT server")
	for {
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			log.Debugf("TLCP: DoT accept error: %v", err)
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
		msg, err := zdnsutil.ReadTCPMsg(conn)
		if err != nil {
			if !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.EOF) {
				log.Debugf("TLCP: DoT read error from %s: %v", clientIP, err)
			}
			return
		}

		resp := s.handler.ServeDNS(msg, clientIP, true, config.ProtoTLCP)
		pool.DefaultMessage.Put(msg)
		if resp == nil {
			return
		}

		if err := zdnsutil.WriteTCPMsg(conn, resp); err != nil {
			log.Debugf("TLCP: DoT write error to %s: %v", clientIP, err)
			pool.DefaultMessage.Put(resp)
			return
		}
		pool.DefaultMessage.Put(resp)
	}
}
