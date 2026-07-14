package tlcp

import (
	"errors"
	"fmt"
	"io"
	"net"
	"zjdns/config"
	zdnsutil "zjdns/internal/dnsutil"
	"zjdns/internal/log"

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
	addrs, err := zdnsutil.ResolveBindAddrs("tcp", s.cfg.Port)
	if err != nil {
		return fmt.Errorf("resolve bind addrs: %w", err)
	}

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
		log.Infof("TLCP: DoT server started on %s (TLCP)", addr)

		go s.serveDOT(tlcpListener)
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
		go s.handleDOTConn(conn)
	}
}

func (s *Server) handleDOTConn(conn net.Conn) {
	defer zdnsutil.HandlePanic("TLCP DoT handler")
	defer func() { _ = conn.Close() }()

	clientIP := clientIPFromAddr(conn.RemoteAddr())

	for {
		msg, err := readTCPMsg(conn)
		if err != nil {
			if !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.EOF) {
				log.Debugf("TLCP: DoT read error from %s: %v", clientIP, err)
			}
			return
		}

		resp := s.handler.ServeDNS(msg, clientIP, true, config.ProtoTLCP)
		if resp == nil {
			return
		}

		if err := writeTCPMsg(conn, resp); err != nil {
			log.Debugf("TLCP: DoT write error to %s: %v", clientIP, err)
			return
		}
	}
}

// readTCPMsg reads a DNS message prefixed with a 2-byte big-endian length.
func readTCPMsg(conn net.Conn) (*dns.Msg, error) {
	var prefix [2]byte
	if _, err := io.ReadFull(conn, prefix[:]); err != nil {
		return nil, err
	}
	length := int(prefix[0])<<8 | int(prefix[1])
	buf := make([]byte, length)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}
	msg := new(dns.Msg)
	msg.Data = buf
	if err := msg.Unpack(); err != nil {
		return nil, err
	}
	return msg, nil
}

// writeTCPMsg writes a DNS message prefixed with a 2-byte big-endian length.
func writeTCPMsg(conn net.Conn, msg *dns.Msg) error {
	if err := msg.Pack(); err != nil {
		return err
	}
	length := uint16(len(msg.Data))                    //nolint:gosec // G115: DNS TCP message — protocol-bounded uint16
	prefix := [2]byte{byte(length >> 8), byte(length)} //nolint:gosec // G115: DNS wire format — protocol-bounded byte
	if _, err := conn.Write(prefix[:]); err != nil {
		return err
	}
	_, err := conn.Write(msg.Data)
	return err
}

// clientIPFromAddr extracts the IP address from a net.Addr.
func clientIPFromAddr(addr net.Addr) net.IP {
	switch a := addr.(type) {
	case *net.TCPAddr:
		return a.IP
	case *net.UDPAddr:
		return a.IP
	default:
		host, _, err := net.SplitHostPort(addr.String())
		if err != nil {
			return nil
		}
		return net.ParseIP(host)
	}
}
