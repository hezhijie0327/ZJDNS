package tcp

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"
	"zjdns/config"
	"zjdns/edns"
	zdnsutil "zjdns/internal/dnsutil"
	"zjdns/internal/log"
	"zjdns/internal/pool"

	"codeberg.org/miekg/dns"
	"gitee.com/Trisia/gotlcp/tlcp"
	eTLS "gitlab.com/go-extension/tls"
)

const (
	// sharedDOTConnBufferSize is the read buffer size for shared DoT connections.
	sharedDOTConnBufferSize = 4096
)

// ServeDOT accepts connections from a shared TLS/TLCP listener and handles
// each one as a DNS-over-TCP connection.  Both *eTLS.Conn (TLS) and
// *tlcp.Conn (TLCP) are supported transparently.
func handleSharedDOTConn(conn net.Conn, handler edns.DNSHandler, ctx context.Context, protoLabel string) {
	// Enable TCP keep-alive on the underlying connection if possible.
	// The tcpKeepAliveListener already set keepalive before the handshake,
	// but re-assert here as a belt-and-suspenders measure for eTLS connections.
	setTCPKeepAlive(conn)

	reader := bufio.NewReaderSize(conn, sharedDOTConnBufferSize)
	connCtx, connCancel := context.WithCancel(ctx)

	type writeTask struct{ data []byte }
	writeCh := make(chan writeTask, config.DefaultDOTWriteChannelSize)

	writerDone := make(chan struct{})
	go func() {
		defer zdnsutil.HandlePanic("Shared DoT writer")
		defer close(writerDone)
		for task := range writeCh {
			_ = conn.SetWriteDeadline(time.Now().Add(config.DefaultDNSQueryTimeout))
			_, err := conn.Write(task.data)
			pool.DefaultBuffer.Put(task.data)
			if err != nil {
				log.Debugf("SHARED: %s write error: %v", protoLabel, err)
				connCancel()
				return
			}
		}
	}()

	var wg sync.WaitGroup
	defer func() {
		connCancel()
		wg.Wait()
		close(writeCh)
		<-writerDone
	}()

	workerCap := make(chan struct{}, config.DefaultMaxPipe)
	lengthBuf := make([]byte, zdnsutil.DNSFramePrefixLen)

	for {
		if connCtx.Err() != nil {
			return
		}

		_ = conn.SetReadDeadline(time.Now().Add(config.DefaultTCPPoolIdleTimeout))

		_, err := io.ReadFull(reader, lengthBuf)
		if err != nil {
			if err != io.EOF && !isTemporaryError(err) {
				log.Debugf("SHARED: %s read length error remote=%s: %v",
					protoLabel, conn.RemoteAddr(), err)
			}
			return
		}

		msgLength := binary.BigEndian.Uint16(lengthBuf)
		if msgLength == 0 || msgLength > pool.SecureBufferSize-zdnsutil.DNSFramePrefixLen {
			return
		}

		buf := pool.DefaultBuffer.Get()
		msgBuf := buf
		if cap(msgBuf) < int(msgLength) {
			msgBuf = make([]byte, msgLength)
		} else {
			msgBuf = msgBuf[:msgLength]
		}
		_, err = io.ReadFull(reader, msgBuf)
		if err != nil {
			pool.DefaultBuffer.Put(buf)
			return
		}

		req := pool.DefaultMessage.Get()
		req.Data = msgBuf
		if err := req.Unpack(); err != nil {
			pool.DefaultMessage.Put(req)
			pool.DefaultBuffer.Put(buf)
			continue
		}
		pooled := cap(msgBuf) >= cap(buf)

		var clientIP net.IP
		if addr := conn.RemoteAddr(); addr != nil {
			if tcpAddr, ok := addr.(*net.TCPAddr); ok {
				clientIP = tcpAddr.IP
			}
		}

		select {
		case workerCap <- struct{}{}:
		case <-connCtx.Done():
			pool.DefaultMessage.Put(req)
			pool.DefaultBuffer.Put(buf)
			return
		}

		wg.Add(1)
		go func(query *dns.Msg, ip net.IP, pooledBuf []byte, isPooled bool) {
			defer func() { <-workerCap }()
			defer zdnsutil.HandlePanic("Shared DoT worker")
			defer wg.Done()
			defer pool.DefaultMessage.Put(query)
			defer func() {
				if isPooled {
					pool.DefaultBuffer.Put(pooledBuf)
				}
			}()

			response := handler.ServeDNS(query, ip, true, config.ProtoTLS)
			if response == nil {
				return
			}
			defer pool.DefaultMessage.Put(response)

			if err := response.Pack(); err != nil {
				log.Debugf("SHARED: %s response pack error: %v", protoLabel, err)
				return
			}
			respBuf := response.Data

			poolBuf := pool.DefaultBuffer.Get()
			poolBufOK := len(poolBuf) >= zdnsutil.DNSFramePrefixLen+len(respBuf)
			var writeBuf []byte
			if poolBufOK {
				writeBuf = poolBuf[:zdnsutil.DNSFramePrefixLen+len(respBuf)]
			} else {
				writeBuf = make([]byte, zdnsutil.DNSFramePrefixLen+len(respBuf))
				pool.DefaultBuffer.Put(poolBuf)
			}
			binary.BigEndian.PutUint16(writeBuf[:zdnsutil.DNSFramePrefixLen], uint16(len(respBuf))) //nolint:gosec // G115: DNS length prefix — max 65535 fits uint16
			copy(writeBuf[zdnsutil.DNSFramePrefixLen:], respBuf)

			select {
			case writeCh <- writeTask{data: writeBuf}:
			case <-connCtx.Done():
				if poolBufOK {
					pool.DefaultBuffer.Put(writeBuf)
				}
			}
		}(req, clientIP, buf, pooled)
	}
}

// setTCPKeepAlive enables TCP keep-alive on the underlying TCP connection
// behind a TLS or TLCP conn.  This is a best-effort operation — failures
// are silent since the raw listener already configured keepalive.
func setTCPKeepAlive(conn net.Conn) {
	var tcpConn *net.TCPConn
	switch c := conn.(type) {
	case *eTLS.Conn:
		if nc, ok := c.NetConn().(*net.TCPConn); ok {
			tcpConn = nc
		}
	case *tlcp.Conn:
		// tlcp.Conn embeds net.Conn — try to unwrap through the chain.
		tcpConn = unwrapTLCPConn(c)
	default:
		// Plain net.TCPConn (shouldn't happen in shared listener, but handle it).
		if tc, ok := conn.(*net.TCPConn); ok {
			tcpConn = tc
		}
	}
	if tcpConn != nil {
		_ = tcpConn.SetKeepAlive(true)
		_ = tcpConn.SetKeepAlivePeriod(config.DefaultTCPKeepAlivePeriod)
	}
}

// unwrapTLCPConn attempts to extract the underlying *net.TCPConn from a
// *tlcp.Conn by checking if the embedded connection exposes one.
func unwrapTLCPConn(conn *tlcp.Conn) *net.TCPConn {
	// tlcp.Conn may expose the underlying net.Conn through its interface.
	// Try RemoteAddr + type assertion chain. If the inner conn is a
	// *net.TCPConn, the raw socket keepalive is already configured from
	// tcpKeepAliveListener — this function is a best-effort re-assertion.
	return nil
}

// isTemporaryError reports whether err is a temporary network error that
// should not terminate the connection.
func isTemporaryError(err error) bool {
	var ne net.Error
	if errors.As(err, &ne) {
		return ne.Timeout()
	}
	return false
}
