package udp

import (
	"context"
	"errors"
	"net"
	"time"
	"zjdns/config"
	"zjdns/edns"
	zdnsutil "zjdns/internal/dnsutil"
	"zjdns/internal/log"

	"gitee.com/Trisia/gotlcp/dtlcp"
)

// acceptLoop accepts connections from listener and dispatches each to handle
// in its own goroutine.  Returns when ctx is cancelled or the listener is
// closed.
func acceptLoop(listener net.Listener, handle func(net.Conn), ctx context.Context, name string) {
	defer zdnsutil.HandlePanic("Shared " + name + " server")

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			log.Warnf("SHARED: %s Accept failed: %v (type=%T)", name, err, err)
			time.Sleep(config.DefaultAcceptRetryDelay)
			continue
		}

		go handle(conn)
	}
}

// ServeDTLS accepts connections from a shared UDP listener and handles
// each one as a DNS-over-DTLS or DNS-over-DTLCP connection.
func ServeDTLS(listener net.Listener, handler edns.DNSHandler, ctx context.Context) {
	acceptLoop(listener, func(conn net.Conn) {
		defer zdnsutil.HandlePanic("Shared DTLS handler")
		defer func() { _ = conn.Close() }()

		protoLabel := "DTLS"
		if _, ok := conn.(*dtlcp.Conn); ok {
			protoLabel = "DTLCP"
		}
		log.Debugf("SHARED: DTLS %s connection from %s", protoLabel, conn.RemoteAddr())

		handleSharedDTLSConn(conn, handler, protoLabel)
	}, ctx, "DTLS")
}
