package tcp

import (
	"context"
	"errors"
	"net"
	"time"
	"zjdns/config"
	"zjdns/edns"
	zdnsutil "zjdns/internal/dnsutil"
	"zjdns/internal/log"

	"gitee.com/Trisia/gotlcp/tlcp"
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

// ServeDOT accepts connections from a shared TLS/TLCP listener and handles
// each one as a DNS-over-TCP connection.
func ServeDOT(listener net.Listener, handler edns.DNSHandler, ctx context.Context) {
	acceptLoop(listener, func(conn net.Conn) {
		defer zdnsutil.HandlePanic("Shared DoT handler")
		defer func() { _ = conn.Close() }()

		protoLabel := "TLS"
		if _, ok := conn.(*tlcp.Conn); ok {
			protoLabel = "TLCP"
		}
		log.Debugf("SHARED: DoT %s connection from %s", protoLabel, conn.RemoteAddr())

		handleSharedDOTConn(conn, handler, ctx, protoLabel)
	}, ctx, "DoT")
}
