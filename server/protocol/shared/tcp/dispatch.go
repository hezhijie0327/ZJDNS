package tcp

import (
	"context"
	"errors"
	"net"
	"net/http"
	"zjdns/internal/log"

	zdnsutil "zjdns/internal/dnsutil"

	"gitee.com/Trisia/gotlcp/tlcp"
	eTLS "gitlab.com/go-extension/tls"
)

// connListener adapts a single net.Conn into a net.Listener that returns
// that conn once and then blocks forever.  Used to feed individual TLS/TLCP
// connections into an http.Server without giving the server its own accept
// loop.
type connListener struct {
	conn net.Conn
	done chan struct{}
}

func (l *connListener) Accept() (net.Conn, error) {
	if l.done == nil {
		l.done = make(chan struct{})
		return l.conn, nil
	}
	<-l.done
	return nil, net.ErrClosed
}

func (l *connListener) Close() error {
	if l.done != nil {
		close(l.done)
	}
	return l.conn.Close()
}

func (l *connListener) Addr() net.Addr { return l.conn.LocalAddr() }

// ServeDispatch accepts connections from a shared listener and dispatches
// them based on protocol:
//   - *eTLS.Conn / *tlcp.Conn → per-connection HTTP/1.1 server
//   - raw net.Conn            → rawHandler (e.g. DNSCrypt TCP)
func ServeDispatch(listener net.Listener, httpSrv *http.Server, rawHandler func(net.Conn), ctx context.Context) {
	defer zdnsutil.HandlePanic("Shared dispatch server")

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
			log.Warnf("SHARED: dispatch Accept failed: %v", err)
			continue
		}

		switch conn.(type) {
		case *eTLS.Conn, *tlcp.Conn:
			go func() {
				defer zdnsutil.HandlePanic("Shared dispatch HTTP")
				_ = httpSrv.Serve(&connListener{conn: conn})
			}()
		default:
			if rawHandler != nil {
				go rawHandler(conn)
			} else {
				log.Debugf("SHARED: no handler for raw connection from %s, closing", conn.RemoteAddr())
				_ = conn.Close()
			}
		}
	}
}
