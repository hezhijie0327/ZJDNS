package demux

import (
	"net"
	"sync"
	"time"
	zdnsutil "zjdns/internal/dnsutil"
	"zjdns/internal/log"
)

// TCPConfig configures a TCP demux listener.
//
// Inner is the raw TCP listener to accept connections from.
// Routes maps protocol family names ("tls", "tlcp") to connection wrapper
// functions.  Each wrapper receives the detected connection (with the
// record header buffered for replay) and returns a protocol-specific
// connection (e.g. eTLS.Server(c, cfg) or tlcp.Server(c, cfg)).
//
// Connections whose detected protocol has no matching route are closed
// immediately.
type TCPConfig struct {
	Inner  net.Listener
	Routes map[string]func(net.Conn) net.Conn

	// SniffConcurrency bounds concurrent sniff goroutines; <= 0 selects the
	// package default.  Injected by the caller (the wiring layer reads the
	// config) — internal/ packages must not import config.
	SniffConcurrency int
}

// TCPDemuxListener demultiplexes TCP connections by record-layer protocol.
// Each accepted connection is inspected via DetectTCPProtocol; the detected
// protocol selects a route wrapper and a per-protocol queue.  Callers
// retrieve virtual net.Listeners via Listener() and pass them to
// http.Server.Serve or manual accept loops.
type TCPDemuxListener struct {
	inner  net.Listener
	routes map[string]func(net.Conn) net.Conn
	queues map[string]*protocolQueue
	// sniffSem bounds concurrent sniff goroutines (see TCPConfig).
	sniffSem chan struct{}
	mu       sync.Mutex
	closed   bool
	done     chan struct{} // closed when the accept loop exits
}

// defaultSniffConcurrency bounds concurrent sniff goroutines when the
// caller does not configure one: each accepted connection spawns a sniffer
// that lives up to sniffTimeout when the peer is silent — an unbounded
// spawn would let a connect flood (port scanners) exhaust goroutines and
// fds while the downstream LimitListeners only gate post-sniff.
const defaultSniffConcurrency = 4096

// acceptRetryDelay mirrors config.DefaultAcceptRetryDelay — internal/
// packages must not import config (see TCPConfig.SniffConcurrency), so the
// value is restated locally with the same 100ms backoff as every other
// accept loop in the tree.
const acceptRetryDelay = 100 * time.Millisecond

// NewTCPDemux creates and starts a TCP demux listener.  The accept loop
// runs in a background goroutine and exits when Close() is called; accept
// errors are logged and retried with a backoff (it never exits on its
// own).
func NewTCPDemux(cfg TCPConfig) *TCPDemuxListener {
	sniffLimit := cfg.SniffConcurrency
	if sniffLimit <= 0 {
		sniffLimit = defaultSniffConcurrency
	}
	d := &TCPDemuxListener{
		inner:    cfg.Inner,
		routes:   cfg.Routes,
		queues:   make(map[string]*protocolQueue),
		done:     make(chan struct{}),
		sniffSem: make(chan struct{}, sniffLimit),
	}

	// Pre-create a queue for each configured route so that Listener()
	// returns a valid net.Listener even before any connection arrives.
	for proto := range cfg.Routes {
		d.queues[proto] = newProtocolQueue(cfg.Inner.Addr())
	}

	go d.acceptLoop()
	return d
}

// Listener returns the virtual net.Listener for the given protocol family.
// The returned listener yields connections whose protocol was detected as
// "protocol" and that have been wrapped by the corresponding route function.
//
// Returns nil if no route is configured for the protocol.
func (d *TCPDemuxListener) Listener(protocol string) net.Listener {
	d.mu.Lock()
	defer d.mu.Unlock()
	if q, ok := d.queues[protocol]; ok {
		return q
	}
	return nil
}

// Close stops the accept loop and closes all per-protocol queues.
func (d *TCPDemuxListener) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil
	}
	d.closed = true
	_ = d.inner.Close()
	for _, q := range d.queues {
		_ = q.Close()
	}
	return nil
}

// Done returns a channel that is closed when the accept loop exits.
func (d *TCPDemuxListener) Done() <-chan struct{} {
	return d.done
}

func (d *TCPDemuxListener) acceptLoop() {
	defer close(d.done)
	defer zdnsutil.HandlePanic("TCP demux accept")

	for {
		conn, err := d.inner.Accept()
		if err != nil {
			// Check if we're shutting down.
			d.mu.Lock()
			closed := d.closed
			d.mu.Unlock()
			if closed {
				return
			}
			// Same discipline as every other accept loop in the tree
			// (plain/tcp.go, tls/tls.go, shared/tcp.go, ...): log, back
			// off, keep serving.  Returning here would silently kill the
			// whole shared TCP port until process restart — this loop is
			// its only accept entry — and a bare continue would spin at
			// 100% CPU under a sustained EMFILE condition.  A non-temporary
			// accept error (EPERM, ENOMEM, EBADF, EINVAL) is usually a
			// transient resource condition, not a reason to die.
			if ne, ok := err.(interface{ Temporary() bool }); ok && ne.Temporary() {
				time.Sleep(acceptRetryDelay)
				continue
			}
			log.Warnf("PLAIN: TCP demux accept error: %v — retrying", err)
			time.Sleep(acceptRetryDelay)
			continue
		}

		// Sniff off the accept loop: DetectTCPProtocol blocks on the
		// client's first bytes, and a silent client must not stall accepts
		// on the shared port.  The per-conn goroutine dies with the bounded
		// sniff (or the push); the queue is channel-based, so concurrent
		// pushes are safe.  Try-acquire the sniff slot first: a flood of
		// silent clients is dropped at the gate instead of exhausting
		// goroutines/fds for the full sniffTimeout window.
		select {
		case d.sniffSem <- struct{}{}:
		default:
			_ = conn.Close()
			continue
		}
		go func() {
			defer func() { <-d.sniffSem }()
			d.handleConn(conn)
		}()
	}
}

// handleConn sniffs one accepted connection and routes it to its protocol
// queue (or closes it).
func (d *TCPDemuxListener) handleConn(conn net.Conn) {
	defer zdnsutil.HandlePanic("TCP demux sniff")
	proto, detected, detectErr := DetectTCPProtocol(conn)
	if detectErr != nil {
		_ = conn.Close()
		return
	}

	d.mu.Lock()
	wrapper, ok := d.routes[proto]
	q := d.queues[proto]
	d.mu.Unlock()
	if !ok || q == nil {
		// Unknown or unconfigured protocol — close.
		_ = detected.Close()
		return
	}

	wrapped := wrapper(detected)
	if !q.push(wrapped) {
		// Queue full or closed — drop the connection.
		_ = wrapped.Close()
	}
}
