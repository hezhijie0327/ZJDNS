package demux

import (
	"net"
	"sync"
	"zjdns/config"
	zdnsutil "zjdns/internal/dnsutil"
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
}

// TCPDemuxListener demultiplexes TCP connections by record-layer protocol.
// Each accepted connection is inspected via DetectTCPProtocol; the detected
// protocol selects a route wrapper and a per-protocol queue.  Callers
// retrieve virtual net.Listeners via Listener() and pass them to
// http.Server.Serve, eHTTP.Server.Serve, or manual accept loops.
type TCPDemuxListener struct {
	inner  net.Listener
	routes map[string]func(net.Conn) net.Conn
	queues map[string]*protocolQueue
	mu     sync.Mutex
	closed bool
	done   chan struct{} // closed when the accept loop exits
}

// sniffSem bounds concurrent sniff goroutines: each accepted connection
// spawns one and lives up to sniffTimeout when the peer is silent — an
// unbounded spawn let a connect flood (port scanners) exhaust goroutines
// and fds while the downstream LimitListeners only gate post-sniff (P-M6).
var sniffSem = make(chan struct{}, config.DefaultServerGoroutineLimit)

// NewTCPDemux creates and starts a TCP demux listener.  The accept loop
// runs in a background goroutine and exits when Close() is called or the
// inner listener returns a non-temporary error.
func NewTCPDemux(cfg TCPConfig) *TCPDemuxListener {
	d := &TCPDemuxListener{
		inner:  cfg.Inner,
		routes: cfg.Routes,
		queues: make(map[string]*protocolQueue),
		done:   make(chan struct{}),
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
			// Temporary errors: retry (mirrors the pattern used by
			// all other accept loops in the codebase).
			if ne, ok := err.(interface{ Temporary() bool }); ok && ne.Temporary() {
				continue
			}
			return
		}

		// Sniff off the accept loop: DetectTCPProtocol blocks on the
		// client's first bytes, and a silent client (scanner, health
		// check) used to stall the WHOLE shared port — no further
		// connection was even accepted while one peer sat silent.  The
		// per-conn goroutine dies with the bounded sniff (or the push);
		// the queue is channel-based, so concurrent pushes are safe.
		// Try-acquire the sniff slot first: a flood of silent clients
		// is dropped at the gate instead of exhausting goroutines/fds
		// for the full sniffTimeout window (P-M6).
		select {
		case sniffSem <- struct{}{}:
		default:
			_ = conn.Close()
			continue
		}
		go func() {
			defer func() { <-sniffSem }()
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
