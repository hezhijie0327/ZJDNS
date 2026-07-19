package udp

import (
	"context"
	stdtls "crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"
	"zjdns/internal/log"
	"zjdns/server/protocol/shared"

	"gitee.com/Trisia/gotlcp/dtlcp"
	"github.com/pion/dtls/v3"
)

// singlePacketListener wraps a single udpPacketConn as a net.PacketListener
// that returns one connection and then blocks.  Used to feed a per-client
// virtual socket into pion/dtls's listener machinery.
type singlePacketListener struct {
	pconn *udpPacketConn
	addr  net.Addr
	done  bool
}

// udpClientState tracks a single client in the shared UDP listener.
type udpClientState struct {
	proto string              // "dtls" or "dtlcp"
	pconn *udpPacketConn      // per-client virtual socket
	queue chan udpDemuxPacket // incoming packets
	addr  *net.UDPAddr
}

type udpAccept struct {
	conn net.Conn
	err  error
}

// Listener wraps a *net.UDPConn and auto-detects DTLS vs DTLCP on
// each new client's first datagram.  Detection uses the TLS record layer
// header: major version 0x03 = DTLS, 0x01 = DTLCP.
//
// A background demultiplexer reads from the shared UDP socket and routes
// packets to per-client virtual sockets, preventing packet-stealing between
// concurrent DTLS and DTLCP connections.
type Listener struct {
	conn     net.PacketConn
	dtlsCert *stdtls.Certificate
	dtlcpCfg *dtlcp.Config
	ctx      context.Context
	cancel   context.CancelCauseFunc

	mu       sync.Mutex
	clients  map[string]*udpClientState
	acceptCh chan *udpAccept
	closed   bool
}

// NewListener creates a port-sharing UDP listener for DTLS + DTLCP.
// Call Start() after construction to begin the demux read loop.
func NewListener(conn net.PacketConn, dtlsCert *stdtls.Certificate, dtlcpCfg *dtlcp.Config) *Listener {
	ctx, cancel := context.WithCancelCause(context.Background())
	return &Listener{
		conn:     conn,
		dtlsCert: dtlsCert,
		dtlcpCfg: dtlcpCfg,
		ctx:      ctx,
		cancel:   cancel,
		clients:  make(map[string]*udpClientState),
		acceptCh: make(chan *udpAccept),
	}
}

// Start begins the background demux read loop.
func (l *Listener) Start() {
	go l.demuxLoop()
}

// Accept waits for a new client and returns the handshaked DTLS or DTLCP
// connection.
func (l *Listener) Accept() (net.Conn, error) {
	result := <-l.acceptCh
	return result.conn, result.err
}

// Close stops the demux loop and closes the underlying UDP socket.
func (l *Listener) Close() error {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil
	}
	l.closed = true
	l.cancel(errors.New("shared UDP listener closed"))
	l.mu.Unlock()
	return l.conn.Close()
}

// Addr returns the underlying UDP socket's local address.
func (l *Listener) Addr() net.Addr {
	return l.conn.LocalAddr()
}

// demuxLoop reads datagrams from the shared UDP socket and routes them to
// per-client virtual sockets.  New clients trigger protocol detection and
// connection handoff via Accept().
func (l *Listener) demuxLoop() {
	buf := make([]byte, 65536)
	for {
		select {
		case <-l.ctx.Done():
			return
		default:
		}

		n, remoteAddr, err := l.conn.ReadFrom(buf)
		if err != nil {
			if l.ctx.Err() != nil {
				return
			}
			log.Debugf("SHARED: UDP demux read error: %v", err)
			return
		}
		udpAddr, ok := remoteAddr.(*net.UDPAddr)
		if !ok {
			continue
		}

		key := udpAddr.String()
		l.mu.Lock()
		client, exists := l.clients[key]
		if exists {
			pkt := make([]byte, n)
			copy(pkt, buf[:n])
			select {
			case client.queue <- udpDemuxPacket{data: pkt, remote: udpAddr}:
			default:
				log.Debugf("SHARED: UDP dropping packet for %s (queue full)", key)
			}
			l.mu.Unlock()
			continue
		}

		// New client — detect protocol.
		if n < shared.RecordHeaderLen {
			l.mu.Unlock()
			log.Debugf("SHARED: UDP short packet (%d bytes) from %s, dropping", n, key)
			continue
		}

		var proto string
		switch shared.ClassifyRecordHeader(buf[:shared.RecordHeaderLen]) {
		case shared.VersionDTLS:
			proto = "dtls"
		case shared.VersionTLCP:
			proto = "dtlcp"
		default:
			l.mu.Unlock()
			log.Debugf("SHARED: UDP unknown protocol from %s, dropping", key)
			continue
		}

		// Buffer the first packet for the handshake.
		firstPkt := make([]byte, n)
		copy(firstPkt, buf[:n])
		queue := make(chan udpDemuxPacket, 64)
		queue <- udpDemuxPacket{data: firstPkt, remote: udpAddr}

		pconn := &udpPacketConn{
			realConn: l.conn,
			queue:    queue,
			remote:   udpAddr,
		}

		client = &udpClientState{
			proto: proto,
			pconn: pconn,
			queue: queue,
			addr:  udpAddr,
		}
		l.clients[key] = client
		l.mu.Unlock()

		// Create the protocol-specific connection.
		var conn net.Conn
		var acceptErr error
		switch proto {
		case "dtls":
			conn, acceptErr = l.createDTLSConn(pconn, udpAddr)
		case "dtlcp":
			conn, acceptErr = l.createDTLCPConn(pconn, udpAddr)
		}

		if acceptErr != nil {
			l.mu.Lock()
			delete(l.clients, key)
			l.mu.Unlock()
			log.Debugf("SHARED: UDP %s conn from %s failed: %v", proto, key, acceptErr)
		}

		select {
		case l.acceptCh <- &udpAccept{conn: conn, err: acceptErr}:
		case <-l.ctx.Done():
			return
		}
	}
}

// createDTLSConn creates a DTLS server connection from a per-client virtual
// PacketConn, using pion/dtls's listener machinery.
func (l *Listener) createDTLSConn(pconn *udpPacketConn, addr *net.UDPAddr) (net.Conn, error) {
	pl := &singlePacketListener{pconn: pconn, addr: addr}
	dtlsLn, err := dtls.NewListenerWithOptions(pl, dtls.WithCertificates(*l.dtlsCert))
	if err != nil {
		return nil, fmt.Errorf("shared: create DTLS listener: %w", err)
	}
	conn, err := dtlsLn.Accept()
	_ = dtlsLn.Close()
	return conn, err
}

// createDTLCPConn creates a DTLCP server connection from a per-client virtual
// PacketConn.
func (l *Listener) createDTLCPConn(pconn *udpPacketConn, addr *net.UDPAddr) (net.Conn, error) {
	conn := dtlcp.Server(pconn, addr, l.dtlcpCfg)
	if err := conn.Handshake(); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("shared: DTLCP handshake: %w", err)
	}
	return conn, nil
}

// singlePacketListener methods.

func (pl *singlePacketListener) Accept() (net.PacketConn, net.Addr, error) {
	if pl.done {
		return nil, nil, net.ErrClosed
	}
	pl.done = true
	return pl.pconn, pl.addr, nil
}

func (pl *singlePacketListener) Close() error   { return nil }
func (pl *singlePacketListener) Addr() net.Addr { return pl.pconn.LocalAddr() }
