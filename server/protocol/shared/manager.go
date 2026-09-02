// Package shared implements port multiplexing for TLS+TLCP (TCP) and
// QUIC+DTLS+DTLCP (UDP).  Multiple protocols share a single port via
// record-layer demultiplexing without coupling to any specific protocol
// server implementation.
package shared

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync"
	"zjdns/config"

	dtlsnet "github.com/pion/dtls/v3/pkg/net"
	eHTTP "gitlab.com/go-extension/http"
	eTLS "gitlab.com/go-extension/tls"
)

// Host is the minimal interface the protocol server must implement for
// the shared-port Manager to schedule goroutines and observe cancellation.
type Host interface {
	Go(f func() error)
	Ctx() context.Context
}

// TCPGroup describes one TCP shared port and its protocol handlers.
// A typical deployment has two groups: one for HTTPS+HTTPoverTLCP+DNSCrypt
// on port 443 and one for DoT+DoT(TLCP) on port 853.
type TCPGroup struct {
	Port       string
	TLSCfg     *eTLS.Config
	NextProtos []string // TLS NextProtos (e.g. config.NextProtoDOH or config.NextProtoDOT)

	// TLS side: either DOHHandler (HTTP-level) or DOTHandler (raw listener).
	DOHHandler eHTTP.Handler
	DOTHandler func(net.Listener) error

	// TLCP side: either DOHTLCP (HTTP-level) or DOTTLCP (raw listener).
	DOHTLCP http.Handler
	DOTTLCP func(net.Listener)

	// DNSCrypt TCP (only on HTTPS port).
	ServeDNSCryptTCP func(ctx context.Context, conn net.Conn)

	// TLCP connection wrapping.
	WrapConn func(c net.Conn, nextProtos []string) net.Conn
}

// UDPGroup describes one UDP shared port and its protocol handlers.
// A typical deployment has one group (e.g. QUIC+DTLS+DTLCP on 853);
// a multi-port deployment (e.g. QUIC on 853 and DNSCrypt+HTTP3 on 443)
// uses two groups.
type UDPGroup struct {
	Port             string
	DOQHandler       func(net.PacketConn) error
	HTTP3Handler     func(net.PacketConn) error
	DTLSHandler      func(dtlsnet.PacketListener) error
	ServeDTLCP       func(pc net.PacketConn, src *net.UDPAddr, cleanup func())
	ServeDNSCrypt    func(ctx context.Context, data []byte, src net.Addr, pc net.PacketConn)
	ClassifyDNSCrypt func(data []byte) string
}

// Config carries all handlers and configuration the Manager needs from
// the TLS and TLCP protocol servers.  All fields are optional; the
// Manager starts only the port pairs for which handlers are provided.
type Config struct {
	// TCP shared port groups.  Each group binds one TCP port and
	// demultiplexes among TLS/TLCP/DNSCrypt by record-layer detection.
	TCPGroups []TCPGroup

	// UDP shared port groups.  Each group binds one UDP port and
	// demultiplexes among its configured protocols.
	UDPGroups []UDPGroup
}

// tcpRuntime holds the runtime state for one TCP shared port group.
type tcpRuntime struct {
	cfg     *TCPGroup
	demux   tcpDemuxCloser
	dohSrv  *eHTTP.Server
	tlcpSrv *http.Server
	tlcpLn  net.Listener
}

// udpRuntime holds the runtime state for one UDP shared port group.
type udpRuntime struct {
	cfg        *UDPGroup
	conn       *net.UDPConn
	dtlsPL     *dtlsPacketListener
	quicPC     *quicPacketConn
	h3PC       *quicPacketConn
	dcState    *sharedDNSCryptClient
	dtlcpState *sharedDTLSClient

	// clientSem bounds concurrent per-client handler goroutines (DTLCP
	// handshake/service, DNSCrypt drain).  Without a try-acquire cap, a
	// spoofed-source flood created one DemuxPacketConn + goroutine per
	// unique (IP, port) for the idle-reap window — unbounded (2026-09 P3).
	clientSem chan struct{}
}

// Manager manages shared-port resources for all protocol pairs.
// It owns a cancelable lifecycle context and a mutex for resource tracking,
// with zero coupling to the tlcp.Server struct.  Handler goroutines are
// scheduled on the Host (whose group the server shutdown waits on); the
// per-client flood bound is udpRuntime.clientSem, not a scheduling limit.
type Manager struct {
	host Host
	cfg  *Config

	mu sync.Mutex
	// TCP shared port runtimes (one per TCPGroup).
	tcpRuntimes []*tcpRuntime
	// UDP shared port runtimes (one per UDPGroup).
	udpRuntimes []*udpRuntime

	groupCtx    context.Context
	groupCancel context.CancelCauseFunc
}

// tcpDemuxCloser is a minimal interface for closing a TCP demux listener.
type tcpDemuxCloser interface {
	Close() error
	Listener(proto string) net.Listener
}

// New creates a shared-port Manager.
func New(host Host, cfg *Config) *Manager {
	groupCtx, groupCancel := context.WithCancelCause(host.Ctx())
	return &Manager{
		host:        host,
		cfg:         cfg,
		groupCtx:    groupCtx,
		groupCancel: groupCancel,
	}
}

// admit reserves a per-client handler slot; it never blocks the dispatch
// loop — over-cap sources are dropped (UDP semantics, clients retransmit).
func (rt *udpRuntime) admit() bool {
	select {
	case rt.clientSem <- struct{}{}:
		return true
	default:
		return false
	}
}

// release frees a slot reserved by admit (run when the client handler
// exits, including via reap-driven channel close).
func (rt *udpRuntime) release() { <-rt.clientSem }

// Start launches all configured shared-port listeners.
func (m *Manager) Start() error {
	for i := range m.cfg.TCPGroups {
		if err := m.startTCPGroup(&m.cfg.TCPGroups[i]); err != nil {
			return err
		}
	}
	for i := range m.cfg.UDPGroups {
		if err := m.startUDPGroup(&m.cfg.UDPGroups[i]); err != nil {
			return err
		}
	}
	return nil
}

// Shutdown gracefully stops all shared-port listeners and servers.
func (m *Manager) Shutdown() {
	m.groupCancel(errors.New("shared port shutdown"))

	m.mu.Lock()
	tcpRTs := append([]*tcpRuntime(nil), m.tcpRuntimes...)
	udpRTs := append([]*udpRuntime(nil), m.udpRuntimes...)
	m.mu.Unlock()

	for _, rt := range tcpRTs {
		if rt.dohSrv != nil {
			ctx, cancel := context.WithTimeout(context.Background(), config.DefaultShutdownTimeout)
			_ = rt.dohSrv.Shutdown(ctx) // _ = error: best-effort shutdown sweep
			cancel()
		}
		if rt.tlcpSrv != nil {
			ctx, cancel := context.WithTimeout(context.Background(), config.DefaultShutdownTimeout)
			_ = rt.tlcpSrv.Shutdown(ctx) // _ = error: best-effort shutdown sweep
			cancel()
		}
		if rt.tlcpLn != nil {
			_ = rt.tlcpLn.Close() // _ = error: best-effort close sweep
		}
		if rt.demux != nil {
			_ = rt.demux.Close() // _ = error: best-effort close sweep (drains queued conns)
		}
	}
	for _, rt := range udpRTs {
		if rt.quicPC != nil {
			_ = rt.quicPC.Close() // _ = error: best-effort close sweep
		}
		if rt.h3PC != nil {
			_ = rt.h3PC.Close() // _ = error: best-effort close sweep
		}
		if rt.dtlsPL != nil {
			_ = rt.dtlsPL.Close() // _ = error: best-effort close sweep
		}
		if rt.conn != nil {
			_ = rt.conn.Close() // _ = error: best-effort close sweep; unblocks the dispatch loop for its exit sweep
		}
	}
}
