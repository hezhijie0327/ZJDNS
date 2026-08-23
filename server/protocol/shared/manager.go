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
	"golang.org/x/sync/errgroup"
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
	cfg     *UDPGroup
	conn    *net.UDPConn
	dtlsPL  *dtlsPacketListener
	quicPC  *quicPacketConn
	h3PC    *quicPacketConn
	dcState *sharedDNSCryptClient
}

// Manager manages shared-port resources for all protocol pairs.
// It owns its own errgroup for goroutine lifecycle and a mutex for
// resource tracking, with zero coupling to the tlcp.Server struct.
type Manager struct {
	host Host
	cfg  *Config

	mu sync.Mutex
	// TCP shared port runtimes (one per TCPGroup).
	tcpRuntimes []*tcpRuntime
	// UDP shared port runtimes (one per UDPGroup).
	udpRuntimes []*udpRuntime

	group       *errgroup.Group
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
	ctx, cancel := context.WithCancelCause(host.Ctx())
	group, groupCtx := errgroup.WithContext(ctx)
	group.SetLimit(config.DefaultServerGoroutineLimit)
	return &Manager{
		host:        host,
		cfg:         cfg,
		group:       group,
		groupCtx:    groupCtx,
		groupCancel: cancel,
	}
}

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
			_ = rt.dohSrv.Shutdown(ctx)
			cancel()
		}
		if rt.tlcpSrv != nil {
			ctx, cancel := context.WithTimeout(context.Background(), config.DefaultShutdownTimeout)
			_ = rt.tlcpSrv.Shutdown(ctx)
			cancel()
		}
		if rt.tlcpLn != nil {
			_ = rt.tlcpLn.Close()
		}
		if rt.demux != nil {
			_ = rt.demux.Close()
		}
	}
	for _, rt := range udpRTs {
		if rt.quicPC != nil {
			_ = rt.quicPC.Close()
		}
		if rt.h3PC != nil {
			_ = rt.h3PC.Close()
		}
		if rt.dtlsPL != nil {
			_ = rt.dtlsPL.Close()
		}
		if rt.conn != nil {
			_ = rt.conn.Close()
		}
	}
}
