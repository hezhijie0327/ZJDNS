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

// Config carries all handlers and configuration the Manager needs from
// the TLS and TLCP protocol servers.  All fields are optional; the
// Manager starts only the port pairs for which handlers are provided.
type Config struct {
	// TCP 443: HTTPS + HTTPoverTLCP.
	Port       string
	TLSCfg     *eTLS.Config  // TLS config for the TLS-side connections
	DOHHandler eHTTP.Handler // DOH handler for the TLS-side
	DOHTLCP    http.Handler  // HTTPoverTLCP handler for the TLCP-side

	// TCP 853: TLS(DoT) + TLCP(DoT).
	DOTPort    string
	DOTHandler func(net.Listener) error // TLS-side DoT handler
	DOTTLCP    func(net.Listener)       // TLCP-side DoT accept loop

	// UDP 853: QUIC(DoQ) + DTLS + DTLCP.
	DTLSPort    string
	DTLSHandler func(dtlsnet.PacketListener) error
	DOQHandler  func(net.PacketConn) error
	ServeDTLCP  func(pc net.PacketConn, src *net.UDPAddr, cleanup func())

	// TLCP connection wrapping for the TLCP-side on shared TCP ports.
	// WrapConn wraps a raw net.Conn with the TLCP protocol handshake.
	WrapConn func(c net.Conn, nextProtos []string) net.Conn
}

// Manager manages shared-port resources for all protocol pairs.
// It owns its own errgroup for goroutine lifecycle and a mutex for
// resource tracking, with zero coupling to the tlcp.Server struct.
type Manager struct {
	host Host
	cfg  *Config

	mu sync.Mutex
	// TCP 443 shared resources.
	dohDemux tcpDemuxCloser
	dohSrv   *eHTTP.Server
	tlcpSrv  *http.Server
	// TCP 853 shared resources.
	dotDemux  tcpDemuxCloser
	dotTLCPln net.Listener
	// UDP 853 shared resources.
	udpConn     *net.UDPConn
	dtlsPL      *dtlsPacketListener
	quicPC      *quicPacketConn
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
	if m.cfg.Port != "" {
		if err := m.startDOH(); err != nil {
			return err
		}
	}
	if m.cfg.DOTPort != "" {
		if err := m.startDOT(); err != nil {
			return err
		}
	}
	if m.cfg.DTLSPort != "" {
		if err := m.startDTLS(); err != nil {
			return err
		}
	}
	return nil
}

// Shutdown gracefully stops all shared-port listeners and servers.
func (m *Manager) Shutdown() {
	m.groupCancel(errors.New("shared port shutdown"))

	m.mu.Lock()
	dohSrv := m.dohSrv
	tlcpSrv := m.tlcpSrv
	dohDemux := m.dohDemux
	dotDemux := m.dotDemux
	dotTLCPln := m.dotTLCPln
	quicPC := m.quicPC
	dtlsPL := m.dtlsPL
	udpConn := m.udpConn
	m.mu.Unlock()

	if dohSrv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), config.DefaultShutdownTimeout)
		_ = dohSrv.Shutdown(ctx)
		cancel()
	}
	if tlcpSrv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), config.DefaultShutdownTimeout)
		_ = tlcpSrv.Shutdown(ctx)
		cancel()
	}
	if dohDemux != nil {
		_ = dohDemux.Close()
	}
	if dotTLCPln != nil {
		_ = dotTLCPln.Close()
	}
	if dotDemux != nil {
		_ = dotDemux.Close()
	}
	if quicPC != nil {
		_ = quicPC.Close()
	}
	if dtlsPL != nil {
		_ = dtlsPL.Close()
	}
	if udpConn != nil {
		_ = udpConn.Close()
	}
}
