package security

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"
	"zjdns/types"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// HTTP/3 传输包装器
type http3Transport struct {
	baseTransport *http3.Transport
	closed        bool
	mu            sync.RWMutex
}

// 统一安全连接客户端
type UnifiedSecureClient struct {
	protocol        string
	serverName      string
	skipVerify      bool
	timeout         time.Duration
	tlsConn         *tls.Conn
	quicConn        *quic.Conn
	dohClient       *DoHClient
	isQUICConnected bool
	lastActivity    time.Time
	mu              sync.Mutex
}

// DoH客户端实现
type DoHClient struct {
	addr         *url.URL
	tlsConfig    *tls.Config
	client       *http.Client
	clientMu     sync.Mutex
	quicConfig   *quic.Config
	timeout      time.Duration
	skipVerify   bool
	serverName   string
	addrRedacted string
	httpVersions []string
	closed       int32
}

// SecureConnErrorHandler 安全连接错误处理器
type SecureConnErrorHandler struct{}

// Minimal interface definitions to break circular dependency
type DNSProcessor interface {
	ProcessDNSQuery(req *dns.Msg, clientIP net.IP, isSecureConnection bool) *dns.Msg
	GetConfig() *types.ServerConfig
}

// SecureDNSManager 安全DNS管理器
type SecureDNSManager struct {
	server        DNSProcessor
	tlsConfig     *tls.Config
	ctx           context.Context
	cancel        context.CancelFunc
	wg            sync.WaitGroup
	tlsListener   net.Listener
	quicConn      *net.UDPConn
	quicListener  *quic.EarlyListener
	quicTransport *quic.Transport
	httpsServer   *http.Server
	h3Server      *http3.Server
	httpsListener net.Listener
	h3Listener    *quic.EarlyListener
}
