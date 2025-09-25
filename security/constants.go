package security

import (
	"time"

	"github.com/quic-go/quic-go"
	"golang.org/x/net/http2"
)

// Constants
const (
	SecureConnIdleTimeout      = 300 * time.Second
	SecureConnKeepAlive        = 15 * time.Second
	SecureConnHandshakeTimeout = 3 * time.Second
	SecureConnQueryTimeout     = 5 * time.Second
	SecureConnBufferSizeBytes  = 8192
	UpstreamUDPBufferSizeBytes = 4096
	DefaultHTTPSPort           = "443"
	DoHMaxConnsPerHost         = 3
	DoHMaxIdleConns            = 3
	DoHIdleConnTimeout         = 300 * time.Second
	DefaultDNSQueryPath        = "/dns-query"
	DoHReadHeaderTimeout       = 5 * time.Second
	DoHWriteTimeout            = 5 * time.Second
	DoHMaxRequestSize          = 8192
	MinDNSPacketSizeBytes      = 12
)

// QUIC error codes
const (
	QUICCodeNoError       quic.ApplicationErrorCode = 0
	QUICCodeProtocolError quic.ApplicationErrorCode = 2
)

// Protocol identifiers
var (
	NextProtoQUIC  = []string{"doq", "doq-i02", "doq-i00", "dq"}
	NextProtoHTTP3 = []string{"h3"}
	NextProtoHTTP2 = []string{http2.NextProtoTLS, "http/1.1"}
)
