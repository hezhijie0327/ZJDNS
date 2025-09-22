package main

import (
	"time"

	"github.com/quic-go/quic-go"
	"golang.org/x/net/http2"
)

// ==================== 系统常量定义 ====================

const (
	// 日志
	DefaultLogLevel = "info"

	// DNS服务端口
	DefaultDNSPort       = "53"
	DefaultSecureDNSPort = "853"
	DefaultHTTPSPort     = "443"
	DefaultDNSQueryPath  = "/dns-query"

	// 特殊标识符
	RecursiveServerIndicator = "builtin_recursive"

	// 缓冲区大小
	ClientUDPBufferSizeBytes   = 1232
	UpstreamUDPBufferSizeBytes = 4096
	SecureConnBufferSizeBytes  = 8192
	MinDNSPacketSizeBytes      = 12

	// RFC限制
	MaxDomainNameLengthRFC  = 253
	MaxInputLineLengthChars = 128
	MaxConfigFileSizeBytes  = 1024 * 1024
	MaxRegexPatternLength   = 100
)

const (
	// DNS Padding配置
	DNSPaddingBlockSizeBytes = 128
	DNSPaddingFillByte       = 0x00
	DNSPaddingMinSizeBytes   = 12
	DNSPaddingMaxSizeBytes   = 468
)

const (
	// 连接超时配置
	SecureConnIdleTimeout      = 300 * time.Second
	SecureConnKeepAlive        = 15 * time.Second
	SecureConnHandshakeTimeout = 3 * time.Second
	SecureConnQueryTimeout     = 5 * time.Second
	SecureConnMaxRetries       = 3
)

const (
	// DoH相关配置
	DoHReadHeaderTimeout = 5 * time.Second
	DoHWriteTimeout      = 5 * time.Second
	DoHMaxRequestSize    = 8192
	DoHMaxConnsPerHost   = 3
	DoHMaxIdleConns      = 3
	DoHIdleConnTimeout   = 300 * time.Second
	DoHReadIdleTimeout   = 30 * time.Second
)

const (
	// QUIC配置
	QUICAddrValidatorCacheSize = 1000
	QUICAddrValidatorCacheTTL  = 300 * time.Second
)

const (
	// 缓存配置
	DefaultCacheTTLSeconds       = 300
	StaleTTLSeconds              = 30
	StaleMaxAgeSeconds           = 259200
	CacheRefreshThresholdSeconds = 300
	CacheRefreshQueueSize        = 500
)

const (
	// 并发控制
	MaxGlobalConcurrency            = 1000
	SingleQueryMaxConcurrency       = 3
	NameServerResolveMaxConcurrency = 3
)

const (
	// 递归查询限制
	MaxCNAMEChainLength       = 16
	MaxRecursionDepth         = 16
	MaxNameServerResolveCount = 3
)

const (
	// 超时配置
	StandardQueryTimeout     = 5 * time.Second
	StandardOperationTimeout = 5 * time.Second
	RecursiveQueryTimeout    = 15 * time.Second
	ExtendedQueryTimeout     = 30 * time.Second
	GracefulShutdownTimeout  = 5 * time.Second
)

const (
	// Redis配置
	RedisConnectionPoolSize    = 20
	RedisMinIdleConnections    = 5
	RedisMaxRetryAttempts      = 3
	RedisConnectionPoolTimeout = 5 * time.Second
	RedisReadTimeout           = 3 * time.Second
	RedisWriteTimeout          = 3 * time.Second
	RedisDialTimeout           = 5 * time.Second
)

const (
	// ECS配置
	PublicIPDetectionTimeout = 3 * time.Second
	HTTPClientRequestTimeout = 5 * time.Second
	IPDetectionCacheExpiry   = 300 * time.Second
	MaxTrustedIPv4CIDRs      = 1024
	MaxTrustedIPv6CIDRs      = 256
	DefaultECSIPv4PrefixLen  = 24
	DefaultECSIPv6PrefixLen  = 64
	DefaultECSClientScope    = 0
)

const (
	// Speedtest配置
	DefaultSpeedTestTimeout     = 3 * time.Second
	DefaultSpeedTestConcurrency = 10
	DefaultSpeedTestCacheTTL    = 300 * time.Second
	SpeedTestDebounceInterval   = 30 * time.Second
)

// 协议标识符
var (
	NextProtoQUIC  = []string{"doq", "doq-i02", "doq-i00", "dq"}
	NextProtoHTTP3 = []string{"h3"}
	NextProtoHTTP2 = []string{http2.NextProtoTLS, "http/1.1"}
)

// QUIC错误码
const (
	QUICCodeNoError       quic.ApplicationErrorCode = 0
	QUICCodeInternalError quic.ApplicationErrorCode = 1
	QUICCodeProtocolError quic.ApplicationErrorCode = 2
)
