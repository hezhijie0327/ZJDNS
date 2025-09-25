package network

import "time"

const (
	// 缓冲区大小
	UpstreamUDPBufferSizeBytes = 4096
	ClientUDPBufferSizeBytes   = 1232
	SecureConnBufferSizeBytes  = 8192

	// 超时配置
	StandardQueryTimeout     = 5 * time.Second
	SecureConnQueryTimeout   = 5 * time.Second
	PublicIPDetectionTimeout = 3 * time.Second
	HTTPClientRequestTimeout = 5 * time.Second
	IPDetectionCacheExpiry   = 300 * time.Second

	// DNS Padding配置
	DNSPaddingBlockSizeBytes = 128
	DNSPaddingFillByte       = 0x00
	DNSPaddingMinSizeBytes   = 12
	DNSPaddingMaxSizeBytes   = 468

	// ECS配置
	DefaultECSIPv4PrefixLen = 24
	DefaultECSIPv6PrefixLen = 64
	DefaultECSClientScope   = 0

	// IP过滤器配置
	MaxTrustedIPv4CIDRs     = 1024
	MaxTrustedIPv6CIDRs     = 256
	MaxInputLineLengthChars = 128
)
