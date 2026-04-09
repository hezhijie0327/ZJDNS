// Package main implements ZJDNS - High Performance DNS Server
// Supporting DoT/DoH/DoQ/DoH3 and recursive resolution
package main

import (
	"math"
	"time"

	"github.com/quic-go/quic-go"
)

// =============================================================================
// Global Constants - Network Configuration
// =============================================================================

const (
	DefaultDNSPort   = "53"
	DefaultDOTPort   = "853"
	DefaultDOHPort   = "443"
	DefaultPprofPort = "6060"

	RecursiveIndicator = "builtin_recursive"
	DefaultQueryPath   = "/dns-query"
	PprofPath          = "/debug/pprof/"
)

// =============================================================================
// Global Constants - Buffer & Memory Configuration
// =============================================================================

const (
	UDPBufferSize        = 1232
	TCPBufferSize        = 4096
	SecureBufferSize     = 8192
	DoHMaxRequestSize    = 8192
	TLSConnBufferSize    = 128
	ResultBufferCapacity = 128
	MaxIncomingStreams   = math.MaxUint16

	// Object pool sizes
	MessagePoolSize = 512
	BufferPoolSize  = 256
)

// =============================================================================
// Global Constants - Protocol Limits & Constraints
// =============================================================================

const (
	MaxDomainLength = 253
	MaxCNAMEChain   = 16
	MaxRecursionDep = 16
	MaxResultLength = 512

	DefaultECSv4Len = 24
	DefaultECSv6Len = 64
	DefaultECSScope = 0
	PaddingSize     = 468

	// DNS Cookie constants (RFC 7873)
	DefaultCookieClientLen = 8  // 8 bytes client cookie
	DefaultCookieServerLen = 16 // 16 bytes server cookie (recommended)
	MaxCookieServerLen     = 32 // 32 bytes max server cookie
)

// Extended DNS Error codes (RFC 8914)
const (
	EDECodeOther                uint16 = 0  // Other
	EDECodeUnsupportedDNSKEY    uint16 = 1  // Unsupported DNSKEY Algorithm
	EDECodeUnsupportedDS        uint16 = 2  // Unsupported DS Digest Type
	EDECodeStaleAnswer          uint16 = 3  // Stale Answer
	EDECodeForgedAnswer         uint16 = 4  // Forged Answer
	EDECodeDNSSECIndeterminate  uint16 = 5  // DNSSEC Indeterminate
	EDECodeDNSSECBogus          uint16 = 6  // DNSSEC Bogus
	EDECodeSignatureExpired     uint16 = 7  // Signature Expired
	EDECodeSignatureNotYetValid uint16 = 8  // Signature Not Yet Valid
	EDECodeDNSKEYMissing        uint16 = 9  // DNSKEY Missing
	EDECodeRRSIGsMissing        uint16 = 10 // RRSIGs Missing
	EDECodeNoZoneKeyBitSet      uint16 = 11 // No Zone Key Bit Set
	EDECodeNSECMissing          uint16 = 12 // NSEC Missing
	EDECodeCachedError          uint16 = 13 // Cached Error
	EDECodeNotReady             uint16 = 14 // Not Ready
	EDECodeBlocked              uint16 = 15 // Blocked
	EDECodeCensored             uint16 = 16 // Censored
	EDECodeFiltered             uint16 = 17 // Filtered
	EDECodeProhibited           uint16 = 18 // Prohibited
	EDECodeStaleNSAnswer        uint16 = 19 // Stale NS Answer
	EDECodeUnknownRCODE         uint16 = 20 // Unknown RCODE
	EDECodeNotAuth              uint16 = 21 // Not Authoritative
	EDECodeNotSupported         uint16 = 22 // Not Supported
	EDECodeNoReachableAuthority uint16 = 23 // No Reachable Authority
	EDECodeNetworkError         uint16 = 24 // Network Error
	EDECodeInvalidData          uint16 = 25 // Invalid Data
)

// =============================================================================
// Global Constants - Timing Configuration
// =============================================================================

const (
	DefaultTimeout   = 2 * time.Second
	OperationTimeout = 3 * time.Second
	IdleTimeout      = 5 * time.Second
)

// =============================================================================
// Global Constants - Cache Configuration
// =============================================================================

const (
	DefaultCacheTTL = 10
	StaleTTL        = 30
	StaleMaxAge     = 30 * 86400

	RedisPrefixDNS = "dns:"
)

// =============================================================================
// Global Constants - QUIC Configuration
// =============================================================================

const (
	QUICCodeNoError       quic.ApplicationErrorCode = 0
	QUICCodeInternalError quic.ApplicationErrorCode = 1
	QUICCodeProtocolError quic.ApplicationErrorCode = 2
)

// =============================================================================
// Global Constants - Logging Configuration
// =============================================================================

const (
	DefaultLogLevel = "info"

	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorYellow = "\033[33m"
	ColorGreen  = "\033[32m"
	ColorCyan   = "\033[36m"
	ColorBold   = "\033[1m"
)

// =============================================================================
// Global Variables - Root Servers & Protocol ALPN
// =============================================================================

var (
	// https://www.internic.net/domain/named.root
	DefaultRootServers = []string{
		"198.41.0.4:53", "[2001:503:ba3e::2:30]:53",
		"170.247.170.2:53", "[2801:1b8:10::b]:53",
		"192.33.4.12:53", "[2001:500:2::c]:53",
		"199.7.91.13:53", "[2001:500:2d::d]:53",
		"192.203.230.10:53", "[2001:500:a8::e]:53",
		"192.5.5.241:53", "[2001:500:2f::f]:53",
		"192.112.36.4:53", "[2001:500:12::d0d]:53",
		"198.97.190.53:53", "[2001:500:1::53]:53",
		"192.36.148.17:53", "[2001:7fe::53]:53",
		"192.58.128.30:53", "[2001:503:c27::2:30]:53",
		"193.0.14.129:53", "[2001:7fd::1]:53",
		"199.7.83.42:53", "[2001:500:9f::42]:53",
		"202.12.27.33:53", "[2001:dc3::35]:53",
	}

	// NextProtoDOT is the ALPN for DoT
	NextProtoDOT = []string{"dot"}

	// NextProtoDoQ is the ALPN for DoQ
	NextProtoDoQ = []string{"doq"}

	// NextProtoDoH3 is the ALPN for DoH3
	NextProtoDoH3 = []string{"h3"}

	// NextProtoDoH is the ALPN for DoH
	NextProtoDoH = []string{"h2"}
)
