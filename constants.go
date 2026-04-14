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
/*
	0 - 24 - Defined
	25-49151 - Unassigned
	49152-65535 - Reserved for Private Use
*/
const (
	// The error in question falls into a category that does not match known extended error codes. Implementations SHOULD include an EXTRA-TEXT value to augment this error code with additional information.
	EDECodeOtherError uint16 = 0
	// The resolver attempted to perform DNSSEC validation, but a DNSKEY RRset contained only unsupported DNSSEC algorithms.
	EDECodeUnsupportedDNSKEYAlgorithm uint16 = 1
	// The resolver attempted to perform DNSSEC validation, but a DS RRset contained only unsupported Digest Types.
	EDECodeUnsupportedDSDigestType uint16 = 2
	// The resolver was unable to resolve the answer within its time limits and decided to answer with previously cached data instead of answering with an error. This is typically caused by problems communicating with an authoritative server, possibly as result of a denial of service (DoS) attack against another network.
	EDECodeStaleAnswer uint16 = 3
	// For policy reasons (legal obligation or malware filtering, for instance), an answer was forged. Note that this should be used when an answer is still provided, not when failure codes are returned instead. See Blocked (15), Censored (16), and Filtered (17) for use when returning other response codes.
	EDECodeForgedAnswer uint16 = 4
	// The resolver attempted to perform DNSSEC validation, but validation ended in the Indeterminate state [RFC4035].
	EDECodeDNSSECIndeterminate uint16 = 5
	// The resolver attempted to perform DNSSEC validation, but validation ended in the Bogus state.
	EDECodeDNSSECBogus uint16 = 6
	// The resolver attempted to perform DNSSEC validation, but no signatures are presently valid and some (often all) are expired.
	EDECodeSignatureExpired uint16 = 7
	// The resolver attempted to perform DNSSEC validation, but no signatures are presently valid and at least some are not yet valid.
	EDECodeSignatureNotYetValid uint16 = 8
	// A DS record existed at a parent, but no supported matching DNSKEY record could be found for the child.
	EDECodeDNSKEYMissing uint16 = 9
	// The resolver attempted to perform DNSSEC validation, but no RRSIGs could be found for at least one RRset where RRSIGs were expected.
	EDECodeRRSIGsMissing uint16 = 10
	// The resolver attempted to perform DNSSEC validation, but no Zone Key Bit was set in a DNSKEY.
	EDECodeNoZoneKeyBitSet uint16 = 11
	// The resolver attempted to perform DNSSEC validation, but the requested data was missing and a covering NSEC or NSEC3 was not provided.
	EDECodeNSECMissing uint16 = 12
	// The resolver is returning the SERVFAIL RCODE from its cache.
	EDECodeCachedError uint16 = 13
	// The server is unable to answer the query, as it was not fully functional when the query was received.
	EDECodeNotReady uint16 = 14
	// The server is unable to respond to the request because the domain is on a blocklist due to an internal security policy imposed by the operator of the server resolving or forwarding the query.
	EDECodeBlocked uint16 = 15
	// The server is unable to respond to the request because the domain is on a blocklist due to an external requirement imposed by an entity other than the operator of the server resolving or forwarding the query. Note that how the imposed policy is applied is irrelevant (in-band DNS filtering, court order, etc.).
	EDECodeCensored uint16 = 16
	// The server is unable to respond to the request because the domain is on a blocklist as requested by the client. Functionally, this amounts to "you requested that we filter domains like this one."
	EDECodeFiltered uint16 = 17
	// An authoritative server or recursive resolver that receives a query from an "unauthorized" client can annotate its REFUSED message with this code. Examples of "unauthorized" clients are recursive queries from IP addresses outside the network, blocklisted IP addresses, local policy, etc.
	EDECodeProhibited uint16 = 18
	// The resolver was unable to resolve an answer within its configured time limits and decided to answer with a previously cached NXDOMAIN answer instead of answering with an error. This may be caused, for example, by problems communicating with an authoritative server, possibly as result of a denial of service (DoS) attack against another network. (See also Code 3.)
	EDECodeStaleNXDomainAnswer uint16 = 19
	// An authoritative server that receives a query with the Recursion Desired (RD) bit clear, or when it is not configured for recursion for a domain for which it is not authoritative, SHOULD include this EDE code in the REFUSED response. A resolver that receives a query with the RD bit clear SHOULD include this EDE code in the REFUSED response.
	EDECodeNotAuthoritative uint16 = 20
	// The requested operation or query is not supported.
	EDECodeNotSupported uint16 = 21
	// The resolver could not reach any of the authoritative name servers (or they potentially refused to reply).
	EDECodeNoReachableAuthority uint16 = 22
	// An unrecoverable error occurred while communicating with another server.
	EDECodeNetworkError uint16 = 23
	// The authoritative server cannot answer with data for a zone it is otherwise configured to support. Examples of this include its most recent zone being too old or having expired.
	EDECodeInvalidData uint16 = 24
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
	DefaultCacheTTL                  = 10
	DefaultMemoryCacheSize           = 10000
	StaleTTL                         = 30
	StaleMaxAge                      = 30 * 86400
	ServeExpiredClientTimeout = 500 // RFC 8767 recommends 1.8 seconds

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

// =============================================================================
// DNSSEC Trust Anchors (IANA Root Zone)
// =============================================================================

var (
	// DefaultRootTrustAnchors are the IANA root trust anchors
	// Source: https://data.iana.org/root-anchors/root-anchors.xml
	// Updated: 2024-07-18 (adds KSK 38696)
	DefaultRootTrustAnchors = []RootTrustAnchor{
		// KSK 20326 - Active since 2017-02-02
		{
			Zone:       ".",
			KeyTag:     20326,
			Algorithm:  8, // RSASHA256
			DigestType: 2, // SHA-256
			Digest:     "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D",
			PublicKey:  "AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=",
			Flags:      257, // KSK
		},
		// KSK 38696 - Active since 2024-07-18
		{
			Zone:       ".",
			KeyTag:     38696,
			Algorithm:  8, // RSASHA256
			DigestType: 2, // SHA-256
			Digest:     "683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16",
			PublicKey:  "AwEAAa96jeuknZlaeSrvyAJj6ZHv28hhOKkx3rLGXVaC6rXTsDc449/cidltpkyGwCJNnOAlFNKF2jBosZBU5eeHspaQWOmOElZsjICMQMC3aeHbGiShvZsx4wMYSjH8e7Vrhbu6irwCzVBApESjbUdpWWmEnhathWu1jo+siFUiRAAxm9qyJNg/wOZqqzL/dL/q8PkcRU5oUKEpUge71M3ej2/7CPqpdVwuMoTvoB+ZOT4YeGyxMvHmbrxlFzGOHOijtzN+u1TQNatX2XBuzZNQ1K+s2CXkPIZo7s6JgZyvaBevYtxPvYLw4z9mR7K2vaF18UYH9Z9GNUUeayffKC73PYc=",
			Flags:      257, // KSK
		},
	}
)
