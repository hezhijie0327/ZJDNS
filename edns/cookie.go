package edns

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/bits"
	"net"
	"sync/atomic"
	"time"

	"codeberg.org/miekg/dns"

	"zjdns/internal/log"
)

// CookieOption holds the parsed client and server DNS Cookie values.
type CookieOption struct {
	ClientCookie []byte
	ServerCookie []byte
}

// CookieValStatus encodes the RFC 9018 validation outcome.
type CookieValStatus int

// secretPair holds the three most recent cookie signing secrets, retaining
// previous and older secrets to validate cookies issued before the last rotation.
type secretPair struct {
	current  []byte // active signing secret, 16 bytes
	previous []byte // previous secret retained for validation
	older    []byte // retained for one extra rotation cycle
}

// CookieGenerator creates and validates DNS Cookies using SipHash-2-4 per
// RFC 9018 ("Interoperable DNS Server Cookie").
type CookieGenerator struct {
	secrets atomic.Pointer[secretPair]
}

const (
	CookieValid      CookieValStatus = iota // hash matches, timestamp within renewal window
	CookieValidRenew                        // hash matches, but timestamp >30 min — reissue
	CookieExpired                           // timestamp >1 h — reject
	CookieFuture                            // timestamp >5 min in the future — reject
	CookieInvalid                           // version/hash mismatch or malformed
)

// Cookie length constants (RFC 9018).
const (
	DefaultCookieClientLen       = 8
	DefaultCookieServerLen       = 16
	cookieVersion          uint8 = 1
	cookieSigOffset              = 8 // siphash starts at byte 8 of the server cookie
	cookieSecretSize             = 16
)

// RFC 9018 §4.3 time boundaries.
const (
	cookieServerLifetime = 1 * time.Hour
	cookieRenewThreshold = 30 * time.Minute
	cookieFutureMax      = 5 * time.Minute
)

// timeNow returns the current Unix timestamp. Factored as a package-level
// variable so tests can inject a deterministic clock.
var timeNow = func() uint32 { return uint32(log.NowUnix()) }

// NewCookieGenerator creates a CookieGenerator with a random 16-byte secret.
func NewCookieGenerator() *CookieGenerator {
	secret := make([]byte, cookieSecretSize)
	if _, err := rand.Read(secret); err != nil {
		panic(fmt.Sprintf("EDNS: failed to generate cookie secret: %v (system CSPRNG unavailable)", err))
	}
	cg := &CookieGenerator{}
	cg.secrets.Store(&secretPair{current: secret})
	return cg
}

// RotateSecret rotates the cookie signing secret, keeping the previous one for
// validation.
func (c *CookieGenerator) RotateSecret() {
	if c == nil {
		return
	}
	newSecret := make([]byte, cookieSecretSize)
	if _, err := rand.Read(newSecret); err != nil {
		panic(fmt.Sprintf("EDNS: failed to rotate cookie secret: %v (system CSPRNG unavailable)", err))
	}
	old := c.secrets.Load()
	if old == nil {
		c.secrets.Store(&secretPair{current: newSecret})
		return
	}
	c.secrets.Store(&secretPair{current: newSecret, previous: old.current, older: old.previous})
}

func (c *CookieGenerator) loadSecrets() *secretPair {
	if c == nil {
		return nil
	}
	return c.secrets.Load()
}

// GenerateServerCookie builds an RFC 9018 server cookie from the client IP
// and client cookie.
//
// Wire format (16 bytes):
//
//	[0]     version (1)
//	[1:4]   reserved (0)
//	[4:8]   timestamp (Unix, uint32 big-endian)
//	[8:16]  SipHash-2-4(clientCookie | version | reserved | timestamp | clientIP)
func (c *CookieGenerator) GenerateServerCookie(clientIP net.IP, clientCookie []byte) []byte {
	sp := c.loadSecrets()
	if sp == nil || len(clientCookie) != DefaultCookieClientLen {
		return nil
	}

	var key [cookieSecretSize]byte
	copy(key[:], sp.current)

	ts := timeNow()
	serverCookie := make([]byte, DefaultCookieServerLen)
	serverCookie[0] = cookieVersion
	// bytes 1-3 are zero (reserved)
	binary.BigEndian.PutUint32(serverCookie[4:8], ts)

	sig := rfc9018MAC(&key, clientCookie, ts, clientIP)
	copy(serverCookie[cookieSigOffset:], sig[:])

	return serverCookie
}

// IsServerCookieValid validates an RFC 9018 server cookie against all
// active secrets.
func (c *CookieGenerator) IsServerCookieValid(clientIP net.IP, clientCookie, serverCookie []byte) CookieValStatus {
	sp := c.loadSecrets()
	if sp == nil || len(clientCookie) != DefaultCookieClientLen || len(serverCookie) != DefaultCookieServerLen {
		return CookieInvalid
	}
	if serverCookie[0] != cookieVersion {
		return CookieInvalid
	}

	ts := binary.BigEndian.Uint32(serverCookie[4:8])
	now := timeNow()

	// RFC 9018 §4.3 — time boundary checks using Serial Number Arithmetic
	// (RFC 1982). compare1982 handles the 32-bit timestamp wrap.
	var needsRenew bool
	cmp := compare1982(now, ts)
	if cmp > 0 {
		// Cookie is in the past (now > ts).
		age := subtract1982(now, ts)
		if age > uint32(cookieServerLifetime.Seconds()) {
			return CookieExpired
		}
		if age > uint32(cookieRenewThreshold.Seconds()) {
			needsRenew = true
		}
	} else if cmp < 0 {
		// Cookie is in the future (ts > now).
		skew := subtract1982(ts, now)
		if skew > uint32(cookieFutureMax.Seconds()) {
			return CookieFuture
		}
	}

	var sig [8]byte
	copy(sig[:], serverCookie[cookieSigOffset:])

	// Try every known secret: current, previous, older.
	secrets := [][]byte{sp.current, sp.previous, sp.older}
	for i, secret := range secrets {
		if len(secret) != cookieSecretSize {
			continue
		}
		var key [cookieSecretSize]byte
		copy(key[:], secret)

		expect := rfc9018MAC(&key, clientCookie, ts, clientIP)
		if sig == expect {
			if i > 0 || needsRenew {
				// Validated with a staging/old secret or needs a
				// fresher timestamp — tell the client to renew.
				return CookieValidRenew
			}
			return CookieValid
		}
	}
	return CookieInvalid
}

// rfc9018MAC computes the 8-byte SipHash-2-4 authenticator used in RFC 9018
// server cookies.
//
// Input (per §4.2):
//
//	clientCookie (8) | version (1) | reserved (3) | timestamp (4) | clientIP (4 or 16)
//
// IPv4 addresses use the 4-byte wire form; IPv6 use the full 16 bytes.
func rfc9018MAC(key *[16]byte, clientCookie []byte, timestamp uint32, clientIP net.IP) [8]byte {
	var buf [36]byte // buf is at most 8+1+3+4+16 = 32 bytes
	n := copy(buf[:], clientCookie[:8])
	buf[n] = cookieVersion
	n += 4 // version + 3 reserved bytes (already zero)
	binary.BigEndian.PutUint32(buf[n:], timestamp)
	n += 4

	ip := clientIP.To16()
	if ip == nil {
		ip = net.IPv4zero.To16()
	}
	copy(buf[n:], ip) // 16 bytes

	var mac [8]byte
	sum := siphash24(key, buf[:n+16])
	binary.BigEndian.PutUint64(mac[:], sum)
	return mac
}

// compare1982 compares two uint32 values using Serial Number Arithmetic
// (RFC 1982). Returns -1 if a < b, 0 if a == b, 1 if a > b.
func compare1982(a, b uint32) int {
	if a == b {
		return 0
	}
	if a-b <= 0x7FFFFFFF {
		return 1 // a > b
	}
	return -1 // a < b
}

// subtract1982 returns a - b using Serial Number Arithmetic (RFC 1982 §2) for
// unsigned 32-bit values, suitable for timestamp comparison.
func subtract1982(a, b uint32) uint32 {
	//nolint:gosec // G115: RFC 1982 serial number arithmetic — sign conversion is intentional
	return uint32(int64(a) - int64(b))
}

// BuildCookieResponse builds a hex-encoded cookie string from client and
// server cookies.
func BuildCookieResponse(clientCookie, serverCookie []byte) string {
	if len(clientCookie) != DefaultCookieClientLen {
		return ""
	}
	cookie := make([]byte, 0, len(clientCookie)+len(serverCookie))
	cookie = append(cookie, clientCookie...)
	cookie = append(cookie, serverCookie...)
	return hex.EncodeToString(cookie)
}

// ParseCookie extracts the DNS Cookie option from a DNS message.
func (h *Handler) ParseCookie(msg *dns.Msg) *CookieOption {
	if h == nil || msg == nil {
		return nil
	}
	for _, rr := range msg.Pseudo {
		cookie, ok := rr.(*dns.COOKIE)
		if !ok {
			continue
		}
		cookieBytes, err := hex.DecodeString(cookie.Cookie)
		if err != nil {
			return nil
		}
		if len(cookieBytes) < DefaultCookieClientLen {
			return nil
		}
		clientCookie := cookieBytes[:DefaultCookieClientLen]
		var serverCookie []byte
		if len(cookieBytes) > DefaultCookieClientLen {
			serverCookie = cookieBytes[DefaultCookieClientLen:]
		}
		return &CookieOption{
			ClientCookie: clientCookie,
			ServerCookie: serverCookie,
		}
	}
	return nil
}

// ── SipHash-2-4 ───────────────────────────────────────────────────────────
//
// This is a self-contained implementation of SipHash-2-4 (64-bit output),
// using the reference specification from https://131002.net/siphash/.
// It is used exclusively for RFC 9018 DNS Cookie MAC computation.

func siphash24(key *[16]byte, msg []byte) uint64 {
	k0 := binary.LittleEndian.Uint64(key[0:8])
	k1 := binary.LittleEndian.Uint64(key[8:16])

	v0 := k0 ^ 0x736f6d6570736575
	v1 := k1 ^ 0x646f72616e646f6d
	v2 := k0 ^ 0x6c7967656e657261
	v3 := k1 ^ 0x7465646279746573

	b := uint64(len(msg)) << 56

	for len(msg) >= 8 {
		m := binary.LittleEndian.Uint64(msg)
		v3 ^= m
		sipRound(&v0, &v1, &v2, &v3)
		sipRound(&v0, &v1, &v2, &v3)
		v0 ^= m
		msg = msg[8:]
	}

	var last uint64
	for i := len(msg) - 1; i >= 0; i-- {
		last |= uint64(msg[i]) << (i * 8)
	}
	last |= b

	v3 ^= last
	sipRound(&v0, &v1, &v2, &v3)
	sipRound(&v0, &v1, &v2, &v3)
	v0 ^= last

	v2 ^= 0xff
	sipRound(&v0, &v1, &v2, &v3)
	sipRound(&v0, &v1, &v2, &v3)
	sipRound(&v0, &v1, &v2, &v3)
	sipRound(&v0, &v1, &v2, &v3)

	return v0 ^ v1 ^ v2 ^ v3
}

func sipRound(v0, v1, v2, v3 *uint64) {
	*v0 += *v1
	*v2 += *v3
	*v1 = bits.RotateLeft64(*v1, 13)
	*v3 = bits.RotateLeft64(*v3, 16)
	*v1 ^= *v0
	*v3 ^= *v2
	*v0 = bits.RotateLeft64(*v0, 32)
	*v2 += *v1
	*v0 += *v3
	*v1 = bits.RotateLeft64(*v1, 17)
	*v3 = bits.RotateLeft64(*v3, 21)
	*v1 ^= *v2
	*v3 ^= *v0
	*v2 = bits.RotateLeft64(*v2, 32)
}
