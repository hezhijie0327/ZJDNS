package edns

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"sync/atomic"
	"zjdns/internal/log"

	"codeberg.org/miekg/dns"
)

// Cookie length constants.
const (
	DefaultCookieClientLen = 8
	DefaultCookieServerLen = 16
)

const cookieSecretSize = 32

const hmacContextClient = "client"

// CookieOption holds the parsed client and server DNS Cookie values.
type CookieOption struct {
	ClientCookie []byte
	ServerCookie []byte
}

type secretPair struct {
	current  []byte
	previous []byte
	older    []byte // retained for one extra rotation cycle to avoid BADCOOKIE on slow clients
}

// CookieGenerator creates and validates DNS Cookies using HMAC-SHA256.
// Uses lock-free atomic.Pointer for the hot path; only RotateSecret atomically
// swaps the secret pair.
type CookieGenerator struct {
	secrets atomic.Pointer[secretPair]
}

// NewCookieGenerator creates a CookieGenerator with a random secret.
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

// loadSecrets atomically loads the current secret pair.
func (c *CookieGenerator) loadSecrets() *secretPair {
	if c == nil {
		return nil
	}
	return c.secrets.Load()
}

// GenerateServerCookie creates a server cookie from the client IP and client
// cookie.
func (c *CookieGenerator) GenerateServerCookie(clientIP net.IP, clientCookie []byte) []byte {
	sp := c.loadSecrets()
	if sp == nil || len(clientCookie) != DefaultCookieClientLen {
		return nil
	}
	if clientIP == nil {
		clientIP = net.IPv4zero
	}
	clientIP = clientIP.To16()

	data := make([]byte, 0, len(clientIP)+len(clientCookie))
	data = append(data, clientIP...)
	data = append(data, clientCookie...)

	h := hmac.New(sha256.New, sp.current)
	h.Write(data)
	mac := h.Sum(nil)

	serverCookie := make([]byte, DefaultCookieServerLen)
	copy(serverCookie, mac[:DefaultCookieServerLen])
	return serverCookie
}

// IsServerCookieValid verifies a server cookie against the current and
// previous secrets.
func (c *CookieGenerator) IsServerCookieValid(clientIP net.IP, clientCookie, serverCookie []byte) bool {
	sp := c.loadSecrets()
	if sp == nil || len(clientCookie) != DefaultCookieClientLen || len(serverCookie) != DefaultCookieServerLen {
		return false
	}
	if clientIP == nil {
		clientIP = net.IPv4zero
	}
	clientIP = clientIP.To16()

	data := make([]byte, 0, len(clientIP)+len(clientCookie))
	data = append(data, clientIP...)
	data = append(data, clientCookie...)

	h := hmac.New(sha256.New, sp.current)
	h.Write(data)
	if hmac.Equal(serverCookie, h.Sum(nil)[:DefaultCookieServerLen]) {
		return true
	}
	if len(sp.previous) > 0 {
		hPrev := hmac.New(sha256.New, sp.previous)
		hPrev.Write(data)
		if hmac.Equal(serverCookie, hPrev.Sum(nil)[:DefaultCookieServerLen]) {
			return true
		}
	}
	if len(sp.older) > 0 {
		hOld := hmac.New(sha256.New, sp.older)
		hOld.Write(data)
		return hmac.Equal(serverCookie, hOld.Sum(nil)[:DefaultCookieServerLen])
	}
	return false
}

// GenerateClientCookie generates a client cookie for the given IP address.
func (c *CookieGenerator) GenerateClientCookie(clientIP net.IP) []byte {
	sp := c.loadSecrets()
	if sp == nil {
		return nil
	}
	clientCookie := make([]byte, DefaultCookieClientLen)
	h := hmac.New(sha256.New, sp.current)
	h.Write(clientIP)
	h.Write([]byte(hmacContextClient))
	copy(clientCookie, h.Sum(nil))
	return clientCookie
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
func (m *Handler) ParseCookie(msg *dns.Msg) *CookieOption {
	if m == nil || msg == nil {
		return nil
	}
	for _, rr := range msg.Pseudo {
		cookie, ok := rr.(*dns.COOKIE)
		if !ok {
			continue
		}
		cookieBytes, err := hex.DecodeString(cookie.Cookie)
		if err != nil {
			log.Debugf("EDNS: invalid cookie hex: %v", err)
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
