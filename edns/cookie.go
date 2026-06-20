package edns

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"sync"

	"github.com/miekg/dns"
)

// Cookie length constants.
const (
	DefaultCookieClientLen = 8
	DefaultCookieServerLen = 16
	MaxCookieServerLen     = 32
)

// CookieOption holds the parsed client and server DNS Cookie values.
type CookieOption struct {
	ClientCookie []byte
	ServerCookie []byte
}

// CookieGenerator creates and validates DNS Cookies using HMAC-SHA256.
type CookieGenerator struct {
	mu             sync.RWMutex
	secret         []byte
	previousSecret []byte
}

// NewCookieGenerator creates a CookieGenerator with a random secret.
func NewCookieGenerator() *CookieGenerator {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		panic(fmt.Sprintf("EDNS: failed to generate cookie secret: %v (system CSPRNG unavailable)", err))
	}
	return &CookieGenerator{secret: secret}
}

// RotateSecret rotates the cookie signing secret, keeping the previous one for
// validation.
func (cg *CookieGenerator) RotateSecret() {
	if cg == nil {
		return
	}
	newSecret := make([]byte, 32)
	if _, err := rand.Read(newSecret); err != nil {
		panic(fmt.Sprintf("EDNS: failed to rotate cookie secret: %v (system CSPRNG unavailable)", err))
	}
	cg.mu.Lock()
	cg.previousSecret = cg.secret
	cg.secret = newSecret
	cg.mu.Unlock()
}

// GenerateServerCookie creates a server cookie from the client IP and client
// cookie.
func (cg *CookieGenerator) GenerateServerCookie(clientIP net.IP, clientCookie []byte) []byte {
	if cg == nil || len(clientCookie) != DefaultCookieClientLen {
		return nil
	}
	if clientIP == nil {
		clientIP = net.ParseIP("0.0.0.0")
	}
	clientIP = clientIP.To16()

	data := make([]byte, 0, len(clientIP)+len(clientCookie))
	data = append(data, clientIP...)
	data = append(data, clientCookie...)

	cg.mu.RLock()
	h := hmac.New(sha256.New, cg.secret)
	cg.mu.RUnlock()
	h.Write(data)
	mac := h.Sum(nil)

	serverCookie := make([]byte, DefaultCookieServerLen)
	copy(serverCookie, mac[:DefaultCookieServerLen])
	return serverCookie
}

// ValidateServerCookie verifies a server cookie against the current and
// previous secrets.
func (cg *CookieGenerator) ValidateServerCookie(clientIP net.IP, clientCookie, serverCookie []byte) bool {
	if cg == nil || len(clientCookie) != DefaultCookieClientLen || len(serverCookie) != DefaultCookieServerLen {
		return false
	}
	if clientIP == nil {
		clientIP = net.ParseIP("0.0.0.0")
	}
	clientIP = clientIP.To16()

	data := make([]byte, 0, len(clientIP)+len(clientCookie))
	data = append(data, clientIP...)
	data = append(data, clientCookie...)

	cg.mu.RLock()
	h := hmac.New(sha256.New, cg.secret)
	prevLen := len(cg.previousSecret)
	var prevSecret []byte
	if prevLen > 0 {
		prevSecret = make([]byte, prevLen)
		copy(prevSecret, cg.previousSecret)
	}
	cg.mu.RUnlock()

	h.Write(data)
	if hmac.Equal(serverCookie, h.Sum(nil)[:DefaultCookieServerLen]) {
		return true
	}
	if prevLen > 0 {
		hPrev := hmac.New(sha256.New, prevSecret)
		hPrev.Write(data)
		return hmac.Equal(serverCookie, hPrev.Sum(nil)[:DefaultCookieServerLen])
	}
	return false
}

// GenerateClientCookie generates a client cookie for the given IP address.
func (cg *CookieGenerator) GenerateClientCookie(clientIP net.IP) []byte {
	clientCookie := make([]byte, DefaultCookieClientLen)
	h := hmac.New(sha256.New, cg.secret)
	h.Write(clientIP)
	h.Write([]byte("client"))
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
	if m == nil || msg == nil || msg.Extra == nil {
		return nil
	}
	opt := msg.IsEdns0()
	if opt == nil {
		return nil
	}
	for _, option := range opt.Option {
		if cookie, ok := option.(*dns.EDNS0_COOKIE); ok {
			cookieBytes, _ := hex.DecodeString(cookie.Cookie)
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
	}
	return nil
}
