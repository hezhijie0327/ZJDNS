package edns

import (
	"net"
	"testing"
)

func TestCookieGenerator_RFC9018_Basic(t *testing.T) {
	cg := NewCookieGenerator()
	if cg == nil {
		t.Fatal("NewCookieGenerator returned nil")
	}

	clientIP := net.ParseIP("192.168.1.1")
	clientCookie := []byte{1, 2, 3, 4, 5, 6, 7, 8}

	// Generate server cookie
	serverCookie := cg.GenerateServerCookie(clientIP, clientCookie)
	if len(serverCookie) != DefaultCookieServerLen {
		t.Errorf("server cookie len = %d, want %d", len(serverCookie), DefaultCookieServerLen)
	}

	// Check RFC 9018 wire format: version byte must be 1
	if serverCookie[0] != 1 {
		t.Errorf("cookie version = %d, want 1", serverCookie[0])
	}
	// Reserved bytes must be zero
	if serverCookie[1] != 0 || serverCookie[2] != 0 || serverCookie[3] != 0 {
		t.Errorf("reserved bytes not zero: %v", serverCookie[1:4])
	}

	// Validate fresh server cookie
	status := cg.IsServerCookieValid(clientIP, clientCookie, serverCookie)
	if status != CookieValid {
		t.Errorf("IsServerCookieValid = %d, want CookieValid (0)", status)
	}

	// Short client cookie -> Invalid
	if cg.IsServerCookieValid(clientIP, []byte{0, 0, 0, 0}, serverCookie) != CookieInvalid {
		t.Error("IsServerCookieValid should return CookieInvalid with short client cookie")
	}

	// Wrong server cookie length -> Invalid
	if cg.IsServerCookieValid(clientIP, clientCookie, []byte{0}) != CookieInvalid {
		t.Error("IsServerCookieValid should return CookieInvalid with short server cookie")
	}

	// Wrong version -> Invalid
	badVer := make([]byte, DefaultCookieServerLen)
	copy(badVer, serverCookie)
	badVer[0] = 2
	if cg.IsServerCookieValid(clientIP, clientCookie, badVer) != CookieInvalid {
		t.Error("IsServerCookieValid should return CookieInvalid for version != 1")
	}

	// Tampered hash -> Invalid
	tampered := make([]byte, DefaultCookieServerLen)
	copy(tampered, serverCookie)
	tampered[15] ^= 0xff
	if cg.IsServerCookieValid(clientIP, clientCookie, tampered) != CookieInvalid {
		t.Error("IsServerCookieValid should return CookieInvalid for tampered cookie")
	}

	// IPv6 client
	ip6 := net.ParseIP("2001:db8::1")
	serverCookie6 := cg.GenerateServerCookie(ip6, clientCookie)
	if status := cg.IsServerCookieValid(ip6, clientCookie, serverCookie6); status != CookieValid {
		t.Errorf("IPv6: IsServerCookieValid = %d, want CookieValid (0)", status)
	}
}

func TestCookieGenerator_RFC9018_Rotation(t *testing.T) {
	cg := NewCookieGenerator()
	clientIP := net.ParseIP("10.0.0.1")
	clientCookie := []byte{8, 7, 6, 5, 4, 3, 2, 1}

	oldCookie := cg.GenerateServerCookie(clientIP, clientCookie)
	cg.RotateSecret()
	newCookie := cg.GenerateServerCookie(clientIP, clientCookie)

	// Old cookie should still validate (previous secret retained) but flag renew
	statusOld := cg.IsServerCookieValid(clientIP, clientCookie, oldCookie)
	if statusOld != CookieValidRenew {
		t.Errorf("old cookie status = %d, want CookieValidRenew (%d)", statusOld, CookieValidRenew)
	}

	// New cookie should validate with current secret
	statusNew := cg.IsServerCookieValid(clientIP, clientCookie, newCookie)
	if statusNew != CookieValid {
		t.Errorf("new cookie status = %d, want CookieValid (%d)", statusNew, CookieValid)
	}

	// Second rotation: even older secret still validates
	cg.RotateSecret()
	statusOld = cg.IsServerCookieValid(clientIP, clientCookie, oldCookie)
	if statusOld != CookieValidRenew {
		t.Errorf("after 2nd rotation old cookie status = %d, want CookieValidRenew (%d)", statusOld, CookieValidRenew)
	}
}

func TestCookieGenerator_RFC9018_Nil(t *testing.T) {
	var cg *CookieGenerator
	if cg.GenerateServerCookie(nil, nil) != nil {
		t.Error("nil CookieGenerator should return nil")
	}
	if cg.IsServerCookieValid(nil, nil, nil) != CookieInvalid {
		t.Error("nil CookieGenerator should return CookieInvalid")
	}
	cg.RotateSecret() // should not panic
}

func TestCookieGenerator_RFC9018_TimeExpired(t *testing.T) {
	cg := NewCookieGenerator()
	clientIP := net.ParseIP("192.168.1.1")
	clientCookie := []byte{1, 2, 3, 4, 5, 6, 7, 8}

	origNow := timeNow
	defer func() { timeNow = origNow }()

	now := origNow()
	cookie := cg.GenerateServerCookie(clientIP, clientCookie)

	// Advance clock past expiry (> 1 hour)
	timeNow = func() uint32 { return now + 3601 }
	status := cg.IsServerCookieValid(clientIP, clientCookie, cookie)
	if status != CookieExpired {
		t.Errorf("expired cookie status = %d, want CookieExpired", status)
	}
}

func TestCookieGenerator_RFC9018_TimeRenew(t *testing.T) {
	cg := NewCookieGenerator()
	clientIP := net.ParseIP("192.168.1.1")
	clientCookie := []byte{1, 2, 3, 4, 5, 6, 7, 8}

	origNow := timeNow
	defer func() { timeNow = origNow }()

	now := origNow()
	cookie := cg.GenerateServerCookie(clientIP, clientCookie)

	// Advance clock past renew threshold (> 30 min but < 1 hour)
	timeNow = func() uint32 { return now + 1801 }
	status := cg.IsServerCookieValid(clientIP, clientCookie, cookie)
	if status != CookieValidRenew {
		t.Errorf("renew cookie status = %d, want CookieValidRenew", status)
	}
}

func TestCookieGenerator_RFC9018_TimeFuture(t *testing.T) {
	cg := NewCookieGenerator()
	clientIP := net.ParseIP("192.168.1.1")
	clientCookie := []byte{1, 2, 3, 4, 5, 6, 7, 8}

	origNow := timeNow
	defer func() { timeNow = origNow }()

	now := origNow()
	timeNow = func() uint32 { return now + 3600 }
	cookie := cg.GenerateServerCookie(clientIP, clientCookie)

	timeNow = origNow
	status := cg.IsServerCookieValid(clientIP, clientCookie, cookie)
	if status != CookieFuture {
		t.Errorf("future cookie status = %d, want CookieFuture (%d)", status, CookieFuture)
	}
}
