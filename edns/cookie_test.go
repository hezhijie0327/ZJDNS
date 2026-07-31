package edns

import (
	"encoding/binary"
	"encoding/hex"
	"net"
	"testing"
)

func TestCookieGenerator_RFC9018_Basic(t *testing.T) {
	cg, _ := NewCookieGenerator()
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
	cg, _ := NewCookieGenerator()
	clientIP := net.ParseIP("10.0.0.1")
	clientCookie := []byte{8, 7, 6, 5, 4, 3, 2, 1}

	oldCookie := cg.GenerateServerCookie(clientIP, clientCookie)
	_ = cg.RotateSecret()
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
	_ = cg.RotateSecret()
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
	_ = cg.RotateSecret() // should not panic
}

func TestCookieGenerator_RFC9018_TimeExpired(t *testing.T) {
	cg, _ := NewCookieGenerator()
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
	cg, _ := NewCookieGenerator()
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
	cg, _ := NewCookieGenerator()
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

func TestRFC9018TestVector_A1_NewCookie(t *testing.T) {
	// RFC 9018 Appendix A.1: Learning a New Server Cookie
	// Secret: e5e973e5a6b2a43f48e7dc849e37bfcf
	// Client IP: 198.51.100.100
	// Client Cookie: 2464c4abcf10c957
	// Timestamp: 1559731985 (Wed Jun 5 10:53:05 UTC 2019)
	// Expected Server Cookie: 010000005cf79f111f8130c3eee29480

	//nolint:gosec // G101: RFC 9018 public test vector — not a credential
	secretHex := "e5e973e5a6b2a43f48e7dc849e37bfcf"
	secret, _ := hex.DecodeString(secretHex)
	var key [16]byte
	copy(key[:], secret)

	clientCookie, _ := hex.DecodeString("2464c4abcf10c957")
	clientIP := net.ParseIP("198.51.100.100").To4()
	ts := uint32(1559731985)

	var reserved [3]byte // zero for new cookie
	mac := rfc9018MAC(&key, clientCookie, reserved, ts, clientIP)

	// Build full server cookie
	serverCookie := make([]byte, 16)
	serverCookie[0] = 1 // version
	// reserved bytes 1-3 are zero
	binary.BigEndian.PutUint32(serverCookie[4:8], ts)
	copy(serverCookie[8:], mac[:])

	got := hex.EncodeToString(serverCookie)
	want := "010000005cf79f111f8130c3eee29480"
	if got != want {
		t.Errorf("server cookie mismatch\ngot:  %s\nwant: %s", got, want)
	}
}

func TestRFC9018TestVector_A3_NonZeroReserved(t *testing.T) {
	// RFC 9018 Appendix A.3: Another Client with non-zero Reserved bytes
	// Secret: e5e973e5a6b2a43f48e7dc849e37bfcf
	// Client IP: 203.0.113.203
	// Full cookie from request: fc93fc62807ddb8601abcdef5cf78f71a314227b6679ebf5
	// Client Cookie: fc93fc62807ddb86
	// Server Cookie: 01abcdef5cf78f71a314227b6679ebf5
	//   Version: 01
	//   Reserved: abcdef (non-zero!)
	//   Timestamp: 5cf78f71 = 1559727985
	//   Hash: a314227b6679ebf5

	//nolint:gosec // G101: RFC 9018 public test vector — not a credential
	secretHex := "e5e973e5a6b2a43f48e7dc849e37bfcf"
	secret, _ := hex.DecodeString(secretHex)
	var key [16]byte
	copy(key[:], secret)

	clientCookie, _ := hex.DecodeString("fc93fc62807ddb86")
	serverCookie, _ := hex.DecodeString("01abcdef5cf78f71a314227b6679ebf5")
	clientIP := net.ParseIP("203.0.113.203").To4()

	// Extract fields from server cookie
	ts := binary.BigEndian.Uint32(serverCookie[4:8])
	var reserved [3]byte
	copy(reserved[:], serverCookie[1:4])

	// Verify reserved is non-zero
	if reserved == [3]byte{0, 0, 0} {
		t.Fatal("expected non-zero reserved bytes in test vector")
	}

	mac := rfc9018MAC(&key, clientCookie, reserved, ts, clientIP)

	var expectedMAC [8]byte
	copy(expectedMAC[:], serverCookie[8:])

	if mac != expectedMAC {
		t.Errorf("MAC mismatch with non-zero reserved bytes\ngot:  %x\nwant: %x", mac, expectedMAC)
	}
}

func TestRFC9018TestVector_A4_IPv6_RolledSecret(t *testing.T) {
	// RFC 9018 Appendix A.4: IPv6 query with rolled-over secret
	// Old Secret: dd3bdf9344b678b185a6f5cb60fca715
	// Client IPv6: 2001:db8:220:1:59de:d0f4:8769:82b8
	// Client Cookie: 22681ab97d52c298
	// Server Cookie from request: 010000005cf7c57926556bd0934c72f8
	// Timestamp: 5cf7c579 = 1559741817

	//nolint:gosec // G101: RFC 9018 public test vector — not a credential
	oldSecretHex := "dd3bdf9344b678b185a6f5cb60fca715"
	oldSecret, _ := hex.DecodeString(oldSecretHex)
	var key [16]byte
	copy(key[:], oldSecret)

	clientCookie, _ := hex.DecodeString("22681ab97d52c298")
	serverCookie, _ := hex.DecodeString("010000005cf7c57926556bd0934c72f8")
	clientIP := net.ParseIP("2001:db8:220:1:59de:d0f4:8769:82b8")

	ts := binary.BigEndian.Uint32(serverCookie[4:8])
	var reserved [3]byte
	copy(reserved[:], serverCookie[1:4])

	mac := rfc9018MAC(&key, clientCookie, reserved, ts, clientIP)

	var expectedMAC [8]byte
	copy(expectedMAC[:], serverCookie[8:])

	if mac != expectedMAC {
		t.Errorf("IPv6 MAC mismatch\ngot:  %x\nwant: %x", mac, expectedMAC)
	}
}

func TestRFC9018TestVector_A2_RenewedCookie(t *testing.T) {
	// RFC 9018 Appendix A.2: Same client, renewed cookie (40 min later)
	// Secret: e5e973e5a6b2a43f48e7dc849e37bfcf (same)
	// Client IP: 198.51.100.100 (same)
	// Client Cookie: 2464c4abcf10c957 (same)
	// Timestamp: 1559734385 (Wed Jun 5 11:33:05 UTC 2019)
	// Expected Server Cookie: 010000005cf7a871d4a564a1442aca77

	//nolint:gosec // G101: RFC 9018 public test vector — not a credential
	secretHex := "e5e973e5a6b2a43f48e7dc849e37bfcf"
	secret, _ := hex.DecodeString(secretHex)
	var key [16]byte
	copy(key[:], secret)

	clientCookie, _ := hex.DecodeString("2464c4abcf10c957")
	clientIP := net.ParseIP("198.51.100.100").To4()
	ts := uint32(1559734385)

	var reserved [3]byte
	mac := rfc9018MAC(&key, clientCookie, reserved, ts, clientIP)

	serverCookie := make([]byte, 16)
	serverCookie[0] = 1
	binary.BigEndian.PutUint32(serverCookie[4:8], ts)
	copy(serverCookie[8:], mac[:])

	got := hex.EncodeToString(serverCookie)
	want := "010000005cf7a871d4a564a1442aca77"
	if got != want {
		t.Errorf("renewed cookie mismatch\ngot:  %s\nwant: %s", got, want)
	}
}

func TestNonZeroReservedRoundTrip(t *testing.T) {
	// RFC 9018 §4.2: A cookie generated with non-zero reserved bytes
	// by another implementation MUST be validated using the received
	// reserved bytes in the MAC computation.
	// Test vector A.3 (already verified above) exercises this.
	// Here we verify the round-trip: generate with non-zero reserved,
	// validate with the same non-zero reserved.
	gen := &CookieGenerator{}
	gen.secrets.Store(&secretPair{current: []byte("0123456789abcdef")})

	clientIP := net.ParseIP("192.0.2.1")
	clientCookie := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

	// Build a cookie with non-zero reserved bytes and a MAC computed
	// WITH those reserved bytes (as another implementation would).
	macKey := [16]byte{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'}
	ts := timeNow()
	reserved := [3]byte{0xAB, 0xCD, 0xEF}
	mac := rfc9018MAC(&macKey, clientCookie, reserved, ts, clientIP)

	sc := make([]byte, 16)
	sc[0] = cookieVersion
	copy(sc[1:4], reserved[:])
	binary.BigEndian.PutUint32(sc[4:8], ts)
	copy(sc[8:], mac[:])

	// Validation must succeed (RFC 9018 §4.2: MUST NOT enforce zero).
	status := gen.IsServerCookieValid(clientIP, clientCookie, sc)
	if status != CookieValid {
		t.Errorf("non-zero reserved cookie should validate, got status=%d", status)
	}
}
