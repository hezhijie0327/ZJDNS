// Package dashboard — JWT authentication for the web dashboard.
//
// A random 256-bit secret is generated on every startup (in-memory only).
// Tokens expire after 24 hours; restarting the server invalidates all tokens.
// Credentials are read from config (default: admin/zjdns).

package dashboard

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
	"zjdns/internal/log"

	"github.com/golang-jwt/jwt/v5"
)

// AuthConfig holds the dashboard authentication credentials.
type AuthConfig struct {
	Username string
	Password string
}

// AuthManager handles JWT token creation and validation.
type AuthManager struct {
	secret []byte
}

type claims struct {
	jwt.RegisteredClaims
}

// NewAuthManager creates an AuthManager with a freshly generated JWT secret.
func NewAuthManager() *AuthManager {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		log.Warnf("DASHBOARD: crypto/rand failed, using fallback secret: %v", err)
		// fallback: deterministic but acceptable for localhost dashboard
		raw = []byte("zjdns-dashboard-fallback-secret-v1")
	}
	hash := sha256.Sum256(raw)
	log.Debugf("DASHBOARD: generated new JWT secret")
	return &AuthManager{secret: hash[:]}
}

// Login validates credentials and returns a signed JWT token.
func (a *AuthManager) Login(username, password string, cfg AuthConfig) (string, error) {
	if username != cfg.Username || password != cfg.Password {
		return "", errors.New("invalid credentials")
	}
	now := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims{
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(24 * time.Hour)),
			Subject:   username,
		},
	})
	return token.SignedString(a.secret)
}

// ValidateToken parses and validates a JWT token string.
func (a *AuthManager) ValidateToken(tokenString string) (*claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &claims{},
		func(_ *jwt.Token) (any, error) { return a.secret, nil },
	)
	if err != nil {
		return nil, err
	}
	c, ok := token.Claims.(*claims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token")
	}
	return c, nil
}

// Middleware returns an HTTP middleware that requires a valid JWT Bearer token.
func (a *AuthManager) Middleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "" || !strings.HasPrefix(auth, "Bearer ") {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		token := strings.TrimPrefix(auth, "Bearer ")
		if _, err := a.ValidateToken(token); err != nil {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// HandleLogin is the POST /api/auth/login handler.
func (a *AuthManager) HandleLogin(cfg AuthConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}

		var body struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
			return
		}

		token, err := a.Login(body.Username, body.Password, cfg)
		if err != nil {
			http.Error(w, `{"error":"invalid credentials"}`, http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"token": token})
	}
}
