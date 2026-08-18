package gateway

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const adminCookieName = "fgw_admin"

type securityManager struct {
	masterKey         []byte
	adminPasswordHash [32]byte
	secureCookies     bool
	trustForwardedFor bool
	mu                sync.Mutex
	loginAttempts     map[string]*attemptWindow
	apiAttempts       map[string]*attemptWindow
	activeSessions    map[[32]byte]time.Time
	activeOAuthStates map[[32]byte]time.Time
	now               func() time.Time
}

type attemptWindow struct {
	Started time.Time
	Count   int
}

func newSecurityManager(cfg RuntimeConfig) *securityManager {
	return &securityManager{
		masterKey:         append([]byte(nil), cfg.MasterKey...),
		adminPasswordHash: sha256.Sum256([]byte(cfg.AdminPassword)),
		secureCookies:     cfg.BaseURL.Scheme == "https",
		trustForwardedFor: cfg.TrustForwardedFor,
		loginAttempts:     map[string]*attemptWindow{},
		apiAttempts:       map[string]*attemptWindow{},
		activeSessions:    map[[32]byte]time.Time{},
		activeOAuthStates: map[[32]byte]time.Time{},
		now:               time.Now,
	}
}

func (s *securityManager) clientIP(r *http.Request) string {
	if s.trustForwardedFor {
		if forwarded := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-For"), ",")[0]); net.ParseIP(forwarded) != nil {
			return forwarded
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

func (s *securityManager) allowAttempt(collection map[string]*attemptWindow, key string, maximum int, window time.Duration) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for existingKey, existing := range collection {
		if now.Sub(existing.Started) >= window {
			delete(collection, existingKey)
		}
	}
	entry := collection[key]
	if entry == nil || now.Sub(entry.Started) >= window {
		if len(collection) >= 10_000 {
			return false
		}
		collection[key] = &attemptWindow{Started: now, Count: 1}
		return true
	}
	entry.Count++
	return entry.Count <= maximum
}

func (s *securityManager) allowLogin(r *http.Request) bool {
	return s.allowAttempt(s.loginAttempts, s.clientIP(r), 10, 15*time.Minute)
}

func (s *securityManager) allowAPI(key string) bool {
	return s.allowAttempt(s.apiAttempts, key, 300, time.Minute)
}

func (s *securityManager) verifyPassword(value string) bool {
	actual := sha256.Sum256([]byte(value))
	return subtle.ConstantTimeCompare(actual[:], s.adminPasswordHash[:]) == 1
}

func (s *securityManager) sign(value string) string {
	mac := hmac.New(sha256.New, s.masterKey)
	mac.Write([]byte(value))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (s *securityManager) newSession() (string, error) {
	nonce, err := randomBytes(24)
	if err != nil {
		return "", err
	}
	expiresAt := s.now().Add(12 * time.Hour)
	payload := strconv.FormatInt(expiresAt.Unix(), 10) + "." + base64.RawURLEncoding.EncodeToString(nonce)
	session := payload + "." + s.sessionSignature(payload)
	s.mu.Lock()
	s.pruneSessionsLocked()
	s.activeSessions[sha256.Sum256([]byte(session))] = expiresAt
	s.mu.Unlock()
	return session, nil
}

func (s *securityManager) sessionSignature(payload string) string {
	return s.sign("session:" + base64.RawURLEncoding.EncodeToString(s.adminPasswordHash[:]) + ":" + payload)
}

func (s *securityManager) validSession(value string) bool {
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		return false
	}
	payload := parts[0] + "." + parts[1]
	expected := s.sessionSignature(payload)
	if subtle.ConstantTimeCompare([]byte(parts[2]), []byte(expected)) != 1 {
		return false
	}
	expires, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneSessionsLocked()
	if !s.now().Before(time.Unix(expires, 0)) {
		return false
	}
	registeredExpiry, active := s.activeSessions[sha256.Sum256([]byte(value))]
	return active && registeredExpiry.Unix() == expires
}

func (s *securityManager) revokeSession(value string) {
	s.mu.Lock()
	delete(s.activeSessions, sha256.Sum256([]byte(value)))
	s.mu.Unlock()
}

func (s *securityManager) pruneSessionsLocked() {
	now := s.now()
	for id, expiresAt := range s.activeSessions {
		if !now.Before(expiresAt) {
			delete(s.activeSessions, id)
		}
	}
}

func (s *securityManager) registerOAuthState(state string, expiresAt time.Time) {
	s.mu.Lock()
	s.pruneOAuthStatesLocked()
	s.activeOAuthStates[sha256.Sum256([]byte(state))] = expiresAt
	s.mu.Unlock()
}

func (s *securityManager) consumeOAuthState(state string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneOAuthStatesLocked()
	id := sha256.Sum256([]byte(state))
	_, active := s.activeOAuthStates[id]
	delete(s.activeOAuthStates, id)
	return active
}

func (s *securityManager) pruneOAuthStatesLocked() {
	now := s.now()
	for id, expiresAt := range s.activeOAuthStates {
		if !now.Before(expiresAt) {
			delete(s.activeOAuthStates, id)
		}
	}
}

func (s *securityManager) csrfToken(session string) string {
	return s.sign("csrf:" + session)
}

func (s *securityManager) verifyCSRF(r *http.Request) bool {
	cookie, err := r.Cookie(adminCookieName)
	if err != nil || !s.validSession(cookie.Value) {
		return false
	}
	provided := r.FormValue("csrf_token")
	expected := s.csrfToken(cookie.Value)
	return subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) == 1
}

func (s *securityManager) setSessionCookie(w http.ResponseWriter, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:     adminCookieName,
		Value:    value,
		Path:     "/admin",
		MaxAge:   int((12 * time.Hour).Seconds()),
		HttpOnly: true,
		Secure:   s.secureCookies,
		// OAuth returns from accounts.google.com with a top-level GET. Lax keeps
		// that callback authenticated while still excluding cross-site POSTs.
		SameSite: http.SameSiteLaxMode,
	})
}

func (s *securityManager) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     adminCookieName,
		Value:    "",
		Path:     "/admin",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   s.secureCookies,
		SameSite: http.SameSiteLaxMode,
	})
}

func (s *securityManager) requireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(adminCookieName)
		if err != nil || !s.validSession(cookie.Value) {
			http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
			return
		}
		if r.Method == http.MethodPost {
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		}
		next.ServeHTTP(w, r)
	})
}

func bearerToken(r *http.Request) (string, error) {
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, "Bearer ") {
		return "", errors.New("missing bearer token")
	}
	token := strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))
	if token == "" || len(token) > 256 {
		return "", errors.New("invalid bearer token")
	}
	return token, nil
}

func applySecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; script-src 'self'; img-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
		if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

func requestHash(req ProxyRequest) (string, error) {
	rawBody := req.RawBody
	if len(rawBody) == 0 {
		var err error
		rawBody, err = canonicalJSON(req.Body)
		if err != nil {
			return "", err
		}
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte(req.Method))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write([]byte(req.Path))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(rawBody)
	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}
