package gateway

import (
	"bytes"
	"net/url"
	"testing"
	"time"
)

func TestChangingAdminPasswordInvalidatesSessions(t *testing.T) {
	baseURL, _ := url.Parse("https://gateway.customer.example.com")
	first := newSecurityManager(RuntimeConfig{BaseURL: baseURL, MasterKey: bytes.Repeat([]byte{1}, 32), AdminPassword: "first-secure-password"})
	session, err := first.newSession()
	if err != nil {
		t.Fatal(err)
	}
	if !first.validSession(session) {
		t.Fatal("new session was invalid")
	}
	second := newSecurityManager(RuntimeConfig{BaseURL: baseURL, MasterKey: bytes.Repeat([]byte{1}, 32), AdminPassword: "second-secure-password"})
	if second.validSession(session) {
		t.Fatal("session survived an admin password rotation")
	}
}

func TestRevokedAndExpiredAdminSessionsAreRejected(t *testing.T) {
	baseURL, _ := url.Parse("https://gateway.customer.example.com")
	security := newSecurityManager(RuntimeConfig{BaseURL: baseURL, MasterKey: bytes.Repeat([]byte{1}, 32), AdminPassword: "secure-password"})
	now := time.Unix(1_800_000_000, 0)
	security.now = func() time.Time { return now }

	revoked, err := security.newSession()
	if err != nil {
		t.Fatal(err)
	}
	security.revokeSession(revoked)
	if security.validSession(revoked) {
		t.Fatal("revoked session remained valid")
	}

	expired, err := security.newSession()
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(13 * time.Hour)
	if security.validSession(expired) {
		t.Fatal("expired session remained valid")
	}
	if len(security.activeSessions) != 0 {
		t.Fatal("expired session was not pruned")
	}
}

func TestOAuthStateIsSessionBoundExpiringAndSingleUse(t *testing.T) {
	baseURL, _ := url.Parse("https://gateway.customer.example.com")
	security := newSecurityManager(RuntimeConfig{BaseURL: baseURL, MasterKey: bytes.Repeat([]byte{1}, 32), AdminPassword: "secure-password"})
	now := time.Unix(1_800_000_000, 0)
	security.now = func() time.Time { return now }
	app := &App{security: security}

	state, err := app.oauthState("session-one")
	if err != nil {
		t.Fatal(err)
	}
	if app.validOAuthState("session-two", state) {
		t.Fatal("OAuth state was accepted for a different admin session")
	}
	if !app.validOAuthState("session-one", state) {
		t.Fatal("valid OAuth state was denied")
	}
	if app.validOAuthState("session-one", state) {
		t.Fatal("OAuth state could be replayed")
	}

	expired, err := app.oauthState("session-one")
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(11 * time.Minute)
	if app.validOAuthState("session-one", expired) {
		t.Fatal("expired OAuth state was accepted")
	}
}
