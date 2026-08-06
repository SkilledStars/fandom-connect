package gateway

import (
	"bytes"
	"net/url"
	"testing"
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
