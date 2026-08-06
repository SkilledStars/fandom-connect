package gateway

import (
	"bytes"
	"encoding/base64"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func testApp(t *testing.T) *App {
	t.Helper()
	baseURL, _ := url.Parse("https://gateway.customer.example.com")
	app, err := NewApp(RuntimeConfig{
		BaseURL:             baseURL,
		MasterKey:           bytes.Repeat([]byte{7}, 32),
		AdminPassword:       "a-secure-test-password",
		DataPath:            t.TempDir() + "/gateway.db",
		ListenAddr:          ":8080",
		GoogleAdsAPIVersion: "v24",
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = app.Close() })
	return app
}

func TestHealthAndSecurityHeaders(t *testing.T) {
	app := testApp(t)
	request := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	recorder := httptest.NewRecorder()
	app.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || recorder.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("unexpected health response: status=%d headers=%v", recorder.Code, recorder.Header())
	}
}

func TestNetworkSmoke(t *testing.T) {
	app := testApp(t)
	server := httptest.NewServer(app.Handler())
	t.Cleanup(server.Close)

	response, err := server.Client().Get(server.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("network health request returned %d", response.StatusCode)
	}

	response, err = server.Client().Get(server.URL + "/admin/login")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("network admin request returned %d", response.StatusCode)
	}
}

func TestAPIRequiresValidKeyAndHidesUnconfiguredMetadata(t *testing.T) {
	app := testApp(t)
	request := httptest.NewRequest(http.MethodGet, "/v1/metadata", nil)
	recorder := httptest.NewRecorder()
	app.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous metadata returned %d", recorder.Code)
	}

	key, _, err := app.store.CreateAPIKey("test")
	if err != nil {
		t.Fatal(err)
	}
	request = httptest.NewRequest(http.MethodGet, "/v1/metadata", nil)
	request.Header.Set("Authorization", "Bearer "+key)
	recorder = httptest.NewRecorder()
	app.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusServiceUnavailable || strings.Contains(recorder.Body.String(), key) {
		t.Fatalf("unexpected configured response: status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestAdminLoginAndCSRFGate(t *testing.T) {
	app := testApp(t)
	form := url.Values{"password": {"a-secure-test-password"}}
	request := httptest.NewRequest(http.MethodPost, "/admin/login", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recorder := httptest.NewRecorder()
	app.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusSeeOther || len(recorder.Result().Cookies()) != 1 {
		t.Fatalf("login failed: status=%d", recorder.Code)
	}
	cookie := recorder.Result().Cookies()[0]
	if !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("admin cookie is not hardened: %#v", cookie)
	}

	request = httptest.NewRequest(http.MethodPost, "/admin/keys", strings.NewReader("name=test"))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(cookie)
	recorder = httptest.NewRecorder()
	app.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("missing CSRF token returned %d", recorder.Code)
	}

	csrf := app.security.csrfToken(cookie.Value)
	form = url.Values{"name": {"test"}, "csrf_token": {csrf}}
	request = httptest.NewRequest(http.MethodPost, "/admin/keys", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(cookie)
	recorder = httptest.NewRecorder()
	app.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("valid CSRF request returned %d: %s", recorder.Code, recorder.Body.String())
	}
	if _, err := base64.RawURLEncoding.DecodeString(strings.Split(strings.Split(recorder.Body.String(), "fgw_live_")[1], "_")[0]); err != nil {
		// The exact key is deliberately only present once in HTML; its random ID
		// need not be a UUID, but must remain URL-safe.
		t.Fatal("generated key was not URL-safe")
	}
}
