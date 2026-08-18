package gateway

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
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
		GoogleAdsAPIVersion: "v23",
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
	if !strings.Contains(recorder.Header().Get("Content-Security-Policy"), "script-src 'self'") {
		t.Fatalf("admin script policy is missing: %q", recorder.Header().Get("Content-Security-Policy"))
	}
}

func TestAdminAssetsCannotRemainStaleAcrossDeploys(t *testing.T) {
	app := testApp(t)
	for _, test := range []struct {
		path        string
		contentType string
		bodyParts   []string
	}{
		{
			path:        "/admin/style.css?v=2",
			contentType: "text/css; charset=utf-8",
			bodyParts:   []string{"max-height:24rem", "overflow-y:scroll", "scrollbar-gutter:stable"},
		},
		{
			path:        "/admin/admin.js?v=1",
			contentType: "text/javascript; charset=utf-8",
			bodyParts:   []string{"data-campaign-search", "row.hidden", "rows.length"},
		},
	} {
		request := httptest.NewRequest(http.MethodGet, test.path, nil)
		recorder := httptest.NewRecorder()
		app.Handler().ServeHTTP(recorder, request)
		if recorder.Code != http.StatusOK || recorder.Header().Get("Content-Type") != test.contentType || recorder.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("asset %s returned unexpected status or headers: status=%d headers=%v", test.path, recorder.Code, recorder.Header())
		}
		for _, bodyPart := range test.bodyParts {
			if !strings.Contains(recorder.Body.String(), bodyPart) {
				t.Fatalf("asset %s omitted %q", test.path, bodyPart)
			}
		}
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

func TestConfiguredMetadataReportsGoogleAdsAPIVersion(t *testing.T) {
	app := testApp(t)
	cfg, err := app.store.Config()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Google = &GoogleCredential{Mode: "oauth", LoginCustomerID: "1234567890"}
	cfg.Accounts = map[string]AccountPolicy{
		"1234567890": {
			CustomerID:  "1234567890",
			AllowCreate: true,
			Campaigns:   map[string]CampaignPolicy{},
		},
	}
	if err := app.store.SaveConfig(cfg); err != nil {
		t.Fatal(err)
	}
	key, _, err := app.store.CreateAPIKey("test")
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/v1/metadata", nil)
	request.Header.Set("Authorization", "Bearer "+key)
	recorder := httptest.NewRecorder()
	app.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("configured metadata returned %d: %s", recorder.Code, recorder.Body.String())
	}
	var metadata MetadataResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &metadata); err != nil {
		t.Fatal(err)
	}
	if metadata.GoogleAdsAPIVersion != "v23" {
		t.Fatalf("metadata omitted the configured API version: %#v", metadata)
	}
}

func TestAdminCanGrantAllCurrentAndFutureCampaignAccess(t *testing.T) {
	app := testApp(t)
	cfg, err := app.store.Config()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Accounts = map[string]AccountPolicy{
		"123": {
			CustomerID:  "123",
			DisplayName: "Advertiser",
			Campaigns: map[string]CampaignPolicy{
				"10": {CampaignID: "10", Name: "Existing campaign"},
			},
		},
		"999": {
			CustomerID:  "999",
			DisplayName: "Manager",
			IsManager:   true,
			Campaigns:   map[string]CampaignPolicy{},
		},
	}
	if err := app.store.SaveConfig(cfg); err != nil {
		t.Fatal(err)
	}

	session, err := app.security.newSession()
	if err != nil {
		t.Fatal(err)
	}
	cookie := &http.Cookie{Name: adminCookieName, Value: session}

	pageRequest := httptest.NewRequest(http.MethodGet, "/admin", nil)
	pageRequest.AddCookie(cookie)
	page := httptest.NewRecorder()
	app.Handler().ServeHTTP(page, pageRequest)
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), `class="campaign-list"`) ||
		!strings.Contains(page.Body.String(), "Full access to all current and future campaigns") ||
		!strings.Contains(page.Body.String(), `placeholder="Search by name, ID, or status"`) ||
		!strings.Contains(page.Body.String(), `/admin/style.css?v=2`) ||
		!strings.Contains(page.Body.String(), `/admin/admin.js?v=1`) {
		t.Fatalf("admin page omitted the bounded list or full-access control: status=%d", page.Code)
	}

	form := url.Values{
		"csrf_token": {app.security.csrfToken(session)},
		"all:123":    {"on"},
		"all:999":    {"on"},
	}
	request := httptest.NewRequest(http.MethodPost, "/admin/policy", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(cookie)
	recorder := httptest.NewRecorder()
	app.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("full-access save returned %d: %s", recorder.Code, recorder.Body.String())
	}

	saved, err := app.store.Config()
	if err != nil {
		t.Fatal(err)
	}
	if !saved.Accounts["123"].AllCampaignsReadWrite {
		t.Fatal("advertiser full-campaign access was not saved")
	}
	if saved.Accounts["999"].AllCampaignsReadWrite {
		t.Fatal("manager account incorrectly received a campaign policy")
	}
}

func TestMetadataPublishesEffectiveAllCampaignAccess(t *testing.T) {
	app := testApp(t)
	cfg, err := app.store.Config()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Google = &GoogleCredential{Mode: "oauth", LoginCustomerID: "123"}
	cfg.Accounts = map[string]AccountPolicy{
		"123": {
			CustomerID:            "123",
			DisplayName:           "Advertiser",
			AllCampaignsReadWrite: true,
			Campaigns: map[string]CampaignPolicy{
				"10": {CampaignID: "10", Name: "Existing campaign"},
			},
		},
	}
	if err := app.store.SaveConfig(cfg); err != nil {
		t.Fatal(err)
	}
	key, _, err := app.store.CreateAPIKey("test")
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/v1/metadata", nil)
	request.Header.Set("Authorization", "Bearer "+key)
	recorder := httptest.NewRecorder()
	app.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("metadata returned %d: %s", recorder.Code, recorder.Body.String())
	}
	var metadata MetadataResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &metadata); err != nil {
		t.Fatal(err)
	}
	if len(metadata.Accounts) != 1 || !metadata.Accounts[0].AllCampaignsReadWrite || len(metadata.Accounts[0].Campaigns) != 1 ||
		!metadata.Accounts[0].Campaigns[0].Read || !metadata.Accounts[0].Campaigns[0].Write {
		t.Fatalf("metadata did not publish effective full access: %#v", metadata.Accounts)
	}
}

func TestProxyForwardsAuthorizedBodyAndGoogleResponseBytesExactly(t *testing.T) {
	app := testApp(t)
	googleClient, googleCfg := testGoogleClient(func(request *http.Request) (*http.Response, error) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatal(err)
		}
		want := `{"query" : "SELECT campaign.id FROM campaign WHERE campaign.id = 111", "pageToken" : "abc"}`
		if string(body) != want {
			t.Fatalf("upstream request body changed:\n got: %s\nwant: %s", body, want)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": {"application/json; charset=utf-8"}},
			Body:       io.NopCloser(strings.NewReader("{ \"results\" : [ { \"campaign\" : { \"id\" : \"111\" } } ] }")),
		}, nil
	})
	app.google = googleClient
	app.policy.google = googleClient
	config, err := app.store.Config()
	if err != nil {
		t.Fatal(err)
	}
	config.Google = googleCfg.Google
	config.Accounts = map[string]AccountPolicy{
		"1234567890": {
			CustomerID: "1234567890",
			Campaigns: map[string]CampaignPolicy{
				"111": {CampaignID: "111", Read: true},
			},
		},
	}
	if err := app.store.SaveConfig(config); err != nil {
		t.Fatal(err)
	}
	key, _, err := app.store.CreateAPIKey("test")
	if err != nil {
		t.Fatal(err)
	}
	requestBody := `{"method":"POST","path":"/v23/customers/1234567890/googleAds:search","body":{"query" : "SELECT campaign.id FROM campaign WHERE campaign.id = 111", "pageToken" : "abc"}}`
	request := httptest.NewRequest(http.MethodPost, "/v1/proxy", strings.NewReader(requestBody))
	request.Header.Set("Authorization", "Bearer "+key)
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	app.Handler().ServeHTTP(recorder, request)

	wantResponse := `{ "results" : [ { "campaign" : { "id" : "111" } } ] }`
	if recorder.Code != http.StatusOK || recorder.Body.String() != wantResponse {
		t.Fatalf("upstream response changed: status=%d body=%q", recorder.Code, recorder.Body.String())
	}
	if recorder.Header().Get("Content-Type") != "application/json; charset=utf-8" {
		t.Fatalf("upstream content type changed: %q", recorder.Header().Get("Content-Type"))
	}
}

func TestProxyAddsCampaignBoundaryAndPreservesPaginationToken(t *testing.T) {
	app := testApp(t)
	googleClient, googleCfg := testGoogleClient(func(request *http.Request) (*http.Response, error) {
		var body map[string]any
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		query, _ := body["query"].(string)
		if !strings.Contains(query, "WHERE campaign.id IN (111, 222) ORDER BY campaign.id") {
			t.Fatalf("gateway boundary did not reach Google: %s", query)
		}
		if body["pageToken"] != "abc" {
			t.Fatalf("pagination token changed: %#v", body)
		}
		return jsonResponse(http.StatusOK, `{"results":[]}`), nil
	})
	app.google = googleClient
	app.policy.google = googleClient
	config, err := app.store.Config()
	if err != nil {
		t.Fatal(err)
	}
	config.Google = googleCfg.Google
	config.Accounts = map[string]AccountPolicy{
		"1234567890": {
			CustomerID: "1234567890",
			Campaigns: map[string]CampaignPolicy{
				"111": {CampaignID: "111", Read: true},
				"222": {CampaignID: "222", Read: true},
			},
		},
	}
	if err := app.store.SaveConfig(config); err != nil {
		t.Fatal(err)
	}
	key, _, err := app.store.CreateAPIKey("test")
	if err != nil {
		t.Fatal(err)
	}
	requestBody := `{"method":"POST","path":"/v23/customers/1234567890/googleAds:search","body":{"query":"SELECT campaign.id FROM campaign ORDER BY campaign.id","pageToken":"abc"}}`
	request := httptest.NewRequest(http.MethodPost, "/v1/proxy", strings.NewReader(requestBody))
	request.Header.Set("Authorization", "Bearer "+key)
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	app.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("rewritten request returned %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestExactNameLookupUsesOneOriginalRequestAndNeverReleasesUnauthorizedRows(t *testing.T) {
	setup := func(t *testing.T, responder roundTripFunc) (*App, string) {
		t.Helper()
		app := testApp(t)
		googleClient, googleCfg := testGoogleClient(responder)
		app.google = googleClient
		app.policy.google = googleClient
		cfg, err := app.store.Config()
		if err != nil {
			t.Fatal(err)
		}
		cfg.Google = googleCfg.Google
		cfg.Accounts = map[string]AccountPolicy{
			"1234567890": {
				CustomerID: "1234567890",
				Campaigns: map[string]CampaignPolicy{
					"111": {CampaignID: "111", Read: true},
				},
			},
		}
		if err := app.store.SaveConfig(cfg); err != nil {
			t.Fatal(err)
		}
		key, _, err := app.store.CreateAPIKey("test")
		if err != nil {
			t.Fatal(err)
		}
		return app, key
	}
	proxy := func(app *App, key, query string) *httptest.ResponseRecorder {
		requestBody := `{"method":"POST","path":"/v23/customers/1234567890/googleAds:search","body":{"query":` + string(mustJSON(query)) + `}}`
		request := httptest.NewRequest(http.MethodPost, "/v1/proxy", strings.NewReader(requestBody))
		request.Header.Set("Authorization", "Bearer "+key)
		request.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()
		app.Handler().ServeHTTP(recorder, request)
		return recorder
	}
	query := `SELECT custom_audience.resource_name, custom_audience.name FROM custom_audience WHERE custom_audience.name = 'CIA - Exact'`

	t.Run("empty result is forwarded exactly after one Google call", func(t *testing.T) {
		var calls atomic.Int32
		app, key := setup(t, func(request *http.Request) (*http.Response, error) {
			calls.Add(1)
			body, err := io.ReadAll(request.Body)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(body), `"query":"`+query+`"`) {
				t.Fatalf("original exact-name request body changed: %s", body)
			}
			return jsonResponse(http.StatusOK, `{ "results" : [ ] }`), nil
		})
		recorder := proxy(app, key, query)
		if recorder.Code != http.StatusOK || recorder.Body.String() != `{ "results" : [ ] }` {
			t.Fatalf("empty exact-name response changed: status=%d body=%q", recorder.Code, recorder.Body.String())
		}
		if calls.Load() != 1 {
			t.Fatalf("exact-name request reached Google %d times", calls.Load())
		}
	})

	t.Run("unauthorized result bytes never reach Fandom", func(t *testing.T) {
		var originalCalls atomic.Int32
		app, key := setup(t, func(request *http.Request) (*http.Response, error) {
			body, err := io.ReadAll(request.Body)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(body), "FROM custom_audience") {
				originalCalls.Add(1)
				return jsonResponse(http.StatusOK, `{"results":[{"customAudience":{"resourceName":"customers/1234567890/customAudiences/999","name":"CIA - Exact","members":[{"keyword":"FORBIDDEN_SECRET"}]}}]}`), nil
			}
			return jsonResponse(http.StatusOK, `{"results":[]}`), nil
		})
		recorder := proxy(app, key, query)
		if recorder.Code != http.StatusForbidden {
			t.Fatalf("unauthorized result returned %d: %s", recorder.Code, recorder.Body.String())
		}
		if strings.Contains(recorder.Body.String(), "FORBIDDEN_SECRET") {
			t.Fatal("unauthorized Google response bytes escaped the gateway")
		}
		if originalCalls.Load() != 1 {
			t.Fatalf("original exact-name request reached Google %d times", originalCalls.Load())
		}
	})
}

func mustJSON(value string) []byte {
	raw, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return raw
}

func TestProxyRejectsDuplicateJSONKeysBeforePolicyOrUpstream(t *testing.T) {
	app := testApp(t)
	upstreamCalled := false
	googleClient, googleCfg := testGoogleClient(func(request *http.Request) (*http.Response, error) {
		upstreamCalled = true
		return jsonResponse(http.StatusOK, `{"results":[]}`), nil
	})
	app.google = googleClient
	app.policy.google = googleClient
	config, err := app.store.Config()
	if err != nil {
		t.Fatal(err)
	}
	config.Google = googleCfg.Google
	config.Accounts = map[string]AccountPolicy{
		"1234567890": {
			CustomerID: "1234567890",
			Campaigns: map[string]CampaignPolicy{
				"111": {CampaignID: "111", Read: true},
			},
		},
	}
	if err := app.store.SaveConfig(config); err != nil {
		t.Fatal(err)
	}
	key, _, err := app.store.CreateAPIKey("test")
	if err != nil {
		t.Fatal(err)
	}

	requests := []string{
		`{"method":"POST","method":"GET","path":"/v23/customers/1234567890/googleAds:search","body":{"query":"SELECT campaign.id FROM campaign WHERE campaign.id = 111"}}`,
		`{"method":"POST","path":"/v23/customers/1234567890/googleAds:search","body":{"query":"SELECT campaign.id FROM campaign WHERE campaign.id = 111","query":"SELECT campaign.id FROM campaign"}}`,
		`{"method":"POST","path":"/v23/customers/1234567890/googleAds:search","body":{"nested":{"x":1,"x":2},"query":"SELECT campaign.id FROM campaign WHERE campaign.id = 111"}}`,
	}
	for _, requestBody := range requests {
		request := httptest.NewRequest(http.MethodPost, "/v1/proxy", strings.NewReader(requestBody))
		request.Header.Set("Authorization", "Bearer "+key)
		request.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()
		app.Handler().ServeHTTP(recorder, request)
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("duplicate-key request returned %d: %s", recorder.Code, recorder.Body.String())
		}
	}
	if upstreamCalled {
		t.Fatal("duplicate-key request reached Google")
	}
}

func TestPolicyRevocationWaitsForPriorRequestAndBlocksEveryLaterRequest(t *testing.T) {
	app := testApp(t)
	upstreamStarted := make(chan struct{})
	releaseUpstream := make(chan struct{})
	var upstreamCalls atomic.Int32
	googleClient, googleCfg := testGoogleClient(func(_ *http.Request) (*http.Response, error) {
		if upstreamCalls.Add(1) == 1 {
			close(upstreamStarted)
			<-releaseUpstream
		}
		return jsonResponse(http.StatusOK, `{"results":[]}`), nil
	})
	app.google = googleClient
	app.policy.google = googleClient
	cfg, err := app.store.Config()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Google = googleCfg.Google
	cfg.Accounts = map[string]AccountPolicy{
		"1234567890": {
			CustomerID: "1234567890",
			Campaigns: map[string]CampaignPolicy{
				"111": {CampaignID: "111", Read: true},
			},
		},
	}
	if err := app.store.SaveConfig(cfg); err != nil {
		t.Fatal(err)
	}
	key, _, err := app.store.CreateAPIKey("test")
	if err != nil {
		t.Fatal(err)
	}

	proxy := func() *httptest.ResponseRecorder {
		body := `{"method":"POST","path":"/v23/customers/1234567890/googleAds:search","body":{"query":"SELECT campaign.id FROM campaign WHERE campaign.id = 111"}}`
		request := httptest.NewRequest(http.MethodPost, "/v1/proxy", strings.NewReader(body))
		request.Header.Set("Authorization", "Bearer "+key)
		request.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()
		app.Handler().ServeHTTP(recorder, request)
		return recorder
	}
	firstDone := make(chan *httptest.ResponseRecorder, 1)
	go func() { firstDone <- proxy() }()
	select {
	case <-upstreamStarted:
	case <-time.After(time.Second):
		t.Fatal("authorized request never reached the upstream boundary")
	}

	session, err := app.security.newSession()
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{"csrf_token": {app.security.csrfToken(session)}}
	policyRequest := httptest.NewRequest(http.MethodPost, "/admin/policy", strings.NewReader(form.Encode()))
	policyRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	policyRequest.AddCookie(&http.Cookie{Name: adminCookieName, Value: session})
	policyDone := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		recorder := httptest.NewRecorder()
		app.Handler().ServeHTTP(recorder, policyRequest)
		policyDone <- recorder
	}()
	select {
	case <-policyDone:
		t.Fatal("revocation reported success while an old-policy request was still in flight")
	case <-time.After(75 * time.Millisecond):
	}

	close(releaseUpstream)
	if recorder := <-firstDone; recorder.Code != http.StatusOK {
		t.Fatalf("the already-authorized request returned %d: %s", recorder.Code, recorder.Body.String())
	}
	if recorder := <-policyDone; recorder.Code != http.StatusSeeOther {
		t.Fatalf("policy revocation returned %d: %s", recorder.Code, recorder.Body.String())
	}
	if recorder := proxy(); recorder.Code != http.StatusForbidden {
		t.Fatalf("request after revocation returned %d: %s", recorder.Code, recorder.Body.String())
	}
	if calls := upstreamCalls.Load(); calls != 1 {
		t.Fatalf("revoked request reached Google; upstream calls=%d", calls)
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
	if !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteLaxMode {
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
	keyAt := strings.Index(recorder.Body.String(), "fgw_live_")
	if keyAt < 0 || keyAt+len("fgw_live_")+12 > recorder.Body.Len() {
		t.Fatal("generated key was not present in the response")
	}
	keyID := recorder.Body.String()[keyAt+len("fgw_live_") : keyAt+len("fgw_live_")+12]
	if _, err := base64.RawURLEncoding.DecodeString(keyID); err != nil {
		// The exact key is deliberately only present once in HTML; its random ID
		// need not be a UUID, but must remain URL-safe.
		t.Fatal("generated key was not URL-safe")
	}

	form = url.Values{"csrf_token": {csrf}}
	request = httptest.NewRequest(http.MethodPost, "/admin/logout", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(cookie)
	recorder = httptest.NewRecorder()
	app.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("logout returned %d", recorder.Code)
	}
	request = httptest.NewRequest(http.MethodGet, "/admin", nil)
	request.AddCookie(cookie)
	recorder = httptest.NewRecorder()
	app.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusSeeOther || recorder.Header().Get("Location") != "/admin/login" {
		t.Fatalf("logged-out session remained usable: status=%d location=%q", recorder.Code, recorder.Header().Get("Location"))
	}
}

func TestSavedServiceAccountCanBeEditedWithoutReenteringSecrets(t *testing.T) {
	app := testApp(t)
	cfg, err := app.store.Config()
	if err != nil {
		t.Fatal(err)
	}
	serviceAccountJSON := `{"type":"service_account","project_id":"test-project","client_email":"fandom-service@test-project.iam.gserviceaccount.com","private_key":"-----BEGIN PRIVATE KEY-----\nnot-a-real-key\n-----END PRIVATE KEY-----\n","token_uri":"https://oauth2.googleapis.com/token"}`
	cfg.Google = &GoogleCredential{
		Mode:               "service_account",
		DeveloperToken:     "saved-developer-token",
		LoginCustomerID:    "123",
		ServiceAccountJSON: serviceAccountJSON,
	}
	if err := app.store.SaveConfig(cfg); err != nil {
		t.Fatal(err)
	}

	loginForm := url.Values{"password": {"a-secure-test-password"}}
	request := httptest.NewRequest(http.MethodPost, "/admin/login", strings.NewReader(loginForm.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recorder := httptest.NewRecorder()
	app.Handler().ServeHTTP(recorder, request)
	cookie := recorder.Result().Cookies()[0]
	csrf := app.security.csrfToken(cookie.Value)

	editForm := url.Values{
		"csrf_token":           {csrf},
		"service_account_json": {""},
		"developer_token":      {""},
		"login_customer_id":    {"456"},
	}
	request = httptest.NewRequest(http.MethodPost, "/admin/google/service-account", strings.NewReader(editForm.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(cookie)
	recorder = httptest.NewRecorder()
	app.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("save returned %d: %s", recorder.Code, recorder.Body.String())
	}

	saved, err := app.store.Config()
	if err != nil {
		t.Fatal(err)
	}
	if saved.Google.ServiceAccountJSON != serviceAccountJSON || saved.Google.DeveloperToken != "saved-developer-token" || saved.Google.LoginCustomerID != "456" {
		t.Fatalf("saved credential was not preserved correctly: %#v", saved.Google)
	}

	request = httptest.NewRequest(http.MethodGet, "/admin", nil)
	request.AddCookie(cookie)
	recorder = httptest.NewRecorder()
	app.Handler().ServeHTTP(recorder, request)
	body := recorder.Body.String()
	for _, expected := range []string{"Saved Google connection", "fandom-service@test-project.iam.gserviceaccount.com", "test-project", "Saved — leave blank to keep it"} {
		if !strings.Contains(body, expected) {
			t.Fatalf("admin page did not show %q", expected)
		}
	}
	for _, secret := range []string{"not-a-real-key", "saved-developer-token"} {
		if strings.Contains(body, secret) {
			t.Fatalf("admin page exposed saved secret %q", secret)
		}
	}
}

func TestRediscoveryPreservesOnlyMatchingCampaignPermissions(t *testing.T) {
	existing := map[string]AccountPolicy{
		"123": {
			CustomerID:            "123",
			AllowCreate:           true,
			AllCampaignsReadWrite: true,
			Campaigns: map[string]CampaignPolicy{
				"10": {CampaignID: "10", Name: "Old name", Read: true, Write: true},
				"20": {CampaignID: "20", Name: "Removed", Read: true},
			},
		},
	}
	discovered := map[string]AccountPolicy{
		"123": {
			CustomerID:  "123",
			DisplayName: "Fresh account name",
			Campaigns: map[string]CampaignPolicy{
				"10": {CampaignID: "10", Name: "Fresh campaign name"},
				"30": {CampaignID: "30", Name: "New campaign"},
			},
		},
	}

	merged := mergeDiscoveredPolicy(discovered, existing)
	if !merged["123"].AllowCreate || !merged["123"].AllCampaignsReadWrite || !merged["123"].Campaigns["10"].Read || !merged["123"].Campaigns["10"].Write {
		t.Fatal("matching permissions were not preserved")
	}
	if merged["123"].Campaigns["10"].Name != "Fresh campaign name" {
		t.Fatal("fresh Google metadata was not retained")
	}
	if merged["123"].Campaigns["30"].Read || merged["123"].Campaigns["30"].Write {
		t.Fatal("a newly discovered campaign inherited permissions")
	}
	if _, ok := merged["123"].Campaigns["20"]; ok {
		t.Fatal("a campaign no longer discovered by Google was retained")
	}
}
