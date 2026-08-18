package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"golang.org/x/oauth2"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

func testGoogleClient(responder roundTripFunc) (*GoogleClient, PersistentConfig) {
	credential := &GoogleCredential{
		Mode:              "oauth",
		DeveloperToken:    "developer-token",
		LoginCustomerID:   "123",
		OAuthClientID:     "client-id",
		OAuthClientSecret: "client-secret",
		OAuthRefreshToken: "refresh-token",
	}
	key := sha256.Sum256([]byte(strings.Join([]string{
		credential.Mode,
		credential.OAuthClientID,
		credential.OAuthClientSecret,
		credential.OAuthRefreshToken,
		credential.ServiceAccountJSON,
	}, "\x00")))
	return &GoogleClient{
		apiVersion:     "v23",
		httpClient:     &http.Client{Transport: responder},
		cachedTokenKey: key,
		cachedTokenSource: oauth2.StaticTokenSource(&oauth2.Token{
			AccessToken: "access-token",
		}),
	}, PersistentConfig{Google: credential, Accounts: map[string]AccountPolicy{}}
}

func jsonResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": {"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func TestNormalizeCustomerIDOnlyAcceptsCanonicalFormats(t *testing.T) {
	tests := map[string]string{
		"1234567890":     "1234567890",
		"123-456-7890":   "1234567890",
		" 123-456-7890 ": "1234567890",
		"abc1234567890":  "",
		"123--456-7890":  "",
		"123 456 7890":   "",
	}
	for input, expected := range tests {
		if actual := normalizeCustomerID(input); actual != expected {
			t.Errorf("normalizeCustomerID(%q) = %q, want %q", input, actual, expected)
		}
	}
}

func TestSearchDoesNotSendUnsupportedPageSize(t *testing.T) {
	client, cfg := testGoogleClient(func(request *http.Request) (*http.Response, error) {
		var body map[string]any
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if _, present := body["pageSize"]; present {
			t.Fatal("Google Ads search request included unsupported pageSize")
		}
		if body["query"] != "SELECT customer.id FROM customer" {
			t.Fatalf("unexpected query body: %#v", body)
		}
		return jsonResponse(http.StatusOK, `{"results":[]}`), nil
	})

	if _, err := client.search(context.Background(), cfg, "123", "SELECT customer.id FROM customer"); err != nil {
		t.Fatal(err)
	}
}

func TestDiscoverReturnsCustomerQueryErrors(t *testing.T) {
	client, cfg := testGoogleClient(func(request *http.Request) (*http.Response, error) {
		if strings.HasSuffix(request.URL.Path, "/customers:listAccessibleCustomers") {
			return jsonResponse(http.StatusOK, `{"resourceNames":["customers/123"]}`), nil
		}
		return jsonResponse(http.StatusBadRequest, `{"error":{"message":"diagnostic failure"}}`), nil
	})

	_, err := client.Discover(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "query Google Ads customer 123: diagnostic failure") {
		t.Fatalf("discovery hid the Google error: %v", err)
	}
}

func TestDiscoverRejectsMalformedAccessibleCustomerInsteadOfRepairingIt(t *testing.T) {
	client, cfg := testGoogleClient(func(request *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusOK, `{"resourceNames":["customers/12x3"]}`), nil
	})

	_, err := client.Discover(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), `invalid accessible customer resource "customers/12x3"`) {
		t.Fatalf("discovery accepted or hid a malformed customer resource: %v", err)
	}
}

func TestDiscoverRejectsMismatchedCustomerRow(t *testing.T) {
	client, cfg := testGoogleClient(func(request *http.Request) (*http.Response, error) {
		if strings.HasSuffix(request.URL.Path, "/customers:listAccessibleCustomers") {
			return jsonResponse(http.StatusOK, `{"resourceNames":["customers/123"]}`), nil
		}
		return jsonResponse(http.StatusOK, `{"results":[{"customer":{"id":"456"}}]}`), nil
	})

	_, err := client.Discover(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), `returned customer "456" while customer 123 was requested`) {
		t.Fatalf("discovery accepted or hid a mismatched customer row: %v", err)
	}
}

func TestDiscoverRejectsMalformedCampaignIDInsteadOfRepairingIt(t *testing.T) {
	client, cfg := testGoogleClient(func(request *http.Request) (*http.Response, error) {
		if strings.HasSuffix(request.URL.Path, "/customers:listAccessibleCustomers") {
			return jsonResponse(http.StatusOK, `{"resourceNames":["customers/123"]}`), nil
		}
		var body struct {
			Query string `json:"query"`
		}
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(body.Query, "FROM customer") {
			return jsonResponse(http.StatusOK, `{"results":[{"customer":{"id":"123","descriptiveName":"Test"}}]}`), nil
		}
		return jsonResponse(http.StatusOK, `{"results":[{"campaign":{"id":"45x6","name":"Bad"}}]}`), nil
	})

	_, err := client.Discover(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), `invalid identifier "45x6"`) {
		t.Fatalf("discovery accepted or hid a malformed campaign identifier: %v", err)
	}
}

func TestDiscoverRejectsTrailingJSON(t *testing.T) {
	client, cfg := testGoogleClient(func(request *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusOK, `{"resourceNames":["customers/123"]}{}`), nil
	})

	if _, err := client.Discover(context.Background(), cfg); err == nil {
		t.Fatal("discovery accepted trailing JSON from Google")
	}
}

func TestDiscoverRejectsCredentialsThatCannotDirectlyAccessConfiguredLogin(t *testing.T) {
	client, cfg := testGoogleClient(func(request *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusOK, `{"resourceNames":["customers/456"]}`), nil
	})

	_, err := client.Discover(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "configured login customer 123 is not directly accessible") {
		t.Fatalf("discovery accepted credentials for a different login account: %v", err)
	}
}

func TestDiscoverIgnoresUnrelatedDirectlyAccessibleRoots(t *testing.T) {
	client, cfg := testGoogleClient(func(request *http.Request) (*http.Response, error) {
		if strings.HasSuffix(request.URL.Path, "/customers:listAccessibleCustomers") {
			return jsonResponse(http.StatusOK, `{"resourceNames":["customers/123","customers/456"]}`), nil
		}
		if strings.Contains(request.URL.Path, "/customers/456/") {
			t.Fatal("discovery queried an unrelated directly accessible account")
		}
		var body struct {
			Query string `json:"query"`
		}
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(body.Query, "FROM customer") {
			return jsonResponse(http.StatusOK, `{"results":[{"customer":{"id":"123","descriptiveName":"Configured"}}]}`), nil
		}
		return jsonResponse(http.StatusOK, `{"results":[]}`), nil
	})

	accounts, err := client.Discover(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(accounts) != 1 || accounts["123"].CustomerID != "123" {
		t.Fatalf("discovery included unexpected accounts: %#v", accounts)
	}
}
