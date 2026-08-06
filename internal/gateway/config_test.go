package gateway

import (
	"encoding/base64"
	"testing"
)

func setValidRuntimeEnvironment(t *testing.T) {
	t.Helper()
	t.Setenv("GATEWAY_BASE_URL", "https://gateway.customer.example.com")
	t.Setenv("GATEWAY_MASTER_KEY", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	t.Setenv("GATEWAY_ADMIN_PASSWORD", "a-secure-test-password")
	t.Setenv("GATEWAY_DATA_PATH", t.TempDir()+"/gateway.db")
}

func TestRuntimeConfigRequiresHTTPS(t *testing.T) {
	setValidRuntimeEnvironment(t)
	t.Setenv("GATEWAY_BASE_URL", "http://gateway.customer.example.com")
	if _, err := LoadRuntimeConfig(); err == nil {
		t.Fatal("insecure base URL was accepted")
	}
}

func TestRuntimeConfigValidatesGoogleAdsAPIVersion(t *testing.T) {
	setValidRuntimeEnvironment(t)
	t.Setenv("GATEWAY_GOOGLE_ADS_API_VERSION", "../../v24")
	if _, err := LoadRuntimeConfig(); err == nil {
		t.Fatal("invalid Google Ads API version was accepted")
	}
	t.Setenv("GATEWAY_GOOGLE_ADS_API_VERSION", "v25")
	cfg, err := LoadRuntimeConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.GoogleAdsAPIVersion != "v25" {
		t.Fatalf("unexpected API version: %s", cfg.GoogleAdsAPIVersion)
	}
}

func TestServiceAccountCredentialCannotChooseTokenHost(t *testing.T) {
	credential := &GoogleCredential{
		Mode:            "service_account",
		DeveloperToken:  "developer-token",
		LoginCustomerID: "1234567890",
		ServiceAccountJSON: `{
			"type":"service_account",
			"client_email":"gateway@example.iam.gserviceaccount.com",
			"private_key":"-----BEGIN PRIVATE KEY-----\\ntest\\n-----END PRIVATE KEY-----\\n",
			"token_uri":"http://127.0.0.1/token"
		}`,
	}
	if err := validateGoogleCredential(credential); err == nil {
		t.Fatal("service-account token host was not pinned to Google")
	}
}
