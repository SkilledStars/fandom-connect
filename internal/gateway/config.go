package gateway

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
)

const (
	protocolVersion            = "1.0"
	defaultDataPath            = "/data/gateway.db"
	defaultListen              = ":8080"
	defaultGoogleAdsAPIVersion = "v24"
)

var googleAdsAPIVersionPattern = regexp.MustCompile(`^v[0-9]+$`)

type RuntimeConfig struct {
	BaseURL             *url.URL
	MasterKey           []byte
	AdminPassword       string
	DataPath            string
	ListenAddr          string
	AllowInsecureHTTP   bool
	TrustForwardedFor   bool
	GoogleAdsAPIVersion string
}

func LoadRuntimeConfig() (RuntimeConfig, error) {
	var cfg RuntimeConfig
	baseURL, err := url.Parse(strings.TrimSpace(os.Getenv("GATEWAY_BASE_URL")))
	if err != nil || baseURL.Host == "" {
		return cfg, errors.New("GATEWAY_BASE_URL must be an absolute URL")
	}
	cfg.AllowInsecureHTTP = strings.EqualFold(os.Getenv("GATEWAY_ALLOW_INSECURE_HTTP"), "true")
	if baseURL.Scheme != "https" && !cfg.AllowInsecureHTTP {
		return cfg, errors.New("GATEWAY_BASE_URL must use HTTPS")
	}
	if baseURL.RawQuery != "" || baseURL.Fragment != "" || baseURL.User != nil {
		return cfg, errors.New("GATEWAY_BASE_URL cannot contain credentials, a query, or a fragment")
	}
	if baseURL.Path != "" && baseURL.Path != "/" {
		return cfg, errors.New("GATEWAY_BASE_URL cannot contain a path")
	}
	baseURL.Path = ""

	masterKey, err := parseMasterKey(os.Getenv("GATEWAY_MASTER_KEY"))
	if err != nil {
		return cfg, err
	}
	adminPassword := os.Getenv("GATEWAY_ADMIN_PASSWORD")
	if len(adminPassword) < 16 {
		return cfg, errors.New("GATEWAY_ADMIN_PASSWORD must contain at least 16 characters")
	}

	cfg.BaseURL = baseURL
	cfg.MasterKey = masterKey
	cfg.AdminPassword = adminPassword
	cfg.DataPath = envOrDefault("GATEWAY_DATA_PATH", defaultDataPath)
	cfg.ListenAddr = envOrDefault("GATEWAY_LISTEN_ADDR", defaultListen)
	cfg.TrustForwardedFor = strings.EqualFold(os.Getenv("GATEWAY_TRUST_FORWARDED_FOR"), "true")
	cfg.GoogleAdsAPIVersion = envOrDefault("GATEWAY_GOOGLE_ADS_API_VERSION", defaultGoogleAdsAPIVersion)
	if !googleAdsAPIVersionPattern.MatchString(cfg.GoogleAdsAPIVersion) {
		return cfg, errors.New("GATEWAY_GOOGLE_ADS_API_VERSION must look like v24")
	}
	return cfg, nil
}

func parseMasterKey(raw string) ([]byte, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("GATEWAY_MASTER_KEY is required")
	}
	if decoded, err := base64.StdEncoding.DecodeString(raw); err == nil && len(decoded) == 32 {
		return decoded, nil
	}
	if decoded, err := base64.RawStdEncoding.DecodeString(raw); err == nil && len(decoded) == 32 {
		return decoded, nil
	}
	if decoded, err := hex.DecodeString(raw); err == nil && len(decoded) == 32 {
		return decoded, nil
	}
	return nil, errors.New("GATEWAY_MASTER_KEY must be exactly 32 bytes encoded as base64 or hex")
}

func envOrDefault(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func randomBytes(size int) ([]byte, error) {
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		return nil, fmt.Errorf("secure random generation failed: %w", err)
	}
	return value, nil
}
