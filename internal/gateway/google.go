package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

const (
	googleAdsScope      = "https://www.googleapis.com/auth/adwords"
	googleAdsAPIHost    = "googleads.googleapis.com"
	googleOAuthAuthURL  = "https://accounts.google.com/o/oauth2/v2/auth"
	googleOAuthTokenURL = "https://oauth2.googleapis.com/token"
	maximumUpstreamBody = 16 << 20
	maximumAccounts     = 500
	maximumCampaigns    = 20000
)

var cleanIDPattern = regexp.MustCompile(`^\d{1,20}$`)
var formattedCustomerIDPattern = regexp.MustCompile(`^\d{3}-\d{3}-\d{4}$`)

type GoogleClient struct {
	store             *Store
	httpClient        *http.Client
	apiVersion        string
	tokenMu           sync.Mutex
	cachedTokenKey    [32]byte
	cachedTokenSource oauth2.TokenSource
}

type UpstreamResponse struct {
	Status      int
	ContentType string
	Body        []byte
}

func NewGoogleClient(store *Store, apiVersion string) *GoogleClient {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxIdleConns = 20
	transport.MaxIdleConnsPerHost = 20
	transport.IdleConnTimeout = 60 * time.Second
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	return &GoogleClient{
		store:      store,
		apiVersion: apiVersion,
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   90 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (g *GoogleClient) oauthContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, oauth2.HTTPClient, g.httpClient)
}

func normalizeCustomerID(value string) string {
	value = strings.TrimSpace(value)
	if formattedCustomerIDPattern.MatchString(value) {
		return strings.ReplaceAll(value, "-", "")
	}
	if cleanIDPattern.MatchString(value) {
		return value
	}
	return ""
}

// googleIDValue validates identifiers returned by Google without repairing
// them. Removing unexpected characters here could turn a malformed or
// mismatched upstream identifier into a different, valid-looking resource.
func googleIDValue(value any) (string, error) {
	var id string
	switch typed := value.(type) {
	case string:
		id = typed
	case json.Number:
		id = typed.String()
	default:
		return "", errors.New("Google returned an identifier with an invalid JSON type")
	}
	if !isNonzeroPositiveID(id) {
		return "", fmt.Errorf("Google returned an invalid identifier %q", id)
	}
	return id, nil
}

func decodeGoogleJSON(raw []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	return ensureJSONEOF(decoder)
}

func validateGoogleCredential(credential *GoogleCredential) error {
	if credential == nil {
		return errors.New("Google Ads is not configured")
	}
	credential.LoginCustomerID = normalizeCustomerID(credential.LoginCustomerID)
	if !isNonzeroPositiveID(credential.LoginCustomerID) {
		return errors.New("a valid Google Ads login customer ID is required")
	}
	credential.DeveloperToken = strings.TrimSpace(credential.DeveloperToken)
	if credential.DeveloperToken == "" || len(credential.DeveloperToken) > 200 {
		return errors.New("a Google Ads developer token is required")
	}
	switch credential.Mode {
	case "oauth":
		if credential.OAuthClientID == "" || credential.OAuthClientSecret == "" || len(credential.OAuthClientID) > 500 || len(credential.OAuthClientSecret) > 500 {
			return errors.New("OAuth client ID and client secret are required")
		}
	case "service_account":
		if len(credential.ServiceAccountJSON) == 0 || len(credential.ServiceAccountJSON) > 64<<10 || !json.Valid([]byte(credential.ServiceAccountJSON)) {
			return errors.New("service account JSON is invalid")
		}
		var key struct {
			Type        string `json:"type"`
			ClientEmail string `json:"client_email"`
			PrivateKey  string `json:"private_key"`
			TokenURI    string `json:"token_uri"`
		}
		if json.Unmarshal([]byte(credential.ServiceAccountJSON), &key) != nil || key.Type != "service_account" || !strings.HasSuffix(key.ClientEmail, ".gserviceaccount.com") || !strings.Contains(key.PrivateKey, "BEGIN PRIVATE KEY") || key.TokenURI != googleOAuthTokenURL {
			return errors.New("service account JSON is not a valid Google service-account key")
		}
	default:
		return errors.New("Google authentication mode must be oauth or service_account")
	}
	return nil
}

func (g *GoogleClient) oauthConfig(cfg PersistentConfig, baseURL *url.URL) (*oauth2.Config, error) {
	if cfg.Google == nil || cfg.Google.Mode != "oauth" {
		return nil, errors.New("OAuth is not configured")
	}
	callback := *baseURL
	callback.Path = strings.TrimRight(callback.Path, "/") + "/admin/google/callback"
	callback.RawQuery = ""
	return &oauth2.Config{
		ClientID:     cfg.Google.OAuthClientID,
		ClientSecret: cfg.Google.OAuthClientSecret,
		RedirectURL:  callback.String(),
		Scopes:       []string{googleAdsScope},
		Endpoint: oauth2.Endpoint{
			AuthURL:  googleOAuthAuthURL,
			TokenURL: googleOAuthTokenURL,
		},
	}, nil
}

func (g *GoogleClient) tokenSource(ctx context.Context, cfg PersistentConfig) (oauth2.TokenSource, error) {
	if err := validateGoogleCredential(cfg.Google); err != nil {
		return nil, err
	}
	credentialKey := sha256.Sum256([]byte(strings.Join([]string{
		cfg.Google.Mode,
		cfg.Google.OAuthClientID,
		cfg.Google.OAuthClientSecret,
		cfg.Google.OAuthRefreshToken,
		cfg.Google.ServiceAccountJSON,
	}, "\x00")))
	g.tokenMu.Lock()
	defer g.tokenMu.Unlock()
	if g.cachedTokenSource != nil && g.cachedTokenKey == credentialKey {
		return g.cachedTokenSource, nil
	}
	// Reuse access tokens between requests. The client has its own timeout, so
	// the refresh source does not retain a soon-to-be-cancelled request context.
	ctx = g.oauthContext(context.Background())
	var source oauth2.TokenSource
	switch cfg.Google.Mode {
	case "oauth":
		if cfg.Google.OAuthRefreshToken == "" {
			return nil, errors.New("Google OAuth authorization has not been completed")
		}
		oauthConfig := &oauth2.Config{
			ClientID:     cfg.Google.OAuthClientID,
			ClientSecret: cfg.Google.OAuthClientSecret,
			Scopes:       []string{googleAdsScope},
			Endpoint:     oauth2.Endpoint{AuthURL: googleOAuthAuthURL, TokenURL: googleOAuthTokenURL},
		}
		source = oauthConfig.TokenSource(ctx, &oauth2.Token{RefreshToken: cfg.Google.OAuthRefreshToken})
	case "service_account":
		jwtConfig, err := google.JWTConfigFromJSON([]byte(cfg.Google.ServiceAccountJSON), googleAdsScope)
		if err != nil {
			return nil, fmt.Errorf("parse service account: %w", err)
		}
		jwtConfig.TokenURL = googleOAuthTokenURL
		source = jwtConfig.TokenSource(ctx)
	default:
		return nil, errors.New("unsupported Google authentication mode")
	}
	g.cachedTokenKey = credentialKey
	g.cachedTokenSource = oauth2.ReuseTokenSource(nil, source)
	return g.cachedTokenSource, nil
}

func (g *GoogleClient) Do(ctx context.Context, cfg PersistentConfig, method, path string, body map[string]any) (UpstreamResponse, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return UpstreamResponse{}, err
	}
	return g.DoRaw(ctx, cfg, method, path, raw)
}

// DoRaw forwards the policy engine's effective Google request body. Requests
// that were already campaign-scoped retain their original bytes; the policy
// engine may re-encode a body when it must add a gateway-owned campaign
// boundary or a non-sensitive field used for response authorization.
func (g *GoogleClient) DoRaw(ctx context.Context, cfg PersistentConfig, method, path string, rawBody []byte) (UpstreamResponse, error) {
	if err := validateProxyPath(path); err != nil {
		return UpstreamResponse{}, err
	}
	tokenSource, err := g.tokenSource(ctx, cfg)
	if err != nil {
		return UpstreamResponse{}, err
	}
	token, err := tokenSource.Token()
	if err != nil {
		return UpstreamResponse{}, fmt.Errorf("obtain Google access token: %w", err)
	}

	var reader io.Reader
	if method != http.MethodGet {
		if len(rawBody) == 0 {
			rawBody = []byte(`{}`)
		}
		reader = bytes.NewReader(rawBody)
	}
	requestURL := "https://" + googleAdsAPIHost + path
	req, err := http.NewRequestWithContext(ctx, method, requestURL, reader)
	if err != nil {
		return UpstreamResponse{}, err
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	req.Header.Set("developer-token", cfg.Google.DeveloperToken)
	loginCustomerID := normalizeCustomerID(cfg.Google.LoginCustomerID)
	targetCustomerID := ""
	if matches := proxyPathPattern.FindStringSubmatch(path); len(matches) > 1 {
		targetCustomerID = matches[1]
	}
	// Google expects this header when traversing a manager account, but not for
	// listAccessibleCustomers or direct calls to the login account itself.
	if targetCustomerID != "" && targetCustomerID != loginCustomerID {
		req.Header.Set("login-customer-id", loginCustomerID)
	}
	if reader != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := g.httpClient.Do(req)
	if err != nil {
		return UpstreamResponse{}, fmt.Errorf("Google Ads request failed: %w", err)
	}
	defer resp.Body.Close()
	limited := io.LimitReader(resp.Body, maximumUpstreamBody+1)
	raw, err := io.ReadAll(limited)
	if err != nil {
		return UpstreamResponse{}, err
	}
	if len(raw) > maximumUpstreamBody {
		return UpstreamResponse{}, errors.New("Google Ads response exceeded the 16 MB safety limit")
	}
	return UpstreamResponse{Status: resp.StatusCode, ContentType: resp.Header.Get("Content-Type"), Body: raw}, nil
}

func (g *GoogleClient) search(ctx context.Context, cfg PersistentConfig, customerID, query string) ([]map[string]any, error) {
	customerID = normalizeCustomerID(customerID)
	path := fmt.Sprintf("/%s/customers/%s/googleAds:search", g.apiVersion, customerID)
	var results []map[string]any
	pageToken := ""
	for {
		// Google Ads API search responses use a fixed page size. Sending a
		// pageSize value is rejected with PAGE_SIZE_NOT_SUPPORTED.
		body := map[string]any{"query": query}
		if pageToken != "" {
			body["pageToken"] = pageToken
		}
		response, err := g.Do(ctx, cfg, http.MethodPost, path, body)
		if err != nil {
			return nil, err
		}
		if response.Status < 200 || response.Status >= 300 {
			return nil, googleResponseError(response)
		}
		var payload struct {
			Results       []map[string]any `json:"results"`
			NextPageToken string           `json:"nextPageToken"`
		}
		if err := decodeGoogleJSON(response.Body, &payload); err != nil {
			return nil, err
		}
		results = append(results, payload.Results...)
		if len(results) > maximumCampaigns {
			return nil, fmt.Errorf("Google Ads query exceeded the %d-row discovery limit", maximumCampaigns)
		}
		pageToken = payload.NextPageToken
		if pageToken == "" {
			return results, nil
		}
	}
}

func googleResponseError(response UpstreamResponse) error {
	var payload struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(response.Body, &payload) == nil && payload.Error.Message != "" {
		return errors.New(payload.Error.Message)
	}
	return fmt.Errorf("Google Ads returned HTTP %d", response.Status)
}

func (g *GoogleClient) Discover(ctx context.Context, cfg PersistentConfig) (map[string]AccountPolicy, error) {
	response, err := g.Do(ctx, cfg, http.MethodGet, "/"+g.apiVersion+"/customers:listAccessibleCustomers", nil)
	if err != nil {
		return nil, err
	}
	if response.Status < 200 || response.Status >= 300 {
		return nil, googleResponseError(response)
	}
	var roots struct {
		ResourceNames []string `json:"resourceNames"`
	}
	if err := decodeGoogleJSON(response.Body, &roots); err != nil {
		return nil, err
	}

	accessible := map[string]bool{}
	for _, resourceName := range roots.ResourceNames {
		if !strings.HasPrefix(resourceName, "customers/") {
			return nil, fmt.Errorf("Google returned an invalid accessible customer resource %q", resourceName)
		}
		id, idErr := googleIDValue(strings.TrimPrefix(resourceName, "customers/"))
		if idErr != nil {
			return nil, fmt.Errorf("Google returned an invalid accessible customer resource %q: %w", resourceName, idErr)
		}
		accessible[id] = true
	}
	loginID := normalizeCustomerID(cfg.Google.LoginCustomerID)
	if !isNonzeroPositiveID(loginID) || !accessible[loginID] {
		return nil, fmt.Errorf("configured login customer %s is not directly accessible to these Google credentials", loginID)
	}
	// A gateway has one explicit Google Ads login account. Discover only that
	// account and its descendants; unrelated accounts directly accessible to
	// the same Google identity must never be pulled into this gateway by
	// accident.
	accounts := map[string]AccountPolicy{}
	parentByID := map[string]string{}
	queue := []string{loginID}
	seen := map[string]bool{}
	for len(queue) > 0 {
		customerID := queue[0]
		queue = queue[1:]
		if seen[customerID] {
			continue
		}
		if len(accounts) >= maximumAccounts {
			return nil, fmt.Errorf("Google Ads discovery exceeded the %d-account safety limit", maximumAccounts)
		}
		seen[customerID] = true

		infoRows, infoErr := g.search(ctx, cfg, customerID, `SELECT customer.id, customer.descriptive_name, customer.currency_code, customer.time_zone, customer.manager, customer.test_account FROM customer`)
		if infoErr != nil {
			return nil, fmt.Errorf("query Google Ads customer %s: %w", customerID, infoErr)
		}
		account := AccountPolicy{CustomerID: customerID, DisplayName: customerID, Campaigns: map[string]CampaignPolicy{}}
		account.ParentID = parentByID[customerID]
		if len(infoRows) != 1 {
			return nil, fmt.Errorf("Google returned %d customer rows for requested customer %s", len(infoRows), customerID)
		}
		customer, ok := infoRows[0]["customer"].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("Google returned a malformed customer row for requested customer %s", customerID)
		}
		returnedCustomerID, idErr := googleIDValue(customer["id"])
		if idErr != nil || returnedCustomerID != customerID {
			return nil, fmt.Errorf("Google returned customer %q while customer %s was requested", returnedCustomerID, customerID)
		}
		account.DisplayName = stringValue(customer["descriptiveName"], customerID)
		account.CurrencyCode = stringValue(customer["currencyCode"], "")
		account.TimeZone = stringValue(customer["timeZone"], "")
		account.IsManager, _ = customer["manager"].(bool)
		if existing, ok := cfg.Accounts[customerID]; ok {
			account.AllowCreate = existing.AllowCreate
			account.AllCampaignsReadWrite = existing.AllCampaignsReadWrite
		}
		accounts[customerID] = account

		if account.IsManager {
			rows, hierarchyErr := g.search(ctx, cfg, customerID, `SELECT customer_client.id, customer_client.descriptive_name, customer_client.currency_code, customer_client.time_zone, customer_client.manager, customer_client.level, customer_client.status FROM customer_client WHERE customer_client.level <= 1`)
			if hierarchyErr != nil {
				return nil, fmt.Errorf("query Google Ads hierarchy for customer %s: %w", customerID, hierarchyErr)
			}
			for _, row := range rows {
				client, ok := row["customerClient"].(map[string]any)
				if !ok {
					return nil, fmt.Errorf("Google returned a malformed hierarchy row for customer %s", customerID)
				}
				childID, idErr := googleIDValue(client["id"])
				if idErr != nil {
					return nil, fmt.Errorf("Google returned a malformed hierarchy customer for customer %s: %w", customerID, idErr)
				}
				if childID == customerID {
					continue
				}
				queue = append(queue, childID)
				if parentByID[childID] == "" {
					parentByID[childID] = customerID
				}
				if existing, ok := accounts[childID]; ok {
					existing.ParentID = parentByID[childID]
					accounts[childID] = existing
				}
			}
		}
	}

	totalCampaigns := 0
	for customerID, account := range accounts {
		if account.IsManager {
			continue
		}
		rows, campaignErr := g.search(ctx, cfg, customerID, `SELECT campaign.id, campaign.name, campaign.status FROM campaign WHERE campaign.status != 'REMOVED' ORDER BY campaign.name`)
		if campaignErr != nil {
			return nil, fmt.Errorf("query Google Ads campaigns for customer %s: %w", customerID, campaignErr)
		}
		if totalCampaigns+len(rows) > maximumCampaigns {
			return nil, fmt.Errorf("Google Ads discovery exceeded the %d-campaign safety limit", maximumCampaigns)
		}
		for _, row := range rows {
			campaign, ok := row["campaign"].(map[string]any)
			if !ok {
				return nil, fmt.Errorf("Google returned a malformed campaign row for customer %s", customerID)
			}
			id, idErr := googleIDValue(campaign["id"])
			if idErr != nil {
				return nil, fmt.Errorf("Google returned a malformed campaign for customer %s: %w", customerID, idErr)
			}
			policy := CampaignPolicy{CampaignID: id, Name: stringValue(campaign["name"], id), Status: stringValue(campaign["status"], "")}
			if oldAccount, ok := cfg.Accounts[customerID]; ok {
				if old, ok := oldAccount.Campaigns[id]; ok {
					policy.Read = old.Read
					policy.Write = old.Write
				}
			}
			account.Campaigns[id] = policy
			totalCampaigns++
		}
		accounts[customerID] = account
	}

	// Reapply relationships from discovery, falling back to the prior snapshot when
	// Google did not return the hierarchy in this refresh.
	for id, old := range cfg.Accounts {
		if current, ok := accounts[id]; ok {
			if parent := parentByID[id]; parent != "" {
				current.ParentID = parent
			} else if current.ParentID == "" {
				current.ParentID = old.ParentID
			}
			accounts[id] = current
		}
	}
	return accounts, nil
}

func stringValue(value any, fallback string) string {
	switch typed := value.(type) {
	case string:
		if typed != "" {
			return typed
		}
	case json.Number:
		return typed.String()
	case float64:
		return fmt.Sprintf("%.0f", typed)
	}
	return fallback
}

func sortedAccountIDs(accounts map[string]AccountPolicy) []string {
	ids := make([]string, 0, len(accounts))
	for id := range accounts {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}
