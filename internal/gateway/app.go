package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"
)

//go:embed web/*.html web/*.css
var webFiles embed.FS

type App struct {
	cfg       RuntimeConfig
	logger    *slog.Logger
	store     *Store
	security  *securityManager
	google    *GoogleClient
	policy    *PolicyEngine
	templates *template.Template
	writeMu   sync.Mutex
}

type adminView struct {
	Config           PersistentConfig
	Accounts         []AccountPolicy
	Keys             []APIKeyRecord
	Audit            []AuditEvent
	CSRF             string
	CallbackURL      string
	BaseURL          string
	GoogleConfigured bool
	Message          string
	Error            string
	NewKey           string
}

func NewApp(cfg RuntimeConfig, logger *slog.Logger) (*App, error) {
	store, err := OpenStore(cfg.DataPath, cfg.MasterKey)
	if err != nil {
		return nil, err
	}
	funcs := template.FuncMap{
		"campaigns": func(account AccountPolicy) []CampaignPolicy {
			values := make([]CampaignPolicy, 0, len(account.Campaigns))
			for _, campaign := range account.Campaigns {
				values = append(values, campaign)
			}
			sort.Slice(values, func(i, j int) bool {
				if values[i].Name == values[j].Name {
					return values[i].CampaignID < values[j].CampaignID
				}
				return strings.ToLower(values[i].Name) < strings.ToLower(values[j].Name)
			})
			return values
		},
		"date": func(value time.Time) string {
			if value.IsZero() {
				return "Never"
			}
			return value.Local().Format("2006-01-02 15:04")
		},
	}
	templates, err := template.New("root").Funcs(funcs).ParseFS(webFiles, "web/*.html")
	if err != nil {
		store.Close()
		return nil, fmt.Errorf("parse web templates: %w", err)
	}
	googleClient := NewGoogleClient(store, cfg.GoogleAdsAPIVersion)
	return &App{
		cfg:       cfg,
		logger:    logger,
		store:     store,
		security:  newSecurityManager(cfg),
		google:    googleClient,
		policy:    NewPolicyEngine(store, googleClient),
		templates: templates,
	}, nil
}

func (a *App) Close() error { return a.store.Close() }

func (a *App) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", a.handleHealth)
	mux.HandleFunc("GET /admin/login", a.handleLoginPage)
	mux.HandleFunc("POST /admin/login", a.handleLogin)
	mux.Handle("GET /admin/style.css", http.HandlerFunc(a.handleStyle))

	admin := http.NewServeMux()
	admin.HandleFunc("GET /admin", a.handleAdmin)
	admin.HandleFunc("POST /admin/logout", a.handleLogout)
	admin.HandleFunc("POST /admin/google/oauth", a.handleSaveOAuth)
	admin.HandleFunc("GET /admin/google/start", a.handleOAuthStart)
	admin.HandleFunc("GET /admin/google/callback", a.handleOAuthCallback)
	admin.HandleFunc("POST /admin/google/service-account", a.handleSaveServiceAccount)
	admin.HandleFunc("POST /admin/discover", a.handleDiscover)
	admin.HandleFunc("POST /admin/policy", a.handlePolicy)
	admin.HandleFunc("POST /admin/keys", a.handleCreateKey)
	admin.HandleFunc("POST /admin/keys/revoke", a.handleRevokeKey)
	mux.Handle("/admin", a.security.requireAdmin(admin))
	mux.Handle("/admin/", a.security.requireAdmin(admin))

	mux.HandleFunc("GET /v1/metadata", a.requireAPI(a.handleMetadata))
	mux.HandleFunc("POST /v1/proxy", a.requireAPI(a.handleProxy))
	return applySecurityHeaders(a.logRequests(mux))
}

func (a *App) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		next.ServeHTTP(w, r)
		if r.URL.Path != "/healthz" {
			a.logger.Info("request", "method", r.Method, "path", r.URL.Path, "duration_ms", time.Since(started).Milliseconds())
		}
	})
}

func (a *App) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, `{"status":"ok"}`)
}

func RunHealthcheck() error {
	address := envOrDefault("GATEWAY_HEALTHCHECK_URL", "http://127.0.0.1:8080/healthz")
	client := &http.Client{Timeout: 4 * time.Second}
	resp, err := client.Get(address)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health endpoint returned %d", resp.StatusCode)
	}
	return nil
}

func (a *App) handleStyle(w http.ResponseWriter, _ *http.Request) {
	raw, err := webFiles.ReadFile("web/style.css")
	if err != nil {
		http.NotFound(w, nil)
		return
	}
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_, _ = w.Write(raw)
}

func (a *App) render(w http.ResponseWriter, name string, view adminView, status int) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := a.templates.ExecuteTemplate(w, name, view); err != nil {
		a.logger.Error("render failed", "template", name, "error", err)
	}
}

func (a *App) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(adminCookieName); err == nil && a.security.validSession(cookie.Value) {
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}
	a.render(w, "login.html", adminView{}, http.StatusOK)
}

func (a *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	if !a.security.allowLogin(r) {
		a.render(w, "login.html", adminView{Error: "Too many attempts. Try again later."}, http.StatusTooManyRequests)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil || !a.security.verifyPassword(r.FormValue("password")) {
		time.Sleep(250 * time.Millisecond)
		a.render(w, "login.html", adminView{Error: "Incorrect password."}, http.StatusUnauthorized)
		return
	}
	session, err := a.security.newSession()
	if err != nil {
		http.Error(w, "Unable to create session", http.StatusInternalServerError)
		return
	}
	a.security.setSessionCookie(w, session)
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (a *App) handleLogout(w http.ResponseWriter, r *http.Request) {
	if !a.requireCSRF(w, r) {
		return
	}
	a.security.clearSessionCookie(w)
	http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
}

func (a *App) adminData(r *http.Request) (adminView, error) {
	cfg, err := a.store.Config()
	if err != nil {
		return adminView{}, err
	}
	if cfg.Google == nil {
		cfg.Google = &GoogleCredential{}
	}
	keys, err := a.store.ListAPIKeys()
	if err != nil {
		return adminView{}, err
	}
	audit, err := a.store.RecentAudit(50)
	if err != nil {
		return adminView{}, err
	}
	accounts := make([]AccountPolicy, 0, len(cfg.Accounts))
	for _, account := range cfg.Accounts {
		accounts = append(accounts, account)
	}
	sort.Slice(accounts, func(i, j int) bool {
		if accounts[i].IsManager != accounts[j].IsManager {
			return accounts[i].IsManager
		}
		return strings.ToLower(accounts[i].DisplayName) < strings.ToLower(accounts[j].DisplayName)
	})
	cookie, _ := r.Cookie(adminCookieName)
	callback := *a.cfg.BaseURL
	callback.Path = strings.TrimRight(callback.Path, "/") + "/admin/google/callback"
	return adminView{
		Config:           cfg,
		Accounts:         accounts,
		Keys:             keys,
		Audit:            audit,
		CSRF:             a.security.csrfToken(cookie.Value),
		CallbackURL:      callback.String(),
		BaseURL:          a.cfg.BaseURL.String(),
		GoogleConfigured: cfg.Google.Mode == "oauth" || cfg.Google.Mode == "service_account",
	}, nil
}

func (a *App) handleAdmin(w http.ResponseWriter, r *http.Request) {
	view, err := a.adminData(r)
	if err != nil {
		http.Error(w, "Unable to load gateway configuration", http.StatusInternalServerError)
		return
	}
	view.Message = r.URL.Query().Get("message")
	view.Error = r.URL.Query().Get("error")
	a.render(w, "admin.html", view, http.StatusOK)
}

func (a *App) requireCSRF(w http.ResponseWriter, r *http.Request) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 20<<20)
	if err := r.ParseMultipartForm(20 << 20); err != nil && !errors.Is(err, http.ErrNotMultipart) {
		if parseErr := r.ParseForm(); parseErr != nil {
			http.Error(w, "Invalid form", http.StatusBadRequest)
			return false
		}
	}
	if !a.security.verifyCSRF(r) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return false
	}
	return true
}

func (a *App) redirectAdmin(w http.ResponseWriter, r *http.Request, key, message string) {
	values := url.Values{}
	values.Set(key, message)
	http.Redirect(w, r, "/admin?"+values.Encode(), http.StatusSeeOther)
}

func (a *App) handleSaveOAuth(w http.ResponseWriter, r *http.Request) {
	if !a.requireCSRF(w, r) {
		return
	}
	cfg, err := a.store.Config()
	if err != nil {
		http.Error(w, "Unable to load configuration", http.StatusInternalServerError)
		return
	}
	credential := &GoogleCredential{
		Mode:              "oauth",
		DeveloperToken:    strings.TrimSpace(r.FormValue("developer_token")),
		LoginCustomerID:   normalizeCustomerID(r.FormValue("login_customer_id")),
		OAuthClientID:     strings.TrimSpace(r.FormValue("oauth_client_id")),
		OAuthClientSecret: strings.TrimSpace(r.FormValue("oauth_client_secret")),
	}
	if cfg.Google != nil && cfg.Google.Mode == "oauth" && cfg.Google.OAuthClientID == credential.OAuthClientID {
		credential.OAuthRefreshToken = cfg.Google.OAuthRefreshToken
	}
	if err := validateGoogleCredential(credential); err != nil {
		a.redirectAdmin(w, r, "error", err.Error())
		return
	}
	identityChanged := cfg.Google != nil && (cfg.Google.Mode != credential.Mode ||
		cfg.Google.LoginCustomerID != credential.LoginCustomerID ||
		cfg.Google.OAuthClientID != credential.OAuthClientID)
	if identityChanged {
		cfg.Accounts = map[string]AccountPolicy{}
		if err := a.store.ClearDerivedGoogleState(); err != nil {
			http.Error(w, "Unable to reset prior Google policy", http.StatusInternalServerError)
			return
		}
	}
	cfg.Google = credential
	if err := a.store.SaveConfig(cfg); err != nil {
		http.Error(w, "Unable to save configuration", http.StatusInternalServerError)
		return
	}
	a.redirectAdmin(w, r, "message", "OAuth settings saved. Complete Google authorization next.")
}

func (a *App) handleSaveServiceAccount(w http.ResponseWriter, r *http.Request) {
	if !a.requireCSRF(w, r) {
		return
	}
	cfg, err := a.store.Config()
	if err != nil {
		http.Error(w, "Unable to load configuration", http.StatusInternalServerError)
		return
	}
	credential := &GoogleCredential{
		Mode:               "service_account",
		DeveloperToken:     strings.TrimSpace(r.FormValue("developer_token")),
		LoginCustomerID:    normalizeCustomerID(r.FormValue("login_customer_id")),
		ServiceAccountJSON: strings.TrimSpace(r.FormValue("service_account_json")),
	}
	if err := validateGoogleCredential(credential); err != nil {
		a.redirectAdmin(w, r, "error", err.Error())
		return
	}
	identityChanged := cfg.Google != nil && (cfg.Google.Mode != credential.Mode ||
		cfg.Google.LoginCustomerID != credential.LoginCustomerID ||
		cfg.Google.ServiceAccountJSON != credential.ServiceAccountJSON)
	if identityChanged {
		cfg.Accounts = map[string]AccountPolicy{}
		if err := a.store.ClearDerivedGoogleState(); err != nil {
			http.Error(w, "Unable to reset prior Google policy", http.StatusInternalServerError)
			return
		}
	}
	cfg.Google = credential
	if err := a.store.SaveConfig(cfg); err != nil {
		http.Error(w, "Unable to save configuration", http.StatusInternalServerError)
		return
	}
	a.redirectAdmin(w, r, "message", "Service account settings saved.")
}

func (a *App) oauthState(session string) (string, error) {
	nonce, err := randomBytes(24)
	if err != nil {
		return "", err
	}
	payload := fmt.Sprintf("%d.%s", time.Now().Add(10*time.Minute).Unix(), base64.RawURLEncoding.EncodeToString(nonce))
	return payload + "." + a.security.sign("oauth:"+session+":"+payload), nil
}

func (a *App) validOAuthState(session, state string) bool {
	parts := strings.Split(state, ".")
	if len(parts) != 3 {
		return false
	}
	payload := parts[0] + "." + parts[1]
	expected := a.security.sign("oauth:" + session + ":" + payload)
	if subtle.ConstantTimeCompare([]byte(expected), []byte(parts[2])) != 1 {
		return false
	}
	expiresAt, err := strconv.ParseInt(parts[0], 10, 64)
	return err == nil && expiresAt > 0 && time.Now().Before(time.Unix(expiresAt, 0))
}

func (a *App) handleOAuthStart(w http.ResponseWriter, r *http.Request) {
	cfg, err := a.store.Config()
	if err != nil {
		a.redirectAdmin(w, r, "error", "OAuth settings are unavailable.")
		return
	}
	oauthConfig, err := a.google.oauthConfig(cfg, a.cfg.BaseURL)
	if err != nil {
		a.redirectAdmin(w, r, "error", err.Error())
		return
	}
	cookie, _ := r.Cookie(adminCookieName)
	state, err := a.oauthState(cookie.Value)
	if err != nil {
		http.Error(w, "Unable to start OAuth", http.StatusInternalServerError)
		return
	}
	target := oauthConfig.AuthCodeURL(state, oauth2.AccessTypeOffline, oauth2.SetAuthURLParam("prompt", "consent"), oauth2.SetAuthURLParam("include_granted_scopes", "true"))
	http.Redirect(w, r, target, http.StatusSeeOther)
}

func (a *App) handleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	cookie, _ := r.Cookie(adminCookieName)
	if cookie == nil || !a.validOAuthState(cookie.Value, r.URL.Query().Get("state")) {
		a.redirectAdmin(w, r, "error", "Google OAuth state was invalid or expired.")
		return
	}
	if oauthError := r.URL.Query().Get("error"); oauthError != "" {
		a.redirectAdmin(w, r, "error", "Google authorization failed: "+oauthError)
		return
	}
	cfg, err := a.store.Config()
	if err != nil {
		http.Error(w, "Unable to load configuration", http.StatusInternalServerError)
		return
	}
	oauthConfig, err := a.google.oauthConfig(cfg, a.cfg.BaseURL)
	if err != nil {
		a.redirectAdmin(w, r, "error", err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	token, err := oauthConfig.Exchange(a.google.oauthContext(ctx), r.URL.Query().Get("code"))
	if err != nil || token.RefreshToken == "" {
		a.redirectAdmin(w, r, "error", "Google did not return a refresh token. Revoke the prior grant and try again.")
		return
	}
	// A new Google grant may represent a different human or accessible account
	// set. Require campaign permissions to be selected again.
	cfg.Accounts = map[string]AccountPolicy{}
	if err := a.store.ClearDerivedGoogleState(); err != nil {
		http.Error(w, "Unable to reset prior Google policy", http.StatusInternalServerError)
		return
	}
	cfg.Google.OAuthRefreshToken = token.RefreshToken
	if err := a.store.SaveConfig(cfg); err != nil {
		http.Error(w, "Unable to store Google authorization", http.StatusInternalServerError)
		return
	}
	a.redirectAdmin(w, r, "message", "Google Ads connected. Discover accounts and campaigns next.")
}

func (a *App) handleDiscover(w http.ResponseWriter, r *http.Request) {
	if !a.requireCSRF(w, r) {
		return
	}
	cfg, err := a.store.Config()
	if err != nil {
		http.Error(w, "Unable to load configuration", http.StatusInternalServerError)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	accounts, err := a.google.Discover(ctx, cfg)
	if err != nil {
		a.redirectAdmin(w, r, "error", "Google Ads discovery failed: "+err.Error())
		return
	}
	cfg.Accounts = accounts
	if err := a.store.SaveConfig(cfg); err != nil {
		http.Error(w, "Unable to save discovered accounts", http.StatusInternalServerError)
		return
	}
	a.redirectAdmin(w, r, "message", fmt.Sprintf("Discovered %d Google Ads accounts.", len(accounts)))
}

func (a *App) handlePolicy(w http.ResponseWriter, r *http.Request) {
	if !a.requireCSRF(w, r) {
		return
	}
	cfg, err := a.store.Config()
	if err != nil {
		http.Error(w, "Unable to load configuration", http.StatusInternalServerError)
		return
	}
	for accountID, account := range cfg.Accounts {
		account.AllowCreate = r.Form.Has("create:" + accountID)
		for campaignID, campaign := range account.Campaigns {
			campaign.Read = r.Form.Has("read:" + accountID + ":" + campaignID)
			campaign.Write = r.Form.Has("write:" + accountID + ":" + campaignID)
			if campaign.Write {
				campaign.Read = true
			}
			account.Campaigns[campaignID] = campaign
		}
		cfg.Accounts[accountID] = account
	}
	if displayName := strings.TrimSpace(r.FormValue("display_name")); displayName != "" && len(displayName) <= 120 {
		cfg.DisplayName = displayName
	}
	if err := a.store.SaveConfig(cfg); err != nil {
		http.Error(w, "Unable to save policy", http.StatusInternalServerError)
		return
	}
	_ = a.store.AppendAudit(AuditEvent{Actor: "admin", Action: "policy.updated", Allowed: true, Status: http.StatusOK})
	a.redirectAdmin(w, r, "message", "Campaign access policy saved.")
}

func (a *App) handleCreateKey(w http.ResponseWriter, r *http.Request) {
	if !a.requireCSRF(w, r) {
		return
	}
	plaintext, _, err := a.store.CreateAPIKey(r.FormValue("name"))
	if err != nil {
		http.Error(w, "Unable to create connection key", http.StatusInternalServerError)
		return
	}
	view, err := a.adminData(r)
	if err != nil {
		http.Error(w, "Unable to load dashboard", http.StatusInternalServerError)
		return
	}
	view.NewKey = plaintext
	view.Message = "Connection key created. Copy it now; it will not be shown again."
	a.render(w, "admin.html", view, http.StatusOK)
}

func (a *App) handleRevokeKey(w http.ResponseWriter, r *http.Request) {
	if !a.requireCSRF(w, r) {
		return
	}
	if err := a.store.RevokeAPIKey(r.FormValue("id")); err != nil {
		http.Error(w, "Unable to revoke key", http.StatusInternalServerError)
		return
	}
	a.redirectAdmin(w, r, "message", "Connection key revoked.")
}

func (a *App) requireAPI(next func(http.ResponseWriter, *http.Request, APIKeyRecord)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, err := bearerToken(r)
		if err != nil {
			writeJSONError(w, http.StatusUnauthorized, "invalid_token", err.Error())
			return
		}
		record, ok := a.store.VerifyAPIKey(token)
		if !ok {
			writeJSONError(w, http.StatusUnauthorized, "invalid_token", "connection key was not recognized")
			return
		}
		if !a.security.allowAPI(record.ID) {
			w.Header().Set("Retry-After", "60")
			writeJSONError(w, http.StatusTooManyRequests, "rate_limited", "gateway request limit exceeded")
			return
		}
		next(w, r, record)
	}
}

func (a *App) handleMetadata(w http.ResponseWriter, _ *http.Request, _ APIKeyRecord) {
	cfg, err := a.store.Config()
	if err != nil || cfg.Google == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "not_configured", "Google Ads is not configured")
		return
	}
	metadata := MetadataResponse{
		ProtocolVersion: protocolVersion,
		GatewayID:       cfg.GatewayID,
		DisplayName:     cfg.DisplayName,
		LoginCustomerID: cfg.Google.LoginCustomerID,
		Capabilities: map[string]bool{
			"campaignRead":   true,
			"campaignWrite":  true,
			"campaignCreate": true,
			"genericRest":    true,
			"failClosed":     true,
		},
	}
	visibleAccounts := map[string]bool{}
	for accountID, account := range cfg.Accounts {
		if account.IsManager {
			continue
		}
		if len(allowedCampaignIDs(account, false)) > 0 || account.AllowCreate {
			visibleAccounts[accountID] = true
			parentID := account.ParentID
			for parentID != "" && !visibleAccounts[parentID] {
				visibleAccounts[parentID] = true
				parentID = cfg.Accounts[parentID].ParentID
			}
		}
	}
	for _, accountID := range sortedAccountIDs(cfg.Accounts) {
		account := cfg.Accounts[accountID]
		if !visibleAccounts[accountID] {
			continue
		}
		campaigns := make([]MetadataCampaign, 0)
		for _, campaign := range account.Campaigns {
			if !campaign.Read && !campaign.Write {
				continue
			}
			campaigns = append(campaigns, MetadataCampaign(campaign))
		}
		if !account.IsManager && len(campaigns) == 0 && !account.AllowCreate {
			continue
		}
		sort.Slice(campaigns, func(i, j int) bool { return strings.ToLower(campaigns[i].Name) < strings.ToLower(campaigns[j].Name) })
		metadata.Accounts = append(metadata.Accounts, MetadataAccount{
			CustomerID: account.CustomerID, DisplayName: account.DisplayName,
			CurrencyCode: account.CurrencyCode, TimeZone: account.TimeZone,
			IsManager: account.IsManager, ParentID: account.ParentID,
			AllowCreate: account.AllowCreate, Campaigns: campaigns,
		})
	}
	writeJSON(w, http.StatusOK, metadata)
}

func (a *App) handleProxy(w http.ResponseWriter, r *http.Request, key APIKeyRecord) {
	if mediaType := strings.ToLower(strings.Split(r.Header.Get("Content-Type"), ";")[0]); mediaType != "application/json" {
		writeJSONError(w, http.StatusUnsupportedMediaType, "invalid_content_type", "Content-Type must be application/json")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 20<<20)
	decoder := json.NewDecoder(r.Body)
	decoder.UseNumber()
	decoder.DisallowUnknownFields()
	var proxyRequest ProxyRequest
	if err := decoder.Decode(&proxyRequest); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", "request JSON is invalid")
		return
	}
	if err := ensureJSONEOF(decoder); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", "request must contain one JSON object")
		return
	}
	cfg, err := a.store.Config()
	if err != nil {
		writeJSONError(w, http.StatusServiceUnavailable, "not_configured", "gateway configuration is unavailable")
		return
	}
	decision, err := a.policy.Authorize(r.Context(), cfg, proxyRequest)
	if err != nil {
		_ = a.store.AppendAudit(AuditEvent{Actor: "key:" + key.ID, Action: proxyRequest.Method + " " + proxyRequest.Path, Allowed: false, Status: http.StatusForbidden, Reason: err.Error()})
		writeJSONError(w, http.StatusForbidden, "policy_denied", err.Error())
		return
	}

	requestDigest, err := requestHash(decision.Request)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	idempotencyKey := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if decision.Write {
		if len(idempotencyKey) < 16 || len(idempotencyKey) > 200 {
			writeJSONError(w, http.StatusBadRequest, "idempotency_required", "write requests require an Idempotency-Key containing 16 to 200 characters")
			return
		}
		a.writeMu.Lock()
		defer a.writeMu.Unlock()
		if cached, found, cacheErr := a.store.GetIdempotency(idempotencyKey, requestDigest); cacheErr != nil {
			writeJSONError(w, http.StatusConflict, "idempotency_conflict", cacheErr.Error())
			return
		} else if found {
			if cached.Status == 0 {
				writeJSONError(w, http.StatusConflict, "idempotency_pending", "the earlier request may have reached Google; inspect the campaign before trying a new request")
				return
			}
			writeUpstream(w, UpstreamResponse{Status: cached.Status, ContentType: cached.ContentType, Body: cached.Body})
			return
		}
		if err := a.store.PutIdempotency(IdempotencyRecord{
			Key: idempotencyKey, RequestHash: requestDigest, CreatedAt: time.Now().UTC(),
		}); err != nil {
			writeJSONError(w, http.StatusServiceUnavailable, "idempotency_unavailable", "the gateway could not reserve this write request")
			return
		}
	}

	response, err := a.google.Do(r.Context(), cfg, decision.Request.Method, decision.Request.Path, decision.Request.Body)
	if err != nil {
		_ = a.store.AppendAudit(decisionAudit("key:"+key.ID, decision, http.StatusBadGateway, false, err.Error()))
		writeJSONError(w, http.StatusBadGateway, "upstream_failed", err.Error())
		return
	}
	if err := a.policy.RecordSuccess(cfg, decision, response); err != nil {
		a.logger.Error("failed to record resource ownership", "error", err)
		writeJSONError(w, http.StatusInternalServerError, "ownership_record_failed", "Google accepted the operation but the gateway could not record its ownership; stop and inspect the gateway")
		return
	}
	if decision.Write {
		if err := a.store.PutIdempotency(IdempotencyRecord{
			Key: idempotencyKey, RequestHash: requestDigest, Status: response.Status,
			ContentType: response.ContentType, Body: response.Body, CreatedAt: time.Now().UTC(),
		}); err != nil {
			a.logger.Error("failed to finalize idempotency record", "error", err)
			writeJSONError(w, http.StatusInternalServerError, "idempotency_record_failed", "Google returned a response but the gateway could not finalize the request record; inspect the campaign before retrying")
			return
		}
	}
	_ = a.store.AppendAudit(decisionAudit("key:"+key.ID, decision, response.Status, response.Status >= 200 && response.Status < 300, ""))
	writeUpstream(w, response)
}

func writeUpstream(w http.ResponseWriter, response UpstreamResponse) {
	contentType := response.ContentType
	if contentType == "" {
		contentType = "application/json"
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(response.Status)
	_, _ = w.Write(response.Body)
}

func writeJSONError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{
		"error": map[string]any{
			"code": status, "status": strings.ToUpper(code), "message": message,
		},
	})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); errors.Is(err, io.EOF) {
		return nil
	}
	return errors.New("extra JSON content")
}

func canonicalJSON(value any) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimSpace(buffer.Bytes()), nil
}

func sha256Text(value string) string {
	hash := sha256.Sum256([]byte(value))
	return fmt.Sprintf("%x", hash[:])
}
