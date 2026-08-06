package gateway

import "time"

type PersistentConfig struct {
	GatewayID   string                   `json:"gatewayId"`
	DisplayName string                   `json:"displayName"`
	Google      *GoogleCredential        `json:"google,omitempty"`
	Accounts    map[string]AccountPolicy `json:"accounts"`
	UpdatedAt   time.Time                `json:"updatedAt"`
}

type GoogleCredential struct {
	Mode               string `json:"mode"`
	DeveloperToken     string `json:"developerToken"`
	LoginCustomerID    string `json:"loginCustomerId"`
	OAuthClientID      string `json:"oauthClientId,omitempty"`
	OAuthClientSecret  string `json:"oauthClientSecret,omitempty"`
	OAuthRefreshToken  string `json:"oauthRefreshToken,omitempty"`
	ServiceAccountJSON string `json:"serviceAccountJson,omitempty"`
}

type AccountPolicy struct {
	CustomerID   string                    `json:"customerId"`
	DisplayName  string                    `json:"displayName"`
	CurrencyCode string                    `json:"currencyCode,omitempty"`
	TimeZone     string                    `json:"timeZone,omitempty"`
	IsManager    bool                      `json:"isManager"`
	ParentID     string                    `json:"parentId,omitempty"`
	AllowCreate  bool                      `json:"allowCreate"`
	Campaigns    map[string]CampaignPolicy `json:"campaigns"`
}

type CampaignPolicy struct {
	CampaignID string `json:"campaignId"`
	Name       string `json:"name"`
	Status     string `json:"status,omitempty"`
	Read       bool   `json:"read"`
	Write      bool   `json:"write"`
}

type APIKeyRecord struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Hash      string    `json:"hash"`
	CreatedAt time.Time `json:"createdAt"`
}

type ResourceOwnership struct {
	ResourceName string    `json:"resourceName"`
	CustomerID   string    `json:"customerId"`
	CampaignID   string    `json:"campaignId,omitempty"`
	ResourceType string    `json:"resourceType"`
	CreatedAt    time.Time `json:"createdAt"`
}

type AuditEvent struct {
	ID           string    `json:"id"`
	At           time.Time `json:"at"`
	Actor        string    `json:"actor"`
	Action       string    `json:"action"`
	CustomerID   string    `json:"customerId,omitempty"`
	CampaignIDs  []string  `json:"campaignIds,omitempty"`
	ResourceType string    `json:"resourceType,omitempty"`
	Allowed      bool      `json:"allowed"`
	Status       int       `json:"status"`
	Reason       string    `json:"reason,omitempty"`
}

type IdempotencyRecord struct {
	Key         string    `json:"key"`
	RequestHash string    `json:"requestHash"`
	Status      int       `json:"status"`
	ContentType string    `json:"contentType"`
	Body        []byte    `json:"body"`
	CreatedAt   time.Time `json:"createdAt"`
}

type ProxyRequest struct {
	Method string         `json:"method"`
	Path   string         `json:"path"`
	Body   map[string]any `json:"body,omitempty"`
}

type MetadataResponse struct {
	ProtocolVersion string            `json:"protocolVersion"`
	GatewayID       string            `json:"gatewayId"`
	DisplayName     string            `json:"displayName"`
	LoginCustomerID string            `json:"loginCustomerId"`
	Accounts        []MetadataAccount `json:"accounts"`
	Capabilities    map[string]bool   `json:"capabilities"`
}

type MetadataAccount struct {
	CustomerID   string             `json:"customerId"`
	DisplayName  string             `json:"displayName"`
	CurrencyCode string             `json:"currencyCode,omitempty"`
	TimeZone     string             `json:"timeZone,omitempty"`
	IsManager    bool               `json:"isManager"`
	ParentID     string             `json:"parentCustomerId,omitempty"`
	AllowCreate  bool               `json:"allowCreate"`
	Campaigns    []MetadataCampaign `json:"campaigns"`
}

type MetadataCampaign struct {
	CampaignID string `json:"campaignId"`
	Name       string `json:"name"`
	Status     string `json:"status,omitempty"`
	Read       bool   `json:"read"`
	Write      bool   `json:"write"`
}
