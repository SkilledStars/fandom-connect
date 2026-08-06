package gateway

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func testPolicy(t *testing.T) (*PolicyEngine, *Store, PersistentConfig) {
	t.Helper()
	store := testStore(t)
	cfg, err := store.Config()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Google = &GoogleCredential{Mode: "oauth", DeveloperToken: "unused", LoginCustomerID: "9999999999", OAuthClientID: "unused", OAuthClientSecret: "unused", OAuthRefreshToken: "unused"}
	cfg.Accounts = map[string]AccountPolicy{
		"1234567890": {
			CustomerID: "1234567890", DisplayName: "Advertiser", Campaigns: map[string]CampaignPolicy{
				"111": {CampaignID: "111", Name: "Writable", Read: true, Write: true},
				"222": {CampaignID: "222", Name: "Readable", Read: true},
				"333": {CampaignID: "333", Name: "Blocked"},
			},
		},
	}
	if err := store.SaveConfig(cfg); err != nil {
		t.Fatal(err)
	}
	googleClient := NewGoogleClient(store, "v24")
	return NewPolicyEngine(store, googleClient), store, cfg
}

func TestPolicyRewritesCampaignReads(t *testing.T) {
	policy, _, cfg := testPolicy(t)
	decision, err := policy.Authorize(context.Background(), cfg, ProxyRequest{
		Method: "POST", Path: "/v24/customers/1234567890/googleAds:search",
		Body: map[string]any{"query": `SELECT campaign.id, campaign.name FROM campaign ORDER BY campaign.name`},
	})
	if err != nil {
		t.Fatal(err)
	}
	query := decision.Request.Body["query"].(string)
	if !strings.Contains(query, "campaign.id IN (111, 222)") || strings.Contains(query, "333") {
		t.Fatalf("campaign policy was not applied: %s", query)
	}
}

func TestPolicyRejectsMismatchedGoogleAdsAPIVersion(t *testing.T) {
	policy, _, cfg := testPolicy(t)
	_, err := policy.Authorize(context.Background(), cfg, ProxyRequest{
		Method: "POST", Path: "/v25/customers/1234567890/googleAds:search",
		Body: map[string]any{"query": `SELECT campaign.id FROM campaign`},
	})
	if err == nil || !strings.Contains(err.Error(), "configured for Google Ads API v24") {
		t.Fatalf("mismatched API version was accepted: %v", err)
	}
}

func TestPolicyRejectsAccountWideMetrics(t *testing.T) {
	policy, _, cfg := testPolicy(t)
	_, err := policy.Authorize(context.Background(), cfg, ProxyRequest{
		Method: "POST", Path: "/v24/customers/1234567890/googleAds:search",
		Body: map[string]any{"query": `SELECT customer.id, metrics.cost_micros FROM customer`},
	})
	if err == nil || !strings.Contains(err.Error(), "metrics.cost_micros") {
		t.Fatalf("account-wide metric query was not denied: %v", err)
	}
}

func TestPolicyRejectsMetricsHiddenInCustomerFilter(t *testing.T) {
	policy, _, cfg := testPolicy(t)
	_, err := policy.Authorize(context.Background(), cfg, ProxyRequest{
		Method: "POST", Path: "/v24/customers/1234567890/googleAds:search",
		Body: map[string]any{"query": `SELECT customer.id FROM customer WHERE metrics.cost_micros > 0`},
	})
	if err == nil || !strings.Contains(err.Error(), "metrics.cost_micros") {
		t.Fatalf("metric filter side channel was not denied: %v", err)
	}
}

func TestPolicyAllowsOnlyWritableCampaignMutation(t *testing.T) {
	policy, _, cfg := testPolicy(t)
	allowed := ProxyRequest{Method: "POST", Path: "/v24/customers/1234567890/campaigns:mutate", Body: map[string]any{
		"operations": []any{map[string]any{"update": map[string]any{"resourceName": "customers/1234567890/campaigns/111", "status": "PAUSED"}}},
	}}
	if _, err := policy.Authorize(context.Background(), cfg, allowed); err != nil {
		t.Fatalf("writable campaign was denied: %v", err)
	}
	blocked := allowed
	blocked.Body = map[string]any{"operations": []any{map[string]any{"update": map[string]any{"resourceName": "customers/1234567890/campaigns/222", "status": "PAUSED"}}}}
	if _, err := policy.Authorize(context.Background(), cfg, blocked); err == nil || !strings.Contains(err.Error(), "read-only") {
		t.Fatalf("read-only campaign mutation was accepted: %v", err)
	}
}

func TestCampaignCreationFailsClosedUntilExplicitlyEnabled(t *testing.T) {
	policy, _, cfg := testPolicy(t)
	request := ProxyRequest{Method: "POST", Path: "/v24/customers/1234567890/campaigns:mutate", Body: map[string]any{
		"operations": []any{map[string]any{"create": map[string]any{"name": "New campaign", "status": "PAUSED"}}},
	}}
	if _, err := policy.Authorize(context.Background(), cfg, request); err == nil {
		t.Fatal("campaign creation was accepted without permission")
	}
	account := cfg.Accounts["1234567890"]
	account.AllowCreate = true
	cfg.Accounts["1234567890"] = account
	if _, err := policy.Authorize(context.Background(), cfg, request); err != nil {
		t.Fatalf("explicitly permitted campaign creation was denied: %v", err)
	}
}

func TestOwnedAccountResourceCannotBeGuessed(t *testing.T) {
	policy, store, cfg := testPolicy(t)
	requestFor := func(resource string) ProxyRequest {
		return ProxyRequest{Method: "POST", Path: "/v24/customers/1234567890/customAudiences:mutate", Body: map[string]any{
			"operations": []any{map[string]any{"update": map[string]any{"resourceName": resource, "name": "Updated"}}},
		}}
	}
	resource := "customers/1234567890/customAudiences/987"
	if _, err := policy.Authorize(context.Background(), cfg, requestFor(resource)); err == nil {
		t.Fatal("unowned account-scoped resource was accepted")
	}
	if err := store.PutOwnership(ResourceOwnership{ResourceName: resource, CustomerID: "1234567890", ResourceType: "custom_audience", CampaignID: "111"}); err != nil {
		t.Fatal(err)
	}
	if _, err := policy.Authorize(context.Background(), cfg, requestFor(resource)); err != nil {
		t.Fatalf("owned resource was denied: %v", err)
	}
}

func TestMutationCannotReferenceUnownedAccountResource(t *testing.T) {
	policy, store, cfg := testPolicy(t)
	label := "customers/1234567890/labels/987"
	request := ProxyRequest{Method: "POST", Path: "/v24/customers/1234567890/campaignLabels:mutate", Body: map[string]any{
		"operations": []any{map[string]any{"create": map[string]any{
			"campaign": "customers/1234567890/campaigns/111",
			"label":    label,
		}}},
	}}
	if _, err := policy.Authorize(context.Background(), cfg, request); err == nil || !strings.Contains(err.Error(), "not created by this gateway") {
		t.Fatalf("unowned label reference was accepted: %v", err)
	}
	if err := store.PutOwnership(ResourceOwnership{ResourceName: label, CustomerID: "1234567890", ResourceType: "label"}); err != nil {
		t.Fatal(err)
	}
	if _, err := policy.Authorize(context.Background(), cfg, request); err != nil {
		t.Fatalf("owned label reference was denied: %v", err)
	}
}

func TestGenericMutationCanUseEarlierTemporaryParents(t *testing.T) {
	policy, _, cfg := testPolicy(t)
	request := ProxyRequest{Method: "POST", Path: "/v24/customers/1234567890/googleAds:mutate", Body: map[string]any{
		"mutateOperations": []any{
			map[string]any{"adGroupOperation": map[string]any{"create": map[string]any{
				"resourceName": "customers/1234567890/adGroups/-1",
				"campaign":     "customers/1234567890/campaigns/111",
			}}},
			map[string]any{"adGroupAdOperation": map[string]any{"create": map[string]any{
				"adGroup": "customers/1234567890/adGroups/-1",
				"ad":      map[string]any{"responsiveSearchAd": map[string]any{}},
			}}},
		},
	}}
	if _, err := policy.Authorize(context.Background(), cfg, request); err != nil {
		t.Fatalf("temporary parent relationship was denied: %v", err)
	}
}

func TestMultipleTemporaryCampaignsKeepTheirOwnChildren(t *testing.T) {
	policy, store, cfg := testPolicy(t)
	account := cfg.Accounts["1234567890"]
	account.AllowCreate = true
	cfg.Accounts["1234567890"] = account
	request := ProxyRequest{Method: "POST", Path: "/v24/customers/1234567890/googleAds:mutate", Body: map[string]any{
		"mutateOperations": []any{
			map[string]any{"campaignOperation": map[string]any{"create": map[string]any{"resourceName": "customers/1234567890/campaigns/-1", "name": "One"}}},
			map[string]any{"adGroupOperation": map[string]any{"create": map[string]any{"resourceName": "customers/1234567890/adGroups/-2", "campaign": "customers/1234567890/campaigns/-1"}}},
			map[string]any{"campaignOperation": map[string]any{"create": map[string]any{"resourceName": "customers/1234567890/campaigns/-3", "name": "Two"}}},
			map[string]any{"adGroupOperation": map[string]any{"create": map[string]any{"resourceName": "customers/1234567890/adGroups/-4", "campaign": "customers/1234567890/campaigns/-3"}}},
		},
	}}
	decision, err := policy.Authorize(context.Background(), cfg, request)
	if err != nil {
		t.Fatal(err)
	}
	response, _ := json.Marshal(map[string]any{"results": []any{
		map[string]any{"campaignResult": map[string]any{"resourceName": "customers/1234567890/campaigns/501"}},
		map[string]any{"adGroupResult": map[string]any{"resourceName": "customers/1234567890/adGroups/601"}},
		map[string]any{"campaignResult": map[string]any{"resourceName": "customers/1234567890/campaigns/502"}},
		map[string]any{"adGroupResult": map[string]any{"resourceName": "customers/1234567890/adGroups/602"}},
	}})
	if err := policy.RecordSuccess(cfg, decision, UpstreamResponse{Status: 200, Body: response}); err != nil {
		t.Fatal(err)
	}
	first, ok := store.Ownership("customers/1234567890/adGroups/601")
	if !ok || first.CampaignID != "501" {
		t.Fatalf("first child had wrong owner: %#v", first)
	}
	second, ok := store.Ownership("customers/1234567890/adGroups/602")
	if !ok || second.CampaignID != "502" {
		t.Fatalf("second child had wrong owner: %#v", second)
	}
}

func TestSuccessfulCampaignCreationBecomesOwnedAndAllowed(t *testing.T) {
	policy, store, cfg := testPolicy(t)
	account := cfg.Accounts["1234567890"]
	account.AllowCreate = true
	cfg.Accounts["1234567890"] = account
	request := ProxyRequest{Method: "POST", Path: "/v24/customers/1234567890/campaigns:mutate", Body: map[string]any{
		"operations": []any{map[string]any{"create": map[string]any{"name": "New campaign", "status": "PAUSED"}}},
	}}
	decision, err := policy.Authorize(context.Background(), cfg, request)
	if err != nil {
		t.Fatal(err)
	}
	responseBody, _ := json.Marshal(map[string]any{"results": []any{map[string]any{"resourceName": "customers/1234567890/campaigns/444"}}})
	if err := policy.RecordSuccess(cfg, decision, UpstreamResponse{Status: 200, Body: responseBody}); err != nil {
		t.Fatal(err)
	}
	updated, err := store.Config()
	if err != nil {
		t.Fatal(err)
	}
	created := updated.Accounts["1234567890"].Campaigns["444"]
	if !created.Read || !created.Write || created.Name != "New campaign" {
		t.Fatalf("created campaign policy was not recorded: %#v", created)
	}
}

func TestResultPositionsArePreservedAfterPartialFailure(t *testing.T) {
	payload := map[string]any{"results": []any{
		map[string]any{},
		map[string]any{"resourceName": "customers/1234567890/campaigns/444"},
	}}
	resourceNames := extractResultResourceNames(payload)
	if len(resourceNames) != 2 || resourceNames[0] != "" || resourceNames[1] != "customers/1234567890/campaigns/444" {
		t.Fatalf("result positions were shifted: %#v", resourceNames)
	}
}
