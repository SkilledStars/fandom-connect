package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
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
	googleClient := NewGoogleClient(store, "v23")
	return NewPolicyEngine(store, googleClient), store, cfg
}

func TestPolicyForwardsAlreadyScopedCampaignReadsUnchanged(t *testing.T) {
	policy, _, cfg := testPolicy(t)
	query := `SELECT campaign.id, campaign.name FROM campaign WHERE campaign.id IN (111, 222) ORDER BY campaign.name`
	decision, err := policy.Authorize(context.Background(), cfg, ProxyRequest{
		Method: "POST", Path: "/v23/customers/1234567890/googleAds:search",
		Body: map[string]any{"query": query},
	})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Request.Body["query"] != query {
		t.Fatalf("authorized query was changed: %v", decision.Request.Body["query"])
	}
	if strings.Join(decision.CampaignIDs, ",") != "111,222" {
		t.Fatalf("unexpected authorized campaigns: %#v", decision.CampaignIDs)
	}
}

func TestPolicyScopesUnscopedAndRejectsBlockedCampaignReads(t *testing.T) {
	policy, _, cfg := testPolicy(t)
	unscoped := `SELECT campaign.id FROM campaign ORDER BY campaign.id`
	decision, err := policy.Authorize(context.Background(), cfg, ProxyRequest{
		Method: "POST", Path: "/v23/customers/1234567890/googleAds:search",
		Body: map[string]any{"query": unscoped},
	})
	if err != nil {
		t.Fatalf("safe unscoped campaign query was denied: %v", err)
	}
	rewritten, _ := decision.Request.Body["query"].(string)
	if !strings.Contains(rewritten, "WHERE campaign.id IN (111, 222) ORDER BY") {
		t.Fatalf("gateway campaign boundary was not injected: %s", rewritten)
	}

	blockedQueries := []string{
		`SELECT campaign.id FROM campaign WHERE campaign.id = 333`,
		`SELECT campaign.id FROM campaign WHERE campaign.id IN (111, 333)`,
	}
	for _, query := range blockedQueries {
		_, err := policy.Authorize(context.Background(), cfg, ProxyRequest{
			Method: "POST", Path: "/v23/customers/1234567890/googleAds:search",
			Body: map[string]any{"query": query},
		})
		if err == nil {
			t.Fatalf("unsafe campaign query was accepted: %s", query)
		}
	}
}

func TestAllCampaignAccessAllowsCurrentAndFutureCampaigns(t *testing.T) {
	policy, _, cfg := testPolicy(t)
	account := cfg.Accounts["1234567890"]
	account.AllCampaignsReadWrite = true
	cfg.Accounts[account.CustomerID] = account

	query := `SELECT campaign.id, campaign.name FROM campaign ORDER BY campaign.name`
	decision, err := policy.Authorize(context.Background(), cfg, ProxyRequest{
		Method: "POST", Path: "/v23/customers/1234567890/googleAds:search",
		Body: map[string]any{"query": query},
	})
	if err != nil {
		t.Fatalf("account-wide campaign discovery was denied: %v", err)
	}
	if decision.Request.Body["query"] != query {
		t.Fatalf("account-wide campaign query was changed: %v", decision.Request.Body["query"])
	}

	updateFutureCampaign := ProxyRequest{
		Method: "POST", Path: "/v23/customers/1234567890/campaigns:mutate",
		Body: map[string]any{"operations": []any{map[string]any{
			"update": map[string]any{
				"resourceName": "customers/1234567890/campaigns/999",
				"status":       "PAUSED",
			},
		}}},
	}
	if _, err := policy.Authorize(context.Background(), cfg, updateFutureCampaign); err != nil {
		t.Fatalf("future campaign write was denied: %v", err)
	}

	account.AllCampaignsReadWrite = false
	cfg.Accounts[account.CustomerID] = account
	if _, err := policy.Authorize(context.Background(), cfg, updateFutureCampaign); err == nil {
		t.Fatal("future campaign write remained allowed after full access was revoked")
	}
}

func TestAllCampaignAccessDoesNotExposeUnrelatedAccountResources(t *testing.T) {
	policy, _, cfg := testPolicy(t)
	account := cfg.Accounts["1234567890"]
	account.AllCampaignsReadWrite = true
	cfg.Accounts[account.CustomerID] = account

	_, err := policy.Authorize(context.Background(), cfg, ProxyRequest{
		Method: "POST", Path: "/v23/customers/1234567890/googleAds:search",
		Body: map[string]any{"query": `SELECT recommendation_subscription.type, recommendation_subscription.status FROM recommendation_subscription`},
	})
	if err == nil {
		t.Fatal("all-campaign access exposed an unrelated account-wide resource")
	}
}

func TestPolicyRejectsMismatchedGoogleAdsAPIVersion(t *testing.T) {
	policy, _, cfg := testPolicy(t)
	_, err := policy.Authorize(context.Background(), cfg, ProxyRequest{
		Method: "POST", Path: "/v25/customers/1234567890/googleAds:search",
		Body: map[string]any{"query": `SELECT campaign.id FROM campaign`},
	})
	if err == nil || !strings.Contains(err.Error(), "configured for Google Ads API v23") {
		t.Fatalf("mismatched API version was accepted: %v", err)
	}
}

func TestPolicyRejectsAccountWideMetrics(t *testing.T) {
	policy, _, cfg := testPolicy(t)
	_, err := policy.Authorize(context.Background(), cfg, ProxyRequest{
		Method: "POST", Path: "/v23/customers/1234567890/googleAds:search",
		Body: map[string]any{"query": `SELECT customer.id, metrics.cost_micros FROM customer`},
	})
	if err == nil || !strings.Contains(err.Error(), "metrics.cost_micros") {
		t.Fatalf("account-wide metric query was not denied: %v", err)
	}
}

func TestPolicyAllowsConversionTrackingReadiness(t *testing.T) {
	policy, _, cfg := testPolicy(t)
	query := `SELECT customer.conversion_tracking_setting.conversion_tracking_status FROM customer`
	decision, err := policy.Authorize(context.Background(), cfg, ProxyRequest{
		Method: "POST", Path: "/v23/customers/1234567890/googleAds:search",
		Body: map[string]any{"query": query},
	})
	if err != nil {
		t.Fatalf("conversion-tracking readiness was denied: %v", err)
	}
	if decision.Request.Body["query"] != query {
		t.Fatalf("customer readiness query was unexpectedly rewritten: %v", decision.Request.Body["query"])
	}
}

func TestPolicyRejectsAccountWideRecommendationSubscriptionMetadata(t *testing.T) {
	policy, _, cfg := testPolicy(t)
	query := `SELECT recommendation_subscription.type, recommendation_subscription.status FROM recommendation_subscription`
	_, err := policy.Authorize(context.Background(), cfg, ProxyRequest{
		Method: "POST", Path: "/v23/customers/1234567890/googleAds:search",
		Body: map[string]any{"query": query},
	})
	if err == nil {
		t.Fatal("account-wide recommendation subscription metadata was accepted")
	}
}

func TestCustomerMetadataRequiresSomeExplicitAccountPermission(t *testing.T) {
	policy, _, cfg := testPolicy(t)
	account := cfg.Accounts["1234567890"]
	for id, campaign := range account.Campaigns {
		campaign.Read = false
		campaign.Write = false
		account.Campaigns[id] = campaign
	}
	cfg.Accounts[account.CustomerID] = account
	_, err := policy.Authorize(context.Background(), cfg, ProxyRequest{
		Method: "POST", Path: "/v23/customers/1234567890/googleAds:search",
		Body: map[string]any{"query": `SELECT customer.id FROM customer`},
	})
	if err == nil || !strings.Contains(err.Error(), "requires a permitted campaign") {
		t.Fatalf("customer metadata was exposed without any granted campaign: %v", err)
	}
}

func TestPolicyRejectsZeroCampaignBoundary(t *testing.T) {
	policy, _, cfg := testPolicy(t)
	_, err := policy.Authorize(context.Background(), cfg, ProxyRequest{
		Method: "POST", Path: "/v23/customers/1234567890/googleAds:search",
		Body: map[string]any{"query": `SELECT campaign.id FROM campaign WHERE campaign.id = 0`},
	})
	if err == nil {
		t.Fatal("zero was accepted as a campaign identifier")
	}
}

func TestPublicReferenceQueriesCannotSmuggleUnsafeCustomerFields(t *testing.T) {
	policy, _, cfg := testPolicy(t)
	query := `SELECT detailed_demographic.resource_name, customer.auto_tagging_enabled FROM detailed_demographic`
	if _, err := policy.Authorize(context.Background(), cfg, ProxyRequest{
		Method: "POST", Path: "/v23/customers/1234567890/googleAds:search",
		Body: map[string]any{"query": query},
	}); err == nil || !strings.Contains(err.Error(), "customer.auto_tagging_enabled") {
		t.Fatalf("unsafe customer field was accepted through reference data: %v", err)
	}
}

func TestAccountScopedQueriesRejectCrossResourceFieldSmuggling(t *testing.T) {
	policy, _, cfg := testPolicy(t)
	queries := []string{
		`SELECT campaign.name FROM customer`,
		`SELECT campaign.name, user_interest.resource_name FROM user_interest`,
		`SELECT campaign.name, custom_audience.resource_name FROM custom_audience WHERE custom_audience.resource_name = 'customers/1234567890/customAudiences/701'`,
	}
	for _, query := range queries {
		if _, err := policy.Authorize(context.Background(), cfg, ProxyRequest{
			Method: "POST", Path: "/v23/customers/1234567890/googleAds:search",
			Body: map[string]any{"query": query},
		}); err == nil || !strings.Contains(err.Error(), "not rooted") {
			t.Fatalf("cross-resource account query was not denied: %v\n%s", err, query)
		}
	}
}

func TestPolicyAllowsFandomImportAndDraftQueries(t *testing.T) {
	policy, _, cfg := testPolicy(t)
	queries := []string{
		`SELECT campaign.resource_name, campaign.id, campaign.name, campaign.status, campaign.advertising_channel_type, campaign.advertising_channel_sub_type, campaign.campaign_budget, campaign_budget.resource_name, campaign_budget.amount_micros, campaign_budget.total_amount_micros, campaign.bidding_strategy_type, campaign.serving_status FROM campaign WHERE campaign.id IN (111, 222)`,
		`SELECT ad_group.resource_name, ad_group.id, ad_group.name, ad_group.status, ad_group.type, ad_group.audience_setting.use_audience_grouped, ad_group.optimized_targeting_enabled, ad_group.targeting_setting.target_restrictions, ad_group.cpc_bid_micros, ad_group.cpm_bid_micros, ad_group.cpv_bid_micros, ad_group.effective_cpc_bid_micros, ad_group.campaign FROM ad_group WHERE campaign.id = 111 AND ad_group.status != 'REMOVED'`,
		`SELECT metrics.conversions, metrics.conversions_value FROM campaign WHERE segments.date BETWEEN '2026-07-01' AND '2026-07-31' AND campaign.id IN (111, 222)`,
	}
	for _, query := range queries {
		decision, err := policy.Authorize(context.Background(), cfg, ProxyRequest{
			Method: "POST", Path: "/v23/customers/1234567890/googleAds:search",
			Body: map[string]any{"query": query},
		})
		if err != nil {
			t.Fatalf("Fandom query was denied: %v\n%s", err, query)
		}
		if decision.Request.Body["query"] != query {
			t.Fatalf("Fandom query was changed: %v", decision.Request.Body["query"])
		}
	}
}

func TestPolicyCoversFandomMutationServices(t *testing.T) {
	services := map[string]string{
		"campaigns": "campaign", "campaignBudgets": "campaign_budget",
		"adGroups": "ad_group", "adGroupAds": "ad_group_ad",
		"adGroupCriteria": "ad_group_criterion", "campaignCriteria": "campaign_criterion",
		"customAudiences": "custom_audience", "audiences": "audience",
		"assets": "asset", "labels": "label", "campaignLabels": "campaign_label",
		"adGroupLabels": "ad_group_label", "assetGroups": "asset_group",
		"assetGroupAssets": "asset_group_asset", "campaignAssets": "campaign_asset",
		"adGroupAssets": "ad_group_asset",
	}
	for service, resource := range services {
		if mutateServiceTypes[service] != resource {
			t.Errorf("Fandom mutation service %s is missing or mapped incorrectly", service)
		}
	}
}

func TestUnknownCampaignScopedViewFailsClosed(t *testing.T) {
	policy, _, cfg := testPolicy(t)
	query := `SELECT future_campaign_view.resource_name, metrics.clicks FROM future_campaign_view WHERE campaign.id IN (111, 222)`
	for _, fullAccess := range []bool{false, true} {
		account := cfg.Accounts["1234567890"]
		account.AllCampaignsReadWrite = fullAccess
		cfg.Accounts[account.CustomerID] = account
		_, err := policy.Authorize(context.Background(), cfg, ProxyRequest{
			Method: "POST", Path: "/v23/customers/1234567890/googleAds:search",
			Body: map[string]any{"query": query},
		})
		if err == nil || !strings.Contains(err.Error(), "not supported") {
			t.Fatalf("unknown resource was accepted with fullAccess=%v: %v", fullAccess, err)
		}
	}
}

func TestPolicyScopesFandomCampaignResources(t *testing.T) {
	policy, _, cfg := testPolicy(t)
	queries := []string{
		`SELECT campaign.id, campaign.name FROM campaign WHERE campaign.status != 'REMOVED'`,
		`SELECT ad_group.id, ad_group.name FROM ad_group WHERE ad_group.status != 'REMOVED'`,
		`SELECT geographic_view.country_criterion_id, metrics.impressions FROM geographic_view`,
		`SELECT age_range_view.resource_name, metrics.clicks FROM age_range_view WHERE segments.date DURING LAST_30_DAYS`,
		`SELECT recommendation.resource_name, recommendation.type FROM recommendation`,
	}
	for _, query := range queries {
		decision, err := policy.Authorize(context.Background(), cfg, ProxyRequest{
			Method: "POST", Path: "/v23/customers/1234567890/googleAds:search",
			Body: map[string]any{"query": query},
		})
		if err != nil {
			t.Fatalf("Fandom campaign resource was denied: %v\n%s", err, query)
		}
		rewritten, _ := decision.Request.Body["query"].(string)
		if !strings.Contains(rewritten, "campaign.id IN (111, 222)") {
			t.Fatalf("campaign boundary was not injected: %s", rewritten)
		}
	}
}

func TestPolicyReadsOnlyExactlyRequestedResourcesAttachedToSharedCampaigns(t *testing.T) {
	policy, _, cfg := testPolicy(t)
	googleClient, googleCfg := testGoogleClient(func(request *http.Request) (*http.Response, error) {
		var body map[string]any
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		query := stringValue(body["query"], "")
		if strings.Contains(query, "FROM audience") {
			return jsonResponse(http.StatusOK, `{"results":[]}`), nil
		}
		if !strings.Contains(query, "FROM ad_group_criterion") && !strings.Contains(query, "FROM campaign_criterion") {
			t.Fatalf("unexpected reference verification query: %s", query)
		}
		if strings.Contains(query, "customAudiences/701") {
			if strings.Contains(query, "FROM campaign_criterion") {
				return jsonResponse(http.StatusOK, `{"results":[]}`), nil
			}
			return jsonResponse(http.StatusOK, `{"results":[{"campaign":{"id":"111"},"adGroupCriterion":{"customAudience":{"customAudience":"customers/1234567890/customAudiences/701"}}}]}`), nil
		}
		if strings.Contains(query, "FROM campaign_criterion") {
			return jsonResponse(http.StatusOK, `{"results":[]}`), nil
		}
		return jsonResponse(http.StatusOK, `{"results":[{"campaign":{"id":"333"},"adGroupCriterion":{"customAudience":{"customAudience":"customers/1234567890/customAudiences/703"}}}]}`), nil
	})
	policy.google = googleClient
	cfg.Google = googleCfg.Google

	query := `SELECT custom_audience.resource_name, custom_audience.members FROM custom_audience WHERE custom_audience.resource_name = 'customers/1234567890/customAudiences/701'`
	decision, err := policy.Authorize(context.Background(), cfg, ProxyRequest{
		Method: "POST", Path: "/v23/customers/1234567890/googleAds:search",
		Body: map[string]any{"query": query},
	})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Request.Body["query"] != query {
		t.Fatalf("authorized account resource query was changed: %v", decision.Request.Body["query"])
	}
	if err := policy.ValidateResponse(context.Background(), cfg, decision, UpstreamResponse{
		Status: http.StatusOK,
		Body:   []byte(`{"results":[{"customAudience":{"resourceName":"customers/1234567890/customAudiences/701","members":[]}}]}`),
	}); err != nil {
		t.Fatalf("authorized resource response was denied: %v", err)
	}
	blocked := `SELECT custom_audience.resource_name FROM custom_audience WHERE custom_audience.resource_name = 'customers/1234567890/customAudiences/703'`
	blockedDecision, err := policy.Authorize(context.Background(), cfg, ProxyRequest{
		Method: "POST", Path: "/v23/customers/1234567890/googleAds:search",
		Body: map[string]any{"query": blocked},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := policy.ValidateResponse(context.Background(), cfg, blockedDecision, UpstreamResponse{
		Status: http.StatusOK,
		Body:   []byte(`{"results":[{"customAudience":{"resourceName":"customers/1234567890/customAudiences/703"}}]}`),
	}); err == nil {
		t.Fatal("resource attached only to a blocked campaign was readable")
	}
}

func TestPolicyBatchesOwnedResourceResponseAuthorization(t *testing.T) {
	policy, _, cfg := testPolicy(t)
	first := "customers/1234567890/customAudiences/701"
	second := "customers/1234567890/customAudiences/702"
	adGroupQueries := 0
	campaignQueries := 0
	googleClient, googleCfg := testGoogleClient(func(request *http.Request) (*http.Response, error) {
		var body map[string]any
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		query := stringValue(body["query"], "")
		switch {
		case strings.Contains(query, "FROM ad_group_criterion"):
			adGroupQueries++
			if !strings.Contains(query, first) || !strings.Contains(query, second) {
				t.Fatalf("ownership lookup was not batched: %s", query)
			}
			return jsonResponse(http.StatusOK, `{"results":[
				{"campaign":{"id":"111"},"adGroupCriterion":{"customAudience":{"customAudience":"customers/1234567890/customAudiences/701"}}},
				{"campaign":{"id":"222"},"adGroupCriterion":{"customAudience":{"customAudience":"customers/1234567890/customAudiences/702"}}}
			]}`), nil
		case strings.Contains(query, "FROM campaign_criterion"):
			campaignQueries++
			return jsonResponse(http.StatusOK, `{"results":[]}`), nil
		default:
			t.Fatalf("unexpected batch-authorization query: %s", query)
			return nil, nil
		}
	})
	policy.google = googleClient
	cfg.Google = googleCfg.Google

	query := `SELECT custom_audience.resource_name, custom_audience.name FROM custom_audience WHERE custom_audience.resource_name IN ('customers/1234567890/customAudiences/701', 'customers/1234567890/customAudiences/702')`
	decision, err := policy.Authorize(context.Background(), cfg, ProxyRequest{
		Method: "POST", Path: "/v23/customers/1234567890/googleAds:search",
		Body: map[string]any{"query": query},
	})
	if err != nil {
		t.Fatal(err)
	}
	err = policy.ValidateResponse(context.Background(), cfg, decision, UpstreamResponse{
		Status: http.StatusOK,
		Body: []byte(`{"results":[
			{"customAudience":{"resourceName":"customers/1234567890/customAudiences/701","name":"One"}},
			{"customAudience":{"resourceName":"customers/1234567890/customAudiences/702","name":"Two"}}
		]}`),
	})
	if err != nil {
		t.Fatalf("batched authorized resources were denied: %v", err)
	}
	if adGroupQueries != 1 || campaignQueries != 1 {
		t.Fatalf("expected one ownership lookup per reference type, got ad-group=%d campaign=%d", adGroupQueries, campaignQueries)
	}
}

func TestSharedAccountResourceReadRequiresAtLeastOneReadableAttachment(t *testing.T) {
	policy, store, cfg := testPolicy(t)
	resourceName := "customers/1234567890/customAudiences/701"
	if err := store.PutOwnership(ResourceOwnership{
		ResourceName: resourceName,
		CustomerID:   "1234567890",
		ResourceType: "custom_audience",
		CampaignID:   "111",
	}); err != nil {
		t.Fatal(err)
	}
	googleClient, googleCfg := testGoogleClient(func(request *http.Request) (*http.Response, error) {
		var body map[string]any
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		query := stringValue(body["query"], "")
		switch {
		case strings.Contains(query, "FROM ad_group_criterion"):
			return jsonResponse(http.StatusOK, `{"results":[
				{"campaign":{"id":"111"},"adGroupCriterion":{"customAudience":{"customAudience":"customers/1234567890/customAudiences/701"}}},
				{"campaign":{"id":"333"},"adGroupCriterion":{"customAudience":{"customAudience":"customers/1234567890/customAudiences/701"}}}
			]}`), nil
		case strings.Contains(query, "FROM campaign_criterion"), strings.Contains(query, "FROM audience"):
			return jsonResponse(http.StatusOK, `{"results":[]}`), nil
		default:
			t.Fatalf("unexpected shared-resource query: %s", query)
			return nil, nil
		}
	})
	policy.google = googleClient
	cfg.Google = googleCfg.Google
	decision, err := policy.Authorize(context.Background(), cfg, ProxyRequest{
		Method: "POST", Path: "/v23/customers/1234567890/googleAds:search",
		Body: map[string]any{"query": `SELECT custom_audience.resource_name, custom_audience.members FROM custom_audience WHERE custom_audience.resource_name = 'customers/1234567890/customAudiences/701'`},
	})
	if err != nil {
		t.Fatal(err)
	}
	err = policy.ValidateResponse(context.Background(), cfg, decision, UpstreamResponse{
		Status: http.StatusOK,
		Body:   []byte(`{"results":[{"customAudience":{"resourceName":"customers/1234567890/customAudiences/701","members":[]}}]}`),
	})
	if err != nil {
		t.Fatalf("resource used by an explicitly readable campaign was denied: %v", err)
	}
}

func TestOwnedResourceQueryAddsAuthorizationField(t *testing.T) {
	policy, _, cfg := testPolicy(t)
	query := `SELECT custom_audience.members FROM custom_audience WHERE custom_audience.id = 701`
	decision, err := policy.Authorize(context.Background(), cfg, ProxyRequest{
		Method: "POST", Path: "/v23/customers/1234567890/googleAds:search",
		Body: map[string]any{"query": query, "pageToken": "abc"},
	})
	if err != nil {
		t.Fatalf("exact owned-resource query was denied: %v", err)
	}
	rewritten, _ := decision.Request.Body["query"].(string)
	if !strings.Contains(rewritten, "custom_audience.members, custom_audience.resource_name FROM custom_audience") {
		t.Fatalf("resource authorization field was not injected: %s", rewritten)
	}
	if decision.Request.Body["pageToken"] != "abc" {
		t.Fatalf("unrelated request fields were not preserved: %#v", decision.Request.Body)
	}
}

func TestGeoTargetConstantsAreSafeReferenceData(t *testing.T) {
	policy, _, cfg := testPolicy(t)
	query := `SELECT geo_target_constant.resource_name, geo_target_constant.name, geo_target_constant.country_code FROM geo_target_constant WHERE geo_target_constant.resource_name = 'geoTargetConstants/2840'`
	decision, err := policy.Authorize(context.Background(), cfg, ProxyRequest{
		Method: "POST", Path: "/v23/customers/1234567890/googleAds:search",
		Body: map[string]any{"query": query},
	})
	if err != nil {
		t.Fatalf("public geo target reference was denied: %v", err)
	}
	if decision.Request.Body["query"] != query {
		t.Fatalf("reference query was unexpectedly rewritten: %v", decision.Request.Body["query"])
	}
}

func TestPolicyRejectsAccountResourceListings(t *testing.T) {
	policy, _, cfg := testPolicy(t)
	_, err := policy.Authorize(context.Background(), cfg, ProxyRequest{
		Method: "POST", Path: "/v23/customers/1234567890/googleAds:search",
		Body: map[string]any{"query": `SELECT custom_audience.resource_name, custom_audience.name FROM custom_audience`},
	})
	if err == nil {
		t.Fatal("account-wide custom audience listing was accepted")
	}
}

func TestPolicyAllowsOnlyAuthorizedResourcesThroughExactNameLookup(t *testing.T) {
	policy, store, cfg := testPolicy(t)
	allowedResource := "customers/1234567890/customAudiences/701"
	if err := store.PutOwnership(ResourceOwnership{
		ResourceName: allowedResource,
		CustomerID:   "1234567890",
		ResourceType: "custom_audience",
		CampaignID:   "111",
	}); err != nil {
		t.Fatal(err)
	}
	googleClient, googleCfg := testGoogleClient(func(request *http.Request) (*http.Response, error) {
		var body map[string]any
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		query := stringValue(body["query"], "")
		switch {
		case strings.Contains(query, "FROM custom_audience"):
			return jsonResponse(http.StatusOK, `{"results":[{"customAudience":{"name":"CIA - Allowed","resourceName":"customers/1234567890/customAudiences/701"}}]}`), nil
		case strings.Contains(query, "FROM ad_group_criterion"), strings.Contains(query, "FROM campaign_criterion"), strings.Contains(query, "FROM audience"):
			return jsonResponse(http.StatusOK, `{"results":[]}`), nil
		default:
			t.Fatalf("unexpected policy verification query: %s", query)
			return nil, nil
		}
	})
	policy.google = googleClient
	cfg.Google = googleCfg.Google

	query := `SELECT custom_audience.resource_name, custom_audience.name, custom_audience.members FROM custom_audience WHERE custom_audience.name = 'CIA - Allowed'`
	decision, err := policy.Authorize(context.Background(), cfg, ProxyRequest{
		Method: "POST", Path: "/v23/customers/1234567890/googleAds:search",
		Body: map[string]any{"query": query},
	})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Request.Body["query"] != query {
		t.Fatalf("exact-name query was changed: %v", decision.Request.Body["query"])
	}
	if err := policy.ValidateResponse(context.Background(), cfg, decision, UpstreamResponse{
		Status: http.StatusOK,
		Body:   []byte(`{"results":[{"customAudience":{"name":"CIA - Allowed","resourceName":"customers/1234567890/customAudiences/701"}}]}`),
	}); err != nil {
		t.Fatalf("authorized exact-name result was denied: %v", err)
	}
}

func TestPolicyRejectsExactNameResolvingToUnauthorizedResource(t *testing.T) {
	policy, _, cfg := testPolicy(t)
	googleClient, googleCfg := testGoogleClient(func(request *http.Request) (*http.Response, error) {
		var body map[string]any
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		query := stringValue(body["query"], "")
		if strings.Contains(query, "FROM custom_audience") {
			return jsonResponse(http.StatusOK, `{"results":[{"customAudience":{"name":"CIA - Blocked","resourceName":"customers/1234567890/customAudiences/703"}}]}`), nil
		}
		return jsonResponse(http.StatusOK, `{"results":[]}`), nil
	})
	policy.google = googleClient
	cfg.Google = googleCfg.Google

	decision, err := policy.Authorize(context.Background(), cfg, ProxyRequest{
		Method: "POST", Path: "/v23/customers/1234567890/googleAds:search",
		Body: map[string]any{"query": `SELECT custom_audience.resource_name, custom_audience.name FROM custom_audience WHERE custom_audience.name = 'CIA - Blocked'`},
	})
	if err != nil {
		t.Fatal(err)
	}
	err = policy.ValidateResponse(context.Background(), cfg, decision, UpstreamResponse{
		Status: http.StatusOK,
		Body:   []byte(`{"results":[{"customAudience":{"name":"CIA - Blocked","resourceName":"customers/1234567890/customAudiences/703"}}]}`),
	})
	if err == nil || !strings.Contains(err.Error(), "not attached to a permitted campaign") {
		t.Fatalf("unauthorized exact-name result was accepted: %v", err)
	}
}

func TestPolicyAllowsVerifiedExactNameWithNoCurrentMatch(t *testing.T) {
	policy, _, cfg := testPolicy(t)
	googleClient, googleCfg := testGoogleClient(func(request *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusOK, `{"results":[]}`), nil
	})
	policy.google = googleClient
	cfg.Google = googleCfg.Google
	query := `SELECT audience.resource_name, audience.name FROM audience WHERE audience.name IN ('Audience - DG - New (12345678)')`
	decision, err := policy.Authorize(context.Background(), cfg, ProxyRequest{
		Method: "POST", Path: "/v23/customers/1234567890/googleAds:search",
		Body: map[string]any{"query": query},
	})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Request.Body["query"] != query {
		t.Fatalf("empty exact-name query was changed: %v", decision.Request.Body["query"])
	}
	if err := policy.ValidateResponse(context.Background(), cfg, decision, UpstreamResponse{
		Status: http.StatusOK,
		Body:   []byte(`{"results":[]}`),
	}); err != nil {
		t.Fatalf("empty exact-name response was denied: %v", err)
	}
}

func TestGoogleAdsSearchResponseDecoderFailsClosed(t *testing.T) {
	invalid := []string{
		``,
		`null`,
		`"not an object"`,
		`{} trailing`,
		`[null]`,
		`{"results":{}}`,
		`{"results":[null]}`,
		`[{"results":[]},42]`,
	}
	for _, raw := range invalid {
		if _, err := decodeGoogleAdsSearchRows([]byte(raw)); err == nil {
			t.Fatalf("malformed Google response was accepted: %q", raw)
		}
	}

	valid := []string{
		`{}`,
		`{"results":[]}`,
		`{"results":[{"campaign":{"id":"111"}}]}`,
		`[{"results":[{"campaign":{"id":"111"}}]},{"results":[]}]`,
	}
	for _, raw := range valid {
		if _, err := decodeGoogleAdsSearchRows([]byte(raw)); err != nil {
			t.Fatalf("valid Google response was denied: %v\n%s", err, raw)
		}
	}
}

func TestAccountResourceResponseRejectsInvalidOrUnrequestedRows(t *testing.T) {
	policy, store, cfg := testPolicy(t)
	requested := "customers/1234567890/customAudiences/701"
	if err := store.PutOwnership(ResourceOwnership{
		ResourceName: requested,
		CustomerID:   "1234567890",
		ResourceType: "custom_audience",
		CampaignID:   "111",
	}); err != nil {
		t.Fatal(err)
	}
	googleClient, googleCfg := testGoogleClient(func(request *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusOK, `{"results":[]}`), nil
	})
	policy.google = googleClient
	cfg.Google = googleCfg.Google
	decision, err := policy.Authorize(context.Background(), cfg, ProxyRequest{
		Method: "POST", Path: "/v23/customers/1234567890/googleAds:search",
		Body: map[string]any{"query": `SELECT custom_audience.resource_name FROM custom_audience WHERE custom_audience.resource_name = 'customers/1234567890/customAudiences/701'`},
	})
	if err != nil {
		t.Fatal(err)
	}

	responses := []string{
		`{"results":[{"customAudience":{}}]}`,
		`{"results":[{"customAudience":{"resourceName":"customers/9999999999/customAudiences/701"}}]}`,
		`{"results":[{"customAudience":{"resourceName":"customers/1234567890/customAudiences/702"}}]}`,
		`[{"results":[{"customAudience":{"resourceName":"customers/1234567890/customAudiences/701"}}]},{"results":[{"customAudience":{"resourceName":"customers/1234567890/customAudiences/702"}}]}]`,
	}
	for _, raw := range responses {
		if err := policy.ValidateResponse(context.Background(), cfg, decision, UpstreamResponse{Status: http.StatusOK, Body: []byte(raw)}); err == nil {
			t.Fatalf("unsafe account resource response was accepted: %s", raw)
		}
	}
}

func TestPolicyRejectsEveryNonPostMethodAndUnknownOperation(t *testing.T) {
	policy, _, cfg := testPolicy(t)
	for _, method := range []string{"GET", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"} {
		if _, err := policy.Authorize(context.Background(), cfg, ProxyRequest{
			Method: method, Path: "/v23/customers/1234567890/googleAds:search",
			Body: map[string]any{"query": `SELECT campaign.id FROM campaign WHERE campaign.id = 111`},
		}); err == nil {
			t.Fatalf("%s request was accepted", method)
		}
	}
	if _, err := policy.Authorize(context.Background(), cfg, ProxyRequest{
		Method: "POST", Path: "/v23/customers/1234567890/googleAds:futureOperation", Body: map[string]any{},
	}); err == nil {
		t.Fatal("unknown Google Ads operation was accepted")
	}
}

func TestPolicyRejectsNonExactAndFakeQuotedAccountResourceBoundaries(t *testing.T) {
	policy, _, cfg := testPolicy(t)
	queries := []string{
		`SELECT custom_audience.resource_name FROM custom_audience WHERE custom_audience.name LIKE 'CIA - %'`,
		`SELECT custom_audience.resource_name FROM custom_audience WHERE custom_audience.description = 'custom_audience.resource_name = \'customers/1234567890/customAudiences/701\''`,
	}
	for _, query := range queries {
		_, err := policy.Authorize(context.Background(), cfg, ProxyRequest{
			Method: "POST", Path: "/v23/customers/1234567890/googleAds:search",
			Body: map[string]any{"query": query},
		})
		if err == nil {
			t.Fatalf("non-exact or quoted fake boundary was accepted: %s", query)
		}
	}
}

func TestRevokedCampaignHidesPreviouslyOwnedAccountResources(t *testing.T) {
	policy, store, cfg := testPolicy(t)
	googleClient, googleCfg := testGoogleClient(func(request *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusOK, `{"results":[]}`), nil
	})
	policy.google = googleClient
	cfg.Google = googleCfg.Google
	resourceName := "customers/1234567890/customAudiences/703"
	if err := store.PutOwnership(ResourceOwnership{
		ResourceName: resourceName,
		CustomerID:   "1234567890",
		ResourceType: "custom_audience",
		CampaignID:   "333",
	}); err != nil {
		t.Fatal(err)
	}
	decision, err := policy.Authorize(context.Background(), cfg, ProxyRequest{
		Method: "POST", Path: "/v23/customers/1234567890/googleAds:search",
		Body: map[string]any{"query": `SELECT custom_audience.resource_name FROM custom_audience WHERE custom_audience.resource_name = 'customers/1234567890/customAudiences/703'`},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := policy.ValidateResponse(context.Background(), cfg, decision, UpstreamResponse{
		Status: http.StatusOK,
		Body:   []byte(`{"results":[{"customAudience":{"resourceName":"customers/1234567890/customAudiences/703"}}]}`),
	}); err == nil {
		t.Fatal("resource from a revoked campaign remained readable")
	}
}

func TestUpstreamAuditReasonIncludesGoogleError(t *testing.T) {
	reason := upstreamAuditReason(UpstreamResponse{
		Status: 400,
		Body:   []byte(`{"error":{"message":"Unrecognized field in query"}}`),
	})
	if reason != "Unrecognized field in query" {
		t.Fatalf("unexpected audit reason: %q", reason)
	}
	if allowedReason := upstreamAuditReason(UpstreamResponse{Status: 200}); allowedReason != "" {
		t.Fatalf("successful response recorded a failure reason: %q", allowedReason)
	}
}

func TestPolicyRejectsMetricsHiddenInCustomerFilter(t *testing.T) {
	policy, _, cfg := testPolicy(t)
	_, err := policy.Authorize(context.Background(), cfg, ProxyRequest{
		Method: "POST", Path: "/v23/customers/1234567890/googleAds:search",
		Body: map[string]any{"query": `SELECT customer.id FROM customer WHERE metrics.cost_micros > 0`},
	})
	if err == nil || !strings.Contains(err.Error(), "metrics.cost_micros") {
		t.Fatalf("metric filter side channel was not denied: %v", err)
	}
}

func TestPolicyRejectsMetricsHiddenInOwnedResourceFilter(t *testing.T) {
	policy, _, cfg := testPolicy(t)
	_, err := policy.Authorize(context.Background(), cfg, ProxyRequest{
		Method: "POST", Path: "/v23/customers/1234567890/googleAds:search",
		Body: map[string]any{"query": `SELECT custom_audience.resource_name FROM custom_audience WHERE metrics.cost_micros > 0`},
	})
	if err == nil || !strings.Contains(err.Error(), "account-level resource metrics") {
		t.Fatalf("metric filter side channel was not denied: %v", err)
	}
}

func TestPolicyRejectsUnsafeCustomerFieldOnCampaignQuery(t *testing.T) {
	policy, _, cfg := testPolicy(t)
	_, err := policy.Authorize(context.Background(), cfg, ProxyRequest{
		Method: "POST", Path: "/v23/customers/1234567890/googleAds:search",
		Body: map[string]any{"query": `SELECT campaign.id, customer.auto_tagging_enabled FROM campaign`},
	})
	if err == nil || !strings.Contains(err.Error(), "customer.auto_tagging_enabled") {
		t.Fatalf("unsafe account field was not denied through a campaign query: %v", err)
	}
}

func TestPolicyAllowsOnlyWritableCampaignMutation(t *testing.T) {
	policy, _, cfg := testPolicy(t)
	allowed := ProxyRequest{Method: "POST", Path: "/v23/customers/1234567890/campaigns:mutate", Body: map[string]any{
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

func TestEveryExistingCampaignResourceMutationResolvesAndEnforcesItsCampaign(t *testing.T) {
	policy, _, cfg := testPolicy(t)
	googleClient, googleCfg := testGoogleClient(func(request *http.Request) (*http.Response, error) {
		var body map[string]any
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		query := stringValue(body["query"], "")
		campaignID := "111"
		if strings.Contains(query, "/999") || strings.Contains(query, "campaignCriteria/333~") {
			campaignID = "333"
		}
		resourceName := ""
		resourceKey := ""
		switch {
		case strings.Contains(query, "FROM ad_group_ad "):
			resourceName, resourceKey = resourceNameFromExactFilter(query), "adGroupAd"
		case strings.Contains(query, "FROM ad_group_criterion "):
			resourceName, resourceKey = resourceNameFromExactFilter(query), "adGroupCriterion"
		case strings.Contains(query, "FROM campaign_criterion "):
			resourceName, resourceKey = resourceNameFromExactFilter(query), "campaignCriterion"
		case strings.Contains(query, "FROM asset_group "):
			resourceName, resourceKey = resourceNameFromExactFilter(query), "assetGroup"
		case strings.Contains(query, "FROM ad_group "):
			resourceName, resourceKey = resourceNameFromExactFilter(query), "adGroup"
		default:
			t.Fatalf("unexpected campaign ownership query: %s", query)
		}
		response, err := json.Marshal(map[string]any{"results": []any{map[string]any{
			"campaign":  map[string]any{"id": campaignID},
			resourceKey: map[string]any{"resourceName": resourceName},
		}}})
		if err != nil {
			t.Fatal(err)
		}
		return jsonResponse(http.StatusOK, string(response)), nil
	})
	policy.google = googleClient
	cfg.Google = googleCfg.Google

	tests := []struct {
		name            string
		service         string
		allowedResource string
		blockedResource string
	}{
		{"ad group", "adGroups", "customers/1234567890/adGroups/901", "customers/1234567890/adGroups/999"},
		{"ad group ad", "adGroupAds", "customers/1234567890/adGroupAds/901~902", "customers/1234567890/adGroupAds/999~902"},
		{"ad group criterion", "adGroupCriteria", "customers/1234567890/adGroupCriteria/901~903", "customers/1234567890/adGroupCriteria/999~903"},
		{"campaign criterion", "campaignCriteria", "customers/1234567890/campaignCriteria/111~904", "customers/1234567890/campaignCriteria/333~904"},
		{"asset group", "assetGroups", "customers/1234567890/assetGroups/905", "customers/1234567890/assetGroups/999"},
		{"campaign label", "campaignLabels", "customers/1234567890/campaignLabels/111~906", "customers/1234567890/campaignLabels/333~906"},
		{"campaign asset", "campaignAssets", "customers/1234567890/campaignAssets/111~907~HEADLINE", "customers/1234567890/campaignAssets/333~907~HEADLINE"},
		{"ad group label", "adGroupLabels", "customers/1234567890/adGroupLabels/901~906", "customers/1234567890/adGroupLabels/999~906"},
		{"ad group asset", "adGroupAssets", "customers/1234567890/adGroupAssets/901~907~HEADLINE", "customers/1234567890/adGroupAssets/999~907~HEADLINE"},
		{"asset group asset", "assetGroupAssets", "customers/1234567890/assetGroupAssets/905~907~HEADLINE", "customers/1234567890/assetGroupAssets/999~907~HEADLINE"},
	}

	for _, test := range tests {
		t.Run(test.name+" allowed", func(t *testing.T) {
			request := ProxyRequest{Method: "POST", Path: "/v23/customers/1234567890/" + test.service + ":mutate", Body: map[string]any{
				"operations": []any{map[string]any{"remove": test.allowedResource}},
			}}
			if _, err := policy.Authorize(context.Background(), cfg, request); err != nil {
				t.Fatalf("writable resource was denied: %v", err)
			}
		})
		t.Run(test.name+" blocked", func(t *testing.T) {
			request := ProxyRequest{Method: "POST", Path: "/v23/customers/1234567890/" + test.service + ":mutate", Body: map[string]any{
				"operations": []any{map[string]any{"remove": test.blockedResource}},
			}}
			if _, err := policy.Authorize(context.Background(), cfg, request); err == nil || !strings.Contains(err.Error(), "campaign 333") {
				t.Fatalf("blocked resource was accepted: %v", err)
			}
		})
	}
}

func resourceNameFromExactFilter(query string) string {
	marker := " = '"
	start := strings.LastIndex(query, marker)
	if start < 0 {
		return ""
	}
	value := query[start+len(marker):]
	end := strings.IndexByte(value, '\'')
	if end < 0 {
		return ""
	}
	return value[:end]
}

func TestCampaignResolutionRejectsMismatchedGoogleResource(t *testing.T) {
	policy, _, cfg := testPolicy(t)
	googleClient, googleCfg := testGoogleClient(func(request *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusOK, `{"results":[{"campaign":{"id":"111"},"adGroup":{"resourceName":"customers/1234567890/adGroups/DIFFERENT"}}]}`), nil
	})
	policy.google = googleClient
	cfg.Google = googleCfg.Google
	request := ProxyRequest{Method: "POST", Path: "/v23/customers/1234567890/adGroups:mutate", Body: map[string]any{
		"operations": []any{map[string]any{"remove": "customers/1234567890/adGroups/901"}},
	}}
	if _, err := policy.Authorize(context.Background(), cfg, request); err == nil || !strings.Contains(err.Error(), "mismatched resource") {
		t.Fatalf("mismatched Google ownership result was accepted: %v", err)
	}
}

func TestGenericMutationRejectsWholeBatchWhenAnyOperationIsBlocked(t *testing.T) {
	policy, _, cfg := testPolicy(t)
	request := ProxyRequest{Method: "POST", Path: "/v23/customers/1234567890/googleAds:mutate", Body: map[string]any{
		"mutateOperations": []any{
			map[string]any{"campaignOperation": map[string]any{"update": map[string]any{"resourceName": "customers/1234567890/campaigns/111", "status": "PAUSED"}}},
			map[string]any{"campaignOperation": map[string]any{"update": map[string]any{"resourceName": "customers/1234567890/campaigns/333", "status": "PAUSED"}}},
		},
	}}
	if _, err := policy.Authorize(context.Background(), cfg, request); err == nil || !strings.Contains(err.Error(), "campaign 333") {
		t.Fatalf("mixed generic mutation batch was accepted: %v", err)
	}
}

func TestCampaignCreationFailsClosedUntilExplicitlyEnabled(t *testing.T) {
	policy, _, cfg := testPolicy(t)
	request := ProxyRequest{Method: "POST", Path: "/v23/customers/1234567890/campaigns:mutate", Body: map[string]any{
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

func TestCampaignCreationMustBeExplicitlyPaused(t *testing.T) {
	policy, _, cfg := testPolicy(t)
	account := cfg.Accounts["1234567890"]
	account.AllowCreate = true
	cfg.Accounts["1234567890"] = account

	for _, status := range []any{nil, "ENABLED", "REMOVED"} {
		create := map[string]any{"name": "Unsafe campaign"}
		if status != nil {
			create["status"] = status
		}
		request := ProxyRequest{Method: "POST", Path: "/v23/customers/1234567890/campaigns:mutate", Body: map[string]any{
			"operations": []any{map[string]any{"create": create}},
		}}
		if _, err := policy.Authorize(context.Background(), cfg, request); err == nil || !strings.Contains(err.Error(), "created PAUSED") {
			t.Fatalf("campaign create with status %v was accepted: %v", status, err)
		}
	}
}

func TestCampaignCreationPreflightCannotListUnpermittedCampaignNames(t *testing.T) {
	policy, _, cfg := testPolicy(t)
	account := cfg.Accounts["1234567890"]
	account.AllowCreate = true
	account.Campaigns = map[string]CampaignPolicy{}
	cfg.Accounts["1234567890"] = account

	decision, err := policy.Authorize(context.Background(), cfg, ProxyRequest{
		Method: "POST", Path: "/v23/customers/1234567890/googleAds:search",
		Body: map[string]any{"query": `SELECT campaign.name FROM campaign WHERE campaign.name = 'New draft'`},
	})
	if err != nil {
		t.Fatalf("safe campaign-name preflight was denied: %v", err)
	}
	query, _ := decision.Request.Body["query"].(string)
	if !strings.Contains(query, "campaign.id = 0") {
		t.Fatalf("campaign-name preflight could inspect unpermitted campaigns: %s", query)
	}
}

func TestOwnedAccountResourceCannotBeGuessed(t *testing.T) {
	policy, store, cfg := testPolicy(t)
	googleClient, googleCfg := testGoogleClient(func(request *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusOK, `{"results":[]}`), nil
	})
	policy.google = googleClient
	cfg.Google = googleCfg.Google
	requestFor := func(resource string) ProxyRequest {
		return ProxyRequest{Method: "POST", Path: "/v23/customers/1234567890/customAudiences:mutate", Body: map[string]any{
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

func TestExistingCustomAudienceAttachedOnlyToWritableCampaignCanBeUpdated(t *testing.T) {
	policy, _, cfg := testPolicy(t)
	resource := "customers/1234567890/customAudiences/987"
	googleClient, googleCfg := testGoogleClient(func(request *http.Request) (*http.Response, error) {
		var body map[string]any
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		query := stringValue(body["query"], "")
		if strings.Contains(query, "FROM ad_group_criterion") {
			return jsonResponse(http.StatusOK, `{"results":[{"campaign":{"id":"111"},"adGroupCriterion":{"customAudience":{"customAudience":"customers/1234567890/customAudiences/987"}}}]}`), nil
		}
		return jsonResponse(http.StatusOK, `{"results":[]}`), nil
	})
	policy.google = googleClient
	cfg.Google = googleCfg.Google

	request := ProxyRequest{Method: "POST", Path: "/v23/customers/1234567890/customAudiences:mutate", Body: map[string]any{
		"operations": []any{map[string]any{"update": map[string]any{"resourceName": resource, "name": "Updated"}}},
	}}
	if _, err := policy.Authorize(context.Background(), cfg, request); err != nil {
		t.Fatalf("existing custom audience attached only to a writable campaign was denied: %v", err)
	}
}

func TestExistingSharedReferenceRequiresEveryAttachedCampaignToBeWritable(t *testing.T) {
	policy, _, cfg := testPolicy(t)
	label := "customers/1234567890/labels/987"
	blocked := false
	googleClient, googleCfg := testGoogleClient(func(request *http.Request) (*http.Response, error) {
		var body map[string]any
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		query := stringValue(body["query"], "")
		if strings.Contains(query, "FROM campaign_label") {
			campaignID := "111"
			if blocked {
				campaignID = "222"
			}
			return jsonResponse(http.StatusOK, fmt.Sprintf(`{"results":[{"campaign":{"id":"%s"},"campaignLabel":{"label":"%s"}}]}`, campaignID, label)), nil
		}
		return jsonResponse(http.StatusOK, `{"results":[]}`), nil
	})
	policy.google = googleClient
	cfg.Google = googleCfg.Google
	request := ProxyRequest{Method: "POST", Path: "/v23/customers/1234567890/campaignLabels:mutate", Body: map[string]any{
		"operations": []any{map[string]any{"create": map[string]any{
			"campaign": "customers/1234567890/campaigns/111",
			"label":    label,
		}}},
	}}
	if _, err := policy.Authorize(context.Background(), cfg, request); err != nil {
		t.Fatalf("existing label used only by a writable campaign was denied: %v", err)
	}
	blocked = true
	if _, err := policy.Authorize(context.Background(), cfg, request); err == nil || !strings.Contains(err.Error(), "campaign 222 is read-only") {
		t.Fatalf("label shared with a read-only campaign was accepted: %v", err)
	}
}

func TestLabelChecksAdAndCriterionAttachments(t *testing.T) {
	for _, attachedFrom := range []string{"ad_group_ad_label", "ad_group_criterion_label"} {
		t.Run(attachedFrom, func(t *testing.T) {
			policy, _, cfg := testPolicy(t)
			label := "customers/1234567890/labels/987"
			googleClient, googleCfg := testGoogleClient(func(request *http.Request) (*http.Response, error) {
				var body map[string]any
				if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
					t.Fatal(err)
				}
				query := stringValue(body["query"], "")
				if strings.Contains(query, "FROM "+attachedFrom) {
					resultField := "adGroupAdLabel"
					if attachedFrom == "ad_group_criterion_label" {
						resultField = "adGroupCriterionLabel"
					}
					return jsonResponse(http.StatusOK, fmt.Sprintf(`{"results":[{"campaign":{"id":"222"},"%s":{"label":"%s"}}]}`, resultField, label)), nil
				}
				return jsonResponse(http.StatusOK, `{"results":[]}`), nil
			})
			policy.google = googleClient
			cfg.Google = googleCfg.Google

			request := ProxyRequest{Method: "POST", Path: "/v23/customers/1234567890/campaignLabels:mutate", Body: map[string]any{
				"operations": []any{map[string]any{"create": map[string]any{
					"campaign": "customers/1234567890/campaigns/111",
					"label":    label,
				}}},
			}}
			if _, err := policy.Authorize(context.Background(), cfg, request); err == nil || !strings.Contains(err.Error(), "campaign 222 is read-only") {
				t.Fatalf("label attached through %s was accepted: %v", attachedFrom, err)
			}
		})
	}
}

func TestAssetReadRejectsAccountAndAssetSetLinks(t *testing.T) {
	for _, attachedFrom := range []string{"customer_asset", "asset_set_asset"} {
		t.Run(attachedFrom, func(t *testing.T) {
			policy, _, cfg := testPolicy(t)
			asset := "customers/1234567890/assets/987"
			googleClient, googleCfg := testGoogleClient(func(request *http.Request) (*http.Response, error) {
				var body map[string]any
				if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
					t.Fatal(err)
				}
				query := stringValue(body["query"], "")
				if strings.Contains(query, "FROM "+attachedFrom) {
					resultField := "customerAsset"
					if attachedFrom == "asset_set_asset" {
						resultField = "assetSetAsset"
					}
					return jsonResponse(http.StatusOK, fmt.Sprintf(`{"results":[{"%s":{"asset":"%s"}}]}`, resultField, asset)), nil
				}
				return jsonResponse(http.StatusOK, `{"results":[]}`), nil
			})
			policy.google = googleClient
			cfg.Google = googleCfg.Google

			decision, err := policy.Authorize(context.Background(), cfg, ProxyRequest{
				Method: "POST", Path: "/v23/customers/1234567890/googleAds:search",
				Body: map[string]any{"query": `SELECT asset.resource_name FROM asset WHERE asset.resource_name = 'customers/1234567890/assets/987'`},
			})
			if err != nil {
				t.Fatal(err)
			}
			err = policy.ValidateResponse(context.Background(), cfg, decision, UpstreamResponse{
				Status: http.StatusOK,
				Body:   []byte(`{"results":[{"asset":{"resourceName":"customers/1234567890/assets/987"}}]}`),
			})
			if err == nil || !strings.Contains(err.Error(), "account or shared-set scope") {
				t.Fatalf("asset linked through %s was exposed: %v", attachedFrom, err)
			}
		})
	}
}

func TestOwnedAccountResourceWriteRequiresEveryAttachedCampaign(t *testing.T) {
	policy, store, cfg := testPolicy(t)
	resource := "customers/1234567890/customAudiences/987"
	if err := store.PutOwnership(ResourceOwnership{ResourceName: resource, CustomerID: "1234567890", ResourceType: "custom_audience", CampaignID: "111"}); err != nil {
		t.Fatal(err)
	}
	googleClient, googleCfg := testGoogleClient(func(request *http.Request) (*http.Response, error) {
		var body map[string]any
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		query := stringValue(body["query"], "")
		if strings.Contains(query, "FROM ad_group_criterion") {
			return jsonResponse(http.StatusOK, `{"results":[
				{"campaign":{"id":"111"},"adGroupCriterion":{"customAudience":{"customAudience":"customers/1234567890/customAudiences/987"}}},
				{"campaign":{"id":"222"},"adGroupCriterion":{"customAudience":{"customAudience":"customers/1234567890/customAudiences/987"}}}
			]}`), nil
		}
		return jsonResponse(http.StatusOK, `{"results":[]}`), nil
	})
	policy.google = googleClient
	cfg.Google = googleCfg.Google

	request := ProxyRequest{Method: "POST", Path: "/v23/customers/1234567890/customAudiences:mutate", Body: map[string]any{
		"operations": []any{map[string]any{"update": map[string]any{"resourceName": resource, "name": "Updated"}}},
	}}
	_, err := policy.Authorize(context.Background(), cfg, request)
	if err == nil || !strings.Contains(err.Error(), "campaign 222 is read-only") {
		t.Fatalf("shared resource update was not denied for its read-only campaign: %v", err)
	}
}

func TestCustomAudienceWriteChecksCampaignLevelAndTransitiveAudienceAttachments(t *testing.T) {
	policy, store, cfg := testPolicy(t)
	resource := "customers/1234567890/customAudiences/987"
	if err := store.PutOwnership(ResourceOwnership{ResourceName: resource, CustomerID: "1234567890", ResourceType: "custom_audience", CampaignID: "111"}); err != nil {
		t.Fatal(err)
	}
	googleClient, googleCfg := testGoogleClient(func(request *http.Request) (*http.Response, error) {
		var body map[string]any
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		query := stringValue(body["query"], "")
		switch {
		case strings.Contains(query, "FROM ad_group_criterion") && strings.Contains(query, "custom_audience"):
			return jsonResponse(http.StatusOK, `{"results":[]}`), nil
		case strings.Contains(query, "FROM campaign_criterion"):
			return jsonResponse(http.StatusOK, `{"results":[{"campaign":{"id":"111"},"campaignCriterion":{"customAudience":{"customAudience":"customers/1234567890/customAudiences/987"}}}]}`), nil
		case strings.Contains(query, "FROM audience") && strings.Contains(query, "dimensions.audience_segments"):
			return jsonResponse(http.StatusOK, `{"results":[{"audience":{"resourceName":"customers/1234567890/audiences/888"}}]}`), nil
		case strings.Contains(query, "FROM ad_group_criterion") && strings.Contains(query, "audience.audience"):
			return jsonResponse(http.StatusOK, `{"results":[]}`), nil
		case strings.Contains(query, "FROM asset_group_signal"):
			return jsonResponse(http.StatusOK, `{"results":[{"campaign":{"id":"333"},"assetGroupSignal":{"audience":{"audience":"customers/1234567890/audiences/888"}}}]}`), nil
		case strings.Contains(query, "SELECT audience.resource_name, audience.asset_group"):
			return jsonResponse(http.StatusOK, `{"results":[{"audience":{"resourceName":"customers/1234567890/audiences/888"}}]}`), nil
		default:
			t.Fatalf("unexpected ownership query: %s", query)
			return nil, nil
		}
	})
	policy.google = googleClient
	cfg.Google = googleCfg.Google

	request := ProxyRequest{Method: "POST", Path: "/v23/customers/1234567890/customAudiences:mutate", Body: map[string]any{
		"operations": []any{map[string]any{"update": map[string]any{"resourceName": resource, "name": "Updated"}}},
	}}
	_, err := policy.Authorize(context.Background(), cfg, request)
	if err == nil || !strings.Contains(err.Error(), "campaign 333 is read-only") {
		t.Fatalf("transitively shared custom audience update was not denied: %v", err)
	}
}

func TestCampaignBudgetWriteIgnoresStaleOwnershipAndChecksEveryLiveCampaign(t *testing.T) {
	policy, store, cfg := testPolicy(t)
	resource := "customers/1234567890/campaignBudgets/987"
	if err := store.PutOwnership(ResourceOwnership{ResourceName: resource, CustomerID: "1234567890", ResourceType: "campaign_budget", CampaignID: "111"}); err != nil {
		t.Fatal(err)
	}
	googleClient, googleCfg := testGoogleClient(func(request *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusOK, `{"results":[
			{"campaign":{"id":"111","campaignBudget":"customers/1234567890/campaignBudgets/987"}},
			{"campaign":{"id":"222","campaignBudget":"customers/1234567890/campaignBudgets/987"}}
		]}`), nil
	})
	policy.google = googleClient
	cfg.Google = googleCfg.Google
	request := ProxyRequest{Method: "POST", Path: "/v23/customers/1234567890/campaignBudgets:mutate", Body: map[string]any{
		"operations": []any{map[string]any{"update": map[string]any{"resourceName": resource, "amountMicros": json.Number("1000000")}}},
	}}
	_, err := policy.Authorize(context.Background(), cfg, request)
	if err == nil || !strings.Contains(err.Error(), "campaign 222 is read-only") {
		t.Fatalf("shared campaign budget update was not denied: %v", err)
	}
}

func TestSharedAssetAndLabelUpdatesAreAlwaysDenied(t *testing.T) {
	policy, store, cfg := testPolicy(t)
	resources := []struct {
		service, resourceType, resourceName string
	}{
		{"assets", "asset", "customers/1234567890/assets/901"},
		{"labels", "label", "customers/1234567890/labels/902"},
	}
	for _, test := range resources {
		if err := store.PutOwnership(ResourceOwnership{ResourceName: test.resourceName, CustomerID: "1234567890", ResourceType: test.resourceType, CampaignID: "111"}); err != nil {
			t.Fatal(err)
		}
		request := ProxyRequest{Method: "POST", Path: "/v23/customers/1234567890/" + test.service + ":mutate", Body: map[string]any{
			"operations": []any{map[string]any{"update": map[string]any{"resourceName": test.resourceName, "name": "Changed"}}},
		}}
		if _, err := policy.Authorize(context.Background(), cfg, request); err == nil || !strings.Contains(err.Error(), "shared account resource") {
			t.Fatalf("%s update was not denied: %v", test.resourceType, err)
		}
	}
}

func TestMutationResourceNamesAndTemporaryIDsAreStrict(t *testing.T) {
	policy, _, cfg := testPolicy(t)
	requests := []ProxyRequest{
		{Method: "POST", Path: "/v23/customers/1234567890/googleAds:mutate", Body: map[string]any{"mutateOperations": []any{
			map[string]any{"adGroupOperation": map[string]any{"create": map[string]any{"resourceName": "customers/1234567890/campaigns/-1", "campaign": "customers/1234567890/campaigns/111"}}},
		}}},
		{Method: "POST", Path: "/v23/customers/1234567890/googleAds:mutate", Body: map[string]any{"mutateOperations": []any{
			map[string]any{"adGroupOperation": map[string]any{"create": map[string]any{"resourceName": "customers/9999999999/adGroups/-1", "campaign": "customers/1234567890/campaigns/111"}}},
		}}},
		{Method: "POST", Path: "/v23/customers/1234567890/googleAds:mutate", Body: map[string]any{"mutateOperations": []any{
			map[string]any{"adGroupOperation": map[string]any{"create": map[string]any{"resourceName": "customers/1234567890/adGroups/1", "campaign": "customers/1234567890/campaigns/111"}}},
		}}},
		{Method: "POST", Path: "/v23/customers/1234567890/googleAds:mutate", Body: map[string]any{"mutateOperations": []any{
			map[string]any{"adGroupOperation": map[string]any{"create": map[string]any{"resourceName": "customers/1234567890/adGroups/-1", "campaign": "customers/1234567890/campaigns/111"}}},
			map[string]any{"adGroupOperation": map[string]any{"create": map[string]any{"resourceName": "customers/1234567890/adGroups/-1", "campaign": "customers/1234567890/campaigns/111"}}},
		}}},
	}
	for _, request := range requests {
		if _, err := policy.Authorize(context.Background(), cfg, request); err == nil {
			t.Fatalf("invalid mutation resource identity was accepted: %#v", request.Body)
		}
	}
}

func TestValidCompositeTemporaryAndAssetLinkResourceNamesAreAccepted(t *testing.T) {
	policy, store, cfg := testPolicy(t)
	parent := "customers/1234567890/adGroups/777"
	if err := store.PutOwnership(ResourceOwnership{ResourceName: parent, CustomerID: "1234567890", ResourceType: "ad_group", CampaignID: "111"}); err != nil {
		t.Fatal(err)
	}
	criterionCreate := ProxyRequest{Method: "POST", Path: "/v23/customers/1234567890/googleAds:mutate", Body: map[string]any{
		"mutateOperations": []any{
			map[string]any{"adGroupCriterionOperation": map[string]any{"create": map[string]any{
				"resourceName": "customers/1234567890/adGroupCriteria/777~-1",
				"adGroup":      parent,
				"keyword":      map[string]any{"text": "safe"},
			}}},
		},
	}}
	if _, err := policy.Authorize(context.Background(), cfg, criterionCreate); err != nil {
		t.Fatalf("valid composite temporary resource was denied: %v", err)
	}

	assetLinkRemove := ProxyRequest{Method: "POST", Path: "/v23/customers/1234567890/campaignAssets:mutate", Body: map[string]any{
		"operations": []any{map[string]any{"remove": "customers/1234567890/campaignAssets/111~901~HEADLINE"}},
	}}
	if _, err := policy.Authorize(context.Background(), cfg, assetLinkRemove); err != nil {
		t.Fatalf("valid campaign asset link resource was denied: %v", err)
	}
}

func TestParentOwnershipRecordMustMatchExpectedResourceType(t *testing.T) {
	policy, store, cfg := testPolicy(t)
	parent := "customers/1234567890/adGroups/777"
	if err := store.PutOwnership(ResourceOwnership{ResourceName: parent, CustomerID: "1234567890", ResourceType: "asset", CampaignID: "111"}); err != nil {
		t.Fatal(err)
	}
	request := ProxyRequest{Method: "POST", Path: "/v23/customers/1234567890/adGroupAds:mutate", Body: map[string]any{
		"operations": []any{map[string]any{"create": map[string]any{"adGroup": parent, "ad": map[string]any{}}}},
	}}
	if _, err := policy.Authorize(context.Background(), cfg, request); err == nil || !strings.Contains(err.Error(), "ownership type") {
		t.Fatalf("mismatched parent ownership type was accepted: %v", err)
	}
}

func TestMutationCannotReferenceUnownedAccountResource(t *testing.T) {
	policy, store, cfg := testPolicy(t)
	googleClient, googleCfg := testGoogleClient(func(request *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusOK, `{"results":[]}`), nil
	})
	policy.google = googleClient
	cfg.Google = googleCfg.Google
	label := "customers/1234567890/labels/987"
	request := ProxyRequest{Method: "POST", Path: "/v23/customers/1234567890/campaignLabels:mutate", Body: map[string]any{
		"operations": []any{map[string]any{"create": map[string]any{
			"campaign": "customers/1234567890/campaigns/111",
			"label":    label,
		}}},
	}}
	if _, err := policy.Authorize(context.Background(), cfg, request); err == nil || !strings.Contains(err.Error(), "was not created by this gateway") {
		t.Fatalf("unowned label reference was accepted: %v", err)
	}
	if err := store.PutOwnership(ResourceOwnership{ResourceName: label, CustomerID: "1234567890", ResourceType: "label"}); err != nil {
		t.Fatal(err)
	}
	if _, err := policy.Authorize(context.Background(), cfg, request); err != nil {
		t.Fatalf("owned label reference was denied: %v", err)
	}
}

func TestMutationCannotReferenceUnknownCustomerResource(t *testing.T) {
	policy, _, cfg := testPolicy(t)
	request := ProxyRequest{Method: "POST", Path: "/v23/customers/1234567890/campaigns:mutate", Body: map[string]any{
		"operations": []any{map[string]any{"update": map[string]any{
			"resourceName":         "customers/1234567890/campaigns/111",
			"futureSharedResource": "customers/1234567890/futureSharedResources/987",
		}}},
	}}
	if _, err := policy.Authorize(context.Background(), cfg, request); err == nil || !strings.Contains(err.Error(), "is not supported") {
		t.Fatalf("unknown customer resource reference was accepted: %v", err)
	}
}

func TestMutationCannotReferenceResourceOwnedByBlockedCampaign(t *testing.T) {
	policy, store, cfg := testPolicy(t)
	blockedAdGroup := "customers/1234567890/adGroups/777"
	if err := store.PutOwnership(ResourceOwnership{ResourceName: blockedAdGroup, CustomerID: "1234567890", ResourceType: "ad_group", CampaignID: "222"}); err != nil {
		t.Fatal(err)
	}
	request := ProxyRequest{Method: "POST", Path: "/v23/customers/1234567890/campaigns:mutate", Body: map[string]any{
		"operations": []any{map[string]any{"update": map[string]any{
			"resourceName": "customers/1234567890/campaigns/111",
			"futureParent": blockedAdGroup,
		}}},
	}}
	if _, err := policy.Authorize(context.Background(), cfg, request); err == nil || !strings.Contains(err.Error(), "222") {
		t.Fatalf("blocked campaign resource reference was accepted: %v", err)
	}
}

func TestGenericMutationCanUseEarlierTemporaryParents(t *testing.T) {
	policy, _, cfg := testPolicy(t)
	request := ProxyRequest{Method: "POST", Path: "/v23/customers/1234567890/googleAds:mutate", Body: map[string]any{
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

func TestWritableCampaignCanUseImmutableGoogleTargetingCatalogs(t *testing.T) {
	policy, store, cfg := testPolicy(t)
	adGroup := "customers/1234567890/adGroups/777"
	if err := store.PutOwnership(ResourceOwnership{ResourceName: adGroup, CustomerID: "1234567890", ResourceType: "ad_group", CampaignID: "111"}); err != nil {
		t.Fatal(err)
	}

	requests := []ProxyRequest{
		{Method: "POST", Path: "/v23/customers/1234567890/adGroupCriteria:mutate", Body: map[string]any{
			"operations": []any{map[string]any{"create": map[string]any{
				"adGroup":      adGroup,
				"userInterest": map[string]any{"userInterestCategory": "customers/1234567890/userInterests/501"},
			}}},
		}},
		{Method: "POST", Path: "/v23/customers/1234567890/campaignCriteria:mutate", Body: map[string]any{
			"operations": []any{map[string]any{"create": map[string]any{
				"campaign":  "customers/1234567890/campaigns/111",
				"lifeEvent": map[string]any{"lifeEvent": "customers/1234567890/lifeEvents/601"},
			}}},
		}},
	}
	for _, request := range requests {
		if _, err := policy.Authorize(context.Background(), cfg, request); err != nil {
			t.Fatalf("immutable Google targeting catalog reference was denied: %v", err)
		}
	}
}

func TestEverySupportedMutationServiceRoutesThroughCampaignPolicy(t *testing.T) {
	policy, store, cfg := testPolicy(t)
	googleClient, googleCfg := testGoogleClient(func(request *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusOK, `{"results":[]}`), nil
	})
	policy.google = googleClient
	cfg.Google = googleCfg.Google
	account := cfg.Accounts["1234567890"]
	account.AllowCreate = true
	cfg.Accounts[account.CustomerID] = account

	owned := []ResourceOwnership{
		{ResourceName: "customers/1234567890/adGroups/777", CustomerID: "1234567890", ResourceType: "ad_group", CampaignID: "111"},
		{ResourceName: "customers/1234567890/assetGroups/888", CustomerID: "1234567890", ResourceType: "asset_group", CampaignID: "111"},
		{ResourceName: "customers/1234567890/assets/901", CustomerID: "1234567890", ResourceType: "asset", CampaignID: "111"},
		{ResourceName: "customers/1234567890/labels/902", CustomerID: "1234567890", ResourceType: "label", CampaignID: "111"},
	}
	for _, owner := range owned {
		if err := store.PutOwnership(owner); err != nil {
			t.Fatal(err)
		}
	}

	tests := []struct {
		service string
		create  map[string]any
	}{
		{"campaigns", map[string]any{"name": "Campaign", "status": "PAUSED"}},
		{"campaignBudgets", map[string]any{"name": "Budget"}},
		{"adGroups", map[string]any{"campaign": "customers/1234567890/campaigns/111"}},
		{"adGroupAds", map[string]any{"adGroup": "customers/1234567890/adGroups/777"}},
		{"adGroupCriteria", map[string]any{"adGroup": "customers/1234567890/adGroups/777"}},
		{"campaignCriteria", map[string]any{"campaign": "customers/1234567890/campaigns/111"}},
		{"customAudiences", map[string]any{"name": "Custom audience"}},
		{"audiences", map[string]any{"name": "Audience"}},
		{"assets", map[string]any{"name": "Asset"}},
		{"labels", map[string]any{"name": "Label"}},
		{"campaignLabels", map[string]any{"campaign": "customers/1234567890/campaigns/111", "label": "customers/1234567890/labels/902"}},
		{"adGroupLabels", map[string]any{"adGroup": "customers/1234567890/adGroups/777", "label": "customers/1234567890/labels/902"}},
		{"assetGroups", map[string]any{"campaign": "customers/1234567890/campaigns/111"}},
		{"assetGroupAssets", map[string]any{"assetGroup": "customers/1234567890/assetGroups/888", "asset": "customers/1234567890/assets/901"}},
		{"campaignAssets", map[string]any{"campaign": "customers/1234567890/campaigns/111", "asset": "customers/1234567890/assets/901"}},
		{"adGroupAssets", map[string]any{"adGroup": "customers/1234567890/adGroups/777", "asset": "customers/1234567890/assets/901"}},
	}

	for _, test := range tests {
		t.Run(test.service, func(t *testing.T) {
			request := ProxyRequest{Method: "POST", Path: "/v23/customers/1234567890/" + test.service + ":mutate", Body: map[string]any{
				"operations": []any{map[string]any{"create": test.create}},
			}}
			decision, err := policy.Authorize(context.Background(), cfg, request)
			if err != nil {
				t.Fatalf("supported Fandom mutation service was denied: %v", err)
			}
			if !decision.Write || len(decision.Mutations) != 1 {
				t.Fatalf("mutation service did not produce one write decision: %#v", decision)
			}
		})
	}
}

func TestGoogleTargetingCatalogReferencesRemainCustomerBoundAndStrict(t *testing.T) {
	policy, store, cfg := testPolicy(t)
	adGroup := "customers/1234567890/adGroups/777"
	if err := store.PutOwnership(ResourceOwnership{ResourceName: adGroup, CustomerID: "1234567890", ResourceType: "ad_group", CampaignID: "111"}); err != nil {
		t.Fatal(err)
	}
	for _, resourceName := range []string{
		"customers/9999999999/userInterests/501",
		"customers/1234567890/userInterests/-1",
		"customers/1234567890/userInterests/0",
		"customers/1234567890/userInterests/501~502",
	} {
		request := ProxyRequest{Method: "POST", Path: "/v23/customers/1234567890/adGroupCriteria:mutate", Body: map[string]any{
			"operations": []any{map[string]any{"create": map[string]any{
				"adGroup":      adGroup,
				"userInterest": map[string]any{"userInterestCategory": resourceName},
			}}},
		}}
		if _, err := policy.Authorize(context.Background(), cfg, request); err == nil {
			t.Fatalf("unsafe targeting catalog resource was accepted: %s", resourceName)
		}
	}
}

func TestAccountWideRecommendationSubscriptionWritesRemainDenied(t *testing.T) {
	policy, _, cfg := testPolicy(t)
	request := ProxyRequest{Method: "POST", Path: "/v23/customers/1234567890/googleAds:mutate", Body: map[string]any{
		"mutateOperations": []any{map[string]any{
			"recommendationSubscriptionOperation": map[string]any{"update": map[string]any{
				"resourceName": "customers/1234567890/recommendationSubscriptions/CAMPAIGN_BUDGET",
				"status":       "PAUSED",
			}},
		}},
	}}
	if _, err := policy.Authorize(context.Background(), cfg, request); err == nil {
		t.Fatal("account-wide recommendation subscription write was accepted")
	}
}

func TestMultipleTemporaryCampaignsKeepTheirOwnChildren(t *testing.T) {
	policy, store, cfg := testPolicy(t)
	account := cfg.Accounts["1234567890"]
	account.AllowCreate = true
	cfg.Accounts["1234567890"] = account
	request := ProxyRequest{Method: "POST", Path: "/v23/customers/1234567890/googleAds:mutate", Body: map[string]any{
		"mutateOperations": []any{
			map[string]any{"campaignOperation": map[string]any{"create": map[string]any{"resourceName": "customers/1234567890/campaigns/-1", "name": "One", "status": "PAUSED"}}},
			map[string]any{"adGroupOperation": map[string]any{"create": map[string]any{"resourceName": "customers/1234567890/adGroups/-2", "campaign": "customers/1234567890/campaigns/-1"}}},
			map[string]any{"campaignOperation": map[string]any{"create": map[string]any{"resourceName": "customers/1234567890/campaigns/-3", "name": "Two", "status": "PAUSED"}}},
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
	request := ProxyRequest{Method: "POST", Path: "/v23/customers/1234567890/campaigns:mutate", Body: map[string]any{
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

func TestGenericMutationResultPositionsArePreserved(t *testing.T) {
	payload := map[string]any{"mutateOperationResponses": []any{
		map[string]any{"campaignBudgetResult": map[string]any{"resourceName": "customers/1234567890/campaignBudgets/701"}},
		map[string]any{},
		map[string]any{"campaignResult": map[string]any{"resourceName": "customers/1234567890/campaigns/702"}},
	}}
	resourceNames := extractResultResourceNames(payload)
	if len(resourceNames) != 3 ||
		resourceNames[0] != "customers/1234567890/campaignBudgets/701" ||
		resourceNames[1] != "" ||
		resourceNames[2] != "customers/1234567890/campaigns/702" {
		t.Fatalf("generic result positions were not preserved: %#v", resourceNames)
	}
}

func TestGenericCampaignCreationBecomesOwnedAndAllowed(t *testing.T) {
	policy, store, cfg := testPolicy(t)
	account := cfg.Accounts["1234567890"]
	account.AllowCreate = true
	cfg.Accounts["1234567890"] = account
	request := ProxyRequest{Method: "POST", Path: "/v23/customers/1234567890/googleAds:mutate", Body: map[string]any{
		"mutateOperations": []any{
			map[string]any{"campaignBudgetOperation": map[string]any{"create": map[string]any{
				"resourceName": "customers/1234567890/campaignBudgets/-1",
				"name":         "Atomic budget",
			}}},
			map[string]any{"campaignOperation": map[string]any{"create": map[string]any{
				"resourceName":   "customers/1234567890/campaigns/-2",
				"name":           "Atomic campaign",
				"status":         "PAUSED",
				"campaignBudget": "customers/1234567890/campaignBudgets/-1",
			}}},
		},
	}}
	decision, err := policy.Authorize(context.Background(), cfg, request)
	if err != nil {
		t.Fatal(err)
	}
	responseBody, _ := json.Marshal(map[string]any{"mutateOperationResponses": []any{
		map[string]any{"campaignBudgetResult": map[string]any{"resourceName": "customers/1234567890/campaignBudgets/701"}},
		map[string]any{"campaignResult": map[string]any{"resourceName": "customers/1234567890/campaigns/702"}},
	}})
	if err := policy.RecordSuccess(cfg, decision, UpstreamResponse{Status: 200, Body: responseBody}); err != nil {
		t.Fatal(err)
	}
	updated, err := store.Config()
	if err != nil {
		t.Fatal(err)
	}
	created := updated.Accounts["1234567890"].Campaigns["702"]
	if !created.Read || !created.Write || created.Name != "Atomic campaign" {
		t.Fatalf("generic campaign creation was not recorded: %#v", created)
	}
	budget, ok := store.Ownership("customers/1234567890/campaignBudgets/701")
	if !ok || budget.CampaignID != "702" {
		t.Fatalf("generic campaign budget ownership was not linked: %#v", budget)
	}
}

func TestValidateOnlyMutationDoesNotRecordPhantomResources(t *testing.T) {
	policy, store, cfg := testPolicy(t)
	account := cfg.Accounts["1234567890"]
	account.AllowCreate = true
	cfg.Accounts["1234567890"] = account
	request := ProxyRequest{Method: "POST", Path: "/v23/customers/1234567890/googleAds:mutate", Body: map[string]any{
		"validateOnly": true,
		"mutateOperations": []any{
			map[string]any{"campaignOperation": map[string]any{"create": map[string]any{
				"resourceName": "customers/1234567890/campaigns/-1",
				"name":         "Validation only",
				"status":       "PAUSED",
			}}},
		},
	}}
	decision, err := policy.Authorize(context.Background(), cfg, request)
	if err != nil {
		t.Fatal(err)
	}
	responseBody, _ := json.Marshal(map[string]any{"mutateOperationResponses": []any{
		map[string]any{"campaignResult": map[string]any{"resourceName": "customers/1234567890/campaigns/999"}},
	}})
	if err := policy.RecordSuccess(cfg, decision, UpstreamResponse{Status: 200, Body: responseBody}); err != nil {
		t.Fatal(err)
	}
	updated, err := store.Config()
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := updated.Accounts["1234567890"].Campaigns["999"]; exists {
		t.Fatal("validate-only campaign was recorded as a real campaign")
	}
	if _, exists := store.Ownership("customers/1234567890/campaigns/999"); exists {
		t.Fatal("validate-only campaign received an ownership record")
	}
}

func TestSuccessfulCreateRequiresValidMatchingGoogleResourceName(t *testing.T) {
	policy, _, cfg := testPolicy(t)
	account := cfg.Accounts["1234567890"]
	account.AllowCreate = true
	cfg.Accounts["1234567890"] = account
	request := ProxyRequest{Method: "POST", Path: "/v23/customers/1234567890/campaigns:mutate", Body: map[string]any{
		"operations": []any{map[string]any{"create": map[string]any{"name": "New campaign", "status": "PAUSED"}}},
	}}
	decision, err := policy.Authorize(context.Background(), cfg, request)
	if err != nil {
		t.Fatal(err)
	}
	responses := []string{
		`not-json`,
		`{}`,
		`{"results":[{}]}`,
		`{"results":[{"resourceName":"customers/9999999999/campaigns/444"}]}`,
		`{"results":[{"resourceName":"customers/1234567890/adGroups/444"}]}`,
		`{"results":[{"resourceName":"customers/1234567890/campaigns/0"}]}`,
	}
	for _, raw := range responses {
		if err := policy.RecordSuccess(cfg, decision, UpstreamResponse{Status: http.StatusOK, Body: []byte(raw)}); err == nil {
			t.Fatalf("unsafe mutation success response was accepted: %s", raw)
		}
	}
}

func TestPartialFailureMayOmitFailedCreateResourceName(t *testing.T) {
	policy, _, cfg := testPolicy(t)
	account := cfg.Accounts["1234567890"]
	account.AllowCreate = true
	cfg.Accounts["1234567890"] = account
	request := ProxyRequest{Method: "POST", Path: "/v23/customers/1234567890/campaigns:mutate", Body: map[string]any{
		"partialFailure": true,
		"operations":     []any{map[string]any{"create": map[string]any{"name": "Rejected campaign", "status": "PAUSED"}}},
	}}
	decision, err := policy.Authorize(context.Background(), cfg, request)
	if err != nil {
		t.Fatal(err)
	}
	response := UpstreamResponse{Status: http.StatusOK, Body: []byte(`{"partialFailureError":{"code":3,"message":"invalid"},"results":[{}]}`)}
	if err := policy.RecordSuccess(cfg, decision, response); err != nil {
		t.Fatalf("partial-failure response was rejected: %v", err)
	}
	malformed := UpstreamResponse{Status: http.StatusOK, Body: []byte(`{"partialFailureError":null,"results":[{}]}`)}
	if err := policy.RecordSuccess(cfg, decision, malformed); err == nil {
		t.Fatal("an empty create result without a real partial-failure error was accepted")
	}
}

func TestAccountResourceQueryRejectsDisjunction(t *testing.T) {
	policy, store, cfg := testPolicy(t)
	resourceName := "customers/1234567890/labels/987"
	if err := store.PutOwnership(ResourceOwnership{
		ResourceName: resourceName,
		CustomerID:   "1234567890",
		ResourceType: "label",
		CampaignID:   "111",
	}); err != nil {
		t.Fatal(err)
	}
	query := `SELECT label.resource_name FROM label WHERE label.resource_name = 'customers/1234567890/labels/987' OR label.status = 'ENABLED'`
	if _, err := policy.Authorize(context.Background(), cfg, ProxyRequest{
		Method: "POST", Path: "/v23/customers/1234567890/googleAds:search",
		Body: map[string]any{"query": query},
	}); err == nil || !strings.Contains(err.Error(), "OR conditions") {
		t.Fatalf("account resource disjunction was accepted: %v", err)
	}
}

func TestMutationRejectsMalformedCustomerResourceName(t *testing.T) {
	policy, _, cfg := testPolicy(t)
	request := ProxyRequest{
		Method: "POST",
		Path:   "/v23/customers/1234567890/campaignLabels:mutate",
		Body: map[string]any{"operations": []any{map[string]any{"create": map[string]any{
			"campaign": "customers/1234567890/campaigns/111",
			"label":    "customers/123x4567890/labels/987",
		}}}},
	}
	if _, err := policy.Authorize(context.Background(), cfg, request); err == nil {
		t.Fatal("malformed customer resource name was accepted")
	}
}

func TestSuccessfulAssociationLinksOwnedResourceToCampaign(t *testing.T) {
	policy, store, cfg := testPolicy(t)
	googleClient, googleCfg := testGoogleClient(func(request *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusOK, `{"results":[]}`), nil
	})
	policy.google = googleClient
	cfg.Google = googleCfg.Google
	labelResourceName := "customers/1234567890/labels/987"
	if err := store.PutOwnership(ResourceOwnership{
		ResourceName: labelResourceName,
		CustomerID:   "1234567890",
		ResourceType: "label",
	}); err != nil {
		t.Fatal(err)
	}
	request := ProxyRequest{
		Method: "POST",
		Path:   "/v23/customers/1234567890/campaignLabels:mutate",
		Body: map[string]any{"operations": []any{map[string]any{"create": map[string]any{
			"campaign": "customers/1234567890/campaigns/111",
			"label":    labelResourceName,
		}}}},
	}
	decision, err := policy.Authorize(context.Background(), cfg, request)
	if err != nil {
		t.Fatal(err)
	}
	response := UpstreamResponse{
		Status: http.StatusOK,
		Body:   []byte(`{"results":[{"resourceName":"customers/1234567890/campaignLabels/111~987"}]}`),
	}
	if err := policy.RecordSuccess(cfg, decision, response); err != nil {
		t.Fatal(err)
	}
	owner, ok := store.Ownership(labelResourceName)
	if !ok || owner.CampaignID != "111" {
		t.Fatalf("label ownership was not linked to campaign 111: %#v", owner)
	}

	revoked := cfg.Accounts["1234567890"]
	revoked.Campaigns["111"] = CampaignPolicy{CampaignID: "111", Name: "Revoked"}
	cfg.Accounts["1234567890"] = revoked
	query := `SELECT label.resource_name FROM label WHERE label.resource_name = 'customers/1234567890/labels/987'`
	readDecision, err := policy.Authorize(context.Background(), cfg, ProxyRequest{
		Method: "POST", Path: "/v23/customers/1234567890/googleAds:search",
		Body: map[string]any{"query": query},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := policy.ValidateResponse(context.Background(), cfg, readDecision, UpstreamResponse{
		Status: http.StatusOK,
		Body:   []byte(`{"results":[{"label":{"resourceName":"customers/1234567890/labels/987"}}]}`),
	}); err == nil {
		t.Fatal("label remained readable after its campaign permission was revoked")
	}
}
