package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

const testCustomSegment = "customers/1234567890/customAudiences/987"
const testContainingAudience = "customers/1234567890/audiences/888"

// Exercise the real policy and HTTP search client. The upstream rejects the
// nested filter from the production incident, rather than accepting any query
// that happens to contain FROM audience.
func customAudiencePolicyFixture(t *testing.T, pages []string, owners map[string]string) (*PolicyEngine, PersistentConfig) {
	t.Helper()
	policy, store, cfg := testPolicy(t)
	if err := store.PutOwnership(ResourceOwnership{ResourceName: testCustomSegment, CustomerID: "1234567890", ResourceType: "custom_audience"}); err != nil {
		t.Fatal(err)
	}
	client, googleCfg := testGoogleClient(func(request *http.Request) (*http.Response, error) {
		var body map[string]any
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		query := stringValue(body["query"], "")
		switch {
		case strings.Contains(query, "audience.dimensions.audience_segments"):
			return jsonResponse(http.StatusBadRequest, `{"error":{"message":"Request contains an invalid argument."}}`), nil
		case query == "SELECT audience.resource_name, audience.dimensions FROM audience":
			if len(pages) == 0 {
				return jsonResponse(http.StatusServiceUnavailable, `{"error":{"message":"audience lookup unavailable"}}`), nil
			}
			page := 0
			if token := stringValue(body["pageToken"], ""); token != "" {
				if token != "second-page" || len(pages) != 2 {
					t.Fatalf("unexpected audience page token %q", token)
				}
				page = 1
			}
			return jsonResponse(http.StatusOK, pages[page]), nil
		case strings.Contains(query, "FROM ad_group_criterion") && strings.Contains(query, "ad_group_criterion.audience.audience"):
			for audience, campaign := range owners {
				if strings.Contains(query, "'"+audience+"'") {
					return jsonResponse(http.StatusOK, fmt.Sprintf(`{"results":[{"campaign":{"id":%q},"adGroupCriterion":{"audience":{"audience":%q}}}]}`, campaign, audience)), nil
				}
			}
			return jsonResponse(http.StatusOK, `{"results":[]}`), nil
		case strings.Contains(query, "FROM ad_group_criterion"), strings.Contains(query, "FROM campaign_criterion"), strings.Contains(query, "FROM asset_group_signal"):
			return jsonResponse(http.StatusOK, `{"results":[]}`), nil
		case strings.HasPrefix(query, "SELECT audience.resource_name, audience.asset_group FROM audience WHERE audience.resource_name = "):
			return jsonResponse(http.StatusOK, `{"results":[]}`), nil
		default:
			t.Fatalf("unexpected ownership query: %s", query)
			return nil, nil
		}
	})
	policy.google = client
	cfg.Google = googleCfg.Google
	return policy, cfg
}

func containingAudienceRow(resource, segment string) string {
	return fmt.Sprintf(`{"audience":{"resourceName":%q,"dimensions":[{"age":{"minAge":25}},{"audienceSegments":{"segments":[{"userInterest":{"userInterestCategory":"customers/1234567890/userInterests/1"}},{"customAudience":{"customAudience":%q}}]}}]}}`, resource, segment)
}

func segmentUpdateRequest() ProxyRequest {
	return ProxyRequest{Method: "POST", Path: "/v23/customers/1234567890/customAudiences:mutate", Body: map[string]any{
		"operations": []any{map[string]any{"update": map[string]any{
			"resourceName": testCustomSegment,
			"members":      []any{map[string]any{"memberType": "URL", "url": "youtube.com"}},
		}, "updateMask": "members"}},
	}}
}

func TestCustomAudienceOwnershipAllowsReadAttachAndEdit(t *testing.T) {
	for _, attached := range []bool{false, true} {
		t.Run(fmt.Sprintf("already_attached_%t", attached), func(t *testing.T) {
			page := `{"results":[]}`
			if attached {
				page = `{"results":[` + containingAudienceRow(testContainingAudience, testCustomSegment) + `]}`
			}
			policy, cfg := customAudiencePolicyFixture(t, []string{page}, map[string]string{testContainingAudience: "111"})
			ctx := context.Background()
			read, err := policy.Authorize(ctx, cfg, ProxyRequest{
				Method: "POST", Path: "/v23/customers/1234567890/googleAds:search",
				Body: map[string]any{"query": "SELECT custom_audience.resource_name, custom_audience.members FROM custom_audience WHERE custom_audience.resource_name = '" + testCustomSegment + "'"},
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := policy.ValidateResponse(ctx, cfg, read, UpstreamResponse{Status: http.StatusOK, Body: []byte(fmt.Sprintf(`{"results":[{"customAudience":{"resourceName":%q,"members":[{"memberType":"URL","url":"youtube.com"}]}}]}`, testCustomSegment))}); err != nil {
				t.Fatalf("custom segment read-back failed: %v", err)
			}
			attach := ProxyRequest{Method: "POST", Path: "/v23/customers/1234567890/audiences:mutate", Body: map[string]any{
				"operations": []any{map[string]any{"update": map[string]any{
					"resourceName": testContainingAudience,
					"dimensions":   []any{map[string]any{"audienceSegments": map[string]any{"segments": []any{map[string]any{"customAudience": map[string]any{"customAudience": testCustomSegment}}}}}},
				}, "updateMask": "dimensions"}},
			}}
			if _, err := policy.Authorize(ctx, cfg, attach); err != nil {
				t.Fatalf("attaching custom segment to a writable audience failed: %v", err)
			}
			if _, err := policy.Authorize(ctx, cfg, segmentUpdateRequest()); err != nil {
				t.Fatalf("editing custom segment members failed: %v", err)
			}
		})
	}
}

func TestCustomAudienceOwnershipChecksAllPagesAndEveryCampaign(t *testing.T) {
	otherAudience := "customers/1234567890/audiences/889"
	pages := []string{
		`{"results":[` + containingAudienceRow(testContainingAudience, testCustomSegment) + `],"nextPageToken":"second-page"}`,
		`{"results":[` + containingAudienceRow(otherAudience, testCustomSegment) + `]}`,
	}
	policy, cfg := customAudiencePolicyFixture(t, pages, map[string]string{testContainingAudience: "111", otherAudience: "222"})
	_, err := policy.Authorize(context.Background(), cfg, segmentUpdateRequest())
	if err == nil || !strings.Contains(err.Error(), "campaign 222 is read-only") {
		t.Fatalf("shared segment edit must be denied for the second page's read-only campaign: %v", err)
	}
}

// Rebuilding an Audience instead of updating a segment still references a
// real CustomAudience. Both public mutate transports must enforce ownership.
func TestCustomAudienceOwnershipAllowsAudienceCreateInBothTransports(t *testing.T) {
	for _, generic := range []bool{false, true} {
		for _, allCampaigns := range []bool{false, true} {
			t.Run(fmt.Sprintf("generic_%t_all_campaigns_%t", generic, allCampaigns), func(t *testing.T) {
				policy, cfg := customAudiencePolicyFixture(t, []string{`{"results":[]}`}, nil)
				account := cfg.Accounts["1234567890"]
				account.AllCampaignsReadWrite = allCampaigns
				cfg.Accounts["1234567890"] = account
				operation := map[string]any{"create": map[string]any{
					"name": "[TEST] Managed audience",
					"dimensions": []any{map[string]any{"audienceSegments": map[string]any{
						"segments": []any{map[string]any{"customAudience": map[string]any{"customAudience": testCustomSegment}}},
					}}},
				}}
				request := ProxyRequest{Method: "POST", Path: "/v23/customers/1234567890/audiences:mutate", Body: map[string]any{
					"operations": []any{operation}, "validateOnly": true,
				}}
				if generic {
					request.Path = "/v23/customers/1234567890/googleAds:mutate"
					request.Body = map[string]any{"mutateOperations": []any{map[string]any{"audienceOperation": operation}}, "validateOnly": true}
				}
				if _, err := policy.Authorize(context.Background(), cfg, request); err != nil {
					t.Fatalf("creating an audience referencing a gateway-created segment failed: %v", err)
				}
			})
		}
	}
}

func TestCustomAudienceOwnershipIgnoresOtherSegments(t *testing.T) {
	pages := []string{`{"results":[` + containingAudienceRow(testContainingAudience, "customers/1234567890/customAudiences/9870") + `]}`}
	policy, cfg := customAudiencePolicyFixture(t, pages, map[string]string{testContainingAudience: "333"})
	if _, err := policy.Authorize(context.Background(), cfg, segmentUpdateRequest()); err != nil {
		t.Fatalf("a different segment on a blocked campaign must not block this gateway-created segment: %v", err)
	}
}

func TestCustomAudienceOwnershipFailsClosedOnIncompleteLookup(t *testing.T) {
	for name, pages := range map[string][]string{
		"upstream failure":    nil,
		"invalid dimensions":  {`{"results":[{"audience":{"resourceName":"customers/1234567890/audiences/888","dimensions":"invalid"}}]}`},
		"different customer":  {`{"results":[` + containingAudienceRow("customers/9999999999/audiences/888", testCustomSegment) + `]}`},
		"missing resource":    {`{"results":[` + containingAudienceRow("", testCustomSegment) + `]}`},
		"second page failure": {`{"results":[],"nextPageToken":"second-page"}`, `{"results":"invalid"}`},
	} {
		t.Run(name, func(t *testing.T) {
			policy, cfg := customAudiencePolicyFixture(t, pages, nil)
			if _, err := policy.Authorize(context.Background(), cfg, segmentUpdateRequest()); err == nil {
				t.Fatal("an incomplete ownership lookup authorized a shared-resource edit")
			}
		})
	}
}
