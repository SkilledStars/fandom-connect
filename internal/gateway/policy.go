package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"
)

var proxyPathPattern = regexp.MustCompile(`^/v[0-9]+/customers/([0-9]+)(?:/([A-Za-z][A-Za-z0-9]*):([A-Za-z][A-Za-z0-9]*))?(?::([A-Za-z][A-Za-z0-9]*))?$`)
var accessibleCustomersPathPattern = regexp.MustCompile(`^/v[0-9]+/customers:listAccessibleCustomers$`)
var customerResourceCollectionPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]*$`)
var customerResourceIdentifierPattern = regexp.MustCompile(`^-?[0-9]{1,20}(?:~(?:-?[0-9]{1,20}|[A-Z][A-Z0-9_]{0,49}))*$`)
var resourceEnumPattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,49}$`)

var ownedReadResources = map[string]string{
	"asset":           "asset.resource_name",
	"audience":        "audience.resource_name",
	"campaign_budget": "campaign_budget.resource_name",
	"custom_audience": "custom_audience.resource_name",
	"label":           "label.resource_name",
}

var ownedResourceCollections = map[string]string{
	"asset":           "assets",
	"audience":        "audiences",
	"campaign_budget": "campaignBudgets",
	"custom_audience": "customAudiences",
	"label":           "labels",
}

type referenceQuerySpec struct {
	From       string
	Field      string
	ResultPath []string
}

type accountResourceNameQuerySpec struct {
	NameField          string
	ResourceResultPath []string
}

// Some canonical Fandom operations use an exact Google Ads resource name
// lookup before deciding whether to create or reuse an account-owned object.
// The gateway resolves only those exact names internally, verifies every
// matching resource against campaign permissions, and adds the canonical
// resource-name field to SELECT when response authorization requires it.
var accountResourceNameQueries = map[string]accountResourceNameQuerySpec{
	"asset":           {NameField: "asset.name", ResourceResultPath: []string{"asset", "resourceName"}},
	"audience":        {NameField: "audience.name", ResourceResultPath: []string{"audience", "resourceName"}},
	"campaign_budget": {NameField: "campaign_budget.name", ResourceResultPath: []string{"campaignBudget", "resourceName"}},
	"custom_audience": {NameField: "custom_audience.name", ResourceResultPath: []string{"customAudience", "resourceName"}},
	"label":           {NameField: "label.name", ResourceResultPath: []string{"label", "resourceName"}},
}

// Account-scoped resources can be reused by multiple campaigns. Fandom may
// read one only when the request names it exactly and Google confirms that it
// is attached to a campaign the gateway permits. The extra lookup returns only
// campaign IDs and resource names; it never proxies an account-wide listing.
var accountResourceReferenceQueries = map[string][]referenceQuerySpec{
	"campaign_budget": {
		{From: "campaign", Field: "campaign.campaign_budget", ResultPath: []string{"campaign", "campaignBudget"}},
	},
	"custom_audience": {
		{From: "ad_group_criterion", Field: "ad_group_criterion.custom_audience.custom_audience", ResultPath: []string{"adGroupCriterion", "customAudience", "customAudience"}},
		{From: "campaign_criterion", Field: "campaign_criterion.custom_audience.custom_audience", ResultPath: []string{"campaignCriterion", "customAudience", "customAudience"}},
	},
	"audience": {
		{From: "ad_group_criterion", Field: "ad_group_criterion.audience.audience", ResultPath: []string{"adGroupCriterion", "audience", "audience"}},
		{From: "asset_group_signal", Field: "asset_group_signal.audience.audience", ResultPath: []string{"assetGroupSignal", "audience", "audience"}},
	},
	"asset": {
		{From: "ad_group_ad_asset_view", Field: "ad_group_ad_asset_view.asset", ResultPath: []string{"adGroupAdAssetView", "asset"}},
		{From: "ad_group_asset", Field: "ad_group_asset.asset", ResultPath: []string{"adGroupAsset", "asset"}},
		{From: "campaign_asset", Field: "campaign_asset.asset", ResultPath: []string{"campaignAsset", "asset"}},
		{From: "asset_group_asset", Field: "asset_group_asset.asset", ResultPath: []string{"assetGroupAsset", "asset"}},
	},
	"label": {
		{From: "campaign_label", Field: "campaign_label.label", ResultPath: []string{"campaignLabel", "label"}},
		{From: "ad_group_label", Field: "ad_group_label.label", ResultPath: []string{"adGroupLabel", "label"}},
		{From: "ad_group_ad_label", Field: "ad_group_ad_label.label", ResultPath: []string{"adGroupAdLabel", "label"}},
		{From: "ad_group_criterion_label", Field: "ad_group_criterion_label.label", ResultPath: []string{"adGroupCriterionLabel", "label"}},
	},
}

// These links make an asset account-wide or place it behind another shared
// object whose full campaign reach is not represented by one direct campaign
// relationship. Fandom does not currently need either shape, so fail closed
// instead of guessing at ownership. This check runs for reads and writes.
var accountWideResourceReferenceQueries = map[string][]referenceQuerySpec{
	"asset": {
		{From: "customer_asset", Field: "customer_asset.asset", ResultPath: []string{"customerAsset", "asset"}},
		{From: "asset_set_asset", Field: "asset_set_asset.asset", ResultPath: []string{"assetSetAsset", "asset"}},
	},
}

var safeReferenceResources = map[string]bool{
	"detailed_demographic": true,
	"geo_target_constant":  true,
	"life_event":           true,
	"topic_constant":       true,
	"user_interest":        true,
}

// These are immutable Google-owned targeting catalogs, not customer-created
// objects. A permitted campaign may reference an entry, but the identifier
// must still be a canonical positive numeric ID in the request customer.
var safeReferencedResourceCollections = map[string]bool{
	"detailedDemographics": true,
	"lifeEvents":           true,
	"userInterests":        true,
}

// Only resources whose v23 field metadata exposes campaign as an attributed
// resource belong here. Partial grants are enforced by adding the gateway's
// own campaign.id boundary before the query reaches Google. Keeping this list
// explicit makes new Google resources fail closed until their ownership model
// has been reviewed.
var campaignScopedReadResources = map[string]bool{
	"ad_group":               true,
	"ad_group_ad":            true,
	"ad_group_ad_asset_view": true,
	"ad_group_audience_view": true,
	"ad_group_criterion":     true,
	"age_range_view":         true,
	"asset_group":            true,
	"campaign":               true,
	"campaign_criterion":     true,
	"detail_placement_view":  true,
	"display_keyword_view":   true,
	"gender_view":            true,
	"geographic_view":        true,
	"keyword_view":           true,
	"recommendation":         true,
	"search_term_view":       true,
	"topic_view":             true,
}

var safeCustomerFields = map[string]bool{
	"customer.id": true,
	// This readiness enum is required to select a valid bidding strategy when
	// creating a campaign. It exposes no campaigns, metrics, or conversions.
	"customer.conversion_tracking_setting.conversion_tracking_status": true,
	"customer.descriptive_name":                                       true,
	"customer.currency_code":                                          true,
	"customer.time_zone":                                              true,
	"customer.manager":                                                true,
	"customer.test_account":                                           true,
	"customer.status":                                                 true,
}

var mutateServiceTypes = map[string]string{
	"campaigns":        "campaign",
	"campaignBudgets":  "campaign_budget",
	"adGroups":         "ad_group",
	"adGroupAds":       "ad_group_ad",
	"adGroupCriteria":  "ad_group_criterion",
	"campaignCriteria": "campaign_criterion",
	"customAudiences":  "custom_audience",
	"audiences":        "audience",
	"assets":           "asset",
	"labels":           "label",
	"campaignLabels":   "campaign_label",
	"adGroupLabels":    "ad_group_label",
	"assetGroups":      "asset_group",
	"assetGroupAssets": "asset_group_asset",
	"campaignAssets":   "campaign_asset",
	"adGroupAssets":    "ad_group_asset",
}

var resourceCollections = map[string]string{
	"campaign":           "campaigns",
	"campaign_budget":    "campaignBudgets",
	"ad_group":           "adGroups",
	"ad_group_ad":        "adGroupAds",
	"ad_group_criterion": "adGroupCriteria",
	"campaign_criterion": "campaignCriteria",
	"custom_audience":    "customAudiences",
	"audience":           "audiences",
	"asset":              "assets",
	"label":              "labels",
	"campaign_label":     "campaignLabels",
	"ad_group_label":     "adGroupLabels",
	"asset_group":        "assetGroups",
	"asset_group_asset":  "assetGroupAssets",
	"campaign_asset":     "campaignAssets",
	"ad_group_asset":     "adGroupAssets",
}

var campaignResolutionResultPaths = map[string][]string{
	"ad_group":           {"adGroup", "resourceName"},
	"ad_group_ad":        {"adGroupAd", "resourceName"},
	"ad_group_criterion": {"adGroupCriterion", "resourceName"},
	"campaign_criterion": {"campaignCriterion", "resourceName"},
	"asset_group":        {"assetGroup", "resourceName"},
	"campaign_budget":    {"campaign", "campaignBudget"},
}

type resourceIdentifierShape struct {
	components   int
	lastIsEnum   bool
	relationship bool
}

var resourceIdentifierShapes = map[string]resourceIdentifierShape{
	"campaign":           {components: 1},
	"campaign_budget":    {components: 1},
	"ad_group":           {components: 1},
	"custom_audience":    {components: 1},
	"audience":           {components: 1},
	"asset":              {components: 1},
	"label":              {components: 1},
	"asset_group":        {components: 1},
	"ad_group_ad":        {components: 2},
	"ad_group_criterion": {components: 2},
	"campaign_criterion": {components: 2},
	"campaign_label":     {components: 2, relationship: true},
	"ad_group_label":     {components: 2, relationship: true},
	"asset_group_asset":  {components: 3, lastIsEnum: true, relationship: true},
	"campaign_asset":     {components: 3, lastIsEnum: true, relationship: true},
	"ad_group_asset":     {components: 3, lastIsEnum: true, relationship: true},
}

var genericOperationTypes = map[string]string{
	"campaignOperation":          "campaign",
	"campaignBudgetOperation":    "campaign_budget",
	"adGroupOperation":           "ad_group",
	"adGroupAdOperation":         "ad_group_ad",
	"adGroupCriterionOperation":  "ad_group_criterion",
	"campaignCriterionOperation": "campaign_criterion",
	"customAudienceOperation":    "custom_audience",
	"audienceOperation":          "audience",
	"assetOperation":             "asset",
	"labelOperation":             "label",
	"campaignLabelOperation":     "campaign_label",
	"adGroupLabelOperation":      "ad_group_label",
	"assetGroupOperation":        "asset_group",
	"assetGroupAssetOperation":   "asset_group_asset",
	"campaignAssetOperation":     "campaign_asset",
	"adGroupAssetOperation":      "ad_group_asset",
}

type Mutation struct {
	ResourceType string
	Action       string
	Value        map[string]any
	ResourceName string
	TempName     string
	CampaignID   string
}

type temporaryResource struct {
	ResourceType string
	CampaignID   string
}

var sensitiveReferencedResources = map[string]string{
	"campaignBudgets": "campaign_budget",
	"customAudiences": "custom_audience",
	"audiences":       "audience",
	"assets":          "asset",
	"labels":          "label",
}

// Every customer-scoped resource reference inside a write must be understood
// by the policy. These resources inherit a campaign owner and can therefore be
// resolved back to that campaign. Unknown collections are denied below; a new
// Google Ads resource type must never become writable merely because Google
// starts accepting a new field.
var campaignOwnedReferencedResources = map[string]string{
	"adGroups":         "ad_group",
	"adGroupAds":       "ad_group_ad",
	"adGroupCriteria":  "ad_group_criterion",
	"campaignCriteria": "campaign_criterion",
	"assetGroups":      "asset_group",
	"campaignLabels":   "campaign_label",
	"adGroupLabels":    "ad_group_label",
	"assetGroupAssets": "asset_group_asset",
	"campaignAssets":   "campaign_asset",
	"adGroupAssets":    "ad_group_asset",
}

type PolicyDecision struct {
	Request      ProxyRequest
	CustomerID   string
	Write        bool
	ResourceType string
	CampaignIDs  []string
	Mutations    []Mutation
	QueryResult  *accountResourceQueryResultPolicy
}

type accountResourceQueryResultPolicy struct {
	ResourceType           string
	ResourceNameField      string
	RequestedResourceNames []string
	RequestedExactNames    []string
}

type PolicyEngine struct {
	store  *Store
	google *GoogleClient
}

func NewPolicyEngine(store *Store, googleClient *GoogleClient) *PolicyEngine {
	return &PolicyEngine{store: store, google: googleClient}
}

func validateProxyPath(path string) error {
	if path == "" || len(path) > 512 || strings.ContainsAny(path, "?#%\\") || strings.Contains(path, "..") || strings.Contains(path, "//") {
		return errors.New("Google Ads path is invalid")
	}
	if accessibleCustomersPathPattern.MatchString(path) {
		return nil
	}
	if !proxyPathPattern.MatchString(path) {
		return errors.New("Google Ads path is not an allowed customer endpoint")
	}
	return nil
}

func parseProxyPath(path string) (customerID, service, action string, err error) {
	if err = validateProxyPath(path); err != nil {
		return "", "", "", err
	}
	matches := proxyPathPattern.FindStringSubmatch(path)
	if len(matches) == 0 {
		return "", "", "", errors.New("account discovery is not available to API clients")
	}
	customerID = matches[1]
	service = matches[2]
	action = matches[3]
	if matches[4] != "" {
		action = matches[4]
	}
	return
}

func allowedCampaignIDs(account AccountPolicy, write bool) []string {
	ids := make([]string, 0, len(account.Campaigns))
	for id, campaign := range account.Campaigns {
		if campaign.CampaignID != id || !isNonzeroPositiveID(id) {
			continue
		}
		allowed := campaign.Read || campaign.Write
		if write {
			allowed = campaign.Write
		}
		if allowed {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return ids
}

func hasCampaignAccess(account AccountPolicy, write bool) bool {
	return account.AllCampaignsReadWrite || len(allowedCampaignIDs(account, write)) > 0
}

func (p *PolicyEngine) Authorize(ctx context.Context, cfg PersistentConfig, request ProxyRequest) (PolicyDecision, error) {
	request.Method = strings.ToUpper(strings.TrimSpace(request.Method))
	if request.Method != http.MethodPost {
		return PolicyDecision{}, errors.New("only POST Google Ads operations are accepted through the campaign gateway")
	}
	if !strings.HasPrefix(request.Path, "/"+p.google.apiVersion+"/") {
		return PolicyDecision{}, fmt.Errorf("the gateway is configured for Google Ads API %s", p.google.apiVersion)
	}
	customerID, service, action, err := parseProxyPath(request.Path)
	if err != nil {
		return PolicyDecision{}, err
	}
	account, ok := cfg.Accounts[customerID]
	if !ok || account.IsManager {
		return PolicyDecision{}, errors.New("the target advertiser account is not configured in this gateway")
	}
	if account.CustomerID != customerID {
		return PolicyDecision{}, errors.New("the target advertiser account configuration is inconsistent")
	}
	decision := PolicyDecision{Request: request, CustomerID: customerID, ResourceType: service}

	switch {
	case service == "googleAds" && (action == "search" || action == "searchStream"):
		query, _ := request.Body["query"].(string)
		campaigns, resultPolicy, effectiveQuery, authorizeErr := p.authorizeQuery(ctx, cfg, account, customerID, query)
		if authorizeErr != nil {
			return PolicyDecision{}, authorizeErr
		}
		if effectiveQuery != query {
			request.Body["query"] = effectiveQuery
			rawBody, marshalErr := json.Marshal(request.Body)
			if marshalErr != nil {
				return PolicyDecision{}, errors.New("rewritten Google Ads request could not be encoded")
			}
			request.RawBody = rawBody
			decision.Request = request
		}
		decision.CampaignIDs = campaigns
		decision.QueryResult = resultPolicy
		return decision, nil
	case service == "googleAds" && action == "mutate":
		decision.Write = true
		mutations, parseErr := parseGenericMutations(request.Body)
		if parseErr != nil {
			return PolicyDecision{}, parseErr
		}
		return p.authorizeMutations(ctx, cfg, account, decision, mutations)
	case action == "mutate":
		resourceType, exists := mutateServiceTypes[service]
		if !exists {
			return PolicyDecision{}, errors.New("this Google Ads mutation service is not supported by the gateway policy")
		}
		decision.Write = true
		decision.ResourceType = resourceType
		mutations, parseErr := parseServiceMutations(resourceType, request.Body)
		if parseErr != nil {
			return PolicyDecision{}, parseErr
		}
		return p.authorizeMutations(ctx, cfg, account, decision, mutations)
	case service == "" && (action == "generateKeywordIdeas" || action == "generateKeywordHistoricalMetrics"):
		if !hasCampaignAccess(account, false) && !account.AllowCreate {
			return PolicyDecision{}, errors.New("keyword planning requires at least one permitted campaign or campaign creation permission")
		}
		return decision, nil
	default:
		return PolicyDecision{}, errors.New("this Google Ads operation is not supported by the gateway policy")
	}
}

func (p *PolicyEngine) authorizeQuery(ctx context.Context, cfg PersistentConfig, account AccountPolicy, customerID, query string) ([]string, *accountResourceQueryResultPolicy, string, error) {
	resource, _, err := gaqlResource(query)
	if err != nil {
		return nil, nil, "", err
	}
	if err := rejectGAQLDisjunction(query); err != nil {
		return nil, nil, "", err
	}
	fields, fieldErr := referencedFields(query)
	if fieldErr != nil {
		return nil, nil, "", fieldErr
	}
	for _, referenced := range fields {
		if strings.HasPrefix(referenced, "customer.") && !safeCustomerFields[referenced] {
			return nil, nil, "", fmt.Errorf("customer field %s is not available through a campaign-scoped gateway", referenced)
		}
	}
	_, isOwnedResource := ownedReadResources[resource]
	if resource == "customer" || isOwnedResource || safeReferenceResources[resource] {
		for _, referenced := range fields {
			if strings.HasPrefix(referenced, "metrics.") || strings.HasPrefix(referenced, "segments.") {
				return nil, nil, "", fmt.Errorf("account-level resource metrics field %s is not available through a campaign-scoped gateway", referenced)
			}
		}
	}
	if resource == "customer" || isOwnedResource || safeReferenceResources[resource] {
		for _, referenced := range fields {
			if strings.HasPrefix(referenced, resource+".") || safeCustomerFields[referenced] {
				continue
			}
			return nil, nil, "", fmt.Errorf("field %s is not rooted in the authorized %s resource", referenced, resource)
		}
	}
	readIDs := allowedCampaignIDs(account, false)
	if field, ok := ownedReadResources[resource]; ok {
		requested, requestErr := requestedAccountResourceNames(query, customerID, resource, field)
		if requestErr != nil {
			return nil, nil, "", requestErr
		}
		var requestedNames []string
		if len(requested) == 0 {
			var nameErr error
			requestedNames, nameErr = requestedAccountResourceExactNames(query, resource)
			if nameErr != nil {
				return nil, nil, "", nameErr
			}
			if len(requestedNames) == 0 {
				return nil, nil, "", fmt.Errorf("%s queries must explicitly restrict a resource name, ID, or exact name", resource)
			}
		}
		query, requestErr = ensureGAQLSelectedField(query, field)
		if requestErr != nil {
			return nil, nil, "", requestErr
		}
		selected, selectedErr := selectedFields(query)
		if selectedErr != nil {
			return nil, nil, "", selectedErr
		}
		selectedSet := map[string]bool{}
		for _, selectedField := range selected {
			selectedSet[selectedField] = true
		}
		if !selectedSet[field] {
			return nil, nil, "", fmt.Errorf("%s queries must select %s so the response can be authorized", resource, field)
		}
		if len(requestedNames) > 0 && !selectedSet[accountResourceNameQueries[resource].NameField] {
			return nil, nil, "", fmt.Errorf("%s exact-name queries must select the name field so the response can be authorized", resource)
		}
		return readIDs, &accountResourceQueryResultPolicy{
			ResourceType:           resource,
			ResourceNameField:      field,
			RequestedResourceNames: requested,
			RequestedExactNames:    requestedNames,
		}, query, nil
	}
	if resource == "customer" {
		if !hasCampaignAccess(account, false) && !account.AllowCreate {
			return nil, nil, "", errors.New("customer metadata requires a permitted campaign or campaign creation permission")
		}
		return nil, nil, query, nil
	}
	if safeReferenceResources[resource] {
		if !hasCampaignAccess(account, false) && !account.AllowCreate {
			return nil, nil, "", errors.New("reference data requires a permitted campaign")
		}
		return nil, nil, query, nil
	}

	if !campaignScopedReadResources[resource] {
		return nil, nil, "", fmt.Errorf("GAQL resource %s is not supported by the gateway policy", resource)
	}
	if account.AllCampaignsReadWrite {
		return nil, nil, query, nil
	}

	// Preserve an explicit caller boundary after verifying it. Otherwise add a
	// gateway-owned boundary containing every currently readable campaign. The
	// original query can only narrow this condition because OR and NOT are
	// rejected above.
	requestedCampaigns, scopeErr := explicitCampaignIDs(query)
	if scopeErr == nil {
		for _, campaignID := range requestedCampaigns {
			if err := requireCampaign(account, campaignID, false); err != nil {
				return nil, nil, "", fmt.Errorf("campaign %s is not readable: %w", campaignID, err)
			}
		}
		return requestedCampaigns, nil, query, nil
	}
	whereHasCampaignID, fieldErr := gaqlWhereReferencesField(query, "campaign.id")
	if fieldErr != nil {
		return nil, nil, "", fieldErr
	}
	if whereHasCampaignID {
		return nil, nil, "", fmt.Errorf("GAQL campaign.id boundary is invalid: %w", scopeErr)
	}
	condition := numericInCondition("campaign.id", readIDs)
	rewritten, rewriteErr := addGAQLCondition(query, condition)
	if rewriteErr != nil {
		return nil, nil, "", rewriteErr
	}
	return readIDs, nil, rewritten, nil
}

func requestedAccountResourceNames(query, customerID, resourceType, resourceNameField string) ([]string, error) {
	collection := ownedResourceCollections[resourceType]
	if collection == "" {
		return nil, errors.New("account resource collection is not supported")
	}
	values, err := exactGAQLStringFilterValues(query, resourceNameField)
	if err != nil {
		return nil, err
	}

	// A few older Fandom views address custom audiences by numeric ID. Convert
	// those exact filters to canonical resource names before authorization.
	idField := strings.TrimSuffix(resourceNameField, ".resource_name") + ".id"
	ids, err := exactGAQLNumericFilterValues(query, idField)
	if err != nil {
		return nil, err
	}
	for _, id := range ids {
		values = append(values, fmt.Sprintf("customers/%s/%s/%s", customerID, collection, id))
	}

	prefix := fmt.Sprintf("customers/%s/%s/", customerID, collection)
	validated := make([]string, 0, len(values))
	for _, value := range uniqueStrings(values) {
		if !strings.HasPrefix(value, prefix) {
			return nil, fmt.Errorf("%s resource belongs to a different advertiser account", resourceType)
		}
		id := strings.TrimPrefix(value, prefix)
		if !isNonzeroPositiveID(id) {
			return nil, fmt.Errorf("%s resource name is malformed", resourceType)
		}
		validated = append(validated, value)
	}
	return validated, nil
}

func requestedAccountResourceExactNames(query, resourceType string) ([]string, error) {
	spec, ok := accountResourceNameQueries[resourceType]
	if !ok {
		return nil, nil
	}
	names, err := exactGAQLStringFilterValues(query, spec.NameField)
	if err != nil {
		return nil, err
	}
	if len(names) > 200 {
		return nil, errors.New("exact-name lookup exceeds the 200-name safety limit")
	}
	for _, name := range names {
		if name == "" || len(name) > 1024 || strings.ContainsAny(name, "'\\\r\n") {
			return nil, errors.New("exact-name lookup contains an unsupported resource name")
		}
	}
	return names, nil
}

func nestedString(value map[string]any, path ...string) string {
	var current any = value
	for _, segment := range path {
		object, ok := current.(map[string]any)
		if !ok {
			return ""
		}
		current = object[segment]
	}
	return stringValue(current, "")
}

// ValidateResponse authorizes account-scoped query results after Google has
// produced them but before a single response byte is returned to Fandom. This
// makes exact-name lookups race-free: the original request is sent exactly
// once, an empty result stays empty, and every non-empty result must still be
// attached to a currently permitted campaign.
func (p *PolicyEngine) ValidateResponse(ctx context.Context, cfg PersistentConfig, decision PolicyDecision, response UpstreamResponse) error {
	policy := decision.QueryResult
	if policy == nil || response.Status < 200 || response.Status >= 300 {
		return nil
	}
	account, ok := cfg.Accounts[decision.CustomerID]
	if !ok || account.IsManager {
		return errors.New("the target advertiser account is no longer configured")
	}
	spec, ok := accountResourceNameQueries[policy.ResourceType]
	if !ok || len(spec.ResourceResultPath) == 0 {
		return errors.New("account resource response policy is invalid")
	}
	rows, err := decodeGoogleAdsSearchRows(response.Body)
	if err != nil {
		return fmt.Errorf("Google Ads response could not be safely authorized: %w", err)
	}
	requestedResources := map[string]bool{}
	for _, resourceName := range policy.RequestedResourceNames {
		requestedResources[resourceName] = true
	}
	requestedNames := map[string]bool{}
	for _, name := range policy.RequestedExactNames {
		requestedNames[name] = true
	}
	collection := ownedResourceCollections[policy.ResourceType]
	prefix := fmt.Sprintf("customers/%s/%s/", decision.CustomerID, collection)
	resources := make([]string, 0, len(rows))
	for _, row := range rows {
		resourceName := nestedString(row, spec.ResourceResultPath...)
		if !strings.HasPrefix(resourceName, prefix) || !isNonzeroPositiveID(strings.TrimPrefix(resourceName, prefix)) {
			return fmt.Errorf("Google returned an invalid %s resource name", policy.ResourceType)
		}
		if len(requestedResources) > 0 && !requestedResources[resourceName] {
			return fmt.Errorf("Google returned an unrequested %s resource", policy.ResourceType)
		}
		if len(requestedNames) > 0 {
			name := nestedString(row, spec.ResourceResultPath[0], "name")
			if !requestedNames[name] {
				return fmt.Errorf("Google returned an unrequested %s exact-name result", policy.ResourceType)
			}
		}
		resources = append(resources, resourceName)
	}
	resources = uniqueStrings(resources)
	if len(resources) == 0 {
		return nil
	}
	directCampaigns, err := p.resolveDirectAccountResourceCampaigns(
		ctx,
		cfg,
		decision.CustomerID,
		policy.ResourceType,
		resources,
	)
	if err != nil {
		return err
	}
	for _, resourceName := range resources {
		campaignIDs := directCampaigns[resourceName]
		if len(campaignIDs) == 0 {
			// Rare ownership shapes (for example a CustomAudience nested in an
			// Audience) need the full transitive resolver. The common direct
			// attachment path above is batched to avoid one Google round trip per
			// response row.
			campaignIDs, err = p.resolveAccountResourceCampaigns(
				ctx,
				cfg,
				decision.CustomerID,
				policy.ResourceType,
				resourceName,
			)
			if err != nil {
				return err
			}
		}
		if len(campaignIDs) > 0 {
			readable := false
			for _, campaignID := range campaignIDs {
				if requireCampaign(account, campaignID, false) == nil {
					readable = true
					break
				}
			}
			if !readable {
				return fmt.Errorf("%s resource %s is not attached to a readable campaign", policy.ResourceType, resourceName)
			}
			continue
		}

		owner, owned := p.store.Ownership(resourceName)
		if !owned || owner.CustomerID != decision.CustomerID || owner.ResourceType != policy.ResourceType {
			return fmt.Errorf("%s resource %s is not attached to a permitted campaign", policy.ResourceType, resourceName)
		}
		if owner.CampaignID != "" {
			if err := requireCampaign(account, owner.CampaignID, false); err != nil {
				return fmt.Errorf("%s resource %s is not attached to a permitted campaign: %w", policy.ResourceType, resourceName, err)
			}
			continue
		}
		// A gateway-created account resource may exist briefly before Fandom
		// links it. Keep only that creation workflow available, and only while
		// the account still has a readable campaign or create permission.
		if !hasCampaignAccess(account, false) && !account.AllowCreate {
			return fmt.Errorf("%s resource %s is not attached to a permitted campaign", policy.ResourceType, resourceName)
		}
	}
	return nil
}

func decodeGoogleAdsSearchRows(raw []byte) ([]map[string]any, error) {
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.UseNumber()
	var payload any
	if err := decoder.Decode(&payload); err != nil {
		return nil, err
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return nil, err
	}
	var pages []any
	switch typed := payload.(type) {
	case map[string]any:
		pages = []any{typed}
	case []any:
		pages = typed
	default:
		return nil, errors.New("search response is not an object or stream array")
	}
	var rows []map[string]any
	for _, rawPage := range pages {
		page, ok := rawPage.(map[string]any)
		if !ok {
			return nil, errors.New("search stream contains a malformed page")
		}
		rawResults, present := page["results"]
		if !present {
			continue
		}
		results, ok := rawResults.([]any)
		if !ok {
			return nil, errors.New("search results are malformed")
		}
		for _, rawRow := range results {
			row, ok := rawRow.(map[string]any)
			if !ok {
				return nil, errors.New("search result row is malformed")
			}
			rows = append(rows, row)
		}
	}
	return rows, nil
}

func parseServiceMutations(resourceType string, body map[string]any) ([]Mutation, error) {
	raw, ok := body["operations"].([]any)
	if !ok || len(raw) == 0 || len(raw) > 1000 {
		return nil, errors.New("mutation operations must contain between 1 and 1000 entries")
	}
	mutations := make([]Mutation, 0, len(raw))
	for _, entry := range raw {
		operation, ok := entry.(map[string]any)
		if !ok {
			return nil, errors.New("mutation operation is malformed")
		}
		mutation, err := normalizeMutation(resourceType, operation)
		if err != nil {
			return nil, err
		}
		mutations = append(mutations, mutation)
	}
	return mutations, nil
}

func parseGenericMutations(body map[string]any) ([]Mutation, error) {
	raw, ok := body["mutateOperations"].([]any)
	if !ok || len(raw) == 0 || len(raw) > 1000 {
		return nil, errors.New("mutateOperations must contain between 1 and 1000 entries")
	}
	mutations := make([]Mutation, 0, len(raw))
	for _, entry := range raw {
		wrapper, ok := entry.(map[string]any)
		if !ok || len(wrapper) != 1 {
			return nil, errors.New("generic mutation operation is malformed")
		}
		for operationName, rawOperation := range wrapper {
			resourceType, exists := genericOperationTypes[operationName]
			operation, operationOK := rawOperation.(map[string]any)
			if !exists || !operationOK {
				return nil, fmt.Errorf("generic mutation %s is not supported", operationName)
			}
			mutation, err := normalizeMutation(resourceType, operation)
			if err != nil {
				return nil, err
			}
			mutations = append(mutations, mutation)
		}
	}
	return mutations, nil
}

func normalizeMutation(resourceType string, operation map[string]any) (Mutation, error) {
	mutation := Mutation{ResourceType: resourceType}
	actions := 0
	if create, ok := operation["create"].(map[string]any); ok {
		mutation.Action = "create"
		mutation.Value = create
		mutation.TempName = stringValue(create["resourceName"], "")
		actions++
	}
	if update, ok := operation["update"].(map[string]any); ok {
		mutation.Action = "update"
		mutation.Value = update
		mutation.ResourceName = stringValue(update["resourceName"], "")
		actions++
	}
	if remove, ok := operation["remove"].(string); ok {
		mutation.Action = "remove"
		mutation.ResourceName = remove
		actions++
	}
	if actions != 1 {
		return Mutation{}, errors.New("each mutation must contain exactly one create, update, or remove action")
	}
	return mutation, nil
}

func (p *PolicyEngine) authorizeMutations(ctx context.Context, cfg PersistentConfig, account AccountPolicy, decision PolicyDecision, mutations []Mutation) (PolicyDecision, error) {
	temporaryResources := map[string]temporaryResource{}
	var campaignIDs []string
	for index := range mutations {
		mutation := &mutations[index]
		if err := validateMutationResourceName(account.CustomerID, *mutation); err != nil {
			return PolicyDecision{}, fmt.Errorf("%s %s denied: %w", mutation.Action, mutation.ResourceType, err)
		}
		if mutation.TempName != "" {
			if _, exists := temporaryResources[mutation.TempName]; exists {
				return PolicyDecision{}, fmt.Errorf("create %s denied: temporary resource name is duplicated", mutation.ResourceType)
			}
		}
		campaignID, err := p.authorizeMutation(ctx, cfg, account, *mutation, temporaryResources)
		if err != nil {
			return PolicyDecision{}, fmt.Errorf("%s %s denied: %w", mutation.Action, mutation.ResourceType, err)
		}
		if mutation.ResourceType == "campaign" && mutation.Action == "create" && mutation.TempName != "" {
			campaignID = "__new_campaign__:" + mutation.TempName
		}
		mutation.CampaignID = campaignID
		if err := p.authorizeReferencedResources(ctx, cfg, account, *mutation, temporaryResources); err != nil {
			return PolicyDecision{}, fmt.Errorf("%s %s denied: %w", mutation.Action, mutation.ResourceType, err)
		}
		if mutation.Action == "create" && mutation.TempName != "" {
			temporaryResources[mutation.TempName] = temporaryResource{
				ResourceType: mutation.ResourceType,
				CampaignID:   campaignID,
			}
		}
		if campaignID != "" && !strings.HasPrefix(campaignID, "__new_campaign__") {
			campaignIDs = append(campaignIDs, campaignID)
		}
	}
	decision.CampaignIDs = uniqueStrings(campaignIDs)
	decision.Mutations = mutations
	return decision, nil
}

func validateMutationResourceName(customerID string, mutation Mutation) error {
	expectedCollection := resourceCollections[mutation.ResourceType]
	if expectedCollection == "" {
		return errors.New("resource type is not supported")
	}
	resourceName := mutation.ResourceName
	if mutation.Action == "create" {
		resourceName = mutation.TempName
		if resourceName == "" {
			return nil
		}
	}
	parsedCustomerID, collection, identifier, ok := parseCustomerResourceName(resourceName)
	if !ok || parsedCustomerID != customerID || collection != expectedCollection {
		return errors.New("resource name does not match the request customer and resource type")
	}
	shape, exists := resourceIdentifierShapes[mutation.ResourceType]
	components := strings.Split(identifier, "~")
	if !exists || len(components) != shape.components {
		return errors.New("resource name has an invalid identifier shape")
	}
	if shape.lastIsEnum {
		if !resourceEnumPattern.MatchString(components[len(components)-1]) {
			return errors.New("asset-link resource name has an invalid field type")
		}
		components = components[:len(components)-1]
	}
	if mutation.Action == "create" && shape.relationship {
		return errors.New("relationship creates must identify their parent resources instead of supplying a resource name")
	}
	for index, component := range components {
		if mutation.Action == "create" {
			// For a composite child, parent IDs may be existing positive IDs or
			// earlier negative temporary IDs. The new resource's own final ID must
			// always be a nonzero negative temporary ID.
			if index == len(components)-1 {
				if !isNonzeroSignedID(component, true) {
					return errors.New("create resource names require a nonzero negative temporary ID")
				}
			} else if !isNonzeroSignedID(component, false) {
				return errors.New("create resource parent IDs are invalid")
			}
			continue
		}
		if !isNonzeroPositiveID(component) {
			return errors.New("update and remove resource names require positive Google Ads IDs")
		}
	}
	return nil
}

func isNonzeroPositiveID(value string) bool {
	return cleanIDPattern.MatchString(value) && strings.TrimLeft(value, "0") != ""
}

func isNonzeroSignedID(value string, requireNegative bool) bool {
	negative := strings.HasPrefix(value, "-")
	if requireNegative && !negative {
		return false
	}
	digits := strings.TrimPrefix(value, "-")
	return cleanIDPattern.MatchString(digits) && strings.TrimLeft(digits, "0") != ""
}

func (p *PolicyEngine) authorizeMutation(ctx context.Context, cfg PersistentConfig, account AccountPolicy, mutation Mutation, temporaryResources map[string]temporaryResource) (string, error) {
	if mutation.Action == "create" {
		switch mutation.ResourceType {
		case "campaign":
			if !account.AllowCreate {
				return "", errors.New("creating campaigns is not enabled for this advertiser account")
			}
			if strings.ToUpper(strings.TrimSpace(stringValue(mutation.Value["status"], ""))) != "PAUSED" {
				return "", errors.New("new campaigns must explicitly be created PAUSED")
			}
			return "__new_campaign__", nil
		case "campaign_budget":
			if !account.AllowCreate {
				return "", errors.New("creating campaign budgets requires campaign creation permission")
			}
			return "", nil
		case "custom_audience", "audience", "asset", "label":
			if !account.AllowCreate && !hasCampaignAccess(account, true) {
				return "", errors.New("no writable campaign or campaign creation permission is configured")
			}
			return "", nil
		case "ad_group", "asset_group", "campaign_criterion", "campaign_asset", "campaign_label":
			return p.authorizeParentCampaign(ctx, cfg, account, stringValue(mutation.Value["campaign"], ""), temporaryResources)
		case "ad_group_ad", "ad_group_criterion", "ad_group_asset", "ad_group_label":
			return p.authorizeParentResource(ctx, cfg, account, "ad_group", stringValue(mutation.Value["adGroup"], ""), temporaryResources)
		case "asset_group_asset":
			return p.authorizeParentResource(ctx, cfg, account, "asset_group", stringValue(mutation.Value["assetGroup"], ""), temporaryResources)
		default:
			return "", errors.New("resource creation is not supported")
		}
	}
	if mutation.ResourceName == "" {
		return "", errors.New("resource name is required")
	}
	switch mutation.ResourceType {
	case "campaign":
		id := campaignIDFromResource(mutation.ResourceName)
		return id, requireCampaign(account, id, true)
	case "campaign_budget":
		return p.authorizeAccountResourceWrite(ctx, cfg, account, mutation.ResourceType, mutation.ResourceName)
	case "custom_audience", "audience", "asset", "label":
		if mutation.ResourceType == "asset" || mutation.ResourceType == "label" {
			return "", errors.New("updating or removing this shared account resource is not supported through a campaign-scoped gateway")
		}
		return p.authorizeAccountResourceWrite(ctx, cfg, account, mutation.ResourceType, mutation.ResourceName)
	default:
		ids, err := p.resolveCampaigns(ctx, cfg, account.CustomerID, mutation.ResourceType, mutation.ResourceName)
		if err != nil {
			return "", err
		}
		if len(ids) == 0 {
			return "", errors.New("the affected campaign could not be determined")
		}
		for _, id := range ids {
			if err := requireCampaign(account, id, true); err != nil {
				return "", err
			}
		}
		return ids[0], nil
	}
}

// authorizeAccountResourceWrite permits a shared Google Ads resource only
// when every campaign currently using it is writable. An unattached resource
// is usable only when this gateway created it, which keeps guessed account
// resource names fail-closed while allowing Fandom's create-then-link flow.
func (p *PolicyEngine) authorizeAccountResourceWrite(ctx context.Context, cfg PersistentConfig, account AccountPolicy, resourceType, resourceName string) (string, error) {
	campaignIDs, err := p.resolveAccountResourceCampaigns(ctx, cfg, account.CustomerID, resourceType, resourceName)
	if err != nil {
		return "", err
	}
	if len(campaignIDs) > 0 {
		for _, campaignID := range campaignIDs {
			if err := requireCampaign(account, campaignID, true); err != nil {
				return "", err
			}
		}
		return campaignIDs[0], nil
	}

	owner, ok := p.store.Ownership(resourceName)
	if !ok || owner.CustomerID != account.CustomerID || owner.ResourceType != resourceType {
		return "", errors.New("the account-scoped resource is not attached to a writable campaign and was not created by this gateway")
	}
	if owner.CampaignID != "" {
		return owner.CampaignID, requireCampaign(account, owner.CampaignID, true)
	}
	if !account.AllowCreate && !hasCampaignAccess(account, true) {
		return "", errors.New("the account-scoped resource is not attached to a writable campaign")
	}
	return "", nil
}

func (p *PolicyEngine) resolveAccountResourceCampaigns(ctx context.Context, cfg PersistentConfig, customerID, resourceType, resourceName string) ([]string, error) {
	if strings.ContainsAny(resourceName, "'\\\r\n") {
		return nil, errors.New("resource ownership cannot be safely resolved")
	}
	specs := accountResourceReferenceQueries[resourceType]
	if len(specs) == 0 {
		if len(accountWideResourceReferenceQueries[resourceType]) == 0 {
			return nil, nil
		}
	}
	var campaignIDs []string
	for _, spec := range specs {
		query := fmt.Sprintf(
			"SELECT campaign.id, %s FROM %s WHERE %s",
			spec.Field,
			spec.From,
			stringInCondition(spec.Field, []string{resourceName}),
		)
		rows, err := p.google.search(ctx, cfg, customerID, query)
		if err != nil {
			return nil, fmt.Errorf("resolve %s campaign ownership: %w", resourceType, err)
		}
		for _, row := range rows {
			if nestedString(row, spec.ResultPath...) != resourceName {
				return nil, fmt.Errorf("Google returned a mismatched %s reference", resourceType)
			}
			campaignID := nestedString(row, "campaign", "id")
			if !isNonzeroPositiveID(campaignID) {
				return nil, fmt.Errorf("Google returned a %s reference without a campaign", resourceType)
			}
			campaignIDs = append(campaignIDs, campaignID)
		}
	}
	for _, spec := range accountWideResourceReferenceQueries[resourceType] {
		query := fmt.Sprintf(
			"SELECT %s FROM %s WHERE %s",
			spec.Field,
			spec.From,
			stringInCondition(spec.Field, []string{resourceName}),
		)
		rows, err := p.google.search(ctx, cfg, customerID, query)
		if err != nil {
			return nil, fmt.Errorf("resolve %s account-wide ownership: %w", resourceType, err)
		}
		for _, row := range rows {
			if nestedString(row, spec.ResultPath...) != resourceName {
				return nil, fmt.Errorf("Google returned a mismatched %s account-wide reference", resourceType)
			}
		}
		if len(rows) > 0 {
			return nil, fmt.Errorf("%s is linked at account or shared-set scope and cannot be exposed through a campaign-scoped gateway", resourceType)
		}
	}

	if resourceType == "audience" {
		// An ASSET_GROUP-scoped Audience belongs to exactly one asset group even
		// before an AssetGroupSignal exists. Resolve that immutable parent too.
		query := fmt.Sprintf(
			"SELECT audience.resource_name, audience.asset_group FROM audience WHERE audience.resource_name = '%s'",
			resourceName,
		)
		rows, err := p.google.search(ctx, cfg, customerID, query)
		if err != nil {
			return nil, fmt.Errorf("resolve audience asset-group ownership: %w", err)
		}
		for _, row := range rows {
			if nestedString(row, "audience", "resourceName") != resourceName {
				return nil, errors.New("Google returned a mismatched audience resource")
			}
			assetGroup := nestedString(row, "audience", "assetGroup")
			if assetGroup == "" {
				continue
			}
			ids, err := p.resolveCampaigns(ctx, cfg, customerID, "asset_group", assetGroup)
			if err != nil {
				return nil, fmt.Errorf("resolve audience asset-group campaign: %w", err)
			}
			campaignIDs = append(campaignIDs, ids...)
		}
	}

	if resourceType == "custom_audience" {
		// A CustomAudience can also affect campaigns transitively through a
		// customer-scoped Audience. Resolve each containing Audience and then
		// every campaign or asset group that consumes it.
		query := fmt.Sprintf(
			"SELECT audience.resource_name FROM audience WHERE audience.dimensions.audience_segments.segments.custom_audience.custom_audience = '%s'",
			resourceName,
		)
		rows, err := p.google.search(ctx, cfg, customerID, query)
		if err != nil {
			return nil, fmt.Errorf("resolve custom audience transitive ownership: %w", err)
		}
		for _, row := range rows {
			audienceResourceName := nestedString(row, "audience", "resourceName")
			if audienceResourceName == "" {
				continue
			}
			parsedCustomerID, collection, _, ok := parseCustomerResourceName(audienceResourceName)
			if !ok || parsedCustomerID != customerID || collection != "audiences" {
				return nil, errors.New("Google returned an invalid transitive audience resource name")
			}
			ids, err := p.resolveAccountResourceCampaigns(ctx, cfg, customerID, "audience", audienceResourceName)
			if err != nil {
				return nil, err
			}
			campaignIDs = append(campaignIDs, ids...)
		}
	}
	return uniqueStrings(campaignIDs), nil
}

func (p *PolicyEngine) resolveDirectAccountResourceCampaigns(
	ctx context.Context,
	cfg PersistentConfig,
	customerID string,
	resourceType string,
	resourceNames []string,
) (map[string][]string, error) {
	requested := map[string]bool{}
	for _, resourceName := range resourceNames {
		if strings.ContainsAny(resourceName, "'\\\r\n") {
			return nil, errors.New("resource ownership cannot be safely resolved")
		}
		requested[resourceName] = true
	}
	resolved := map[string][]string{}
	for _, spec := range accountResourceReferenceQueries[resourceType] {
		query := fmt.Sprintf(
			"SELECT campaign.id, %s FROM %s WHERE %s",
			spec.Field,
			spec.From,
			stringInCondition(spec.Field, resourceNames),
		)
		rows, err := p.google.search(ctx, cfg, customerID, query)
		if err != nil {
			return nil, fmt.Errorf("resolve %s campaign ownership: %w", resourceType, err)
		}
		for _, row := range rows {
			resourceName := nestedString(row, spec.ResultPath...)
			if !requested[resourceName] {
				return nil, fmt.Errorf("Google returned a mismatched %s reference", resourceType)
			}
			campaignID := nestedString(row, "campaign", "id")
			if !isNonzeroPositiveID(campaignID) {
				return nil, fmt.Errorf("Google returned a %s reference without a campaign", resourceType)
			}
			resolved[resourceName] = append(resolved[resourceName], campaignID)
		}
	}
	for _, spec := range accountWideResourceReferenceQueries[resourceType] {
		query := fmt.Sprintf(
			"SELECT %s FROM %s WHERE %s",
			spec.Field,
			spec.From,
			stringInCondition(spec.Field, resourceNames),
		)
		rows, err := p.google.search(ctx, cfg, customerID, query)
		if err != nil {
			return nil, fmt.Errorf("resolve %s account-wide ownership: %w", resourceType, err)
		}
		for _, row := range rows {
			resourceName := nestedString(row, spec.ResultPath...)
			if !requested[resourceName] {
				return nil, fmt.Errorf("Google returned a mismatched %s account-wide reference", resourceType)
			}
			return nil, fmt.Errorf("%s is linked at account or shared-set scope and cannot be exposed through a campaign-scoped gateway", resourceType)
		}
	}
	for resourceName, campaignIDs := range resolved {
		resolved[resourceName] = uniqueStrings(campaignIDs)
	}
	return resolved, nil
}

func (p *PolicyEngine) authorizeParentCampaign(ctx context.Context, cfg PersistentConfig, account AccountPolicy, resourceName string, temporaryResources map[string]temporaryResource) (string, error) {
	if temporary, ok := temporaryResources[resourceName]; ok && temporary.ResourceType == "campaign" {
		if strings.HasPrefix(temporary.CampaignID, "__new_campaign__") && account.AllowCreate {
			return temporary.CampaignID, nil
		}
	}
	id := campaignIDFromResource(resourceName)
	return id, requireCampaign(account, id, true)
}

func (p *PolicyEngine) authorizeParentResource(ctx context.Context, cfg PersistentConfig, account AccountPolicy, resourceType, resourceName string, temporaryResources map[string]temporaryResource) (string, error) {
	if resourceName == "" {
		return "", errors.New("parent resource is required")
	}
	if temporary, ok := temporaryResources[resourceName]; ok && temporary.ResourceType == resourceType {
		if strings.HasPrefix(temporary.CampaignID, "__new_campaign__") && !account.AllowCreate {
			return "", errors.New("the temporary parent belongs to a campaign that cannot be created")
		}
		return temporary.CampaignID, nil
	}
	if owner, ok := p.store.Ownership(resourceName); ok && owner.CustomerID == account.CustomerID && owner.ResourceType == resourceType {
		if owner.CampaignID == "" && account.AllowCreate {
			return "__new_campaign__", nil
		}
		return owner.CampaignID, requireCampaign(account, owner.CampaignID, true)
	}
	ids, err := p.resolveCampaigns(ctx, cfg, account.CustomerID, resourceType, resourceName)
	if err != nil || len(ids) != 1 {
		if err == nil {
			err = errors.New("parent campaign could not be determined")
		}
		return "", err
	}
	return ids[0], requireCampaign(account, ids[0], true)
}

func (p *PolicyEngine) authorizeReferencedResources(ctx context.Context, cfg PersistentConfig, account AccountPolicy, mutation Mutation, temporaryResources map[string]temporaryResource) error {
	for _, resourceName := range customerResourceReferences(mutation.Value) {
		if resourceName == mutation.ResourceName || resourceName == mutation.TempName {
			continue
		}
		customerID, resourceCollection, resourceID, ok := parseCustomerResourceName(resourceName)
		if !ok || customerID != account.CustomerID {
			return errors.New("a referenced Google Ads resource belongs to a different advertiser account")
		}
		if resourceCollection == "campaigns" {
			if temporary, ok := temporaryResources[resourceName]; ok && temporary.ResourceType == "campaign" {
				if strings.HasPrefix(temporary.CampaignID, "__new_campaign__") && account.AllowCreate {
					continue
				}
			}
			if err := requireCampaign(account, resourceID, true); err != nil {
				return err
			}
			continue
		}
		if safeReferencedResourceCollections[resourceCollection] {
			if !isNonzeroPositiveID(resourceID) {
				return fmt.Errorf("referenced Google Ads catalog resource %s is malformed", resourceCollection)
			}
			continue
		}
		resourceType, sensitive := sensitiveReferencedResources[resourceCollection]
		if sensitive {
			if temporary, ok := temporaryResources[resourceName]; ok && temporary.ResourceType == resourceType {
				continue
			}
			if _, err := p.authorizeAccountResourceWrite(ctx, cfg, account, resourceType, resourceName); err != nil {
				return fmt.Errorf("referenced %s is not writable: %w", resourceType, err)
			}
			continue
		}

		resourceType, campaignOwned := campaignOwnedReferencedResources[resourceCollection]
		if campaignOwned {
			if temporary, ok := temporaryResources[resourceName]; ok && temporary.ResourceType == resourceType {
				continue
			}
			campaignIDs, err := p.resolveCampaigns(ctx, cfg, account.CustomerID, resourceType, resourceName)
			if err != nil || len(campaignIDs) == 0 {
				if err == nil {
					err = errors.New("referenced resource campaign could not be determined")
				}
				return err
			}
			for _, campaignID := range campaignIDs {
				if err := requireCampaign(account, campaignID, true); err != nil {
					return err
				}
			}
			continue
		}

		return fmt.Errorf("referenced Google Ads resource collection %s is not supported by the gateway policy", resourceCollection)
	}
	return nil
}

func customerResourceReferences(value any) []string {
	var references []string
	var walk func(any)
	walk = func(current any) {
		switch typed := current.(type) {
		case string:
			if strings.HasPrefix(typed, "customers/") {
				references = append(references, typed)
			}
		case map[string]any:
			for _, child := range typed {
				walk(child)
			}
		case []any:
			for _, child := range typed {
				walk(child)
			}
		}
	}
	walk(value)
	return uniqueStrings(references)
}

func parseCustomerResourceName(value string) (customerID, collection, identifier string, ok bool) {
	parts := strings.Split(value, "/")
	if len(parts) != 4 || parts[0] != "customers" ||
		!isNonzeroPositiveID(parts[1]) ||
		!customerResourceCollectionPattern.MatchString(parts[2]) ||
		!customerResourceIdentifierPattern.MatchString(parts[3]) {
		return "", "", "", false
	}
	return parts[1], parts[2], parts[3], true
}

func requireCampaign(account AccountPolicy, campaignID string, write bool) error {
	if !isNonzeroPositiveID(campaignID) {
		return errors.New("campaign identifier is invalid")
	}
	if account.AllCampaignsReadWrite {
		return nil
	}
	policy, ok := account.Campaigns[campaignID]
	if !ok || policy.CampaignID != campaignID {
		return fmt.Errorf("campaign %s is not permitted", campaignID)
	}
	if write && !policy.Write {
		return fmt.Errorf("campaign %s is read-only", campaignID)
	}
	if !write && !policy.Read && !policy.Write {
		return fmt.Errorf("campaign %s is not readable", campaignID)
	}
	return nil
}

func campaignIDFromResource(resourceName string) string {
	_, collection, identifier, ok := parseCustomerResourceName(resourceName)
	if !ok || collection != "campaigns" || !isNonzeroPositiveID(identifier) {
		return ""
	}
	return identifier
}

func (p *PolicyEngine) resolveCampaigns(ctx context.Context, cfg PersistentConfig, customerID, resourceType, resourceName string) ([]string, error) {
	if owner, ok := p.store.Ownership(resourceName); ok && owner.CustomerID == customerID {
		if owner.ResourceType != resourceType {
			return nil, errors.New("stored resource ownership type does not match the requested resource")
		}
		if owner.CampaignID == "" {
			return nil, nil
		}
		return []string{owner.CampaignID}, nil
	}
	field := ""
	from := resourceType
	switch resourceType {
	case "ad_group", "ad_group_ad", "ad_group_criterion", "campaign_criterion", "asset_group":
		field = resourceType + ".resource_name"
	case "campaign_budget":
		from = "campaign"
		field = "campaign.campaign_budget"
	case "campaign_label", "campaign_asset":
		if id := compositeFirstID(resourceName); id != "" {
			return []string{id}, nil
		}
	case "ad_group_label", "ad_group_asset", "asset_group_asset":
		parentType := "ad_group"
		if resourceType == "asset_group_asset" {
			parentType = "asset_group"
		}
		if id := compositeFirstID(resourceName); id != "" {
			parentResource := fmt.Sprintf("customers/%s/%ss/%s", customerID, camelPlural(parentType), id)
			return p.resolveCampaigns(ctx, cfg, customerID, parentType, parentResource)
		}
	}
	if field == "" || strings.ContainsAny(resourceName, "'\\\r\n") {
		return nil, errors.New("resource ownership cannot be safely resolved")
	}
	resultPath := campaignResolutionResultPaths[resourceType]
	if len(resultPath) == 0 {
		return nil, errors.New("resource ownership response cannot be safely validated")
	}
	query := fmt.Sprintf("SELECT campaign.id, %s FROM %s WHERE %s = '%s'", field, from, field, resourceName)
	rows, err := p.google.search(ctx, cfg, customerID, query)
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, row := range rows {
		if nestedString(row, resultPath...) != resourceName {
			return nil, errors.New("Google returned a mismatched resource while resolving campaign ownership")
		}
		campaign, _ := row["campaign"].(map[string]any)
		id := stringValue(campaign["id"], "")
		if !isNonzeroPositiveID(id) {
			return nil, errors.New("Google returned an invalid campaign ID while resolving resource ownership")
		}
		ids = append(ids, id)
	}
	return uniqueStrings(ids), nil
}

func compositeFirstID(resourceName string) string {
	_, _, identifier, ok := parseCustomerResourceName(resourceName)
	if !ok {
		return ""
	}
	first := strings.Split(identifier, "~")[0]
	if !isNonzeroPositiveID(first) {
		return ""
	}
	return first
}

func camelPlural(resourceType string) string {
	switch resourceType {
	case "ad_group":
		return "adGroup"
	case "asset_group":
		return "assetGroup"
	default:
		return resourceType
	}
}

func uniqueStrings(values []string) []string {
	seen := map[string]bool{}
	var output []string
	for _, value := range values {
		if value != "" && !seen[value] {
			seen[value] = true
			output = append(output, value)
		}
	}
	sort.Strings(output)
	return output
}

func (p *PolicyEngine) RecordSuccess(cfg PersistentConfig, decision PolicyDecision, response UpstreamResponse) error {
	if !decision.Write || response.Status < 200 || response.Status >= 300 {
		return nil
	}
	// Google can return generated resource names for validate-only requests,
	// even though nothing was actually persisted. Never turn those names into
	// gateway ownership records or campaign permissions.
	if validateOnly, _ := decision.Request.Body["validateOnly"].(bool); validateOnly {
		return nil
	}
	var payload any
	decoder := json.NewDecoder(strings.NewReader(string(response.Body)))
	decoder.UseNumber()
	if err := decoder.Decode(&payload); err != nil {
		return fmt.Errorf("Google returned malformed mutation success JSON: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return fmt.Errorf("Google returned malformed mutation success JSON: %w", err)
	}
	resourceNames := extractResultResourceNames(payload)
	if len(resourceNames) != len(decision.Mutations) {
		return fmt.Errorf("Google returned %d mutation results for %d authorized operations", len(resourceNames), len(decision.Mutations))
	}
	partialFailure, _ := decision.Request.Body["partialFailure"].(bool)
	root, _ := payload.(map[string]any)
	partialFailureError, hasPartialFailureError := root["partialFailureError"].(map[string]any)
	hasPartialFailureError = hasPartialFailureError && len(partialFailureError) > 0
	for index, mutation := range decision.Mutations {
		resourceName := ""
		if index < len(resourceNames) {
			resourceName = resourceNames[index]
		}
		if resourceName == "" {
			if mutation.Action == "create" && !(partialFailure && hasPartialFailureError) {
				return fmt.Errorf("Google accepted a %s create without returning its resource name", mutation.ResourceType)
			}
			continue
		}
		if err := validateReturnedResourceName(decision.CustomerID, mutation.ResourceType, resourceName); err != nil {
			return err
		}
	}
	createdByTemp := map[string]string{}
	for index, mutation := range decision.Mutations {
		if mutation.Action != "create" || index >= len(resourceNames) || resourceNames[index] == "" {
			continue
		}
		createdByTemp[mutation.TempName] = resourceNames[index]
	}

	current, err := p.store.Config()
	if err != nil {
		return err
	}
	account, ok := current.Accounts[decision.CustomerID]
	if !ok || account.CustomerID != decision.CustomerID || account.IsManager {
		return errors.New("the authorized advertiser account configuration changed before mutation state could be recorded")
	}
	pendingOwners := map[string]ResourceOwnership{}
	lookupOwner := func(resourceName string) (ResourceOwnership, bool) {
		if owner, found := pendingOwners[resourceName]; found {
			return owner, true
		}
		return p.store.Ownership(resourceName)
	}
	for index, mutation := range decision.Mutations {
		if mutation.Action != "create" || index >= len(resourceNames) || resourceNames[index] == "" {
			continue
		}
		resourceName := resourceNames[index]
		campaignID := mutation.CampaignID
		if mutation.ResourceType == "campaign" {
			campaignID = campaignIDFromResource(resourceName)
			if campaignID == "" {
				continue
			}
			if account.Campaigns == nil {
				account.Campaigns = map[string]CampaignPolicy{}
			}
			account.Campaigns[campaignID] = CampaignPolicy{
				CampaignID: campaignID,
				Name:       stringValue(mutation.Value["name"], campaignID),
				Status:     stringValue(mutation.Value["status"], "PAUSED"),
				Read:       true,
				Write:      true,
			}
		}
		if strings.HasPrefix(campaignID, "__new_campaign__:") {
			temporaryName := strings.TrimPrefix(campaignID, "__new_campaign__:")
			campaignID = campaignIDFromResource(createdByTemp[temporaryName])
		} else if campaignID == "__new_campaign__" {
			for _, actual := range createdByTemp {
				if id := campaignIDFromResource(actual); id != "" {
					campaignID = id
					break
				}
			}
		}
		owner := ResourceOwnership{ResourceName: resourceName, CustomerID: decision.CustomerID, CampaignID: campaignID, ResourceType: mutation.ResourceType}
		pendingOwners[resourceName] = owner
		if mutation.ResourceType == "campaign" {
			if budget := stringValue(mutation.Value["campaignBudget"], ""); budget != "" {
				if actual, ok := createdByTemp[budget]; ok {
					budget = actual
				}
				if budgetOwner, ok := lookupOwner(budget); ok {
					budgetOwner.CampaignID = campaignID
					pendingOwners[budget] = budgetOwner
				}
			}
		}
	}
	// Tie every newly referenced account-scoped resource to the campaign that
	// consumed it. This prevents a later campaign revocation from leaving an
	// unattached ownership record that could still authorize reads.
	for index, mutation := range decision.Mutations {
		if index >= len(resourceNames) || resourceNames[index] == "" {
			continue
		}
		campaignID := mutation.CampaignID
		if strings.HasPrefix(campaignID, "__new_campaign__:") {
			campaignID = campaignIDFromResource(createdByTemp[strings.TrimPrefix(campaignID, "__new_campaign__:")])
		} else if campaignID == "__new_campaign__" {
			for _, actual := range createdByTemp {
				if id := campaignIDFromResource(actual); id != "" {
					campaignID = id
					break
				}
			}
		}
		if !isNonzeroPositiveID(campaignID) {
			continue
		}
		for _, reference := range customerResourceReferences(mutation.Value) {
			if actual, ok := createdByTemp[reference]; ok {
				reference = actual
			}
			owner, ok := lookupOwner(reference)
			if !ok || owner.CustomerID != decision.CustomerID || owner.CampaignID != "" {
				continue
			}
			if _, sensitive := ownedReadResources[owner.ResourceType]; !sensitive {
				continue
			}
			owner.CampaignID = campaignID
			pendingOwners[reference] = owner
		}
	}
	current.Accounts[decision.CustomerID] = account
	owners := make([]ResourceOwnership, 0, len(pendingOwners))
	for _, owner := range pendingOwners {
		owners = append(owners, owner)
	}
	return p.store.SaveConfigAndOwnership(current, owners)
}

func validateReturnedResourceName(customerID, resourceType, resourceName string) error {
	expectedCollection := resourceCollections[resourceType]
	returnedCustomerID, collection, identifier, ok := parseCustomerResourceName(resourceName)
	if !ok || returnedCustomerID != customerID || collection != expectedCollection {
		return fmt.Errorf("Google returned a %s resource name outside the authorized customer or resource type", resourceType)
	}
	shape, exists := resourceIdentifierShapes[resourceType]
	components := strings.Split(identifier, "~")
	if !exists || len(components) != shape.components {
		return fmt.Errorf("Google returned a %s resource name with an invalid identifier shape", resourceType)
	}
	if shape.lastIsEnum {
		if !resourceEnumPattern.MatchString(components[len(components)-1]) {
			return fmt.Errorf("Google returned a %s resource name with an invalid field type", resourceType)
		}
		components = components[:len(components)-1]
	}
	for _, component := range components {
		if !isNonzeroPositiveID(component) {
			return fmt.Errorf("Google returned a %s resource name with a non-positive ID", resourceType)
		}
	}
	return nil
}

func firstResourceName(value any) string {
	var found string
	var walk func(any)
	walk = func(current any) {
		if found != "" {
			return
		}
		switch typed := current.(type) {
		case map[string]any:
			if value, ok := typed["resourceName"].(string); ok && strings.HasPrefix(value, "customers/") {
				found = value
				return
			}
			for _, child := range typed {
				walk(child)
			}
		case []any:
			for _, child := range typed {
				walk(child)
			}
		}
	}
	walk(value)
	return found
}

func extractResultResourceNames(value any) []string {
	root, ok := value.(map[string]any)
	if !ok {
		return nil
	}
	// Resource-specific mutate services return `results`. The generic atomic
	// GoogleAdsService.Mutate endpoint returns `mutateOperationResponses`.
	// Preserve array positions for both shapes so ownership stays aligned with
	// the request operations, including partial-failure responses.
	results, ok := root["results"].([]any)
	if !ok {
		results, ok = root["mutateOperationResponses"].([]any)
	}
	if !ok {
		return nil
	}
	output := make([]string, len(results))
	for index, result := range results {
		output[index] = firstResourceName(result)
	}
	return output
}

func decisionAudit(actor string, decision PolicyDecision, status int, allowed bool, reason string) AuditEvent {
	return AuditEvent{
		At:           time.Now().UTC(),
		Actor:        actor,
		Action:       decision.Request.Method + " " + decision.Request.Path,
		CustomerID:   decision.CustomerID,
		CampaignIDs:  decision.CampaignIDs,
		ResourceType: decision.ResourceType,
		Allowed:      allowed,
		Status:       status,
		Reason:       reason,
	}
}
