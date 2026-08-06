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

var readCampaignResources = map[string]string{
	"campaign":               "campaign.id",
	"ad_group":               "campaign.id",
	"ad_group_ad":            "campaign.id",
	"ad_group_ad_asset_view": "campaign.id",
	"ad_group_audience_view": "campaign.id",
	"ad_group_criterion":     "campaign.id",
	"age_range_view":         "campaign.id",
	"asset_group":            "campaign.id",
	"asset_group_asset":      "campaign.id",
	"campaign_asset":         "campaign.id",
	"campaign_criterion":     "campaign.id",
	"detail_placement_view":  "campaign.id",
	"display_keyword_view":   "campaign.id",
	"gender_view":            "campaign.id",
	"geographic_view":        "campaign.id",
	"keyword_view":           "campaign.id",
	"recommendation":         "campaign.id",
	"search_term_view":       "campaign.id",
	"topic_view":             "campaign.id",
}

var ownedReadResources = map[string]string{
	"asset":           "asset.resource_name",
	"audience":        "audience.resource_name",
	"campaign_budget": "campaign_budget.resource_name",
	"custom_audience": "custom_audience.resource_name",
	"label":           "label.resource_name",
}

var safeReferenceResources = map[string]bool{
	"detailed_demographic":        true,
	"life_event":                  true,
	"recommendation_subscription": true,
	"topic_constant":              true,
	"user_interest":               true,
}

var safeCustomerFields = map[string]bool{
	"customer.id":               true,
	"customer.descriptive_name": true,
	"customer.currency_code":    true,
	"customer.time_zone":        true,
	"customer.manager":          true,
	"customer.test_account":     true,
	"customer.status":           true,
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

type PolicyDecision struct {
	Request      ProxyRequest
	CustomerID   string
	Write        bool
	ResourceType string
	CampaignIDs  []string
	Mutations    []Mutation
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
		allowed := campaign.Read || campaign.Write
		if write {
			allowed = campaign.Write
		}
		if allowed && cleanIDPattern.MatchString(id) {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return ids
}

func (p *PolicyEngine) Authorize(ctx context.Context, cfg PersistentConfig, request ProxyRequest) (PolicyDecision, error) {
	request.Method = strings.ToUpper(strings.TrimSpace(request.Method))
	if request.Method != http.MethodGet && request.Method != http.MethodPost {
		return PolicyDecision{}, errors.New("only GET and POST Google Ads requests are accepted")
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
	decision := PolicyDecision{Request: request, CustomerID: customerID, ResourceType: service}

	switch {
	case service == "googleAds" && (action == "search" || action == "searchStream"):
		query, _ := request.Body["query"].(string)
		rewritten, campaigns, rewriteErr := p.authorizeQuery(account, customerID, query)
		if rewriteErr != nil {
			return PolicyDecision{}, rewriteErr
		}
		decision.Request.Body["query"] = rewritten
		decision.CampaignIDs = campaigns
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
		if len(allowedCampaignIDs(account, false)) == 0 && !account.AllowCreate {
			return PolicyDecision{}, errors.New("keyword planning requires at least one permitted campaign or campaign creation permission")
		}
		return decision, nil
	default:
		return PolicyDecision{}, errors.New("this Google Ads operation is not supported by the gateway policy")
	}
}

func (p *PolicyEngine) authorizeQuery(account AccountPolicy, customerID, query string) (string, []string, error) {
	resource, _, err := gaqlResource(query)
	if err != nil {
		return "", nil, err
	}
	readIDs := allowedCampaignIDs(account, false)
	if field, ok := readCampaignResources[resource]; ok {
		if len(readIDs) == 0 {
			return "", nil, errors.New("no campaigns in this account permit reads")
		}
		rewritten, rewriteErr := rewriteGAQL(query, numericInCondition(field, readIDs))
		return rewritten, readIDs, rewriteErr
	}
	if field, ok := ownedReadResources[resource]; ok {
		fields, fieldErr := selectedFields(query)
		if fieldErr != nil {
			return "", nil, fieldErr
		}
		for _, selected := range fields {
			if strings.HasPrefix(selected, "metrics.") || strings.HasPrefix(selected, "segments.") {
				return "", nil, errors.New("account-level resource metrics are not available through a campaign-scoped gateway")
			}
		}
		owned, ownedErr := p.store.OwnedResources(customerID, resource)
		if ownedErr != nil {
			return "", nil, ownedErr
		}
		rewritten, rewriteErr := rewriteGAQL(query, stringInCondition(field, owned))
		return rewritten, readIDs, rewriteErr
	}
	if resource == "customer" {
		fields, fieldErr := referencedFields(query)
		if fieldErr != nil {
			return "", nil, fieldErr
		}
		for _, field := range fields {
			if !safeCustomerFields[field] {
				return "", nil, fmt.Errorf("customer field %s is not available through a campaign-scoped gateway", field)
			}
		}
		return query, readIDs, nil
	}
	if safeReferenceResources[resource] {
		if len(readIDs) == 0 && !account.AllowCreate {
			return "", nil, errors.New("reference data requires a permitted campaign")
		}
		return query, readIDs, nil
	}
	return "", nil, fmt.Errorf("GAQL resource %s is not supported by the gateway policy", resource)
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
		campaignID, err := p.authorizeMutation(ctx, cfg, account, *mutation, temporaryResources)
		if err != nil {
			return PolicyDecision{}, fmt.Errorf("%s %s denied: %w", mutation.Action, mutation.ResourceType, err)
		}
		if mutation.ResourceType == "campaign" && mutation.Action == "create" && mutation.TempName != "" {
			campaignID = "__new_campaign__:" + mutation.TempName
		}
		mutation.CampaignID = campaignID
		if err := p.authorizeReferencedResources(account, *mutation, temporaryResources); err != nil {
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

func (p *PolicyEngine) authorizeMutation(ctx context.Context, cfg PersistentConfig, account AccountPolicy, mutation Mutation, temporaryResources map[string]temporaryResource) (string, error) {
	if mutation.Action == "create" {
		switch mutation.ResourceType {
		case "campaign":
			if !account.AllowCreate {
				return "", errors.New("creating campaigns is not enabled for this advertiser account")
			}
			return "__new_campaign__", nil
		case "campaign_budget":
			if !account.AllowCreate {
				return "", errors.New("creating campaign budgets requires campaign creation permission")
			}
			return "", nil
		case "custom_audience", "audience", "asset", "label":
			if !account.AllowCreate && len(allowedCampaignIDs(account, true)) == 0 {
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
	case "custom_audience", "audience", "asset", "label":
		owner, ok := p.store.Ownership(mutation.ResourceName)
		if !ok || owner.CustomerID != account.CustomerID || owner.ResourceType != mutation.ResourceType {
			return "", errors.New("the account-scoped resource was not created by this gateway")
		}
		if owner.CampaignID != "" {
			return owner.CampaignID, requireCampaign(account, owner.CampaignID, true)
		}
		return "", nil
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
	if owner, ok := p.store.Ownership(resourceName); ok && owner.CustomerID == account.CustomerID {
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

func (p *PolicyEngine) authorizeReferencedResources(account AccountPolicy, mutation Mutation, temporaryResources map[string]temporaryResource) error {
	var references []string
	var walk func(any)
	walk = func(value any) {
		switch typed := value.(type) {
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
	walk(mutation.Value)

	for _, resourceName := range uniqueStrings(references) {
		if resourceName == mutation.ResourceName || resourceName == mutation.TempName {
			continue
		}
		parts := strings.Split(resourceName, "/")
		if len(parts) < 4 || parts[0] != "customers" || normalizeCustomerID(parts[1]) != account.CustomerID {
			return errors.New("a referenced Google Ads resource belongs to a different advertiser account")
		}
		resourceCollection := parts[2]
		if resourceCollection == "campaigns" {
			if temporary, ok := temporaryResources[resourceName]; ok && temporary.ResourceType == "campaign" {
				if strings.HasPrefix(temporary.CampaignID, "__new_campaign__") && account.AllowCreate {
					continue
				}
			}
			if err := requireCampaign(account, normalizeCustomerID(parts[3]), true); err != nil {
				return err
			}
			continue
		}
		resourceType, sensitive := sensitiveReferencedResources[resourceCollection]
		if !sensitive {
			continue
		}
		if temporary, ok := temporaryResources[resourceName]; ok && temporary.ResourceType == resourceType {
			continue
		}
		owner, ok := p.store.Ownership(resourceName)
		if !ok || owner.CustomerID != account.CustomerID || owner.ResourceType != resourceType {
			return fmt.Errorf("referenced %s was not created by this gateway", resourceType)
		}
		if owner.CampaignID != "" {
			if err := requireCampaign(account, owner.CampaignID, true); err != nil {
				return err
			}
		}
	}
	return nil
}

func requireCampaign(account AccountPolicy, campaignID string, write bool) error {
	policy, ok := account.Campaigns[campaignID]
	if !ok {
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
	parts := strings.Split(resourceName, "/")
	if len(parts) < 4 || parts[len(parts)-2] != "campaigns" {
		return ""
	}
	return normalizeCustomerID(parts[len(parts)-1])
}

func (p *PolicyEngine) resolveCampaigns(ctx context.Context, cfg PersistentConfig, customerID, resourceType, resourceName string) ([]string, error) {
	if owner, ok := p.store.Ownership(resourceName); ok && owner.CustomerID == customerID {
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
	query := fmt.Sprintf("SELECT campaign.id FROM %s WHERE %s = '%s'", from, field, resourceName)
	rows, err := p.google.search(ctx, cfg, customerID, query)
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, row := range rows {
		campaign, _ := row["campaign"].(map[string]any)
		id := normalizeCustomerID(stringValue(campaign["id"], ""))
		if id != "" {
			ids = append(ids, id)
		}
	}
	return uniqueStrings(ids), nil
}

func compositeFirstID(resourceName string) string {
	parts := strings.Split(resourceName, "/")
	if len(parts) < 4 {
		return ""
	}
	composite := parts[len(parts)-1]
	return normalizeCustomerID(strings.Split(composite, "~")[0])
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
	var payload any
	decoder := json.NewDecoder(strings.NewReader(string(response.Body)))
	decoder.UseNumber()
	if err := decoder.Decode(&payload); err != nil {
		return nil
	}
	resourceNames := extractResultResourceNames(payload)
	if len(resourceNames) == 0 {
		return nil
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
	account := current.Accounts[decision.CustomerID]
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
		if err := p.store.PutOwnership(owner); err != nil {
			return err
		}
		if mutation.ResourceType == "campaign" {
			if budget := stringValue(mutation.Value["campaignBudget"], ""); budget != "" {
				if actual, ok := createdByTemp[budget]; ok {
					budget = actual
				}
				if budgetOwner, ok := p.store.Ownership(budget); ok {
					budgetOwner.CampaignID = campaignID
					_ = p.store.PutOwnership(budgetOwner)
				}
			}
		}
	}
	current.Accounts[decision.CustomerID] = account
	return p.store.SaveConfig(current)
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
	results, ok := root["results"].([]any)
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
