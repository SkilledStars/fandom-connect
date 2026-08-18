package gateway

import (
	"reflect"
	"strings"
	"testing"
)

func TestExplicitCampaignIDsAcceptsOnlyPositiveBoundaries(t *testing.T) {
	tests := []struct {
		query string
		want  []string
	}{
		{
			`SELECT campaign.id FROM campaign WHERE campaign.id = 111`,
			[]string{"111"},
		},
		{
			`SELECT metrics.clicks FROM campaign WHERE segments.date DURING LAST_30_DAYS AND campaign.id IN (222, 111, 222) ORDER BY metrics.clicks DESC LIMIT 10`,
			[]string{"111", "222"},
		},
	}
	for _, test := range tests {
		got, err := explicitCampaignIDs(test.query)
		if err != nil {
			t.Fatalf("valid campaign boundary was rejected: %v\n%s", err, test.query)
		}
		if !reflect.DeepEqual(got, test.want) {
			t.Fatalf("unexpected campaign IDs: got %#v want %#v", got, test.want)
		}
	}
}

func TestExplicitCampaignIDsRejectsAmbiguousOrUnscopedQueries(t *testing.T) {
	queries := []string{
		`SELECT campaign.id FROM campaign`,
		`SELECT campaign.id FROM campaign WHERE campaign.status = 'ENABLED'`,
		`SELECT campaign.id FROM campaign WHERE campaign.id != 111`,
		`SELECT campaign.id FROM campaign WHERE campaign.id NOT IN (111)`,
		`SELECT campaign.id FROM campaign WHERE campaign.id = '111'`,
		`SELECT campaign.id FROM campaign WHERE campaign.id = -111`,
		`SELECT campaign.id FROM campaign WHERE campaign.id IN ()`,
		`SELECT campaign.id FROM campaign WHERE campaign.id IN (111,)`,
		`SELECT campaign.id FROM campaign WHERE campaign.id IN (111`,
		`SELECT campaign.id FROM campaign WHERE campaign.id = 111 OR campaign.id = 333`,
		`SELECT campaign.id FROM campaign WHERE campaign.id = 111 WHERE campaign.id = 222`,
		`SELECT campaign.id FROM campaign WHERE campaign.id = 111; SELECT customer.id FROM customer`,
		`SELECT campaign.id FROM campaign WHERE campaign.id = 111 -- hidden`,
		`SELECT campaign.id FROM campaign WHERE campaign.id = 111 /* hidden */`,
		`SELECT campaign.id FROM campaign WHERE NOT (campaign.id = 111)`,
		`SELECT campaign.id FROM campaign WHERE campaign.id = 111 | campaign.id = 333`,
	}
	for _, query := range queries {
		if _, err := explicitCampaignIDs(query); err == nil {
			t.Fatalf("unsafe query was accepted: %s", query)
		}
	}
}

func TestGAQLLexerIgnoresKeywordsAndFieldsInsideStrings(t *testing.T) {
	resource, _, err := gaqlResource(
		`SELECT campaign.id, campaign.name FROM campaign WHERE campaign.id = 111 AND campaign.name = 'FROM customer OR metrics.cost_micros'`,
	)
	if err != nil || resource != "campaign" {
		t.Fatalf("quoted text affected parsing: resource=%q err=%v", resource, err)
	}
	fields, err := selectedFields(
		`SELECT customer.id, customer.descriptive_name FROM customer WHERE customer.descriptive_name = 'metrics.cost_micros'`,
	)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"customer.descriptive_name", "customer.id"}
	if !reflect.DeepEqual(fields, want) {
		t.Fatalf("unexpected fields: got %#v want %#v", fields, want)
	}
	ids, err := explicitCampaignIDs(
		`SELECT campaign.id FROM campaign WHERE campaign.id = 111 AND campaign.name = 'WHERE campaign.id = 999 OR FROM customer'`,
	)
	if err != nil || !reflect.DeepEqual(ids, []string{"111"}) {
		t.Fatalf("quoted campaign syntax affected the boundary: ids=%#v err=%v", ids, err)
	}
}

func TestExactGAQLFiltersAreStrictAndIgnoreQuotedFieldNames(t *testing.T) {
	query := `SELECT custom_audience.resource_name FROM custom_audience WHERE custom_audience.resource_name IN ('customers/123/customAudiences/2', 'customers/123/customAudiences/1') AND custom_audience.description = 'custom_audience.id = 999'`
	resources, err := exactGAQLStringFilterValues(query, "custom_audience.resource_name")
	if err != nil {
		t.Fatal(err)
	}
	wantResources := []string{"customers/123/customAudiences/1", "customers/123/customAudiences/2"}
	if !reflect.DeepEqual(resources, wantResources) {
		t.Fatalf("unexpected exact resources: got %#v want %#v", resources, wantResources)
	}
	ids, err := exactGAQLNumericFilterValues(query, "custom_audience.id")
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 0 {
		t.Fatalf("quoted field text created a numeric boundary: %#v", ids)
	}

	unsafe := []string{
		`SELECT custom_audience.resource_name FROM custom_audience WHERE custom_audience.resource_name = 123`,
		`SELECT custom_audience.resource_name FROM custom_audience WHERE custom_audience.resource_name IN ()`,
		`SELECT custom_audience.resource_name FROM custom_audience WHERE custom_audience.resource_name IN ('one',)`,
		`SELECT custom_audience.resource_name FROM custom_audience WHERE custom_audience.id IN (1, '2')`,
	}
	for _, candidate := range unsafe {
		if _, err := exactGAQLStringFilterValues(candidate, "custom_audience.resource_name"); err == nil {
			if _, numericErr := exactGAQLNumericFilterValues(candidate, "custom_audience.id"); numericErr == nil {
				t.Fatalf("malformed exact filter was accepted: %s", candidate)
			}
		}
	}
}

func TestAddGAQLConditionPreservesExistingClauses(t *testing.T) {
	tests := []struct {
		query string
		want  string
	}{
		{
			`SELECT campaign.id FROM campaign ORDER BY campaign.id LIMIT 10`,
			`SELECT campaign.id FROM campaign WHERE campaign.id IN (111, 222) ORDER BY campaign.id LIMIT 10`,
		},
		{
			`SELECT campaign.id FROM campaign WHERE campaign.status = 'ENABLED' ORDER BY campaign.id`,
			`SELECT campaign.id FROM campaign WHERE campaign.status = 'ENABLED' AND campaign.id IN (111, 222) ORDER BY campaign.id`,
		},
		{
			`SELECT campaign.id FROM campaign WHERE campaign.name = 'ORDER BY campaign.id'`,
			`SELECT campaign.id FROM campaign WHERE campaign.name = 'ORDER BY campaign.id' AND campaign.id IN (111, 222)`,
		},
	}
	for _, test := range tests {
		got, err := addGAQLCondition(test.query, "campaign.id IN (111, 222)")
		if err != nil {
			t.Fatalf("query could not be narrowed: %v\n%s", err, test.query)
		}
		if got != test.want {
			t.Fatalf("unexpected rewrite:\n got: %s\nwant: %s", got, test.want)
		}
	}
}

func TestEnsureGAQLSelectedFieldAddsOnlyMissingField(t *testing.T) {
	query := `SELECT custom_audience.name FROM custom_audience WHERE custom_audience.name = 'FROM custom_audience'`
	rewritten, err := ensureGAQLSelectedField(query, "custom_audience.resource_name")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rewritten, "custom_audience.name, custom_audience.resource_name FROM custom_audience") {
		t.Fatalf("authorization field was not selected: %s", rewritten)
	}
	unchanged, err := ensureGAQLSelectedField(rewritten, "custom_audience.resource_name")
	if err != nil {
		t.Fatal(err)
	}
	if unchanged != rewritten {
		t.Fatalf("selected field was duplicated: %s", unchanged)
	}
}
