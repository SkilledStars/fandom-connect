package gateway

import (
	"strings"
	"testing"
)

func TestRewriteGAQLAddsCampaignConditionBeforeOrderAndLimit(t *testing.T) {
	query := `SELECT campaign.id, metrics.clicks FROM campaign WHERE segments.date DURING LAST_30_DAYS ORDER BY metrics.clicks DESC LIMIT 100`
	rewritten, err := rewriteGAQL(query, "campaign.id IN (123, 456)")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rewritten, "WHERE segments.date DURING LAST_30_DAYS AND (campaign.id IN (123, 456)) ORDER BY") {
		t.Fatalf("condition was not inserted safely: %s", rewritten)
	}
}

func TestRewriteGAQLCreatesWhereClause(t *testing.T) {
	query := `SELECT ad_group.id FROM ad_group LIMIT 10`
	rewritten, err := rewriteGAQL(query, "campaign.id IN (123)")
	if err != nil {
		t.Fatal(err)
	}
	if rewritten != `SELECT ad_group.id FROM ad_group WHERE campaign.id IN (123) LIMIT 10` {
		t.Fatalf("unexpected rewrite: %s", rewritten)
	}
}

func TestGAQLRejectsCommentsMultipleStatementsAndFakeFrom(t *testing.T) {
	queries := []string{
		`SELECT campaign.id FROM campaign; SELECT customer.id FROM customer`,
		`SELECT campaign.id FROM campaign -- hide the injected policy`,
		`SELECT campaign.id FROM campaign /* hide */`,
		`SELECT campaign.id, 'FROM customer' FROM campaign`,
	}
	for index, query := range queries {
		resource, _, err := gaqlResource(query)
		if index == 3 {
			if err != nil || resource != "campaign" {
				t.Fatalf("quoted FROM must be ignored, resource=%q err=%v", resource, err)
			}
			continue
		}
		if err == nil {
			t.Fatalf("unsafe query was accepted: %s", query)
		}
	}
}

func TestSelectedFieldsIgnoresStringContents(t *testing.T) {
	fields, err := selectedFields(`SELECT customer.id, customer.descriptive_name FROM customer WHERE customer.descriptive_name = 'metrics.cost_micros'`)
	if err != nil {
		t.Fatal(err)
	}
	if len(fields) != 2 || fields[0] != "customer.descriptive_name" || fields[1] != "customer.id" {
		t.Fatalf("unexpected fields: %#v", fields)
	}
}
