package gateway

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	key := make([]byte, 32)
	for index := range key {
		key[index] = byte(index + 1)
	}
	store, err := OpenStore(t.TempDir()+"/gateway.db", key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func TestStoreEncryptsConfigurationAtRest(t *testing.T) {
	store := testStore(t)
	cfg, err := store.Config()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Google = &GoogleCredential{Mode: "oauth", DeveloperToken: "developer-secret", LoginCustomerID: "1234567890", OAuthClientID: "client", OAuthClientSecret: "client-secret", OAuthRefreshToken: "refresh-secret"}
	if err := store.SaveConfig(cfg); err != nil {
		t.Fatal(err)
	}
	data, readErr := readFile(store.db.Path())
	if readErr != nil {
		t.Fatal(readErr)
	}
	text := string(data)
	for _, secret := range []string{"developer-secret", "client-secret", "refresh-secret"} {
		if strings.Contains(text, secret) {
			t.Fatalf("database leaked plaintext secret %q", secret)
		}
	}
}

func TestStoreEncryptsGoogleDerivedDataAtRest(t *testing.T) {
	store := testStore(t)
	resourceName := "customers/1234567890/customAudiences/987654321"
	responseMarker := "sensitive-google-response-marker"
	auditMarker := "sensitive-audit-marker"
	if err := store.PutOwnership(ResourceOwnership{
		ResourceName: resourceName,
		CustomerID:   "1234567890",
		CampaignID:   "111",
		ResourceType: "custom_audience",
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.PutIdempotency(IdempotencyRecord{
		Key:         "encrypted-record-test",
		RequestHash: "request-hash",
		Status:      200,
		Body:        []byte(responseMarker),
		CreatedAt:   time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.AppendAudit(AuditEvent{Actor: "test", Action: auditMarker, Allowed: true, Status: 200}); err != nil {
		t.Fatal(err)
	}

	data, err := readFile(store.db.Path())
	if err != nil {
		t.Fatal(err)
	}
	for _, plaintext := range []string{resourceName, responseMarker, auditMarker} {
		if strings.Contains(string(data), plaintext) {
			t.Fatalf("database leaked derived Google data %q", plaintext)
		}
	}
	if _, ok := store.Ownership(resourceName); !ok {
		t.Fatal("encrypted ownership record could not be read")
	}
	if cached, found, err := store.GetIdempotency("encrypted-record-test", "request-hash"); err != nil || !found || string(cached.Body) != responseMarker {
		t.Fatalf("encrypted idempotency record could not be read: found=%v err=%v", found, err)
	}
	if events, err := store.RecentAudit(1); err != nil || len(events) != 1 || events[0].Action != auditMarker {
		t.Fatalf("encrypted audit record could not be read: events=%#v err=%v", events, err)
	}
}

func TestStoreMigratesLegacyDerivedDataWithoutLosingIt(t *testing.T) {
	key := make([]byte, 32)
	for index := range key {
		key[index] = byte(index + 1)
	}
	path := t.TempDir() + "/gateway.db"
	store, err := OpenStore(path, key)
	if err != nil {
		t.Fatal(err)
	}
	resourceName := "customers/1234567890/labels/987654321"
	owner := ResourceOwnership{ResourceName: resourceName, CustomerID: "1234567890", CampaignID: "111", ResourceType: "label"}
	idempotency := IdempotencyRecord{Key: "legacy-idempotency", RequestHash: "legacy-request", Status: 200, Body: []byte("legacy-response"), CreatedAt: time.Now()}
	audit := AuditEvent{ID: "legacy-audit", At: time.Now().UTC(), Actor: "legacy", Action: "legacy-action", Allowed: true, Status: 200}
	if err := store.db.Update(func(tx *bolt.Tx) error {
		ownerRaw, _ := json.Marshal(owner)
		if err := tx.Bucket(bucketOwnership).Put([]byte(resourceName), ownerRaw); err != nil {
			return err
		}
		idempotencyRaw, _ := json.Marshal(idempotency)
		if err := tx.Bucket(bucketIdempotency).Put([]byte(idempotency.Key), idempotencyRaw); err != nil {
			return err
		}
		auditRaw, _ := json.Marshal(audit)
		return tx.Bucket(bucketAudit).Put([]byte("legacy-audit-key"), auditRaw)
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	migrated, err := OpenStore(path, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = migrated.Close() })
	if saved, ok := migrated.Ownership(resourceName); !ok || saved.CampaignID != "111" {
		t.Fatalf("legacy ownership was lost: %#v", saved)
	}
	if saved, found, err := migrated.GetIdempotency(idempotency.Key, idempotency.RequestHash); err != nil || !found || string(saved.Body) != "legacy-response" {
		t.Fatalf("legacy idempotency was lost: found=%v value=%#v err=%v", found, saved, err)
	}
	if events, err := migrated.RecentAudit(10); err != nil || len(events) != 1 || events[0].Action != audit.Action {
		t.Fatalf("legacy audit was lost: events=%#v err=%v", events, err)
	}
	if err := migrated.db.View(func(tx *bolt.Tx) error {
		ownership := tx.Bucket(bucketOwnership)
		if ownership.Get([]byte(resourceName)) != nil {
			return fmt.Errorf("legacy plaintext ownership key remained active")
		}
		for _, record := range []struct {
			bucket []byte
			key    []byte
		}{
			{bucketOwnership, ownershipKey(resourceName)},
			{bucketIdempotency, []byte(idempotency.Key)},
			{bucketAudit, []byte("legacy-audit-key")},
		} {
			if raw := tx.Bucket(record.bucket).Get(record.key); !bytes.HasPrefix(raw, recordPrefix) {
				return fmt.Errorf("legacy record was not encrypted")
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestAPIKeysAreHashedAndRevocable(t *testing.T) {
	store := testStore(t)
	plaintext, record, err := store.CreateAPIKey("Fandom")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(plaintext, "fgw_live_") || strings.Contains(record.Hash, plaintext) {
		t.Fatal("API key format or hash is invalid")
	}
	verified, ok := store.VerifyAPIKey(plaintext)
	if !ok || verified.ID != record.ID {
		t.Fatal("valid API key did not verify")
	}
	if _, ok := store.VerifyAPIKey(plaintext + "x"); ok {
		t.Fatal("modified API key verified")
	}
	if err := store.RevokeAPIKey(record.ID); err != nil {
		t.Fatal(err)
	}
	if _, ok := store.VerifyAPIKey(plaintext); ok {
		t.Fatal("revoked API key verified")
	}
}

func TestAPIKeyNamesAreRequiredAndBounded(t *testing.T) {
	store := testStore(t)
	for _, name := range []string{"", "   ", strings.Repeat("x", 121)} {
		if _, _, err := store.CreateAPIKey(name); err == nil {
			t.Fatalf("CreateAPIKey accepted invalid name %q", name)
		}
	}
	if _, record, err := store.CreateAPIKey("  Fandom  "); err != nil {
		t.Fatal(err)
	} else if record.Name != "Fandom" {
		t.Fatalf("API key name was not normalized: %q", record.Name)
	}
}

func TestIdempotencyRejectsKeyReuseForDifferentRequest(t *testing.T) {
	store := testStore(t)
	record := IdempotencyRecord{Key: "0123456789abcdef", RequestHash: "first", Status: 200, Body: []byte(`{"ok":true}`), CreatedAt: time.Now()}
	if err := store.PutIdempotency(record); err != nil {
		t.Fatal(err)
	}
	if _, found, err := store.GetIdempotency(record.Key, "first"); err != nil || !found {
		t.Fatalf("cached response missing: found=%v err=%v", found, err)
	}
	if _, _, err := store.GetIdempotency(record.Key, "different"); err == nil {
		t.Fatal("idempotency key reuse was accepted")
	}
}

func TestIdempotencyCanReplayAnyAcceptedUpstreamResponseSize(t *testing.T) {
	store := testStore(t)
	body := make([]byte, (2<<20)+1)
	record := IdempotencyRecord{Key: "large-response-key", RequestHash: "large", Status: 200, Body: body, CreatedAt: time.Now()}
	if err := store.PutIdempotency(record); err != nil {
		t.Fatalf("an accepted upstream response could not be cached for safe replay: %v", err)
	}
	cached, found, err := store.GetIdempotency(record.Key, record.RequestHash)
	if err != nil || !found || len(cached.Body) != len(body) {
		t.Fatalf("large cached response was not replayable: found=%v size=%d err=%v", found, len(cached.Body), err)
	}
}

func TestClearDerivedGoogleStateKeepsKeysButRemovesOwnership(t *testing.T) {
	store := testStore(t)
	key, _, err := store.CreateAPIKey("Fandom")
	if err != nil {
		t.Fatal(err)
	}
	resource := "customers/1234567890/labels/123"
	if err := store.PutOwnership(ResourceOwnership{ResourceName: resource, CustomerID: "1234567890", ResourceType: "label"}); err != nil {
		t.Fatal(err)
	}
	if err := store.ClearDerivedGoogleState(); err != nil {
		t.Fatal(err)
	}
	if _, ok := store.Ownership(resource); ok {
		t.Fatal("resource ownership survived credential reset")
	}
	if _, ok := store.VerifyAPIKey(key); !ok {
		t.Fatal("Fandom API key was unexpectedly revoked")
	}
}

func TestGoogleIdentityChangeCommitsConfigAndDerivedStateAsOneBoundary(t *testing.T) {
	store := testStore(t)
	key, _, err := store.CreateAPIKey("Fandom")
	if err != nil {
		t.Fatal(err)
	}
	resource := "customers/1234567890/labels/123"
	if err := store.PutOwnership(ResourceOwnership{ResourceName: resource, CustomerID: "1234567890", ResourceType: "label"}); err != nil {
		t.Fatal(err)
	}
	if err := store.PutIdempotency(IdempotencyRecord{Key: "identity-boundary", RequestHash: "old", Status: 200, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	cfg, err := store.Config()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Google = &GoogleCredential{Mode: "oauth", DeveloperToken: "new", LoginCustomerID: "9999999999", OAuthClientID: "new-client", OAuthClientSecret: "secret", OAuthRefreshToken: "refresh"}
	cfg.Accounts = map[string]AccountPolicy{}
	if err := store.SaveConfigClearingDerivedState(cfg); err != nil {
		t.Fatal(err)
	}
	saved, err := store.Config()
	if err != nil || saved.Google == nil || saved.Google.LoginCustomerID != "9999999999" || len(saved.Accounts) != 0 {
		t.Fatalf("new Google identity was not committed: %#v err=%v", saved, err)
	}
	if _, ok := store.Ownership(resource); ok {
		t.Fatal("old ownership survived a Google identity change")
	}
	if _, found, err := store.GetIdempotency("identity-boundary", "old"); err != nil || found {
		t.Fatalf("old idempotency state survived: found=%v err=%v", found, err)
	}
	if _, ok := store.VerifyAPIKey(key); !ok {
		t.Fatal("Fandom connection key was unexpectedly revoked")
	}
}
