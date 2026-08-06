package gateway

import (
	"strings"
	"testing"
	"time"
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
