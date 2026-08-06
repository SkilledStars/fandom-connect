package gateway

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"
)

var (
	bucketConfig      = []byte("config")
	bucketAPIKeys     = []byte("api_keys")
	bucketOwnership   = []byte("ownership")
	bucketIdempotency = []byte("idempotency")
	bucketAudit       = []byte("audit")
	configKey         = []byte("current")
)

type Store struct {
	db   *bolt.DB
	aead cipher.AEAD
	now  func() time.Time
}

func OpenStore(path string, masterKey []byte) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create data directory: %w", err)
	}
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, fmt.Errorf("initialize encryption: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("initialize authenticated encryption: %w", err)
	}
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 5 * time.Second, NoFreelistSync: false})
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	store := &Store{db: db, aead: aead, now: time.Now}
	if err := store.db.Update(func(tx *bolt.Tx) error {
		for _, name := range [][]byte{bucketConfig, bucketAPIKeys, bucketOwnership, bucketIdempotency, bucketAudit} {
			if _, err := tx.CreateBucketIfNotExists(name); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		db.Close()
		return nil, fmt.Errorf("initialize database: %w", err)
	}
	if _, err := store.Config(); errors.Is(err, errNotConfigured) {
		id, randomErr := randomBytes(16)
		if randomErr != nil {
			db.Close()
			return nil, randomErr
		}
		initial := PersistentConfig{
			GatewayID:   "fgw_" + base64.RawURLEncoding.EncodeToString(id),
			DisplayName: "Fandom Google Ads Gateway",
			Accounts:    map[string]AccountPolicy{},
			UpdatedAt:   store.now().UTC(),
		}
		if err := store.SaveConfig(initial); err != nil {
			db.Close()
			return nil, err
		}
	} else if err != nil {
		db.Close()
		return nil, err
	}
	return store, nil
}

var errNotConfigured = errors.New("gateway configuration is missing")

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) seal(plaintext []byte) ([]byte, error) {
	nonce, err := randomBytes(s.aead.NonceSize())
	if err != nil {
		return nil, err
	}
	return s.aead.Seal(nonce, nonce, plaintext, []byte("fandom-google-ads-gateway:v1")), nil
}

func (s *Store) open(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < s.aead.NonceSize() {
		return nil, errors.New("encrypted database record is malformed")
	}
	nonce := ciphertext[:s.aead.NonceSize()]
	return s.aead.Open(nil, nonce, ciphertext[s.aead.NonceSize():], []byte("fandom-google-ads-gateway:v1"))
}

func (s *Store) Config() (PersistentConfig, error) {
	var cfg PersistentConfig
	err := s.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket(bucketConfig).Get(configKey)
		if len(raw) == 0 {
			return errNotConfigured
		}
		plaintext, err := s.open(append([]byte(nil), raw...))
		if err != nil {
			return err
		}
		return json.Unmarshal(plaintext, &cfg)
	})
	if cfg.Accounts == nil {
		cfg.Accounts = map[string]AccountPolicy{}
	}
	return cfg, err
}

func (s *Store) SaveConfig(cfg PersistentConfig) error {
	cfg.UpdatedAt = s.now().UTC()
	if cfg.Accounts == nil {
		cfg.Accounts = map[string]AccountPolicy{}
	}
	plaintext, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	sealed, err := s.seal(plaintext)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketConfig).Put(configKey, sealed)
	})
}

func (s *Store) ClearDerivedGoogleState() error {
	return s.db.Update(func(tx *bolt.Tx) error {
		for _, name := range [][]byte{bucketOwnership, bucketIdempotency} {
			if err := tx.DeleteBucket(name); err != nil && !errors.Is(err, bolt.ErrBucketNotFound) {
				return err
			}
			if _, err := tx.CreateBucket(name); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Store) CreateAPIKey(name string) (string, APIKeyRecord, error) {
	idBytes, err := randomBytes(9)
	if err != nil {
		return "", APIKeyRecord{}, err
	}
	secret, err := randomBytes(32)
	if err != nil {
		return "", APIKeyRecord{}, err
	}
	id := base64.RawURLEncoding.EncodeToString(idBytes)
	plaintext := "fgw_live_" + id + "_" + base64.RawURLEncoding.EncodeToString(secret)
	hash := sha256.Sum256([]byte(plaintext))
	record := APIKeyRecord{
		ID:        id,
		Name:      strings.TrimSpace(name),
		Hash:      base64.RawStdEncoding.EncodeToString(hash[:]),
		CreatedAt: s.now().UTC(),
	}
	if record.Name == "" {
		record.Name = "Fandom"
	}
	raw, _ := json.Marshal(record)
	err = s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketAPIKeys).Put([]byte(id), raw)
	})
	return plaintext, record, err
}

func (s *Store) VerifyAPIKey(plaintext string) (APIKeyRecord, bool) {
	const prefix = "fgw_live_"
	const idLength = 12 // 9 random bytes encoded with base64.RawURLEncoding.
	if !strings.HasPrefix(plaintext, prefix) || len(plaintext) <= len(prefix)+idLength+1 {
		return APIKeyRecord{}, false
	}
	remainder := strings.TrimPrefix(plaintext, prefix)
	if remainder[idLength] != '_' {
		return APIKeyRecord{}, false
	}
	id := remainder[:idLength]
	var record APIKeyRecord
	err := s.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket(bucketAPIKeys).Get([]byte(id))
		if len(raw) == 0 {
			return errors.New("not found")
		}
		return json.Unmarshal(raw, &record)
	})
	if err != nil {
		return APIKeyRecord{}, false
	}
	expected, err := base64.RawStdEncoding.DecodeString(record.Hash)
	if err != nil {
		return APIKeyRecord{}, false
	}
	actual := sha256.Sum256([]byte(plaintext))
	return record, subtle.ConstantTimeCompare(expected, actual[:]) == 1
}

func (s *Store) ListAPIKeys() ([]APIKeyRecord, error) {
	var records []APIKeyRecord
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketAPIKeys).ForEach(func(_, value []byte) error {
			var record APIKeyRecord
			if err := json.Unmarshal(value, &record); err != nil {
				return err
			}
			record.Hash = ""
			records = append(records, record)
			return nil
		})
	})
	sort.Slice(records, func(i, j int) bool { return records[i].CreatedAt.After(records[j].CreatedAt) })
	return records, err
}

func (s *Store) RevokeAPIKey(id string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketAPIKeys).Delete([]byte(id))
	})
}

func (s *Store) PutOwnership(owner ResourceOwnership) error {
	if owner.ResourceName == "" || owner.CustomerID == "" {
		return errors.New("resource ownership is incomplete")
	}
	owner.CreatedAt = s.now().UTC()
	raw, _ := json.Marshal(owner)
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketOwnership).Put([]byte(owner.ResourceName), raw)
	})
}

func (s *Store) Ownership(resourceName string) (ResourceOwnership, bool) {
	var owner ResourceOwnership
	err := s.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket(bucketOwnership).Get([]byte(resourceName))
		if len(raw) == 0 {
			return errors.New("not found")
		}
		return json.Unmarshal(raw, &owner)
	})
	return owner, err == nil
}

func (s *Store) OwnedResources(customerID, resourceType string) ([]string, error) {
	var values []string
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketOwnership).ForEach(func(_, raw []byte) error {
			var owner ResourceOwnership
			if err := json.Unmarshal(raw, &owner); err != nil {
				return err
			}
			if owner.CustomerID == customerID && owner.ResourceType == resourceType {
				values = append(values, owner.ResourceName)
			}
			return nil
		})
	})
	sort.Strings(values)
	return values, err
}

func (s *Store) GetIdempotency(key, requestHash string) (IdempotencyRecord, bool, error) {
	var record IdempotencyRecord
	err := s.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket(bucketIdempotency).Get([]byte(key))
		if len(raw) == 0 {
			return nil
		}
		return json.Unmarshal(raw, &record)
	})
	if err != nil || record.Key == "" {
		return record, false, err
	}
	if record.RequestHash != requestHash {
		return record, false, errors.New("idempotency key was already used for a different request")
	}
	if s.now().Sub(record.CreatedAt) > 24*time.Hour {
		return IdempotencyRecord{}, false, nil
	}
	return record, true, nil
}

func (s *Store) PutIdempotency(record IdempotencyRecord) error {
	if len(record.Body) > 2<<20 {
		return errors.New("idempotency response exceeded the 2 MB storage limit")
	}
	raw, _ := json.Marshal(record)
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(bucketIdempotency)
		if err := bucket.Put([]byte(record.Key), raw); err != nil {
			return err
		}
		cutoff := s.now().Add(-24 * time.Hour)
		cursor := bucket.Cursor()
		for key, value := cursor.First(); key != nil; key, value = cursor.Next() {
			var existing IdempotencyRecord
			if json.Unmarshal(value, &existing) == nil && existing.CreatedAt.Before(cutoff) {
				if err := cursor.Delete(); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

func (s *Store) AppendAudit(event AuditEvent) error {
	if event.ID == "" {
		id, err := randomBytes(12)
		if err != nil {
			return err
		}
		event.ID = base64.RawURLEncoding.EncodeToString(id)
	}
	if event.At.IsZero() {
		event.At = s.now().UTC()
	}
	raw, _ := json.Marshal(event)
	key := []byte(event.At.Format("20060102T150405.000000000Z07:00") + ":" + event.ID)
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(bucketAudit)
		if err := bucket.Put(key, raw); err != nil {
			return err
		}
		for bucket.Stats().KeyN > 5000 {
			first, _ := bucket.Cursor().First()
			if first == nil {
				break
			}
			if err := bucket.Delete(first); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Store) RecentAudit(limit int) ([]AuditEvent, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	var events []AuditEvent
	err := s.db.View(func(tx *bolt.Tx) error {
		cursor := tx.Bucket(bucketAudit).Cursor()
		for key, value := cursor.Last(); key != nil && len(events) < limit; key, value = cursor.Prev() {
			var event AuditEvent
			if err := json.Unmarshal(value, &event); err != nil {
				return err
			}
			events = append(events, event)
		}
		return nil
	})
	return events, err
}
