package models

import (
	"strings"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func testDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&User{}, &APIKeyPoolEntry{}, &Setting{}); err != nil {
		t.Fatal(err)
	}
	return db
}

// rawColumn reads a column straight from SQLite, bypassing GORM hooks, so we can
// prove the value is actually ciphertext on disk.
func rawColumn(t *testing.T, db *gorm.DB, table, col, id string) string {
	t.Helper()
	var v string
	if err := db.Table(table).Select(col).Where("id = ?", id).Scan(&v).Error; err != nil {
		t.Fatal(err)
	}
	return v
}

func TestUserKeyEncryptedAtRest(t *testing.T) {
	t.Setenv("CYP_DATA_KEY", "0123456789abcdef0123456789abcdef") // 32 bytes
	db := testDB(t)

	const secret = "sk-or-v1-supersecretkey-abcdef123456"
	u := User{Email: "a@b.c", Role: RoleClient, Status: UserActive, LLMAPIKey: secret}
	if err := db.Create(&u).Error; err != nil {
		t.Fatal(err)
	}
	// AfterSave must have decrypted the in-memory struct back to plaintext.
	if u.LLMAPIKey != secret {
		t.Fatalf("in-memory key not restored: got %q", u.LLMAPIKey)
	}
	// On disk it must be ciphertext.
	raw := rawColumn(t, db, "users", "llm_api_key", u.ID)
	if !strings.HasPrefix(raw, "enc:v1:") {
		t.Fatalf("key not encrypted at rest: %q", raw)
	}
	if strings.Contains(raw, secret) {
		t.Fatalf("plaintext key leaked into column: %q", raw)
	}
	// Reading back through GORM must transparently decrypt.
	var got User
	if err := db.First(&got, "id = ?", u.ID).Error; err != nil {
		t.Fatal(err)
	}
	if got.LLMAPIKey != secret {
		t.Fatalf("round-trip failed: got %q want %q", got.LLMAPIKey, secret)
	}
}

func TestPoolKeyEncryptedAtRest(t *testing.T) {
	t.Setenv("CYP_DATA_KEY", "0123456789abcdef0123456789abcdef")
	db := testDB(t)

	const secret = "sk-poolkey-987654321zyxwvu"
	e := APIKeyPoolEntry{Provider: "openrouter", KeyValue: secret, Active: true}
	if err := db.Create(&e).Error; err != nil {
		t.Fatal(err)
	}
	raw := rawColumn(t, db, "api_key_pool_entries", "key_value", e.ID)
	if !strings.HasPrefix(raw, "enc:v1:") || strings.Contains(raw, secret) {
		t.Fatalf("pool key not encrypted at rest: %q", raw)
	}
	var got APIKeyPoolEntry
	if err := db.First(&got, "id = ?", e.ID).Error; err != nil {
		t.Fatal(err)
	}
	if got.KeyValue != secret {
		t.Fatalf("pool round-trip failed: got %q", got.KeyValue)
	}
}

func TestEncryptExistingSecretsMigration(t *testing.T) {
	db := testDB(t)

	// Seed a plaintext row WITHOUT a data key (simulates a pre-encryption install).
	const secret = "sk-legacy-plaintext-key-000111222"
	u := User{Email: "legacy@b.c", Role: RoleClient, Status: UserActive, LLMAPIKey: secret}
	if err := db.Create(&u).Error; err != nil {
		t.Fatal(err)
	}
	if raw := rawColumn(t, db, "users", "llm_api_key", u.ID); raw != secret {
		t.Fatalf("expected plaintext when no data key, got %q", raw)
	}

	// Now a data key appears and the boot-time migration runs.
	t.Setenv("CYP_DATA_KEY", "0123456789abcdef0123456789abcdef")
	EncryptExistingSecrets(db)

	raw := rawColumn(t, db, "users", "llm_api_key", u.ID)
	if !strings.HasPrefix(raw, "enc:v1:") {
		t.Fatalf("migration did not encrypt legacy key: %q", raw)
	}
	var got User
	if err := db.First(&got, "id = ?", u.ID).Error; err != nil {
		t.Fatal(err)
	}
	if got.LLMAPIKey != secret {
		t.Fatalf("legacy key unreadable after migration: got %q", got.LLMAPIKey)
	}
}
