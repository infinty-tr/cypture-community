package models

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"io"
	"os"
	"strings"

	"gorm.io/gorm"
)

const encPrefix = "enc:v1:"

func dataKey() []byte {
	k := strings.TrimSpace(os.Getenv("CYP_DATA_KEY"))
	if k == "" {
		return nil
	}
	if b, err := base64.StdEncoding.DecodeString(k); err == nil && len(b) == 32 {
		return b
	}
	if len(k) >= 32 {
		return []byte(k[:32])
	}
	return nil
}

func encryptField(s string) string {
	if s == "" || strings.HasPrefix(s, encPrefix) {
		return s
	}
	key := dataKey()
	if key == nil {
		return s
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return s
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return s
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return s
	}
	ct := gcm.Seal(nonce, nonce, []byte(s), nil)
	return encPrefix + base64.StdEncoding.EncodeToString(ct)
}

func decryptField(s string) string {
	if !strings.HasPrefix(s, encPrefix) {
		return s
	}
	key := dataKey()
	if key == nil {
		return s
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(s, encPrefix))
	if err != nil {
		return s
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return s
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return s
	}
	ns := gcm.NonceSize()
	if len(raw) < ns {
		return s
	}
	pt, err := gcm.Open(nil, raw[:ns], raw[ns:], nil)
	if err != nil {
		return s
	}
	return string(pt)
}

func (e *Engagement) BeforeSave(tx *gorm.DB) error {
	e.TestCredentials = encryptField(e.TestCredentials)
	return nil
}

func (e *Engagement) AfterSave(tx *gorm.DB) error {
	e.TestCredentials = decryptField(e.TestCredentials)
	return nil
}

func (e *Engagement) AfterFind(tx *gorm.DB) error {
	e.TestCredentials = decryptField(e.TestCredentials)
	return nil
}

// User.LLMAPIKey holds a user's own (BYOK) provider key. Encrypt it at rest with
// the same AES-GCM helper used for TestCredentials.
func (u *User) BeforeSave(tx *gorm.DB) error {
	u.LLMAPIKey = encryptField(u.LLMAPIKey)
	return nil
}

func (u *User) AfterSave(tx *gorm.DB) error {
	u.LLMAPIKey = decryptField(u.LLMAPIKey)
	return nil
}

func (u *User) AfterFind(tx *gorm.DB) error {
	u.LLMAPIKey = decryptField(u.LLMAPIKey)
	return nil
}

// APIKeyPoolEntry.KeyValue is an operator-pool provider key — encrypt at rest too.
func (e *APIKeyPoolEntry) BeforeSave(tx *gorm.DB) error {
	e.KeyValue = encryptField(e.KeyValue)
	return nil
}

func (e *APIKeyPoolEntry) AfterSave(tx *gorm.DB) error {
	e.KeyValue = decryptField(e.KeyValue)
	return nil
}

func (e *APIKeyPoolEntry) AfterFind(tx *gorm.DB) error {
	e.KeyValue = decryptField(e.KeyValue)
	return nil
}

// EncryptSecret / DecryptSecret expose the field cipher for write paths that
// bypass GORM struct hooks — map-based Updates and the generic Setting table.
// Both are idempotent (the enc:v1: prefix guards double-encryption) and are
// no-ops when CYP_DATA_KEY is unset.
func EncryptSecret(s string) string { return encryptField(s) }
func DecryptSecret(s string) string { return decryptField(s) }

// DataKeyConfigured reports whether a valid CYP_DATA_KEY is present, so callers
// (e.g. prod config validation) can require encryption-at-rest.
func DataKeyConfigured() bool { return dataKey() != nil }

// EncryptExistingSecrets upgrades any plaintext secret columns to enc:v1: in
// place. It is a no-op when CYP_DATA_KEY is unset or the values are already
// encrypted, and is safe to run on every boot after AutoMigrate.
func EncryptExistingSecrets(db *gorm.DB) {
	if dataKey() == nil {
		return
	}
	like := encPrefix + "%"

	var users []User
	db.Where("llm_api_key <> '' AND llm_api_key NOT LIKE ?", like).Find(&users)
	for i := range users {
		db.Model(&User{}).Where("id = ?", users[i].ID).
			UpdateColumn("llm_api_key", encryptField(users[i].LLMAPIKey))
	}

	var pool []APIKeyPoolEntry
	db.Where("key_value <> '' AND key_value NOT LIKE ?", like).Find(&pool)
	for i := range pool {
		db.Model(&APIKeyPoolEntry{}).Where("id = ?", pool[i].ID).
			UpdateColumn("key_value", encryptField(pool[i].KeyValue))
	}

	var st Setting
	if err := db.First(&st, "key = ?", "llm_api_key").Error; err == nil {
		if st.Value != "" && !strings.HasPrefix(st.Value, encPrefix) {
			db.Model(&Setting{}).Where("key = ?", "llm_api_key").
				UpdateColumn("value", encryptField(st.Value))
		}
	}
}
