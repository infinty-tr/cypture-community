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
