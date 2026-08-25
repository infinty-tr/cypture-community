package keypool

import (
	"errors"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"cypture/internal/models"
)

var ErrNoKey = errors.New("no active pool key")

type Allocator struct{ db *gorm.DB }

func New(db *gorm.DB) *Allocator { return &Allocator{db: db} }

func (a *Allocator) HasKeys() bool {
	var n int64
	a.db.Model(&models.APIKeyPoolEntry{}).
		Where("active = ? AND disabled = ?", true, false).Count(&n)
	return n > 0
}

func (a *Allocator) KeyForUser(userID string) (*models.APIKeyPoolEntry, error) {
	var asn models.UserKeyAssignment
	if err := a.db.First(&asn, "user_id = ?", userID).Error; err == nil {
		var e models.APIKeyPoolEntry
		if err := a.db.First(&e, "id = ? AND active = ? AND disabled = ?",
			asn.KeyID, true, false).Error; err == nil {
			return &e, nil
		}
	}
	return a.assign(userID, nil)
}

func (a *Allocator) Reassign(userID string, exclude map[string]bool) (*models.APIKeyPoolEntry, error) {
	return a.assign(userID, exclude)
}

func (a *Allocator) assign(userID string, exclude map[string]bool) (*models.APIKeyPoolEntry, error) {

	var best *models.APIKeyPoolEntry
	err := a.db.Transaction(func(tx *gorm.DB) error {
		var keys []models.APIKeyPoolEntry
		tx.Where("active = ? AND disabled = ?", true, false).Order("created_at asc").Find(&keys)
		if len(keys) == 0 {
			return ErrNoKey
		}
		counts := map[string]int64{}
		var rows []struct {
			KeyID string
			C     int64
		}
		tx.Model(&models.UserKeyAssignment{}).Select("key_id, count(*) as c").Group("key_id").Scan(&rows)
		for _, r := range rows {
			counts[r.KeyID] = r.C
		}
		var bestC int64
		for i := range keys {
			if exclude[keys[i].ID] {
				continue
			}
			if best == nil || counts[keys[i].ID] < bestC {
				best = &keys[i]
				bestC = counts[keys[i].ID]
			}
		}
		if best == nil {
			return ErrNoKey
		}

		return tx.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "user_id"}},
			UpdateAll: true,
		}).Create(&models.UserKeyAssignment{
			UserID:     userID,
			KeyID:      best.ID,
			Provider:   best.Provider,
			AssignedAt: time.Now(),
		}).Error
	})
	if err != nil {
		return nil, err
	}
	return best, nil
}

func (a *Allocator) Disable(keyID, reason string) {
	a.db.Model(&models.APIKeyPoolEntry{}).Where("id = ?", keyID).
		Updates(map[string]any{
			"disabled":     true,
			"failed_count": gorm.Expr("failed_count + 1"),
			"last_error":   reason,
		})
}

func (a *Allocator) MarkUsed(keyID string) {
	now := time.Now()
	a.db.Model(&models.APIKeyPoolEntry{}).Where("id = ?", keyID).
		Updates(map[string]any{
			"usage_count":  gorm.Expr("usage_count + 1"),
			"last_used_at": now,
		})
}
