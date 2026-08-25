package auth

import (
	"log/slog"
	"strings"

	"gorm.io/gorm"

	"cypture/internal/config"
	"cypture/internal/models"
)

func EnsureAdmin(db *gorm.DB, cfg *config.Config) error {
	if cfg.AdminPassword == "" {
		return nil
	}
	email := strings.ToLower(strings.TrimSpace(cfg.AdminEmail))

	var existing models.User
	err := db.Where("email = ?", email).First(&existing).Error
	if err == nil {
		return nil
	}
	if err != gorm.ErrRecordNotFound {
		return err
	}

	hash, err := HashPassword(cfg.AdminPassword)
	if err != nil {
		return err
	}
	admin := models.User{
		Email:        email,
		PasswordHash: hash,
		Role:         models.RoleAdmin,
		Status:       models.UserActive,
		CompanyName:  "Cypture",
	}
	if err := db.Create(&admin).Error; err != nil {
		return err
	}
	slog.Info("seed admin created", "email", email)
	return nil
}
