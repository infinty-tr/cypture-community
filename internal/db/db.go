package db

import (
	"fmt"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	glogger "gorm.io/gorm/logger"

	"cypture/internal/models"
)

func Open(path string, dev bool) (*gorm.DB, error) {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return nil, fmt.Errorf("create db dir: %w", err)
		}
	}

	level := glogger.Error
	if dev {
		level = glogger.Warn
	}

	gormLog := glogger.New(
		log.New(os.Stdout, "\r\n", log.LstdFlags),
		glogger.Config{
			SlowThreshold:             200 * time.Millisecond,
			LogLevel:                  level,
			IgnoreRecordNotFoundError: true,
			Colorful:                  true,
		},
	)

	gdb, err := gorm.Open(sqlite.Open(path), &gorm.Config{
		Logger:                 gormLog,
		TranslateError:         true,
		SkipDefaultTransaction: true,
	})
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}

	for _, p := range []string{
		"PRAGMA journal_mode=WAL;",
		"PRAGMA foreign_keys=ON;",
		"PRAGMA busy_timeout=5000;",
		"PRAGMA synchronous=NORMAL;",
	} {
		if err := gdb.Exec(p).Error; err != nil {
			return nil, fmt.Errorf("pragma %q: %w", p, err)
		}
	}

	sqlDB, err := gdb.DB()
	if err != nil {
		return nil, err
	}
	sqlDB.SetMaxOpenConns(1)
	sqlDB.SetConnMaxLifetime(time.Hour)

	if err := gdb.AutoMigrate(models.All()...); err != nil {
		return nil, fmt.Errorf("automigrate: %w", err)
	}

	// One-time upgrade of any plaintext secret columns to encrypted-at-rest.
	// No-op when CYP_DATA_KEY is unset or values are already encrypted.
	models.EncryptExistingSecrets(gdb)

	slog.Info("database ready", "path", path)
	return gdb, nil
}
