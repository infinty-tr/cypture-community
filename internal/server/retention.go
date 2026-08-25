package server

import (
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"cypture/internal/models"
)

func (s *Server) startRetentionMaintenance() {
	days := s.Cfg.ScanRetentionDays
	if days <= 0 {
		return
	}
	go func() {
		s.purgeExpiredScans(days)
		t := time.NewTicker(24 * time.Hour)
		defer t.Stop()
		for range t.C {
			s.purgeExpiredScans(days)
		}
	}()
}

func (s *Server) purgeExpiredScans(days int) {
	cutoff := time.Now().AddDate(0, 0, -days)
	finished := []models.ScanStatus{models.ScanCompleted, models.ScanStopped, models.ScanFailed}

	var sessions []models.ScanSession
	s.DB.Where("archived = ? AND created_at < ? AND status IN ?", false, cutoff, finished).
		Find(&sessions)
	if len(sessions) == 0 {
		return
	}

	reportsDir := filepath.Join(filepath.Dir(s.Cfg.DBPath), "reports")
	_ = os.MkdirAll(reportsDir, 0o750)

	for i := range sessions {
		sess := &sessions[i]

		if md := s.reportFromFile(sess); md != "" {
			arch := filepath.Join(reportsDir, sess.ID+".md")
			if err := os.WriteFile(arch, []byte(md), 0o640); err == nil {
				sess.ReportPath = arch
			}
		}

		if sess.WorkDir != "" && isSafePath(sess.WorkDir) {
			_ = os.RemoveAll(sess.WorkDir)
		}

		s.DB.Where("scan_session_id = ?", sess.ID).Delete(&models.LogEvent{})
		s.DB.Where("scan_session_id = ?", sess.ID).Delete(&models.HTTPTraffic{})

		s.DB.Model(&models.ScanSession{}).Where("id = ?", sess.ID).
			Updates(map[string]any{"archived": true, "report_path": sess.ReportPath})
	}
	slog.Info("scan retention purge", "count", len(sessions), "older_than_days", days)
}
