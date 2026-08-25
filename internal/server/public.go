package server

import (
	"net/http"
	"strings"

	"cypture/internal/models"
)

func (s *Server) handlePublicStats(w http.ResponseWriter, r *http.Request) {
	type sevCount struct {
		Severity string
		C        int64
	}
	var rows []sevCount
	s.DB.Model(&models.Finding{}).Select("severity, count(*) as c").Group("severity").Scan(&rows)

	out := map[string]int64{"critical": 0, "high": 0, "medium": 0, "low": 0}
	var total int64
	for _, rc := range rows {
		sev := strings.ToLower(strings.TrimSpace(rc.Severity))
		if _, ok := out[sev]; ok {
			out[sev] += rc.C
		}
		total += rc.C
	}
	var scans int64
	s.DB.Model(&models.ScanSession{}).Count(&scans)

	writeJSON(w, http.StatusOK, map[string]any{
		"total":    total,
		"critical": out["critical"],
		"high":     out["high"],
		"medium":   out["medium"],
		"low":      out["low"],
		"scans":    scans,
	})
}
