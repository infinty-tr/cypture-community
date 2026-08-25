package server

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"cypture/internal/auth"
	"cypture/internal/config"
	"cypture/internal/models"
)

func (s *Server) handleAdminDeleteScan(w http.ResponseWriter, r *http.Request) {
	actor, _ := auth.UserFrom(r.Context())
	id := r.PathValue("id")
	var sess models.ScanSession
	if err := s.DB.First(&sess, "id = ?", id).Error; err != nil {
		writeErr(w, http.StatusNotFound, "scan not found")
		return
	}
	running := sess.Status == models.ScanStarting || sess.Status == models.ScanRunning || sess.Status == models.ScanAwaitingInput
	if running {

		s.Scans.Stop(id)
		s.audit(actor.ID, "scan.stop", "scan", id, "via delete", clientIP(r))
		writeJSON(w, http.StatusAccepted, map[string]string{"status": "stopping",
			"message": "Scan is stopping; delete it again once it finishes."})
		return
	}
	s.DB.Where("scan_session_id = ?", id).Delete(&models.LogEvent{})
	s.DB.Where("scan_session_id = ?", id).Delete(&models.Finding{})
	s.DB.Where("scan_session_id = ?", id).Delete(&models.Question{})
	s.DB.Delete(&sess)
	s.audit(actor.ID, "scan.delete", "scan", id, "", clientIP(r))
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) handleAdminRestartScan(w http.ResponseWriter, r *http.Request) {
	actor, _ := auth.UserFrom(r.Context())
	id := r.PathValue("id")
	var sess models.ScanSession
	if err := s.DB.First(&sess, "id = ?", id).Error; err != nil {
		writeErr(w, http.StatusNotFound, "scan not found")
		return
	}
	running := sess.Status == models.ScanStarting || sess.Status == models.ScanRunning || sess.Status == models.ScanAwaitingInput
	if running {
		s.Scans.Stop(id)
		writeJSON(w, http.StatusAccepted, map[string]string{"status": "stopping",
			"message": "The running scan is stopping; restart it once it finishes."})
		return
	}
	var eng models.Engagement
	if err := s.DB.First(&eng, "id = ?", sess.EngagementID).Error; err != nil {
		writeErr(w, http.StatusNotFound, "engagement not found")
		return
	}
	scanID, err := s.Scans.Start(&eng)
	var llmErr *ErrLLMValidation
	switch {
	case errors.As(err, &llmErr):
		writeErr(w, http.StatusUnprocessableEntity, "provider validation failed: "+llmErr.Msg)
		return
	case errors.Is(err, ErrInsufficientBalance):
		writeErr(w, http.StatusPaymentRequired, "the customer has insufficient balance for the selected model")
		return
	case errors.Is(err, ErrNoSubscription):
		writeErr(w, http.StatusPaymentRequired, "the customer has no active subscription")
		return
	case errors.Is(err, ErrNoScansRemaining):
		writeErr(w, http.StatusPaymentRequired, "the customer's plan has no remaining scans")
		return
	case errors.Is(err, ErrTooManyConcurrent):
		writeErr(w, http.StatusTooManyRequests, "the customer's concurrent scan limit is full")
		return
	case err != nil:
		writeErr(w, http.StatusInternalServerError, "could not restart: "+err.Error())
		return
	}
	s.audit(actor.ID, "scan.restart", "scan", id, "new="+scanID, clientIP(r))
	writeJSON(w, http.StatusOK, map[string]any{"status": "started", "scan_id": scanID})
}

func (s *Server) handleAdminUserDetail(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var u models.User
	if err := s.DB.First(&u, "id = ? AND role = ?", id, models.RoleClient).Error; err != nil {
		writeErr(w, http.StatusNotFound, "user not found")
		return
	}

	var engIDs []string
	s.DB.Model(&models.Engagement{}).Where("client_id = ?", u.ID).Pluck("id", &engIDs)
	scans := make([]map[string]any, 0)
	if len(engIDs) > 0 {
		var sessions []models.ScanSession
		s.DB.Where("engagement_id IN ?", engIDs).Order("created_at desc").Limit(50).Find(&sessions)

		seeds := map[string]string{}
		var engs []models.Engagement
		s.DB.Where("id IN ?", engIDs).Find(&engs)
		for _, e := range engs {
			seeds[e.ID] = e.Seed
		}

		scanIDs := make([]string, 0, len(sessions))
		for _, ss := range sessions {
			scanIDs = append(scanIDs, ss.ID)
		}
		fcByScan := s.dedupedCountByScan(scanIDs)
		for _, ss := range sessions {
			scans = append(scans, map[string]any{
				"scan_id": ss.ID, "seed": seeds[ss.EngagementID], "status": ss.Status,
				"findings": fcByScan[ss.ID], "cost_usd": config.MicrosToUSD(ss.CostMicros), "created_at": tstr(&ss.CreatedAt),
			})
		}
	}

	var sessCount int64
	s.DB.Model(&models.AuthSession{}).Where("user_id = ?", u.ID).Count(&sessCount)

	writeJSON(w, http.StatusOK, map[string]any{
		"user": toUserDTO(&u), "scans": scans, "active_sessions": sessCount,
	})
}

func (s *Server) handleAdminLogoutUser(w http.ResponseWriter, r *http.Request) {
	actor, _ := auth.UserFrom(r.Context())
	id := r.PathValue("id")
	var u models.User
	if err := s.DB.First(&u, "id = ? AND role = ?", id, models.RoleClient).Error; err != nil {
		writeErr(w, http.StatusNotFound, "user not found")
		return
	}
	res := s.DB.Where("user_id = ?", u.ID).Delete(&models.AuthSession{})
	s.audit(actor.ID, "user.logout", "user", u.ID, "sessions revoked", clientIP(r))
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "revoked": res.RowsAffected})
}

func (s *Server) handleAdminAudit(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 500 {
			limit = n
		}
	}
	var logs []models.AuditLog
	s.DB.Order("created_at desc").Limit(limit).Find(&logs)

	ids := make([]string, 0, len(logs))
	for _, l := range logs {
		ids = append(ids, l.ActorID)
	}
	emails := map[string]string{}
	if len(ids) > 0 {
		var users []models.User
		s.DB.Where("id IN ?", ids).Find(&users)
		for _, u := range users {
			emails[u.ID] = u.Email
		}
	}
	out := make([]map[string]any, 0, len(logs))
	for i := range logs {
		l := logs[i]
		out = append(out, map[string]any{
			"actor": emails[l.ActorID], "action": l.Action, "target_type": l.TargetType,
			"target_id": l.TargetID, "detail": l.Detail, "ip": l.IP, "created_at": tstr(&l.CreatedAt),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"logs": out})
}

type findingModReq struct {
	Severity *string `json:"severity"`
	Verified *bool   `json:"verified"`
}

func (s *Server) handleAdminUpdateFinding(w http.ResponseWriter, r *http.Request) {
	actor, _ := auth.UserFrom(r.Context())
	id := r.PathValue("id")
	var f models.Finding
	if err := s.DB.First(&f, "id = ?", id).Error; err != nil {
		writeErr(w, http.StatusNotFound, "finding not found")
		return
	}
	var req findingModReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	upd := map[string]any{}
	if req.Severity != nil {
		sev := strings.ToLower(strings.TrimSpace(*req.Severity))
		if _, ok := severityRank[sev]; !ok {
			writeErr(w, http.StatusBadRequest, "invalid severity")
			return
		}
		upd["severity"] = sev
	}
	if req.Verified != nil {
		upd["verified"] = *req.Verified
	}
	if len(upd) == 0 {
		writeErr(w, http.StatusBadRequest, "nothing to update")
		return
	}
	s.DB.Model(&f).Updates(upd)
	s.audit(actor.ID, "finding.update", "finding", id, detailKV(upd), clientIP(r))
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleAdminDeleteFinding(w http.ResponseWriter, r *http.Request) {
	actor, _ := auth.UserFrom(r.Context())
	id := r.PathValue("id")
	var f models.Finding
	if err := s.DB.First(&f, "id = ?", id).Error; err != nil {
		writeErr(w, http.StatusNotFound, "finding not found")
		return
	}
	s.DB.Delete(&f)
	s.audit(actor.ID, "finding.delete", "finding", id, "title="+f.Title, clientIP(r))
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func detailKV(m map[string]any) string {
	parts := make([]string, 0, len(m))
	for k, v := range m {
		parts = append(parts, k+"="+strings.TrimSpace(strings.ReplaceAll(strings.ToLower(toStr(v)), "\n", " ")))
	}
	return strings.Join(parts, " ")
}

func toStr(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case bool:
		if t {
			return "true"
		}
		return "false"
	default:
		return ""
	}
}
