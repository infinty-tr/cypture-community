package server

import (
	"encoding/json"
	"net/http"
	"time"

	"cypture/internal/auth"
	"cypture/internal/models"
)

func (s *Server) authorizeScan(w http.ResponseWriter, r *http.Request, scanID string) (*models.ScanSession, *models.Engagement, bool) {
	u, ok := auth.UserFrom(r.Context())
	if !ok || u == nil {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return nil, nil, false
	}
	var sess models.ScanSession
	if err := s.DB.First(&sess, "id = ?", scanID).Error; err != nil {
		writeErr(w, http.StatusNotFound, "scan not found")
		return nil, nil, false
	}
	var eng models.Engagement
	if err := s.DB.First(&eng, "id = ?", sess.EngagementID).Error; err != nil {
		writeErr(w, http.StatusNotFound, "engagement not found")
		return nil, nil, false
	}
	if u.Role != models.RoleAdmin && eng.ClientID != u.ID {
		writeErr(w, http.StatusForbidden, "forbidden")
		return nil, nil, false
	}
	return &sess, &eng, true
}

func (s *Server) handleScanStatus(w http.ResponseWriter, r *http.Request) {
	sess, eng, ok := s.authorizeScan(w, r, r.PathValue("id"))
	if !ok {
		return
	}
	var openQ *models.Question
	var q models.Question
	if err := s.DB.Where("scan_session_id = ? AND status = ?", sess.ID, models.QOpen).
		Order("created_at desc").First(&q).Error; err == nil {
		openQ = &q
	}
	resp := map[string]any{
		"scan_id":       sess.ID,
		"status":        sess.Status,
		"engagement_id": eng.ID,
		"engagement":    toEngagementDTO(eng, false),
		"started_at":    tstr(sess.StartedAt),
		"ended_at":      tstr(sess.EndedAt),
		"open_question": questionPayload(openQ),
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleScanEvents(w http.ResponseWriter, r *http.Request) {
	sess, _, ok := s.authorizeScan(w, r, r.PathValue("id"))
	if !ok {
		return
	}
	var events []models.LogEvent
	s.DB.Where("scan_session_id = ?", sess.ID).Order("seq asc").Find(&events)
	out := make([]map[string]any, 0, len(events))
	for _, e := range events {
		out = append(out, map[string]any{
			"seq": e.Seq, "level": e.Level, "category": e.Category,
			"module": e.Module, "message": e.Message,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": out})
}

func (s *Server) handleScanFindings(w http.ResponseWriter, r *http.Request) {
	sess, _, ok := s.authorizeScan(w, r, r.PathValue("id"))
	if !ok {
		return
	}
	var fs []models.Finding
	s.DB.Where("scan_session_id = ?", sess.ID).Order("created_at asc").Find(&fs)

	fs = dedupeFindings(fs)
	writeJSON(w, http.StatusOK, map[string]any{"findings": fs})
}

func (s *Server) handleScanTraffic(w http.ResponseWriter, r *http.Request) {
	sess, _, ok := s.authorizeScan(w, r, r.PathValue("id"))
	if !ok {
		return
	}
	var ts []models.HTTPTraffic
	s.DB.Where("scan_session_id = ?", sess.ID).Order("seq asc").Limit(3000).Find(&ts)
	out := make([]map[string]any, 0, len(ts))
	for _, t := range ts {
		out = append(out, trafficToMap(t))
	}
	writeJSON(w, http.StatusOK, map[string]any{"traffic": out})
}

func (s *Server) handleScanStop(w http.ResponseWriter, r *http.Request) {
	u, _ := auth.UserFrom(r.Context())
	sess, _, ok := s.authorizeScan(w, r, r.PathValue("id"))
	if !ok {
		return
	}
	if s.Scans.Stop(sess.ID) {
		s.audit(u.ID, "scan.stop", "scan", sess.ID, "", clientIP(r))
		writeJSON(w, http.StatusOK, map[string]string{"status": "stopping"})
		return
	}
	writeErr(w, http.StatusConflict, "scan is not running")
}

type answerReq struct {
	QuestionID string `json:"question_id"`
	OptionID   string `json:"option_id"`
}

func (s *Server) handleScanAnswer(w http.ResponseWriter, r *http.Request) {
	u, _ := auth.UserFrom(r.Context())

	if u == nil || u.Role != models.RoleAdmin {
		writeErr(w, http.StatusForbidden, "only the operator can answer")
		return
	}
	sess, _, ok := s.authorizeScan(w, r, r.PathValue("id"))
	if !ok {
		return
	}
	var req answerReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}

	var q models.Question
	if err := s.DB.First(&q, "id = ? AND scan_session_id = ?", req.QuestionID, sess.ID).Error; err != nil {
		writeErr(w, http.StatusNotFound, "question not found")
		return
	}
	if q.Status != models.QOpen {
		writeErr(w, http.StatusConflict, "question already resolved")
		return
	}
	if !optionAllowed(q.Options, req.OptionID) {
		writeErr(w, http.StatusBadRequest, "invalid option")
		return
	}
	if s.Scans.Answer(sess.ID, req.QuestionID, req.OptionID) {
		s.audit(u.ID, "scan.answer", "scan", sess.ID, "opt="+req.OptionID, clientIP(r))
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
		return
	}
	writeErr(w, http.StatusConflict, "could not deliver answer")
}

func (s *Server) handleEngagementScan(w http.ResponseWriter, r *http.Request) {
	u, _ := auth.UserFrom(r.Context())
	id := r.PathValue("id")
	var eng models.Engagement
	if err := s.DB.First(&eng, "id = ?", id).Error; err != nil {
		writeErr(w, http.StatusNotFound, "engagement not found")
		return
	}
	if u.Role != models.RoleAdmin && eng.ClientID != u.ID {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	var sess models.ScanSession
	if err := s.DB.Where("engagement_id = ?", id).Order("created_at desc").First(&sess).Error; err != nil {
		writeErr(w, http.StatusNotFound, "no scan yet")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"scan_id": sess.ID, "status": sess.Status})
}

func (s *Server) handleScanWS(w http.ResponseWriter, r *http.Request) {
	scanID := r.PathValue("id")

	tok := ""
	if c, err := r.Cookie(auth.SessionCookie); err == nil {
		tok = c.Value
	}
	u, err := s.Auth.Resolve(tok)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var sess models.ScanSession
	if err := s.DB.First(&sess, "id = ?", scanID).Error; err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	var eng models.Engagement
	if err := s.DB.First(&eng, "id = ?", sess.EngagementID).Error; err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if u.Role != models.RoleAdmin && eng.ClientID != u.ID {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	up := s.upgrader()
	ws, err := up.Upgrade(w, r, nil)
	if err != nil {
		return
	}

	conn := &wsConn{ws: ws, send: make(chan []byte, 1024)}
	s.Hub.add(scanID, conn)
	quit := make(chan struct{})
	defer func() {
		close(quit)
		s.Hub.remove(scanID, conn)
		ws.Close()
	}()

	send := func(p []byte) bool {
		select {
		case conn.send <- p:
			return true
		case <-quit:
			return false
		}
	}
	go func() {
		var events []models.LogEvent
		s.DB.Where("scan_session_id = ?", scanID).Order("seq asc").Find(&events)
		for _, e := range events {
			ev := map[string]any{
				"type": "event", "seq": e.Seq, "level": e.Level,
				"category": e.Category, "module": e.Module, "message": e.Message,
			}
			if e.PaneID != "" {
				ev["data"] = map[string]any{
					"pane_id": e.PaneID, "pane_module": e.PaneModule, "pane_status": e.PaneStatus,
				}
			}
			if !send(mustJSON(ev)) {
				return
			}
		}
		var findings []models.Finding
		s.DB.Where("scan_session_id = ?", scanID).Order("created_at asc").Find(&findings)
		for _, f := range findings {
			if !send(mustJSON(map[string]any{
				"type": "finding",
				"data": map[string]any{
					"db_id": f.ID,
					"title": f.Title, "severity": f.Severity, "endpoint": f.Endpoint,
					"method": f.Method, "vuln_type": f.VulnType, "evidence": f.Evidence,
					"poc": f.PoC, "cvss": f.CVSS, "confidence": f.Confidence,
					"request": f.Request, "response": f.Response, "remediation": f.Remediation,
					"verified": f.Verified, "verify_note": f.VerifyNote,
					"repro_steps": f.ReproSteps, "impact": f.Impact,
					"extracted_evidence": f.ExtractedEvidence, "proof_kind": f.ProofKind,
				},
			})) {
				return
			}
		}

		var traffic []models.HTTPTraffic
		s.DB.Where("scan_session_id = ?", scanID).Order("seq desc").Limit(300).Find(&traffic)
		for i := len(traffic) - 1; i >= 0; i-- {
			if !send(mustJSON(map[string]any{"type": "traffic", "data": trafficToMap(traffic[i])})) {
				return
			}
		}
		var oq models.Question
		if err := s.DB.Where("scan_session_id = ? AND status = ?", scanID, models.QOpen).
			Order("created_at desc").First(&oq).Error; err == nil {
			if p := questionPayload(&oq); p != nil {
				p["type"] = "question"
				send(mustJSON(p))
			}
		}
	}()

	go wsReadLoop(ws)
	wsWriteLoop(ws, conn)
}

func wsReadLoop(ws interface {
	ReadMessage() (int, []byte, error)
}) {
	for {
		if _, _, err := ws.ReadMessage(); err != nil {
			return
		}
	}
}

func wsWriteLoop(ws interface {
	WriteMessage(int, []byte) error
}, conn *wsConn) {
	const textMessage = 1
	ping := time.NewTicker(30 * time.Second)
	defer ping.Stop()
	for {
		select {
		case msg, ok := <-conn.send:
			if !ok {
				return
			}
			if err := ws.WriteMessage(textMessage, msg); err != nil {
				return
			}
		case <-ping.C:
			if err := ws.WriteMessage(textMessage, []byte(`{"type":"ping"}`)); err != nil {
				return
			}
		}
	}
}

func optionAllowed(optionsJSON, id string) bool {
	var opts []struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal([]byte(optionsJSON), &opts); err != nil {
		return false
	}
	for _, o := range opts {
		if o.ID == id {
			return true
		}
	}
	return false
}

func questionPayload(q *models.Question) map[string]any {
	if q == nil {
		return nil
	}
	var opts []map[string]string
	_ = json.Unmarshal([]byte(q.Options), &opts)
	return map[string]any{
		"question_id":     q.ID,
		"prompt":          q.Prompt,
		"options":         opts,
		"default_id":      q.DefaultOption,
		"timeout_seconds": q.TimeoutSeconds,
		"expires_at":      q.ExpiresAt.Format(time.RFC3339),
	}
}
