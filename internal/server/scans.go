package server

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"cypture/internal/auth"
	"cypture/internal/config"
	"cypture/internal/models"
)

type scanListItem struct {
	ScanID       string `json:"scan_id"`
	EngagementID string `json:"engagement_id"`
	Seed         string `json:"seed"`
	Title        string `json:"title"`
	Mode         string `json:"mode"`
	Status       string `json:"status"`
	StartedAt    string `json:"started_at,omitempty"`
	EndedAt      string `json:"ended_at,omitempty"`
	CreatedAt    string `json:"created_at"`
	Findings     int64  `json:"findings"`
	CompanyName  string `json:"company_name,omitempty"`
	ClientEmail  string `json:"client_email,omitempty"`
}

func (s *Server) handleListScans(w http.ResponseWriter, r *http.Request) {
	u, _ := auth.UserFrom(r.Context())
	isAdmin := u.Role == models.RoleAdmin

	eq := s.DB.Order("created_at desc")
	if isAdmin {
		eq = eq.Preload("Client")
	} else {
		eq = eq.Where("client_id = ?", u.ID)
	}
	var engs []models.Engagement
	eq.Find(&engs)

	engByID := make(map[string]*models.Engagement, len(engs))
	ids := make([]string, 0, len(engs))
	for i := range engs {
		engByID[engs[i].ID] = &engs[i]
		ids = append(ids, engs[i].ID)
	}

	var scans []models.ScanSession
	if len(ids) > 0 {
		s.DB.Where("engagement_id IN ?", ids).Order("created_at desc").Find(&scans)
	}

	scanIDs := make([]string, 0, len(scans))
	for i := range scans {
		scanIDs = append(scanIDs, scans[i].ID)
	}
	findCounts := s.dedupedCountByScan(scanIDs)

	out := make([]scanListItem, 0, len(scans))
	for i := range scans {
		sc := &scans[i]
		eng := engByID[sc.EngagementID]
		if eng == nil {
			continue
		}
		fc := findCounts[sc.ID]
		item := scanListItem{
			ScanID:       sc.ID,
			EngagementID: eng.ID,
			Seed:         eng.Seed,
			Title:        eng.Title,
			Mode:         eng.Mode,
			Status:       string(sc.Status),
			StartedAt:    tstr(sc.StartedAt),
			EndedAt:      tstr(sc.EndedAt),
			CreatedAt:    sc.CreatedAt.Format(time.RFC3339),
			Findings:     fc,
		}
		if isAdmin && eng.Client != nil {
			item.CompanyName = eng.Client.CompanyName
			item.ClientEmail = eng.Client.Email
		}
		out = append(out, item)
	}
	writeJSON(w, http.StatusOK, map[string]any{"scans": out})
}

type adminScanReq struct {
	Title           string   `json:"title"`
	ScopeIncludes   []string `json:"scope_includes"`
	ScopeExcludes   []string `json:"scope_excludes"`
	ScopeText       string   `json:"scope_text"`
	Mode            string   `json:"mode"`
	Model           string   `json:"model"`
	OperatorPrompt  string   `json:"operator_prompt"`
	TestCredentials string   `json:"test_credentials"`
}

func (s *Server) handleAdminCreateScan(w http.ResponseWriter, r *http.Request) {
	actor, _ := auth.UserFrom(r.Context())

	var req adminScanReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}

	includes := normalizePatterns(req.ScopeIncludes)
	excludes := normalizePatterns(req.ScopeExcludes)
	if len(includes) == 0 {
		writeErr(w, http.StatusBadRequest, "at least one scope pattern is required (e.g. *.abc.com)")
		return
	}

	seed := deriveSeedTarget(req.ScopeIncludes)
	if seed == "" {
		writeErr(w, http.StatusBadRequest, "could not derive a valid target from the scope")
		return
	}
	if !(ScopeSet{Includes: includes, Excludes: excludes}).Allows(seed) {
		writeErr(w, http.StatusBadRequest, "the derived target is outside the approved scope (check the exclusion list)")
		return
	}

	if reason := blockedScopeReason(seed, includes); reason != "" {
		writeErr(w, http.StatusForbidden, "This target cannot be scanned: "+reason)
		return
	}

	mode := strings.ToLower(strings.TrimSpace(req.Mode))
	if mode == "" {
		mode = "full"
	}
	if !validModes[mode] {
		writeErr(w, http.StatusBadRequest, "invalid mode")
		return
	}

	model := strings.ToLower(strings.TrimSpace(req.Model))
	if model != "" && !config.ValidModelTier(model) {
		writeErr(w, http.StatusBadRequest, "invalid model")
		return
	}

	now := time.Now()
	e := models.Engagement{
		ClientID:        actor.ID,
		Title:           strings.TrimSpace(req.Title),
		ScopeIncludes:   encodeList(includes),
		ScopeExcludes:   encodeList(excludes),
		Seed:            seed,
		ScopeText:       strings.TrimSpace(req.ScopeText),
		Mode:            mode,
		Model:           model,
		OperatorPrompt:  strings.TrimSpace(req.OperatorPrompt),
		TestCredentials: strings.TrimSpace(req.TestCredentials),
		Status:          models.EngAccepted,
		ReviewedByID:    &actor.ID,
		SubmittedAt:     &now,
		AcceptedAt:      &now,
	}
	if e.Title == "" {
		e.Title = seed
	}
	if err := s.DB.Create(&e).Error; err != nil {
		writeErr(w, http.StatusInternalServerError, "could not create engagement")
		return
	}
	s.audit(actor.ID, "engagement.admin_create", "engagement", e.ID, "seed="+seed, clientIP(r))

	scanID, err := s.Scans.Start(&e)
	var llmErr *ErrLLMValidation
	if errors.As(err, &llmErr) {
		writeErr(w, http.StatusUnprocessableEntity, "provider validation failed: "+llmErr.Msg)
		return
	}
	if errors.Is(err, ErrInsufficientBalance) {
		writeErr(w, http.StatusPaymentRequired, "insufficient balance for the selected model")
		return
	}
	if errors.Is(err, ErrTooManyConcurrent) {
		writeErr(w, http.StatusTooManyRequests, "your concurrent scan limit is full — try again once current scans finish")
		return
	}
	if errors.Is(err, ErrNoSubscription) {
		writeErr(w, http.StatusPaymentRequired, "the customer has no active subscription")
		return
	}
	if errors.Is(err, ErrNoScansRemaining) {
		writeErr(w, http.StatusPaymentRequired, "the customer's plan has no remaining scans")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "engagement created but scan failed to start")
		return
	}
	s.audit(actor.ID, "scan.start", "scan", scanID, "engagement="+e.ID, clientIP(r))

	writeJSON(w, http.StatusOK, map[string]any{
		"status":        "started",
		"scan_id":       scanID,
		"engagement_id": e.ID,
	})
}

func (s *Server) handleAdminStats(w http.ResponseWriter, r *http.Request) {
	var stats struct {
		Pending  int64 `json:"pending"`
		Running  int64 `json:"running"`
		Scans    int64 `json:"scans"`
		Findings int64 `json:"findings"`
		Clients  int64 `json:"clients"`
	}
	s.DB.Model(&models.Engagement{}).Where("status IN ?", []string{
		string(models.EngSubmitted), string(models.EngUnderReview),
	}).Count(&stats.Pending)
	s.DB.Model(&models.ScanSession{}).Where("status IN ?", []string{
		string(models.ScanStarting), string(models.ScanRunning), string(models.ScanAwaitingInput),
	}).Count(&stats.Running)
	s.DB.Model(&models.ScanSession{}).Count(&stats.Scans)
	s.DB.Model(&models.Finding{}).Count(&stats.Findings)
	s.DB.Model(&models.User{}).Where("role = ?", models.RoleClient).Count(&stats.Clients)
	writeJSON(w, http.StatusOK, stats)
}
