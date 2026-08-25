package server

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"cypture/internal/auth"
	"cypture/internal/models"
)

func (s *Server) handleAdminListEngagements(w http.ResponseWriter, r *http.Request) {
	q := s.DB.Preload("Client").Order("created_at desc")
	if st := r.URL.Query().Get("status"); st != "" {
		q = q.Where("status = ?", st)
	}
	var list []models.Engagement
	q.Find(&list)
	out := make([]engagementDTO, 0, len(list))
	for i := range list {
		out = append(out, toEngagementDTO(&list[i], true))
	}
	writeJSON(w, http.StatusOK, map[string]any{"engagements": out})
}

func (s *Server) handleAdminGetEngagement(w http.ResponseWriter, r *http.Request) {
	e, ok := s.loadEngagementAdmin(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"engagement": toEngagementDTO(e, true)})
}

func (s *Server) handleReviewEngagement(w http.ResponseWriter, r *http.Request) {
	actor, _ := auth.UserFrom(r.Context())
	e, ok := s.loadEngagementAdmin(w, r)
	if !ok {
		return
	}
	if e.Status != models.EngSubmitted && e.Status != models.EngUnderReview {
		writeErr(w, http.StatusConflict, "engagement is not awaiting review")
		return
	}
	s.DB.Model(e).Updates(map[string]any{"status": models.EngUnderReview, "reviewed_by_id": actor.ID})
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

type acceptReq struct {
	AdminNotes      string   `json:"admin_notes"`
	ScopeIncludes   []string `json:"scope_includes"`
	ScopeExcludes   []string `json:"scope_excludes"`
	OperatorPrompt  string   `json:"operator_prompt"`
	TestCredentials string   `json:"test_credentials"`

	LLMAPIKey   *string `json:"llm_api_key"`
	LLMProvider *string `json:"llm_provider"`
	RunnerModel *string `json:"runner_model"`
}

func (s *Server) handleAcceptEngagement(w http.ResponseWriter, r *http.Request) {
	actor, _ := auth.UserFrom(r.Context())
	e, ok := s.loadEngagementAdmin(w, r)
	if !ok {
		return
	}
	if e.Status != models.EngSubmitted && e.Status != models.EngUnderReview {
		writeErr(w, http.StatusConflict, "only submitted engagements can be accepted")
		return
	}
	origStatus := e.Status

	var req acceptReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}

	includes := normalizePatterns(req.ScopeIncludes)
	if len(includes) == 0 {
		includes = decodeList(e.ScopeIncludes)
	}
	excludes := normalizePatterns(req.ScopeExcludes)
	if len(excludes) == 0 {
		excludes = decodeList(e.ScopeExcludes)
	}
	if len(includes) == 0 {
		writeErr(w, http.StatusBadRequest, "at least one scope pattern is required")
		return
	}

	seed := ""
	if len(req.ScopeIncludes) > 0 {
		seed = deriveSeedTarget(req.ScopeIncludes)
	}
	if seed == "" {
		seed = strings.TrimSpace(e.Seed)
	}
	if seed == "" {
		seed = deriveSeed(includes)
	}
	if seed == "" {
		writeErr(w, http.StatusBadRequest, "could not derive a valid target from the scope")
		return
	}

	if !(ScopeSet{Includes: includes, Excludes: excludes}).Allows(seed) {
		writeErr(w, http.StatusBadRequest, "the derived target is outside the approved scope (check the exclusion list)")
		return
	}

	now := time.Now()
	upd := map[string]any{
		"status":         models.EngAccepted,
		"admin_notes":    strings.TrimSpace(req.AdminNotes),
		"scope_includes": encodeList(includes),
		"scope_excludes": encodeList(excludes),
		"seed":           seed,
		"reviewed_by_id": actor.ID,
		"accepted_at":    &now,
	}

	if op := strings.TrimSpace(req.OperatorPrompt); op != "" {
		upd["operator_prompt"] = op
		e.OperatorPrompt = op
	}

	if tc := strings.TrimSpace(req.TestCredentials); tc != "" {
		upd["test_credentials"] = tc
		e.TestCredentials = tc
	}
	s.DB.Model(e).Updates(upd)
	s.audit(actor.ID, "engagement.accept", "engagement", e.ID, "seed="+seed, clientIP(r))

	if req.LLMAPIKey != nil {
		kupd := map[string]any{"llm_api_key": strings.TrimSpace(*req.LLMAPIKey)}
		if req.LLMProvider != nil {
			kupd["llm_provider"] = strings.TrimSpace(*req.LLMProvider)
		}
		if req.RunnerModel != nil {
			kupd["runner_model"] = strings.TrimSpace(*req.RunnerModel)
		}
		s.DB.Model(&models.User{}).Where("id = ?", e.ClientID).Updates(kupd)
		set := strings.TrimSpace(*req.LLMAPIKey) != ""
		s.audit(actor.ID, "user.llm_key.admin_set", "user", e.ClientID,
			map[bool]string{true: "admin set client LLM key on accept", false: "admin cleared client LLM key on accept"}[set], clientIP(r))
	}

	s.DB.First(e, "id = ?", e.ID)
	scanID, err := s.Scans.Start(e)
	if err != nil {

		s.DB.Model(e).Updates(map[string]any{"status": origStatus, "accepted_at": nil})
		switch {
		case errors.Is(err, ErrInsufficientBalance):
			writeErr(w, http.StatusPaymentRequired, "the customer has insufficient balance for the selected model")
		case errors.Is(err, ErrNoSubscription):
			writeErr(w, http.StatusPaymentRequired, "the customer has no active subscription")
		case errors.Is(err, ErrNoScansRemaining):
			writeErr(w, http.StatusPaymentRequired, "the customer's plan has no remaining scans")
		case errors.Is(err, ErrTooManyConcurrent):
			writeErr(w, http.StatusTooManyRequests, "the customer's concurrent scan limit is full")
		default:
			var llmErr *ErrLLMValidation
			if errors.As(err, &llmErr) {
				writeErr(w, http.StatusUnprocessableEntity, "provider validation failed: "+llmErr.Msg)
			} else {
				writeErr(w, http.StatusInternalServerError, "engagement accepted but scan failed to start")
			}
		}
		return
	}
	s.audit(actor.ID, "scan.start", "scan", scanID, "engagement="+e.ID, clientIP(r))

	writeJSON(w, http.StatusOK, map[string]any{"status": "accepted", "scan_id": scanID})
}

type rejectReq struct {
	AdminNotes string `json:"admin_notes"`
}

func (s *Server) handleRejectEngagement(w http.ResponseWriter, r *http.Request) {
	actor, _ := auth.UserFrom(r.Context())
	e, ok := s.loadEngagementAdmin(w, r)
	if !ok {
		return
	}
	if e.Status == models.EngAccepted || e.Status == models.EngRunning {
		writeErr(w, http.StatusConflict, "cannot reject an accepted or running engagement")
		return
	}
	var req rejectReq
	_ = decodeJSON(r, &req)
	s.DB.Model(e).Updates(map[string]any{
		"status":         models.EngRejected,
		"admin_notes":    strings.TrimSpace(req.AdminNotes),
		"reviewed_by_id": actor.ID,
	})
	s.audit(actor.ID, "engagement.reject", "engagement", e.ID, "", clientIP(r))
	writeJSON(w, http.StatusOK, map[string]string{"status": "rejected"})
}

func (s *Server) handleAdminQuestions(w http.ResponseWriter, r *http.Request) {
	var qs []models.Question
	s.DB.Where("status = ?", models.QOpen).Order("created_at asc").Find(&qs)
	out := make([]map[string]any, 0, len(qs))
	for i := range qs {
		q := &qs[i]
		var sess models.ScanSession
		if s.DB.First(&sess, "id = ?", q.ScanSessionID).Error != nil {
			continue
		}
		var eng models.Engagement
		s.DB.Preload("Client").First(&eng, "id = ?", sess.EngagementID)
		p := questionPayload(q)
		p["scan_id"] = sess.ID
		p["engagement_id"] = eng.ID
		p["seed"] = eng.Seed
		if eng.Client != nil {
			p["company_name"] = eng.Client.CompanyName
			p["client_email"] = eng.Client.Email
		}
		out = append(out, p)
	}
	writeJSON(w, http.StatusOK, map[string]any{"questions": out})
}

func (s *Server) loadEngagementAdmin(w http.ResponseWriter, r *http.Request) (*models.Engagement, bool) {
	id := r.PathValue("id")
	var e models.Engagement
	if err := s.DB.Preload("Client").First(&e, "id = ?", id).Error; err != nil {
		writeErr(w, http.StatusNotFound, "engagement not found")
		return nil, false
	}
	return &e, true
}
