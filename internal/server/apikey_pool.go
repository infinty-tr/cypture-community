package server

import (
	"net/http"
	"strings"

	"cypture/internal/auth"
	"cypture/internal/models"
	"cypture/internal/orchestrator"
)

type apiKeyDTO struct {
	ID          string `json:"id"`
	Provider    string `json:"provider"`
	Model       string `json:"model"`
	Label       string `json:"label"`
	KeyMasked   string `json:"key_masked"`
	Active      bool   `json:"active"`
	Disabled    bool   `json:"disabled"`
	FailedCount int    `json:"failed_count"`
	UsageCount  int64  `json:"usage_count"`
	Users       int64  `json:"users"`
	LastError   string `json:"last_error,omitempty"`
}

func (s *Server) handleListAPIKeys(w http.ResponseWriter, r *http.Request) {
	var keys []models.APIKeyPoolEntry
	s.DB.Order("created_at asc").Find(&keys)

	counts := map[string]int64{}
	var rows []struct {
		KeyID string
		C     int64
	}
	s.DB.Model(&models.UserKeyAssignment{}).
		Select("key_id, count(*) as c").Group("key_id").Scan(&rows)
	for _, r := range rows {
		counts[r.KeyID] = r.C
	}

	out := make([]apiKeyDTO, 0, len(keys))
	for i := range keys {
		k := &keys[i]
		out = append(out, apiKeyDTO{
			ID: k.ID, Provider: k.Provider, Model: k.Model, Label: k.Label,
			KeyMasked: maskKey(k.KeyValue), Active: k.Active, Disabled: k.Disabled,
			FailedCount: k.FailedCount, UsageCount: k.UsageCount,
			Users: counts[k.ID], LastError: k.LastError,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"keys": out})
}

type addAPIKeyReq struct {
	Provider string `json:"provider"`
	Model    string `json:"model"`
	KeyValue string `json:"key_value"`
	Label    string `json:"label"`
	Validate bool   `json:"validate"`
}

func (s *Server) handleAddAPIKey(w http.ResponseWriter, r *http.Request) {
	actor, _ := auth.UserFrom(r.Context())
	var req addAPIKeyReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	provider := strings.TrimSpace(req.Provider)
	key := strings.TrimSpace(req.KeyValue)
	model := strings.TrimSpace(req.Model)
	if provider == "" {
		writeErr(w, http.StatusBadRequest, "provider is required")
		return
	}
	if key == "" {
		writeErr(w, http.StatusBadRequest, "key_value is required")
		return
	}

	if req.Validate {
		ok, msg := orchestrator.ValidateLLM(r.Context(), s.Cfg.DockerImage, key, provider, model)
		writeJSON(w, http.StatusOK, map[string]any{"valid": ok, "message": msg})
		return
	}

	entry := models.APIKeyPoolEntry{
		Provider: provider, Model: model, KeyValue: key,
		Label: strings.TrimSpace(req.Label), Active: true,
	}
	if err := s.DB.Create(&entry).Error; err != nil {
		writeErr(w, http.StatusInternalServerError, "could not add key")
		return
	}
	s.audit(actor.ID, "apikey.add", "apikey", entry.ID, "provider="+provider, clientIP(r))
	writeJSON(w, http.StatusCreated, map[string]any{"status": "ok", "id": entry.ID})
}

func (s *Server) handleToggleAPIKey(w http.ResponseWriter, r *http.Request) {
	actor, _ := auth.UserFrom(r.Context())
	id := r.PathValue("id")

	var entry models.APIKeyPoolEntry
	if err := s.DB.First(&entry, "id = ?", id).Error; err != nil {
		writeErr(w, http.StatusNotFound, "key not found")
		return
	}
	updates := map[string]any{"active": !entry.Active}
	if !entry.Active {

		updates["disabled"] = false
		updates["failed_count"] = 0
		updates["last_error"] = ""
	}
	s.DB.Model(&entry).Updates(updates)
	s.audit(actor.ID, "apikey.toggle", "apikey", id, "", clientIP(r))
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

func (s *Server) handleDeleteAPIKey(w http.ResponseWriter, r *http.Request) {
	actor, _ := auth.UserFrom(r.Context())
	id := r.PathValue("id")
	var entry models.APIKeyPoolEntry
	if err := s.DB.First(&entry, "id = ?", id).Error; err != nil {
		writeErr(w, http.StatusNotFound, "key not found")
		return
	}
	s.DB.Where("key_id = ?", id).Delete(&models.UserKeyAssignment{})
	if err := s.DB.Delete(&models.APIKeyPoolEntry{}, "id = ?", id).Error; err != nil {
		writeErr(w, http.StatusInternalServerError, "could not delete key")
		return
	}
	s.audit(actor.ID, "apikey.delete", "apikey", id, "", clientIP(r))
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

func (s *Server) handleAPIKeyAssignments(w http.ResponseWriter, r *http.Request) {
	type assignRow struct {
		Email     string `json:"email"`
		Provider  string `json:"provider"`
		KeyMasked string `json:"key_masked"`
		Label     string `json:"label"`
	}
	var asns []models.UserKeyAssignment
	s.DB.Find(&asns)
	out := make([]assignRow, 0, len(asns))
	for i := range asns {
		var u models.User
		if err := s.DB.Select("email").First(&u, "id = ?", asns[i].UserID).Error; err != nil {
			continue
		}
		var k models.APIKeyPoolEntry
		s.DB.First(&k, "id = ?", asns[i].KeyID)
		out = append(out, assignRow{
			Email: u.Email, Provider: asns[i].Provider,
			KeyMasked: maskKey(k.KeyValue), Label: k.Label,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"assignments": out})
}
