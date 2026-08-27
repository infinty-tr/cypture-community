package server

import (
	"net/http"
	"strings"
	"time"

	"cypture/internal/auth"
	"cypture/internal/models"
	"cypture/internal/orchestrator"

	"gorm.io/gorm"
)

const (
	settingLLMAPIKey      = "llm_api_key"
	settingLLMProvider    = "llm_provider"
	settingRunnerModel    = "runner_model"
	settingReasoningModel = "reasoning_model"
)

func getSetting(db *gorm.DB, key string) string {
	var s models.Setting
	if err := db.First(&s, "key = ?", key).Error; err != nil {
		return ""
	}
	v := strings.TrimSpace(s.Value)
	if key == settingLLMAPIKey {
		v = models.DecryptSecret(v)
	}
	return v
}

func setSetting(db *gorm.DB, key, value string) error {
	value = strings.TrimSpace(value)
	if key == settingLLMAPIKey {
		value = models.EncryptSecret(value)
	}
	return db.Save(&models.Setting{Key: key, Value: value, UpdatedAt: time.Now()}).Error
}

func maskKey(k string) string {
	k = strings.TrimSpace(k)
	if k == "" {
		return ""
	}
	if len(k) <= 8 {
		return "****"
	}
	return k[:4] + "…" + k[len(k)-4:]
}

type settingsReq struct {
	LLMAPIKey      *string `json:"llm_api_key"`
	LLMProvider    *string `json:"llm_provider"`
	RunnerModel    *string `json:"runner_model"`
	ReasoningModel *string `json:"reasoning_model"`
}

func (s *Server) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	key := getSetting(s.DB, settingLLMAPIKey)
	if key == "" {
		key = s.Cfg.LLMAPIKey
	}
	model := getSetting(s.DB, settingRunnerModel)
	if model == "" {
		model = s.Cfg.RunnerModel
	}
	reasoning := getSetting(s.DB, settingReasoningModel)
	if reasoning == "" {
		reasoning = s.Cfg.ReasoningModel
	}
	provider := getSetting(s.DB, settingLLMProvider)
	if provider == "" {
		provider = s.Cfg.LLMProvider
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"llm_api_key_set":    key != "",
		"llm_api_key_masked": maskKey(key),
		"llm_provider":       provider,
		"runner_model":       model,
		"reasoning_model":    reasoning,

		"model_tiers": []string{"openai/gpt-4o", "openai/gpt-4o-mini", "anthropic/claude-3-5-sonnet", "openrouter/<provider>/<model>"},
	})
}

func (s *Server) handleSetSettings(w http.ResponseWriter, r *http.Request) {
	actor, _ := auth.UserFrom(r.Context())
	var req settingsReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	if req.LLMAPIKey != nil {
		_ = setSetting(s.DB, settingLLMAPIKey, *req.LLMAPIKey)
	}
	if req.LLMProvider != nil {
		_ = setSetting(s.DB, settingLLMProvider, *req.LLMProvider)
	}
	if req.RunnerModel != nil {
		_ = setSetting(s.DB, settingRunnerModel, *req.RunnerModel)
	}
	if req.ReasoningModel != nil {
		_ = setSetting(s.DB, settingReasoningModel, *req.ReasoningModel)
	}
	s.audit(actor.ID, "settings.update", "settings", "llm", "provider/model updated", clientIP(r))
	s.handleGetSettings(w, r)
}

func (s *Server) handleValidateSettings(w http.ResponseWriter, r *http.Request) {
	var req settingsReq
	_ = decodeJSON(r, &req)

	key := ""
	if req.LLMAPIKey != nil {
		key = *req.LLMAPIKey
	}
	if strings.TrimSpace(key) == "" {
		key = getSetting(s.DB, settingLLMAPIKey)
		if key == "" {
			key = s.Cfg.LLMAPIKey
		}
	}
	model := ""
	if req.RunnerModel != nil {
		model = *req.RunnerModel
	}
	if strings.TrimSpace(model) == "" {
		model = getSetting(s.DB, settingRunnerModel)
		if model == "" {
			model = s.Cfg.RunnerModel
		}
	}
	provider := ""
	if req.LLMProvider != nil {
		provider = *req.LLMProvider
	}
	ok, msg := orchestrator.ValidateLLM(r.Context(), s.Cfg.DockerImage, key, provider, model)
	writeJSON(w, http.StatusOK, map[string]any{"valid": ok, "message": msg, "model": model})
}

func (s *Server) handleGetMyLLM(w http.ResponseWriter, r *http.Request) {
	u, _ := auth.UserFrom(r.Context())
	var usr models.User
	s.DB.Select("llm_api_key", "llm_provider", "runner_model").First(&usr, "id = ?", u.ID)
	writeJSON(w, http.StatusOK, map[string]any{
		"llm_api_key_set":    usr.LLMAPIKey != "",
		"llm_api_key_masked": maskKey(usr.LLMAPIKey),
		"llm_provider":       usr.LLMProvider,
		"runner_model":       usr.RunnerModel,
	})
}

func (s *Server) handleSetMyLLM(w http.ResponseWriter, r *http.Request) {
	u, _ := auth.UserFrom(r.Context())
	var req struct {
		LLMAPIKey   *string `json:"llm_api_key"`
		LLMProvider *string `json:"llm_provider"`
		RunnerModel *string `json:"runner_model"`
		Validate    bool    `json:"validate"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}

	if req.LLMAPIKey != nil && len(*req.LLMAPIKey) > 512 {
		writeErr(w, http.StatusBadRequest, "api key is too long")
		return
	}
	if req.LLMProvider != nil && len(*req.LLMProvider) > 64 {
		writeErr(w, http.StatusBadRequest, "provider is too long")
		return
	}
	if req.RunnerModel != nil && len(*req.RunnerModel) > 128 {
		writeErr(w, http.StatusBadRequest, "model id is too long")
		return
	}

	if req.Validate {
		var usr models.User
		s.DB.First(&usr, "id = ?", u.ID)
		key := usr.LLMAPIKey
		if req.LLMAPIKey != nil && *req.LLMAPIKey != "" {
			key = *req.LLMAPIKey
		}
		model := usr.RunnerModel
		if req.RunnerModel != nil && *req.RunnerModel != "" {
			model = *req.RunnerModel
		}
		provider := ""
		if req.LLMProvider != nil {
			provider = *req.LLMProvider
		}
		ok, msg := orchestrator.ValidateLLM(r.Context(), s.Cfg.DockerImage, key, provider, model)
		writeJSON(w, http.StatusOK, map[string]any{"valid": ok, "message": msg})
		return
	}

	updates := map[string]any{}
	if req.LLMAPIKey != nil {
		// Map-based Updates bypass the User BeforeSave hook, so encrypt here.
		updates["llm_api_key"] = models.EncryptSecret(strings.TrimSpace(*req.LLMAPIKey))
	}
	if req.LLMProvider != nil {
		updates["llm_provider"] = strings.TrimSpace(*req.LLMProvider)
	}
	if req.RunnerModel != nil {
		updates["runner_model"] = strings.TrimSpace(*req.RunnerModel)
	}
	if len(updates) > 0 {
		s.DB.Model(&models.User{}).Where("id = ?", u.ID).Updates(updates)
	}
	s.handleGetMyLLM(w, r)
}
