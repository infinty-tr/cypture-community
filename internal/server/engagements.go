package server

import (
	"strings"
	"time"

	"cypture/internal/models"
)

var validModes = map[string]bool{
	"full": true, "attack": true, "web": true, "api": true, "recon": true,
}

type engagementDTO struct {
	ID            string   `json:"id"`
	Title         string   `json:"title"`
	Seed          string   `json:"seed"`
	ScopeIncludes []string `json:"scope_includes"`
	ScopeExcludes []string `json:"scope_excludes"`
	ScopeText     string   `json:"scope_text"`
	Mode          string   `json:"mode"`
	Model         string   `json:"model,omitempty"`
	ClientNotes   string   `json:"client_notes"`
	AdminNotes    string   `json:"admin_notes"`
	Status        string   `json:"status"`
	ClientEmail   string   `json:"client_email,omitempty"`
	CompanyName   string   `json:"company_name,omitempty"`
	ClientHasKey  bool     `json:"client_has_key"`
	CreatedAt     string   `json:"created_at"`
	SubmittedAt   string   `json:"submitted_at,omitempty"`
	AcceptedAt    string   `json:"accepted_at,omitempty"`
}

func tstr(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.Format(time.RFC3339)
}

func toEngagementDTO(e *models.Engagement, withClient bool) engagementDTO {
	d := engagementDTO{
		ID:            e.ID,
		Title:         e.Title,
		Seed:          e.Seed,
		ScopeIncludes: decodeList(e.ScopeIncludes),
		ScopeExcludes: decodeList(e.ScopeExcludes),
		ScopeText:     e.ScopeText,
		Mode:          e.Mode,
		Model:         e.Model,
		ClientNotes:   e.ClientNotes,
		AdminNotes:    e.AdminNotes,
		Status:        string(e.Status),
		CreatedAt:     e.CreatedAt.Format(time.RFC3339),
		SubmittedAt:   tstr(e.SubmittedAt),
		AcceptedAt:    tstr(e.AcceptedAt),
	}
	if withClient && e.Client != nil {
		d.ClientEmail = e.Client.Email
		d.CompanyName = e.Client.CompanyName
		d.ClientHasKey = strings.TrimSpace(e.Client.LLMAPIKey) != ""
	}
	return d
}

type createEngagementReq struct {
	Target        string   `json:"target"`
	Title         string   `json:"title"`
	ScopeIncludes []string `json:"scope_includes"`
	ScopeExcludes []string `json:"scope_excludes"`
	ScopeText     string   `json:"scope_text"`
	Mode          string   `json:"mode"`
	Model         string   `json:"model"`
	ClientNotes   string   `json:"client_notes"`
	Authorized    bool     `json:"authorized"`
}
