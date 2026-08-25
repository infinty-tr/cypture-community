package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type Role string

const (
	RoleAdmin  Role = "admin"
	RoleClient Role = "client"

	RoleViewer Role = "viewer"
)

type UserStatus string

const (
	UserInvited  UserStatus = "invited"
	UserActive   UserStatus = "active"
	UserDisabled UserStatus = "disabled"
)

type EngagementStatus string

const (
	EngDraft       EngagementStatus = "draft"
	EngSubmitted   EngagementStatus = "submitted"
	EngUnderReview EngagementStatus = "under_review"
	EngAccepted    EngagementStatus = "accepted"
	EngRejected    EngagementStatus = "rejected"
	EngRunning     EngagementStatus = "running"
	EngCompleted   EngagementStatus = "completed"
	EngStopped     EngagementStatus = "stopped"
	EngFailed      EngagementStatus = "failed"
)

type ScanStatus string

const (
	ScanStarting      ScanStatus = "starting"
	ScanRunning       ScanStatus = "running"
	ScanAwaitingInput ScanStatus = "awaiting_input"
	ScanCompleted     ScanStatus = "completed"
	ScanStopped       ScanStatus = "stopped"
	ScanFailed        ScanStatus = "failed"
)

type QuestionStatus string

const (
	QOpen     QuestionStatus = "open"
	QAnswered QuestionStatus = "answered"
	QExpired  QuestionStatus = "expired"
)

type Base struct {
	ID        string         `gorm:"primaryKey;type:text" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`
}

func (b *Base) BeforeCreate(_ *gorm.DB) error {
	if b.ID == "" {
		b.ID = uuid.NewString()
	}
	return nil
}

type User struct {
	Base
	Email        string     `gorm:"uniqueIndex;not null" json:"email"`
	PasswordHash string     `gorm:"not null" json:"-"`
	Role         Role       `gorm:"not null;index" json:"role"`
	Status       UserStatus `gorm:"not null;index" json:"status"`
	CompanyName  string     `json:"company_name"`

	InviteTokenHash    string     `gorm:"index" json:"-"`
	InviteExpiresAt    *time.Time `json:"-"`
	MustChangePassword bool       `json:"must_change_password"`

	EmailVerified bool `gorm:"not null;default:true" json:"email_verified"`

	CreatedByID *string `gorm:"index" json:"created_by_id,omitempty"`

	FailedLogins int        `json:"-"`
	LockedUntil  *time.Time `json:"-"`

	LLMAPIKey   string `json:"-"`
	LLMProvider string `json:"llm_provider"`
	RunnerModel string `json:"runner_model"`
}

type Engagement struct {
	Base
	ClientID string `gorm:"index;not null" json:"client_id"`
	Client   *User  `gorm:"foreignKey:ClientID" json:"client,omitempty"`

	Title string `json:"title"`

	ScopeIncludes string `gorm:"type:text" json:"scope_includes"`
	ScopeExcludes string `gorm:"type:text" json:"scope_excludes"`

	Seed      string `json:"seed"`
	ScopeText string `json:"scope_text"`
	Mode      string `json:"mode"`
	Model     string `json:"model"`

	ClientNotes string `json:"client_notes"`
	AdminNotes  string `json:"admin_notes"`

	OperatorPrompt string `json:"operator_prompt"`

	TestCredentials string `json:"test_credentials"`

	Status       EngagementStatus `gorm:"index;not null" json:"status"`
	ReviewedByID *string          `json:"reviewed_by_id,omitempty"`
	SubmittedAt  *time.Time       `json:"submitted_at,omitempty"`
	AcceptedAt   *time.Time       `json:"accepted_at,omitempty"`
}

type ScanSession struct {
	Base
	EngagementID string     `gorm:"index;not null" json:"engagement_id"`
	Status       ScanStatus `gorm:"index;not null" json:"status"`

	AgentSessionID string     `json:"-"`
	WorkDir        string     `json:"-"`
	ReportPath     string     `json:"-"`
	StartedAt      *time.Time `json:"started_at,omitempty"`
	EndedAt        *time.Time `json:"ended_at,omitempty"`
	LastSeq        int        `json:"last_seq"`

	Archived bool `gorm:"not null;default:false;index" json:"-"`

	Model           string `json:"model"`
	CostMicros      int64  `gorm:"not null;default:0" json:"cost_micros"`
	TokensInput     int64  `gorm:"not null;default:0" json:"tokens_input"`
	TokensOutput    int64  `gorm:"not null;default:0" json:"tokens_output"`
	TokensReasoning int64  `gorm:"not null;default:0" json:"tokens_reasoning"`
}

type LogEvent struct {
	Base
	ScanSessionID string `gorm:"index;not null" json:"scan_session_id"`
	Seq           int    `gorm:"index" json:"seq"`
	Level         string `json:"level"`
	Category      string `json:"category"`
	Module        string `json:"module"`
	Message       string `json:"message"`

	PaneID     string `json:"pane_id"`
	PaneModule string `json:"pane_module"`
	PaneStatus string `json:"pane_status"`
}

type Question struct {
	Base
	ScanSessionID  string         `gorm:"index;not null" json:"scan_session_id"`
	Prompt         string         `json:"prompt"`
	Options        string         `gorm:"type:text" json:"options"`
	DefaultOption  string         `json:"default_option"`
	TimeoutSeconds int            `json:"timeout_seconds"`
	Status         QuestionStatus `gorm:"index;not null" json:"status"`
	SelectedOption string         `json:"selected_option"`
	AnsweredBy     string         `json:"answered_by"`
	ResolvedAt     *time.Time     `json:"resolved_at,omitempty"`
	ExpiresAt      time.Time      `json:"expires_at"`
}

type Finding struct {
	Base
	EngagementID  string `gorm:"index;not null" json:"engagement_id"`
	ScanSessionID string `gorm:"index" json:"scan_session_id"`
	Title         string `json:"title"`
	Severity      string `json:"severity"`
	VulnType      string `json:"vuln_type"`
	Endpoint      string `json:"endpoint"`
	Method        string `json:"method"`
	Evidence      string `gorm:"type:text" json:"evidence"`
	Remediation   string `gorm:"type:text" json:"remediation"`

	PoC               string `gorm:"type:text" json:"poc"`
	CVSS              string `json:"cvss"`
	Confidence        string `json:"confidence"`
	Request           string `gorm:"type:text" json:"request"`
	Response          string `gorm:"type:text" json:"response"`
	DurationMs        int64  `json:"duration_ms"`
	ProofArtifact     string `json:"proof_artifact"`
	Verified          bool   `json:"verified"`
	VerifyNote        string `gorm:"type:text" json:"verify_note"`
	ProofKind         string `json:"proof_kind"`
	ExtractedEvidence string `gorm:"type:text" json:"extracted_evidence"`
	ReproSteps        string `gorm:"type:text" json:"repro_steps"`
	Impact            string `gorm:"type:text" json:"impact"`
	Status            string `json:"status"`
}

type AuthSession struct {
	Base
	UserID    string    `gorm:"index;not null" json:"user_id"`
	TokenHash string    `gorm:"uniqueIndex;not null" json:"-"`
	ExpiresAt time.Time `gorm:"index" json:"expires_at"`
	UserAgent string    `json:"-"`
	IP        string    `json:"-"`
}

type AuditLog struct {
	Base
	ActorID    string `gorm:"index" json:"actor_id"`
	Action     string `gorm:"index" json:"action"`
	TargetType string `json:"target_type"`
	TargetID   string `json:"target_id"`
	Detail     string `gorm:"type:text" json:"detail"`
	IP         string `json:"ip"`
}

type Setting struct {
	Key       string    `gorm:"primaryKey;type:text" json:"key"`
	Value     string    `gorm:"type:text" json:"value"`
	UpdatedAt time.Time `json:"updated_at"`
}

type APIKeyPoolEntry struct {
	Base
	Provider    string     `gorm:"index;not null" json:"provider"`
	Model       string     `json:"model"`
	KeyValue    string     `gorm:"not null" json:"-"`
	Label       string     `json:"label"`
	Active      bool       `gorm:"not null;default:true" json:"active"`
	Disabled    bool       `gorm:"not null;default:false" json:"disabled"`
	FailedCount int        `gorm:"not null;default:0" json:"failed_count"`
	UsageCount  int64      `gorm:"not null;default:0" json:"usage_count"`
	LastError   string     `json:"last_error,omitempty"`
	LastUsedAt  *time.Time `json:"last_used_at,omitempty"`
}

type UserKeyAssignment struct {
	UserID     string    `gorm:"primaryKey;type:text" json:"user_id"`
	KeyID      string    `gorm:"index;not null" json:"key_id"`
	Provider   string    `gorm:"index" json:"provider"`
	AssignedAt time.Time `json:"assigned_at"`
}

type KBEntry struct {
	TargetHost    string    `gorm:"primaryKey;type:text" json:"target_host"`
	LastRun       time.Time `json:"last_run"`
	Runs          int       `json:"runs"`
	ConfirmedTech string    `gorm:"type:text" json:"confirmed_tech"`
	KnownFindings string    `gorm:"type:text" json:"known_findings"`
	DeadEnds      string    `gorm:"type:text" json:"dead_ends"`
	Notes         string    `gorm:"type:text" json:"notes"`
}

type TechPrior struct {
	TechKey   string    `gorm:"primaryKey;type:text" json:"tech_key"`
	VulnClass string    `gorm:"primaryKey;type:text" json:"vuln_class"`
	Hits      int       `json:"hits"`
	Notes     string    `gorm:"type:text" json:"notes"`
	LastSeen  time.Time `json:"last_seen"`
}

type HTTPTraffic struct {
	Base
	ScanSessionID string `gorm:"index" json:"scan_session_id"`
	Seq           int64  `gorm:"index" json:"seq"`
	Method        string `json:"method"`
	URL           string `gorm:"type:text" json:"url"`
	Host          string `json:"host"`
	Path          string `gorm:"type:text" json:"path"`
	Status        int    `json:"status"`
	DurationMs    int64  `json:"duration_ms"`
	Length        int    `json:"length"`
	TLS           bool   `json:"tls"`
	ReqHeaders    string `gorm:"type:text" json:"req_headers"`
	ReqBody       string `gorm:"type:text" json:"req_body"`
	RespHeaders   string `gorm:"type:text" json:"resp_headers"`
	RespBody      string `gorm:"type:text" json:"resp_body"`
	TrueLen       int    `json:"true_len"`
	Error         string `json:"error,omitempty"`
}

func All() []any {
	return []any{
		&Setting{},
		&APIKeyPoolEntry{},
		&UserKeyAssignment{},
		&KBEntry{},
		&TechPrior{},
		&User{},
		&Engagement{},
		&ScanSession{},
		&LogEvent{},
		&Question{},
		&Finding{},
		&HTTPTraffic{},
		&AuthSession{},
		&AuditLog{},
	}
}
