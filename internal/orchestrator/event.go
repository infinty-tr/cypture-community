package orchestrator

import (
	"context"
	"time"
)

const (
	LevelInfo    = "info"
	LevelSuccess = "success"
	LevelWarning = "warning"
	LevelError   = "error"
	LevelThought = "thought"
	LevelAction  = "action"
	LevelFinding = "finding"
	LevelSystem  = "system"

	CatSystem   = "system"
	CatPlanning = "planning"
	CatModule   = "module"
	CatFinding  = "finding"
	CatQuestion = "question"
	CatAnswer   = "answer"
	CatComplete = "complete"
	CatUsage    = "usage"
	CatKB       = "kb"
	CatTraffic  = "traffic"
)

type Event struct {
	Seq      int            `json:"seq"`
	Level    string         `json:"level"`
	Category string         `json:"category"`
	Module   string         `json:"module"`
	Message  string         `json:"message"`
	Data     map[string]any `json:"data,omitempty"`

	Lane string `json:"-"`
}

type Option struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

type Question struct {
	Prompt    string        `json:"prompt"`
	Options   []Option      `json:"options"`
	DefaultID string        `json:"default_id"`
	Timeout   time.Duration `json:"-"`
}

type Controller interface {
	Emit(Event)

	Ask(Question) string
}

type RunSpec struct {
	ScanID          string
	Mode            string
	Target          string
	ScopeHosts      []string
	ScopeExcludes   []string
	OperatorPrompt  string
	TestCredentials string
	WorkDir         string
	AgentDir        string

	AgentBin string
	Model    string

	ReasoningModel string
	AgentName      string
	SkipPerms      bool
	LLMAPIKey      string
	LLMProvider    string
	KBSeed         []byte

	Image           string
	Network         string
	Memory          string
	CPUs            string
	AgentAuthDir    string
	EngineTokenPath string
	BudgetSeconds   int

	Kubeconfig string
	Namespace  string
	KubectlBin string
}

type Runner interface {
	Run(ctx context.Context, spec RunSpec, ctrl Controller) error
}
