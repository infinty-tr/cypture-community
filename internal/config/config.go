package config

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type Config struct {
	Host    string
	Port    int
	BaseURL string
	Env     string

	DBPath string

	SessionSecret []byte

	AdminEmail    string
	AdminPassword string

	AgentDir  string
	AgentBin  string
	EngineBin string
	EngineURL string

	RunnerKind  string
	RunnerModel string
	RunnerAgent string

	ReasoningModel string

	LLMAPIKey       string
	LLMProvider     string
	RunnerSkipPerms bool
	BudgetSeconds   int

	ScanRetentionDays int

	PriceMarkup         float64
	MaxConcurrent       int
	GlobalMaxConcurrent int
	RateLimitPerMin     int
	RateLimitBurst      int

	DockerImage     string
	DockerNetwork   string
	DockerMemory    string
	DockerCPUs      string
	AgentAuthDir    string
	EngineTokenPath string

	K8sKubeconfig string
	K8sNamespace  string
	KubectlBin    string

	SMTPHost string
	SMTPPort string
	SMTPUser string
	SMTPPass string
	SMTPFrom string

	TUIBin string

	FrontendDir string
}

func (c *Config) Dev() bool {
	switch strings.ToLower(strings.TrimSpace(c.Env)) {
	case "dev", "local", "test", "development":
		return true
	default:
		return false
	}
}

func (c *Config) EmailVerifyEnabled() bool { return strings.TrimSpace(c.SMTPHost) != "" }

var ModelTiers = map[string]string{
	"free":     "openai/gpt-4o-mini",
	"fast":     "openai/gpt-4o-mini",
	"strong":   "openai/gpt-4o",
	"frontier": "openai/gpt-4o",
}

func ValidModelTier(label string) bool {
	_, ok := ModelTiers[strings.ToLower(strings.TrimSpace(label))]
	return ok
}

const MicrosPerUSD = 1_000_000

func USDToMicros(usd float64) int64 {
	if usd <= 0 {
		return 0
	}
	return int64(usd*MicrosPerUSD + 0.5)
}

func MicrosToUSD(micros int64) float64 { return float64(micros) / MicrosPerUSD }

type ModelPrice struct {
	InPerM  float64
	OutPerM float64
}

var ModelPrices = map[string]ModelPrice{
	"openai/gpt-4o-mini": {InPerM: 0.15, OutPerM: 0.60},
	"openai/gpt-4o":      {InPerM: 2.50, OutPerM: 10.00},
}

func PriceTokensMicros(model string, tokensIn, tokensOut, tokensReasoning int64) int64 {
	p, ok := ModelPrices[model]
	if !ok {
		return 0
	}
	usd := float64(tokensIn)/1e6*p.InPerM + float64(tokensOut+tokensReasoning)/1e6*p.OutPerM
	return USDToMicros(usd)
}

func ResolveModel(label, def string) string {
	if id, ok := ModelTiers[strings.ToLower(strings.TrimSpace(label))]; ok {
		return id
	}
	return def
}

func defaultPath(rel string) string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return rel
	}
	return filepath.Join(home, rel)
}

func env(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func envFloat(key string, def float64) float64 {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
	}
	return def
}

func Load() *Config {
	wd, _ := os.Getwd()

	c := &Config{
		Host:          env("CYPTURE_HOST", "127.0.0.1"),
		Port:          envInt("CYPTURE_PORT", 7777),
		Env:           env("CYPTURE_ENV", "dev"),
		DBPath:        env("CYPTURE_DB_PATH", filepath.Join(wd, "data", "cypture.db")),
		AdminEmail:    env("ADMIN_EMAIL", "admin@cypture.local"),
		AdminPassword: env("ADMIN_PASSWORD", ""),
		AgentDir:      env("CYPTURE_AGENT_DIR", filepath.Join(wd, "agent")),
		AgentBin:      env("CYPTURE_AGENT_BIN", "cypture-agent"),
		EngineBin:     env("CYPTURE_ENGINE_BIN", "cypture-engine"),
		EngineURL:     env("CYPTURE_ENGINE_URL", "http://localhost:8080"),
		FrontendDir:   env("CYPTURE_FRONTEND_DIR", filepath.Join(wd, "frontend")),

		RunnerKind:        env("CYPTURE_RUNNER", "sim"),
		RunnerModel:       env("CYPTURE_RUNNER_MODEL", "openai/gpt-4o-mini"),
		RunnerAgent:       env("CYPTURE_RUNNER_AGENT", ""),
		ReasoningModel:    env("CYPTURE_REASONING_MODEL", ""),
		LLMAPIKey:         env("CYPTURE_LLM_API_KEY", ""),
		LLMProvider:       env("CYPTURE_LLM_PROVIDER", ""),
		RunnerSkipPerms:   strings.EqualFold(env("CYPTURE_RUNNER_SKIP_PERMS", "false"), "true"),
		BudgetSeconds:     envInt("CYPTURE_BUDGET_SECONDS", 0),
		ScanRetentionDays: envInt("CYPTURE_SCAN_RETENTION_DAYS", 30),

		PriceMarkup:         envFloat("CYPTURE_PRICE_MARKUP", 1.0),
		MaxConcurrent:       envInt("CYPTURE_MAX_CONCURRENT_SCANS", 3),
		GlobalMaxConcurrent: envInt("CYPTURE_GLOBAL_MAX_CONCURRENT_SCANS", 6),
		RateLimitPerMin:     envInt("CYPTURE_RATE_LIMIT_PER_MIN", 240),
		RateLimitBurst:      envInt("CYPTURE_RATE_LIMIT_BURST", 60),

		DockerImage:     env("CYPTURE_DOCKER_IMAGE", "cypture-engine:latest"),
		DockerNetwork:   env("CYPTURE_DOCKER_NETWORK", ""),
		DockerMemory:    env("CYPTURE_DOCKER_MEMORY", "2g"),
		DockerCPUs:      env("CYPTURE_DOCKER_CPUS", "2"),
		AgentAuthDir:    env("CYPTURE_AGENT_AUTH_DIR", defaultPath(".local/share/cypture-agent")),
		EngineTokenPath: env("CYPTURE_ENGINE_TOKEN", defaultPath(".cypture-mcp/token.json")),
		K8sKubeconfig:   env("CYPTURE_KUBECONFIG", "/etc/rancher/k3s/k3s.yaml"),
		K8sNamespace:    env("CYPTURE_K8S_NAMESPACE", "default"),
		KubectlBin:      env("CYPTURE_KUBECTL_BIN", "kubectl"),
		TUIBin:          env("CYPTURE_TUI_BIN", ""),

		SMTPHost: env("CYPTURE_SMTP_HOST", ""),
		SMTPPort: env("CYPTURE_SMTP_PORT", "587"),
		SMTPUser: env("CYPTURE_SMTP_USER", ""),
		SMTPPass: env("CYPTURE_SMTP_PASS", ""),
		SMTPFrom: env("CYPTURE_SMTP_FROM", ""),
	}

	c.BaseURL = env("CYPTURE_BASE_URL", "http://"+c.Host+":"+strconv.Itoa(c.Port))

	if s := strings.TrimSpace(os.Getenv("CYPTURE_SESSION_SECRET")); s != "" {
		c.SessionSecret = []byte(s)
	} else {
		buf := make([]byte, 32)
		_, _ = rand.Read(buf)
		c.SessionSecret = buf
		slog.Warn("CYPTURE_SESSION_SECRET not set — generated an ephemeral secret; " +
			"all sessions will be invalidated on restart. Set it in production.")
	}

	if c.AdminPassword == "" {
		slog.Warn("ADMIN_PASSWORD not set — no seed admin will be created until you set one.")
	}

	return c
}

func (c *Config) Validate() error {
	if c.Dev() {
		return nil
	}
	var problems []string

	secret := strings.TrimSpace(os.Getenv("CYPTURE_SESSION_SECRET"))
	if len(secret) < 32 {
		problems = append(problems, "CYPTURE_SESSION_SECRET must be set to a strong value "+
			"(≥32 chars; generate with `openssl rand -hex 32`)")
	}

	switch {
	case c.AdminPassword == "":
		problems = append(problems, "ADMIN_PASSWORD must be set in prod")
	case len(c.AdminPassword) < 12:
		problems = append(problems, "ADMIN_PASSWORD is too short (use ≥12 chars)")
	}

	if c.RunnerSkipPerms {
		problems = append(problems, "CYPTURE_RUNNER_SKIP_PERMS must be false in prod "+
			"(skipping permission prompts is unsafe)")
	}

	if len(problems) > 0 {
		return fmt.Errorf("insecure production config:\n  - %s", strings.Join(problems, "\n  - "))
	}
	return nil
}

func RandomToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
