package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
)

type DockerRunner struct{}

func (DockerRunner) Run(ctx context.Context, spec RunSpec, ctrl Controller) error {
	name := "cyp-" + sanitize(spec.ScanID)

	depth := "deep"

	feedPath := ""
	if dir, err := os.MkdirTemp("", "cyp-feed-"+sanitize(spec.ScanID)); err == nil {
		feedPath = filepath.Join(dir, "feed.jsonl")
		defer os.RemoveAll(dir)

		if len(spec.KBSeed) > 0 {
			_ = os.WriteFile(filepath.Join(dir, "kb.json"), spec.KBSeed, 0o644)
		}
	}

	mem := spec.Memory
	if mem == "" {
		mem = "2g"
		if depth == "deep" {

			mem = "6g"
		}
	}
	cpus := spec.CPUs
	if cpus == "" {
		cpus = "2"
	}
	args := []string{
		"run", "--rm", "-i",
		"--name", name,
		"--security-opt", "no-new-privileges",
		"--cap-drop", "ALL",

		"--cap-add", "DAC_OVERRIDE",
		"--ipc", "private",
		"--pids-limit", "512",
		"--ulimit", "nofile=4096:8192",
		"--memory", mem,
		"--cpus", cpus,
	}
	if feedPath != "" {
		args = append(args, "-v", filepath.Dir(feedPath)+":/cyp")
	}
	if spec.Network != "" {
		args = append(args, "--network", spec.Network)
	}

	if spec.LLMAPIKey == "" && spec.AgentAuthDir != "" && os.Getenv("CYP_ALLOW_SHARED_AUTH_JSON") == "1" {
		if p := spec.AgentAuthDir + "/auth.json"; fileExists(p) {
			args = append(args, "-v", p+":/root/.local/share/cypture-agent/auth.json:ro")
		}
	}

	args = append(args,
		"-e", "CYP_MODE="+spec.Mode,
		"-e", "CYP_TARGET="+spec.Target,
		"-e", "CYP_SCOPE_INCLUDES="+strings.Join(spec.ScopeHosts, ","),
		"-e", "CYP_SCOPE_EXCLUDES="+strings.Join(spec.ScopeExcludes, ","),
	)
	if spec.Model != "" {
		args = append(args, "-e", "CYP_MODEL="+spec.Model)
	}

	if rm := strings.TrimSpace(spec.ReasoningModel); rm != "" && rm != spec.Model {
		if providerPrefix(rm) == providerPrefix(spec.Model) {
			args = append(args, "-e", "CYP_MODEL_REASONING="+rm)
		} else {
			ctrl.Emit(Event{Level: LevelWarning, Category: CatSystem, Module: "Çekirdek",
				Message: "Reasoning-model separation skipped: a different provider from the base model (a single key cannot validate both)."})
		}
	}

	if p := strings.TrimSpace(spec.OperatorPrompt); p != "" {
		args = append(args, "-e", "CYP_OPERATOR_PROMPT="+p)
	}

	if c := strings.TrimSpace(spec.TestCredentials); c != "" {
		args = append(args, "-e", "CYP_TEST_CREDS="+c)
	}

	if spec.LLMAPIKey != "" {
		kf, err := os.CreateTemp("", "cyp-key-*")
		if err != nil {

			return fmt.Errorf("could not create a secure temporary file for the LLM key; scan aborted (the key is NOT placed in argv): %w", err)
		}
		_, _ = kf.WriteString(spec.LLMAPIKey)
		_ = kf.Close()
		defer os.Remove(kf.Name())
		args = append(args, "-v", kf.Name()+":/run/cyp_llm_key:ro", "-e", "CYP_LLM_API_KEY_FILE=/run/cyp_llm_key")
		if spec.LLMProvider != "" {
			args = append(args, "-e", "CYP_LLM_PROVIDER="+spec.LLMProvider)
		}
	}

	args = append(args, "-e", "CYP_DEPTH="+depth)
	if spec.AgentName != "" {
		args = append(args, "-e", "CYP_AGENT="+spec.AgentName)
	}
	if spec.SkipPerms {
		args = append(args, "-e", "CYP_SKIP_PERMS=1")
	}

	passEnv := []string{
		"CYP_OOB_ADDR", "CYP_OOB_URL", "CYP_OOB_DOMAIN", "CYP_OOB_SMTP_ADDR",
		"CYP_MAX_PARALLEL", "CYP_DEEPEN_HOSTS_PER_ROUND", "CYP_REAPER_STALL_TTL",
		"CYP_AGENT_WAIT_MAX", "CYP_USE_MODEL_ORCH", "CYP_DETERMINISTIC", "CYP_GATE_MAX_WAIT", "CYP_SCRUB_KEYS",
	}
	for _, k := range passEnv {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			args = append(args, "-e", k+"="+v)
		}
	}

	img := spec.Image
	if img == "" {
		img = "cypture-engine:latest"
	}
	args = append(args, img)

	cmd := exec.CommandContext(ctx, "docker", args...)

	ctrl = withPanes(ctrl)

	ctrl.Emit(Event{Level: LevelSystem, Category: CatSystem, Module: "Çekirdek",
		Message: "Preparing an isolated assessment environment; mapping the target surface."})
	ctrl.Emit(Event{Level: LevelInfo, Category: CatSystem, Module: "Çekirdek",
		Message: "Starting assessment modules; the first observations will begin streaming shortly (~30s)."})

	onCancel := func() {
		_ = exec.Command("docker", "kill", name).Run()
	}

	ctrl, stopHB, stalledFor := withHeartbeat(ctx, ctrl)
	defer stopHB()

	if feedPath != "" {
		go tailFeed(ctx, feedPath, ctrl)
		go tailFindings(ctx, filepath.Join(filepath.Dir(feedPath), "findings.ndjson"), ctrl)

		go tailTraffic(ctx, filepath.Join(filepath.Dir(feedPath), "traffic.ndjson"), ctrl)

		go tailAgents(ctx, filepath.Join(filepath.Dir(feedPath), "agents"), ctrl)

		go tailQuestions(ctx, filepath.Dir(feedPath), ctrl)
	}

	const stallLimit = 10 * time.Minute
	var stalled atomic.Bool
	watchCtx, stopWatch := context.WithCancel(ctx)
	defer stopWatch()
	go func() {
		t := time.NewTicker(15 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-watchCtx.Done():
				return
			case <-t.C:
				if stalledFor() > stallLimit {
					ctrl.Emit(Event{Level: LevelWarning, Category: CatSystem, Module: "Çekirdek",
						Message: "Activity has stalled; ending the assessment and saving the findings collected so far."})
					stalled.Store(true)
					onCancel()
					return
				}
			}
		}
	}()

	err := streamNDJSON(ctx, cmd, ctrl, onCancel)

	if feedPath != "" {
		importFindingsJSON(filepath.Dir(feedPath), ctrl)
		importKBUpdate(filepath.Dir(feedPath), ctrl)
	}

	if stalled.Load() {
		return nil
	}
	return err
}

func tailLines(ctx context.Context, path string, fn func(line string)) {
	var off int64
	pending := ""
	tick := time.NewTicker(400 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		f, err := os.Open(path)
		if err != nil {
			continue
		}

		if fi, statErr := f.Stat(); statErr == nil && fi.Size() < off {
			off = 0
			pending = ""
		}
		if off > 0 {
			if _, err := f.Seek(off, io.SeekStart); err != nil {
				_ = f.Close()
				off = 0
				continue
			}
		}
		data, _ := io.ReadAll(f)
		_ = f.Close()
		off += int64(len(data))
		pending += string(data)
		for {
			i := strings.IndexByte(pending, '\n')
			if i < 0 {
				break
			}
			line := strings.TrimSpace(pending[:i])
			pending = pending[i+1:]
			if line != "" {
				fn(line)
			}
		}
	}
}

func tailFeed(ctx context.Context, path string, ctrl Controller) {
	tailLines(ctx, path, func(line string) {
		if e := feedEvent(line); e != nil {
			ctrl.Emit(*e)
		}
	})
}

func tailFindings(ctx context.Context, path string, ctrl Controller) {

	seen := map[string]bool{}
	tick := time.NewTicker(400 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || seen[line] {
				continue
			}
			seen[line] = true
			var mm map[string]any
			if json.Unmarshal([]byte(line), &mm) == nil {
				emitFinding(mm, ctrl)
			}
		}
	}
}

func tailTraffic(ctx context.Context, path string, ctrl Controller) {
	tailLines(ctx, path, func(line string) {
		var m map[string]any
		if json.Unmarshal([]byte(line), &m) == nil && len(m) > 0 {
			ctrl.Emit(Event{Category: CatTraffic, Data: m})
		}
	})
}

func tailQuestions(ctx context.Context, dir string, ctrl Controller) {
	qpath := filepath.Join(dir, "question.json")
	apath := filepath.Join(dir, "answer.json")
	tick := time.NewTicker(800 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		data, err := os.ReadFile(qpath)
		if err != nil {
			continue
		}
		_ = os.Remove(qpath)
		var q struct {
			Prompt  string `json:"prompt"`
			Options []struct {
				ID    string `json:"id"`
				Label string `json:"label"`
			} `json:"options"`
			Default string `json:"default_id"`
			Timeout int    `json:"timeout"`
		}
		if json.Unmarshal(data, &q) != nil || strings.TrimSpace(q.Prompt) == "" {
			continue
		}
		opts := make([]Option, 0, len(q.Options))
		for _, o := range q.Options {
			opts = append(opts, Option{ID: o.ID, Label: Scrub(o.Label)})
		}
		if len(opts) == 0 {
			opts = []Option{{ID: "deep", Label: "Yes, dig deeper"}, {ID: "stop", Label: "No, report"}}
		}
		def := q.Default
		if def == "" {
			def = opts[0].ID
		}
		to := time.Duration(q.Timeout) * time.Second
		if to <= 0 || to > 240*time.Second {
			to = 240 * time.Second
		}
		choice := ctrl.Ask(Question{Prompt: Scrub(q.Prompt), Options: opts, DefaultID: def, Timeout: to})
		if strings.TrimSpace(choice) == "" {
			choice = def
		}
		_ = os.WriteFile(apath, []byte(`{"option_id":`+jsonQuote(choice)+`}`), 0o644)
	}
}

func jsonQuote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func importFindingsJSON(dir string, ctrl Controller) {
	data, err := os.ReadFile(filepath.Join(dir, "findings.json"))
	if err != nil {
		return
	}

	var arr []map[string]any
	if json.Unmarshal(data, &arr) != nil {
		var wrap struct {
			Findings []map[string]any `json:"findings"`
		}
		if json.Unmarshal(data, &wrap) != nil {
			return
		}
		arr = wrap.Findings
	}
	for _, m := range arr {
		emitFinding(m, ctrl)
	}
}

func importKBUpdate(dir string, ctrl Controller) {
	data, err := os.ReadFile(filepath.Join(dir, "kb_update.json"))
	if err != nil {
		return
	}
	var m map[string]any
	if json.Unmarshal(data, &m) != nil || len(m) == 0 {
		return
	}
	ctrl.Emit(Event{Level: LevelInfo, Category: CatKB, Module: "Bilgi Tabanı", Data: m})
}

func emitFinding(m map[string]any, ctrl Controller) {
	gv := func(keys ...string) string {
		for _, k := range keys {
			if v, ok := m[k]; ok {
				if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
					return s
				}
			}
		}
		return ""
	}
	title := gv("title", "name")
	if title == "" {
		return
	}
	sev := strings.ToLower(gv("severity"))
	if sev == "" {
		sev = "info"
	}
	gb := func(keys ...string) bool {
		for _, k := range keys {
			if v, ok := m[k]; ok {
				if b, ok := v.(bool); ok {
					return b
				}
			}
		}
		return false
	}

	gn := func(keys ...string) int64 {
		for _, k := range keys {
			switch v := m[k].(type) {
			case float64:
				return int64(v)
			case int64:
				return v
			case int:
				return int64(v)
			}
		}
		return 0
	}

	verified := gb("verified")

	if !verified && (sev == "critical" || sev == "high") {
		sev = "medium"
	}
	label := "Candidate finding: "
	if verified {
		label = "Verified finding: "
	}
	ctrl.Emit(Event{Level: LevelFinding, Category: CatFinding, Module: "Bulgu Motoru",
		Message: label + Scrub(clip(title, 120)),
		Data: map[string]any{
			"title":          Scrub(title),
			"severity":       sev,
			"endpoint":       Scrub(gv("endpoint", "url")),
			"method":         gv("method"),
			"vuln_type":      Scrub(gv("vuln_type", "type")),
			"evidence":       Scrub(gv("evidence", "description")),
			"poc":            Scrub(gv("poc", "proof_of_concept")),
			"cvss":           gv("cvss", "cvss_score"),
			"confidence":     gv("confidence"),
			"request":        Scrub(gv("request", "raw_request")),
			"response":       Scrub(gv("response", "raw_response")),
			"duration_ms":    gn("duration_ms"),
			"proof_artifact": gv("proof_artifact"),
			"remediation":    Scrub(gv("remediation", "fix")),
			"verified":       verified,
			"verify_note":    Scrub(gv("verify_note", "verification")),

			"repro_steps":        Scrub(gv("repro_steps")),
			"impact":             Scrub(gv("impact")),
			"extracted_evidence": Scrub(gv("extracted_evidence")),
			"proof_kind":         gv("proof_kind"),
		}})
}

func feedEvent(line string) *Event {
	var m map[string]any
	if json.Unmarshal([]byte(line), &m) != nil {
		return nil
	}
	switch feedStr(m, "t") {
	case "req":
		msg := "→ " + strings.TrimSpace(feedStr(m, "method")+" "+feedStr(m, "host")+feedStr(m, "path"))
		if status := feedInt(m, "status"); status > 0 {
			msg += fmt.Sprintf(" (HTTP %d)", status)
		}
		if feedStr(m, "err") != "" {
			msg += " ✗"
		}

		if rp := strings.TrimSpace(feedStr(m, "resp")); rp != "" {
			msg += "\n↳ " + clip(rp, 160)
		}
		return &Event{Level: LevelInfo, Category: CatModule, Module: "HTTP Probe",
			Message: Scrub(clip(msg, 360))}
	case "connect":

		return nil
	case "ws":

		dir := feedStr(m, "dir")
		path := strings.TrimSpace(feedStr(m, "host") + feedStr(m, "path"))
		var msg string
		switch dir {
		case "open":
			msg = "⇅ WS opened " + path
		case "close":
			msg = "⇅ WS closed " + path
		case "c2s":
			msg = "⇡ WS→ " + clip(strings.TrimSpace(feedStr(m, "data")), 200)
		case "s2c":
			msg = "⇣ WS← " + clip(strings.TrimSpace(feedStr(m, "data")), 200)
		default:
			return nil
		}
		return &Event{Level: LevelInfo, Category: CatModule, Module: "WebSocket",
			Message: Scrub(clip(msg, 280))}
	case "find":
		title := feedStr(m, "title")
		if title == "" {
			return nil
		}
		sev := strings.ToLower(feedStr(m, "severity"))
		if sev == "" {
			sev = "info"
		}
		verified := feedBool(m, "verified")

		if !verified && (sev == "critical" || sev == "high") {
			sev = "medium"
		}
		label := "Candidate finding: "
		if verified {
			label = "Verified finding: "
		}
		return &Event{Level: LevelFinding, Category: CatFinding, Module: "Bulgu Motoru",
			Message: label + Scrub(clip(title, 120)),
			Data: map[string]any{
				"title":          Scrub(title),
				"severity":       sev,
				"endpoint":       Scrub(feedStr(m, "endpoint")),
				"method":         feedStr(m, "method"),
				"vuln_type":      Scrub(feedStr(m, "vuln_type")),
				"evidence":       Scrub(feedStr(m, "desc")),
				"poc":            Scrub(feedStr(m, "poc")),
				"cvss":           feedStr(m, "cvss"),
				"confidence":     feedStr(m, "confidence"),
				"request":        Scrub(feedStr(m, "request")),
				"response":       Scrub(feedStr(m, "response")),
				"duration_ms":    int64(feedInt(m, "duration_ms")),
				"proof_artifact": feedStr(m, "proof_artifact"),
				"remediation":    Scrub(feedStr(m, "remediation")),
				"verified":       verified,
				"verify_note":    Scrub(feedStr(m, "verify_note")),
			}}
	}
	return nil
}

func feedStr(m map[string]any, k string) string {
	if v, ok := m[k]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func feedInt(m map[string]any, k string) int {
	if v, ok := m[k]; ok {
		if f, ok := v.(float64); ok {
			return int(f)
		}
	}
	return 0
}

func feedBool(m map[string]any, k string) bool {
	if v, ok := m[k]; ok {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return false
}

func hasWildcardScope(hosts []string) bool {
	for _, h := range hosts {
		if strings.HasPrefix(strings.TrimSpace(h), "*.") {
			return true
		}
	}
	return false
}

func sanitize(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		}
	}
	out := b.String()
	if len(out) > 40 {
		out = out[:40]
	}
	return out
}

func fileExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir()
}

func providerPrefix(model string) string {
	model = strings.TrimSpace(model)
	if i := strings.IndexByte(model, '/'); i > 0 {
		return model[:i]
	}
	return model
}
