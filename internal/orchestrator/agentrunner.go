package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

type AgentRunner struct{}

type ocEvent struct {
	Type string `json:"type"`
	Part struct {
		Type   string `json:"type"`
		Text   string `json:"text"`
		Tool   string `json:"tool"`
		Reason string `json:"reason"`
		State  struct {
			Status string         `json:"status"`
			Input  map[string]any `json:"input"`
			Output string         `json:"output"`
			Title  string         `json:"title"`
		} `json:"state"`
	} `json:"part"`
	Error struct {
		Name    string `json:"name"`
		Message string `json:"message"`
		Data    struct {
			Message string `json:"message"`
			Ref     string `json:"ref"`
		} `json:"data"`
	} `json:"error"`
}

func (AgentRunner) Run(ctx context.Context, spec RunSpec, ctrl Controller) error {
	bin := spec.AgentBin
	if bin == "" {
		bin = "cypture-agent"
	}
	message := fmt.Sprintf("%s %s", spec.Mode, spec.Target)

	args := []string{"run", "--format", "json"}
	if spec.Model != "" {
		args = append(args, "-m", spec.Model)
	}
	if spec.AgentName != "" {
		args = append(args, "--agent", spec.AgentName)
	}
	if spec.SkipPerms {
		args = append(args, "--dangerously-skip-permissions")
	}
	args = append(args, message)

	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = spec.AgentDir

	// Feed directory — the host-mode equivalent of the container's /cyp bridge.
	// spawn_agent.sh drops each specialist's NDJSON stream into <feed>/agents,
	// the engine writes traffic/feed here, and findings land in
	// <feed>/findings.ndjson. The Go side tails all of it to build the cockpit.
	feedDir := strings.TrimSpace(spec.WorkDir)
	if feedDir == "" {
		if d, err := os.MkdirTemp("", "cyp-feed-"+sanitize(spec.ScanID)); err == nil {
			feedDir = d
			defer os.RemoveAll(d)
		}
	}
	agentsDir := ""
	if feedDir != "" {
		agentsDir = filepath.Join(feedDir, "agents")
		if err := os.MkdirAll(agentsDir, 0o755); err != nil {
			ctrl.Emit(Event{Level: LevelWarning, Category: CatSystem, Module: "Çekirdek",
				Message: "Could not create the scan feed directory (" + Scrub(err.Error()) +
					"); specialist agent panes may not appear."})
			agentsDir = ""
		}
		if len(spec.KBSeed) > 0 {
			_ = os.WriteFile(filepath.Join(feedDir, "kb.json"), spec.KBSeed, 0o644)
		}
	}

	env := append(os.Environ(),
		"CYP_MODE="+spec.Mode,
		"CYP_TARGET="+spec.Target,
		"CYP_SCOPE_INCLUDES="+strings.Join(spec.ScopeHosts, ","),
		"CYP_SCOPE_EXCLUDES="+strings.Join(spec.ScopeExcludes, ","),
	)
	if feedDir != "" {
		// CYP_FEED_DIR / CYP_PROJECT_ROOT let the agent scripts (spawn_agent.sh,
		// gate-agent.sh, …) run on the host instead of the container's fixed
		// /cyp and /agent paths; both default to the container values if unset.
		env = append(env,
			"CYP_FEED_DIR="+feedDir,
			"CYP_PROJECT_ROOT="+spec.AgentDir,
			"WS="+feedDir,
			"CYP_FEED_PATH="+filepath.Join(feedDir, "feed.jsonl"),
			"CYP_TRAFFIC_PATH="+filepath.Join(feedDir, "traffic.ndjson"),
		)
	}
	// spawn_agent.sh spawns each specialist with this binary. On the host it is
	// the opencode shim (not a literal `cypture-agent` on PATH), so hand it the
	// resolved path explicitly, or specialists die with "command not found".
	env = append(env, "CYP_AGENT_BIN="+bin)
	if spec.SkipPerms {
		env = append(env, "CYP_SKIP_PERMS=1")
	}
	if spec.Model != "" {
		env = append(env, "CYP_MODEL="+spec.Model)
	}
	if spec.ReasoningModel != "" {
		env = append(env, "CYP_MODEL_REASONING="+spec.ReasoningModel)
	}
	if strings.TrimSpace(spec.OperatorPrompt) != "" {
		env = append(env, "CYP_OPERATOR_PROMPT="+spec.OperatorPrompt)
	}
	if strings.TrimSpace(spec.TestCredentials) != "" {
		env = append(env, "CYP_TEST_CREDS="+spec.TestCredentials)
	}
	cmd.Env = env

	// Group sub-agent activity into cockpit panes/lanes, exactly like the
	// docker/k8s runners do (see docker.go). Without this, every event is
	// classified as "system" and the specialist-agent grid stays empty.
	ctrl = withPanes(ctrl)

	ctrl.Emit(Event{Level: LevelSystem, Category: CatSystem, Module: "Çekirdek",
		Message: "Scan core started; mapping the target surface."})

	ctrl, stopHB, _ := withHeartbeat(ctx, ctrl)
	defer stopHB()

	// Tail the feed exactly like the container runners, so specialist
	// sub-agents, findings and traffic surface in the live cockpit.
	if feedDir != "" {
		go tailFeed(ctx, filepath.Join(feedDir, "feed.jsonl"), ctrl)
		go tailFindings(ctx, filepath.Join(feedDir, "findings.ndjson"), ctrl)
		go tailTraffic(ctx, filepath.Join(feedDir, "traffic.ndjson"), ctrl)
		go tailQuestions(ctx, feedDir, ctrl)
		if agentsDir != "" {
			go tailAgents(ctx, agentsDir, ctrl)
		}
	}

	err := streamNDJSON(ctx, cmd, ctrl, nil)

	if feedDir != "" {
		importFindingsJSON(feedDir, ctrl)
		importKBUpdate(feedDir, ctrl)
	}
	return err
}

func mapEvents(ev ocEvent, dispatched map[string]bool) []Event {
	switch ev.Type {
	case "error":
		// opencode emits {"type":"error","error":{"name":...,"data":{"message":...}}}
		// on provider/model failures. Without this case the failure is invisible and
		// the cockpit just shows an empty, silently-dead agent.
		msg := strings.TrimSpace(ev.Error.Data.Message)
		if msg == "" {
			msg = strings.TrimSpace(ev.Error.Message)
		}
		name := strings.TrimSpace(ev.Error.Name)
		full := strings.TrimSpace(strings.TrimPrefix(name+": "+msg, ": "))
		if strings.TrimSpace(strings.TrimSuffix(full, ":")) == "" {
			return nil
		}
		if ref := strings.TrimSpace(ev.Error.Data.Ref); ref != "" {
			full += " (" + ref + ")"
		}
		if fatal, ok := classifyFatal(full); ok {
			return []Event{{Level: LevelError, Category: CatSystem, Module: "Çekirdek",
				Message: fatal}}
		}
		return []Event{{Level: LevelWarning, Category: CatSystem, Module: "Çekirdek",
			Message: "⚠ Agent error — " + Scrub(clip(full, 400))}}

	case "text", "reasoning":
		txt := strings.TrimSpace(ev.Part.Text)
		if txt == "" {
			return nil
		}

		{
			var kept []string
			for _, ln := range strings.Split(txt, "\n") {
				if !feedNoiseLine(ln) {
					kept = append(kept, ln)
				}
			}
			txt = strings.TrimSpace(strings.Join(kept, "\n"))
			if txt == "" {
				return nil
			}
		}

		if ev.Type == "text" {
			if cleaned, finds := extractFindingMarkers(txt); len(finds) > 0 {
				var evs []Event
				if cleaned != "" {
					evs = append(evs, Event{Level: LevelThought, Category: CatPlanning, Module: "Akıl Yürütme",
						Message: Scrub(clip(cleaned, 4000))})
				}
				for _, fd := range finds {
					evs = append(evs, findingEventFromMarker(fd))
				}
				return evs
			}
		}
		return []Event{{Level: LevelThought, Category: CatPlanning, Module: "Akıl Yürütme",
			Message: Scrub(clip(txt, 4000))}}

	case "step_finish", "step-finish":

		r := strings.ToLower(strings.TrimSpace(ev.Part.Reason))
		if r == "length" || r == "max_tokens" || r == "max-tokens" || strings.Contains(r, "truncat") {
			return []Event{{Level: LevelWarning, Category: CatSystem, Module: "Çekirdek",
				Message: "⚠ The model response was CUT OFF at the token limit (output truncated) — the phase may be incomplete; the deterministic fallback pipeline is engaging."}}
		}
		return nil

	case "tool_use":
		tool := ev.Part.Tool
		status := ev.Part.State.Status
		if status != "running" && status != "completed" {
			return nil
		}
		key := tool + ":" + ev.Part.State.Title + ":" + status
		if dispatched[key] {
			return nil
		}
		dispatched[key] = true

		if strings.Contains(strings.ToLower(tool), "finding") && status == "completed" {
			in := ev.Part.State.Input
			title := firstString(in, "title", "name")
			if title != "" {
				sev := strings.ToLower(firstString(in, "severity"))
				if sev == "" {
					sev = "info"
				}

				verified := boolFromAny(in["verified"])
				if !verified && (sev == "critical" || sev == "high") {
					sev = "medium"
				}
				label := "Candidate finding: "
				if verified {
					label = "Verified finding: "
				}
				return []Event{{Level: LevelFinding, Category: CatFinding, Module: "Bulgu Motoru",
					Message: label + Scrub(clip(title, 120)),
					Data: map[string]any{
						"title":       Scrub(title),
						"severity":    sev,
						"vuln_type":   firstString(in, "vuln_type", "type"),
						"endpoint":    firstString(in, "endpoint", "url"),
						"method":      firstString(in, "method"),
						"evidence":    Scrub(firstString(in, "evidence", "description")),
						"remediation": Scrub(firstString(in, "remediation")),
						"poc":         Scrub(firstString(in, "poc", "proof_of_concept")),
						"cvss":        firstString(in, "cvss", "cvss_score"),
						"confidence":  firstString(in, "confidence"),
						"request":     Scrub(firstString(in, "request", "raw_request")),
						"response":    Scrub(firstString(in, "response", "raw_response")),
						"verified":    verified,
						"verify_note": Scrub(firstString(in, "verify_note", "verification")),
					}}}
			}
		}

		if strings.ToLower(tool) == "task" {
			sub := firstString(ev.Part.State.Input, "subagent_type", "subagentType", "agent", "name", "description")
			desc := firstString(ev.Part.State.Input, "description", "prompt", "task")
			mod := friendlySubagent(sub + " " + desc)
			if status != "completed" {
				msg := "🧩 Module dispatched"
				if desc != "" {
					msg += ": " + clip(desc, 180)
				}
				return []Event{{Level: LevelAction, Category: CatModule, Module: mod, Message: Scrub(msg)}}
			}

			evs := []Event{{Level: LevelInfo, Category: CatModule, Module: mod,
				Message: Scrub("✅ " + mod + " completed")}}
			for _, ln := range observationLines(ev.Part.State.Output, 12) {
				evs = append(evs, Event{Level: LevelInfo, Category: CatModule, Module: mod,
					Message: "↳ " + Scrub(ln)})
			}
			return evs
		}

		if internalNoisyTool(tool) {
			return nil
		}

		module := friendlyModule(tool)
		desc := describeTool(tool, ev.Part.State.Input, ev.Part.State.Title)

		if feedNoiseLine(desc) {
			return nil
		}
		out := []Event{{Level: LevelAction, Category: catForTool(tool), Module: module,
			Message: Scrub(desc)}}

		if status == "completed" {

			if obs := observation(ev.Part.State.Output); obs != "" && !looksInternal(obs) && !feedNoiseLine(obs) {
				out = append(out, Event{Level: LevelInfo, Category: CatModule, Module: module,
					Message: "↳ " + Scrub(obs)})
			}
		}
		return out
	}
	return nil
}

func looksInternal(s string) bool {
	low := strings.ToLower(s)
	for _, k := range []string{"confirmed_tech", "dead_ends", "known_findings", "kb_update", "tech_hints", "\"runs\"",

		"step_finish", "step_start", "sessionid", "\"part\"", "prt_", "ses_", "tool-calls",
		"\"providerid\"", "\"modelid\""} {
		if strings.Contains(low, k) {
			return true
		}
	}
	return false
}

func internalNoisyTool(tool string) bool {
	switch strings.ToLower(tool) {
	case "read", "glob", "grep", "list", "ls", "lsp_diagnostics",
		"todowrite", "todoread", "write", "edit", "patch":
		return true
	}
	return false
}

func observation(output string) string {
	o := strings.TrimSpace(output)
	if o == "" {
		return ""
	}

	for _, ln := range strings.Split(o, "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "<") {
			continue
		}
		return clip(ln, 160)
	}
	return clip(strings.ReplaceAll(o, "\n", " "), 160)
}

func observationLines(output string, max int) []string {
	o := strings.TrimSpace(output)
	if o == "" {
		return nil
	}
	out := []string{}
	for _, ln := range strings.Split(o, "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "<") {
			continue
		}
		if feedNoiseLine(ln) {
			continue
		}
		out = append(out, clip(ln, 200))
		if len(out) >= max {
			break
		}
	}
	return out
}

func catForTool(tool string) string {
	if strings.ToLower(tool) == "task" {
		return CatModule
	}
	if strings.Contains(strings.ToLower(tool), "finding") {
		return CatFinding
	}
	return CatModule
}

func describeTool(tool string, input map[string]any, title string) string {
	t := strings.ToLower(tool)
	if t == "task" {

		sub := firstString(input, "subagent_type", "subagentType", "agent", "name")
		desc := firstString(input, "description", "prompt", "task")
		mod := friendlySubagent(sub + " " + desc)
		if desc != "" {
			return mod + " dispatched: " + clip(desc, 160)
		}
		return mod + " dispatched."
	}

	if host := firstString(input, "host"); host != "" {
		return "Sending request → " + host
	}
	if q := firstString(input, "query"); q != "" {
		return "Querying traffic: " + clip(q, 120)
	}
	if t == "bash" {
		// Don't dump raw multi-line shell (echo/ls/heredoc floods) into the
		// cockpit — collapse to a short, single-line summary.
		if cmd := firstString(input, "command", "cmd", "script"); cmd != "" {
			return "$ " + clip(oneLine(cmd), 120)
		}
		if title != "" {
			return clip(oneLine(title), 120)
		}
		return "Running a local task."
	}
	if title != "" {
		return clip(title, 160)
	}
	return friendlyModule(tool) + " is running."
}

func firstString(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
				return s
			}
		}
	}
	return ""
}

var findingMarkerRe = regexp.MustCompile(`(?i)\[?\s*CYP[-_]FINDING\s*\]?\s*:?`)

func extractFindingMarkers(txt string) (cleaned string, findings []map[string]any) {
	if !strings.Contains(strings.ToUpper(txt), "CYP") {
		return txt, nil
	}
	locs := findingMarkerRe.FindAllStringIndex(txt, -1)
	if len(locs) == 0 {
		return txt, nil
	}
	var b strings.Builder
	prev := 0
	for _, loc := range locs {
		if loc[0] < prev {
			continue
		}
		b.WriteString(txt[prev:loc[0]])
		obj, end := firstJSONObject(txt[loc[1]:])
		if obj != nil && strings.TrimSpace(firstString(obj, "title", "name")) != "" {
			findings = append(findings, obj)
			prev = loc[1] + end
		} else {
			prev = loc[1]
		}
	}
	b.WriteString(txt[prev:])
	return strings.TrimSpace(b.String()), findings
}

func firstJSONObject(s string) (map[string]any, int) {
	start := strings.IndexByte(s, '{')
	if start < 0 {
		return nil, 0
	}
	depth, inStr, esc := 0, false, false
	for i := start; i < len(s); i++ {
		c := s[i]
		if inStr {
			switch {
			case esc:
				esc = false
			case c == '\\':
				esc = true
			case c == '"':
				inStr = false
			}
			continue
		}
		switch c {
		case '"':
			inStr = true
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				var m map[string]any
				if err := json.Unmarshal([]byte(s[start:i+1]), &m); err == nil && m != nil {
					return m, i + 1
				}
				return nil, 0
			}
		}
	}
	return nil, 0
}

func findingEventFromMarker(in map[string]any) Event {
	title := firstString(in, "title", "name")
	sev := strings.ToLower(firstString(in, "severity"))
	if sev == "" {
		sev = "info"
	}

	verified := boolFromAny(in["verified"])
	if !verified && (sev == "critical" || sev == "high") {
		sev = "medium"
	}
	label := "Candidate finding: "
	if verified {
		label = "Verified finding: "
	}
	return Event{Level: LevelFinding, Category: CatFinding, Module: "Bulgu Motoru",
		Message: label + Scrub(clip(title, 120)),
		Data: map[string]any{
			"title":       Scrub(title),
			"severity":    sev,
			"vuln_type":   firstString(in, "vuln_type", "type"),
			"endpoint":    firstString(in, "endpoint", "url"),
			"method":      firstString(in, "method"),
			"evidence":    Scrub(firstString(in, "evidence", "description")),
			"remediation": Scrub(firstString(in, "remediation")),
			"poc":         Scrub(firstString(in, "poc", "proof_of_concept")),
			"cvss":        firstString(in, "cvss", "cvss_score"),
			"confidence":  firstString(in, "confidence"),
			"request":     Scrub(firstString(in, "request", "raw_request")),
			"response":    Scrub(firstString(in, "response", "raw_response")),
			"verified":    boolFromAny(in["verified"]),
			"verify_note": Scrub(firstString(in, "verify_note", "verification")),
		}}
}

func boolFromAny(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return strings.EqualFold(strings.TrimSpace(t), "true")
	}
	return false
}

func usageEvent(line string) *Event {
	var root any
	if json.Unmarshal([]byte(line), &root) != nil {
		return nil
	}
	u, ok := findUsage(root)
	if !ok {
		return nil
	}
	return &Event{Level: LevelInfo, Category: CatUsage, Module: "Metre",
		Data: map[string]any{
			"msg_id":           u.id,
			"cost_usd":         u.cost,
			"tokens_input":     u.tin,
			"tokens_output":    u.tout,
			"tokens_reasoning": u.treason,
			"model":            u.model,
		}}
}

type ocUsage struct {
	id                 string
	cost               float64
	tin, tout, treason int64
	model              string
}

func findUsage(v any) (ocUsage, bool) {
	switch t := v.(type) {
	case map[string]any:
		if tk, ok := t["tokens"].(map[string]any); ok {
			if _, has := tk["input"]; has {
				return ocUsage{
					id:      jsonStr(t, "id", "messageID", "message_id"),
					cost:    jsonNum(t["cost"]),
					tin:     int64(jsonNum(tk["input"])),
					tout:    int64(jsonNum(tk["output"])),
					treason: int64(jsonNum(tk["reasoning"])),
					model:   jsonStr(t, "modelID", "model"),
				}, true
			}
		}
		for _, vv := range t {
			if u, ok := findUsage(vv); ok {
				return u, true
			}
		}
	case []any:
		for _, vv := range t {
			if u, ok := findUsage(vv); ok {
				return u, true
			}
		}
	}
	return ocUsage{}, false
}

func jsonNum(v any) float64 {
	if f, ok := v.(float64); ok {
		return f
	}
	return 0
}

func jsonStr(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if s, ok := m[k].(string); ok && s != "" {
			return s
		}
	}
	return ""
}
