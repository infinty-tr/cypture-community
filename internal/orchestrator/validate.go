package orchestrator

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// validateSem caps how many validation containers can be spawned at once across
// the whole server, so an authenticated user cannot exhaust host resources by
// hammering the "validate key" button (each validation is a `docker run`).
var validateSem = make(chan struct{}, 2)

func ValidateLLM(ctx context.Context, image, apiKey, provider, model string) (bool, string) {
	if image == "" {
		image = "cypture-engine:latest"
	}
	if strings.TrimSpace(apiKey) == "" || strings.TrimSpace(model) == "" {
		return false, "key and model are required"
	}

	select {
	case validateSem <- struct{}{}:
		defer func() { <-validateSem }()
	case <-time.After(20 * time.Second):
		return false, "validation is busy — please retry in a moment"
	case <-ctx.Done():
		return false, "validation cancelled"
	}
	prov := strings.TrimSpace(provider)
	if i := strings.Index(model, "/"); i > 0 {
		prov = model[:i]
	} else if prov == "" {
		prov = model
	}

	buildCurl := func() string {
		s := `MODEL_BARE="${MODEL#*/}"; [ -z "$MODEL_BARE" ] && MODEL_BARE="$MODEL"; `
		s += `case "$PROV" in `
		s += `openai)     URL="https://api.openai.com/v1/chat/completions" ;; `
		s += `deepseek)   URL="https://api.deepseek.com/v1/chat/completions" ;; `
		s += `openrouter) URL="https://openrouter.ai/api/v1/chat/completions" ;; `
		s += `groq)       URL="https://api.groq.com/openai/v1/chat/completions" ;; `
		s += `anthropic)  URL="https://api.anthropic.com/v1/messages" ;; `
		s += `*)          URL="https://openrouter.ai/api/v1/chat/completions" ;; `
		s += `esac; `
		s += `if [ "$PROV" = "anthropic" ]; then `
		s += `curl -sS -m 25 -X POST "$URL" -H "x-api-key: $KEY" -H "anthropic-version: 2023-06-01" -H "content-type: application/json" -d "{\"model\":\"$MODEL_BARE\",\"max_tokens\":5,\"messages\":[{\"role\":\"user\",\"content\":\"Say OK\"}]}" 2>&1`
		s += `; else `
		s += `curl -sS -m 25 -X POST "$URL" -H "Authorization: Bearer $KEY" -H "content-type: application/json" -d "{\"model\":\"$MODEL_BARE\",\"max_tokens\":5,\"messages\":[{\"role\":\"user\",\"content\":\"Say OK\"}]}" 2>&1`
		s += `; fi`
		return s
	}
	script := buildCurl()

	ctx2, cancel := context.WithTimeout(ctx, 75*time.Second)
	defer cancel()
	name := fmt.Sprintf("cyp-llmcheck-%d-%d", os.Getpid(), time.Now().UnixNano())
	defer func() {
		rmCtx, rmCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer rmCancel()
		_ = exec.CommandContext(rmCtx, "docker", "rm", "-f", name).Run()
	}()
	runArgs := []string{"run", "--rm", "--name", name, "--entrypoint", "sh",
		"--security-opt", "no-new-privileges",
		"-e", "PROV=" + prov, "-e", "MODEL=" + model}
	// The key is passed via a 0600 file mounted read-only — NEVER via argv/env,
	// where `ps` / `docker inspect` would expose it. If the temp file cannot be
	// created, abort rather than fall back to a key-in-argv command line.
	kf, err := os.CreateTemp("", "cyp-vkey-*")
	if err != nil {
		return false, "could not create a secure temp file for the key; validation aborted"
	}
	_, _ = kf.WriteString(apiKey)
	_ = kf.Close()
	defer os.Remove(kf.Name())
	runArgs = append(runArgs, "-v", kf.Name()+":/run/cyp_vkey:ro")
	runScript := `KEY="$(cat /run/cyp_vkey)"; ` + script
	runArgs = append(runArgs, image, "-c", runScript)
	cmd := exec.CommandContext(ctx2, "docker", runArgs...)
	out, _ := cmd.CombinedOutput()
	s := string(out)
	low := strings.ToLower(s)

	if strings.Contains(s, `"content":"`) || strings.Contains(s, `"content": "`) ||
		strings.Contains(s, `"text":"`) || strings.Contains(s, `"text": "`) {
		return true, "valid — the " + prov + " model responded ✓"
	}
	switch {
	case strings.Contains(low, "insufficient") || strings.Contains(low, "quota") ||
		strings.Contains(low, "billing") || strings.Contains(low, "402") ||
		strings.Contains(low, "balance"):
		return false, "insufficient balance — no credit on this provider/model"
	case strings.Contains(low, "401") || strings.Contains(low, "unauthorized") ||
		strings.Contains(low, "invalid api key") || strings.Contains(low, "incorrect api key"):
		return false, "authentication failed — API key is incorrect"
	case strings.Contains(low, "404") || (strings.Contains(low, "model") &&
		(strings.Contains(low, "not found") || strings.Contains(low, "does not exist"))):
		return false, "model not found — '" + model + "' does not exist on this provider"
	case ctx2.Err() != nil:
		return false, "timeout — the provider did not respond"
	}
	return false, "could not validate: " + clip(strings.TrimSpace(s), 140)
}
