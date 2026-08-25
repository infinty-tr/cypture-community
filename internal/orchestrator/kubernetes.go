package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

type KubernetesRunner struct{}

func (KubernetesRunner) Run(ctx context.Context, spec RunSpec, ctrl Controller) error {
	podName := "cyp-" + dnsSanitize(spec.ScanID)
	ns := spec.Namespace
	if ns == "" {
		ns = "default"
	}

	depth := "deep"
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

	feedPath := ""
	var feedDir string
	if dir, err := os.MkdirTemp("", "cyp-feed-"+sanitize(spec.ScanID)); err == nil {
		feedDir = dir
		feedPath = filepath.Join(dir, "feed.jsonl")
		defer removeFeedDir(dir)

		_ = os.Chmod(dir, 0o700)
		if len(spec.KBSeed) > 0 {
			_ = os.WriteFile(filepath.Join(dir, "kb.json"), spec.KBSeed, 0o644)
		}
	}
	if feedPath == "" {
		return fmt.Errorf("kubernetes runner: could not create bridge dir")
	}

	keyMounted := false
	if spec.LLMAPIKey != "" {
		if err := os.WriteFile(filepath.Join(feedDir, "cyp_llm_key"), []byte(spec.LLMAPIKey), 0o600); err == nil {
			keyMounted = true
		}
	}

	env := k8sEngineEnv(spec, depth, keyMounted, ctrl)

	node := singleNodeName(ctx, spec)

	ensureEngineEgressPolicy(ctx, spec, ns)

	manifest := podManifest(podName, ns, node, spec.Image, mem, cpus, env, feedDir, spec, keyMounted)

	deletePod := func(graceful bool) {
		dctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		args := []string{"delete", "pod", podName, "--ignore-not-found", "--wait=true", "--timeout=25s"}
		if graceful {

			args = append(args, "--grace-period=6")
		}
		_ = kubectl(dctx, spec, args...).Run()
	}
	defer deletePod(false)

	applyCmd := kubectl(ctx, spec, "apply", "-f", "-")
	applyCmd.Stdin = bytes.NewReader(manifest)
	if out, err := applyCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("kubernetes runner: pod create failed: %s: %w", strings.TrimSpace(string(out)), err)
	}
	onCancel := func() { deletePod(true) }

	ctrl = withPanes(ctrl)
	ctrl.Emit(Event{Level: LevelSystem, Category: CatSystem, Module: "Çekirdek",
		Message: "Preparing an isolated assessment environment; mapping the target surface."})
	ctrl.Emit(Event{Level: LevelInfo, Category: CatSystem, Module: "Çekirdek",
		Message: "Starting assessment modules; the first observations will begin streaming shortly (~30s)."})

	if err := waitPodStarted(ctx, spec, podName); err != nil {
		onCancel()
		return fmt.Errorf("kubernetes runner: pod did not start: %w", err)
	}

	ctrl, stopHB, stalledFor := withHeartbeat(ctx, ctrl)
	defer stopHB()

	go tailFeed(ctx, feedPath, ctrl)
	go tailFindings(ctx, filepath.Join(feedDir, "findings.ndjson"), ctrl)
	go tailTraffic(ctx, filepath.Join(feedDir, "traffic.ndjson"), ctrl)
	go tailAgents(ctx, filepath.Join(feedDir, "agents"), ctrl)
	go tailQuestions(ctx, feedDir, ctrl)

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

	logCmd := kubectl(ctx, spec, "logs", "-f", podName)
	err := streamNDJSON(ctx, logCmd, ctrl, onCancel)

	if feedPath != "" {
		importFindingsJSON(feedDir, ctrl)
		importKBUpdate(feedDir, ctrl)
	}
	if stalled.Load() {
		return nil
	}

	if err == nil && ctx.Err() == nil {
		if code := podExitCode(ctx, spec, podName); code > 0 {
			return fmt.Errorf("kubernetes runner: engine exited with code %d", code)
		}
	}
	return err
}

func k8sEngineEnv(spec RunSpec, depth string, keyMounted bool, ctrl Controller) [][2]string {
	env := [][2]string{
		{"CYP_MODE", spec.Mode},
		{"CYP_TARGET", spec.Target},
		{"CYP_SCOPE_INCLUDES", strings.Join(spec.ScopeHosts, ",")},
		{"CYP_SCOPE_EXCLUDES", strings.Join(spec.ScopeExcludes, ",")},
	}
	if spec.Model != "" {
		env = append(env, [2]string{"CYP_MODEL", spec.Model})
	}
	if rm := strings.TrimSpace(spec.ReasoningModel); rm != "" && rm != spec.Model {
		if providerPrefix(rm) == providerPrefix(spec.Model) {
			env = append(env, [2]string{"CYP_MODEL_REASONING", rm})
		} else {
			ctrl.Emit(Event{Level: LevelWarning, Category: CatSystem, Module: "Çekirdek",
				Message: "Reasoning-model separation skipped: a different provider from the base model (a single key cannot validate both)."})
		}
	}
	if p := strings.TrimSpace(spec.OperatorPrompt); p != "" {
		env = append(env, [2]string{"CYP_OPERATOR_PROMPT", p})
	}
	if c := strings.TrimSpace(spec.TestCredentials); c != "" {
		env = append(env, [2]string{"CYP_TEST_CREDS", c})
	}
	if keyMounted {
		env = append(env, [2]string{"CYP_LLM_API_KEY_FILE", "/cyp/cyp_llm_key"})
		if spec.LLMProvider != "" {
			env = append(env, [2]string{"CYP_LLM_PROVIDER", spec.LLMProvider})
		}
	}
	env = append(env, [2]string{"CYP_DEPTH", depth})
	if spec.AgentName != "" {
		env = append(env, [2]string{"CYP_AGENT", spec.AgentName})
	}
	if spec.SkipPerms {
		env = append(env, [2]string{"CYP_SKIP_PERMS", "1"})
	}

	for _, k := range []string{
		"CYP_OOB_ADDR", "CYP_OOB_URL", "CYP_OOB_DOMAIN", "CYP_OOB_SMTP_ADDR",
		"CYP_MAX_PARALLEL", "CYP_DEEPEN_HOSTS_PER_ROUND", "CYP_REAPER_STALL_TTL",
		"CYP_AGENT_WAIT_MAX", "CYP_USE_MODEL_ORCH", "CYP_DETERMINISTIC", "CYP_GATE_MAX_WAIT", "CYP_SCRUB_KEYS",

		"CYP_TOKEN_BUDGET", "CYP_LLM_HTTP_TIMEOUT_S", "CYP_MCP_CALL_TIMEOUT_S",
		"CYP_MODEL_PROBE_TIMEOUT_S", "CYP_DECIDE_MAX_WAIT",
	} {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			env = append(env, [2]string{k, v})
		}
	}
	return env
}

func podManifest(name, ns, node, image, mem, cpus string, env [][2]string, feedDir string, spec RunSpec, keyMounted bool) []byte {
	img := image
	if img == "" {
		img = "cypture-engine:latest"
	}
	envList := make([]map[string]any, 0, len(env))
	for _, kv := range env {
		envList = append(envList, map[string]any{"name": kv[0], "value": kv[1]})
	}
	volumes := []map[string]any{
		{"name": "cyp-bridge", "hostPath": map[string]any{"path": feedDir, "type": "DirectoryOrCreate"}},
	}
	mounts := []map[string]any{
		{"name": "cyp-bridge", "mountPath": "/cyp"},
	}

	if !keyMounted && spec.AgentAuthDir != "" && os.Getenv("CYP_ALLOW_SHARED_AUTH_JSON") == "1" {
		if p := filepath.Join(spec.AgentAuthDir, "auth.json"); fileExists(p) {
			volumes = append(volumes, map[string]any{"name": "oc-auth", "hostPath": map[string]any{"path": p, "type": "File"}})
			mounts = append(mounts, map[string]any{"name": "oc-auth", "mountPath": "/root/.local/share/cypture-agent/auth.json", "readOnly": true})
		}
	}
	container := map[string]any{
		"name":            "engine",
		"image":           img,
		"imagePullPolicy": "Never",
		"env":             envList,

		"resources": map[string]any{
			"requests": map[string]any{"memory": "512Mi", "cpu": "250m"},
			"limits":   map[string]any{"memory": k8sMem(mem), "cpu": k8sCPU(cpus)},
		},
		"securityContext": map[string]any{
			"allowPrivilegeEscalation": false,
			"capabilities":             map[string]any{"drop": []string{"ALL"}, "add": []string{"DAC_OVERRIDE"}},
		},
		"volumeMounts": mounts,
	}
	podSpec := map[string]any{
		"restartPolicy":                "Never",
		"automountServiceAccountToken": false,

		"securityContext": map[string]any{"seccompProfile": map[string]any{"type": "RuntimeDefault"}},
		"containers":      []map[string]any{container},
		"volumes":         volumes,
	}
	if node != "" {
		podSpec["nodeName"] = node
	}
	pod := map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]any{
			"name":      name,
			"namespace": ns,
			"labels":    map[string]any{"app": "cypture-engine", "cypture.io/scan": sanitize(spec.ScanID)},
		},
		"spec": podSpec,
	}
	b, _ := json.Marshal(pod)
	return b
}

var blockedEgressCIDRs = []string{
	"169.254.0.0/16",
	"168.63.129.16/32",
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"100.64.0.0/10",
}

func engineEgressPolicyManifest(ns string) []byte {
	np := map[string]any{
		"apiVersion": "networking.k8s.io/v1",
		"kind":       "NetworkPolicy",
		"metadata": map[string]any{
			"name":      "cypture-engine-egress",
			"namespace": ns,
			"labels":    map[string]any{"app": "cypture-engine"},
		},
		"spec": map[string]any{
			"podSelector": map[string]any{"matchLabels": map[string]any{"app": "cypture-engine"}},
			"policyTypes": []string{"Egress"},
			"egress": []map[string]any{

				{
					"to":    []map[string]any{{"namespaceSelector": map[string]any{}}},
					"ports": []map[string]any{{"protocol": "UDP", "port": 53}, {"protocol": "TCP", "port": 53}},
				},

				{
					"to": []map[string]any{
						{"ipBlock": map[string]any{"cidr": "0.0.0.0/0", "except": blockedEgressCIDRs}},
					},
				},
			},
		},
	}
	b, _ := json.Marshal(np)
	return b
}

func ensureEngineEgressPolicy(ctx context.Context, spec RunSpec, ns string) {
	actx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	cmd := kubectl(actx, spec, "apply", "-f", "-")
	cmd.Stdin = bytes.NewReader(engineEgressPolicyManifest(ns))
	if out, err := cmd.CombinedOutput(); err != nil {
		slog.Warn("egress NetworkPolicy apply failed (scan continues; verify NetworkPolicy support)",
			"err", err, "out", strings.TrimSpace(string(out)))
	}
}

func kubectl(ctx context.Context, spec RunSpec, args ...string) *exec.Cmd {
	bin := spec.KubectlBin
	if bin == "" {
		bin = "kubectl"
	}
	full := []string{}
	if spec.Kubeconfig != "" {
		full = append(full, "--kubeconfig", spec.Kubeconfig)
	}
	ns := spec.Namespace
	if ns == "" {
		ns = "default"
	}
	full = append(full, "-n", ns)
	full = append(full, args...)
	return exec.CommandContext(ctx, bin, full...)
}

func waitPodStarted(ctx context.Context, spec RunSpec, name string) error {
	deadline := time.NewTimer(150 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(300 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return fmt.Errorf("timeout waiting for pod to start")
		case <-tick.C:
			c := kubectl(ctx, spec, "get", "pod", name, "-o", "jsonpath={.status.phase}")
			out, err := c.Output()
			if err != nil {
				continue
			}
			switch strings.TrimSpace(string(out)) {
			case "Running", "Succeeded", "Failed":
				return nil
			}
		}
	}
}

func podExitCode(ctx context.Context, spec RunSpec, name string) int {
	c := kubectl(ctx, spec, "get", "pod", name, "-o",
		"jsonpath={.status.containerStatuses[0].state.terminated.exitCode}")
	out, err := c.Output()
	if err != nil {
		return -1
	}
	s := strings.TrimSpace(string(out))
	if s == "" {
		return -1
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return -1
	}
	return n
}

func removeFeedDir(path string) bool {
	if os.RemoveAll(path) == nil {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return true
		}
	}
	return exec.Command("sudo", "-n", "rm", "-rf", path).Run() == nil
}

func CleanStaleFeedDirs() int {
	tmp := os.TempDir()
	entries, err := os.ReadDir(tmp)
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range entries {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), "cyp-feed-") {
			continue
		}
		if removeFeedDir(filepath.Join(tmp, e.Name())) {
			n++
		}
	}
	return n
}

func singleNodeName(ctx context.Context, spec RunSpec) string {
	c := kubectl(ctx, spec, "get", "nodes", "-o", "jsonpath={.items[0].metadata.name}")
	out, err := c.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

var dnsBadChars = regexp.MustCompile(`[^a-z0-9-]`)

func dnsSanitize(s string) string {
	s = strings.ToLower(s)
	s = dnsBadChars.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	if s == "" {
		s = "scan"
	}
	if len(s) > 50 {
		s = strings.Trim(s[:50], "-")
	}
	return s
}

func k8sMem(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "2Gi"
	}
	l := strings.ToLower(s)
	switch {
	case strings.HasSuffix(l, "g"):
		return strings.TrimSuffix(s, s[len(s)-1:]) + "Gi"
	case strings.HasSuffix(l, "m"):
		return strings.TrimSuffix(s, s[len(s)-1:]) + "Mi"
	}
	return s
}

func k8sCPU(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "2"
	}
	return s
}
