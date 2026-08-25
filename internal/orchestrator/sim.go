package orchestrator

import (
	"context"
	"strconv"
	"time"
)

type SimRunner struct{}

func (SimRunner) Run(ctx context.Context, spec RunSpec, ctrl Controller) error {
	host := spec.Target
	ctrl = withPanes(ctrl)

	recon := friendlySubagent("recon-agent")
	web := friendlySubagent("web-test-agent")
	api := friendlySubagent("api-test-agent")
	fuzz := friendlySubagent("fuzzing-agent")
	oracle := friendlySubagent("validator-agent")
	scribe := friendlySubagent("reporter-agent")

	emit := func(lane, level, category, msg string, ms int) bool {
		ctrl.Emit(Event{Lane: lane, Level: level, Category: category, Module: lane, Message: msg})
		return sleep(ctx, ms)
	}
	sys := func(level, module, msg string, ms int) bool {
		ctrl.Emit(Event{Level: level, Category: CatSystem, Module: module, Message: msg})
		return sleep(ctx, ms)
	}
	traffic := func(lane, method, url, path string, status, ms int) bool {
		ctrl.Emit(Event{Lane: lane, Level: LevelAction, Category: CatTraffic, Module: lane,
			Message: method + " " + path + " → " + strconv.Itoa(status),
			Data: map[string]any{"method": method, "url": url, "host": host, "path": path,
				"status": float64(status), "tls": true}})
		return sleep(ctx, ms)
	}
	finding := func(lane string, data map[string]any, ms int) bool {
		title, _ := data["title"].(string)
		ctrl.Emit(Event{Lane: lane, Level: LevelFinding, Category: CatFinding, Module: lane,
			Message: "Finding: " + title, Data: data})
		return sleep(ctx, ms)
	}

	steps := []func() bool{
		func() bool {
			return sys(LevelSystem, "Çekirdek",
				"Built-in demo scan (simulation) — no live engine or LLM is used. Configure a runner (docker/k8s) + an LLM key for real assessments.", 1400)
		},
		func() bool {
			return sys(LevelThought, "Akıl Yürütme",
				"Mapping the attack surface for "+host+". Plan: recon → parallel web/api/fuzzing → validation → report.", 1800)
		},

		// ── Recon ──────────────────────────────────────────────────────────────
		func() bool {
			return emit(recon, LevelAction, CatModule, "Resolving DNS and enumerating subdomains…", 1600)
		},
		func() bool { return traffic(recon, "GET", "https://"+host+"/", "/", 200, 1200) },
		func() bool {
			return emit(recon, LevelThought, CatModule, "Server: nginx/1.24. App: PHP 8.1 + jQuery. TLS 1.3, HSTS not set.", 1500)
		},
		func() bool { return traffic(recon, "GET", "https://"+host+"/robots.txt", "/robots.txt", 200, 1100) },
		func() bool {
			return emit(recon, LevelAction, CatModule, "Crawling — following links, forms and JS-referenced routes…", 1800)
		},
		func() bool { return traffic(recon, "GET", "https://"+host+"/login", "/login", 200, 1100) },
		func() bool {
			return traffic(recon, "GET", "https://"+host+"/api/v1/openapi.json", "/api/v1/openapi.json", 200, 1200)
		},
		func() bool {
			return emit(recon, LevelAction, CatModule, "Surface mapped: 14 endpoints, 23 parameters. Input-bearing routes: /search, /product, /api/v1/*.", 1600)
		},
		func() bool {
			return finding(recon, map[string]any{
				"title": "Missing security headers", "severity": "low", "vuln_type": "security-misconfig",
				"endpoint": host + "/", "method": "GET",
				"evidence":    "Responses omit Content-Security-Policy and Strict-Transport-Security.",
				"remediation": "Add a restrictive CSP and enable HSTS on all HTTPS responses.",
			}, 1600)
		},

		// ── Operator decision ──────────────────────────────────────────────────
		func() bool {
			choice := ctrl.Ask(Question{
				Prompt: "Should authenticated testing be performed? This also covers the post-login surface.",
				Options: []Option{
					{ID: "auth", Label: "Yes, test with authentication"},
					{ID: "unauth", Label: "No, unauthenticated surface only"},
					{ID: "safe", Label: "Safe/passive tests only"},
				},
				DefaultID: "unauth",
				Timeout:   45 * time.Second,
			})
			if choice == "" {
				choice = "unauth"
			}
			ctrl.Emit(Event{Level: LevelInfo, Category: CatAnswer, Module: "Operatör Seçimi",
				Message: "Selection applied: " + choice})
			return sleep(ctx, 1200)
		},

		// ── Parallel specialists open ──────────────────────────────────────────
		func() bool {
			return emit(web, LevelAction, CatModule, "Assessing /search — semantic analysis of reflected inputs…", 1500)
		},
		func() bool {
			return emit(api, LevelAction, CatModule, "Reading OpenAPI spec; enumerating /api/v1 objects and testing authorization…", 1500)
		},
		func() bool {
			return emit(fuzz, LevelAction, CatModule, "Fuzzing parameters with error-based, boolean and timing payloads…", 1500)
		},

		// ── Web XSS chain ──────────────────────────────────────────────────────
		func() bool { return traffic(web, "GET", "https://"+host+"/search?q=cypturetest", "/search", 200, 1300) },
		func() bool {
			return emit(web, LevelThought, CatModule, "The q parameter is reflected verbatim into the HTML body.", 1400)
		},
		func() bool {
			return traffic(web, "GET", "https://"+host+"/search?q=<script>alert(1)</script>", "/search", 200, 1300)
		},
		func() bool {
			return emit(web, LevelThought, CatModule, "Payload lands inside a <script> context and executes — reflected XSS. Re-testing 3× vs baseline…", 1600)
		},
		func() bool {
			return emit(api, LevelThought, CatModule, "GET /api/v1/users/{id} returns a record for any id with no ownership check.", 1500)
		},
		func() bool {
			return traffic(api, "GET", "https://"+host+"/api/v1/users/2", "/api/v1/users/2", 200, 1300)
		},
		func() bool {
			return emit(fuzz, LevelThought, CatModule, "A single quote in product?id triggers a 500 with a SQL error signature; boolean payloads diverge.", 1500)
		},
		func() bool { return traffic(fuzz, "GET", "https://"+host+"/product?id=1'", "/product", 500, 1300) },

		// ── Findings (with proof so severities hold) ───────────────────────────
		func() bool {
			return finding(web, map[string]any{
				"title": "Reflected XSS", "severity": "high", "vuln_type": "XSS", "verified": true,
				"endpoint": host + "/search?q=", "method": "GET",
				"evidence":       "The q parameter is reflected unencoded and executes in a <script> context; confirmed over 3 repetitions against a clean baseline.",
				"remediation":    "Apply output-context-appropriate encoding and add a Content-Security-Policy.",
				"proof_artifact": "GET /search?q=<script>alert(1)</script> → 200; alert(1) fires; DOM diff vs baseline attached.",
				"request":        "GET /search?q=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1\nHost: " + host,
				"response":       "HTTP/1.1 200 OK\nContent-Type: text/html\n\n…<div class=\"results\">Results for <script>alert(1)</script></div>…",
			}, 1600)
		},
		func() bool {
			return finding(api, map[string]any{
				"title": "IDOR on /api/v1/users/{id}", "severity": "high", "vuln_type": "idor", "verified": true,
				"endpoint": host + "/api/v1/users/2", "method": "GET",
				"evidence":       "Requesting another user's numeric id returns that user's PII without an authorization check.",
				"remediation":    "Enforce per-object (ownership) authorization on every API object access.",
				"proof_artifact": "As user #1, GET /api/v1/users/2 returned user #2's email and role — cross-account read confirmed.",
				"request":        "GET /api/v1/users/2 HTTP/1.1\nHost: " + host + "\nAuthorization: Bearer <user-1-token>",
				"response":       "HTTP/1.1 200 OK\nContent-Type: application/json\n\n{\"id\":2,\"email\":\"victim@example.com\",\"role\":\"user\"}",
			}, 1600)
		},
		func() bool {
			return finding(fuzz, map[string]any{
				"title": "SQL Injection", "severity": "critical", "vuln_type": "sqli", "verified": true,
				"endpoint": host + "/product?id=", "method": "GET",
				"evidence":       "Boolean- and error-based payloads on id confirm SQL injection; id=1 AND 1=1 vs 1 AND 1=2 diverge and a UNION query returns extra columns.",
				"remediation":    "Use parameterized queries / prepared statements; never build SQL from user input.",
				"proof_artifact": "product?id=1'+UNION+SELECT+version(),2--  → response contains the database version banner (extracted).",
				"request":        "GET /product?id=1'%20UNION%20SELECT%20version(),2-- HTTP/1.1\nHost: " + host,
				"response":       "HTTP/1.1 200 OK\n\n…<td>PostgreSQL 15.4 on x86_64…</td>…",
			}, 1600)
		},

		// ── Validation + report ────────────────────────────────────────────────
		func() bool {
			return emit(oracle, LevelAction, CatModule, "Re-testing candidate findings against baseline and self-checking for false positives…", 1900)
		},
		func() bool {
			return emit(oracle, LevelSuccess, CatModule, "Confirmed SQL injection (DB version extracted), IDOR (cross-account read) and reflected XSS.", 1700)
		},
		func() bool {
			return emit(scribe, LevelAction, CatModule, "Deduplicating findings, applying severity gating and generating the report…", 2000)
		},
		func() bool {
			ctrl.Emit(Event{Level: LevelSuccess, Category: CatComplete, Module: "Çekirdek",
				Message: "Scan complete for " + host + " — 4 findings (1 critical, 1 high, 1 medium, 1 low)."})
			return true
		},
	}

	for _, step := range steps {
		if !step() {
			return ctx.Err()
		}
	}
	return nil
}

func sleep(ctx context.Context, ms int) bool {
	t := time.NewTimer(time.Duration(ms) * time.Millisecond)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func NewRunner(kind string) Runner {
	switch kind {
	case "docker", "container":
		return DockerRunner{}
	case "k8s", "kubernetes":
		return KubernetesRunner{}
	case "cypture-agent", "live", "real":
		return AgentRunner{}
	default:
		return SimRunner{}
	}
}
