package engine

import "strings"

func toolDefs() []map[string]any {
	obj := func(props map[string]any, required ...string) map[string]any {
		m := map[string]any{"type": "object", "properties": props, "additionalProperties": true}
		if len(required) > 0 {
			m["required"] = required
		}
		return m
	}
	s := map[string]any{"type": "string"}
	i := map[string]any{"type": "integer"}
	b := map[string]any{"type": "boolean"}

	base := []map[string]any{
		{
			"name":        "cyp_get_instance",
			"description": "Get engine instance info/status. Call once at start to confirm the engine is ready.",
			"inputSchema": obj(map[string]any{}),
		},
		{
			"name":        "cyp_create_scope",
			"description": "Register an in/out scope (informational; scope is also enforced at the code level).",
			"inputSchema": obj(map[string]any{"name": s, "includes": map[string]any{"type": "array", "items": s}, "excludes": map[string]any{"type": "array", "items": s}}),
		},
		{
			"name":        "cyp_list_scopes",
			"description": "List configured scopes (authorized include/exclude host patterns).",
			"inputSchema": obj(map[string]any{}),
		},
		{
			"name":        "cyp_create_replay_session",
			"description": "Create an isolated request session (its own cookie jar). Use two sessions for IDOR/BOLA (two identities).",
			"inputSchema": obj(map[string]any{}),
		},
		{
			"name":        "cyp_send_request",
			"description": "Send a raw HTTP request through the engine and get the full response (status, headers, body). All target traffic MUST go through this tool. Enforces scope. REQUEST SMUGGLING: a request carrying a Transfer-Encoding header is AUTOMATICALLY sent byte-exact over a raw socket (chunked framing + conflicting Content-Length both survive to the wire), so CL.TE / TE.CL / TE.TE desync IS testable. Set raw_socket:true (alias smuggle:true) to force the byte-exact path for any request (e.g. CL.CL desync, malformed framing) — the response is parsed best-effort and the raw body is always returned.",
			"inputSchema": obj(map[string]any{
				"raw":        s,
				"host":       s,
				"port":       i,
				"tls":        b,
				"sessionId":  s,
				"bodyLimit":  i,
				"raw_socket": b,
				"smuggle":    b,
			}, "raw", "host"),
		},
		{
			"name":        "cyp_batch_send",
			"description": "Send multiple raw HTTP requests in parallel (max 50). Use for BAC token sweeps, parameter fuzzing, endpoint sweeps. Returns per-request results with a label.",
			"inputSchema": obj(map[string]any{"requests": map[string]any{"type": "array", "items": obj(map[string]any{"label": s, "raw": s, "host": s, "port": i, "tls": b, "sessionId": s})}}, "requests"),
		},
		{
			"name":        "cyp_search_history",
			"description": "Search request/response history with filters. `query` (substring on URL/method/status) + optional `host`, `method`, `status` ('200' or a class '2xx'..'5xx'), `mime` (content-type substring), `count`. Returns COMPACT rows (id, method, url, status, length, mime, duration, has_req_body, response snippet) newest-first; get the full request/response via cyp_get_request. Reuse instead of re-sending.",
			"inputSchema": obj(map[string]any{"query": s, "host": s, "method": s, "status": s, "mime": s, "count": i}),
		},
		{
			"name":        "cyp_get_request",
			"description": "Get the full stored request/response (incl. request body) by its requestId.",
			"inputSchema": obj(map[string]any{"id": s}, "id"),
		},
		{
			"name":        "cyp_list_sessions",
			"description": "List identities (replay sessions): each session's id/label, request count, the hosts it talked to, and the cookie names it currently holds per host (authed=true if any). Use to track WHICH identity you are during two-identity authz testing (IDOR/BOLA/BFLA).",
			"inputSchema": obj(map[string]any{}),
		},
		{
			"name":        "cyp_diff_requests",
			"description": "Compare two stored responses by request id (`a`, `b`): status_differs, length_delta, time_delta_ms, body_equal, first_diff_at, header_diff (added/removed/changed) and a hint. Cheap differential signal — boolean SQLi (1=1 vs 1=2), authz A-vs-B, with/without a header, cache-poisoning.",
			"inputSchema": obj(map[string]any{"a": s, "b": s}, "a", "b"),
		},
		{
			"name":        "cyp_reflect",
			"description": "Reflection analysis: find which of a stored request's input values (query/body params, notable headers) are echoed in its response and CLASSIFY the context (html-text / html-attribute / js / json / header) and whether the reflection is encoded. The core signal for reflected XSS / SSTI / header injection. Pass `id` (request); optionally `value` to search a specific string and `response_id` to search a different response.",
			"inputSchema": obj(map[string]any{"id": s, "value": s, "response_id": s}, "id"),
		},
		{
			"name":        "cyp_analyze_response",
			"description": "Structured digest (page_shape) of a stored response by `id`: status, content_type, title, forms + input names, params, sample links, Set-Cookie flags (HttpOnly/Secure/SameSite), security headers present/missing (CSP/HSTS/X-Frame-Options/…), error & leak signatures (SQL errors, stack traces, leaked paths, version banners) and tech hints. Read every interesting response THIS way instead of dumping the whole body.",
			"inputSchema": obj(map[string]any{"id": s}, "id"),
		},
		{
			"name":        "cyp_set_baseline",
			"description": "Mark a stored request `id` as the clean BASELINE for an endpoint `key` (your label, e.g. 'GET /search'). Then feed that id to cyp_diff_requests as `a` so payload responses are diffed against a known-good control (boolean/blind/authz testing).",
			"inputSchema": obj(map[string]any{"key": s, "id": s}, "key", "id"),
		},
		{
			"name":        "cyp_replay_request",
			"description": "Repeater: re-send a stored request (`id`) with EDITS — `method`, `path`/`url`, `set_headers` {name:val}, `remove_headers` [names], `body`, `set_params` {name:val} (patches query and form body), `session`, `tls`/`port`, `follow_redirects`. Returns the new result PLUS an automatic diff against the original. Use to iterate a request variant by variant (header tweak, param change, WAF bypass) without rebuilding raw each time.",
			"inputSchema": obj(map[string]any{
				"id": s, "method": s, "path": s, "url": s,
				"set_headers": map[string]any{"type": "object"}, "remove_headers": map[string]any{"type": "array", "items": s},
				"body": s, "set_params": map[string]any{"type": "object"},
				"session": s, "tls": b, "port": i, "follow_redirects": b, "bodyLimit": i,
			}, "id"),
		},
		{
			"name":        "cyp_get_sitemap",
			"description": "Get the discovered sitemap (distinct host+path observed so far).",
			"inputSchema": obj(map[string]any{}),
		},
		{
			"name":        "cyp_get_session_cookies",
			"description": "Get the cookies currently held by a session for a host.",
			"inputSchema": obj(map[string]any{"sessionId": s, "host": s, "tls": b}, "host"),
		},
		{
			"name":        "cyp_create_finding",
			"description": "Record confirmed, reproducible vulnerabilities to the client panel (the ONLY way they appear — a summary does NOT count). Two modes: (1) single finding via top-level fields; (2) BULK via a 'findings' array of finding objects — use bulk to record ALL findings in one call at the end so none are missed. Per-finding fields: title, severity (critical|high|medium|low|info), endpoint, method, vuln_type, description, evidence, poc (step-by-step proof/payloads), cvss (e.g. 9.8), confidence (confirmed|likely), remediation, request/response (raw HTTP — auto-attached from request history by endpoint if omitted), verified (bool — set true after an INDEPENDENT second confirmation; required for critical/high), verify_note (how it was re-confirmed).",
			"inputSchema": obj(map[string]any{"title": s, "description": s, "evidence": s, "severity": s, "endpoint": s, "method": s, "vuln_type": s, "poc": s, "cvss": s, "confidence": s, "remediation": s, "request": s, "response": s, "reporter": s, "verified": map[string]any{"type": "boolean"}, "verify_note": s, "findings": map[string]any{"type": "array", "items": map[string]any{"type": "object"}}}),
		},
		{
			"name":        "cyp_list_findings",
			"description": "List all recorded findings.",
			"inputSchema": obj(map[string]any{}),
		},
		{
			"name":        "cyp_encode_decode",
			"description": "Encode/decode a string. operation: base64encode|base64decode|urlencode|urldecode|hexencode|hexdecode.",
			"inputSchema": obj(map[string]any{"input": s, "operation": s}, "input", "operation"),
		},
		{
			"name":        "cyp_race_send",
			"description": "RACE / TOCTOU primitive: fire N requests with HTTP/1.1 LAST-BYTE SYNCHRONIZATION so they all arrive in the server's check→use window TOGETHER (sub-millisecond spread) — what plain parallelism (cyp_batch_send) CANNOT do. Use to test coupon/gift-card double-redeem, balance double-withdraw, double-vote, one-per-account limit bypass, signup/invite race. Two input shapes: `requests` [{label, raw}] for distinct payloads, OR `raw` + `count` for N identical copies. Returns per-connection status/length/body plus fireOffsetNs (the realized spread). A race exists when the outcome differs from sequential (e.g. two 200-OK redemptions of a single-use code).",
			"inputSchema": obj(map[string]any{
				"raw": s, "count": i, "host": s, "port": i, "tls": b, "sessionId": s, "bodyLimit": i,
				"requests": map[string]any{"type": "array", "items": obj(map[string]any{"label": s, "raw": s})},
			}, "host"),
		},
		{

			"name":        "cyp_race_window_send",
			"description": "Alias of cyp_race_send: fire N requests with HTTP/1.1 last-byte synchronization (single-packet-style window collapse) for TOCTOU / race-condition tests (double-spend, limit bypass). Inputs: `raw`+`count`, or `requests` [{label, raw}]; plus host/port/tls/sessionId.",
			"inputSchema": obj(map[string]any{
				"raw": s, "count": i, "host": s, "port": i, "tls": b, "sessionId": s, "bodyLimit": i,
				"requests": map[string]any{"type": "array", "items": obj(map[string]any{"label": s, "raw": s})},
			}, "host"),
		},
		{
			"name":        "cyp_sequence",
			"description": "STATEFUL multi-step chain: run an ordered list of requests, carrying values between them. Before each step, {{var}} placeholders in `raw`/`host` are replaced from the variable bag; after each step, `extract` rules capture new values. This expresses exploits a single request cannot: CSRF-token-then-submit, login-then-act, IDOR→password-reset→account-takeover, 'read an id/token from response A, use it in request B'. Each step: {name, raw, host, port, tls, session, extract:[{var, from:'body'|'header:Name'|'status'|'location'|'requestId', regex (1st group), json (dotted path e.g. data.token / items.0.id)}]}. Optional top-level `vars` seeds the bag. Returns each step's status/requestId/extracted values and the final vars.",
			"inputSchema": obj(map[string]any{
				"steps": map[string]any{"type": "array", "items": obj(map[string]any{
					"name": s, "raw": s, "host": s, "port": i, "tls": b, "session": s,
					"extract": map[string]any{"type": "array", "items": obj(map[string]any{"var": s, "from": s, "regex": s, "json": s})},
				})},
				"vars": map[string]any{"type": "object"},
			}, "steps"),
		},
		{
			"name":        "cyp_oob_register",
			"description": "Register an OUT-OF-BAND token for BLIND vuln confirmation AND email-flow capture (self-hosted collaborator). Returns: token; http_url + dns_host to inject into a suspected sink (SSRF URL, XXE external entity, RCE command curl/nslookup, a stored field a backend later renders); and `email` (<token>@oob-domain) to use as the VICTIM address in a register / password-reset / 2FA flow. Then poll with cyp_oob_poll. This is the only reliable way to prove blind SSRF / OOB-RCE / blind XXE-SQLi exfil / second-order injection (body shows nothing) AND to obtain reset links / OTP codes that unlock account-takeover chains.",
			"inputSchema": obj(map[string]any{"label": s}),
		},
		{
			"name":        "cyp_oob_poll",
			"description": "Poll an out-of-band token (from cyp_oob_register). Returns: interactions (blind HTTP/DNS callbacks) + confirmed=true if ANY arrived (the target reached a host you control — verified evidence); AND captured emails with email_links (reset/verify/magic-link URLs) and email_codes (4–8 digit OTP/2FA codes) extracted ready-to-use. Feed a reset link/OTP straight into cyp_sequence to complete a password-reset → account-takeover or 2FA-bypass chain.",
			"inputSchema": obj(map[string]any{"token": s}, "token"),
		},
		{
			"name":        "cyp_param_mine",
			"description": "Discover HIDDEN/undocumented parameters on a stored request (`id`) by probing a list of candidate names (`params`) — the richest source of IDOR, mass-assignment and open-redirect bugs that crawling never reveals (debug, admin, is_admin, role, user_id, account, redirect, next, url, callback). Each candidate is sent with a canary value and the response diffed against the original; params that change status/length or reflect the canary are returned as CANDIDATES to verify manually. Breadth tool — not a finding by itself.",
			"inputSchema": obj(map[string]any{"id": s, "params": map[string]any{"type": "array", "items": s}, "canary": s}, "id"),
		},

		{
			"name":        "cyp_browser_navigate",
			"description": "Load a URL in a REAL headless Chromium (executes JavaScript), wait for the page to settle, and return the final URL, title, rendered HTML, and any JS dialogs that fired. A non-empty `dialogs` array (e.g. \"alert: 1\") is PROOF that injected script executed — the canonical DOM-XSS confirmation. Use for SPAs/JS-heavy apps and to trigger DOM-XSS via URL/fragment payloads. Enforces scope. waitMs: how long to let JS run (default 1500, max 15000).",
			"inputSchema": obj(map[string]any{"url": s, "waitMs": i, "bodyLimit": i}, "url"),
		},
		{
			"name":        "cyp_browser_eval",
			"description": "Run a JavaScript expression in the CURRENTLY LOADED page and return its JSON result plus any JS dialogs it triggered. Use to read DOM/state (document.cookie, localStorage, innerHTML), trigger client-side sinks, or fire a payload and confirm execution via the returned `dialogs`. Navigate first.",
			"inputSchema": obj(map[string]any{"expr": s}, "expr"),
		},
		{
			"name":        "cyp_browser_dom",
			"description": "Return the current page's rendered outerHTML (AFTER JavaScript ran) — the real DOM the user sees, not the raw HTTP body. Use to inspect SPA-generated markup and locate client-side sinks.",
			"inputSchema": obj(map[string]any{"bodyLimit": i}),
		},
		{
			"name":        "cyp_browser_screenshot",
			"description": "Capture a PNG screenshot of the current page; saved to the engagement bridge dir. Returns the file path and byte size (visual evidence for a finding).",
			"inputSchema": obj(map[string]any{}),
		},
	}

	out := make([]map[string]any, 0, len(base)*2)
	for _, t := range base {
		out = append(out, t)
		if n, ok := t["name"].(string); ok && strings.HasPrefix(n, "cyp_") {
			alias := make(map[string]any, len(t))
			for k, v := range t {
				alias[k] = v
			}
			alias["name"] = strings.TrimPrefix(n, "cyp_")
			out = append(out, alias)
		}
	}
	return out
}
