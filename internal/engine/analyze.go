package engine

import (
	"net/url"
	"regexp"
	"strings"
)

type ReflectHit struct {
	Value   string `json:"value"`
	Source  string `json:"source"`
	Param   string `json:"param"`
	Count   int    `json:"count"`
	Context string `json:"context"`
	Encoded bool   `json:"encoded"`
	Snippet string `json:"snippet"`
}

func (e *Engine) Reflect(id, value, responseID string) map[string]any {
	src := e.Get(id)
	if src == nil {
		return map[string]any{"error": "request id not found"}
	}
	resp := src
	if responseID != "" {
		if r := e.Get(responseID); r != nil {
			resp = r
		}
	}
	body := resp.RespBody
	headerBlob := flattenHeaderBlob(resp.RespHeader)

	type cand struct{ source, param, value string }
	var cands []cand
	if value != "" {
		cands = append(cands, cand{"explicit", "value", value})
	} else {

		if u, err := url.Parse(src.URL); err == nil {
			for k, vs := range u.Query() {
				for _, v := range vs {
					if len(v) >= 3 {
						cands = append(cands, cand{"query", k, v})
					}
				}
			}
		}

		for k, v := range parseFormish(src.ReqBody) {
			if len(v) >= 3 {
				cands = append(cands, cand{"body", k, v})
			}
		}

		for hk, hv := range src.ReqHeaders {
			if len(hv) >= 4 && reflectableHeader(hk) {
				cands = append(cands, cand{"header", hk, hv})
			}
		}
	}

	hits := []ReflectHit{}
	seen := map[string]bool{}
	for _, c := range cands {
		if c.value == "" || seen[c.source+"|"+c.param+"|"+c.value] {
			continue
		}
		seen[c.source+"|"+c.param+"|"+c.value] = true

		if n := strings.Count(body, c.value); n > 0 {
			ctx, snip := classifyContext(body, c.value, resp.RespHeader["Content-Type"])
			hits = append(hits, ReflectHit{Value: c.value, Source: c.source, Param: c.param, Count: n, Context: ctx, Encoded: false, Snippet: snip})
			continue
		}

		if enc := htmlEscape(c.value); enc != c.value && strings.Contains(body, enc) {
			hits = append(hits, ReflectHit{Value: c.value, Source: c.source, Param: c.param, Count: strings.Count(body, enc), Context: "html-encoded", Encoded: true, Snippet: snippetAround(body, enc)})
			continue
		}

		if strings.Contains(headerBlob, c.value) {
			hits = append(hits, ReflectHit{Value: c.value, Source: c.source, Param: c.param, Count: 1, Context: "header", Encoded: false, Snippet: snippetAround(headerBlob, c.value)})
		}
	}

	for _, h := range hits {

		if !h.Encoded && (h.Context == "html-text" || h.Context == "html-tag" || h.Context == "js") {
			e.recordProof(src.URL, "raw reflection (in "+h.Context+" context) — XSS/SSTI signal")
			break
		}
	}
	return map[string]any{
		"id":        src.ID,
		"url":       src.URL,
		"reflected": len(hits) > 0,
		"hits":      hits,
		"hint":      reflectHint(hits),
	}
}

func classifyContext(body, value, ctype string) (string, string) {
	idx := strings.Index(body, value)
	if idx < 0 {
		return "unknown", ""
	}
	if strings.Contains(strings.ToLower(ctype), "json") {
		return "json", snippetAt(body, idx, len(value))
	}
	before := body[:idx]

	lastOpen := strings.LastIndex(strings.ToLower(before), "<script")
	lastClose := strings.LastIndex(strings.ToLower(before), "</script>")
	if lastOpen > lastClose {
		return "js", snippetAt(body, idx, len(value))
	}

	lastLT := strings.LastIndex(before, "<")
	lastGT := strings.LastIndex(before, ">")
	if lastLT > lastGT {
		tail := before[lastLT:]
		if strings.Contains(tail, "=\"") || strings.Contains(tail, "='") {
			return "html-attribute", snippetAt(body, idx, len(value))
		}
		return "html-tag", snippetAt(body, idx, len(value))
	}
	return "html-text", snippetAt(body, idx, len(value))
}

func reflectHint(hits []ReflectHit) string {
	if len(hits) == 0 {
		return "no reflection — this input is a weak candidate for XSS/SSTI (still check blind/DOM/stored)"
	}
	for _, h := range hits {
		switch h.Context {
		case "html-text", "html-tag":
			return "raw reflection in HTML body → strong reflected XSS candidate: <svg/onload=…> / inject a tag"
		case "js":
			return "reflection in JS context → break the string (';alert(1)//) or try template injection"
		case "html-attribute":
			return "reflection inside an attribute → break out of the quote (\"><svg onload=…) or add an event handler"
		case "header":
			return "reflection in a response header → try CRLF/header injection / response splitting"
		case "json":
			return "reflection in a JSON value → check the content-type and sink (XSS if written to the DOM)"
		}
	}
	if hits[0].Encoded {
		return "reflection is ENCODED (HTML-entity) → likely neutral; look for a different context/sink"
	}
	return "reflection present — verify the context"
}

var (
	reTitle  = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	reForm   = regexp.MustCompile(`(?is)<form\b[^>]*>`)
	reAttr   = regexp.MustCompile(`(?is)\b(action|method)\s*=\s*["']?([^"'\s>]+)`)
	reInput  = regexp.MustCompile(`(?is)<(?:input|textarea|select)\b[^>]*\bname\s*=\s*["']?([^"'\s>]+)`)
	reHref   = regexp.MustCompile(`(?is)(?:href|src)\s*=\s*["']([^"']+)["']`)
	rePath   = regexp.MustCompile(`(?:/[A-Za-z0-9_.\-]+){2,}`)
	reVerErr = regexp.MustCompile(`(?i)(sql syntax|mysql_fetch|ORA-\d+|PostgreSQL.*ERROR|SQLite3?::|ODBC.*Driver|Unclosed quotation|stack trace|Traceback \(most recent|Exception in|Warning: |Fatal error:|at [a-z0-9_.]+\([A-Za-z0-9_.]+\.(?:java|php|py|rb|go|js):\d+\))`)
)

func (e *Engine) AnalyzeResponse(id string) map[string]any {
	en := e.Get(id)
	if en == nil {
		return map[string]any{"error": "request id not found"}
	}
	body := en.RespBody
	ct := en.RespHeader["Content-Type"]

	forms := []map[string]any{}
	for _, f := range reForm.FindAllString(body, 20) {
		fm := map[string]any{}
		for _, a := range reAttr.FindAllStringSubmatch(f, -1) {
			fm[strings.ToLower(a[1])] = a[2]
		}
		forms = append(forms, fm)
	}
	inputs := uniqStrings(submatches(reInput, body, 60))

	params := map[string]bool{}
	if u, err := url.Parse(en.URL); err == nil {
		for k := range u.Query() {
			params[k] = true
		}
	}
	for _, in := range inputs {
		params[in] = true
	}
	for k := range parseFormish(en.ReqBody) {
		params[k] = true
	}

	links := uniqStrings(submatches(reHref, body, 40))

	cookies := []map[string]any{}
	for _, sc := range splitHeaderMulti(en.RespHeader, "Set-Cookie") {
		name := sc
		if i := strings.IndexByte(sc, '='); i > 0 {
			name = sc[:i]
		}
		low := strings.ToLower(sc)
		cookies = append(cookies, map[string]any{
			"name":     strings.TrimSpace(name),
			"httponly": strings.Contains(low, "httponly"),
			"secure":   strings.Contains(low, "secure"),
			"samesite": extractSameSite(low),
		})
	}

	want := map[string]string{
		"Content-Security-Policy":   "csp",
		"Strict-Transport-Security": "hsts",
		"X-Frame-Options":           "x-frame-options",
		"X-Content-Type-Options":    "x-content-type-options",
		"Referrer-Policy":           "referrer-policy",
		"Permissions-Policy":        "permissions-policy",
	}
	secPresent, secMissing := []string{}, []string{}
	for h, label := range want {
		if headerGet(en.RespHeader, h) != "" {
			secPresent = append(secPresent, label)
		} else {
			secMissing = append(secMissing, label)
		}
	}

	errs := uniqStrings(reVerErr.FindAllString(body, 10))
	paths := uniqStrings(rePath.FindAllString(body, 25))
	secretHits, _ := scanSecrets(body)

	title := ""
	if m := reTitle.FindStringSubmatch(body); len(m) > 1 {
		title = strings.TrimSpace(collapseWS(m[1]))
	}

	return map[string]any{
		"id":               en.ID,
		"url":              en.URL,
		"status":           en.StatusCode,
		"content_type":     ct,
		"length":           en.Length,
		"stored_truncated": en.TrueLen > 0,
		"title":            clipStr(title, 200),
		"forms":            forms,
		"input_names":      inputs,
		"params":           sortedKeys(params),
		"links_sample":     links,
		"cookies":          cookies,
		"security_headers": map[string]any{"present": secPresent, "missing": secMissing},
		"error_signatures": errs,
		"paths_leaked":     paths,
		"secrets":          secretHits,
		"redirect_to":      en.RedirectTo,
		"tech_hints":       techHints(en),
	}
}

func (e *Engine) SetBaseline(key, id string) bool {
	if e.Get(id) == nil {
		return false
	}
	e.mu.Lock()
	e.baselines[key] = id
	e.mu.Unlock()
	return true
}

func (e *Engine) Baseline(key string) string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.baselines[key]
}

func reflectableHeader(name string) bool {
	switch strings.ToLower(name) {
	case "referer", "user-agent", "x-forwarded-for", "x-forwarded-host", "origin", "host":
		return true
	}
	return false
}

func parseFormish(body string) map[string]string {
	out := map[string]string{}
	body = strings.TrimSpace(body)
	if body == "" || strings.HasPrefix(body, "{") || strings.HasPrefix(body, "[") {
		return out
	}
	for _, pair := range strings.Split(body, "&") {
		if i := strings.IndexByte(pair, '='); i > 0 {
			k, _ := url.QueryUnescape(pair[:i])
			v, _ := url.QueryUnescape(pair[i+1:])
			if k != "" {
				out[k] = v
			}
		}
	}
	return out
}

func htmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#39;")
	return r.Replace(s)
}

func flattenHeaderBlob(h map[string]string) string {
	var b strings.Builder
	for k, v := range h {
		b.WriteString(k)
		b.WriteString(": ")
		b.WriteString(v)
		b.WriteString("\n")
	}
	return b.String()
}

func snippetAt(s string, idx, vlen int) string {
	start := idx - 40
	if start < 0 {
		start = 0
	}
	end := idx + vlen + 40
	if end > len(s) {
		end = len(s)
	}
	return collapseWS(s[start:end])
}

func snippetAround(s, sub string) string {
	idx := strings.Index(s, sub)
	if idx < 0 {
		return ""
	}
	return snippetAt(s, idx, len(sub))
}

func collapseWS(s string) string { return strings.Join(strings.Fields(s), " ") }

func submatches(re *regexp.Regexp, s string, max int) []string {
	out := []string{}
	for _, m := range re.FindAllStringSubmatch(s, max) {
		if len(m) > 1 {
			out = append(out, m[1])
		}
	}
	return out
}

func uniqStrings(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func extractSameSite(low string) string {
	if i := strings.Index(low, "samesite="); i >= 0 {
		rest := low[i+len("samesite="):]
		if j := strings.IndexAny(rest, "; "); j >= 0 {
			rest = rest[:j]
		}
		return rest
	}
	return ""
}

func techHints(en *Entry) []string {
	hints := []string{}
	add := func(s string) {
		if s != "" {
			hints = append(hints, s)
		}
	}
	add(headerGet(en.RespHeader, "Server"))
	add(headerGet(en.RespHeader, "X-Powered-By"))
	add(headerGet(en.RespHeader, "X-AspNet-Version"))
	add(headerGet(en.RespHeader, "X-Generator"))
	return uniqStrings(hints)
}

func headerGet(h map[string]string, name string) string {
	for k, v := range h {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return ""
}

func splitHeaderMulti(h map[string]string, name string) []string {
	v := headerGet(h, name)
	if v == "" {
		return nil
	}
	parts := strings.Split(v, ", ")
	out := []string{}
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

var (
	reSecAWS     = regexp.MustCompile(`AKIA[0-9A-Z]{16}`)
	reSecGoogle  = regexp.MustCompile(`AIza[0-9A-Za-z_\-]{35}`)
	reSecJWT     = regexp.MustCompile(`eyJ[A-Za-z0-9_\-]{6,}\.eyJ[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}`)
	reSecPriv    = regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----`)
	reSecSlack   = regexp.MustCompile(`xox[baprs]-[0-9A-Za-z\-]{10,}`)
	reSecGithub  = regexp.MustCompile(`gh[pousr]_[0-9A-Za-z]{36}`)
	reSecStripe  = regexp.MustCompile(`sk_live_[0-9A-Za-z]{16,}`)
	reSecGeneric = regexp.MustCompile(`(?i)(?:api[_-]?key|secret|access[_-]?token|auth[_-]?token|client[_-]?secret|bearer)["' :=]{1,4}([A-Za-z0-9_\-]{20,})`)
	rePIIEmail   = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)
	rePIICard    = regexp.MustCompile(`\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b`)
)

type secretMatcher struct {
	typ  string
	re   *regexp.Regexp
	high bool
}

var secretMatchers = []secretMatcher{
	{"aws-access-key", reSecAWS, true},
	{"google-api-key", reSecGoogle, true},
	{"jwt", reSecJWT, true},
	{"private-key", reSecPriv, true},
	{"slack-token", reSecSlack, true},
	{"github-token", reSecGithub, true},
	{"stripe-secret-key", reSecStripe, true},
	{"generic-secret", reSecGeneric, false},
}

func scanSecrets(body string) (hits []map[string]any, high bool) {
	if body == "" {
		return nil, false
	}
	seen := map[string]bool{}
	add := func(typ, raw string, isHigh bool) {
		m := maskSecret(raw)
		key := typ + "|" + m
		if seen[key] {
			return
		}
		seen[key] = true
		hits = append(hits, map[string]any{"type": typ, "masked": m})
		if isHigh {
			high = true
		}
	}
	for _, sm := range secretMatchers {
		for _, mt := range sm.re.FindAllString(body, 5) {
			add(sm.typ, mt, sm.high)
		}
	}
	for _, m := range uniqStrings(rePIIEmail.FindAllString(body, 5)) {
		add("email", m, false)
	}
	for _, m := range uniqStrings(rePIICard.FindAllString(body, 3)) {
		add("credit-card", m, false)
	}
	return hits, high
}

func maskSecret(s string) string {
	s = strings.TrimSpace(s)
	if len(s) <= 8 {
		return strings.Repeat("*", len(s))
	}
	return s[:4] + strings.Repeat("*", len(s)-6) + s[len(s)-2:]
}

func isTextResponse(h map[string]string) bool {
	ct := strings.ToLower(headerGet(h, "Content-Type"))
	if ct == "" {
		return true
	}
	return strings.Contains(ct, "text/") || strings.Contains(ct, "json") ||
		strings.Contains(ct, "xml") || strings.Contains(ct, "javascript") ||
		strings.Contains(ct, "html")
}

func (e *Engine) PassiveScan(en *Entry) map[string]any {
	body := en.RespBody
	if body == "" {
		return nil
	}
	errs := uniqStrings(reVerErr.FindAllString(body, 5))
	secrets, high := scanSecrets(body)
	if len(errs) == 0 && len(secrets) == 0 {
		return nil
	}
	out := map[string]any{"high": high}
	if len(errs) > 0 {
		out["error_leak"] = errs
	}
	if len(secrets) > 0 {
		out["secrets"] = secrets
	}
	return out
}
