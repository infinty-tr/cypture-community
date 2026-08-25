package engine

import (
	"fmt"
	"strings"
)

type EntrySummary struct {
	ID         string `json:"id"`
	Method     string `json:"method"`
	URL        string `json:"url"`
	Status     int    `json:"status"`
	Length     int    `json:"length"`
	Mime       string `json:"mime,omitempty"`
	DurationMs int64  `json:"duration_ms"`
	HasReqBody bool   `json:"has_req_body,omitempty"`
	SessionID  string `json:"session_id,omitempty"`
	Error      string `json:"error,omitempty"`
	Snippet    string `json:"snippet,omitempty"`
}

type SearchOpts struct {
	Query  string
	Host   string
	Method string
	Status string
	Mime   string
	Count  int
}

func mimeOf(en *Entry) string {
	if en.RespHeader == nil {
		return ""
	}
	ct := en.RespHeader["Content-Type"]
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	return strings.TrimSpace(ct)
}

func statusMatches(code int, want string) bool {
	want = strings.TrimSpace(want)
	if want == "" {
		return true
	}
	if len(want) == 3 && (want[1] == 'x' || want[1] == 'X') && (want[2] == 'x' || want[2] == 'X') {
		return code >= 100 && (code/100) == int(want[0]-'0')
	}
	return strings.TrimSpace(itoa(code)) == want
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [12]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

func preview(s string) string {
	s = strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(s, "\n", " "), "\r", " "))
	return clipStr(s, 200)
}

func (e *Engine) SearchSummaries(o SearchOpts) []EntrySummary {
	count := o.Count
	if count <= 0 || count > 500 {
		count = 50
	}
	q := strings.ToLower(strings.TrimSpace(o.Query))
	host := strings.ToLower(strings.TrimSpace(o.Host))
	method := strings.ToUpper(strings.TrimSpace(o.Method))
	mime := strings.ToLower(strings.TrimSpace(o.Mime))

	e.mu.Lock()
	defer e.mu.Unlock()
	out := []EntrySummary{}
	for i := len(e.history) - 1; i >= 0 && len(out) < count; i-- {
		en := e.history[i]
		if q != "" && !strings.Contains(strings.ToLower(en.URL+" "+en.Method+" "+itoa(en.StatusCode)), q) {
			continue
		}
		if host != "" && !strings.Contains(strings.ToLower(en.Host), host) {
			continue
		}
		if method != "" && !strings.EqualFold(en.Method, method) {
			continue
		}
		if !statusMatches(en.StatusCode, o.Status) {
			continue
		}
		m := mimeOf(en)
		if mime != "" && !strings.Contains(strings.ToLower(m), mime) {
			continue
		}
		out = append(out, EntrySummary{
			ID: en.ID, Method: en.Method, URL: en.URL, Status: en.StatusCode,
			Length: en.Length, Mime: m, DurationMs: en.DurationMs,
			HasReqBody: en.ReqBody != "", SessionID: en.SessionID, Error: en.Error,
			Snippet: preview(en.RespBody),
		})
	}
	return out
}

func (e *Engine) Sessions() []map[string]any {
	e.mu.Lock()

	hostsBySess := map[string]map[string]bool{}
	reqBySess := map[string]int{}
	for _, en := range e.history {
		sid := en.SessionID
		if hostsBySess[sid] == nil {
			hostsBySess[sid] = map[string]bool{}
		}
		if en.Host != "" {
			hostsBySess[sid][en.Host] = true
		}
		reqBySess[sid]++
	}

	ids := []string{""}
	for id := range e.sessions {
		ids = append(ids, id)
	}
	e.mu.Unlock()

	seen := map[string]bool{}
	out := []map[string]any{}
	for _, id := range ids {
		if seen[id] {
			continue
		}
		seen[id] = true
		hosts := []map[string]any{}
		for h := range hostsBySess[id] {
			cookies := e.SessionCookies(id, h, true)
			if len(cookies) == 0 {
				cookies = e.SessionCookies(id, h, false)
			}
			names := make([]string, 0, len(cookies))
			for _, c := range cookies {
				if i := strings.IndexByte(c, '='); i > 0 {
					names = append(names, c[:i])
				}
			}
			hosts = append(hosts, map[string]any{"host": h, "cookies": names, "authed": len(names) > 0})
		}
		label := id
		if label == "" {
			label = "(default)"
		}
		out = append(out, map[string]any{"id": id, "label": label, "requests": reqBySess[id], "hosts": hosts})
	}
	return out
}

func (e *Engine) Diff(idA, idB string) map[string]any {
	a, b := e.Get(idA), e.Get(idB)
	if a == nil || b == nil {
		return map[string]any{"error": "one or both request ids not found"}
	}
	bodyEqual := a.RespBody == b.RespBody
	firstDiff := -1
	if !bodyEqual {
		n := len(a.RespBody)
		if len(b.RespBody) < n {
			n = len(b.RespBody)
		}
		for i := 0; i < n; i++ {
			if a.RespBody[i] != b.RespBody[i] {
				firstDiff = i
				break
			}
		}
		if firstDiff == -1 {
			firstDiff = n
		}
	}

	lenDelta := b.Length - a.Length
	if lenDelta < 0 {
		lenDelta = -lenDelta
	}
	if a.StatusCode != b.StatusCode || (!bodyEqual && lenDelta >= 64) {
		det := fmt.Sprintf("measured differential: status %d↔%d, Δlen=%d, body_equal=%v", a.StatusCode, b.StatusCode, b.Length-a.Length, bodyEqual)
		e.recordProof(a.URL, det)
		e.recordProof(b.URL, det)
	}
	return map[string]any{
		"a":              map[string]any{"id": a.ID, "status": a.StatusCode, "length": a.Length, "mime": mimeOf(a), "url": a.URL},
		"b":              map[string]any{"id": b.ID, "status": b.StatusCode, "length": b.Length, "mime": mimeOf(b), "url": b.URL},
		"status_differs": a.StatusCode != b.StatusCode,
		"length_delta":   b.Length - a.Length,
		"time_delta_ms":  b.DurationMs - a.DurationMs,
		"body_equal":     bodyEqual,
		"first_diff_at":  firstDiff,
		"header_diff":    headerDiff(a.RespHeader, b.RespHeader),
		"hint":           diffHint(a, b, bodyEqual),
	}
}

func headerDiff(a, b map[string]string) map[string]any {
	added, removed := []string{}, []string{}
	changed := []map[string]string{}
	for k, bv := range b {
		if av, ok := headerLookup(a, k); !ok {
			added = append(added, k+": "+bv)
		} else if av != bv {
			changed = append(changed, map[string]string{"header": k, "a": av, "b": bv})
		}
	}
	for k := range a {
		if _, ok := headerLookup(b, k); !ok {
			removed = append(removed, k)
		}
	}
	return map[string]any{"added": added, "removed": removed, "changed": changed}
}

func headerLookup(h map[string]string, name string) (string, bool) {
	for k, v := range h {
		if strings.EqualFold(k, name) {
			return v, true
		}
	}
	return "", false
}

func diffHint(a, b *Entry, bodyEqual bool) string {
	switch {
	case a.StatusCode != b.StatusCode:
		return "Status code differs (" + itoa(a.StatusCode) + " vs " + itoa(b.StatusCode) + ") — strong signal."
	case bodyEqual:
		return "Responses are IDENTICAL — no difference (same behavior as control/baseline)."
	default:
		d := b.Length - a.Length
		if d < 0 {
			d = -d
		}
		if d > 64 {
			return "Body length differs noticeably — worth examining (could be a boolean signal)."
		}
		return "Body changes by a small amount (could be dynamic content; look at the first-diff position)."
	}
}
