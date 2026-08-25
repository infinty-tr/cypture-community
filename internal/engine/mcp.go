package engine

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
)

type Server struct {
	eng *Engine
	out *bufio.Writer
	mu  sync.Mutex
}

func NewServer(eng *Engine) *Server {
	return &Server{eng: eng, out: bufio.NewWriter(os.Stdout)}
}

type rpcReq struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

func (s *Server) Serve() error {
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 0, 1024*1024), 16*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		var req rpcReq
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			continue
		}
		s.handle(req)
	}
	return sc.Err()
}

func (s *Server) handle(req rpcReq) {
	switch req.Method {
	case "initialize":

		proto := "2025-06-18"
		var ip struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		if json.Unmarshal(req.Params, &ip) == nil && ip.ProtocolVersion != "" {
			proto = ip.ProtocolVersion
		}
		s.reply(req.ID, map[string]any{
			"protocolVersion": proto,
			"capabilities":    map[string]any{"tools": map[string]any{"listChanged": true}, "resources": map[string]any{}},
			"serverInfo":      map[string]any{"name": "cypture-engine", "version": "1.0.0"},
		})
	case "notifications/initialized":

	case "tools/list":
		s.reply(req.ID, map[string]any{"tools": toolDefs()})
	case "tools/call":
		s.handleToolCall(req)
	case "resources/list":
		s.reply(req.ID, map[string]any{"resources": []any{}})
	case "ping":
		s.reply(req.ID, map[string]any{})
	default:
		if len(req.ID) > 0 {
			s.replyErr(req.ID, -32601, "method not found: "+req.Method)
		}
	}
}

type toolCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

func (s *Server) handleToolCall(req rpcReq) {
	var p toolCallParams
	_ = json.Unmarshal(req.Params, &p)
	var args map[string]any
	_ = json.Unmarshal(p.Arguments, &args)

	text, isErr := s.dispatch(p.Name, args)
	s.reply(req.ID, map[string]any{
		"content": []map[string]any{{"type": "text", "text": text}},
		"isError": isErr,
	})
}

func (s *Server) dispatch(name string, a map[string]any) (string, bool) {

	name = strings.TrimPrefix(name, "mcp__cyp__")
	if !strings.HasPrefix(name, "cyp_") {
		name = "cyp_" + name
	}
	switch name {
	case "cyp_get_instance":
		return jsonStr(map[string]any{"name": "cypture-engine", "version": "1.0.0", "status": "ready"}), false

	case "cyp_create_scope":
		return jsonStr(map[string]any{"id": "scope_1", "name": str(a, "name")}), false
	case "cyp_list_scopes":
		return jsonStr(map[string]any{"scopes": []map[string]any{{"id": "scope_1", "includes": s.eng.scopeIn, "excludes": s.eng.scopeEx}}}), false

	case "cyp_create_replay_session", "cyp_create_replay_collection":
		return jsonStr(map[string]any{"id": s.eng.CreateSession()}), false

	case "cyp_send_request":
		res, err := s.eng.Send(str(a, "raw"), str(a, "host"), intv(a, "port"), boolv(a, "tls", true), str(a, "sessionId"), intv(a, "bodyLimit"), boolv(a, "raw_socket", false) || boolv(a, "smuggle", false))
		if err != nil {
			return "send_request error: " + err.Error(), true
		}
		return jsonStr(res), false

	case "cyp_batch_send":
		return s.batchSend(a)

	case "cyp_search_history", "cyp_list_requests":

		statusF := str(a, "status")
		if statusF == "" && intv(a, "status") > 0 {
			statusF = itoa(intv(a, "status"))
		}
		return jsonStr(map[string]any{"requests": s.eng.SearchSummaries(SearchOpts{
			Query: str(a, "query"), Host: str(a, "host"), Method: str(a, "method"),
			Status: statusF, Mime: str(a, "mime"), Count: intv(a, "count"),
		})}), false

	case "cyp_list_sessions":

		return jsonStr(map[string]any{"sessions": s.eng.Sessions()}), false

	case "cyp_diff_requests":

		return jsonStr(s.eng.Diff(firstNonEmpty(str(a, "a"), str(a, "id_a")), firstNonEmpty(str(a, "b"), str(a, "id_b")))), false

	case "cyp_reflect":

		return jsonStr(s.eng.Reflect(str(a, "id"), str(a, "value"), str(a, "response_id"))), false

	case "cyp_analyze_response", "cyp_page_shape":

		return jsonStr(s.eng.AnalyzeResponse(str(a, "id"))), false

	case "cyp_set_baseline":

		ok := s.eng.SetBaseline(str(a, "key"), str(a, "id"))
		return jsonStr(map[string]any{"ok": ok, "key": str(a, "key"), "id": str(a, "id")}), false

	case "cyp_replay_request", "cyp_replay":

		ed := ReplayEdit{
			Method: str(a, "method"), Path: str(a, "path"), URL: str(a, "url"),
			SetHeaders: strMap(a, "set_headers"), RemoveHeaders: strSlice(a, "remove_headers"),
			SetParams: strMap(a, "set_params"), Session: str(a, "session"),
			Port: intv(a, "port"), FollowRedirs: boolv(a, "follow_redirects", false),
			BodyLimit: intv(a, "bodyLimit"),
		}
		if _, ok := a["body"]; ok {
			bv := str(a, "body")
			ed.Body = &bv
		}
		if _, ok := a["tls"]; ok {
			tv := boolv(a, "tls", true)
			ed.TLS = &tv
		}
		res, err := s.eng.Replay(str(a, "id"), ed)
		if err != nil {
			return "replay error: " + err.Error(), true
		}
		return jsonStr(res), false

	case "cyp_get_request":
		en := s.eng.Get(str(a, "id"))
		if en == nil {
			return "request not found", true
		}
		return jsonStr(getRequestView(en)), false

	case "cyp_get_sitemap":
		return jsonStr(map[string]any{"sitemap": s.eng.Sitemap()}), false

	case "cyp_get_session_cookies":
		return jsonStr(map[string]any{"cookies": s.eng.SessionCookies(str(a, "sessionId"), str(a, "host"), boolv(a, "tls", true))}), false

	case "cyp_create_finding":

		if arr, ok := a["findings"].([]any); ok && len(arr) > 0 {
			ids := make([]string, 0, len(arr))
			skipped := 0
			for _, it := range arr {
				if m, ok := it.(map[string]any); ok {

					if strings.TrimSpace(str(m, "title")) == "" {
						skipped++
						continue
					}
					f := s.eng.AddFinding(findingInputFrom(m))
					ids = append(ids, f.ID)
				}
			}
			return jsonStr(map[string]any{"created": len(ids), "skipped": skipped, "ids": ids}), false
		}
		if strings.TrimSpace(str(a, "title")) == "" {
			return jsonStr(map[string]any{"error": "title is required — a finding without a title is not recorded"}), false
		}
		f := s.eng.AddFinding(findingInputFrom(a))
		return jsonStr(map[string]any{"id": f.ID, "request_attached": f.Request != "", "response_attached": f.Response != ""}), false
	case "cyp_list_findings":
		return jsonStr(map[string]any{"findings": s.eng.Findings()}), false

	case "cyp_encode_decode":
		return s.encodeDecode(a)

	case "cyp_race_send", "cyp_race_window_send":

		return s.raceSend(a)
	case "cyp_sequence":

		return s.runSequence(a)
	case "cyp_oob_register":
		if s.eng.oob == nil {
			return jsonStr(map[string]any{"error": "out-of-band collector not enabled (set CYP_OOB_ADDR on the engine)"}), false
		}
		return jsonStr(s.eng.oob.Register(str(a, "label"))), false
	case "cyp_oob_poll":
		if s.eng.oob == nil {
			return jsonStr(map[string]any{"error": "out-of-band collector not enabled (set CYP_OOB_ADDR on the engine)"}), false
		}

		oobRes := s.eng.oob.Poll(str(a, "token"))
		s.eng.noteOOB(oobRes)
		return jsonStr(oobRes), false
	case "cyp_param_mine":
		res, err := s.eng.ParamMine(str(a, "id"), strSlice(a, "params"), str(a, "canary"))
		if err != nil {
			return "param_mine error: " + err.Error(), true
		}
		return jsonStr(res), false

	case "cyp_browser_navigate":
		b, err := s.eng.getBrowser()
		if err != nil {
			return "browser error: " + err.Error(), true
		}
		res, err := b.Navigate(str(a, "url"), intv(a, "waitMs"), intv(a, "bodyLimit"))
		if err != nil {
			return "browser_navigate error: " + err.Error(), true
		}
		return jsonStr(res), false
	case "cyp_browser_eval":
		b, err := s.eng.getBrowser()
		if err != nil {
			return "browser error: " + err.Error(), true
		}
		res, err := b.Eval(str(a, "expr"))
		if err != nil {
			return "browser_eval error: " + err.Error(), true
		}
		return jsonStr(res), false
	case "cyp_browser_dom":
		b, err := s.eng.getBrowser()
		if err != nil {
			return "browser error: " + err.Error(), true
		}
		res, err := b.DOM(intv(a, "bodyLimit"))
		if err != nil {
			return "browser_dom error: " + err.Error(), true
		}
		return jsonStr(res), false
	case "cyp_browser_screenshot":
		b, err := s.eng.getBrowser()
		if err != nil {
			return "browser error: " + err.Error(), true
		}
		res, err := b.Screenshot()
		if err != nil {
			return "browser_screenshot error: " + err.Error(), true
		}
		return jsonStr(res), false

	default:
		return "unknown tool: " + name, true
	}
}

func (s *Server) batchSend(a map[string]any) (string, bool) {
	raw, _ := a["requests"].([]any)
	type r struct {
		Label  string      `json:"label"`
		Result *SendResult `json:"result,omitempty"`
		Error  string      `json:"error,omitempty"`
	}
	results := make([]r, len(raw))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 10)
	for i, item := range raw {
		m, _ := item.(map[string]any)
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, m map[string]any) {
			defer wg.Done()
			defer func() { <-sem }()
			label := str(m, "label")
			res, err := s.eng.Send(str(m, "raw"), str(m, "host"), intv(m, "port"), boolv(m, "tls", true), str(m, "sessionId"), intv(m, "bodyLimit"), boolv(m, "raw_socket", false) || boolv(m, "smuggle", false))
			if err != nil {
				results[i] = r{Label: label, Error: err.Error()}
			} else {
				results[i] = r{Label: label, Result: res}
			}
		}(i, m)
	}
	wg.Wait()
	return jsonStr(map[string]any{"results": results, "summary": map[string]any{"total": len(results)}}), false
}

func (s *Server) raceSend(a map[string]any) (string, bool) {
	var reqs []RaceRequest
	if arr, ok := a["requests"].([]any); ok && len(arr) > 0 {
		for i, it := range arr {
			m, _ := it.(map[string]any)
			label := str(m, "label")
			if label == "" {
				label = "r" + itoa(i)
			}
			reqs = append(reqs, RaceRequest{Label: label, Raw: firstNonEmpty(str(m, "raw"), str(a, "raw"))})
		}
	} else {
		count := intv(a, "count")
		if count <= 0 {
			count = 10
		}
		if count > 50 {
			count = 50
		}
		for i := 0; i < count; i++ {
			reqs = append(reqs, RaceRequest{Label: "r" + itoa(i), Raw: str(a, "raw")})
		}
	}
	results, err := s.eng.RaceSend(reqs, str(a, "host"), intv(a, "port"), boolv(a, "tls", true), str(a, "sessionId"), intv(a, "bodyLimit"))
	if err != nil {
		return "race_send error: " + err.Error(), true
	}
	return jsonStr(map[string]any{"results": results, "summary": map[string]any{"total": len(results)}}), false
}

func (s *Server) runSequence(a map[string]any) (string, bool) {
	stepsRaw, _ := a["steps"].([]any)
	if len(stepsRaw) == 0 {
		return jsonStr(map[string]any{"error": "steps array required"}), false
	}
	steps := make([]SeqStep, 0, len(stepsRaw))
	for _, it := range stepsRaw {
		m, _ := it.(map[string]any)
		st := SeqStep{
			Name: str(m, "name"), Raw: str(m, "raw"), Host: str(m, "host"),
			Port: intv(m, "port"), Session: str(m, "session"),
		}
		if _, ok := m["tls"]; ok {
			tv := boolv(m, "tls", true)
			st.TLS = &tv
		}
		if exArr, ok := m["extract"].([]any); ok {
			for _, e := range exArr {
				em, _ := e.(map[string]any)
				st.Extract = append(st.Extract, SeqExtract{
					Var: str(em, "var"), From: str(em, "from"),
					Regex: str(em, "regex"), JSON: firstNonEmpty(str(em, "json"), str(em, "json_path")),
				})
			}
		}
		steps = append(steps, st)
	}
	res, err := s.eng.RunSequence(steps, strMap(a, "vars"))
	if err != nil {
		return "sequence error: " + err.Error(), true
	}
	return jsonStr(res), false
}

func (s *Server) encodeDecode(a map[string]any) (string, bool) {
	in := str(a, "input")
	op := strings.ToLower(str(a, "operation"))
	var out string
	switch op {
	case "base64encode", "base64_encode", "b64encode":
		out = base64.StdEncoding.EncodeToString([]byte(in))
	case "base64decode", "base64_decode", "b64decode":
		b, err := base64.StdEncoding.DecodeString(in)
		if err != nil {
			return "decode error: " + err.Error(), true
		}
		out = string(b)
	case "urlencode", "url_encode":
		out = url.QueryEscape(in)
	case "urldecode", "url_decode":
		d, err := url.QueryUnescape(in)
		if err != nil {
			return "decode error: " + err.Error(), true
		}
		out = d
	case "hexencode", "hex_encode":
		out = hex.EncodeToString([]byte(in))
	case "hexdecode", "hex_decode":
		b, err := hex.DecodeString(in)
		if err != nil {
			return "decode error: " + err.Error(), true
		}
		out = string(b)
	default:
		return "unsupported operation: " + op, true
	}
	return jsonStr(map[string]any{"output": out}), false
}

func (s *Server) reply(id json.RawMessage, result any) {
	if len(id) == 0 {
		return
	}
	s.write(map[string]any{"jsonrpc": "2.0", "id": json.RawMessage(id), "result": result})
}

func (s *Server) replyErr(id json.RawMessage, code int, msg string) {
	s.write(map[string]any{"jsonrpc": "2.0", "id": json.RawMessage(id), "error": map[string]any{"code": code, "message": msg}})
}

func (s *Server) write(v any) {
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.out.Write(b)
	s.out.WriteByte('\n')
	s.out.Flush()
}

func str(m map[string]any, k string) string {
	if v, ok := m[k]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}
func intv(m map[string]any, k string) int {
	if v, ok := m[k]; ok {
		switch n := v.(type) {
		case float64:
			return int(n)
		case int:
			return n
		}
	}
	return 0
}

func strMap(m map[string]any, k string) map[string]string {
	out := map[string]string{}
	if v, ok := m[k].(map[string]any); ok {
		for kk, vv := range v {
			if s, ok := vv.(string); ok {
				out[kk] = s
			} else {
				out[kk] = fmt.Sprint(vv)
			}
		}
	}
	return out
}

func strSlice(m map[string]any, k string) []string {
	out := []string{}
	if v, ok := m[k].([]any); ok {
		for _, it := range v {
			if s, ok := it.(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}
func boolv(m map[string]any, k string, def bool) bool {
	if v, ok := m[k]; ok {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return def
}

func findingInputFrom(a map[string]any) FindingInput {
	return FindingInput{
		Title:             str(a, "title"),
		Description:       firstNonEmpty(str(a, "description"), str(a, "evidence")),
		Severity:          firstNonEmpty(str(a, "severity"), "info"),
		Endpoint:          firstNonEmpty(str(a, "endpoint"), str(a, "url")),
		Method:            str(a, "method"),
		VulnType:          firstNonEmpty(str(a, "vuln_type"), str(a, "type")),
		PoC:               firstNonEmpty(str(a, "poc"), str(a, "proof_of_concept")),
		CVSS:              firstNonEmpty(str(a, "cvss"), str(a, "cvss_score")),
		Request:           firstNonEmpty(str(a, "request"), str(a, "raw_request")),
		Response:          firstNonEmpty(str(a, "response"), str(a, "raw_response")),
		Confidence:        str(a, "confidence"),
		Remediation:       firstNonEmpty(str(a, "remediation"), str(a, "fix")),
		Reporter:          firstNonEmpty(str(a, "reporter"), "cypture"),
		Verified:          boolv(a, "verified", false),
		VerifyNote:        firstNonEmpty(str(a, "verify_note"), str(a, "verification")),
		ProofKind:         firstNonEmpty(str(a, "proof_kind"), str(a, "proofkind")),
		ExtractedEvidence: firstNonEmpty(str(a, "extracted_evidence"), str(a, "extracted_data")),
		Status:            str(a, "status"),
	}
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
func jsonStr(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf("%v", v)
	}
	return string(b)
}

func headerBlob(h map[string]string) string {
	var b strings.Builder
	for k, v := range h {
		b.WriteString(k + ": " + v + "\r\n")
	}
	return b.String()
}

func getRequestView(en *Entry) map[string]any {
	return map[string]any{
		"id":         en.ID,
		"host":       en.Host,
		"port":       en.Port,
		"tls":        en.TLS,
		"method":     en.Method,
		"path":       en.Path,
		"url":        en.URL,
		"statusCode": en.StatusCode,
		"body":       en.RespBody,
		"headers":    headerBlob(en.RespHeader),
		"raw":        rawRequest(en),

		"status_code":  en.StatusCode,
		"resp_body":    en.RespBody,
		"resp_headers": en.RespHeader,
		"req_headers":  en.ReqHeaders,
		"req_body":     en.ReqBody,
		"length":       en.Length,
		"duration_ms":  en.DurationMs,
	}
}
