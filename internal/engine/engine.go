package engine

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Entry struct {
	ID         string            `json:"id"`
	Host       string            `json:"host"`
	Port       int               `json:"port"`
	TLS        bool              `json:"tls"`
	Method     string            `json:"method"`
	Path       string            `json:"path"`
	URL        string            `json:"url"`
	StatusCode int               `json:"status_code"`
	ReqHeaders map[string]string `json:"req_headers,omitempty"`
	ReqBody    string            `json:"req_body,omitempty"`
	RespHeader map[string]string `json:"resp_headers,omitempty"`
	RespBody   string            `json:"resp_body,omitempty"`
	Length     int               `json:"length"`
	DurationMs int64             `json:"duration_ms"`
	SessionID  string            `json:"session_id,omitempty"`
	Error      string            `json:"error,omitempty"`
	RedirectTo string            `json:"redirect_to,omitempty"`
	TrueLen    int               `json:"true_len,omitempty"`
	At         time.Time         `json:"at"`
}

type Finding struct {
	ID                string    `json:"id"`
	Title             string    `json:"title"`
	Description       string    `json:"description"`
	Severity          string    `json:"severity"`
	Endpoint          string    `json:"endpoint,omitempty"`
	Method            string    `json:"method,omitempty"`
	VulnType          string    `json:"vuln_type,omitempty"`
	PoC               string    `json:"poc,omitempty"`
	CVSS              string    `json:"cvss,omitempty"`
	Request           string    `json:"request,omitempty"`
	Response          string    `json:"response,omitempty"`
	DurationMs        int64     `json:"duration_ms,omitempty"`
	ProofArtifact     string    `json:"proof_artifact,omitempty"`
	Confidence        string    `json:"confidence,omitempty"`
	Reporter          string    `json:"reporter"`
	ProofKind         string    `json:"proof_kind,omitempty"`
	ExtractedEvidence string    `json:"extracted_evidence,omitempty"`
	Status            string    `json:"status,omitempty"`
	At                time.Time `json:"at"`
}

type FindingInput struct {
	Title, Description, Severity, Endpoint, Method                            string
	VulnType, PoC, CVSS, Request, Response, Confidence, Remediation, Reporter string
	Verified                                                                  bool
	VerifyNote                                                                string
	ProofKind                                                                 string
	ExtractedEvidence                                                         string
	Status                                                                    string
}

type Engine struct {
	mu        sync.Mutex
	seq       int
	history   []*Entry
	findings  []*Finding
	sessions  map[string]*http.Client
	scopeIn   []string
	scopeEx   []string
	defClient *http.Client

	bodyCap     int
	historyMax  int
	bodyBudget  int64
	storedBytes int64

	baselines map[string]string

	feed   *os.File
	feedMu sync.Mutex

	traffic   *os.File
	trafficMu sync.Mutex

	browser   *Browser
	browserMu sync.Mutex

	ca certAuthority

	oob *OOB

	passiveMu   sync.Mutex
	passiveSeen map[string]bool

	proofMu sync.Mutex
	proofs  map[string]string
	oobHit  bool

	dupMu    sync.Mutex
	dupCount map[string]int
	dupLast  map[string]*SendResult
}

func pathKey(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[i:]
	} else {
		s = "/"
	}
	if i := strings.IndexByte(s, '?'); i >= 0 {
		s = s[:i]
	}
	return strings.ToLower(s)
}

func (e *Engine) recordProof(endpointOrURL, detail string) {
	k := pathKey(endpointOrURL)
	if k == "" {
		return
	}
	e.proofMu.Lock()
	if e.proofs == nil {
		e.proofs = map[string]string{}
	}
	if _, ok := e.proofs[k]; !ok {
		e.proofs[k] = detail
	}
	e.proofMu.Unlock()
}

func (e *Engine) proofFor(endpoint string) (string, bool) {
	e.proofMu.Lock()
	defer e.proofMu.Unlock()
	if e.proofs != nil {
		if d, ok := e.proofs[pathKey(endpoint)]; ok {
			return d, true
		}
	}
	return "", false
}

func (e *Engine) oobBlindProof(vulnType string) bool {
	e.proofMu.Lock()
	hit := e.oobHit
	e.proofMu.Unlock()
	if !hit {
		return false
	}
	v := strings.ToLower(vulnType)
	for _, b := range []string{"ssrf", "rce", "command", "cmd", "xxe", "blind", "oob", "log4", "deseri", "ssti", "interact"} {
		if strings.Contains(v, b) {
			return true
		}
	}
	return false
}

func (e *Engine) noteOOB(res any) {
	b, err := json.Marshal(res)
	if err != nil {
		return
	}
	var m map[string]any
	if json.Unmarshal(b, &m) != nil {
		return
	}
	has := false
	for _, k := range []string{"hits", "emails", "callbacks", "interactions"} {
		if arr, ok := m[k].([]any); ok && len(arr) > 0 {
			has = true
		}
	}
	if c, ok := m["count"].(float64); ok && c > 0 {
		has = true
	}
	if has {
		e.proofMu.Lock()
		e.oobHit = true
		e.proofMu.Unlock()
	}
}

func (e *Engine) SetOOB(o *OOB) { e.oob = o }

const (
	defaultBodyCap    = 256 << 10
	defaultHistoryMax = 8000
	defaultBodyBudget = 512 << 20
)

func (e *Engine) SetLimits(bodyCap, historyMax int, bodyBudget int64) {
	if bodyCap > 0 {
		e.bodyCap = bodyCap
	}
	if historyMax > 0 {
		e.historyMax = historyMax
	}
	if bodyBudget > 0 {
		e.bodyBudget = bodyBudget
	}
}

func (e *Engine) OpenFeed(path string) {
	if strings.TrimSpace(path) == "" {
		return
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	e.feed = f
}

func (e *Engine) feedWrite(v map[string]any) {
	if e.feed == nil {
		return
	}
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	b = append(b, '\n')
	e.feedMu.Lock()
	_, _ = e.feed.Write(b)
	e.feedMu.Unlock()
}

func (e *Engine) OpenTraffic(path string) {
	if strings.TrimSpace(path) == "" {
		return
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	e.traffic = f
}

func (e *Engine) trafficWrite(en *Entry) {
	if e.traffic == nil || en == nil {
		return
	}
	const tcap = 16 << 10
	rec := map[string]any{
		"t": "http", "method": en.Method, "url": en.URL, "host": en.Host, "path": en.Path,
		"status": en.StatusCode, "duration_ms": en.DurationMs, "len": en.Length, "tls": en.TLS,
		"req_headers": en.ReqHeaders, "req_body": clipStr(en.ReqBody, tcap),
		"resp_headers": en.RespHeader, "resp_body": clipStr(en.RespBody, tcap),
		"true_len": en.TrueLen, "err": en.Error, "at": en.At.Format(time.RFC3339),
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return
	}
	b = append(b, '\n')
	e.trafficMu.Lock()
	_, _ = e.traffic.Write(b)
	e.trafficMu.Unlock()
}

func New(includes, excludes []string) *Engine {
	return &Engine{
		sessions:    map[string]*http.Client{},
		scopeIn:     includes,
		scopeEx:     excludes,
		defClient:   newClient(),
		bodyCap:     defaultBodyCap,
		historyMax:  defaultHistoryMax,
		bodyBudget:  defaultBodyBudget,
		baselines:   map[string]string{},
		passiveSeen: map[string]bool{},
	}
}

func (e *Engine) passiveFirst(key string) bool {
	e.passiveMu.Lock()
	defer e.passiveMu.Unlock()
	if e.passiveSeen == nil {
		e.passiveSeen = map[string]bool{}
	}
	if e.passiveSeen[key] {
		return false
	}
	e.passiveSeen[key] = true
	return true
}

func newClient() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{
		Jar:     jar,
		Timeout: 12 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
			MaxIdleConns:        50,
			IdleConnTimeout:     30 * time.Second,
			DisableCompression:  false,
			TLSHandshakeTimeout: 6 * time.Second,
		},

		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func (e *Engine) nextID(prefix string) string {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.seq++
	return fmt.Sprintf("%s_%d", prefix, e.seq)
}

func (e *Engine) InScope(host string) bool {
	host = normalizeHost(host)
	if host == "" {
		return false
	}
	for _, ex := range e.scopeEx {
		if matchPattern(host, ex) {
			return false
		}
	}

	for _, in := range e.scopeIn {
		if matchPattern(host, in) {
			return true
		}
	}
	return false
}

func (e *Engine) CreateSession() string {
	id := e.nextID("sess")
	e.mu.Lock()
	e.sessions[id] = newClient()
	e.mu.Unlock()
	return id
}

func (e *Engine) clientFor(sessionID string) *http.Client {
	if sessionID == "" {
		return e.defClient
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if c, ok := e.sessions[sessionID]; ok {
		return c
	}
	c := newClient()
	e.sessions[sessionID] = c
	return c
}

func (e *Engine) SessionCookies(sessionID, host string, tlsOn bool) []string {
	c := e.clientFor(sessionID)
	scheme := "http"
	if tlsOn {
		scheme = "https"
	}
	u, err := url.Parse(scheme + "://" + host)
	if err != nil || c.Jar == nil {
		return nil
	}
	out := []string{}
	for _, ck := range c.Jar.Cookies(u) {
		out = append(out, ck.Name+"="+ck.Value)
	}
	return out
}

type SendResult struct {
	RequestID  string            `json:"requestId"`
	StatusCode int               `json:"statusCode"`
	Headers    map[string]string `json:"headers"`
	Body       string            `json:"body"`
	Length     int               `json:"length"`
	StoredLen  int               `json:"storedLen"`
	Truncated  bool              `json:"truncated"`
	DurationMs int64             `json:"durationMs"`

	RedirectChain []RedirectHop `json:"redirectChain,omitempty"`
}

type RedirectHop struct {
	RequestID  string `json:"requestId"`
	StatusCode int    `json:"statusCode"`
	From       string `json:"from"`
	Location   string `json:"location"`
}

func (e *Engine) Send(raw, host string, port int, tlsOn bool, sessionID string, bodyLimit int, rawForce bool) (*SendResult, error) {
	host = normalizeHostKeepPort(host)
	bareHost := normalizeHost(host)
	if !e.InScope(bareHost) {
		return nil, fmt.Errorf("host %q is out of the authorized scope", bareHost)
	}
	if bodyLimit <= 0 {
		bodyLimit = 65536
	}
	if bodyLimit > 1<<20 {
		bodyLimit = 1 << 20
	}
	if port == 0 {
		if tlsOn {
			port = 443
		} else {
			port = 80
		}
	}

	if rawForce || needsRawSocket(raw) {
		return e.rawSocketSend(normalizeCRLF(raw), bareHost, port, tlsOn, sessionID, bodyLimit)
	}

	dk := host + "|" + strconv.Itoa(port) + "|" + raw
	e.dupMu.Lock()
	if e.dupCount == nil {
		e.dupCount = map[string]int{}
		e.dupLast = map[string]*SendResult{}
	}
	e.dupCount[dk]++
	dupN := e.dupCount[dk]
	dupPrev := e.dupLast[dk]
	e.dupMu.Unlock()
	if dupN > 6 && dupPrev != nil {
		clone := *dupPrev
		clone.Body = fmt.Sprintf("[CYP-DUPLICATE x%d — the SAME request is being sent over and over, the response is NOT CHANGING. BREAK the loop: try a different payload/parameter/endpoint/technique, or if you are done on this host move to another host.]\n%s", dupN, dupPrev.Body)
		return &clone, nil
	}

	parsed, err := http.ReadRequest(bufio.NewReader(strings.NewReader(normalizeCRLF(raw))))
	if err != nil {
		return nil, fmt.Errorf("invalid raw request: %w", err)
	}
	var bodyBytes []byte
	if parsed.Body != nil {
		bodyBytes, _ = io.ReadAll(parsed.Body)
	}

	client := e.clientFor(sessionID)

	doOnce := func(useTLS bool, p int) (*http.Response, string, error) {
		scheme := "http"
		if useTLS {
			scheme = "https"
		}
		tgt := fmt.Sprintf("%s://%s:%d%s", scheme, bareHost, p, parsed.URL.RequestURI())
		req, err := http.NewRequest(parsed.Method, tgt, strings.NewReader(string(bodyBytes)))
		if err != nil {
			return nil, tgt, err
		}
		for k, vs := range parsed.Header {
			if strings.EqualFold(k, "Host") || strings.EqualFold(k, "Content-Length") {
				continue
			}
			for _, v := range vs {
				req.Header.Add(k, v)
			}
		}
		if h := parsed.Header.Get("Host"); h != "" {
			req.Host = h
		}
		resp, err := client.Do(req)
		return resp, tgt, err
	}

	start := time.Now()
	resp, target, err := doOnce(tlsOn, port)

	if err != nil {
		altTLS := !tlsOn
		altPort := port
		if port == 443 && !altTLS {
			altPort = 80
		} else if port == 80 && altTLS {
			altPort = 443
		}
		if r2, t2, e2 := doOnce(altTLS, altPort); e2 == nil {
			resp, target, err = r2, t2, e2
			tlsOn, port = altTLS, altPort
		}
	}
	dur := time.Since(start).Milliseconds()

	entry := &Entry{
		ID: e.nextID("req"), Host: bareHost, Port: port, TLS: tlsOn,
		Method: parsed.Method, Path: parsed.URL.Path, URL: target,
		SessionID: sessionID, DurationMs: dur, At: time.Now(),
		ReqHeaders: flatten(parsed.Header),
		ReqBody:    clipStr(string(bodyBytes), e.bodyCap),
	}
	if err != nil {
		entry.Error = err.Error()
		e.store(entry)
		return nil, err
	}
	defer resp.Body.Close()

	limited, _ := io.ReadAll(io.LimitReader(resp.Body, int64(bodyLimit)))

	drained, _ := io.Copy(io.Discard, resp.Body)
	trueLen := len(limited) + int(drained)

	entry.StatusCode = resp.StatusCode
	entry.RespHeader = flatten(resp.Header)
	entry.RespBody = clipStr(string(limited), e.bodyCap)
	entry.Length = trueLen
	if trueLen > len(entry.RespBody) {
		entry.TrueLen = trueLen
	}
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		entry.RedirectTo = resp.Header.Get("Location")
	}
	e.store(entry)

	res := &SendResult{
		RequestID:  entry.ID,
		StatusCode: resp.StatusCode,
		Headers:    entry.RespHeader,
		Body:       string(limited),
		Length:     trueLen,
		StoredLen:  len(limited),
		Truncated:  trueLen > len(limited),
		DurationMs: dur,
	}

	e.dupMu.Lock()
	if e.dupLast == nil {
		e.dupLast = map[string]*SendResult{}
	}
	e.dupLast[dk] = res
	e.dupMu.Unlock()
	return res, nil
}

func needsRawSocket(raw string) bool {
	head := normalizeCRLF(raw)
	if i := strings.Index(head, "\r\n\r\n"); i >= 0 {
		head = head[:i]
	}
	for _, line := range strings.Split(head, "\r\n") {
		name := line
		if c := strings.IndexByte(line, ':'); c >= 0 {
			name = line[:c]
		}
		if strings.EqualFold(strings.TrimSpace(name), "Transfer-Encoding") {
			return true
		}
	}
	return false
}

func (e *Engine) rawSocketSend(raw, bareHost string, port int, tlsOn bool, sessionID string, bodyLimit int) (*SendResult, error) {
	if !strings.Contains(strings.ToLower(rawHeaderBlock(raw)), "\r\nhost:") &&
		!strings.HasPrefix(strings.ToLower(raw), "host:") {

		if i := strings.Index(raw, "\r\n"); i >= 0 {
			raw = raw[:i+2] + "Host: " + bareHost + "\r\n" + raw[i+2:]
		}
	}
	method, path := rawRequestLine(raw)

	addr := net.JoinHostPort(bareHost, strconv.Itoa(port))
	start := time.Now()
	var conn net.Conn
	var err error
	dialer := &net.Dialer{Timeout: 15 * time.Second}
	if tlsOn {
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{InsecureSkipVerify: true, ServerName: bareHost})
	} else {
		conn, err = dialer.Dial("tcp", addr)
	}
	entry := &Entry{
		ID: e.nextID("req"), Host: bareHost, Port: port, TLS: tlsOn,
		Method: method, Path: path, URL: schemeOf(tlsOn) + "://" + bareHost + path,
		SessionID: sessionID, At: time.Now(), ReqBody: clipStr(raw, e.bodyCap),
		ReqHeaders: map[string]string{"X-Cypture-Raw": "byte-exact (smuggling)"},
	}
	if err != nil {
		entry.Error = err.Error()
		entry.DurationMs = time.Since(start).Milliseconds()
		e.store(entry)
		return nil, err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	if _, err = conn.Write([]byte(raw)); err != nil {
		entry.Error = err.Error()
		entry.DurationMs = time.Since(start).Milliseconds()
		e.store(entry)
		return nil, err
	}
	respBytes, _ := io.ReadAll(io.LimitReader(conn, int64(bodyLimit)+8192))
	dur := time.Since(start).Milliseconds()

	status, hdr, body := parseRawResponse(string(respBytes))
	trueLen := len(body)
	if len(body) > bodyLimit {
		body = body[:bodyLimit]
	}
	entry.StatusCode = status
	entry.RespHeader = hdr
	entry.RespBody = clipStr(body, e.bodyCap)
	entry.Length = trueLen
	if trueLen > len(entry.RespBody) {
		entry.TrueLen = trueLen
	}
	entry.DurationMs = dur
	e.store(entry)

	return &SendResult{
		RequestID: entry.ID, StatusCode: status, Headers: hdr,
		Body: body, Length: trueLen, StoredLen: len(body), Truncated: trueLen > len(body), DurationMs: dur,
	}, nil
}

func schemeOf(tlsOn bool) string {
	if tlsOn {
		return "https"
	}
	return "http"
}

func rawHeaderBlock(raw string) string {
	if i := strings.Index(raw, "\r\n\r\n"); i >= 0 {
		return raw[:i]
	}
	return raw
}

func rawRequestLine(raw string) (method, path string) {
	line := raw
	if i := strings.Index(raw, "\r\n"); i >= 0 {
		line = raw[:i]
	}
	f := strings.Fields(line)
	if len(f) >= 2 {
		return f[0], f[1]
	}
	if len(f) == 1 {
		return f[0], "/"
	}
	return "RAW", "/"
}

func parseRawResponse(resp string) (status int, headers map[string]string, body string) {
	headers = map[string]string{}
	if resp == "" {
		return 0, headers, ""
	}
	head := resp
	if i := strings.Index(resp, "\r\n\r\n"); i >= 0 {
		head = resp[:i]
		body = resp[i+4:]
	} else {
		body = resp
		head = ""
	}
	lines := strings.Split(head, "\r\n")
	if len(lines) > 0 {
		if f := strings.Fields(lines[0]); len(f) >= 2 {
			status, _ = strconv.Atoi(f[1])
		}
		for _, l := range lines[1:] {
			if c := strings.IndexByte(l, ':'); c >= 0 {
				headers[strings.TrimSpace(l[:c])] = strings.TrimSpace(l[c+1:])
			}
		}
	}
	return status, headers, body
}

func (e *Engine) store(en *Entry) {
	e.mu.Lock()
	e.history = append(e.history, en)
	e.storedBytes += int64(len(en.RespBody) + len(en.ReqBody))

	for len(e.history) > e.historyMax ||
		(e.bodyBudget > 0 && e.storedBytes > e.bodyBudget && len(e.history) > 1) {
		old := e.history[0]
		e.storedBytes -= int64(len(old.RespBody) + len(old.ReqBody))
		if e.storedBytes < 0 {
			e.storedBytes = 0
		}
		e.history = e.history[1:]
	}
	e.mu.Unlock()

	e.feedWrite(map[string]any{
		"t": "req", "method": en.Method, "host": en.Host, "path": en.Path,
		"status": en.StatusCode, "len": en.Length, "tls": en.TLS, "err": en.Error,

		"resp": respPreview(en.RespBody),
	})

	e.trafficWrite(en)

	if en.RespBody != "" && en.Host != "" && e.InScope(en.Host) && isTextResponse(en.RespHeader) {
		if ps := e.PassiveScan(en); ps != nil {
			high, _ := ps["high"].(bool)
			key := en.Host + "|" + en.Path + fmt.Sprintf("|%v|%v", ps["error_leak"], ps["secrets"])
			if e.passiveFirst(key) {
				sig := map[string]any{"t": "signal", "host": en.Host, "path": en.Path, "status": en.StatusCode}
				if v, ok := ps["error_leak"]; ok {
					sig["error_leak"] = v
				}
				if v, ok := ps["secrets"]; ok {
					sig["secrets"] = v
				}
				e.feedWrite(sig)
				if high {

					e.recordProof(en.URL, "passive scan: high-confidence secret/credential leak in response")
					e.feedWrite(map[string]any{
						"t": "find", "vuln_type": "secret-exposure", "severity": "high",
						"status": "probable", "verified": false, "confidence": "likely",
						"proof_artifact": "passive scan: high-confidence secret detected",
						"title":          "Passive: sensitive secret/credential leak in response",
						"endpoint":       en.URL, "method": en.Method, "evidence": ps["secrets"],
					})
				}
			}
		}
	}
}

func respPreview(body string) string {
	s := strings.TrimSpace(body)
	if s == "" {
		return ""
	}
	s = strings.Join(strings.Fields(s), " ")
	return clipStr(s, 400)
}

func (e *Engine) Search(query string, count int) []*Entry {
	if count <= 0 || count > 200 {
		count = 50
	}
	q := strings.ToLower(strings.TrimSpace(query))
	e.mu.Lock()
	defer e.mu.Unlock()
	out := []*Entry{}
	for i := len(e.history) - 1; i >= 0 && len(out) < count; i-- {
		en := e.history[i]
		if q == "" || strings.Contains(strings.ToLower(en.URL+" "+en.Method+" "+fmt.Sprint(en.StatusCode)), q) {
			out = append(out, en)
		}
	}
	return out
}

func (e *Engine) Get(id string) *Entry {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, en := range e.history {
		if en.ID == id {
			return en
		}
	}
	return nil
}

func (e *Engine) Sitemap() []map[string]any {
	e.mu.Lock()
	defer e.mu.Unlock()
	seen := map[string]bool{}
	out := []map[string]any{}
	for _, en := range e.history {
		key := en.Host + en.Path
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, map[string]any{"host": en.Host, "path": en.Path, "status": en.StatusCode})
	}
	return out
}

func capSeverityUnlessVerified(severity string, verified bool) string {
	if verified {
		return severity
	}
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical", "high":
		return "medium"
	}
	return severity
}

func capByProof(severity, proofKind string, realProof bool) string {
	if realProof {
		return severity
	}
	s := strings.ToLower(strings.TrimSpace(severity))
	switch proofKind {
	case "differential":
		if s == "critical" {
			return "high"
		}
		return severity
	default:
		if s == "critical" || s == "high" {
			return "medium"
		}
		return severity
	}
}

func (e *Engine) evidenceInHistory(evidence string) bool {
	ev := strings.TrimSpace(evidence)
	if ev == "" {
		return false
	}
	toks := significantTokens(ev)
	if len(toks) == 0 {
		toks = []string{ev}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, en := range e.history {
		if en == nil {
			continue
		}

		hay := en.RespBody
		for _, t := range toks {
			if strings.Contains(hay, t) {
				return true
			}
		}
	}
	return false
}

func significantTokens(s string) []string {
	var out []string
	var b strings.Builder
	flush := func() {
		if b.Len() >= 5 {
			out = append(out, b.String())
		}
		b.Reset()
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '.', r == '_', r == '-', r == '/', r == ':':
			b.WriteRune(r)
		default:
			flush()
		}
	}
	flush()
	return out
}

func (e *Engine) AddFinding(in FindingInput) *Finding {

	en := e.matchEntry(in.Endpoint)
	if in.Request == "" || in.Response == "" {
		if en != nil {
			if in.Request == "" {
				in.Request = rawRequest(en)
			}
			if in.Response == "" {
				in.Response = rawResponse(en)
			}
			if in.Method == "" {
				in.Method = en.Method
			}
		}
	}

	if in.Verified && en == nil {
		in.Verified = false
		if c := strings.TrimSpace(in.Confidence); c == "" || strings.EqualFold(c, "confirmed") {
			in.Confidence = "unverified"
		}
		in.VerifyNote = strings.TrimSpace("[ENGINE COULD NOT CONFIRM — no real request/response recorded through the engine for this endpoint; 'verified' revoked, proof must be shown via engine traffic] " + in.VerifyNote)
	}

	sevLow := strings.ToLower(strings.TrimSpace(in.Severity))
	if sevLow == "critical" || sevLow == "high" {
		hasPoC := strings.TrimSpace(in.PoC) != ""
		hasDesc := len(strings.TrimSpace(in.Description)) >= 24
		hasReq := strings.TrimSpace(in.Request) != ""
		switch {
		case !hasPoC && !hasDesc && !hasReq:
			in.Confidence = "unverified"
			in.Description = "[PROOF MISSING — no poc/evidence/request; must be verified] " + in.Description
		case !in.Verified:
			if c := strings.TrimSpace(in.Confidence); c == "" || strings.EqualFold(c, "confirmed") {
				in.Confidence = "likely"
			}
			if strings.TrimSpace(in.VerifyNote) == "" {
				in.VerifyNote = "no independent second verification was performed — an adversarial 5-gate check is recommended"
			}
		}
	}

	if capped := capSeverityUnlessVerified(in.Severity, in.Verified); capped != in.Severity {
		if strings.TrimSpace(in.VerifyNote) == "" {
			in.VerifyNote = "severity capped at " + capped + " until proven — it will be raised if real impact is proven (verified)"
		}
		in.Severity = capped
	}

	pkRaw := strings.ToLower(strings.TrimSpace(in.ProofKind))
	if pkRaw != "" {
		realProof := (pkRaw == "extracted_data" || pkRaw == "executed_effect") && strings.TrimSpace(in.ExtractedEvidence) != "" && e.evidenceInHistory(in.ExtractedEvidence)
		switch {
		case realProof:
			in.Status = "confirmed"
			in.Verified = true
		case pkRaw == "differential":
			in.Status = "probable"
		default:
			in.Status = "theoretical"
		}
		if capped := capByProof(in.Severity, pkRaw, realProof); capped != in.Severity {
			if strings.TrimSpace(in.VerifyNote) == "" {
				in.VerifyNote = "severity capped at " + capped + " with proof_kind=" + pkRaw + " — it will be raised if real data/effect (extracted_data/executed_effect) is extracted"
			}
			in.Severity = capped
		}
	} else if in.Status == "" && in.Verified {
		in.Status = "confirmed"
	}

	var durationMs int64
	if en != nil {
		durationMs = en.DurationMs
	}

	proofArtifact, _ := e.proofFor(in.Endpoint)
	if proofArtifact == "" && e.oobBlindProof(in.VulnType) {
		proofArtifact = "out-of-band callback (blind verification)"
	}

	if proofArtifact == "" {
		pk := strings.ToLower(strings.TrimSpace(in.ProofKind))
		if (pk == "extracted_data" || pk == "executed_effect") && len(strings.TrimSpace(in.ExtractedEvidence)) >= 4 {
			if e.evidenceInHistory(in.ExtractedEvidence) {
				proofArtifact = "extracted data/effect: " + clipStr(strings.TrimSpace(in.ExtractedEvidence), 80)
			} else if strings.TrimSpace(in.VerifyNote) == "" {
				in.VerifyNote = "[PROOF NOT GROUNDED — the claimed extracted data was not found in any engine-recorded response; verification not granted]"
			}
		}
	}
	f := &Finding{
		ID: e.nextID("find"), Title: in.Title, Description: in.Description,
		Severity: in.Severity, Endpoint: in.Endpoint, Method: in.Method,
		VulnType: in.VulnType, PoC: in.PoC, CVSS: in.CVSS,
		Request: clipStr(in.Request, e.bodyCap), Response: clipStr(in.Response, e.bodyCap),
		DurationMs: durationMs, ProofArtifact: proofArtifact,
		Confidence: in.Confidence, Reporter: firstNonEmpty(in.Reporter, "cypture"),
		ProofKind: pkRaw, ExtractedEvidence: in.ExtractedEvidence, Status: in.Status, At: time.Now(),
	}
	e.mu.Lock()
	e.findings = append(e.findings, f)
	e.mu.Unlock()

	e.feedWrite(map[string]any{
		"t": "find", "title": f.Title, "severity": f.Severity, "endpoint": f.Endpoint,
		"desc": f.Description, "method": f.Method, "vuln_type": f.VulnType,
		"poc": f.PoC, "cvss": f.CVSS, "request": f.Request, "response": f.Response,
		"duration_ms":    f.DurationMs,
		"proof_artifact": f.ProofArtifact,
		"confidence":     f.Confidence, "remediation": in.Remediation,
		"verified": in.Verified, "verify_note": in.VerifyNote,
		"proof_kind": f.ProofKind, "extracted_evidence": f.ExtractedEvidence, "status": f.Status,
	})
	return f
}

func (e *Engine) matchEntry(endpoint string) *Entry {
	if strings.TrimSpace(endpoint) == "" {
		return nil
	}
	needle := endpoint
	if i := strings.Index(needle, "://"); i >= 0 {
		needle = needle[i+3:]
	}
	if i := strings.IndexByte(needle, '/'); i >= 0 {
		needle = needle[i:]
	}
	pathOnly := needle
	if i := strings.IndexByte(pathOnly, '?'); i >= 0 {
		pathOnly = pathOnly[:i]
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	var best *Entry
	for _, en := range e.history {
		if strings.Contains(en.URL, endpoint) || strings.Contains(en.URL, needle) ||
			(pathOnly != "" && pathOnly != "/" && strings.EqualFold(en.Path, pathOnly)) {
			best = en
		}
	}
	return best
}

func rawRequest(en *Entry) string {
	var b strings.Builder
	target := en.URL
	if i := strings.Index(target, "://"); i >= 0 {
		if j := strings.IndexByte(target[i+3:], '/'); j >= 0 {
			target = target[i+3+j:]
		}
	}
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\n", en.Method, target)
	fmt.Fprintf(&b, "Host: %s\r\n", en.Host)
	for k, v := range en.ReqHeaders {
		if strings.EqualFold(k, "Host") {
			continue
		}
		fmt.Fprintf(&b, "%s: %s\r\n", k, v)
	}
	b.WriteString("\r\n")
	if en.ReqBody != "" {
		b.WriteString(en.ReqBody)
	}
	return b.String()
}

func rawResponse(en *Entry) string {
	var b strings.Builder
	if en.Error != "" {
		fmt.Fprintf(&b, "(transport error) %s\r\n", en.Error)
		return b.String()
	}
	fmt.Fprintf(&b, "HTTP/1.1 %d\r\n", en.StatusCode)
	for k, v := range en.RespHeader {
		fmt.Fprintf(&b, "%s: %s\r\n", k, v)
	}
	b.WriteString("\r\n")
	b.WriteString(en.RespBody)
	return b.String()
}

func clipStr(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "\n…(truncated)"
}

func (e *Engine) Findings() []*Finding {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]*Finding, len(e.findings))
	copy(out, e.findings)
	return out
}

func flatten(h http.Header) map[string]string {
	m := map[string]string{}
	for k, v := range h {
		m[k] = strings.Join(v, ", ")
	}
	return m
}

func normalizeCRLF(raw string) string {
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	raw = strings.ReplaceAll(raw, "\n", "\r\n")
	if !strings.Contains(raw, "\r\n\r\n") {
		raw += "\r\n\r\n"
	}
	return raw
}

func normalizeHostKeepPort(h string) string { return strings.TrimSpace(strings.ToLower(h)) }

func normalizeHost(h string) string {
	h = strings.TrimSpace(strings.ToLower(h))
	h = strings.TrimPrefix(h, "http://")
	h = strings.TrimPrefix(h, "https://")
	if i := strings.IndexAny(h, "/"); i >= 0 {
		h = h[:i]
	}
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	return strings.TrimPrefix(h, "www.")
}

func matchPattern(host, pattern string) bool {
	host = normalizeHost(host)
	p := strings.TrimSpace(strings.ToLower(pattern))

	if hp, _, err := net.SplitHostPort(p); err == nil {
		p = hp
	}
	if host == "" || p == "" {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		if _, ipnet, err := net.ParseCIDR(p); err == nil {
			return ipnet.Contains(ip)
		}
	}

	if strings.HasPrefix(p, "*") {
		base := strings.TrimPrefix(strings.TrimPrefix(p, "*"), ".")
		return host == base || strings.HasSuffix(host, "."+base)
	}
	return host == p
}
