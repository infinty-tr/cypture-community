package engine

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

type OOBHit struct {
	At     time.Time `json:"at"`
	Proto  string    `json:"proto"`
	SrcIP  string    `json:"srcIp"`
	Method string    `json:"method,omitempty"`
	Host   string    `json:"host,omitempty"`
	Path   string    `json:"path,omitempty"`
	Query  string    `json:"query,omitempty"`
	UA     string    `json:"ua,omitempty"`
}

type OOBEmail struct {
	At      time.Time `json:"at"`
	From    string    `json:"from,omitempty"`
	To      []string  `json:"to,omitempty"`
	Subject string    `json:"subject,omitempty"`
	Body    string    `json:"body,omitempty"`
	Links   []string  `json:"links,omitempty"`
	Codes   []string  `json:"codes,omitempty"`
}

type OOB struct {
	mu      sync.Mutex
	hits    map[string][]OOBHit
	emails  map[string][]OOBEmail
	tokens  []string
	baseURL string
	domain  string
}

func NewOOB(baseURL, domain string) *OOB {
	return &OOB{
		hits:    map[string][]OOBHit{},
		emails:  map[string][]OOBEmail{},
		baseURL: strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		domain:  strings.TrimPrefix(strings.TrimSpace(domain), "."),
	}
}

func randToken() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "cyptokfallback"
	}
	return "c" + hex.EncodeToString(b)
}

func (o *OOB) Register(label string) map[string]any {
	tok := randToken()
	o.mu.Lock()
	o.tokens = append(o.tokens, tok)
	if _, ok := o.hits[tok]; !ok {
		o.hits[tok] = []OOBHit{}
	}
	if _, ok := o.emails[tok]; !ok {
		o.emails[tok] = []OOBEmail{}
	}
	o.mu.Unlock()

	res := map[string]any{"token": tok, "label": label}
	if o.baseURL != "" {
		res["http_url"] = o.baseURL + "/" + tok
	}
	if o.domain != "" {
		res["dns_host"] = tok + "." + o.domain
		res["http_url_dns"] = "http://" + tok + "." + o.domain + "/"

		res["email"] = tok + "@" + o.domain
	}
	res["hint"] = "Inject the URL/host into a suspected sink for blind callbacks; OR use `email` as the victim address in a register/reset/2FA flow. Then cyp_oob_poll{token}: any http hit = blind callback CONFIRMED; any captured email exposes its reset link / OTP code to continue the chain (→ cyp_sequence)."
	return res
}

func (o *OOB) Poll(token string) map[string]any {
	o.mu.Lock()
	defer o.mu.Unlock()
	hits := o.hits[token]
	cp := make([]OOBHit, len(hits))
	copy(cp, hits)
	mails := o.emails[token]
	cm := make([]OOBEmail, len(mails))
	copy(cm, mails)

	var links, codes []string
	for _, m := range cm {
		links = append(links, m.Links...)
		codes = append(codes, m.Codes...)
	}
	return map[string]any{
		"token": token, "count": len(cp), "interactions": cp, "confirmed": len(cp) > 0,
		"email_count": len(cm), "emails": cm,
		"email_links": dedupStrings(links), "email_codes": dedupStrings(codes),
	}
}

func (o *OOB) record(hit OOBHit) {
	hay := strings.ToLower(hit.Host + " " + hit.Path + " " + hit.Query)
	o.mu.Lock()
	defer o.mu.Unlock()
	for _, tok := range o.tokens {
		if strings.Contains(hay, tok) {
			o.hits[tok] = append(o.hits[tok], hit)
		}
	}
}

func (o *OOB) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	proto := "http"
	if r.TLS != nil {
		proto = "https"
	}
	o.record(OOBHit{
		At: time.Now(), Proto: proto, SrcIP: ip, Method: r.Method,
		Host: r.Host, Path: r.URL.Path, Query: r.URL.RawQuery, UA: r.UserAgent(),
	})
	w.Header().Set("Server", "nginx")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func (o *OOB) Start(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	o.mu.Lock()
	if o.baseURL == "" {
		o.baseURL = "http://" + ln.Addr().String()
	}
	o.mu.Unlock()
	srv := &http.Server{Handler: o, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second}
	return srv.Serve(ln)
}

func (o *OOB) StartSMTP(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go o.handleSMTP(conn)
	}
}

func (o *OOB) handleSMTP(conn net.Conn) {

	defer func() { _ = recover() }()
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(60 * time.Second))
	r := bufio.NewReader(io.LimitReader(conn, 8<<20))
	w := bufio.NewWriter(conn)
	reply := func(s string) bool {
		_, _ = w.WriteString(s + "\r\n")
		return w.Flush() == nil
	}
	if !reply("220 cypture-oob ESMTP ready") {
		return
	}
	var from string
	var rcpts []string
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		cmd := strings.ToUpper(strings.TrimSpace(line))
		switch {
		case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
			reply("250 cypture-oob")
		case strings.HasPrefix(cmd, "MAIL FROM"):
			from = extractAngleAddr(line)
			reply("250 OK")
		case strings.HasPrefix(cmd, "RCPT TO"):
			if a := extractAngleAddr(line); a != "" {
				rcpts = append(rcpts, a)
			}
			reply("250 OK")
		case cmd == "DATA":
			reply("354 End data with <CR><LF>.<CR><LF>")
			data := readDotData(r)
			o.recordEmail(from, rcpts, data)
			reply("250 OK queued")
			from, rcpts = "", nil
		case cmd == "RSET":
			from, rcpts = "", nil
			reply("250 OK")
		case cmd == "NOOP":
			reply("250 OK")
		case cmd == "QUIT":
			reply("221 Bye")
			return
		case cmd == "":

		default:
			reply("250 OK")
		}
	}
}

func readDotData(r *bufio.Reader) string {
	var b strings.Builder
	for {
		line, err := r.ReadString('\n')
		if err != nil && line == "" {
			break
		}
		trimmed := strings.TrimRight(line, "\r\n")
		if trimmed == "." {
			break
		}
		if strings.HasPrefix(trimmed, "..") {
			trimmed = trimmed[1:]
		}
		b.WriteString(trimmed)
		b.WriteByte('\n')
		if b.Len() > 8<<20 {
			break
		}
		if err != nil {
			break
		}
	}
	return b.String()
}

func (o *OOB) recordEmail(from string, rcpts []string, data string) {
	hay := strings.ToLower(strings.Join(rcpts, " "))
	unfolded := strings.ReplaceAll(data, "=\r\n", "")
	unfolded = strings.ReplaceAll(unfolded, "=\n", "")
	em := OOBEmail{
		At: time.Now(), From: from, To: rcpts,
		Subject: headerValue(data, "Subject"),
		Body:    clip(data, 1<<16),
		Links:   dedupStrings(emailLinkRe.FindAllString(unfolded, 20)),
		Codes:   dedupStrings(otpCodeRe.FindAllString(stripDigitsNoise(unfolded), 10)),
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	for _, tok := range o.tokens {
		if strings.Contains(hay, tok) {
			o.emails[tok] = append(o.emails[tok], em)
		}
	}
}

var (
	emailLinkRe = regexp.MustCompile(`https?://[^\s"'<>)\]]+`)
	otpCodeRe   = regexp.MustCompile(`\b\d{4,8}\b`)
	angleAddrRe = regexp.MustCompile(`<([^>]*)>`)
)

func extractAngleAddr(line string) string {
	if m := angleAddrRe.FindStringSubmatch(line); len(m) == 2 {
		return strings.TrimSpace(m[1])
	}

	if i := strings.IndexByte(line, ':'); i >= 0 {
		if f := strings.Fields(line[i+1:]); len(f) > 0 {
			return strings.TrimSpace(f[0])
		}
	}
	return ""
}

func headerValue(raw, name string) string {
	for _, ln := range strings.Split(raw, "\n") {
		ln = strings.TrimRight(ln, "\r")
		if ln == "" {
			return ""
		}
		if strings.HasPrefix(strings.ToLower(ln), strings.ToLower(name)+":") {
			return strings.TrimSpace(ln[len(name)+1:])
		}
	}
	return ""
}

func stripDigitsNoise(s string) string {
	return regexp.MustCompile(`\d{9,}`).ReplaceAllString(s, " ")
}

func dedupStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func clip(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max]
}
