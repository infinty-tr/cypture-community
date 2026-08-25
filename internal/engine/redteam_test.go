package engine

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/smtp"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

func hostPort(t *testing.T, raw string) (string, int) {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	h, p, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	port, _ := strconv.Atoi(p)
	return h, port
}

func newScopedEngine() *Engine { return New([]string{"127.0.0.1"}, nil) }

func TestRaceSend_FiresAllSynchronized(t *testing.T) {
	var count int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&count, 1)
		w.WriteHeader(200)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	host, port := hostPort(t, srv.URL)

	e := newScopedEngine()
	raw := "POST /redeem HTTP/1.1\r\nHost: " + host + "\r\nContent-Length: 5\r\n\r\nhello"
	results, err := e.RaceSend([]RaceRequest{
		{Label: "a", Raw: raw}, {Label: "b", Raw: raw},
		{Label: "c", Raw: raw}, {Label: "d", Raw: raw},
	}, host, port, false, "", 0)
	if err != nil {
		t.Fatalf("RaceSend: %v", err)
	}
	if len(results) != 4 {
		t.Fatalf("want 4 results, got %d", len(results))
	}
	for _, r := range results {
		if r.Error != "" {
			t.Fatalf("result %s error: %s", r.Label, r.Error)
		}
		if r.StatusCode != 200 {
			t.Fatalf("result %s status=%d, want 200", r.Label, r.StatusCode)
		}
	}
	if got := atomic.LoadInt32(&count); got != 4 {
		t.Fatalf("server saw %d requests, want 4", got)
	}
}

func TestRaceSend_OutOfScopeRejected(t *testing.T) {
	e := newScopedEngine()
	_, err := e.RaceSend([]RaceRequest{{Label: "x", Raw: "GET / HTTP/1.1\r\n\r\n"}}, "evil.example.com", 80, false, "", 0)
	if err == nil {
		t.Fatal("expected out-of-scope rejection, got nil")
	}
}

func TestRunSequence_CarriesStateAcrossSteps(t *testing.T) {
	var sawToken string
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"csrf":"TOK-9182"}}`))
	})
	mux.HandleFunc("/act", func(w http.ResponseWriter, r *http.Request) {
		sawToken = r.URL.Query().Get("t")
		w.WriteHeader(200)
		_, _ = w.Write([]byte("done"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	host, port := hostPort(t, srv.URL)

	e := newScopedEngine()
	tlsOff := false
	steps := []SeqStep{
		{
			Name: "login", Host: host, Port: port, TLS: &tlsOff,
			Raw:     "GET /login HTTP/1.1\r\nHost: " + host + "\r\n\r\n",
			Extract: []SeqExtract{{Var: "tok", From: "body", JSON: "data.csrf"}},
		},
		{
			Name: "act", Host: host, Port: port, TLS: &tlsOff,
			Raw: "GET /act?t={{tok}} HTTP/1.1\r\nHost: " + host + "\r\n\r\n",
		},
	}
	res, err := e.RunSequence(steps, nil)
	if err != nil {
		t.Fatalf("RunSequence: %v", err)
	}
	vars, _ := res["vars"].(map[string]string)
	if vars["tok"] != "TOK-9182" {
		t.Fatalf("extracted token = %q, want TOK-9182", vars["tok"])
	}
	if sawToken != "TOK-9182" {
		t.Fatalf("step 2 sent t=%q, want the borrowed token TOK-9182", sawToken)
	}
}

func TestRunSequence_RegexAndHeaderExtract(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/a", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Trace", "trace-7")
		_, _ = w.Write([]byte("session=ABC123; path=/"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	host, port := hostPort(t, srv.URL)

	e := newScopedEngine()
	tlsOff := false
	steps := []SeqStep{{
		Name: "a", Host: host, Port: port, TLS: &tlsOff,
		Raw: "GET /a HTTP/1.1\r\nHost: " + host + "\r\n\r\n",
		Extract: []SeqExtract{
			{Var: "sid", From: "body", Regex: `session=([A-Z0-9]+)`},
			{Var: "trace", From: "header:X-Trace"},
			{Var: "code", From: "status"},
		},
	}}
	res, err := e.RunSequence(steps, nil)
	if err != nil {
		t.Fatalf("RunSequence: %v", err)
	}
	vars, _ := res["vars"].(map[string]string)
	if vars["sid"] != "ABC123" {
		t.Fatalf("regex extract sid=%q, want ABC123", vars["sid"])
	}
	if vars["trace"] != "trace-7" {
		t.Fatalf("header extract trace=%q, want trace-7", vars["trace"])
	}
	if vars["code"] != "200" {
		t.Fatalf("status extract code=%q, want 200", vars["code"])
	}
}

func TestOOB_RecordsAndConfirms(t *testing.T) {
	o := NewOOB("", "")
	srv := httptest.NewServer(o)
	defer srv.Close()
	o.baseURL = srv.URL

	reg := o.Register("blind-ssrf")
	tok, _ := reg["token"].(string)
	if tok == "" {
		t.Fatal("Register returned no token")
	}

	if p := o.Poll(tok); p["confirmed"].(bool) {
		t.Fatal("token confirmed before any callback")
	}

	resp, err := http.Get(srv.URL + "/" + tok + "/x")
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	_ = resp.Body.Close()

	p := o.Poll(tok)
	if !p["confirmed"].(bool) {
		t.Fatalf("token not confirmed after callback: %+v", p)
	}
	if p["count"].(int) != 1 {
		t.Fatalf("hit count = %v, want 1", p["count"])
	}
}

func TestOOB_RegisterURLs(t *testing.T) {
	o := NewOOB("http://oob.example.com/", "oob.example.com")
	reg := o.Register("x")
	tok := reg["token"].(string)
	if reg["http_url"] != "http://oob.example.com/"+tok {
		t.Fatalf("http_url = %v", reg["http_url"])
	}
	if reg["dns_host"] != tok+".oob.example.com" {
		t.Fatalf("dns_host = %v", reg["dns_host"])
	}
}

func TestParamMine_FindsHiddenParam(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/search", func(w http.ResponseWriter, r *http.Request) {

		if r.URL.Query().Get("debug") != "" {
			_, _ = w.Write([]byte("RESULTS + DEBUG TRACE: internal stack dump here, lots of extra bytes...."))
			return
		}
		_, _ = w.Write([]byte("RESULTS"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	host, port := hostPort(t, srv.URL)

	e := newScopedEngine()
	base, err := e.Send("GET /search?q=1 HTTP/1.1\r\nHost: "+host+"\r\n\r\n", host, port, false, "", 0, false)
	if err != nil {
		t.Fatalf("baseline send: %v", err)
	}
	out, err := e.ParamMine(base.RequestID, []string{"debug", "nope", "whatever"}, "")
	if err != nil {
		t.Fatalf("ParamMine: %v", err)
	}
	interesting, _ := out["interesting"].([]ParamHit)
	found := false
	for _, h := range interesting {
		if h.Param == "debug" {
			found = true
		}
		if h.Param == "nope" || h.Param == "whatever" {
			t.Fatalf("inert param %q flagged interesting: %+v", h.Param, h)
		}
	}
	if !found {
		t.Fatalf("hidden param 'debug' not found; interesting=%+v", interesting)
	}
}

func TestOOB_CapturesEmailWithLinkAndOTP(t *testing.T) {
	o := NewOOB("", "oob.test")
	reg := o.Register("reset-flow")
	tok := reg["token"].(string)
	email, _ := reg["email"].(string)
	if email != tok+"@oob.test" {
		t.Fatalf("register email = %q, want %s@oob.test", email, tok)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		o.handleSMTP(conn)
	}()

	c, err := smtp.Dial(ln.Addr().String())
	if err != nil {
		t.Fatalf("smtp dial: %v", err)
	}
	if err := c.Hello("attacker.test"); err != nil {
		t.Fatalf("HELO: %v", err)
	}
	if err := c.Mail("noreply@victim.test"); err != nil {
		t.Fatalf("MAIL: %v", err)
	}
	if err := c.Rcpt(email); err != nil {
		t.Fatalf("RCPT: %v", err)
	}
	wc, err := c.Data()
	if err != nil {
		t.Fatalf("DATA: %v", err)
	}
	msg := "Subject: Reset your password\r\n\r\n" +
		"Click https://victim.test/reset?token=ABC123DEF to reset.\r\n" +
		"Your verification code is 482913.\r\n"
	if _, err := wc.Write([]byte(msg)); err != nil {
		t.Fatalf("write data: %v", err)
	}
	_ = wc.Close()
	_ = c.Quit()

	p := o.Poll(tok)
	if p["email_count"].(int) != 1 {
		t.Fatalf("email_count = %v, want 1", p["email_count"])
	}
	links := p["email_links"].([]string)
	if len(links) == 0 || !strings.Contains(links[0], "/reset?token=ABC123DEF") {
		t.Fatalf("reset link not extracted: %v", links)
	}
	codes := p["email_codes"].([]string)
	foundCode := false
	for _, c := range codes {
		if c == "482913" {
			foundCode = true
		}
	}
	if !foundCode {
		t.Fatalf("OTP code 482913 not extracted: %v", codes)
	}
	emails := p["emails"].([]OOBEmail)
	if len(emails) != 1 || emails[0].Subject != "Reset your password" {
		t.Fatalf("email subject not parsed: %+v", emails)
	}
}

var _ = fmt.Sprintf
