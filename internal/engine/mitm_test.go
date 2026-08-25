package engine

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestMITMProxyLogsHTTPS(t *testing.T) {

	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Test", "ok")
		_, _ = io.WriteString(w, "secret-body for "+r.URL.Path)
	}))
	defer upstream.Close()

	u, _ := url.Parse(upstream.URL)
	host := u.Hostname()

	e := New([]string{host}, nil)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		srv := &http.Server{Handler: http.HandlerFunc(e.proxyHandler)}
		_ = srv.Serve(ln)
	}()
	time.Sleep(50 * time.Millisecond)

	proxyURL, _ := url.Parse("http://" + ln.Addr().String())
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := client.Get(upstream.URL + "/api/secret")
	if err != nil {
		t.Fatalf("request through MITM proxy failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(string(body), "secret-body for /api/secret") {
		t.Fatalf("body not relayed correctly: %q", string(body))
	}

	e.mu.Lock()
	hist := append([]*Entry(nil), e.history...)
	e.mu.Unlock()
	var found *Entry
	for _, en := range hist {
		if en.Path == "/api/secret" {
			found = en
			break
		}
	}
	if found == nil {
		t.Fatalf("MITM did not log the HTTPS request into history (got %d entries)", len(hist))
	}
	if !found.TLS || found.StatusCode != 200 {
		t.Fatalf("logged entry wrong: tls=%v status=%d", found.TLS, found.StatusCode)
	}
	if !strings.Contains(found.RespBody, "secret-body") {
		t.Fatalf("response body not captured for evidence: %q", found.RespBody)
	}
}

func TestMITMProxyScopeGate(t *testing.T) {
	e := New([]string{"in-scope.test"}, nil)
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		srv := &http.Server{Handler: http.HandlerFunc(e.proxyHandler)}
		_ = srv.Serve(ln)
	}()
	time.Sleep(50 * time.Millisecond)

	proxyURL, _ := url.Parse("http://" + ln.Addr().String())
	client := &http.Client{
		Timeout:   3 * time.Second,
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}

	_, err := client.Get("https://evil.example.com/")
	if err == nil {
		t.Fatal("out-of-scope HTTPS request should have been refused")
	}
}
