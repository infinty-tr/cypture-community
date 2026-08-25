package engine

import (
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func (e *Engine) ServeProxy(addr string) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return
	}
	srv := &http.Server{Handler: http.HandlerFunc(e.proxyHandler)}
	_ = srv.Serve(ln)
}

func (e *Engine) proxyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		e.proxyConnect(w, r)
		return
	}
	e.proxyHTTP(w, r)
}

func (e *Engine) proxyConnect(w http.ResponseWriter, r *http.Request) {
	hostPort := r.Host
	bare := normalizeHost(hostPort)
	if !e.InScope(bare) {
		http.Error(w, "host out of the authorized scope", http.StatusForbidden)
		return
	}
	port := 443
	if p := portOf(hostPort); p > 0 {
		port = p
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "proxy: hijack unsupported", http.StatusInternalServerError)
		return
	}
	client, _, err := hj.Hijack()
	if err != nil {
		return
	}
	_, _ = client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	if e.ensureCA() == nil {
		if leaf, lerr := e.leafFor(bare); lerr == nil {
			e.mitmServe(client, leaf, bare, port)
			return
		}
	}

	e.feedWrite(map[string]any{"t": "connect", "host": bare, "tls": true})
	dest, derr := net.DialTimeout("tcp", ensurePort(hostPort, "443"), 15*time.Second)
	if derr != nil {
		_ = client.Close()
		return
	}
	go func() { _, _ = io.Copy(dest, client); _ = dest.Close() }()
	_, _ = io.Copy(client, dest)
	_ = client.Close()
}

func portOf(hostPort string) int {
	_, p, err := net.SplitHostPort(hostPort)
	if err != nil {
		return 0
	}
	n, err := strconv.Atoi(p)
	if err != nil {
		return 0
	}
	return n
}

func (e *Engine) proxyHTTP(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Hostname()
	if host == "" {
		http.Error(w, "proxy: absolute-URI request required", http.StatusBadRequest)
		return
	}
	if !e.InScope(host) {
		http.Error(w, "host out of the authorized scope", http.StatusForbidden)
		return
	}

	body, _ := io.ReadAll(io.LimitReader(r.Body, 10<<20))
	out, err := http.NewRequest(r.Method, r.URL.String(), strings.NewReader(string(body)))
	if err != nil {
		http.Error(w, "proxy: "+err.Error(), http.StatusBadGateway)
		return
	}
	for k, vs := range r.Header {
		if isHopByHop(k) {
			continue
		}
		for _, v := range vs {
			out.Header.Add(k, v)
		}
	}

	port := 80
	if p := r.URL.Port(); p != "" {
		if n, e2 := strconv.Atoi(p); e2 == nil {
			port = n
		}
	}

	start := time.Now()
	resp, err := e.defClient.Do(out)
	dur := time.Since(start).Milliseconds()

	entry := &Entry{
		ID: e.nextID("req"), Host: host, Port: port, TLS: false,
		Method: r.Method, Path: r.URL.Path, URL: r.URL.String(),
		DurationMs: dur, At: time.Now(), ReqHeaders: flatten(r.Header),
	}
	if err != nil {
		entry.Error = err.Error()
		e.store(entry)
		http.Error(w, "proxy upstream error: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	entry.StatusCode = resp.StatusCode
	entry.RespHeader = flatten(resp.Header)

	entry.RespBody = clipStr(string(respBody), e.bodyCap)
	entry.Length = len(respBody)
	if len(respBody) > len(entry.RespBody) {
		entry.TrueLen = len(respBody)
	}
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		entry.RedirectTo = resp.Header.Get("Location")
	}
	e.store(entry)

	for k, vs := range resp.Header {
		if isHopByHop(k) {
			continue
		}
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(respBody)
}

func ensurePort(host, def string) string {
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host
	}
	return net.JoinHostPort(host, def)
}

var hopByHop = map[string]bool{
	"connection": true, "proxy-connection": true, "keep-alive": true,
	"proxy-authenticate": true, "proxy-authorization": true, "te": true,
	"trailer": true, "transfer-encoding": true, "upgrade": true,
}

func isHopByHop(h string) bool { return hopByHop[strings.ToLower(h)] }
