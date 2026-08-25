package server

import (
	"bufio"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"runtime/debug"
	"strings"
	"sync"
	"time"
)

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")

		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Permissions-Policy", "geolocation=(), microphone=(), camera=(), payment=(), usb=()")

		if strings.HasPrefix(r.URL.Path, "/api/") {
			h.Set("Cache-Control", "no-store, no-cache, must-revalidate, private")
			h.Set("Pragma", "no-cache")
		}

		h.Set("Content-Security-Policy",
			"default-src 'self'; "+
				"script-src 'self' 'unsafe-inline'; "+
				"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "+
				"font-src 'self' https://fonts.gstatic.com; "+
				"img-src 'self' data:; "+
				"connect-src 'self' ws: wss:; "+
				"frame-src 'none'; "+
				"frame-ancestors 'none'; base-uri 'self'")
		if !s.Cfg.Dev() {
			h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) logger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: 200}
		next.ServeHTTP(sw, r)
		slog.Info("http",
			"method", r.Method,
			"path", r.URL.Path,
			"status", sw.status,
			"dur", time.Since(start).Round(time.Millisecond).String(),
		)
	})
}

type ipLimiter struct {
	mu    sync.Mutex
	rate  float64
	burst float64
	seen  map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newIPLimiter(perMin, burst int) *ipLimiter {
	if perMin <= 0 {
		return nil
	}
	if burst < 1 {
		burst = 1
	}
	return &ipLimiter{
		rate:  float64(perMin) / 60.0,
		burst: float64(burst),
		seen:  make(map[string]*bucket),
	}
}

func (l *ipLimiter) allow(ip string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.seen[ip]
	if b == nil {
		b = &bucket{tokens: l.burst, last: now}
		l.seen[ip] = b
	}

	b.tokens += now.Sub(b.last).Seconds() * l.rate
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.last = now

	if len(l.seen) > 4096 {
		for k, v := range l.seen {
			if now.Sub(v.last) > 10*time.Minute {
				delete(l.seen, k)
			}
		}
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func (s *Server) rateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.rl != nil && strings.HasPrefix(r.URL.Path, "/api/") {
			if !s.rl.allow(clientIP(r), time.Now()) {
				w.Header().Set("Retry-After", "5")
				writeErr(w, http.StatusTooManyRequests, "too many requests — please try again shortly")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				slog.Error("panic recovered", "err", rec, "stack", string(debug.Stack()))
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
			}
		}()
		next.ServeHTTP(w, r)
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("underlying ResponseWriter does not support hijacking")
	}
	return h.Hijack()
}

func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
