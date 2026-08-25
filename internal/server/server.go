package server

import (
	"net/http"
	"path/filepath"
	"strings"

	"gorm.io/gorm"

	"cypture/internal/auth"
	"cypture/internal/config"
	"cypture/internal/mailer"
	"cypture/internal/models"
)

type Server struct {
	Cfg    *config.Config
	DB     *gorm.DB
	Auth   *auth.Service
	Mailer mailer.Mailer
	Hub    *Hub
	Scans  *ScanManager
	rl     *ipLimiter
	authRl *ipLimiter
	mux    *http.ServeMux
}

func New(cfg *config.Config, gdb *gorm.DB) *Server {
	hub := NewHub()
	var ml mailer.Mailer = mailer.NewStub()
	if sm := mailer.NewSMTP(cfg.SMTPHost, cfg.SMTPPort, cfg.SMTPUser, cfg.SMTPPass, cfg.SMTPFrom); sm != nil {
		ml = sm
	}
	s := &Server{
		Cfg:    cfg,
		DB:     gdb,
		Auth:   auth.NewService(gdb, cfg),
		Mailer: ml,
		Hub:    hub,
		Scans:  NewScanManager(gdb, cfg, hub),
		rl:     newIPLimiter(cfg.RateLimitPerMin, cfg.RateLimitBurst),
		authRl: newIPLimiter(12, 5),
		mux:    http.NewServeMux(),
	}
	s.routes()
	s.startRetentionMaintenance()
	return s
}

func (s *Server) Handler() http.Handler {
	return s.recoverer(s.securityHeaders(s.rateLimit(s.logger(s.mux))))
}

func (s *Server) routes() {

	s.mux.HandleFunc("GET /api/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	admin := func(h http.HandlerFunc) http.HandlerFunc { return s.Auth.RequireRole(models.RoleAdmin, h) }
	s.mux.HandleFunc("POST /api/auth/login", s.handleLogin)
	s.mux.HandleFunc("POST /api/auth/logout", s.Auth.RequireAuth(s.handleLogout))
	s.mux.HandleFunc("GET /api/auth/me", s.Auth.RequireAuth(s.handleMe))
	s.mux.HandleFunc("POST /api/auth/change-password", s.Auth.RequireAuth(s.handleChangePassword))

	s.mux.HandleFunc("GET /api/public/stats", s.handlePublicStats)

	s.mux.HandleFunc("GET /api/admin/settings", admin(s.handleGetSettings))
	s.mux.HandleFunc("POST /api/admin/settings", admin(s.handleSetSettings))
	s.mux.HandleFunc("POST /api/admin/settings/validate", admin(s.handleValidateSettings))

	s.mux.HandleFunc("GET /api/settings/llm", s.Auth.RequireAuth(s.handleGetMyLLM))
	s.mux.HandleFunc("POST /api/settings/llm", s.Auth.RequireAuth(s.handleSetMyLLM))

	s.mux.HandleFunc("GET /api/admin/api-keys", admin(s.handleListAPIKeys))
	s.mux.HandleFunc("POST /api/admin/api-keys", admin(s.handleAddAPIKey))
	s.mux.HandleFunc("POST /api/admin/api-keys/{id}/toggle", admin(s.handleToggleAPIKey))
	s.mux.HandleFunc("DELETE /api/admin/api-keys/{id}", admin(s.handleDeleteAPIKey))
	s.mux.HandleFunc("GET /api/admin/api-keys/assignments", admin(s.handleAPIKeyAssignments))

	s.mux.HandleFunc("GET /api/admin/engagements", admin(s.handleAdminListEngagements))
	s.mux.HandleFunc("GET /api/admin/engagements/{id}", admin(s.handleAdminGetEngagement))
	s.mux.HandleFunc("GET /api/admin/questions", admin(s.handleAdminQuestions))
	s.mux.HandleFunc("GET /api/admin/stats", admin(s.handleAdminStats))
	s.mux.HandleFunc("POST /api/admin/scans", admin(s.handleAdminCreateScan))
	s.mux.HandleFunc("POST /api/admin/scans/{id}/delete", admin(s.handleAdminDeleteScan))
	s.mux.HandleFunc("POST /api/admin/scans/{id}/restart", admin(s.handleAdminRestartScan))

	s.mux.HandleFunc("GET /api/admin/audit", admin(s.handleAdminAudit))
	s.mux.HandleFunc("POST /api/admin/findings/{id}", admin(s.handleAdminUpdateFinding))
	s.mux.HandleFunc("DELETE /api/admin/findings/{id}", admin(s.handleAdminDeleteFinding))

	authmw := s.Auth.RequireAuth
	s.mux.HandleFunc("GET /api/scans", authmw(s.handleListScans))
	s.mux.HandleFunc("GET /api/engagements/{id}/scan", authmw(s.handleEngagementScan))
	s.mux.HandleFunc("GET /api/scans/{id}", authmw(s.handleScanStatus))
	s.mux.HandleFunc("GET /api/scans/{id}/events", authmw(s.handleScanEvents))
	s.mux.HandleFunc("GET /api/scans/{id}/findings", authmw(s.handleScanFindings))
	s.mux.HandleFunc("GET /api/scans/{id}/traffic", authmw(s.handleScanTraffic))
	s.mux.HandleFunc("GET /api/scans/{id}/report", authmw(s.handleScanReport))
	s.mux.HandleFunc("POST /api/scans/{id}/stop", authmw(s.handleScanStop))
	s.mux.HandleFunc("POST /api/scans/{id}/answer", authmw(s.handleScanAnswer))
	s.mux.HandleFunc("GET /ws/scan/{id}", s.handleScanWS)
	s.mux.HandleFunc("GET /ws/scan/{id}/tty", s.handleScanTTY)

	s.registerFrontend()
}

func (s *Server) registerFrontend() {
	fe := s.Cfg.FrontendDir

	staticCache := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-cache")
			next.ServeHTTP(w, r)
		})
	}
	s.mux.Handle("GET /css/", staticCache(http.StripPrefix("/css/", http.FileServer(http.Dir(filepath.Join(fe, "css"))))))
	s.mux.Handle("GET /js/", staticCache(http.StripPrefix("/js/", http.FileServer(http.Dir(filepath.Join(fe, "js"))))))

	s.mux.HandleFunc("GET /js/admin.js", func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(auth.SessionCookie)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		u, err := s.Auth.Resolve(c.Value)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		if u.Role != models.RoleAdmin {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-cache")
		http.ServeFile(w, r, filepath.Join(fe, "js", "admin.js"))
	})

	s.mux.HandleFunc("GET /api/", func(w http.ResponseWriter, r *http.Request) {
		writeErr(w, http.StatusNotFound, "not found")
	})

	pages := map[string]string{
		"GET /":      "dashboard.html",
		"GET /login": "login.html",
	}
	for pattern, file := range pages {
		f := filepath.Join(fe, file)
		s.mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			http.ServeFile(w, r, f)
		})
	}

	s.mux.HandleFunc("GET /admin", func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(auth.SessionCookie)
		if err != nil {
			http.Redirect(w, r, "/login?next=/admin", http.StatusSeeOther)
			return
		}
		u, err := s.Auth.Resolve(c.Value)
		if err != nil {
			http.Redirect(w, r, "/login?next=/admin", http.StatusSeeOther)
			return
		}
		if u.Role != models.RoleAdmin {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		http.ServeFile(w, r, filepath.Join(fe, "admin.html"))
	})

	redirects := map[string]string{
		"GET /login.html":     "/login",
		"GET /admin.html":     "/admin",
		"GET /dashboard.html": "/",
		"GET /dashboard":      "/",
	}
	for pattern, to := range redirects {
		dest := to
		s.mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, dest, http.StatusMovedPermanently)
		})
	}
}

func isSafePath(p string) bool {
	return !strings.Contains(p, "..")
}
