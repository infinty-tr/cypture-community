package server

import (
	"errors"
	"net/http"
	"time"

	"cypture/internal/auth"
	"cypture/internal/models"
)

func (s *Server) authThrottle(w http.ResponseWriter, r *http.Request) bool {
	if s.authRl != nil && !s.authRl.allow(clientIP(r), time.Now()) {
		w.Header().Set("Retry-After", "30")
		writeErr(w, http.StatusTooManyRequests, "too many attempts — please wait a moment")
		return false
	}
	return true
}

type loginReq struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type userDTO struct {
	ID                 string `json:"id"`
	Email              string `json:"email"`
	Role               string `json:"role"`
	Status             string `json:"status"`
	CompanyName        string `json:"company_name"`
	MustChangePassword bool   `json:"must_change_password"`
}

func toUserDTO(u *models.User) userDTO {
	return userDTO{
		ID:                 u.ID,
		Email:              u.Email,
		Role:               string(u.Role),
		Status:             string(u.Status),
		CompanyName:        u.CompanyName,
		MustChangePassword: u.MustChangePassword,
	}
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if !s.authThrottle(w, r) {
		return
	}
	var req loginReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}

	token, csrf, u, err := s.Auth.Login(req.Email, req.Password, clientIP(r), userAgent(r))
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrLocked):
			writeErr(w, http.StatusTooManyRequests, "too many attempts, try again later")
		case errors.Is(err, auth.ErrDisabled):
			writeErr(w, http.StatusForbidden, "account disabled")
		case errors.Is(err, auth.ErrUnverified):
			writeErr(w, http.StatusForbidden, "please verify your email address — click the link we sent you")
		default:
			writeErr(w, http.StatusUnauthorized, "invalid credentials")
		}
		return
	}

	s.Auth.SetCookies(w, token, csrf)
	s.audit(u.ID, "auth.login", "user", u.ID, "", clientIP(r))
	writeJSON(w, http.StatusOK, map[string]any{
		"user":     toUserDTO(u),
		"csrf":     csrf,
		"redirect": redirectFor(u),
	})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(auth.SessionCookie); err == nil {
		s.Auth.Logout(c.Value)
	}
	s.Auth.ClearCookies(w)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	u, _ := auth.UserFrom(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{
		"user": toUserDTO(u),
	})
}

func redirectFor(u *models.User) string {
	return "/admin"
}
