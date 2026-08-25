package server

import (
	"net/http"

	"cypture/internal/auth"
	"cypture/internal/models"
)

type changePasswordReq struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	u, _ := auth.UserFrom(r.Context())

	var req changePasswordReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	if !auth.VerifyPassword(req.CurrentPassword, u.PasswordHash) {
		writeErr(w, http.StatusUnauthorized, "current password is incorrect")
		return
	}
	hash, err := auth.HashPassword(req.NewPassword)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.DB.Model(&models.User{}).Where("id = ?", u.ID).Updates(map[string]any{
		"password_hash":        hash,
		"must_change_password": false,
	})

	if c, err := r.Cookie(auth.SessionCookie); err == nil {
		s.DB.Where("user_id = ? AND token_hash <> ?", u.ID, sha256Hex(c.Value)).Delete(&models.AuthSession{})
	}
	s.audit(u.ID, "user.change_password", "user", u.ID, "", clientIP(r))
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
