package auth

import (
	"context"
	"net/http"
	"strings"

	"cypture/internal/models"
)

var mustChangeAllowed = map[string]bool{
	"/api/auth/change-password": true,
	"/api/auth/logout":          true,
	"/api/auth/me":              true,
}

var viewerWriteAllowed = map[string]bool{
	"/api/auth/change-password": true,
	"/api/auth/logout":          true,
}

type ctxKey int

const userKey ctxKey = iota

func UserFrom(ctx context.Context) (*models.User, bool) {
	u, ok := ctx.Value(userKey).(*models.User)
	return u, ok
}

func sessionToken(r *http.Request) string {
	c, err := r.Cookie(SessionCookie)
	if err != nil {
		return ""
	}
	return c.Value
}

func (s *Service) RequireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := sessionToken(r)
		u, err := s.Resolve(tok)
		if err != nil {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		if isUnsafe(r.Method) && !s.ValidCSRF(r, tok) {
			http.Error(w, `{"error":"invalid csrf token"}`, http.StatusForbidden)
			return
		}

		if u.MustChangePassword && strings.HasPrefix(r.URL.Path, "/api/") && !mustChangeAllowed[r.URL.Path] {
			http.Error(w, `{"error":"password change required"}`, http.StatusForbidden)
			return
		}

		if u.Role == models.RoleViewer && isUnsafe(r.Method) &&
			strings.HasPrefix(r.URL.Path, "/api/") && !viewerWriteAllowed[r.URL.Path] {
			http.Error(w, `{"error":"read-only viewer account"}`, http.StatusForbidden)
			return
		}
		ctx := context.WithValue(r.Context(), userKey, u)
		next(w, r.WithContext(ctx))
	}
}

func (s *Service) RequireRole(role models.Role, next http.HandlerFunc) http.HandlerFunc {
	return s.RequireAuth(func(w http.ResponseWriter, r *http.Request) {
		u, _ := UserFrom(r.Context())
		if u == nil || u.Role != role {
			http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
			return
		}
		next(w, r)
	})
}

func (s *Service) RequireAnyRole(next http.HandlerFunc, roles ...models.Role) http.HandlerFunc {
	return s.RequireAuth(func(w http.ResponseWriter, r *http.Request) {
		u, _ := UserFrom(r.Context())
		if u != nil {
			for _, role := range roles {
				if u.Role == role {
					next(w, r)
					return
				}
			}
		}
		http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
	})
}

func isUnsafe(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	default:
		return true
	}
}
