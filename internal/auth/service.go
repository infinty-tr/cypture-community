package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"gorm.io/gorm"

	"cypture/internal/config"
	"cypture/internal/models"
)

const (
	SessionCookie = "cyp_session"
	CSRFCookie    = "cyp_csrf"
	CSRFHeader    = "X-CSRF-Token"

	sessionTTL   = 12 * time.Hour
	maxFailed    = 5
	lockDuration = 15 * time.Minute
	tokenEntropy = 32
)

var (
	ErrInvalidCreds = errors.New("invalid credentials")
	ErrLocked       = errors.New("account temporarily locked")
	ErrDisabled     = errors.New("account disabled")
	ErrEmailTaken   = errors.New("email already registered")
	ErrWeakInput    = errors.New("invalid email or weak password")
	ErrUnverified   = errors.New("email not verified")
)

var emailRe = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)

const minPasswordLen = 8

type Service struct {
	db     *gorm.DB
	cfg    *config.Config
	rlMu   sync.Mutex
	rlHits map[string][]time.Time
}

func NewService(db *gorm.DB, cfg *config.Config) *Service {
	return &Service{db: db, cfg: cfg, rlHits: make(map[string][]time.Time)}
}

func hashToken(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(sum[:])
}

func (s *Service) csrfFor(sessionToken string) string {
	mac := hmac.New(sha256.New, s.cfg.SessionSecret)
	mac.Write([]byte("csrf:" + sessionToken))
	return hex.EncodeToString(mac.Sum(nil))
}

func (s *Service) throttle(ip string) bool {
	s.rlMu.Lock()
	defer s.rlMu.Unlock()
	now := time.Now()
	win := now.Add(-1 * time.Minute)
	hits := s.rlHits[ip][:0:0]
	for _, t := range s.rlHits[ip] {
		if t.After(win) {
			hits = append(hits, t)
		}
	}
	if len(hits) >= 10 {
		s.rlHits[ip] = hits
		return false
	}
	s.rlHits[ip] = append(hits, now)
	return true
}

func (s *Service) Login(email, password, ip, ua string) (sessionToken, csrf string, user *models.User, err error) {
	if !s.throttle(ip) {
		return "", "", nil, ErrLocked
	}
	email = strings.ToLower(strings.TrimSpace(email))

	var u models.User
	res := s.db.Where("email = ?", email).First(&u)
	if res.Error != nil {

		_ = VerifyPassword(password, "$argon2id$v=19$m=65536,t=3,p=2$YWFhYWFhYWFhYWFhYWFhYQ$YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE")
		return "", "", nil, ErrInvalidCreds
	}

	if u.LockedUntil != nil && u.LockedUntil.After(time.Now()) {
		return "", "", nil, ErrLocked
	}
	if u.Status == models.UserDisabled {
		return "", "", nil, ErrDisabled
	}

	if !VerifyPassword(password, u.PasswordHash) {
		u.FailedLogins++
		if u.FailedLogins >= maxFailed {
			until := time.Now().Add(lockDuration)
			u.LockedUntil = &until
			u.FailedLogins = 0
		}
		s.db.Model(&u).Updates(map[string]any{"failed_logins": u.FailedLogins, "locked_until": u.LockedUntil})
		return "", "", nil, ErrInvalidCreds
	}

	if !u.EmailVerified {
		return "", "", nil, ErrUnverified
	}

	updates := map[string]any{"failed_logins": 0, "locked_until": nil}
	if u.Status == models.UserInvited {
		updates["status"] = models.UserActive
	}
	s.db.Model(&u).Updates(updates)

	sessionToken = config.RandomToken(tokenEntropy)
	sess := models.AuthSession{
		UserID:    u.ID,
		TokenHash: hashToken(sessionToken),
		ExpiresAt: time.Now().Add(sessionTTL),
		UserAgent: ua,
		IP:        ip,
	}
	if err := s.db.Create(&sess).Error; err != nil {
		return "", "", nil, err
	}
	return sessionToken, s.csrfFor(sessionToken), &u, nil
}

func (s *Service) Register(email, password, company, ip, ua string, requireVerify bool) (sessionToken, csrf, verifyToken string, user *models.User, err error) {
	if !s.throttle(ip) {
		return "", "", "", nil, ErrLocked
	}
	email = strings.ToLower(strings.TrimSpace(email))
	if !emailRe.MatchString(email) || len(email) > 254 || len(password) < minPasswordLen || len(password) > 200 {
		return "", "", "", nil, ErrWeakInput
	}

	hash, err := HashPassword(password)
	if err != nil {
		return "", "", "", nil, err
	}
	u := models.User{
		Email:         email,
		PasswordHash:  hash,
		Role:          models.RoleClient,
		Status:        models.UserActive,
		CompanyName:   strings.TrimSpace(company),
		EmailVerified: !requireVerify,
	}
	if requireVerify {
		verifyToken = config.RandomToken(tokenEntropy)
		exp := time.Now().Add(72 * time.Hour)
		u.InviteTokenHash = hashToken(verifyToken)
		u.InviteExpiresAt = &exp
	}

	if err := s.db.Create(&u).Error; err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			return "", "", "", nil, ErrEmailTaken
		}
		return "", "", "", nil, err
	}

	if requireVerify {

		if err := s.db.Model(&u).Update("email_verified", false).Error; err != nil {
			return "", "", "", nil, err
		}
		u.EmailVerified = false
		return "", "", verifyToken, &u, nil
	}
	sessionToken = config.RandomToken(tokenEntropy)
	sess := models.AuthSession{
		UserID:    u.ID,
		TokenHash: hashToken(sessionToken),
		ExpiresAt: time.Now().Add(sessionTTL),
		UserAgent: ua,
		IP:        ip,
	}
	if err := s.db.Create(&sess).Error; err != nil {
		return "", "", "", nil, err
	}
	return sessionToken, s.csrfFor(sessionToken), "", &u, nil
}

func (s *Service) VerifyEmail(token string) (*models.User, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, ErrInvalidCreds
	}
	var u models.User
	if err := s.db.Where("invite_token_hash = ?", hashToken(token)).First(&u).Error; err != nil {
		return nil, ErrInvalidCreds
	}
	if u.InviteExpiresAt != nil && u.InviteExpiresAt.Before(time.Now()) {
		return nil, ErrInvalidCreds
	}
	s.db.Model(&u).Updates(map[string]any{"email_verified": true, "invite_token_hash": "", "invite_expires_at": nil})
	u.EmailVerified = true
	return &u, nil
}

func (s *Service) Resolve(sessionToken string) (*models.User, error) {
	if sessionToken == "" {
		return nil, ErrInvalidCreds
	}
	var sess models.AuthSession
	if err := s.db.Where("token_hash = ?", hashToken(sessionToken)).First(&sess).Error; err != nil {
		return nil, ErrInvalidCreds
	}
	if sess.ExpiresAt.Before(time.Now()) {
		s.db.Delete(&sess)
		return nil, ErrInvalidCreds
	}
	var u models.User
	if err := s.db.First(&u, "id = ?", sess.UserID).Error; err != nil {
		return nil, ErrInvalidCreds
	}
	if u.Status == models.UserDisabled {
		return nil, ErrDisabled
	}
	return &u, nil
}

func (s *Service) Logout(sessionToken string) {
	if sessionToken == "" {
		return
	}
	s.db.Where("token_hash = ?", hashToken(sessionToken)).Delete(&models.AuthSession{})
}

func (s *Service) SetCookies(w http.ResponseWriter, sessionToken, csrf string) {
	secure := !s.cfg.Dev()
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookie,
		Value:    sessionToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(sessionTTL.Seconds()),
	})

	http.SetCookie(w, &http.Cookie{
		Name:     CSRFCookie,
		Value:    csrf,
		Path:     "/",
		HttpOnly: false,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(sessionTTL.Seconds()),
	})
}

func (s *Service) ClearCookies(w http.ResponseWriter) {
	for _, name := range []string{SessionCookie, CSRFCookie} {
		http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: "/", MaxAge: -1})
	}
}

func (s *Service) ValidCSRF(r *http.Request, sessionToken string) bool {
	got := r.Header.Get(CSRFHeader)
	if got == "" {
		return false
	}
	want := s.csrfFor(sessionToken)
	return hmac.Equal([]byte(got), []byte(want))
}
