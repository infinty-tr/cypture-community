package server

import (
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"

	"github.com/creack/pty"
	"github.com/gorilla/websocket"

	"cypture/internal/auth"
	"cypture/internal/models"
)

var (
	ttyActive    int64
	ttyUserMu    sync.Mutex
	ttyUserCount = map[string]int{}
)

const (
	ttyMaxConcurrent = 32
	ttyMaxPerUser    = 4
)

func ttyAcquireUser(userID string) bool {
	ttyUserMu.Lock()
	defer ttyUserMu.Unlock()
	if ttyUserCount[userID] >= ttyMaxPerUser {
		return false
	}
	ttyUserCount[userID]++
	return true
}

func ttyReleaseUser(userID string) {
	ttyUserMu.Lock()
	defer ttyUserMu.Unlock()
	if ttyUserCount[userID] <= 1 {
		delete(ttyUserCount, userID)
	} else {
		ttyUserCount[userID]--
	}
}

func (s *Server) tuiBinPath() string {
	if s.Cfg.TUIBin != "" {
		return s.Cfg.TUIBin
	}
	if exe, err := os.Executable(); err == nil {
		cand := filepath.Join(filepath.Dir(exe), "cypture-tui")
		if _, e := os.Stat(cand); e == nil {
			return cand
		}
	}
	return "cypture-tui"
}

func (s *Server) handleScanTTY(w http.ResponseWriter, r *http.Request) {
	scanID := r.PathValue("id")

	tok := ""
	if c, err := r.Cookie(auth.SessionCookie); err == nil {
		tok = c.Value
	}
	u, err := s.Auth.Resolve(tok)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var sess models.ScanSession
	if err := s.DB.First(&sess, "id = ?", scanID).Error; err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	var eng models.Engagement
	if err := s.DB.First(&eng, "id = ?", sess.EngagementID).Error; err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if u.Role != models.RoleAdmin && eng.ClientID != u.ID {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	if !ttyAcquireUser(u.ID) {
		http.Error(w, "too many live viewers", http.StatusServiceUnavailable)
		return
	}
	defer ttyReleaseUser(u.ID)
	if atomic.AddInt64(&ttyActive, 1) > ttyMaxConcurrent {
		atomic.AddInt64(&ttyActive, -1)
		http.Error(w, "too many live viewers", http.StatusServiceUnavailable)
		return
	}
	defer atomic.AddInt64(&ttyActive, -1)

	up := s.upgrader()
	ws, err := up.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer ws.Close()

	cmd := exec.Command(s.tuiBinPath(), "--scan", scanID, "--db", s.Cfg.DBPath)

	cmd.Env = append(os.Environ(), "TERM=xterm-256color", "COLORFGBG=15;0")
	ptmx, err := pty.Start(cmd)
	if err != nil {
		_ = ws.WriteMessage(websocket.TextMessage, []byte("\r\nLive terminal is unavailable: the cypture-tui binary is not configured.\r\n"+
			"Build it (go build -o bin/cypture-tui ./cmd/cypture-tui) and set CYPTURE_TUI_BIN to its path.\r\n"+
			"The Cockpit view above shows the full live scan.\r\n"))
		return
	}
	defer func() {
		_ = ptmx.Close()
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		}
	}()
	_ = pty.Setsize(ptmx, &pty.Winsize{Rows: 30, Cols: 100})

	_, _ = ptmx.Write([]byte("\x1b]11;rgb:0707/0909/0a0a\x07"))

	done := make(chan struct{})

	go func() {
		defer close(done)
		buf := make([]byte, 16384)
		for {
			n, rerr := ptmx.Read(buf)
			if n > 0 {
				if werr := ws.WriteMessage(websocket.BinaryMessage, buf[:n]); werr != nil {
					return
				}
			}
			if rerr != nil {
				return
			}
		}
	}()

	go func() {
		for {
			mt, data, rerr := ws.ReadMessage()
			if rerr != nil {
				_ = ptmx.Close()
				if cmd.Process != nil {
					_ = cmd.Process.Kill()
				}
				return
			}
			if mt == websocket.TextMessage {
				var rs struct {
					Cols uint16 `json:"cols"`
					Rows uint16 `json:"rows"`
				}
				if json.Unmarshal(data, &rs) == nil && rs.Cols > 0 && rs.Rows > 0 {
					_ = pty.Setsize(ptmx, &pty.Winsize{Rows: rs.Rows, Cols: rs.Cols})
					continue
				}
			}
			_, _ = ptmx.Write(data)
		}
	}()

	select {
	case <-done:
	case <-r.Context().Done():
	}
}
