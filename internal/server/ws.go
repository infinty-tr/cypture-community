package server

import (
	"net/http"
	"sync"

	"github.com/gorilla/websocket"
)

type Hub struct {
	mu   sync.RWMutex
	subs map[string]map[*wsConn]struct{}
}

type wsConn struct {
	ws   *websocket.Conn
	send chan []byte
}

func NewHub() *Hub {
	return &Hub{subs: make(map[string]map[*wsConn]struct{})}
}

func (h *Hub) add(scanID string, c *wsConn) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.subs[scanID] == nil {
		h.subs[scanID] = make(map[*wsConn]struct{})
	}
	h.subs[scanID][c] = struct{}{}
}

func (h *Hub) remove(scanID string, c *wsConn) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if set := h.subs[scanID]; set != nil {
		delete(set, c)
		if len(set) == 0 {
			delete(h.subs, scanID)
		}
	}
}

func (h *Hub) Subscribers(scanID string) int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.subs[scanID])
}

func (h *Hub) Broadcast(scanID string, payload []byte) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for c := range h.subs[scanID] {
		select {
		case c.send <- payload:
		default:
		}
	}
}

func (s *Server) upgrader() websocket.Upgrader {
	return websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 8192,
		CheckOrigin: func(r *http.Request) bool {
			origin := r.Header.Get("Origin")
			if origin == "" {
				return true
			}
			host := r.Host
			return origin == "http://"+host || origin == "https://"+host ||
				origin == s.Cfg.BaseURL
		},
	}
}
