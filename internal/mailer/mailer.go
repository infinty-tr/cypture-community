package mailer

import (
	"log/slog"
	"sync"
	"time"
)

type Message struct {
	To        string
	Subject   string
	Body      string
	Link      string
	CreatedAt time.Time
}

type Mailer interface {
	Send(m Message) error

	Recent(n int) []Message
}

type Stub struct {
	mu   sync.Mutex
	sent []Message
}

func NewStub() *Stub { return &Stub{} }

func (s *Stub) Send(m Message) error {
	m.CreatedAt = time.Now()
	s.mu.Lock()
	s.sent = append(s.sent, m)
	if len(s.sent) > 50 {
		s.sent = s.sent[len(s.sent)-50:]
	}
	s.mu.Unlock()
	slog.Info("EMAIL (stub) — not actually sent",
		"to", m.To, "subject", m.Subject, "link", m.Link)
	return nil
}

func (s *Stub) Recent(n int) []Message {
	s.mu.Lock()
	defer s.mu.Unlock()
	if n <= 0 || n > len(s.sent) {
		n = len(s.sent)
	}
	out := make([]Message, n)
	copy(out, s.sent[len(s.sent)-n:])
	return out
}
