package mailer

import (
	"crypto/tls"
	"fmt"
	"net/smtp"
	"strings"
	"time"
)

type SMTP struct {
	host string
	port string
	user string
	pass string
	from string
}

func NewSMTP(host, port, user, pass, from string) *SMTP {
	host = strings.TrimSpace(host)
	if host == "" {
		return nil
	}
	if port == "" {
		port = "587"
	}
	if from == "" {
		from = user
	}
	return &SMTP{host: host, port: port, user: user, pass: pass, from: from}
}

func (s *SMTP) Recent(n int) []Message { return nil }

func (s *SMTP) Send(m Message) error {
	addr := s.host + ":" + s.port
	body := m.Body
	if m.Link != "" && !strings.Contains(body, m.Link) {
		body += "\r\n\r\n" + m.Link
	}
	msg := []byte(fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\nDate: %s\r\n\r\n%s\r\n",
		s.from, m.To, m.Subject, time.Now().UTC().Format(time.RFC1123Z), body))

	var auth smtp.Auth
	if s.user != "" {
		auth = &loginAuth{username: s.user, password: s.pass}
	}

	if s.port == "465" {
		return s.sendImplicitTLS(addr, auth, m.To, msg)
	}
	return smtp.SendMail(addr, auth, s.from, []string{m.To}, msg)
}

func (s *SMTP) sendImplicitTLS(addr string, auth smtp.Auth, to string, msg []byte) error {
	conn, err := tls.Dial("tcp", addr, &tls.Config{ServerName: s.host})
	if err != nil {
		return err
	}
	c, err := smtp.NewClient(conn, s.host)
	if err != nil {
		return err
	}
	defer c.Close()
	if auth != nil {
		if err := c.Auth(auth); err != nil {
			return err
		}
	}
	if err := c.Mail(s.from); err != nil {
		return err
	}
	if err := c.Rcpt(to); err != nil {
		return err
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(msg); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

type loginAuth struct{ username, password string }

func (a *loginAuth) Start(_ *smtp.ServerInfo) (string, []byte, error) { return "LOGIN", nil, nil }

func (a *loginAuth) Next(fromServer []byte, more bool) ([]byte, error) {
	if !more {
		return nil, nil
	}
	switch strings.ToLower(strings.TrimSpace(string(fromServer))) {
	case "username:":
		return []byte(a.username), nil
	case "password:":
		return []byte(a.password), nil
	default:
		return nil, fmt.Errorf("mailer: beklenmeyen sunucu sorgusu %q", fromServer)
	}
}
