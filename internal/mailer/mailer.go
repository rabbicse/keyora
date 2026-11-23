// Package mailer delivers transactional email using only the standard library.
package mailer

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/smtp"
	"strings"
	"sync"
	"time"
)

type Message struct {
	To      string
	Subject string
	Body    string
}

type Mailer interface {
	Send(ctx context.Context, m Message) error
}

// Log writes messages to the log instead of sending them. It exists for local
// development: the body contains live verification and reset tokens, so it
// must never be used in production.
type Log struct{ Logger *slog.Logger }

func (l Log) Send(_ context.Context, m Message) error {
	l.Logger.Warn("email not sent (log mailer, development only)", "to", m.To, "subject", m.Subject, "body", m.Body)
	return nil
}

// SMTP sends mail through a relay with STARTTLS when the server offers it.
type SMTP struct {
	Host     string
	Port     string
	Username string
	Password string
	From     string
}

func (s SMTP) Send(_ context.Context, m Message) error {
	if strings.ContainsAny(m.To+m.Subject, "\r\n") {
		return fmt.Errorf("mailer: header injection attempt")
	}
	var auth smtp.Auth
	if s.Username != "" {
		auth = smtp.PlainAuth("", s.Username, s.Password, s.Host)
	}
	msg := "From: " + s.From + "\r\nTo: " + m.To + "\r\nSubject: " + m.Subject +
		"\r\nDate: " + time.Now().UTC().Format(time.RFC1123Z) +
		"\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n" +
		strings.ReplaceAll(m.Body, "\n", "\r\n") + "\r\n"
	return smtp.SendMail(net.JoinHostPort(s.Host, s.Port), auth, s.From, []string{m.To}, []byte(msg))
}

// Recorder keeps messages in memory for tests.
type Recorder struct {
	mu       sync.Mutex
	Messages []Message
}

func (r *Recorder) Send(_ context.Context, m Message) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Messages = append(r.Messages, m)
	return nil
}

// Last returns the most recent message sent to an address.
func (r *Recorder) Last(to string) (Message, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := len(r.Messages) - 1; i >= 0; i-- {
		if r.Messages[i].To == to {
			return r.Messages[i], true
		}
	}
	return Message{}, false
}
