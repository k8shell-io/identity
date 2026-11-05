// Copyright 2026 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package mail sends transactional email (password-reset links and platform
// announcements) via a configured SMTP relay.
package mail

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"strconv"
	"strings"
	"time"

	"github.com/yuin/goldmark"
)

// Config is the minimal SMTP relay configuration needed to send mail.
type Config struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
}

// SendPasswordResetEmail sends a password-reset confirmation link to to.
// Returns an error when cfg.Host is empty (SMTP not configured) or the send
// itself fails; callers are expected to log-and-swallow per
// RequestPasswordReset's contract.
func SendPasswordResetEmail(cfg Config, to, confirmURL string) error {
	subject := "Reset your k8Shell password"
	body := fmt.Sprintf(
		"A password reset was requested for your k8Shell account.\r\n\r\n"+
			"Reset your password: %s\r\n\r\n"+
			"If you did not request this, you can safely ignore this email.\r\n",
		confirmURL)
	return send(cfg, to, subject, body, "text/plain")
}

// SendAnnouncementEmail sends a platform announcement's translated body
// (markdown, per Announcement.Translations) to to, rendered to HTML.
// subject is caller-supplied — an announcement has no user-facing title of
// its own (Announcement.Name is an admin-only label, never shown to end
// users), so callers should pass a generic subject rather than Name.
// Returns an error when cfg.Host is empty (SMTP not configured), the
// markdown fails to render, or the send itself fails; callers are expected
// to treat a failure as "not sent" and retry on a later tick rather than
// swallowing it permanently.
func SendAnnouncementEmail(cfg Config, to, subject, markdownBody string) error {
	var html bytes.Buffer
	if err := goldmark.Convert([]byte(markdownBody), &html); err != nil {
		return fmt.Errorf("render announcement markdown: %w", err)
	}
	return send(cfg, to, subject, html.String(), "text/html")
}

// SendNotificationEmail sends a one-off plain-text notification to to. Both
// subject and body are caller-supplied (NotifyUser), so the subject is
// stripped of CR/LF to prevent header injection, and the body's line endings
// are normalised to CRLF as SMTP requires.
//
// It returns the relay's final reply to the message (e.g. Gmail's
// "2.0.0 OK <queue-id> - gsmtp"), which is the only handle for tracing the
// message on the relay side. Errors name the SMTP step that failed.
// Returns an error when cfg.Host is empty or the send itself fails.
func SendNotificationEmail(cfg Config, to, subject, body string) (string, error) {
	subject = strings.NewReplacer("\r", " ", "\n", " ").Replace(subject)
	body = strings.ReplaceAll(strings.ReplaceAll(body, "\r\n", "\n"), "\n", "\r\n")
	return sendTraced(cfg, to, subject, body, "text/plain")
}

// smtpTimeout bounds a whole traced SMTP conversation.
const smtpTimeout = 60 * time.Second

// sendTraced is send() with the SMTP conversation driven step by step
// instead of through smtp.SendMail, so a failure is attributed to a step
// (dial, starttls, auth, mail from, rcpt to, data) and the server's reply to
// the DATA command is returned on success.
func sendTraced(cfg Config, to, subject, body, contentType string) (string, error) {
	if cfg.Host == "" {
		return "", fmt.Errorf("smtp: host not configured")
	}
	msg := fmt.Sprintf(
		"From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: %s; charset=\"UTF-8\"\r\n\r\n%s",
		cfg.From, to, subject, contentType, body)

	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))
	conn, err := net.DialTimeout("tcp", addr, 15*time.Second)
	if err != nil {
		return "", fmt.Errorf("smtp dial %s: %w", addr, err)
	}
	_ = conn.SetDeadline(time.Now().Add(smtpTimeout))

	c, err := smtp.NewClient(conn, cfg.Host)
	if err != nil {
		conn.Close()
		return "", fmt.Errorf("smtp greeting from %s: %w", addr, err)
	}
	defer c.Close()

	if err := c.Hello("localhost"); err != nil {
		return "", fmt.Errorf("smtp ehlo: %w", err)
	}
	if ok, _ := c.Extension("STARTTLS"); ok {
		if err := c.StartTLS(&tls.Config{ServerName: cfg.Host}); err != nil {
			return "", fmt.Errorf("smtp starttls: %w", err)
		}
	}
	if cfg.Username != "" {
		if err := c.Auth(smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)); err != nil {
			return "", fmt.Errorf("smtp auth: %w", err)
		}
	}
	if err := c.Mail(cfg.From); err != nil {
		return "", fmt.Errorf("smtp mail from <%s>: %w", cfg.From, err)
	}
	if err := c.Rcpt(to); err != nil {
		return "", fmt.Errorf("smtp rcpt to: %w", err)
	}

	// DATA is driven by hand because smtp.Client.Data's writer discards the
	// server's final reply, which carries the relay's queue id.
	id, err := c.Text.Cmd("DATA")
	if err != nil {
		return "", fmt.Errorf("smtp data: %w", err)
	}
	c.Text.StartResponse(id)
	_, _, err = c.Text.ReadResponse(354)
	c.Text.EndResponse(id)
	if err != nil {
		return "", fmt.Errorf("smtp data: %w", err)
	}
	w := c.Text.DotWriter()
	if _, err := w.Write([]byte(msg)); err != nil {
		return "", fmt.Errorf("smtp data body: %w", err)
	}
	if err := w.Close(); err != nil {
		return "", fmt.Errorf("smtp data end: %w", err)
	}
	_, reply, err := c.Text.ReadResponse(250)
	if err != nil {
		return "", fmt.Errorf("smtp message rejected: %w", err)
	}
	_ = c.Quit()
	return reply, nil
}

// send builds a MIME message of the given contentType (e.g. "text/plain" or
// "text/html") and hands it to net/smtp, the common path shared by every
// mail this package sends.
func send(cfg Config, to, subject, body, contentType string) error {
	if cfg.Host == "" {
		return fmt.Errorf("smtp: host not configured")
	}

	msg := []byte(fmt.Sprintf(
		"From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: %s; charset=\"UTF-8\"\r\n\r\n%s",
		cfg.From, to, subject, contentType, body))

	var auth smtp.Auth
	if cfg.Username != "" {
		auth = smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)
	}

	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	return smtp.SendMail(addr, auth, cfg.From, []string{to}, msg)
}
