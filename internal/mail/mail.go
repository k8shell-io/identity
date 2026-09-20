// Copyright 2026 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package mail sends transactional email (password-reset links and platform
// announcements) via a configured SMTP relay.
package mail

import (
	"bytes"
	"fmt"
	"net/smtp"

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
