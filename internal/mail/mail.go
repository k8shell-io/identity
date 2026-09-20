// Copyright 2026 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package mail sends transactional email (currently just password-reset
// links) via a configured SMTP relay.
package mail

import (
	"fmt"
	"net/smtp"
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
	if cfg.Host == "" {
		return fmt.Errorf("smtp: host not configured")
	}

	subject := "Reset your k8Shell password"
	body := fmt.Sprintf(
		"A password reset was requested for your k8Shell account.\r\n\r\n"+
			"Reset your password: %s\r\n\r\n"+
			"If you did not request this, you can safely ignore this email.\r\n",
		confirmURL)
	msg := []byte(fmt.Sprintf(
		"From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=\"UTF-8\"\r\n\r\n%s",
		cfg.From, to, subject, body))

	var auth smtp.Auth
	if cfg.Username != "" {
		auth = smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)
	}

	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	return smtp.SendMail(addr, auth, cfg.From, []string{to}, msg)
}
