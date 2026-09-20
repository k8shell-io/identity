// Copyright 2026 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package db

import (
	"context"
	"fmt"
	"time"
)

// RecordMailSend appends a row to identity.mail_sends, the rolling-24h
// recipient-rate ledger shared by every outbound mail path (password-reset
// and announcement). Callers must only call this after a send has actually
// succeeded — a failed attempt never consumed the relay's quota and must
// not be counted (see CountMailSendsSince).
func (d *DB) RecordMailSend(kind, recipient string) error {
	_, err := d.Pool.Exec(context.Background(),
		`INSERT INTO identity.mail_sends (kind, recipient) VALUES ($1, $2)`,
		kind, recipient,
	)
	if err != nil {
		return fmt.Errorf("record mail send: %w", err)
	}
	return nil
}

// CountMailSendsSince returns the number of identity.mail_sends rows with
// sent_at after since, across every mail kind — the rolling-window count
// MailRateLimitConfig.DailyRecipientCap is checked against.
func (d *DB) CountMailSendsSince(since time.Time) (int, error) {
	var count int
	err := d.Pool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM identity.mail_sends WHERE sent_at > $1`, since,
	).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count mail sends: %w", err)
	}
	return count, nil
}
