// Copyright 2026 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package db

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/k8shell-io/common/pkg/models"
)

// AnnouncementEmailCandidate is a user eligible, by targeting alone, to be
// emailed a given announcement — see ListAnnouncementEmailCandidates. It
// deliberately carries only what the mailer needs to send and doesn't
// duplicate the full User model.
type AnnouncementEmailCandidate struct {
	Username string
	Email    string
}

// ListEmailEligibleAnnouncements returns announcements currently eligible to
// be emailed: active, email_enabled, and within their validity period
// (starts_at/ends_at, same bounds as ListUnreadAnnouncements). Ordered by
// activation order (starts_at, falling back to created_at when starts_at is
// unset) so that, when a daily recipient cap holds back some candidates, the
// oldest-activated announcements are processed first, tick after tick.
// Callers are still responsible for their own day/send-hour gating (see
// Server.sendEligibleAnnouncementEmails) — this only filters on what's
// stored, not on today's date.
func (d *DB) ListEmailEligibleAnnouncements() ([]*models.Announcement, error) {
	rows, err := d.Pool.Query(context.Background(),
		`SELECT `+announcementBaseColumns+`, `+announcementTranslationsExpr+`
		 FROM identity.announcements a
		 WHERE a.active
		   AND a.email_enabled
		   AND (a.starts_at IS NULL OR a.starts_at <= now())
		   AND (a.ends_at   IS NULL OR a.ends_at   >= now())
		 ORDER BY COALESCE(a.starts_at, a.created_at)`,
	)
	if err != nil {
		return nil, fmt.Errorf("list email eligible announcements: %w", err)
	}
	defer rows.Close()

	var list []*models.Announcement
	for rows.Next() {
		a, err := scanAnnouncementRow(rows)
		if err != nil {
			return nil, fmt.Errorf("list email eligible announcements: %w", err)
		}
		list = append(list, a)
	}
	return list, rows.Err()
}

// ListAnnouncementEmailCandidates returns users matching an announcement's
// org/role targeting (same empty-means-everyone semantics as
// ListUnreadAnnouncements) who have an on-file email, are not disabled
// (is_valid), and have not already been sent this announcement's email (see
// identity.announcement_email_sends). It does not check the recipient's own
// announcementsByEmail opt-in or resolve a translation for their language —
// both live in the opaque user_settings blob and are checked by the caller
// per candidate (see Server.sendAnnouncementEmailToCandidate) rather than
// parsed in SQL.
func (d *DB) ListAnnouncementEmailCandidates(announcementID int32, orgs, roles []string) ([]*AnnouncementEmailCandidate, error) {
	rows, err := d.Pool.Query(context.Background(),
		`SELECT u.username, u.email
		 FROM identity.users u
		 WHERE u.is_valid
		   AND u.email IS NOT NULL AND u.email <> ''
		   AND ($1::varchar[] = '{}' OR u.organization = ANY($1))
		   AND ($2::varchar[] = '{}' OR u.roles && $2::varchar[])
		   AND NOT EXISTS (
		       SELECT 1 FROM identity.announcement_email_sends e
		       WHERE e.announcement_id = $3 AND e.username = u.username
		   )
		 ORDER BY u.username`,
		nonNilOrgs(orgs), nonNilRoles(roles), announcementID,
	)
	if err != nil {
		return nil, fmt.Errorf("list announcement email candidates: %w", err)
	}
	defer rows.Close()

	var list []*AnnouncementEmailCandidate
	for rows.Next() {
		var c AnnouncementEmailCandidate
		if err := rows.Scan(&c.Username, &c.Email); err != nil {
			return nil, fmt.Errorf("list announcement email candidates: %w", err)
		}
		list = append(list, &c)
	}
	return list, rows.Err()
}

// ClaimAnnouncementEmailSend atomically claims the right to send
// announcementID's email to username by inserting into
// identity.announcement_email_sends. Returns claimed=false when a row
// already exists — this or another replica/tick already sent it (or is
// mid-send) — which the caller must treat as "do not send". The insert's
// PRIMARY KEY is what makes this safe under concurrent ticks/replicas
// without any additional locking. Callers that fail to actually send after
// claiming must call UnclaimAnnouncementEmailSend so a later tick retries.
func (d *DB) ClaimAnnouncementEmailSend(announcementID int32, username string) (claimed bool, err error) {
	tag, err := d.Pool.Exec(context.Background(),
		`INSERT INTO identity.announcement_email_sends (announcement_id, username)
		 VALUES ($1, $2)
		 ON CONFLICT (announcement_id, username) DO NOTHING`,
		announcementID, username,
	)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23503" {
			return false, fmt.Errorf("%w: announcement %d or user %q does not exist", models.ErrInvalidParameters, announcementID, username)
		}
		return false, fmt.Errorf("claim announcement email send: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// UnclaimAnnouncementEmailSend removes a claim taken by
// ClaimAnnouncementEmailSend after the send itself failed, so a later tick
// retries this (announcement, user) pair instead of silently skipping it
// forever. Best-effort: called from an already-failed-send path, so a
// failure here is logged by the caller rather than propagated further.
func (d *DB) UnclaimAnnouncementEmailSend(announcementID int32, username string) error {
	_, err := d.Pool.Exec(context.Background(),
		`DELETE FROM identity.announcement_email_sends WHERE announcement_id = $1 AND username = $2`,
		announcementID, username,
	)
	if err != nil {
		return fmt.Errorf("unclaim announcement email send: %w", err)
	}
	return nil
}
