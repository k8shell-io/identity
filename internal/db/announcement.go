// Copyright 2026 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package db

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/k8shell-io/common/pkg/db"
	"github.com/k8shell-io/common/pkg/models"
)

// ErrAnnouncementNotFound is returned when no announcement with the given id
// exists.
var ErrAnnouncementNotFound = errors.New("announcement not found")

const announcementColumns = `id, title, body, created_by, orgs, starts_at, ends_at, created_at, updated_at`

func scanAnnouncement(row pgx.Row) (*models.Announcement, error) {
	var a models.Announcement
	if err := row.Scan(&a.ID, &a.Title, &a.Body, &a.CreatedBy, &a.Orgs, &a.StartsAt, &a.EndsAt, &a.CreatedAt, &a.UpdatedAt); err != nil {
		return nil, err
	}
	return &a, nil
}

// nonNilOrgs coalesces a nil orgs slice to an empty (non-nil) one. pgx
// encodes a nil Go slice as SQL NULL rather than an empty array, which
// would violate identity.announcements.orgs' NOT NULL constraint whenever a
// caller creates/updates a global announcement (no orgs at all).
func nonNilOrgs(orgs []string) []string {
	if orgs == nil {
		return []string{}
	}
	return orgs
}

// validateAnnouncementOrgs returns models.ErrInvalidParameters naming any
// org in orgs that doesn't exist in identity.organizations. orgs has no
// per-element foreign key (Postgres arrays don't support one), so existence
// is checked here instead — the same precedent as onboard_rules.roles being
// validated at the application layer against identity.roles.
func (d *DB) validateAnnouncementOrgs(orgs []string) error {
	if len(orgs) == 0 {
		return nil
	}
	rows, err := d.Pool.Query(context.Background(),
		`SELECT name FROM identity.organizations WHERE name = ANY($1)`, orgs)
	if err != nil {
		return fmt.Errorf("validate announcement orgs: %w", err)
	}
	defer rows.Close()

	found := make(map[string]bool, len(orgs))
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return fmt.Errorf("validate announcement orgs: %w", err)
		}
		found[name] = true
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("validate announcement orgs: %w", err)
	}

	var missing []string
	for _, org := range orgs {
		if !found[org] {
			missing = append(missing, org)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("%w: organization(s) do not exist: %s", models.ErrInvalidParameters, strings.Join(missing, ", "))
	}
	return nil
}

// CreateAnnouncement creates a new announcement. It is global when a.Orgs is
// empty, otherwise scoped to the listed organizations — each of which must
// already exist (see validateAnnouncementOrgs). Returns
// models.ErrInvalidParameters if any named org doesn't exist, or if
// a.StartsAt is after a.EndsAt.
func (d *DB) CreateAnnouncement(a *models.Announcement) (*models.Announcement, error) {
	if err := d.validateAnnouncementOrgs(a.Orgs); err != nil {
		return nil, err
	}

	row := d.Pool.QueryRow(context.Background(),
		`INSERT INTO identity.announcements (title, body, created_by, orgs, starts_at, ends_at)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 RETURNING `+announcementColumns,
		a.Title, a.Body, a.CreatedBy, nonNilOrgs(a.Orgs), a.StartsAt, a.EndsAt,
	)
	created, err := scanAnnouncement(row)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23514" && pgErr.ConstraintName == "chk_announcement_period" {
			return nil, fmt.Errorf("%w: starts_at must be before ends_at", models.ErrInvalidParameters)
		}
		return nil, fmt.Errorf("insert announcement: %w", err)
	}
	return created, nil
}

// GetAnnouncement retrieves a single announcement by id, with ReadCount
// populated (the number of distinct users who have read it). Returns
// ErrAnnouncementNotFound when no announcement with that id exists.
func (d *DB) GetAnnouncement(id int32) (*models.Announcement, error) {
	row := d.Pool.QueryRow(context.Background(),
		`SELECT a.id, a.title, a.body, a.created_by, a.orgs, a.starts_at, a.ends_at, a.created_at, a.updated_at,
		        (SELECT COUNT(*) FROM identity.announcement_reads r WHERE r.announcement_id = a.id)
		 FROM identity.announcements a
		 WHERE a.id = $1`,
		id,
	)
	var a models.Announcement
	err := row.Scan(&a.ID, &a.Title, &a.Body, &a.CreatedBy, &a.Orgs, &a.StartsAt, &a.EndsAt, &a.CreatedAt, &a.UpdatedAt, &a.ReadCount)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("%w: id %d", ErrAnnouncementNotFound, id)
	}
	if err != nil {
		return nil, fmt.Errorf("get announcement: %w", err)
	}
	return &a, nil
}

// UpdateAnnouncement partially updates an announcement identified by id — a
// nil title/body leaves that field unchanged. Because a nil orgs/startsAt/
// endsAt is ambiguous between "leave unchanged" and "clear", clearOrgs/
// clearStartsAt/clearEndsAt make the intent explicit: clearOrgs makes the
// announcement global (orgs must be empty when set), clearStartsAt/
// clearEndsAt remove that bound (open-ended) — set at most one of a bound
// and its own clear flag. Returns ErrAnnouncementNotFound when no
// announcement with that id exists, or models.ErrInvalidParameters if any
// named org doesn't exist or the resulting period is invalid.
func (d *DB) UpdateAnnouncement(id int32, title, body *string, orgs []string, clearOrgs bool,
	startsAt *time.Time, clearStartsAt bool, endsAt *time.Time, clearEndsAt bool) (*models.Announcement, error) {
	if len(orgs) > 0 {
		if err := d.validateAnnouncementOrgs(orgs); err != nil {
			return nil, err
		}
	}
	orgsChanged := len(orgs) > 0 || clearOrgs
	startsAtChanged := startsAt != nil || clearStartsAt
	endsAtChanged := endsAt != nil || clearEndsAt

	row := d.Pool.QueryRow(context.Background(),
		`UPDATE identity.announcements SET
		   title      = COALESCE($2, title),
		   body       = COALESCE($3, body),
		   orgs       = CASE WHEN $4 THEN $5::varchar[]     ELSE orgs      END,
		   starts_at  = CASE WHEN $6 THEN $7::timestamptz   ELSE starts_at END,
		   ends_at    = CASE WHEN $8 THEN $9::timestamptz   ELSE ends_at   END,
		   updated_at = now()
		 WHERE id = $1
		 RETURNING `+announcementColumns,
		id, title, body, orgsChanged, nonNilOrgs(orgs), startsAtChanged, startsAt, endsAtChanged, endsAt,
	)
	updated, err := scanAnnouncement(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("%w: id %d", ErrAnnouncementNotFound, id)
	}
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23514" && pgErr.ConstraintName == "chk_announcement_period" {
			return nil, fmt.Errorf("%w: starts_at must be before ends_at", models.ErrInvalidParameters)
		}
		return nil, fmt.Errorf("update announcement: %w", err)
	}
	return updated, nil
}

// DeleteAnnouncement permanently removes an announcement, cascading its
// announcement_reads. Returns ErrAnnouncementNotFound when no announcement
// with that id exists.
func (d *DB) DeleteAnnouncement(id int32) error {
	result, err := d.Pool.Exec(context.Background(), `DELETE FROM identity.announcements WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete announcement: %w", err)
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("%w: id %d", ErrAnnouncementNotFound, id)
	}
	return nil
}

// ListAnnouncements returns announcements for administration, newest first:
// every announcement when org is empty, otherwise only those that apply to
// org (global ones plus any scoped to it). Each entry's ReadCount is
// populated. Unlike ListUnreadAnnouncements/ListUserAnnouncements this is
// not scoped to a requesting user and is not filtered by validity period.
func (d *DB) ListAnnouncements(org string, limit, offset int) ([]*models.Announcement, error) {
	limit, offset = db.AdjustListLimit(limit, offset)

	sqlQuery := `SELECT a.id, a.title, a.body, a.created_by, a.orgs, a.starts_at, a.ends_at, a.created_at, a.updated_at,
		        (SELECT COUNT(*) FROM identity.announcement_reads r WHERE r.announcement_id = a.id)
		 FROM identity.announcements a`

	var args []any
	if org != "" {
		args = append(args, org)
		sqlQuery += fmt.Sprintf(" WHERE a.orgs = '{}' OR $%d = ANY(a.orgs)", len(args))
	}
	sqlQuery += " ORDER BY a.created_at DESC"
	args = append(args, limit, offset)
	sqlQuery += fmt.Sprintf(" LIMIT $%d OFFSET $%d", len(args)-1, len(args))

	rows, err := d.Pool.Query(context.Background(), sqlQuery, args...)
	if err != nil {
		return nil, fmt.Errorf("list announcements: %w", err)
	}
	defer rows.Close()

	var list []*models.Announcement
	for rows.Next() {
		var a models.Announcement
		if err := rows.Scan(&a.ID, &a.Title, &a.Body, &a.CreatedBy, &a.Orgs, &a.StartsAt, &a.EndsAt, &a.CreatedAt, &a.UpdatedAt, &a.ReadCount); err != nil {
			return nil, fmt.Errorf("list announcements: %w", err)
		}
		list = append(list, &a)
	}
	return list, rows.Err()
}

// ListUnreadAnnouncements returns announcements that apply to org (global or
// scoped to it), currently fall within their validity period, and that
// username has not yet read (see identity.announcement_reads). An
// announcement outside its validity period is excluded here even when
// unread — use ListUserAnnouncements to retrieve it regardless.
func (d *DB) ListUnreadAnnouncements(username, org string) ([]*models.Announcement, error) {
	rows, err := d.Pool.Query(context.Background(),
		`SELECT a.id, a.title, a.body, a.created_by, a.orgs, a.starts_at, a.ends_at, a.created_at, a.updated_at
		 FROM identity.announcements a
		 WHERE (a.orgs = '{}' OR $1 = ANY(a.orgs))
		   AND (a.starts_at IS NULL OR a.starts_at <= now())
		   AND (a.ends_at   IS NULL OR a.ends_at   >= now())
		   AND NOT EXISTS (
		       SELECT 1 FROM identity.announcement_reads r
		       WHERE r.announcement_id = a.id AND r.username = $2
		   )
		 ORDER BY a.created_at DESC`,
		org, username,
	)
	if err != nil {
		return nil, fmt.Errorf("list unread announcements: %w", err)
	}
	defer rows.Close()

	var list []*models.Announcement
	for rows.Next() {
		a, err := scanAnnouncement(rows)
		if err != nil {
			return nil, fmt.Errorf("list unread announcements: %w", err)
		}
		list = append(list, a)
	}
	return list, rows.Err()
}

// ListUserAnnouncements returns every announcement that applies to org
// (global or scoped to it), regardless of validity period or read status,
// with IsRead/ReadAt populated per announcement from
// identity.announcement_reads — unlike ListUnreadAnnouncements, this
// includes announcements already read or outside their validity period.
func (d *DB) ListUserAnnouncements(username, org string) ([]*models.Announcement, error) {
	rows, err := d.Pool.Query(context.Background(),
		`SELECT a.id, a.title, a.body, a.created_by, a.orgs, a.starts_at, a.ends_at, a.created_at, a.updated_at,
		        r.read_at IS NOT NULL, r.read_at
		 FROM identity.announcements a
		 LEFT JOIN identity.announcement_reads r ON r.announcement_id = a.id AND r.username = $2
		 WHERE (a.orgs = '{}' OR $1 = ANY(a.orgs))
		 ORDER BY a.created_at DESC`,
		org, username,
	)
	if err != nil {
		return nil, fmt.Errorf("list user announcements: %w", err)
	}
	defer rows.Close()

	var list []*models.Announcement
	for rows.Next() {
		var a models.Announcement
		if err := rows.Scan(&a.ID, &a.Title, &a.Body, &a.CreatedBy, &a.Orgs, &a.StartsAt, &a.EndsAt, &a.CreatedAt, &a.UpdatedAt,
			&a.IsRead, &a.ReadAt); err != nil {
			return nil, fmt.Errorf("list user announcements: %w", err)
		}
		list = append(list, &a)
	}
	return list, rows.Err()
}

// MarkAnnouncementRead records that username has read announcement id.
// Idempotent — marking an already-read announcement again leaves its
// original read_at unchanged. Returns ErrAnnouncementNotFound when no
// announcement with that id exists, or models.ErrInvalidParameters when
// username does not exist.
func (d *DB) MarkAnnouncementRead(id int32, username string) error {
	_, err := d.Pool.Exec(context.Background(),
		`INSERT INTO identity.announcement_reads (announcement_id, username)
		 VALUES ($1, $2)
		 ON CONFLICT (announcement_id, username) DO NOTHING`,
		id, username,
	)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23503" {
			switch pgErr.ConstraintName {
			case "announcement_reads_announcement_id_fkey":
				return fmt.Errorf("%w: id %d", ErrAnnouncementNotFound, id)
			case "announcement_reads_username_fkey":
				return fmt.Errorf("%w: user %q does not exist", models.ErrInvalidParameters, username)
			}
		}
		return fmt.Errorf("mark announcement read: %w", err)
	}
	return nil
}
