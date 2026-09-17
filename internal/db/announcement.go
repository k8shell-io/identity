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

// announcementQuerier is satisfied by both *pgxpool.Pool (d.Pool) and
// pgx.Tx, letting getAnnouncementByID be reused inside CreateAnnouncement/
// UpdateAnnouncement's transaction — to return the row together with the
// translations just written in the same transaction — and standalone by
// GetAnnouncement.
type announcementQuerier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

const announcementBaseColumns = `a.id, a.created_by, a.orgs, a.starts_at, a.ends_at, a.created_at, a.updated_at`

// announcementTranslationsExpr aggregates an announcement's translations as
// three parallel arrays (lang/title/body, all ordered by lang), the same
// array_agg-per-column pattern as OrganizationAdminUsernamesExpr — a
// self-contained correlated subquery per computed field, safe to reference
// from any query selecting from identity.announcements aliased "a".
// zipAnnouncementTranslations reassembles them into
// []models.AnnouncementTranslation in Go.
const announcementTranslationsExpr = `
	COALESCE((SELECT array_agg(t.lang  ORDER BY t.lang) FROM identity.announcement_translations t WHERE t.announcement_id = a.id), ARRAY[]::varchar[]),
	COALESCE((SELECT array_agg(t.title ORDER BY t.lang) FROM identity.announcement_translations t WHERE t.announcement_id = a.id), ARRAY[]::varchar[]),
	COALESCE((SELECT array_agg(t.body  ORDER BY t.lang) FROM identity.announcement_translations t WHERE t.announcement_id = a.id), ARRAY[]::text[])`

func zipAnnouncementTranslations(langs, titles, bodies []string) []models.AnnouncementTranslation {
	out := make([]models.AnnouncementTranslation, len(langs))
	for i := range langs {
		out[i] = models.AnnouncementTranslation{Lang: langs[i], Title: titles[i], Body: bodies[i]}
	}
	return out
}

func scanAnnouncementRow(row pgx.Row) (*models.Announcement, error) {
	var a models.Announcement
	var langs, titles, bodies []string
	if err := row.Scan(&a.ID, &a.CreatedBy, &a.Orgs, &a.StartsAt, &a.EndsAt, &a.CreatedAt, &a.UpdatedAt,
		&langs, &titles, &bodies); err != nil {
		return nil, err
	}
	a.Translations = zipAnnouncementTranslations(langs, titles, bodies)
	return &a, nil
}

// getAnnouncementByID retrieves an announcement (with its translations, no
// ReadCount/IsRead) via q — either d.Pool for a standalone read, or an
// in-flight tx so a caller can read back a row together with writes made
// earlier in the same transaction. Returns ErrAnnouncementNotFound when no
// announcement with that id exists.
func getAnnouncementByID(ctx context.Context, q announcementQuerier, id int32) (*models.Announcement, error) {
	row := q.QueryRow(ctx,
		`SELECT `+announcementBaseColumns+`, `+announcementTranslationsExpr+`
		 FROM identity.announcements a WHERE a.id = $1`, id)
	a, err := scanAnnouncementRow(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("%w: id %d", ErrAnnouncementNotFound, id)
	}
	if err != nil {
		return nil, fmt.Errorf("get announcement: %w", err)
	}
	return a, nil
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

// validateAnnouncementTranslations returns models.ErrInvalidParameters when
// translations is empty, or when any entry has an empty lang/title/body —
// every announcement must be readable in at least one language.
func validateAnnouncementTranslations(translations []models.AnnouncementTranslation) error {
	if len(translations) == 0 {
		return fmt.Errorf("%w: at least one translation is required", models.ErrInvalidParameters)
	}
	for _, t := range translations {
		if t.Lang == "" {
			return fmt.Errorf("%w: translation lang is required", models.ErrInvalidParameters)
		}
		if t.Title == "" {
			return fmt.Errorf("%w: translation title is required (lang=%q)", models.ErrInvalidParameters, t.Lang)
		}
		if t.Body == "" {
			return fmt.Errorf("%w: translation body is required (lang=%q)", models.ErrInvalidParameters, t.Lang)
		}
	}
	return nil
}

// insertAnnouncementTranslations writes translations for announcementID.
// Callers must have already validated translations is non-empty (see
// validateAnnouncementTranslations).
func insertAnnouncementTranslations(ctx context.Context, q announcementQuerier, announcementID int32,
	translations []models.AnnouncementTranslation) error {
	for _, t := range translations {
		_, err := q.Exec(ctx,
			`INSERT INTO identity.announcement_translations (announcement_id, lang, title, body)
			 VALUES ($1, $2, $3, $4)`,
			announcementID, t.Lang, t.Title, t.Body,
		)
		if err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23505" {
				return fmt.Errorf("%w: duplicate translation language %q", models.ErrInvalidParameters, t.Lang)
			}
			return fmt.Errorf("insert announcement translation: %w", err)
		}
	}
	return nil
}

// CreateAnnouncement creates a new announcement with its translations (at
// least one is required). It is global when a.Orgs is empty, otherwise
// scoped to the listed organizations — each of which must already exist
// (see validateAnnouncementOrgs). Returns models.ErrInvalidParameters if
// a.Translations is empty or has an incomplete entry, any named org
// doesn't exist, or a.StartsAt is after a.EndsAt.
func (d *DB) CreateAnnouncement(a *models.Announcement) (*models.Announcement, error) {
	if err := validateAnnouncementTranslations(a.Translations); err != nil {
		return nil, err
	}
	if err := d.validateAnnouncementOrgs(a.Orgs); err != nil {
		return nil, err
	}

	ctx := context.Background()
	tx, err := d.Pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin transaction: %w", err)
	}
	defer func() {
		if err := tx.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			d.log.Error().Err(err).Msg("rollback transaction")
		}
	}()

	var id int32
	err = tx.QueryRow(ctx,
		`INSERT INTO identity.announcements (created_by, orgs, starts_at, ends_at)
		 VALUES ($1, $2, $3, $4)
		 RETURNING id`,
		a.CreatedBy, nonNilOrgs(a.Orgs), a.StartsAt, a.EndsAt,
	).Scan(&id)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23514" && pgErr.ConstraintName == "chk_announcement_period" {
			return nil, fmt.Errorf("%w: starts_at must be before ends_at", models.ErrInvalidParameters)
		}
		return nil, fmt.Errorf("insert announcement: %w", err)
	}

	if err := insertAnnouncementTranslations(ctx, tx, id, a.Translations); err != nil {
		return nil, err
	}

	created, err := getAnnouncementByID(ctx, tx, id)
	if err != nil {
		return nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit transaction: %w", err)
	}
	return created, nil
}

// GetAnnouncement retrieves a single announcement by id, with ReadCount
// populated (the number of distinct users who have read it). Returns
// ErrAnnouncementNotFound when no announcement with that id exists.
func (d *DB) GetAnnouncement(id int32) (*models.Announcement, error) {
	row := d.Pool.QueryRow(context.Background(),
		`SELECT `+announcementBaseColumns+`, `+announcementTranslationsExpr+`,
		        (SELECT COUNT(*) FROM identity.announcement_reads r WHERE r.announcement_id = a.id)
		 FROM identity.announcements a
		 WHERE a.id = $1`,
		id,
	)
	var a models.Announcement
	var langs, titles, bodies []string
	err := row.Scan(&a.ID, &a.CreatedBy, &a.Orgs, &a.StartsAt, &a.EndsAt, &a.CreatedAt, &a.UpdatedAt,
		&langs, &titles, &bodies, &a.ReadCount)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("%w: id %d", ErrAnnouncementNotFound, id)
	}
	if err != nil {
		return nil, fmt.Errorf("get announcement: %w", err)
	}
	a.Translations = zipAnnouncementTranslations(langs, titles, bodies)
	return &a, nil
}

// UpdateAnnouncement partially updates an announcement identified by id.
// translations, when non-empty, replaces the announcement's entire
// translation set (validated the same as on create) — pass nil/empty to
// leave the existing translations unchanged; the set can never be replaced
// with an empty one, since every announcement must keep at least one
// language. Because a nil orgs/startsAt/endsAt is ambiguous between "leave
// unchanged" and "clear", clearOrgs/clearStartsAt/clearEndsAt make the
// intent explicit: clearOrgs makes the announcement global (orgs must be
// empty when set), clearStartsAt/clearEndsAt remove that bound (open-ended)
// — set at most one of a bound and its own clear flag. Returns
// ErrAnnouncementNotFound when no announcement with that id exists, or
// models.ErrInvalidParameters if translations/orgs are invalid or the
// resulting period is invalid.
func (d *DB) UpdateAnnouncement(id int32, translations []models.AnnouncementTranslation, orgs []string, clearOrgs bool,
	startsAt *time.Time, clearStartsAt bool, endsAt *time.Time, clearEndsAt bool) (*models.Announcement, error) {
	if len(translations) > 0 {
		if err := validateAnnouncementTranslations(translations); err != nil {
			return nil, err
		}
	}
	if len(orgs) > 0 {
		if err := d.validateAnnouncementOrgs(orgs); err != nil {
			return nil, err
		}
	}
	orgsChanged := len(orgs) > 0 || clearOrgs
	startsAtChanged := startsAt != nil || clearStartsAt
	endsAtChanged := endsAt != nil || clearEndsAt

	ctx := context.Background()
	tx, err := d.Pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin transaction: %w", err)
	}
	defer func() {
		if err := tx.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			d.log.Error().Err(err).Msg("rollback transaction")
		}
	}()

	tag, err := tx.Exec(ctx,
		`UPDATE identity.announcements SET
		   orgs       = CASE WHEN $2 THEN $3::varchar[]   ELSE orgs      END,
		   starts_at  = CASE WHEN $4 THEN $5::timestamptz ELSE starts_at END,
		   ends_at    = CASE WHEN $6 THEN $7::timestamptz ELSE ends_at   END,
		   updated_at = now()
		 WHERE id = $1`,
		id, orgsChanged, nonNilOrgs(orgs), startsAtChanged, startsAt, endsAtChanged, endsAt,
	)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23514" && pgErr.ConstraintName == "chk_announcement_period" {
			return nil, fmt.Errorf("%w: starts_at must be before ends_at", models.ErrInvalidParameters)
		}
		return nil, fmt.Errorf("update announcement: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return nil, fmt.Errorf("%w: id %d", ErrAnnouncementNotFound, id)
	}

	if len(translations) > 0 {
		if _, err := tx.Exec(ctx,
			`DELETE FROM identity.announcement_translations WHERE announcement_id = $1`, id); err != nil {
			return nil, fmt.Errorf("delete announcement translations: %w", err)
		}
		if err := insertAnnouncementTranslations(ctx, tx, id, translations); err != nil {
			return nil, err
		}
	}

	updated, err := getAnnouncementByID(ctx, tx, id)
	if err != nil {
		return nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit transaction: %w", err)
	}
	return updated, nil
}

// DeleteAnnouncement permanently removes an announcement, cascading its
// translations and read tracking. Returns ErrAnnouncementNotFound when no
// announcement with that id exists.
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

	sqlQuery := `SELECT ` + announcementBaseColumns + `, ` + announcementTranslationsExpr + `,
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
		var langs, titles, bodies []string
		if err := rows.Scan(&a.ID, &a.CreatedBy, &a.Orgs, &a.StartsAt, &a.EndsAt, &a.CreatedAt, &a.UpdatedAt,
			&langs, &titles, &bodies, &a.ReadCount); err != nil {
			return nil, fmt.Errorf("list announcements: %w", err)
		}
		a.Translations = zipAnnouncementTranslations(langs, titles, bodies)
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
		`SELECT `+announcementBaseColumns+`, `+announcementTranslationsExpr+`
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
		a, err := scanAnnouncementRow(rows)
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
		`SELECT `+announcementBaseColumns+`, `+announcementTranslationsExpr+`,
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
		var langs, titles, bodies []string
		if err := rows.Scan(&a.ID, &a.CreatedBy, &a.Orgs, &a.StartsAt, &a.EndsAt, &a.CreatedAt, &a.UpdatedAt,
			&langs, &titles, &bodies, &a.IsRead, &a.ReadAt); err != nil {
			return nil, fmt.Errorf("list user announcements: %w", err)
		}
		a.Translations = zipAnnouncementTranslations(langs, titles, bodies)
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
