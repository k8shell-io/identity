// Copyright 2026 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package db

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/k8shell-io/common/pkg/models"
)

// GetUserSettings returns username's settings row. A missing row is not an
// error — it returns the zero-value *models.UserSettings (Version 0, empty
// Data, zero UpdatedAt), matching GetUserSettingsResponse's own no-NotFound
// contract.
func (d *DB) GetUserSettings(username string) (*models.UserSettings, error) {
	row := d.Pool.QueryRow(context.Background(),
		`SELECT version, data, session_idle_timeout_seconds, updated_at
		 FROM identity.user_settings WHERE username=$1`, username)

	var s models.UserSettings
	s.Username = username
	if err := row.Scan(&s.Version, &s.Data, &s.SessionIdleTimeoutSeconds, &s.UpdatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return &s, nil
		}
		return nil, fmt.Errorf("get user settings: %w", err)
	}
	return &s, nil
}

// PutUserSettings replaces username's settings row (UPSERT, last-write-wins)
// and returns the new version and updated_at. version is not compared
// against any existing value — there is no optimistic-concurrency check.
// Returns models.ErrInvalidParameters if username does not exist.
func (d *DB) PutUserSettings(username string, data []byte, sessionIdleTimeoutSeconds *int32) (*models.UserSettings, error) {
	row := d.Pool.QueryRow(context.Background(),
		`INSERT INTO identity.user_settings (username, version, data, session_idle_timeout_seconds)
		 VALUES ($1, 1, $2, $3)
		 ON CONFLICT (username) DO UPDATE
		   SET version = identity.user_settings.version + 1,
		       data = EXCLUDED.data,
		       session_idle_timeout_seconds = EXCLUDED.session_idle_timeout_seconds,
		       updated_at = now()
		 RETURNING version, updated_at`,
		username, data, sessionIdleTimeoutSeconds,
	)

	s := &models.UserSettings{Username: username, Data: data, SessionIdleTimeoutSeconds: sessionIdleTimeoutSeconds}
	if err := row.Scan(&s.Version, &s.UpdatedAt); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23503" {
			return nil, fmt.Errorf("%w: user %q does not exist", models.ErrInvalidParameters, username)
		}
		return nil, fmt.Errorf("put user settings: %w", err)
	}
	return s, nil
}
