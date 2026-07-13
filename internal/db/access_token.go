// Copyright 2025 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package db

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/k8shell-io/common/pkg/models"
)

const tokenPrefix = "k8sh_"

// tokenPreviewLength is how many characters of a token's random portion (after
// tokenPrefix) are stored for display purposes, letting a user tell their tokens
// apart in listings without the raw value ever being stored or shown again.
const tokenPreviewLength = 8

// generateRawToken creates a new opaque token: "k8sh_" + base64url(32 random bytes).
func generateRawToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate token bytes: %w", err)
	}
	return tokenPrefix + base64.RawURLEncoding.EncodeToString(b), nil
}

// hashToken returns hex(sha256(raw)).
func hashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// previewToken returns tokenPrefix plus the first tokenPreviewLength characters
// of raw's random portion, for display purposes only.
func previewToken(raw string) string {
	return raw[:len(tokenPrefix)+tokenPreviewLength]
}

// CreateAccessToken generates a new PAT for username, stores its hash, and returns
// the raw token (shown to the caller once) along with the new record's ID.
func (d *DB) CreateAccessToken(username, name string, scopes []string, expiresAt *time.Time, active bool) (int64, string, error) {
	raw, err := generateRawToken()
	if err != nil {
		return 0, "", err
	}

	var id int64
	err = d.Pool.QueryRow(context.Background(),
		`INSERT INTO identity.access_tokens (token_hash, username, name, scopes, expires_at, token_preview, is_active)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)
		 RETURNING id`,
		hashToken(raw), username, name, scopes, expiresAt, previewToken(raw), active,
	).Scan(&id)
	if err != nil {
		return 0, "", fmt.Errorf("insert access token: %w", err)
	}

	return id, raw, nil
}

// GetAccessTokenByName looks up the token owned by username with the given name,
// active or not — (username, name) is unique, so at most one row can match.
// Returns models.ErrUserNotFound if no such token exists.
func (d *DB) GetAccessTokenByName(username, name string) (*models.AccessToken, error) {
	var t models.AccessToken
	var expiresAt *time.Time
	var lastUsedAt *time.Time

	var tokenPreview *string
	err := d.Pool.QueryRow(context.Background(),
		`SELECT id, username, name, scopes, expires_at, created_at, last_used_at, is_active, token_preview
		 FROM identity.access_tokens
		 WHERE username = $1 AND name = $2`,
		username, name,
	).Scan(
		&t.ID,
		&t.Username,
		&t.Name,
		&t.Scopes,
		&expiresAt,
		&t.CreatedAt,
		&lastUsedAt,
		&t.IsActive,
		&tokenPreview,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, models.ErrUserNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get access token by name: %w", err)
	}

	t.ExpiresAt = expiresAt
	t.LastUsedAt = lastUsedAt
	t.TokenPreview = tokenPreview
	return &t, nil
}

// RenewAccessToken rotates the raw token of an existing access token record in place,
// applying the given scopes and expiry, and returns the new raw token (shown once).
// The token is reactivated (is_active = TRUE) regardless of its prior state, since
// renewing a revoked token is how its name is brought back into use.
func (d *DB) RenewAccessToken(id int64, scopes []string, expiresAt *time.Time) (string, error) {
	raw, err := generateRawToken()
	if err != nil {
		return "", err
	}

	_, err = d.Pool.Exec(context.Background(),
		`UPDATE identity.access_tokens
		 SET token_hash = $1, scopes = $2, expires_at = $3, last_used_at = NULL, token_preview = $4, is_active = TRUE
		 WHERE id = $5`,
		hashToken(raw), scopes, expiresAt, previewToken(raw), id,
	)
	if err != nil {
		return "", fmt.Errorf("renew access token: %w", err)
	}

	return raw, nil
}

// UpdateAccessToken partially updates an access token's active state and/or scopes,
// enforcing that it belongs to username. Only non-nil fields are applied. Returns
// models.ErrUserNotFound if no matching token owned by username exists.
func (d *DB) UpdateAccessToken(id int64, username string, active *bool, scopes *[]string) (*models.AccessToken, error) {
	var t models.AccessToken
	var expiresAt *time.Time
	var lastUsedAt *time.Time
	var tokenPreview *string

	err := d.Pool.QueryRow(context.Background(),
		`UPDATE identity.access_tokens SET
			is_active = COALESCE($3, is_active),
			scopes    = COALESCE($4, scopes)
		 WHERE id = $1 AND username = $2
		 RETURNING id, username, name, scopes, expires_at, created_at, last_used_at, is_active, token_preview`,
		id, username, active, scopes,
	).Scan(
		&t.ID,
		&t.Username,
		&t.Name,
		&t.Scopes,
		&expiresAt,
		&t.CreatedAt,
		&lastUsedAt,
		&t.IsActive,
		&tokenPreview,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, models.ErrUserNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("update access token: %w", err)
	}

	t.ExpiresAt = expiresAt
	t.LastUsedAt = lastUsedAt
	t.TokenPreview = tokenPreview
	return &t, nil
}

// ResolveAccessToken looks up a token by its raw value, verifies it is active and
// not expired, updates last_used_at, and returns the token record.
func (d *DB) ResolveAccessToken(raw string) (*models.AccessToken, error) {
	hash := hashToken(raw)

	var t models.AccessToken
	var expiresAt *time.Time
	var lastUsedAt *time.Time
	var tokenPreview *string

	err := d.Pool.QueryRow(context.Background(),
		`UPDATE identity.access_tokens
		 SET last_used_at = NOW()
		 WHERE token_hash = $1 AND is_active = TRUE AND (expires_at IS NULL OR expires_at > NOW())
		 RETURNING id, username, name, scopes, expires_at, created_at, last_used_at, is_active, token_preview`,
		hash,
	).Scan(
		&t.ID,
		&t.Username,
		&t.Name,
		&t.Scopes,
		&expiresAt,
		&t.CreatedAt,
		&lastUsedAt,
		&t.IsActive,
		&tokenPreview,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, models.ErrUserNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("resolve access token: %w", err)
	}

	t.ExpiresAt = expiresAt
	t.LastUsedAt = lastUsedAt
	t.TokenPreview = tokenPreview
	return &t, nil
}

// ListAccessTokens returns all access token metadata for a user (no hashes).
func (d *DB) ListAccessTokens(username string) ([]*models.AccessToken, error) {
	rows, err := d.Pool.Query(context.Background(),
		`SELECT id, username, name, scopes, expires_at, created_at, last_used_at, is_active, token_preview
		 FROM identity.access_tokens
		 WHERE username = $1
		 ORDER BY created_at DESC`,
		username,
	)
	if err != nil {
		return nil, fmt.Errorf("list access tokens: %w", err)
	}
	defer rows.Close()

	var tokens []*models.AccessToken
	for rows.Next() {
		var t models.AccessToken
		var expiresAt *time.Time
		var lastUsedAt *time.Time
		var tokenPreview *string
		if err := rows.Scan(
			&t.ID,
			&t.Username,
			&t.Name,
			&t.Scopes,
			&expiresAt,
			&t.CreatedAt,
			&lastUsedAt,
			&t.IsActive,
			&tokenPreview,
		); err != nil {
			return nil, err
		}
		t.ExpiresAt = expiresAt
		t.LastUsedAt = lastUsedAt
		t.TokenPreview = tokenPreview
		tokens = append(tokens, &t)
	}
	return tokens, rows.Err()
}

// RevokeAccessToken soft-deletes a token by ID, enforcing that it belongs to username.
// Returns models.ErrUserNotFound when no matching active token is found.
func (d *DB) RevokeAccessToken(id int64, username string) error {
	result, err := d.Pool.Exec(context.Background(),
		`UPDATE identity.access_tokens
		 SET is_active = FALSE
		 WHERE id = $1 AND username = $2 AND is_active = TRUE`,
		id, username,
	)
	if err != nil {
		return fmt.Errorf("revoke access token: %w", err)
	}
	if result.RowsAffected() == 0 {
		return models.ErrUserNotFound
	}
	return nil
}

// DeleteAccessToken permanently removes an access token by ID, regardless of owner
// or active state. Returns models.ErrUserNotFound if no such token exists.
func (d *DB) DeleteAccessToken(id int64) error {
	result, err := d.Pool.Exec(context.Background(),
		`DELETE FROM identity.access_tokens WHERE id = $1`,
		id,
	)
	if err != nil {
		return fmt.Errorf("delete access token: %w", err)
	}
	if result.RowsAffected() == 0 {
		return models.ErrUserNotFound
	}
	return nil
}

// accessTokenJanitorLockKey is the Postgres advisory lock key used to ensure that
// only one running service instance performs expired access token cleanup at a
// time, even when multiple replicas each run their own janitor on the same schedule.
const accessTokenJanitorLockKey = 8214559041

// DeleteExpiredAccessTokens permanently removes access tokens whose expiry is
// before cutoff. Tokens that never expire (expires_at IS NULL) are untouched.
// The delete is guarded by a transaction-scoped Postgres advisory lock, so if
// another instance is already running the same cleanup, this call is a no-op
// and returns (0, nil) instead of racing it.
func (d *DB) DeleteExpiredAccessTokens(cutoff time.Time) (int64, error) {
	ctx := context.Background()

	tx, err := d.Pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("begin access token cleanup transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var locked bool
	if err := tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock($1)`, accessTokenJanitorLockKey).
		Scan(&locked); err != nil {
		return 0, fmt.Errorf("acquire access token janitor lock: %w", err)
	}
	if !locked {
		return 0, nil
	}

	result, err := tx.Exec(ctx,
		`DELETE FROM identity.access_tokens WHERE expires_at IS NOT NULL AND expires_at < $1`,
		cutoff,
	)
	if err != nil {
		return 0, fmt.Errorf("delete expired access tokens: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("commit access token cleanup: %w", err)
	}

	return result.RowsAffected(), nil
}
