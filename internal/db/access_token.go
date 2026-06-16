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

// CreateAccessToken generates a new PAT for username, stores its hash, and returns
// the raw token (shown to the caller once) along with the new record's ID.
func (d *DB) CreateAccessToken(username, name string, scopes []string, expiresAt *time.Time) (int64, string, error) {
	raw, err := generateRawToken()
	if err != nil {
		return 0, "", err
	}

	var id int64
	err = d.Pool.QueryRow(context.Background(),
		`INSERT INTO identity.access_tokens (token_hash, username, name, scopes, expires_at)
		 VALUES ($1, $2, $3, $4, $5)
		 RETURNING id`,
		hashToken(raw), username, name, scopes, expiresAt,
	).Scan(&id)
	if err != nil {
		return 0, "", fmt.Errorf("insert access token: %w", err)
	}

	return id, raw, nil
}

// ResolveAccessToken looks up a token by its raw value, verifies it is active and
// not expired, updates last_used_at, and returns the token record.
func (d *DB) ResolveAccessToken(raw string) (*models.AccessToken, error) {
	hash := hashToken(raw)

	var t models.AccessToken
	var expiresAt *time.Time
	var lastUsedAt *time.Time

	err := d.Pool.QueryRow(context.Background(),
		`UPDATE identity.access_tokens
		 SET last_used_at = NOW()
		 WHERE token_hash = $1 AND is_active = TRUE AND (expires_at IS NULL OR expires_at > NOW())
		 RETURNING id, username, name, scopes, expires_at, created_at, last_used_at, is_active`,
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
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, models.ErrUserNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("resolve access token: %w", err)
	}

	t.ExpiresAt = expiresAt
	t.LastUsedAt = lastUsedAt
	return &t, nil
}

// ListAccessTokens returns all access token metadata for a user (no hashes).
func (d *DB) ListAccessTokens(username string) ([]*models.AccessToken, error) {
	rows, err := d.Pool.Query(context.Background(),
		`SELECT id, username, name, scopes, expires_at, created_at, last_used_at, is_active
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
		if err := rows.Scan(
			&t.ID,
			&t.Username,
			&t.Name,
			&t.Scopes,
			&expiresAt,
			&t.CreatedAt,
			&lastUsedAt,
			&t.IsActive,
		); err != nil {
			return nil, err
		}
		t.ExpiresAt = expiresAt
		t.LastUsedAt = lastUsedAt
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
