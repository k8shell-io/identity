// Copyright 2026 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package db

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/k8shell-io/common/pkg/models"
)

// ErrEnvVarNotFound is returned when no environment variable with the given
// key exists in the requested scope (organization, user override, or the
// effective view for a user).
var ErrEnvVarNotFound = errors.New("environment variable not found")

// ErrEnvVarExists is returned by AddOrganizationEnvVar/AddUserEnvVar when a
// variable with the same key already exists in that scope.
var ErrEnvVarExists = errors.New("environment variable already exists")

// envVarKeyPattern mirrors chk_org_env_var_key/chk_user_env_var_key in
// db/migrations/000002_env_vars.up.sql.
var envVarKeyPattern = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)

// normalizeEnvVarKey upper-cases key and validates it as a POSIX environment
// variable name, so a bad key is reported as models.ErrInvalidParameters
// here instead of surfacing as a raw constraint violation from the DB. Keys
// are normalized before every lookup too, so they're effectively
// case-insensitive end to end.
func normalizeEnvVarKey(key string) (string, error) {
	normalized := strings.ToUpper(strings.TrimSpace(key))
	if !envVarKeyPattern.MatchString(normalized) {
		return "", fmt.Errorf("%w: invalid environment variable key %q", models.ErrInvalidParameters, key)
	}
	return normalized, nil
}

const envVarSelectColumns = `key, value, is_secret, created_at, updated_at`

func scanEnvVar(row pgx.Row) (*models.EnvVar, error) {
	var v models.EnvVar
	if err := row.Scan(&v.Key, &v.Value, &v.IsSecret, &v.CreatedAt, &v.UpdatedAt); err != nil {
		return nil, err
	}
	return &v, nil
}

// ListOrganizationEnvVars returns every environment variable defined
// directly on org, ordered by key.
func (d *DB) ListOrganizationEnvVars(org string) ([]*models.EnvVar, error) {
	rows, err := d.Pool.Query(context.Background(),
		`SELECT `+envVarSelectColumns+` FROM identity.organization_env_vars WHERE org=$1 ORDER BY key`, org)
	if err != nil {
		return nil, fmt.Errorf("list organization env vars: %w", err)
	}
	defer rows.Close()

	var vars []*models.EnvVar
	for rows.Next() {
		v, err := scanEnvVar(rows)
		if err != nil {
			return nil, fmt.Errorf("list organization env vars: %w", err)
		}
		vars = append(vars, v)
	}
	return vars, rows.Err()
}

// GetOrganizationEnvVar retrieves a single environment variable defined
// directly on org. Returns ErrEnvVarNotFound when no such key exists.
func (d *DB) GetOrganizationEnvVar(org, key string) (*models.EnvVar, error) {
	key, err := normalizeEnvVarKey(key)
	if err != nil {
		return nil, err
	}
	row := d.Pool.QueryRow(context.Background(),
		`SELECT `+envVarSelectColumns+` FROM identity.organization_env_vars WHERE org=$1 AND key=$2`, org, key)
	v, err := scanEnvVar(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("%w: org=%q key=%q", ErrEnvVarNotFound, org, key)
	}
	if err != nil {
		return nil, fmt.Errorf("get organization env var: %w", err)
	}
	return v, nil
}

// AddOrganizationEnvVar creates a new environment variable on org. Returns
// ErrEnvVarExists if key is already defined for org, or
// models.ErrInvalidParameters if key is not a valid POSIX name or org does
// not exist.
func (d *DB) AddOrganizationEnvVar(org, key, value string, isSecret bool) (*models.EnvVar, error) {
	key, err := normalizeEnvVarKey(key)
	if err != nil {
		return nil, err
	}
	row := d.Pool.QueryRow(context.Background(),
		`INSERT INTO identity.organization_env_vars (org, key, value, is_secret)
		 VALUES ($1, $2, $3, $4)
		 RETURNING `+envVarSelectColumns,
		org, key, value, isSecret,
	)
	v, err := scanEnvVar(row)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == "organization_env_vars_uniq" {
			return nil, fmt.Errorf("%w: org=%q key=%q", ErrEnvVarExists, org, key)
		}
		if errors.As(err, &pgErr) && pgErr.Code == "23503" {
			return nil, fmt.Errorf("%w: organization %q does not exist", models.ErrInvalidParameters, org)
		}
		return nil, fmt.Errorf("insert organization env var: %w", err)
	}
	return v, nil
}

// UpdateOrganizationEnvVar partially updates an existing organization
// environment variable — a nil value/isSecret leaves that field unchanged.
// Returns ErrEnvVarNotFound when no such key exists on org.
func (d *DB) UpdateOrganizationEnvVar(org, key string, value *string, isSecret *bool) (*models.EnvVar, error) {
	key, err := normalizeEnvVarKey(key)
	if err != nil {
		return nil, err
	}
	row := d.Pool.QueryRow(context.Background(),
		`UPDATE identity.organization_env_vars
		 SET value=COALESCE($3, value), is_secret=COALESCE($4, is_secret), updated_at=now()
		 WHERE org=$1 AND key=$2
		 RETURNING `+envVarSelectColumns,
		org, key, value, isSecret,
	)
	v, err := scanEnvVar(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("%w: org=%q key=%q", ErrEnvVarNotFound, org, key)
	}
	if err != nil {
		return nil, fmt.Errorf("update organization env var: %w", err)
	}
	return v, nil
}

// DeleteOrganizationEnvVar removes an environment variable from org. Returns
// ErrEnvVarNotFound when no such key exists.
func (d *DB) DeleteOrganizationEnvVar(org, key string) error {
	key, err := normalizeEnvVarKey(key)
	if err != nil {
		return err
	}
	result, err := d.Pool.Exec(context.Background(),
		`DELETE FROM identity.organization_env_vars WHERE org=$1 AND key=$2`, org, key)
	if err != nil {
		return fmt.Errorf("delete organization env var: %w", err)
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("%w: org=%q key=%q", ErrEnvVarNotFound, org, key)
	}
	return nil
}

// ListEffectiveUserEnvVars returns the effective environment variables for a
// user in org: every organization_env_vars entry for org (Origin "org"),
// with any user_env_vars entry for username overriding it by key (Origin
// "user"). Merged here rather than via a DB view/join, per the comment on
// identity.user_env_vars in db/migrations/000002_env_vars.up.sql.
func (d *DB) ListEffectiveUserEnvVars(username, org string) ([]*models.EnvVar, error) {
	orgVars, err := d.ListOrganizationEnvVars(org)
	if err != nil {
		return nil, err
	}
	byKey := make(map[string]*models.EnvVar, len(orgVars))
	for _, v := range orgVars {
		v.Origin = "org"
		byKey[v.Key] = v
	}

	rows, err := d.Pool.Query(context.Background(),
		`SELECT `+envVarSelectColumns+` FROM identity.user_env_vars WHERE username=$1`, username)
	if err != nil {
		return nil, fmt.Errorf("list user env vars: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		v, err := scanEnvVar(rows)
		if err != nil {
			return nil, fmt.Errorf("list user env vars: %w", err)
		}
		v.Origin = "user"
		byKey[v.Key] = v
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list user env vars: %w", err)
	}

	vars := make([]*models.EnvVar, 0, len(byKey))
	for _, v := range byKey {
		vars = append(vars, v)
	}
	sort.Slice(vars, func(i, j int) bool { return vars[i].Key < vars[j].Key })
	return vars, nil
}

// GetEffectiveUserEnvVar retrieves the effective value of key for a user in
// org: the user's own override when present (Origin "user"), otherwise
// org's value (Origin "org"). Returns ErrEnvVarNotFound when neither exists.
func (d *DB) GetEffectiveUserEnvVar(username, org, key string) (*models.EnvVar, error) {
	key, err := normalizeEnvVarKey(key)
	if err != nil {
		return nil, err
	}

	row := d.Pool.QueryRow(context.Background(),
		`SELECT `+envVarSelectColumns+` FROM identity.user_env_vars WHERE username=$1 AND key=$2`, username, key)
	v, err := scanEnvVar(row)
	if err == nil {
		v.Origin = "user"
		return v, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("get user env var: %w", err)
	}

	row = d.Pool.QueryRow(context.Background(),
		`SELECT `+envVarSelectColumns+` FROM identity.organization_env_vars WHERE org=$1 AND key=$2`, org, key)
	v, err = scanEnvVar(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("%w: username=%q key=%q", ErrEnvVarNotFound, username, key)
	}
	if err != nil {
		return nil, fmt.Errorf("get organization env var: %w", err)
	}
	v.Origin = "org"
	return v, nil
}

// AddUserEnvVar creates a new environment variable owned by username,
// overriding any organization value with the same key. Returns
// ErrEnvVarExists if username already has an override for key, or
// models.ErrInvalidParameters if key is not a valid POSIX name or username
// does not exist.
func (d *DB) AddUserEnvVar(username, key, value string, isSecret bool) (*models.EnvVar, error) {
	key, err := normalizeEnvVarKey(key)
	if err != nil {
		return nil, err
	}
	row := d.Pool.QueryRow(context.Background(),
		`INSERT INTO identity.user_env_vars (username, key, value, is_secret)
		 VALUES ($1, $2, $3, $4)
		 RETURNING `+envVarSelectColumns,
		username, key, value, isSecret,
	)
	v, err := scanEnvVar(row)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == "user_env_vars_uniq" {
			return nil, fmt.Errorf("%w: username=%q key=%q", ErrEnvVarExists, username, key)
		}
		if errors.As(err, &pgErr) && pgErr.Code == "23503" {
			return nil, fmt.Errorf("%w: user %q does not exist", models.ErrInvalidParameters, username)
		}
		return nil, fmt.Errorf("insert user env var: %w", err)
	}
	return v, nil
}

// UpdateUserEnvVar partially updates an existing user-owned environment
// variable override — a nil value/isSecret leaves that field unchanged.
// Returns ErrEnvVarNotFound when username has no override for key;
// AddUserEnvVar must be used to create one first.
func (d *DB) UpdateUserEnvVar(username, key string, value *string, isSecret *bool) (*models.EnvVar, error) {
	key, err := normalizeEnvVarKey(key)
	if err != nil {
		return nil, err
	}
	row := d.Pool.QueryRow(context.Background(),
		`UPDATE identity.user_env_vars
		 SET value=COALESCE($3, value), is_secret=COALESCE($4, is_secret), updated_at=now()
		 WHERE username=$1 AND key=$2
		 RETURNING `+envVarSelectColumns,
		username, key, value, isSecret,
	)
	v, err := scanEnvVar(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("%w: username=%q key=%q", ErrEnvVarNotFound, username, key)
	}
	if err != nil {
		return nil, fmt.Errorf("update user env var: %w", err)
	}
	return v, nil
}

// DeleteUserEnvVar removes username's override for key, restoring org's
// value (if any) as the effective value. Returns ErrEnvVarNotFound when
// username has no override for key.
func (d *DB) DeleteUserEnvVar(username, key string) error {
	key, err := normalizeEnvVarKey(key)
	if err != nil {
		return err
	}
	result, err := d.Pool.Exec(context.Background(),
		`DELETE FROM identity.user_env_vars WHERE username=$1 AND key=$2`, username, key)
	if err != nil {
		return fmt.Errorf("delete user env var: %w", err)
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("%w: username=%q key=%q", ErrEnvVarNotFound, username, key)
	}
	return nil
}
