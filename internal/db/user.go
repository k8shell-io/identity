// Copyright 2025 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package db

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/k8shell-io/common/pkg/db"
	"github.com/k8shell-io/common/pkg/models"
)

// FindUser retrieves a user by username.
func (d *DB) FindUser(username string) (*models.User, error) {
	query := `
		SELECT username, is_valid, expires_at, uid, gid, fullname,
		       email, password, shell, sudo, locked,
		       auths, auth_keys, roles, blueprints, source, organization
		FROM identity.users
		WHERE username=$1
	`

	var user models.User
	err := d.Pool.QueryRow(context.Background(), query, username).Scan(
		&user.Username,
		&user.IsValid,
		&user.ExpiresAt,
		&user.UID,
		&user.GID,
		&user.Fullname,
		&user.Email,
		&user.Password,
		&user.Shell,
		&user.Sudo,
		&user.Locked,
		&user.Auths,
		&user.AuthKeys,
		&user.Roles,
		&user.Blueprints,
		&user.Source,
		&user.Organization,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, models.ErrUserNotFound
	} else if err != nil {
		return nil, err
	}

	return &user, nil
}

// FindUserByTokenID looks up a user by the JTI stored in current_token_id.
// Only returns a user if the token has not yet expired, enabling revocation
// by overwriting current_token_id on re-issuance.
func (d *DB) FindUserByTokenID(ctx context.Context, tokenID string) (*models.User, error) {
	query := `
		SELECT username, is_valid, expires_at, uid, gid, fullname,
		       email, COALESCE(password, '') AS password, shell, sudo, locked,
		       auths, auth_keys, roles, blueprints, source, organization
		FROM identity.users
		WHERE current_token_id=$1
		  AND token_expires_at > NOW()
	`

	var user models.User
	err := d.Pool.QueryRow(ctx, query, tokenID).Scan(
		&user.Username,
		&user.IsValid,
		&user.ExpiresAt,
		&user.UID,
		&user.GID,
		&user.Fullname,
		&user.Email,
		&user.Password,
		&user.Shell,
		&user.Sudo,
		&user.Locked,
		&user.Auths,
		&user.AuthKeys,
		&user.Roles,
		&user.Blueprints,
		&user.Source,
		&user.Organization,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, models.ErrUserNotFound
	} else if err != nil {
		return nil, err
	}

	return &user, nil
}

// CreateUser inserts a new user record into the database.
// If the user's organization does not exist and is in the auto-create allowlist,
// it is created automatically. Otherwise the insert will fail if the org is missing.
func (d *DB) CreateUser(user *models.User) error {
	ctx := context.Background()

	tx, err := d.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer func() {
		err := tx.Rollback(ctx)
		if err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			d.log.Error().Err(err).Msg("rollback transaction")
		}
	}()

	if d.orgAutoCreateAllowed(user.Organization) {
		_, err = tx.Exec(ctx,
			`INSERT INTO identity.organizations (name, description)
			 VALUES ($1, '')
			 ON CONFLICT (name) DO NOTHING`,
			user.Organization)
		if err != nil {
			return fmt.Errorf("ensure organization: %w", err)
		}
	}

	_, err = tx.Exec(ctx, `INSERT INTO identity.users (
		username, is_valid, expires_at, uid, gid, fullname,
		email, password, shell, sudo, locked,
		auths, auth_keys, roles, blueprints, source, organization
	) VALUES (
		$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17
	)`,
		user.Username, user.IsValid, user.ExpiresAt, user.UID, user.GID, user.Fullname,
		user.Email, user.Password, user.Shell, user.Sudo, user.Locked,
		user.Auths, user.AuthKeys, user.Roles, user.Blueprints, user.Source, user.Organization)
	if err != nil {
		return err
	}

	return tx.Commit(ctx)
}

// UpdateUser updates an existing user's fields, identified by username.
func (d *DB) UpdateUser(user *models.User) error {
	query := `UPDATE identity.users SET
		is_valid=$1,
		expires_at=$2,
		uid=$3,
		gid=$4,
		fullname=$5,
		email=$6,
		password=$7,
		shell=$8,
		sudo=$9,
		auths=$10,
		auth_keys=$11,
		roles=$12,
		blueprints=$13,
		source=$14,
		organization=$15
	WHERE username=$16`

	_, err := d.Pool.Exec(context.Background(), query,
		user.IsValid,
		user.ExpiresAt,
		user.UID,
		user.GID,
		user.Fullname,
		user.Email,
		user.Password,
		user.Shell,
		user.Sudo,
		user.Auths,
		user.AuthKeys,
		user.Roles,
		user.Blueprints,
		user.Source,
		user.Organization,
		user.Username,
	)
	return err
}

// InvalidateUser marks a user account as invalid (is_valid=false) without deleting it.
func (d *DB) InvalidateUser(username string) error {
	query := `UPDATE identity.users SET is_valid=false WHERE username=$1`
	_, err := d.Pool.Exec(context.Background(), query, username)
	return err
}

// DeleteUser permanently removes a user record from the database by username.
func (d *DB) DeleteUser(username string) error {
	_, err := d.Pool.Exec(context.Background(), `DELETE FROM identity.users WHERE username=$1`, username)
	return err
}

// ListUsers returns a paginated list of all users ordered by username.
func (d *DB) ListUsers(limit, offset int) ([]*models.User, error) {
	limit, offset = db.AdjustListLimit(limit, offset)

	query := `
		SELECT username, is_valid, expires_at, uid, gid, fullname,
		       email, COALESCE(password, '') AS password, shell, sudo, locked,
		       auths, auth_keys, roles, blueprints, source, organization
		FROM identity.users
		ORDER BY username
		LIMIT $1 OFFSET $2
	`

	rows, err := d.Pool.Query(context.Background(), query, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []*models.User
	for rows.Next() {
		var user models.User
		if err := rows.Scan(
			&user.Username,
			&user.IsValid,
			&user.ExpiresAt,
			&user.UID,
			&user.GID,
			&user.Fullname,
			&user.Email,
			&user.Password,
			&user.Shell,
			&user.Sudo,
			&user.Locked,
			&user.Auths,
			&user.AuthKeys,
			&user.Roles,
			&user.Blueprints,
			&user.Source,
			&user.Organization,
		); err != nil {
			return nil, err
		}
		users = append(users, &user)
	}
	return users, nil
}

// AddExternalCredential inserts a new external credential for a user.
// Returns an error if a credential already exists for the given username and service URL.
func (d *DB) AddExternalCredential(cred *models.ExternalCredential) error {
	if cred.Username == "" || cred.ServiceName == "" || cred.ServiceURL == "" ||
		cred.ExternalID == "" || cred.ExternalToken == "" {
		return fmt.Errorf("required field: username, service_name, service_url, external_id, external_token")
	}

	query := `INSERT INTO identity.external_credentials (
        username, service_name, service_url, external_id, external_token
    ) VALUES ($1, $2, $3, $4, $5)`

	_, err := d.Pool.Exec(context.Background(), query,
		cred.Username, cred.ServiceName, cred.ServiceURL, cred.ExternalID, cred.ExternalToken)

	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			switch pgErr.Code {
			case "23505":
				if pgErr.ConstraintName == "external_credentials_username_service_url_key" {
					return fmt.Errorf("credential already exists for user '%s' and service URL '%s'",
						cred.Username, cred.ServiceURL)
				}
			case "23502":
				return fmt.Errorf("required field '%s' cannot be empty", pgErr.ColumnName)
			}
		}
		return err
	}

	return nil
}

// GetExternalCredentials retrieves all external credentials for the given username.
func (d *DB) GetExternalCredentials(username string) ([]*models.ExternalCredential, error) {
	query := `SELECT id, username, service_name, service_url, external_id, external_token
		FROM identity.external_credentials
		WHERE username=$1`

	rows, err := d.Pool.Query(context.Background(), query, username)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var creds []*models.ExternalCredential
	for rows.Next() {
		var cred models.ExternalCredential
		if err := rows.Scan(
			&cred.ID,
			&cred.Username,
			&cred.ServiceName,
			&cred.ServiceURL,
			&cred.ExternalID,
			&cred.ExternalToken,
		); err != nil {
			return nil, err
		}
		creds = append(creds, &cred)
	}
	return creds, nil
}

// DeleteExternalCredential removes an external credential by its ID.
func (d *DB) DeleteExternalCredential(id uint32) error {
	result, err := d.Pool.Exec(context.Background(), `DELETE FROM identity.external_credentials WHERE id=$1`, id)
	if err != nil {
		return err
	}

	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("external credential with ID %d not found", id)
	}

	return nil
}

// UpdateExternalCredential updates an existing external credential record.
func (d *DB) UpdateExternalCredential(cred *models.ExternalCredential) error {
	if cred.Username == "" || cred.ServiceName == "" || cred.ServiceURL == "" ||
		cred.ExternalID == "" || cred.ExternalToken == "" {
		return fmt.Errorf("required field: username, service_name, service_url, external_id, external_token")
	}

	query := `UPDATE identity.external_credentials SET
		service_name=$1,
		service_url=$2,
		external_id=$3,
		external_token=$4,
		updated_at=NOW()
	WHERE id=$5 AND username=$6`

	_, err := d.Pool.Exec(context.Background(), query,
		cred.ServiceName, cred.ServiceURL, cred.ExternalID, cred.ExternalToken, cred.ID, cred.Username)
	return err
}

// SetUserToken stores the JTI of an issued JWT and its expiry for the given user.
// Clears any in-progress refresh claim so the background loop can reclaim the
// user on the next cycle when the new token approaches its expiry.
func (d *DB) SetUserToken(ctx context.Context, username, tokenID string, expiresAt time.Time) error {
	_, err := d.Pool.Exec(ctx,
		`UPDATE identity.users
		 SET current_token_id=$1, token_expires_at=$2, token_refresh_claimed_until=NULL
		 WHERE username=$3`,
		tokenID, expiresAt, username)
	return err
}

// InvalidateUserToken clears the token expiry for the given user so that the
// background refresh loop picks the user up on its next cycle and re-issues a
// fresh token. Any existing refresh claim is also cleared so the row is
// immediately eligible for reclaiming.
func (d *DB) InvalidateUserToken(ctx context.Context, username string) error {
	_, err := d.Pool.Exec(ctx,
		`UPDATE identity.users
		 SET token_expires_at=NOW(), token_refresh_claimed_until=NULL
		 WHERE username=$1`,
		username)
	return err
}

// ClaimUsersForTokenRefresh atomically claims a batch of valid users whose
// tokens are absent or expiring before expiresBeforeTime for renewal.
// It uses SELECT FOR UPDATE SKIP LOCKED so that multiple service instances
// share the work without double-processing.
// claimUntil is set on claimed rows to act as a lease; if an instance crashes
// the lease expires and another instance can reclaim those rows.
// Returns the usernames of the claimed users.
func (d *DB) ClaimUsersForTokenRefresh(ctx context.Context, expiresBeforeTime time.Time, claimUntil time.Time, limit int) ([]string, error) {
	rows, err := d.Pool.Query(ctx, `
		WITH claimed AS (
			SELECT username
			FROM identity.users
			WHERE is_valid = true
			  AND (
			      token_expires_at IS NULL
			      OR token_expires_at < $1
			  )
			  AND (
			      token_refresh_claimed_until IS NULL
			      OR token_refresh_claimed_until < NOW()
			  )
			ORDER BY token_expires_at ASC NULLS FIRST
			LIMIT $2
			FOR UPDATE SKIP LOCKED
		)
		UPDATE identity.users
		SET token_refresh_claimed_until = $3
		WHERE username IN (SELECT username FROM claimed)
		RETURNING username`,
		expiresBeforeTime, limit, claimUntil)
	if err != nil {
		return nil, fmt.Errorf("claim users for token refresh: %w", err)
	}
	defer rows.Close()

	var usernames []string
	for rows.Next() {
		var username string
		if err := rows.Scan(&username); err != nil {
			return nil, err
		}
		usernames = append(usernames, username)
	}
	return usernames, rows.Err()
}
