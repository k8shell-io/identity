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

// FindUser retrieves a user by username. If source is empty, the search is not filtered by source.
func (d *DB) FindUser(username string, source string) (*models.User, error) {
	var (
		query string
		args  []any
	)
	if source == "" {
		query = `
			SELECT username, is_valid, expires_at, uid, gid, fullname,
			       email, password, shell, sudo, locked,
			       auths, auth_keys, roles, blueprints, source, organization
			FROM identity.users
			WHERE username=$1
		`
		args = []any{username}
	} else {
		query = `
			SELECT username, is_valid, expires_at, uid, gid, fullname,
			       email, password, shell, sudo, locked,
			       auths, auth_keys, roles, blueprints, source, organization
			FROM identity.users
			WHERE username=$1 AND source=$2
		`
		args = []any{username, source}
	}

	var user models.User
	err := d.Pool.QueryRow(context.Background(), query, args...).Scan(
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

// FindUserByUsernameAndSource retrieves a user by username and source.
func (d *DB) FindUserByUsernameAndSource(ctx context.Context, username string, source string) (*models.User, error) {
	query := `
		SELECT username, is_valid, expires_at, uid, gid, fullname,
		       email, COALESCE(password, '') AS password, shell, sudo, locked,
		       auths, auth_keys, roles, blueprints, source, organization
		FROM identity.users
		WHERE username=$1 and source=$2
	`

	var user models.User
	err := d.Pool.QueryRow(ctx, query, username, source).Scan(
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

// validServiceNames lists the service types accepted by the user_credentials table.
var validServiceNames = map[string]bool{
	"registry":   true,
	"git":        true,
	"kubernetes": true,
}

// AddUserCredential inserts a new credential for a user.
func (d *DB) AddUserCredential(cred *models.UserCredential) error {
	if cred.Username == "" || cred.ServiceName == "" || cred.ServiceScope == "" || cred.Subject == "" {
		return fmt.Errorf("required field: username, service_name, service_scope, subject")
	}
	if cred.CredentialSource == "" {
		return fmt.Errorf("required field: credential_source")
	}
	if !validServiceNames[cred.ServiceName] {
		return fmt.Errorf("unknown service_name '%s': must be one of registry, git, kubernetes", cred.ServiceName)
	}
	if cred.ServiceName == "registry" && cred.Secret == "" {
		return fmt.Errorf("secret is required for service 'registry'")
	}

	var secret *string
	if cred.Secret != "" {
		secret = &cred.Secret
	}

	query := `INSERT INTO identity.user_credentials (
		username, service_name, service_scope, subject, secret, credential_source
	) VALUES ($1, $2, $3, $4, $5, $6)`

	_, err := d.Pool.Exec(context.Background(), query,
		cred.Username, cred.ServiceName, cred.ServiceScope, cred.Subject, secret, cred.CredentialSource)

	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			switch pgErr.Code {
			case "23505":
				if pgErr.ConstraintName == "user_credentials_username_service_name_service_scope_subject_key" {
					return fmt.Errorf("credential already exists for user '%s', service '%s', scope '%s', subject '%s'",
						cred.Username, cred.ServiceName, cred.ServiceScope, cred.Subject)
				}
			case "23502":
				return fmt.Errorf("required field '%s' cannot be empty", pgErr.ColumnName)
			case "23514":
				switch pgErr.ConstraintName {
				case "chk_service_name":
					return fmt.Errorf("unknown service_name '%s': must be one of registry, git, kubernetes", cred.ServiceName)
				case "chk_credential_source_secret":
					return fmt.Errorf("secret must be present when credential_source='stored' and absent otherwise")
				case "chk_kubernetes_credential_source":
					return fmt.Errorf("kubernetes credentials must have credential_source='kubernetes'")
				case "chk_registry_credential_source":
					return fmt.Errorf("registry credentials must have credential_source='stored'")
				}
			}
		}
		return err
	}

	return nil
}

// GetUserCredential retrieves a single credential for the given user,
// service_name and service_scope. Returns models.ErrUserNotFound when no
// matching active credential exists.
func (d *DB) GetUserCredential(username, serviceName, serviceScope string) (*models.UserCredential, error) {
	query := `SELECT id, username, service_name, service_scope, subject,
			COALESCE(secret, '') AS secret, credential_source
		FROM identity.user_credentials
			WHERE username=$1 AND service_name=$2 AND service_scope=$3 AND is_active=true
		LIMIT 1`

	var cred models.UserCredential
	err := d.Pool.QueryRow(context.Background(), query, username, serviceName, serviceScope).Scan(
		&cred.ID,
		&cred.Username,
		&cred.ServiceName,
		&cred.ServiceScope,
		&cred.Subject,
		&cred.Secret,
		&cred.CredentialSource,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, models.ErrUserNotFound
	}
	if err != nil {
		return nil, err
	}
	return &cred, nil
}

// ListUserCredentials retrieves all credentials for the given username.
func (d *DB) ListUserCredentials(username string) ([]*models.UserCredential, error) {
	query := `SELECT id, username, service_name, service_scope, subject,
			COALESCE(secret, '') AS secret, credential_source
		FROM identity.user_credentials
			WHERE username=$1 AND is_active=true`

	rows, err := d.Pool.Query(context.Background(), query, username)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var creds []*models.UserCredential
	for rows.Next() {
		var cred models.UserCredential
		if err := rows.Scan(
			&cred.ID,
			&cred.Username,
			&cred.ServiceName,
			&cred.ServiceScope,
			&cred.Subject,
			&cred.Secret,
			&cred.CredentialSource,
		); err != nil {
			return nil, err
		}
		creds = append(creds, &cred)
	}
	return creds, nil
}

// UpsertDynamicGitCredential inserts a dynamic git credential row for a user if one does not
// already exist for the given provider. serviceScope must be the provider address (URL) so that
// the git credentials helper can match credentials by URL. providerName is stored as
// credential_source so that ResolveCredential can route directly to the right IDP by name.
// The secret is NULL — the live token is fetched on demand from the provider via GetUserGitToken.
func (d *DB) UpsertDynamicGitCredential(username, providerName, serviceScope string) error {
	query := `INSERT INTO identity.user_credentials
		(username, service_name, service_scope, subject, secret, credential_source)
	VALUES ($1, 'git', $2, $1, NULL, $3)
	ON CONFLICT (username, service_name, service_scope, subject) DO NOTHING`

	_, err := d.Pool.Exec(context.Background(), query, username, serviceScope, providerName)
	return err
}

// DeleteUserCredential removes a user credential by its ID.
func (d *DB) DeleteUserCredential(id uint32) error {
	result, err := d.Pool.Exec(context.Background(), `DELETE FROM identity.user_credentials WHERE id=$1`, id)
	if err != nil {
		return err
	}

	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("user credential with ID %d not found", id)
	}

	return nil
}

// UpdateUserCredential updates an existing user credential record.
// For dynamic credentials (kubernetes, dynamic git) Secret is ignored — the
// secret column stays NULL and is resolved live at request time.
func (d *DB) UpdateUserCredential(cred *models.UserCredential) error {
	if cred.Username == "" || cred.ServiceName == "" || cred.ServiceScope == "" || cred.Subject == "" {
		return fmt.Errorf("required field: username, service_name, service_scope, subject")
	}
	if cred.CredentialSource == "" {
		return fmt.Errorf("required field: credential_source")
	}
	if !validServiceNames[cred.ServiceName] {
		return fmt.Errorf("unknown service_name '%s': must be one of registry, git, kubernetes", cred.ServiceName)
	}
	if cred.ServiceName == "registry" && cred.Secret == "" {
		return fmt.Errorf("secret is required for service 'registry'")
	}

	var secret *string
	if cred.Secret != "" {
		secret = &cred.Secret
	}

	query := `UPDATE identity.user_credentials SET
		service_name=$1,
		service_scope=$2,
		subject=$3,
		secret=$4,
		credential_source=$5,
		updated_at=NOW()
	WHERE id=$6 AND username=$7`

	_, err := d.Pool.Exec(context.Background(), query,
		cred.ServiceName, cred.ServiceScope, cred.Subject, secret, cred.CredentialSource, cred.ID, cred.Username)
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
