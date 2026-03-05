package db

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/k8shell-io/common/pkg/db"
	"github.com/k8shell-io/common/pkg/models"
)

func (d *DB) FindUser(username string) (*models.User, error) {
	query := `
		SELECT username, is_valid, expires_at, uid, gid, fullname, 
		       access_token, email, password, locked, failed_logins,
		       auths, auth_keys, channels, envs, roles, blueprints, source, organization
		FROM public.users
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
		&user.AccessToken,
		&user.Email,
		&user.Password,
		&user.Locked,
		&user.FailedLogins,
		&user.Auths,
		&user.AuthKeys,
		&user.Channels,
		&user.Envs,
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

func (d *DB) FindUserByAccessToken(token string) (*models.User, error) {
	query := `
		SELECT username, is_valid, expires_at, uid, gid, fullname,
		       access_token, email, COALESCE(password, '') AS password, locked, failed_logins,
		       auths, auth_keys, channels, envs, roles, blueprints, source, organization
		FROM public.users
		WHERE access_token=$1
	`

	var user models.User
	err := d.Pool.QueryRow(context.Background(), query, token).Scan(
		&user.Username,
		&user.IsValid,
		&user.ExpiresAt,
		&user.UID,
		&user.GID,
		&user.Fullname,
		&user.AccessToken,
		&user.Email,
		&user.Password,
		&user.Locked,
		&user.FailedLogins,
		&user.Auths,
		&user.AuthKeys,
		&user.Channels,
		&user.Envs,
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

func (d *DB) CreateUser(user *models.User) error {
	accessToken, err := generateAccessToken()
	if err != nil {
		return fmt.Errorf("failed to generate access token: %w", err)
	}
	user.AccessToken = accessToken

	query := `INSERT INTO public.users (
		username, is_valid, expires_at, uid, gid, fullname,
		access_token, email, password, locked, failed_logins,
		auths, auth_keys, channels, envs, roles, blueprints, source, organization
	) VALUES (
		$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19
	)`
	_, err = d.Pool.Exec(context.Background(), query,
		user.Username, user.IsValid, user.ExpiresAt, user.UID, user.GID, user.Fullname, user.AccessToken, user.Email,
		user.Password, user.Locked, user.FailedLogins, user.Auths, user.AuthKeys, user.Channels,
		user.Envs, user.Roles, user.Blueprints, user.Source, user.Organization)
	return err
}

func (d *DB) UpdateUser(user *models.User) error {
	query := `UPDATE public.users SET 
		is_valid=$1,
		expires_at=$2,
		uid=$3,
		gid=$4,
		fullname=$5,
		email=$6,
		password=$7,
		auths=$8,
		auth_keys=$9,
		channels=$10,
		envs=$11,
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
		user.Auths,
		user.AuthKeys,
		user.Channels,
		user.Envs,
		user.Roles,
		user.Blueprints,
		user.Source,
		user.Organization,
		user.Username,
	)
	return err
}

func (d *DB) InvalidateUser(username string) error {
	query := `UPDATE public.users SET is_valid=false WHERE username=$1`
	_, err := d.Pool.Exec(context.Background(), query, username)
	return err
}

func (d *DB) DeleteUser(username string) error {
	_, err := d.Pool.Exec(context.Background(), `DELETE FROM users WHERE username=$1`, username)
	return err
}

func (d *DB) ListUsers(limit, offset int) ([]*models.User, error) {
	limit, offset = db.AdjustListLimit(limit, offset)

	query := `
		SELECT username, is_valid, expires_at, uid, gid, fullname,
		       access_token, email, COALESCE(password, '') AS password, locked, failed_logins,
		       auths, auth_keys, channels, envs, roles, blueprints, source, organization
		FROM public.users
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
			&user.AccessToken,
			&user.Email,
			&user.Password,
			&user.Locked,
			&user.FailedLogins,
			&user.Auths,
			&user.AuthKeys,
			&user.Channels,
			&user.Envs,
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

func (d *DB) AddExternalCredential(cred *models.ExternalCredential) error {
	if cred.Username == "" || cred.ServiceName == "" || cred.ServiceURL == "" ||
		cred.ExternalID == "" || cred.ExternalToken == "" {
		return fmt.Errorf("required field: username, service_name, service_url, external_id, external_token")
	}

	query := `INSERT INTO public.external_credentials (
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

// GetExternalCredentials retrieves all external credentials for a given username
func (d *DB) GetExternalCredentials(username string) ([]*models.ExternalCredential, error) {
	query := `SELECT id, username, service_name, service_url, external_id, external_token
		FROM public.external_credentials
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

// DeleteExternalCredential deletes an external credential by its ID
func (d *DB) DeleteExternalCredential(id uint32) error {
	result, err := d.Pool.Exec(context.Background(), `DELETE FROM public.external_credentials WHERE id=$1`, id)
	if err != nil {
		return err
	}

	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("external credential with ID %d not found", id)
	}

	return nil
}

// UpdateExternalCredential updates an existing external credential
func (d *DB) UpdateExternalCredential(cred *models.ExternalCredential) error {
	if cred.Username == "" || cred.ServiceName == "" || cred.ServiceURL == "" ||
		cred.ExternalID == "" || cred.ExternalToken == "" {
		return fmt.Errorf("required field: username, service_name, service_url, external_id, external_token")
	}

	query := `UPDATE public.external_credentials SET
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

// generateAccessToken creates a random 32-byte hex token
func generateAccessToken() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
