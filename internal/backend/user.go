package backend

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/k8shell-io/common/models"
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
	err := d.pool.QueryRow(context.Background(), query, username).Scan(
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

	query := `INSERT INTO public.users (
		username, is_valid, expires_at, uid, gid, fullname,
		access_token, email, password, locked, failed_logins,
		auths, auth_keys, channels, envs, roles, blueprints, source, organization
	) VALUES (
		$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19
	)`
	_, err = d.pool.Exec(context.Background(), query,
		user.Username, user.IsValid, user.ExpiresAt, user.UID, user.GID, user.Fullname, accessToken, user.Email,
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
		access_token=$6,
		email=$7,
		password=$8,
		locked=$9,
		failed_logins=$10,
		auths=$11,
		auth_keys=$12,
		channels=$13,
		envs=$14,
		roles=$15,
		blueprints=$16,
		source=$17,
		organization=$18
	WHERE username=$19`

	_, err := d.pool.Exec(context.Background(), query,
		user.IsValid,
		user.ExpiresAt,
		user.UID,
		user.GID,
		user.Fullname,
		user.AccessToken,
		user.Email,
		user.Password,
		user.Locked,
		user.FailedLogins,
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
	_, err := d.pool.Exec(context.Background(), query, username)
	return err
}

func (d *DB) DeleteUser(username string) error {
	_, err := d.pool.Exec(context.Background(), `DELETE FROM users WHERE username=$1`, username)
	return err
}

func (d *DB) ListUsers(limit, offset int) ([]*models.User, error) {
	limit, offset = AdjustListLimit(limit, offset)

	query := `
		SELECT username, is_valid, expires_at, uid, gid, fullname,
		       access_token, email, password, locked, failed_logins,
		       auths, auth_keys, channels, envs, roles, blueprints, source, organization
		FROM public.users
		ORDER BY username
		LIMIT $1 OFFSET $2
	`

	rows, err := d.pool.Query(context.Background(), query, limit, offset)
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

// generateAccessToken creates a random 32-byte hex token
func generateAccessToken() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
