package backend

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/k8shell-io/common/pkg/models"
)

func (d *DB) GetUserProviderInfo(username string, provider string) (*models.ProviderInfo, error) {
	query := `SELECT status, created_at, updated_at, username, provider, user_code, device_code, 
					 expires_at, verification_uri, access_token, refresh_token
			  FROM provider_info WHERE username = $1 AND provider = $2`
	row := d.pool.QueryRow(context.Background(), query, username, provider)

	var info models.ProviderInfo
	err := row.Scan(
		&info.Status, &info.CreatedAt, &info.UpdatedAt, &info.Username, &info.Provider,
		&info.UserCode, &info.DeviceCode, &info.ExpiresAt, &info.VerificationURI,
		&info.AccessToken, &info.RefreshToken,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get provider_info: %w", err)
	}
	return &info, nil
}

func (d *DB) CreateUserProviderInfo(info *models.ProviderInfo) error {
	query := `INSERT INTO provider_info (
		username, provider, status, created_at, updated_at,
		user_code, device_code, expires_at, verification_uri, access_token, refresh_token
	) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`
	_, err := d.pool.Exec(context.Background(), query,
		info.Username, info.Provider, info.Status, info.CreatedAt, info.UpdatedAt,
		info.UserCode, info.DeviceCode, info.ExpiresAt, info.VerificationURI,
		info.AccessToken, info.RefreshToken)
	if err != nil {
		return fmt.Errorf("create provider_info: %w", err)
	}
	return nil
}

func (d *DB) DeleteUserProviderInfo(username string, provider string) error {
	if username == "" || provider == "" {
		return fmt.Errorf("username and provider must be specified")
	}
	_, err := d.pool.Exec(context.Background(),
		`DELETE FROM provider_info WHERE username = $1 AND provider = $2`, username, provider)
	if err != nil {
		return fmt.Errorf("delete provider_info: %w", err)
	}
	return nil
}

func (d *DB) UpdateUserProvider(username string, provider string, accessToken string, refreshToken string,
	status string) error {
	if username == "" || provider == "" || accessToken == "" || status == "" {
		return fmt.Errorf("username, provider, accessToken and status must be specified")
	}
	_, err := d.pool.Exec(context.Background(),
		`UPDATE provider_info
		SET access_token = $1,
			refresh_token = $2,
			status = $3,
			updated_at = $4,
			user_code = '',
			device_code = '',
			expires_at = null
		WHERE username = $5 AND provider = $6`,
		accessToken, refreshToken, status, time.Now(), username, provider)
	if err != nil {
		return fmt.Errorf("update provider tokens: %w", err)
	}
	return nil
}

func (d *DB) UpdateUserProviderStatus(username string, provider string, status string) error {
	if username == "" || provider == "" || status == "" {
		return fmt.Errorf("username, provider and status must be specified")
	}
	var err error
	if status == "ready" || status == "pending" {
		_, err = d.pool.Exec(context.Background(),
			`UPDATE provider_info
			SET status = $1,
				updated_at = now()
			WHERE username = $2 AND provider = $3`,
			status, username, provider)
	} else {
		// set user_code and expires_at to '' for non-ready statuses
		_, err = d.pool.Exec(context.Background(),
			`UPDATE provider_info
			SET status = $1,
				updated_at = now(),
				user_code = '',
				device_code = '',
				expires_at = null
			WHERE username = $2 AND provider = $3`,
			status, username, provider)
	}
	if err != nil {
		return fmt.Errorf("update provider status: %w", err)
	}
	return nil
}
