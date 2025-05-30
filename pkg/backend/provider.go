package backend

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

type ProviderInfo struct {
	Status          string
	CreatedAt       time.Time
	UpdatedAt       time.Time
	Username        string
	Provider        string
	UserCode        string
	VerificationURI string
	AccessToken     string
	RefreshToken    string
}

func (d *DB) GetUserProviderInfo(username string, provider string) (*ProviderInfo, error) {
	query := `SELECT status, created_at, updated_at, username, provider, user_code, verification_uri, access_token, refresh_token
			  FROM provider_info WHERE username = $1 AND provider = $2`
	row := d.pool.QueryRow(context.Background(), query, username, provider)

	var info ProviderInfo
	err := row.Scan(
		&info.Status, &info.CreatedAt, &info.UpdatedAt, &info.Username, &info.Provider,
		&info.UserCode, &info.VerificationURI, &info.AccessToken, &info.RefreshToken,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get provider_info: %w", err)
	}
	return &info, nil
}

func (d *DB) CreateUserProviderInfo(info *ProviderInfo) error {
	query := `INSERT INTO provider_info (
		username, provider, status, created_at, updated_at,
		user_code, verification_uri, access_token, refresh_token
	) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`
	_, err := d.pool.Exec(context.Background(), query,
		info.Username, info.Provider, info.Status, info.CreatedAt, info.UpdatedAt,
		info.UserCode, info.VerificationURI, info.AccessToken, info.RefreshToken)
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

func (d *DB) UpdateUserProviderToken(info *ProviderInfo) error {
	if info == nil {
		return fmt.Errorf("provider info cannot be nil")
	}
	if info.Username == "" || info.Provider == "" {
		return fmt.Errorf("username and provider must be specified")
	}
	if info.AccessToken == "" {
		return fmt.Errorf("access token must be specified")
	}
	if info.Status == "" {
		return fmt.Errorf("status must be specified")
	}
	if info.UpdatedAt.IsZero() {
		info.UpdatedAt = time.Now()
	}
	if info.CreatedAt.IsZero() {
		info.CreatedAt = time.Now()
	}

	_, err := d.pool.Exec(context.Background(),
		`UPDATE provider_info
		SET access_token = $1,
			refresh_token = $2,
			status = $3,
			updated_at = $4
		WHERE username = $5 AND provider = $6`,
		info.AccessToken, info.RefreshToken, info.Status,
		info.UpdatedAt, info.Username, info.Provider)
	if err != nil {
		return fmt.Errorf("update provider token: %w", err)
	}
	return nil
}

func (d *DB) UpdateUserProviderStatus(username string, provider string, status string) error {
	if username == "" || provider == "" || status == "" {
		return fmt.Errorf("username, provider and status must be specified")
	}
	_, err := d.pool.Exec(context.Background(),
		`UPDATE provider_info
		SET status = $1,
			updated_at = now()
		WHERE username = $2 AND provider = $3`,
		status, username, provider)
	if err != nil {
		return fmt.Errorf("update provider status: %w", err)
	}
	return nil
}
