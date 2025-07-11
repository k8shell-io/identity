package backend

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/k8shell-io/identity/pkg/models"
)

// FindSession retrieves a session by its ID
func (d *DB) FindSSHSession(sessionID int32) (*models.SSHSession, error) {
	query := `
		SELECT session_id, username, proxy_id, proxy_pid, client, client_ip,
			   start_time, end_time, workspace, channels, bytes_in, bytes_out, prov_time, channels
		FROM public.sessions
		WHERE session_id = $1
	`

	var session models.SSHSession
	err := d.pool.QueryRow(context.Background(), query, sessionID).Scan(
		&session.SessionID,
		&session.Username,
		&session.ProxyID,
		&session.ProxyPID,
		&session.Client,
		&session.ClientIP,
		&session.StartTime,
		&session.EndTime,
		&session.Workspace,
		&session.Channels,
		&session.BytesIn,
		&session.BytesOut,
		&session.ProvTime,
		&session.Channels,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, models.ErrSessionNotFound
	} else if err != nil {
		return nil, err
	}

	return &session, nil
}

// CreateShellSession creates a new shell session in the database
func (d *DB) CreateSSHSession(username string, workspace string, proxy_id string,
	proxy_pid int, client_ip string) (*models.SSHSession, error) {

	if username == "" {
		return nil, errors.New("username cannot be empty")
	}
	if workspace == "" {
		return nil, errors.New("workspace cannot be empty")
	}
	if proxy_id == "" {
		return nil, errors.New("proxy_id cannot be empty")
	}
	if proxy_pid <= 0 {
		return nil, errors.New("proxy_pid must be greater than 0")
	}
	ip := net.ParseIP(client_ip)
	if ip == nil {
		return nil, fmt.Errorf("invalid client IP address: %s", client_ip)
	}

	now := time.Now()
	session := &models.SSHSession{
		Username:  username,
		ProxyID:   proxy_id,
		ProxyPID:  proxy_pid,
		Client:    "",
		ClientIP:  client_ip,
		StartTime: &now,
		Workspace: workspace,
		BytesIn:   0,
		BytesOut:  0,
		Channels:  []models.ChannelShort{},
		ProvTime:  0.0,
	}
	query := ` INSERT INTO sessions (
  username, proxy_id, proxy_pid, client, client_ip,
  start_time, workspace, bytes_in, bytes_out, prov_time, channels
 ) VALUES (
  $1, $2, $3, $4, $5, $6,
  $7, $8, $9, $10, $11
 ) RETURNING session_id, start_time, end_time, workspace, bytes_in, bytes_out
 `
	err := d.pool.QueryRow(context.Background(), query,
		session.Username, session.ProxyID, session.ProxyPID,
		session.Client, session.ClientIP, session.StartTime, session.Workspace,
		session.BytesIn, session.BytesOut, session.ProvTime, session.Channels,
	).Scan(
		&session.SessionID,
		&session.StartTime,
		&session.EndTime,
		&session.Workspace,
		&session.BytesIn,
		&session.BytesOut,
	)
	if err != nil {
		return nil, err
	}
	return session, nil
}

// UpdateShellSessionBytes updates the bytes in and out for a shell session
func (d *DB) UpdateSSHSessionBytes(username string, sessionID int32, bytesIn int64, bytesOut int64) error {
	query := `
		UPDATE sessions
		SET bytes_in = $1, bytes_out = $2
		WHERE session_id = $3 AND username = $4 AND end_time IS NULL
	`
	tag, err := d.pool.Exec(context.Background(), query, bytesIn, bytesOut, sessionID, username)
	if err != nil {
		return fmt.Errorf("failed to update session ID %d bytes: %w", sessionID, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("%w: session ID %d not found", models.ErrActiveSessionNotFound, sessionID)
	}
	return nil
}

// UpdateShellSessionClient updates the client information for a shell session
func (d *DB) UpdateSSHSessionClient(username string, sessionID int32, client string) error {
	if client == "" {
		return errors.New("client cannot be empty")
	}
	query := `
		UPDATE sessions
		SET client = $1
		WHERE session_id = $2 AND username = $3 AND end_time IS NULL
	`
	tag, err := d.pool.Exec(context.Background(), query, client, sessionID, username)
	if err != nil {
		return fmt.Errorf("failed to update session ID %d client: %w", sessionID, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("%w: session ID %d not found", models.ErrActiveSessionNotFound, sessionID)
	}
	return nil
}

// EndShellSession marks a shell session as ended by setting the end time
func (d *DB) EndSSHSession(username string, sessionID int32) error {
	query := `
		UPDATE sessions
		SET end_time = $1
		WHERE session_id = $2 AND username = $3 AND end_time IS NULL
	`
	now := time.Now()
	tag, err := d.pool.Exec(context.Background(), query, now, sessionID, username)
	if err != nil {
		return fmt.Errorf("failed to end session ID %d: %w", sessionID, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("%w: session ID %d not found", models.ErrActiveSessionNotFound, sessionID)
	}
	return nil
}

// GetSSHSessions retrieves a list of SSH sessions for a user with pagination and sorting options
func (d *DB) GetSSHSessions(username string, limit int, offset int, reverse bool) ([]*models.SSHSession, error) {
	limit, offset = AdjustListLimit(limit, offset)

	order := "ASC"
	if reverse {
		order = "DESC"
	}

	query := fmt.Sprintf(`
		SELECT session_id, username, proxy_id, proxy_pid, client, client_ip,
			   start_time, end_time, workspace, channels, bytes_in, bytes_out, prov_time, channels
		FROM public.sessions
		WHERE username = $1
		ORDER BY start_time %s
		LIMIT $2 OFFSET $3
	`, order)

	rows, err := d.pool.Query(context.Background(), query, username, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve sessions for user '%s': %w", username, err)
	}
	defer rows.Close()

	var sessions []*models.SSHSession
	for rows.Next() {
		var session models.SSHSession
		if err := rows.Scan(
			&session.SessionID,
			&session.Username,
			&session.ProxyID,
			&session.ProxyPID,
			&session.Client,
			&session.ClientIP,
			&session.StartTime,
			&session.EndTime,
			&session.Workspace,
			&session.Channels,
			&session.BytesIn,
			&session.BytesOut,
			&session.ProvTime,
			&session.Channels,
		); err != nil {
			return nil, fmt.Errorf("failed to scan session row: %w", err)
		}
		sessions = append(sessions, &session)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating over session rows: %w", err)
	}

	return sessions, nil
}

func (d *DB) GetSSHSession(username string, sessionId int32) (*models.SSHSession, error) {
	query := `
		SELECT session_id, username, proxy_id, proxy_pid, client, client_ip,
			   start_time, end_time, workspace, channels, bytes_in, bytes_out, prov_time, channels
		FROM public.sessions
		WHERE username = $1 AND session_id = $2
	`

	rows, err := d.pool.Query(context.Background(), query, username, sessionId)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve session '%s' for user '%s'", username, err)
	}
	defer rows.Close()

	var session models.SSHSession
	if !rows.Next() {
		return nil, fmt.Errorf("%w: session '%d' for user '%s' not found", models.ErrSessionNotFound, sessionId, username)
	}
	if err := rows.Scan(
		&session.SessionID,
		&session.Username,
		&session.ProxyID,
		&session.ProxyPID,
		&session.Client,
		&session.ClientIP,
		&session.StartTime,
		&session.EndTime,
		&session.Workspace,
		&session.Channels,
		&session.BytesIn,
		&session.BytesOut,
		&session.ProvTime,
		&session.Channels,
	); err != nil {
		return nil, fmt.Errorf("failed to scan session row: %w", err)
	}

	return &session, nil
}

func (db *DB) UpdateSSHSessionProvTime(username string, sessionID int32, provTime float32) error {
	if provTime <= 0 {
		return errors.New("provision time must be greater than 0")
	}

	query := `
		UPDATE sessions
		SET prov_time = $1
		WHERE session_id = $2 AND username = $3 AND end_time IS NULL
	`
	tag, err := db.pool.Exec(context.Background(), query, provTime, sessionID, username)
	if err != nil {
		return fmt.Errorf("failed to update session ID %d provision time: %w", sessionID, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("%w: session ID %d not found", models.ErrActiveSessionNotFound, sessionID)
	}
	return nil
}

// UpdateSSHSessionChannels updates the channels for an SSH session
func (db *DB) UpdateSSHSessionChannels(username string, sessionID int32, channels []string) error {
	if len(channels) == 0 {
		return errors.New("channels cannot be empty")
	}

	query := `
		UPDATE sessions
		SET channels = $1
		WHERE session_id = $2 AND username = $3 AND end_time IS NULL
	`
	tag, err := db.pool.Exec(context.Background(), query, channels, sessionID, username)
	if err != nil {
		return fmt.Errorf("failed to update session ID %d channels: %w", sessionID, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("%w: session ID %d not found", models.ErrActiveSessionNotFound, sessionID)
	}
	return nil
}
