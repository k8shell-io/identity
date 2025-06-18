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
			   start_time, end_time, workspace, channels, bytes_in, bytes_out
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
		ProxyID:   &proxy_id,
		ProxyPID:  &proxy_pid,
		Client:    nil,
		ClientIP:  &client_ip,
		StartTime: &now,
		Workspace: workspace,
		BytesIn:   0,
		BytesOut:  0,
		Channels:  []models.ChannelShort{},
	}
	query := ` INSERT INTO sessions (
  username, proxy_id, proxy_pid, client, client_ip,
  start_time, workspace, bytes_in, bytes_out
 ) VALUES (
  $1, $2, $3, $4, $5, $6,
  $7, $8, $9
 ) RETURNING session_id, start_time, end_time, workspace, bytes_in, bytes_out
 `
	err := d.pool.QueryRow(context.Background(), query,
		session.Username, session.ProxyID, session.ProxyPID,
		session.Client, session.ClientIP, session.StartTime, session.Workspace,
		session.BytesIn, session.BytesOut,
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
  WHERE session_id = $3 and username = $4 end_time IS NULL
 `
	_, err := d.pool.Exec(context.Background(), query, bytesIn, bytesOut, sessionID, username)
	if err != nil {
		return fmt.Errorf("failed to update session ID %d bytes: %w", sessionID, err)
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
		WHERE session_id = $2 AND end_time IS NULL
	`
	_, err := d.pool.Exec(context.Background(), query, client, sessionID)
	if err != nil {
		return fmt.Errorf("failed to update session ID %d client: %w", sessionID, err)
	}
	return nil
}

// EndShellSession marks a shell session as ended by setting the end time
func (d *DB) EndSSHSession(sessionID int32) error {
	query := `
		UPDATE sessions
		SET end_time = $1
		WHERE session_id = $2
	`
	now := time.Now()
	_, err := d.pool.Exec(context.Background(), query, now, sessionID)
	if err != nil {
		return fmt.Errorf("failed to end session ID %d: %w", sessionID, err)
	}
	return nil
}
