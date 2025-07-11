// Copyright 2025 the k8Shell authors

package server

import (
	"fmt"

	"github.com/k8shell-io/identity/pkg/models"
)

// CreateSSHSession creates a new SSH session for a user in a specific workspace.
func (s *Server) CreateSSHSession(username string, workspace string, proxyID string, proxyPID int,
	clientIP string) (*models.SSHSession, error) {
	s.log.Debug().Msgf("Creating SSH session for user '%s' in workspace '%s'", username, workspace)
	session, err := s.DB.CreateSSHSession(username, workspace, proxyID, proxyPID, clientIP)
	if err != nil {
		return nil, fmt.Errorf("failed to create SSH session for user '%s': %w", username, err)
	}
	s.log.Debug().Msgf("SSH session %d created for user '%s' in workspace '%s'", session.SessionID, username, workspace)
	return session, nil
}

// UpdateSSHSession updates an existing SSH session with new bytes and client information.
func (s *Server) UpdateSSHSession(username string, sessionID int32, bytesIn int64, bytesOut int64,
	client string, provTime float32, channels []string) error {
	if bytesIn > 0 || bytesOut > 0 {
		err := s.DB.UpdateSSHSessionBytes(username, sessionID, bytesIn, bytesOut)
		if err != nil {
			return fmt.Errorf("failed to update SSH session %d bytes: %w", sessionID, err)
		}
	}

	if client != "" {
		err := s.DB.UpdateSSHSessionClient(username, sessionID, client)
		if err != nil {
			return fmt.Errorf("failed to update SSH session %d client: %w", sessionID, err)
		}
	}

	if provTime > 0 {
		err := s.DB.UpdateSSHSessionProvTime(username, sessionID, provTime)
		if err != nil {
			return fmt.Errorf("failed to update SSH session %d provision time: %w", sessionID, err)
		}
	}

	if len(channels) > 0 {
		err := s.DB.UpdateSSHSessionChannels(username, sessionID, channels)
		if err != nil {
			return fmt.Errorf("failed to update SSH session %d channels: %w", sessionID, err)
		}
	}

	return nil
}

// GetSSHSessions retrieves a list of SSH sessions for a user with pagination and sorting options.
func (s *Server) GetSSHSessions(username string, limit int, offset int, reverse bool) ([]*models.SSHSession, error) {
	s.log.Debug().Msgf("Retrieving SSH sessions for user '%s' with limit %d and offset %d", username, limit, offset)
	sessions, err := s.DB.GetSSHSessions(username, limit, offset, reverse)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve SSH sessions for user '%s': %w", username, err)
	}
	s.log.Debug().Msgf("Retrieved %d SSH sessions for user '%s'", len(sessions), username)
	return sessions, nil
}

// GetSSHSession retrieves a specific SSH session by its ID for a user.
func (s *Server) GetSSHSession(username string, sessionId int32) (*models.SSHSession, error) {
	s.log.Debug().Msgf("Retrieving SSH session '%d' for user '%s'", sessionId, username)
	sessions, err := s.DB.GetSSHSession(username, sessionId)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve SSH session '%d' for user '%s': %w", sessionId, username, err)
	}
	s.log.Debug().Msgf("Retrieved SSH session '%d' for user '%s'", sessionId, username)
	return sessions, nil
}

// EndSSHSession marks an SSH session as ended by setting the end time.
func (s *Server) EndSSHSession(username string, sessionID int32) error {
	s.log.Debug().Msgf("Ending SSH session with ID %d", sessionID)
	err := s.DB.EndSSHSession(username, sessionID)
	if err != nil {
		return fmt.Errorf("failed to end SSH session %d: %w", sessionID, err)
	}
	s.log.Debug().Msgf("SSH session %d ended successfully", sessionID)
	return nil
}
