// Copyright 2025 the k8Shell authors

package server

import (
	"fmt"

	"github.com/k8shell-io/identity/pkg/models"
)

func (s *Server) CreateSSHSession(username string, workspace string, proxyID string, proxyPID int,
	clientIP string) (*models.SSHSession, error) {
	s.log.Debug().Msgf("Creating SSH session for user '%s' in workspace '%s'", username, workspace)
	session, err := s.DB.CreateSSHSession(username, workspace, proxyID, proxyPID, clientIP)
	if err != nil {
		return nil, fmt.Errorf("failed to create SSH session for user '%s': %w", username, err)
	}
	s.log.Info().Msgf("SSH session %d created for user '%s' in workspace '%s'", session.SessionID, username, workspace)
	return session, nil
}

func (s *Server) UpdateSSHSession(username string, sessionID int32, bytesIn int64, bytesOut int64, client string) error {
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

	return nil
}
