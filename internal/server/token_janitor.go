// Copyright 2025 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"context"
	"time"
)

// accessTokenExpiredRetention is how long an access token is kept in the database
// after it has expired before the janitor deletes it.
const accessTokenExpiredRetention = 6 * time.Hour

// accessTokenJanitorInterval is how often the janitor sweeps for expired access tokens.
const accessTokenJanitorInterval = 1 * time.Hour

// startAccessTokenJanitor starts a background goroutine that periodically deletes
// access tokens that have been expired for longer than accessTokenExpiredRetention.
// It is a no-op when the database is not configured.
func (s *Server) startAccessTokenJanitor(ctx context.Context) {
	if s.DB == nil {
		return
	}
	go s.runAccessTokenJanitor(ctx)
}

func (s *Server) runAccessTokenJanitor(ctx context.Context) {
	s.cleanupExpiredAccessTokens()

	ticker := time.NewTicker(accessTokenJanitorInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.cleanupExpiredAccessTokens()
		}
	}
}

// cleanupExpiredAccessTokens deletes access tokens that expired more than
// accessTokenExpiredRetention ago.
func (s *Server) cleanupExpiredAccessTokens() {
	cutoff := time.Now().Add(-accessTokenExpiredRetention)
	deleted, err := s.DB.DeleteExpiredAccessTokens(cutoff)
	if err != nil {
		s.log.Warn().Err(err).Msg("failed to clean up expired access tokens")
		return
	}
	if deleted > 0 {
		s.log.Info().Msgf("access token janitor deleted %d expired token(s)", deleted)
	}
}
