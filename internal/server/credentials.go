// Copyright 2025 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"context"
	"errors"
	"fmt"

	"github.com/k8shell-io/common/pkg/api/client/identity"
	identityv1 "github.com/k8shell-io/common/pkg/api/gen/go/identity/v1"
	"github.com/k8shell-io/common/pkg/models"
)

// provisionGitCredential creates a dynamic git credential row for the user if
// one does not already exist and the provider supports GetUserGitToken.
// It is called synchronously from CompleteUserWebFlow and CompleteUserDeviceFlow.
func (s *Server) provisionGitCredential(ctx context.Context, username string, provider identity.IdpClient) {
	if s.DB == nil {
		return
	}
	// Check whether a row already exists to avoid an unnecessary RPC.
	_, err := s.DB.GetUserCredential(username, "git", provider.Address())
	if err == nil {
		return // row already exists
	}
	if !isNotFound(err) {
		s.log.Warn().Err(err).Msgf("provisionGitCredential: failed to check existing git credential for user '%s'", username)
		return
	}

	token, err := provider.GetUserGitToken(ctx, &identityv1.Username{Username: username})
	if err != nil || token == nil {
		return // provider does not support git tokens or user not yet authorized
	}

	if upsertErr := s.DB.UpsertDynamicGitCredential(username, provider.Address()); upsertErr != nil {
		s.log.Warn().Err(upsertErr).Msgf("provisionGitCredential: failed to upsert git credential for user '%s'", username)
	}
}

// isNotFound returns true when err signals that a record was not found.
func isNotFound(err error) bool {
	return errors.Is(err, models.ErrUserNotFound)
}

// ResolveCredential looks up the stored credential for the given user,
// service_name and service_scope, then resolves it:
//   - Static credentials (registry, git with secret): returned as stored.
//   - Dynamic git credentials (secret empty): token fetched live from the
//     provider whose address matches service_scope (the provider URL, e.g. github.com).
//   - Dynamic kubernetes credentials: a fresh bound service-account token
//     is issued via the TokenRequest API.
//
// Returns models.ErrUserNotFound when no active credential exists.
func (s *Server) ResolveCredential(ctx context.Context, username, serviceName, serviceScope string) (*models.UserCredential, error) {
	if s.DB == nil {
		return nil, fmt.Errorf("database is not configured")
	}
	cred, err := s.DB.GetUserCredential(username, serviceName, serviceScope)
	if err != nil {
		return nil, err
	}
	switch {
	case serviceName == "kubernetes":
		token, _, err := s.issueKubernetesServiceAccountToken(ctx, serviceScope, cred.Subject, 300)
		if err != nil {
			return nil, fmt.Errorf("issue SA token for '%s/%s': %w", serviceScope, cred.Subject, err)
		}
		cred.Secret = token
	case serviceName == "git" && cred.Secret == "":
		provider, ok := s.providerByAddress(serviceScope)
		if !ok {
			return nil, fmt.Errorf("provider with address '%s' not found for dynamic git credential", serviceScope)
		}
		gitToken, err := provider.GetUserGitToken(ctx, &identityv1.Username{Username: username})
		if err != nil {
			return nil, fmt.Errorf("get git token for user '%s' from provider '%s': %w", username, provider.Name(), err)
		}
		cred.Secret = gitToken.GetToken()
	}
	return cred, nil
}
