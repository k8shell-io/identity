// Copyright 2025 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"context"
	"errors"
	"fmt"
	"time"

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

	if upsertErr := s.DB.UpsertDynamicGitCredential(username, provider.Name(), provider.Address()); upsertErr != nil {
		s.log.Warn().Err(upsertErr).Msgf("provisionGitCredential: failed to upsert git credential for user '%s'", username)
	}
}

// isNotFound returns true when err signals that a record was not found.
func isNotFound(err error) bool {
	return errors.Is(err, models.ErrUserNotFound)
}

// ResolveCredential looks up the stored credential for the given user,
// service_name and service_scope, then resolves it according to credential_source:
//   - "stored": secret returned as-is (registry, static git).
//   - "kubernetes": fresh bound SA token issued via the TokenRequest API.
//   - any other value: treated as an IDP name; token fetched live via GetUserGitToken
//     (dynamic git provisioned by CompleteUserWebFlow / CompleteUserDeviceFlow).
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
	switch cred.CredentialSource {
	case "kubernetes":
		if s.k8sCfg.SAToken.Enabled != nil && !*s.k8sCfg.SAToken.Enabled {
			return nil, fmt.Errorf("kubernetes service-account token issuance is disabled")
		}
		ttl := int64(s.k8sCfg.SAToken.TTL.Seconds())
		token, expiresAt, err := s.issueKubernetesServiceAccountToken(ctx, serviceScope, cred.Subject, ttl)
		if err != nil {
			return nil, fmt.Errorf("issue SA token for '%s/%s': %w", serviceScope, cred.Subject, err)
		}
		cred.Secret = token
		cred.ExpiresAt = &expiresAt

	case "stored":
		// secret already populated from DB — nothing to do

	default:
		// credential_source holds the IDP name (e.g. "github", "gitlab")
		provider, ok := s.providerByName(cred.CredentialSource)
		if !ok {
			return nil, fmt.Errorf("provider '%s' not found for dynamic git credential", cred.CredentialSource)
		}
		gitToken, err := provider.GetUserGitToken(ctx, &identityv1.Username{Username: username})
		if err != nil {
			return nil, fmt.Errorf("get git token for user '%s' from provider '%s': %w", username, provider.Name(), err)
		}
		cred.Secret = gitToken.GetToken()
	}

	if err := s.DB.TouchUserCredentialLastUsed(cred.ID); err != nil {
		s.log.Warn().Err(err).Msgf("ResolveCredential: failed to update last_used_at for credential id %d", cred.ID)
	} else {
		now := time.Now()
		cred.LastUsedAt = &now
	}
	return cred, nil
}
