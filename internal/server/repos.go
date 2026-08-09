// Copyright 2025 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"context"
	"errors"

	"github.com/k8shell-io/common/pkg/api/client/identity"
	identityv1 "github.com/k8shell-io/common/pkg/api/gen/go/identity/v1"
	"github.com/k8shell-io/common/pkg/models"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// repoProviderForUser resolves a username to its stored user record and the
// identity provider that sourced it, which is the provider able to answer
// repository queries on the user's behalf. Repo browsing is always scoped to
// the upstream account the user onboarded with, so there is no fallback to
// other configured providers.
func (s *IdentityService) repoProviderForUser(username string) (*models.User, identity.IdpClient, error) {
	if username == "" {
		return nil, nil, status.Error(codes.InvalidArgument, "username is required")
	}

	user, err := s.server.GetUserByUsername(username, "")
	if err != nil {
		if errors.Is(err, models.ErrUserNotFound) {
			return nil, nil, status.Errorf(codes.NotFound, "user '%s' not found", username)
		}
		return nil, nil, propagateOrInternal(err, "error occurred when getting user '%s': %v", username, err)
	}

	provider, ok := s.server.providerByName(user.Source)
	if !ok {
		return nil, nil, status.Errorf(codes.NotFound,
			"no suitable identity provider found for user '%s'", username)
	}

	return user, provider, nil
}

// ListRepoOwners returns the repository owners — the user's own account plus
// any organizations they belong to — available on the identity provider that
// sourced the user. The login of a returned owner is passed back as
// ListReposRequest.repo_owner to enumerate its repositories.
//
// Providers that don't implement repo browsing (the file provider, for
// instance) surface as Unimplemented rather than being masked as an internal
// error, so callers can hide the repo browser for those users.
func (s *IdentityService) ListRepoOwners(ctx context.Context,
	req *identityv1.Username) (*identityv1.RepoOwnerList, error) {
	user, provider, err := s.repoProviderForUser(req.GetUsername())
	if err != nil {
		return nil, err
	}

	owners, err := provider.ListRepoOwners(ctx, &identityv1.Username{Username: user.Username})
	if err != nil {
		if status.Code(err) == codes.Unimplemented {
			return nil, status.Errorf(codes.Unimplemented,
				"identity provider '%s' does not support listing repo owners", provider.Name())
		}
		return nil, propagateOrInternal(err, "failed to list repo owners for user '%s' with provider '%s': %v",
			user.Username, provider.Name(), err)
	}

	return owners, nil
}

// ListRepos returns the repositories under req.RepoOwner that the user can
// access on the identity provider that sourced them. The owner must be a login
// returned by ListRepoOwners.
func (s *IdentityService) ListRepos(ctx context.Context,
	req *identityv1.ListReposRequest) (*identityv1.RepoList, error) {
	if req.GetRepoOwner() == "" {
		return nil, status.Error(codes.InvalidArgument, "repo_owner is required")
	}

	user, provider, err := s.repoProviderForUser(req.GetUsername())
	if err != nil {
		return nil, err
	}

	repos, err := provider.ListRepos(ctx, &identityv1.ListReposRequest{
		Username:  user.Username,
		RepoOwner: req.GetRepoOwner(),
	})
	if err != nil {
		if status.Code(err) == codes.Unimplemented {
			return nil, status.Errorf(codes.Unimplemented,
				"identity provider '%s' does not support listing repos", provider.Name())
		}
		return nil, propagateOrInternal(err, "failed to list repos for owner '%s' and user '%s' with provider '%s': %v",
			req.GetRepoOwner(), user.Username, provider.Name(), err)
	}

	return repos, nil
}
