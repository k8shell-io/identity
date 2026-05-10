// Copyright 2025 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"context"
	"errors"

	commonv1 "github.com/k8shell-io/common/pkg/api/gen/go/common/v1"
	identityv1 "github.com/k8shell-io/common/pkg/api/gen/go/identity/v1"
	"github.com/k8shell-io/common/pkg/gapi"
	"github.com/k8shell-io/common/pkg/models"
	"github.com/k8shell-io/common/pkg/userstr"
	"github.com/k8shell-io/common/pkg/utils"
	"github.com/rs/zerolog"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// propagateOrInternal returns the error unchanged when its gRPC status code is
// PermissionDenied or Unauthenticated (so upstream IDP rejections are forwarded
// to the caller). All other errors are returned as codes.Internal with the
// supplied message format.
func propagateOrInternal(err error, format string, args ...interface{}) error {
	switch status.Code(err) {
	case codes.PermissionDenied, codes.Unauthenticated, codes.NotFound:
		return err
	}
	return status.Errorf(codes.Internal, format, args...)
}

// IdentityService implements the identity gRPC service.
type IdentityService struct {
	server *Server
	log    *zerolog.Logger
	identityv1.UnimplementedIdentityServiceServer
}

// NewIdentityService returns a new IdentityService.
func NewIdentityService(server *Server) *IdentityService {
	return &IdentityService{
		server: server,
		log:    server.log,
	}
}

// GetUserAccessToken returns the current JWT for the requested user.
// Kubernetes must be configured; the Secret is the source of truth for the token.
func (s *IdentityService) IssueUserToken(ctx context.Context,
	req *identityv1.IssueUserTokenRequest) (*identityv1.IssueUserTokenResponse, error) {
	if req.Username == "" {
		return nil, status.Error(codes.InvalidArgument, "username is required")
	}

	user, err := s.server.GetUserByUsername(req.Username)
	if err != nil {
		if errors.Is(err, models.ErrUserNotFound) {
			return nil, status.Errorf(codes.NotFound, "user '%s' not found", req.Username)
		}
		return nil, propagateOrInternal(err, "error occurred when getting user '%s': %v", req.Username, err)
	}

	token, err := s.server.issueUserToken(user)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to issue token for user '%s': %v",
			req.Username, err)
	}

	return &identityv1.IssueUserTokenResponse{UserToken: token}, nil
}

// GetUsers retrieves users with pagination support.
func (s *IdentityService) GetUsers(ctx context.Context, req *identityv1.GetUsersRequest) (*identityv1.UserList, error) {
	if s.server.DB == nil {
		userList := make([]*commonv1.User, 0)
		localUsers := s.server.getLocalUsers()

		for inx, user := range localUsers {
			if inx < int(req.Offset) {
				continue
			}
			userList = append(userList, gapi.UserToProto(user))
			if len(userList) >= int(req.Limit) {
				break
			}
		}
		return &identityv1.UserList{Users: userList}, nil
	}

	users, err := s.server.DB.ListUsers(int(req.Limit), int(req.Offset))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to list users: %v", err)
	}

	pbUsers := make([]*commonv1.User, len(users))
	for i, user := range users {
		pbUsers[i] = gapi.UserToProto(user)
	}

	return &identityv1.UserList{Users: pbUsers}, nil
}

// FindUser looks up a user by username or access token.
func (s *IdentityService) FindUser(ctx context.Context, req *identityv1.FindUserRequest) (*commonv1.User, error) {
	if req.Username != "" && req.Token != "" {
		return nil, status.Error(codes.InvalidArgument, "only one of username or token can be provided")
	}
	if req.Username == "" && req.Token == "" {
		return nil, status.Error(codes.InvalidArgument, "no username or token provided")
	}

	if req.Username != "" {
		user, err := s.server.GetUserByUsername(req.Username)
		if err != nil {
			if errors.Is(err, models.ErrUserNotFound) {
				return nil, status.Error(codes.NotFound, "user not found")
			}
			s.log.Error().Err(err).Msg("failed to get user")
			return nil, propagateOrInternal(err, "failed to get user")
		}
		return gapi.UserToProto(user), nil
	}

	if req.Token != "" {
		user, err := s.server.GetUserByAccessToken(req.Token)
		if err != nil {
			if errors.Is(err, models.ErrUserNotFound) {
				return nil, status.Error(codes.NotFound, "user not found by token")
			}
			s.log.Error().Err(err).Msg("failed to get user by token")
			return nil, status.Errorf(codes.Internal, "failed to get user by token: %v", err)
		}
		if user == nil {
			return nil, status.Error(codes.NotFound, "user not found for the provided token")
		}
		return gapi.UserToProto(user), nil
	}

	return nil, status.Error(codes.InvalidArgument, "invalid request: must provide either username or token")
}

// AuthUserPublicKey authenticates a user using an SSH public key.
func (s *IdentityService) AuthUserPublicKey(ctx context.Context,
	req *identityv1.AuthUserPublicKeyRequest) (*identityv1.AuthUserResponse, error) {

	user, err := s.server.GetUserByUsername(req.Username)
	if err != nil && !errors.Is(err, models.ErrUserNotFound) {
		return nil, propagateOrInternal(err, "error occured when finding user '%s': %s",
			req.Username, err.Error())
	}

	parsedKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(req.PublicKey))
	if err != nil {
		s.log.Warn().Msgf("Failed to parse provided public key for user '%s': %v", req.Username, err)
		return nil, nil
	}

	// authenticate the user with the public key using the identity providers
	provider, ok := s.server.providerByName(user.Source)
	if !ok {
		return nil, status.Errorf(codes.NotFound, "no suitable identity provider found for user '%s'", req.Username)
	}
	authpb, err := provider.AuthUserPublicKey(context.Background(), &identityv1.AuthUserPublicKeyRequest{
		Username:  req.Username,
		PublicKey: string(ssh.MarshalAuthorizedKey(parsedKey)),
	})
	if err != nil {
		return nil, propagateOrInternal(err, "failed to authenticate user '%s' with provider '%s': %s",
			req.Username, provider.Name(), err.Error())
	}
	return authpb, nil
}

// GetUserOnboardCapability returns onboarding capability information for a user.
func (s *IdentityService) GetUserOnboardCapability(ctx context.Context,
	req *identityv1.Username) (*commonv1.UserOnboardCapability, error) {
	for _, provider := range s.server.orderedProviders("") {
		cap, err := provider.OnboardUserCapability(context.Background(), &identityv1.Username{
			Username: req.Username,
		})
		if err != nil {
			switch status.Code(err) {
			case codes.PermissionDenied, codes.Unauthenticated:
				return nil, err
			}
			if !errors.Is(err, models.ErrMethodNotSupported) && !errors.Is(err, models.ErrUserNotAllowedOnboard) {
				s.log.Error().Msgf("Failed to get onboard capability for user '%s' from provider '%s': %v",
					req.Username, provider.Name(), err)
				continue
			}
		}
		if cap != nil {
			return cap, nil
		}
	}
	return nil, status.Errorf(codes.NotFound, "no onboarding capability found for user '%s'", req.Username)
}

// OnboardUserDeviceFlow starts device-flow onboarding for a user.
func (s *IdentityService) OnboardUserDeviceFlow(ctx context.Context,
	req *identityv1.OnboardUserDeviceFlowRequest) (*commonv1.OnboardUserDeviceFlow, error) {
	provider, ok := s.server.providerByName(req.Provider)
	if !ok {
		return nil, status.Errorf(codes.NotFound,
			"no suitable identity provider found for onboarding via device flow with provider '%s'", req.Provider)
	}

	onboardUserpb, err := provider.OnboardUserDeviceFlow(context.Background(),
		&identityv1.OnboardUserDeviceFlowRequest{
			Provider: req.Provider,
			Username: req.Username,
		})
	if err != nil && !errors.Is(err, models.ErrMethodNotSupported) {
		return nil, propagateOrInternal(err, "failed to onboard user '%s' with provider '%s': %v",
			req.Username, provider.Name(), err)
	}
	if onboardUserpb != nil {
		return onboardUserpb, nil
	}
	return nil, status.Errorf(codes.NotFound, "no onboarding device flow found for user '%s'", req.Username)
}

// OnboardUserWebFlow starts web-flow onboarding for the requested provider.
func (s *IdentityService) OnboardUserWebFlow(ctx context.Context,
	req *identityv1.OnboardUserWebFlowRequest) (*commonv1.OnboardUserWebFlow, error) {
	provider, ok := s.server.providerByName(req.Provider)
	if !ok {
		return nil, status.Errorf(codes.NotFound,
			"no suitable identity provider found for onboarding via web flow with provider '%s'", req.Provider)
	}
	authInfo, err := provider.OnboardUserWebFlow(context.Background(), &identityv1.OnboardUserWebFlowRequest{
		Provider:    req.Provider,
		RedirectUri: req.RedirectUri,
	})
	if err != nil {
		return nil, propagateOrInternal(err, "failed to onboard user via web flow with provider '%s': %v",
			req.Provider, err)
	}
	return authInfo, nil
}

// CompleteUserWebFlow completes web-flow onboarding and returns the resolved user.
func (s *IdentityService) CompleteUserWebFlow(ctx context.Context,
	req *identityv1.CompleteUserWebFlowRequest) (*identityv1.CompleteUserWebFlowResponse, error) {
	provider, _, err := utils.DecodeState(req.State)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to decode web flow state: %v", err)
	}

	p, ok := s.server.providerByName(provider)
	if !ok {
		return nil, status.Errorf(codes.NotFound,
			"no suitable identity provider found to complete web flow for provider '%s'", provider)
	}
	username, err := p.CompleteUserWebFlow(context.Background(), &identityv1.CompleteUserWebFlowRequest{
		State: req.State,
		Code:  req.Code,
	})
	if err != nil {
		return nil, propagateOrInternal(err, "failed to complete web flow for provider '%s': %v", provider, err)
	}

	user, err := s.server.GetUserByUsername(username.GetUsername())
	if err != nil {
		return nil, propagateOrInternal(err, "failed to get user '%s' after completing web flow for provider '%s': %v",
			username.GetUsername(), provider, err)
	}

	token, err := s.server.issueUserToken(user)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to issue token for user '%s'", user.Username)
	}

	if s.server.DB != nil {
		s.server.provisionGitCredential(ctx, username.GetUsername(), p)
	}

	return &identityv1.CompleteUserWebFlowResponse{
		UserToken: token,
	}, nil
}

// CompleteUserDeviceFlow is called by the client after the user has completed
// device-flow authorization on the provider side. It provisions the dynamic git
// credential for the user and returns an empty response.
func (s *IdentityService) CompleteUserDeviceFlow(ctx context.Context,
	req *identityv1.CompleteUserDeviceFlowRequest) (*identityv1.CompleteUserDeviceFlowResponse, error) {
	if req.Username == "" || req.Provider == "" {
		return nil, status.Error(codes.InvalidArgument, "username and provider are required")
	}

	provider, ok := s.server.providerByName(req.Provider)
	if !ok {
		return nil, status.Errorf(codes.NotFound,
			"no suitable identity provider found to complete device flow for provider '%s'", req.Provider)
	}

	if s.server.DB != nil {
		s.server.provisionGitCredential(ctx, req.Username, provider)
	}

	return &identityv1.CompleteUserDeviceFlowResponse{}, nil
}

// GetBlueprintByUserStr resolves and returns a blueprint for the provided user string.
func (s *IdentityService) GetBlueprintByUserStr(ctx context.Context,
	req *identityv1.UserStr) (*identityv1.Blueprint, error) {

	userStr, err := userstr.ParseUserStr(req.Userstr)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid user string: %v", err)
	}

	user, err := s.server.GetUserByUsername(userStr.Username())
	if err != nil {
		return nil, propagateOrInternal(err, "error occurred when getting user '%s': %v", userStr.Username(), err)
	}

	provider, ok := s.server.providerByName(user.Source)
	if !ok {
		return nil, status.Errorf(codes.NotFound, "no suitable identity provider found for user '%s'", userStr.Username())
	}
	blueprintpb, err := provider.GetBlueprintByUserStr(context.Background(), &identityv1.UserStr{
		Userstr: userStr.Raw(),
	})
	if err != nil {
		return nil, propagateOrInternal(err, "failed to get custom blueprint for '%s' with provider '%s': %v",
			userStr.Username(), provider.Name(), err)
	}
	return blueprintpb, nil
}

// ResolvePullRequestToRef resolves a repository pull request to its reference.
func (s *IdentityService) ResolvePullRequestToRef(ctx context.Context,
	req *identityv1.RepoPullRequestRequest) (*identityv1.RepoRefResponse, error) {

	user, err := s.server.GetUserByUsername(req.Username)
	if err != nil {
		return nil, propagateOrInternal(err, "error occurred when getting user '%s': %v", req.Username, err)
	}

	provider, ok := s.server.providerByName(user.Source)
	if !ok {
		return nil, status.Errorf(codes.NotFound, "no suitable identity provider found for user '%s'", req.Username)
	}
	repoRef, err := provider.ResolvePullRequestToRef(context.Background(), &identityv1.RepoPullRequestRequest{
		Username:          req.Username,
		RepoOwner:         req.RepoOwner,
		RepoName:          req.RepoName,
		PullRequestNumber: int32(req.PullRequestNumber),
	})
	if err != nil {
		return nil, propagateOrInternal(err, "failed to resolve pull request to ref for '%s' with provider '%s': %v",
			req.Username, provider.Name(), err)
	}
	return repoRef, nil
}

// ListUserCredentials returns all stored credentials for a user.
func (s *IdentityService) ListUserCredentials(ctx context.Context,
	req *identityv1.Username) (*identityv1.ListUserCredentialsResponse, error) {
	if s.server.DB == nil {
		return nil, status.Errorf(codes.Unavailable, "database is not configured, cannot retrieve user credentials")
	}

	_, err := s.server.GetUserByUsername(req.Username)
	if err != nil {
		if errors.Is(err, models.ErrUserNotFound) {
			return nil, status.Errorf(codes.NotFound, "user '%s' not found", req.Username)
		}
		return nil, propagateOrInternal(err, "error occurred when getting user '%s': %v", req.Username, err)
	}

	creds, err := s.server.DB.ListUserCredentials(req.Username)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get credentials for user '%s': %v", req.Username, err)
	}

	pbCredentials := make([]*commonv1.UserCredential, len(creds))
	for i, cred := range creds {
		pbCredentials[i] = gapi.UserCredentialToProto(cred)
	}

	return &identityv1.ListUserCredentialsResponse{Credentials: pbCredentials}, nil
}

// GetUserCredential resolves a single credential for a user by service name and scope.
// For kubernetes credentials a fresh service account token is issued on the fly.
func (s *IdentityService) GetUserCredential(ctx context.Context,
	req *identityv1.GetUserCredentialRequest) (*commonv1.UserCredential, error) {
	if s.server.DB == nil {
		return nil, status.Errorf(codes.Unavailable, "database is not configured, cannot retrieve user credential")
	}

	cred, err := s.server.ResolveCredential(ctx, req.Username, req.ServiceName, req.ServiceScope)
	if err != nil {
		if errors.Is(err, models.ErrUserNotFound) {
			return nil, status.Errorf(codes.NotFound, "credential not found for user '%s', service '%s', scope '%s'",
				req.Username, req.ServiceName, req.ServiceScope)
		}
		return nil, status.Errorf(codes.Internal, "failed to resolve credential: %v", err)
	}

	return gapi.UserCredentialToProto(cred), nil
}

// AddUserCredential adds an external credential for a user.
func (s *IdentityService) AddUserCredential(ctx context.Context,
	req *commonv1.UserCredential) (*identityv1.AddUserCredentialResponse, error) {
	if s.server.DB == nil {
		return nil, status.Errorf(codes.Unavailable, "database is not configured, cannot add user credential")
	}

	credential := gapi.ProtoToUserCredential(req)

	err := s.server.DB.AddUserCredential(credential)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to add user credential: %v", err)
	}

	return &identityv1.AddUserCredentialResponse{Credential: req}, nil
}

// UpdateUserCredential updates an existing external credential.
func (s *IdentityService) UpdateUserCredential(ctx context.Context,
	req *commonv1.UserCredential) (*identityv1.UpdateUserCredentialResponse, error) {
	if s.server.DB == nil {
		return nil, status.Errorf(codes.Unavailable, "database is not configured, cannot update user credential")
	}

	credential := gapi.ProtoToUserCredential(req)

	err := s.server.DB.UpdateUserCredential(credential)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to update user credential: %v", err)
	}

	return &identityv1.UpdateUserCredentialResponse{Credential: req}, nil
}

// DeleteUserCredential deletes an external credential by ID.
func (s *IdentityService) DeleteUserCredential(ctx context.Context,
	req *identityv1.DeleteUserCredentialRequest) (*identityv1.DeleteUserCredentialResponse, error) {
	if s.server.DB == nil {
		return nil, status.Errorf(codes.Unavailable, "database is not configured, cannot delete user credential")
	}

	err := s.server.DB.DeleteUserCredential(req.Id)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to delete user credential: %v", err)
	}

	return &identityv1.DeleteUserCredentialResponse{Success: true}, nil
}

func (s *IdentityService) GetAvailableIdentityProviders(
	ctx context.Context,
	req *identityv1.GetAvailableIdentityProvidersRequest,
) (*identityv1.GetAvailableIdentityProvidersResponse, error) {
	activeProviders := s.server.orderedProviders("")
	resp := make([]*identityv1.IdentityProviderInfo, len(activeProviders))
	for i, activeProvider := range activeProviders {
		resp[i] = &identityv1.IdentityProviderInfo{
			Name: activeProvider.Name(),
		}
	}

	return &identityv1.GetAvailableIdentityProvidersResponse{
		Providers: resp,
	}, nil
}
