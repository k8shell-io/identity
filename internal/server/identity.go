package server

import (
	"context"
	"errors"
	"fmt"

	"github.com/k8shell-io/common/pkg/gapi"
	commonpb "github.com/k8shell-io/common/pkg/gapi/commonpb"
	"github.com/k8shell-io/common/pkg/models"
	"github.com/k8shell-io/common/pkg/utils"
	"github.com/k8shell-io/identity/pkg/api/identitypb"
	"github.com/k8shell-io/identity/pkg/api/typespb"
	"github.com/rs/zerolog"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// IdentityService implements the identity gRPC service.
type IdentityService struct {
	server *Server
	log    *zerolog.Logger
	identitypb.UnimplementedIdentityServiceServer
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
// If the token is absent or near expiry it is re-issued before reading.
func (s *IdentityService) GetUserAccessToken(ctx context.Context, req *identitypb.GetUserAccessTokenRequest) (*identitypb.GetUserAccessTokenResponse, error) {
	if req.Username == "" {
		return nil, status.Error(codes.InvalidArgument, "username is required")
	}

	if s.server.k8sClient == nil {
		return nil, status.Error(codes.FailedPrecondition, "Kubernetes is not configured")
	}

	user, err := s.server.GetUserByUsername(req.Username)
	if err != nil {
		if errors.Is(err, models.ErrUserNotFound) {
			return nil, status.Errorf(codes.NotFound, "user '%s' not found", req.Username)
		}
		s.log.Error().Err(err).Msgf("GetUserAccessToken: failed to get user '%s'", req.Username)
		return nil, status.Errorf(codes.Internal, "failed to get user '%s'", req.Username)
	}

	if err := s.server.ensureToken(user); err != nil {
		s.log.Error().Err(err).Msgf("GetUserAccessToken: failed to ensure token for user '%s'", req.Username)
		return nil, status.Errorf(codes.Internal, "failed to issue token for user '%s'", req.Username)
	}

	token, err := s.server.getTokenFromKubernetesSecret(req.Username)
	if err != nil {
		s.log.Error().Err(err).Msgf("GetUserAccessToken: failed to read k8s secret for user '%s'", req.Username)
		return nil, status.Errorf(codes.Internal, "failed to read token secret for user '%s'", req.Username)
	}
	return &identitypb.GetUserAccessTokenResponse{AccessToken: token}, nil
}

// GetUsers retrieves users with pagination support.
func (s *IdentityService) GetUsers(ctx context.Context, req *typespb.GetUsersRequest) (*typespb.UserList, error) {
	if s.server.DB == nil {
		userList := make([]*commonpb.User, 0)
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
		return &typespb.UserList{Users: userList}, nil
	}

	users, err := s.server.DB.ListUsers(int(req.Limit), int(req.Offset))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to list users: %v", err)
	}

	pbUsers := make([]*commonpb.User, len(users))
	for i, user := range users {
		pbUsers[i] = gapi.UserToProto(user)
	}

	return &typespb.UserList{Users: pbUsers}, nil
}

// FindUser looks up a user by username or access token.
func (s *IdentityService) FindUser(ctx context.Context, req *typespb.FindUserRequest) (*commonpb.User, error) {
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
			return nil, status.Error(codes.Internal, "failed to get user")
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
	req *typespb.AuthUserPublicKeyRequest) (*typespb.AuthUserResponse, error) {

	user, err := s.server.GetUserByUsername(req.Username)
	if err != nil && !errors.Is(err, models.ErrUserNotFound) {
		return nil, status.Errorf(codes.Internal, "error occured when finding user '%s': %s",
			req.Username, err.Error())
	}

	parsedKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(req.PublicKey))
	if err != nil {
		s.log.Warn().Msgf("Failed to parse provided public key for user '%s': %v", req.Username, err)
		return nil, nil
	}

	// authenticate the user with the public key using the identity providers
	for _, provider := range s.server.IdentityProviders {
		if provider.Name() == user.Source {
			authpb, err := provider.AuthUserPublicKey(context.Background(), &typespb.AuthUserPublicKeyRequest{
				Username:  req.Username,
				PublicKey: string(ssh.MarshalAuthorizedKey(parsedKey)),
			})
			if err != nil {
				return nil, status.Errorf(codes.Internal, "failed to authenticate user '%s' with provider '%s': %s",
					req.Username, provider.Name(), err.Error())
			}
			return authpb, nil
		}
	}

	return nil, nil
}

// GetUserOnboardCapability returns onboarding capability information for a user.
func (s *IdentityService) GetUserOnboardCapability(ctx context.Context,
	req *typespb.Username) (*commonpb.UserOnboardCapability, error) {
	for _, provider := range s.server.IdentityProviders {
		cap, err := provider.OnboardCapability(context.Background(), &typespb.Username{
			Username: req.Username,
		})
		if err != nil && !errors.Is(err, models.ErrMethodNotSupported) &&
			!errors.Is(err, models.ErrUserNotAllowedOnboard) {
			return nil, status.Errorf(codes.Internal, "failed to get onboard capability for user '%s' from provider '%s': %v", req.Username, provider.Name(), err)
		}
		if cap != nil {
			return cap, nil
		}
	}
	return nil, status.Errorf(codes.NotFound, "no onboarding capability found for user '%s'", req.Username)
}

// OnboardUserDeviceFlow starts device-flow onboarding for a user.
func (s *IdentityService) OnboardUserDeviceFlow(ctx context.Context,
	req *typespb.Username) (*commonpb.OnboardUserDeviceFlow, error) {
	for _, provider := range s.server.IdentityProviders {
		onboardUserpb, err := provider.OnboardUserDeviceFlow(context.Background(), &typespb.Username{
			Username: req.Username,
		})
		if err != nil && !errors.Is(err, models.ErrMethodNotSupported) {
			return nil, status.Errorf(codes.Internal, "failed to onboard user '%s' with provider '%s': %v",
				req.Username, provider.Name(), err)
		}
		if onboardUserpb != nil {
			return onboardUserpb, nil
		}
	}
	return nil, status.Errorf(codes.NotFound, "no onboarding device flow found for user '%s'", req.Username)
}

// OnboardUserWebFlow starts web-flow onboarding for the requested provider.
func (s *IdentityService) OnboardUserWebFlow(ctx context.Context,
	req *typespb.OnboardUserWebFlowRequest) (*commonpb.OnboardUserWebFlow, error) {
	for _, provider := range s.server.IdentityProviders {
		if provider.Name() == req.Provider {
			authInfo, err := provider.OnboardUserWebFlow(context.Background(), &typespb.OnboardUserWebFlowRequest{
				Provider:    req.Provider,
				RedirectUri: req.RedirectUri,
			})
			if err != nil {
				return nil, status.Errorf(codes.Internal, "failed to onboard user via web flow with provider '%s': %v",
					req.Provider, err)
			}
			return authInfo, nil
		}
	}
	return nil, status.Errorf(codes.NotFound,
		"no suitable identity provider found for onboarding via web flow with provider '%s'", req.Provider)
}

// CompleteUserWebFlow completes web-flow onboarding and returns the resolved user.
func (s *IdentityService) CompleteUserWebFlow(ctx context.Context,
	req *typespb.CompleteUserWebFlowRequest) (*commonpb.User, error) {
	provider, _, err := utils.DecodeState(req.State)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to decode web flow state: %v", err)
	}

	for _, p := range s.server.IdentityProviders {
		if p.Name() == provider {
			username, err := p.CompleteUserWebFlow(context.Background(), &typespb.CompleteUserWebFlowRequest{
				State: req.State,
				Code:  req.Code,
			})
			if err != nil {
				return nil, status.Errorf(codes.Internal,
					"failed to complete web flow for provider '%s': %v", provider, err)
			}

			user, err := s.server.GetUserByUsername(username.GetUsername())
			if err != nil {
				return nil, status.Errorf(codes.Internal,
					"failed to get user '%s' after completing web flow for provider '%s': %v",
					username.GetUsername(), provider, err)
			}

			return gapi.UserToProto(user), nil
		}
	}
	return nil, status.Errorf(codes.NotFound,
		"no suitable identity provider found to complete web flow for provider '%s'", provider)
}

// GetBlueprintByUserStr resolves and returns a blueprint for the provided user string.
func (s *IdentityService) GetBlueprintByUserStr(ctx context.Context,
	req *typespb.UserStr) (*typespb.Blueprint, error) {

	userStr, err := models.NewUserStr(req.Userstr, false)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid user string: %v", err)
	}

	user, err := s.server.GetUserByUsername(userStr.Username)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "error occurred when getting user '%s': %v", userStr.Username, err)
	}

	for _, provider := range s.server.IdentityProviders {
		if provider.Name() == user.Source {
			blueprintpb, err := provider.GetBlueprintByUserStr(context.Background(), &typespb.UserStr{
				Userstr: userStr.Raw,
			})
			if err != nil {
				return nil, status.Errorf(codes.Internal,
					"failed to get custom blueprint for '%s' with provider '%s': %v",
					userStr.Username, provider.Name(), err)
			}
			return blueprintpb, nil
		}
	}

	return nil, status.Errorf(codes.NotFound, "no suitable identity provider found for user '%s'", userStr.Username)
}

// ResolvePullRequestToRef resolves a repository pull request to its reference.
func (s *IdentityService) ResolvePullRequestToRef(ctx context.Context,
	req *typespb.RepoPullRequestRequest) (*typespb.RepoRefResponse, error) {

	user, err := s.server.GetUserByUsername(req.Username)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "error occurred when getting user '%s': %v", req.Username, err)
	}

	for _, provider := range s.server.IdentityProviders {
		if provider.Name() == user.Source {
			repoRef, err := provider.ResolvePullRequestToRef(context.Background(), &typespb.RepoPullRequestRequest{
				Username:          req.Username,
				RepoOwner:         req.RepoOwner,
				RepoName:          req.RepoName,
				PullRequestNumber: int32(req.PullRequestNumber),
			})
			if err != nil {
				return nil, status.Errorf(codes.Internal,
					"failed to resolve pull request to ref for '%s' with provider '%s': %v",
					req.Username, provider.Name(), err)
			}
			return repoRef, nil
		}
	}

	return nil, status.Errorf(codes.NotFound, "no suitable identity provider found for user '%s'", req.Username)
}

// GetUserCredentials returns external credentials for a user.
func (s *IdentityService) GetUserCredentials(ctx context.Context,
	req *typespb.Username) (*identitypb.GetUserCredentialsResponse, error) {
	if s.server.DB == nil {
		return nil, status.Errorf(codes.Unavailable, "database is not configured, cannot retrieve user credentials")
	}

	user, err := s.server.GetUserByUsername(req.Username)
	if err != nil {
		return nil, fmt.Errorf("error occurred when getting user '%s': %w", req.Username, err)
	}

	var credentials []*models.ExternalCredential
	for _, provider := range s.server.IdentityProviders {
		if provider.Name() == user.Source {
			token, err := provider.GetUserToken(context.Background(), &typespb.Username{
				Username: user.Username,
			})
			if err != nil && !errors.Is(err, models.ErrMethodNotSupported) {
				return nil, fmt.Errorf("failed to get user token for '%s' with provider '%s': %w",
					req.Username, provider.Name(), err)
			}
			if token != nil {
				credentials = append(credentials, &models.ExternalCredential{
					ServiceName:   provider.Name(),
					Username:      user.Username,
					ExternalID:    user.Username,
					ExternalToken: token.Token,
					ServiceURL:    provider.Address(),
				})
			}
		}
	}

	externalCreds, err := s.server.DB.GetExternalCredentials(req.Username)
	if err != nil {
		return nil, fmt.Errorf("failed to get external credentials for user '%s': %w", req.Username, err)
	}
	credentials = append(credentials, externalCreds...)

	pbCredentials := make([]*commonpb.ExternalCredential, len(credentials))
	for i, cred := range credentials {
		pbCredentials[i] = gapi.ExternalCredentialToProto(cred)
	}

	return &identitypb.GetUserCredentialsResponse{Credentials: pbCredentials}, nil
}

// AddUserCredential adds an external credential for a user.
func (s *IdentityService) AddUserCredential(ctx context.Context,
	req *commonpb.ExternalCredential) (*identitypb.AddUserCredentialResponse, error) {
	if s.server.DB == nil {
		return nil, status.Errorf(codes.Unavailable, "database is not configured, cannot add user credential")
	}

	credential := gapi.ProtoToExternalCredential(req)

	err := s.server.DB.AddExternalCredential(credential)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to add user credential: %v", err)
	}

	return &identitypb.AddUserCredentialResponse{Credential: req}, nil
}

// UpdateUserCredential updates an existing external credential.
func (s *IdentityService) UpdateUserCredential(ctx context.Context,
	req *commonpb.ExternalCredential) (*identitypb.UpdateUserCredentialResponse, error) {
	if s.server.DB == nil {
		return nil, status.Errorf(codes.Unavailable, "database is not configured, cannot update user credential")
	}

	credential := gapi.ProtoToExternalCredential(req)

	err := s.server.DB.UpdateExternalCredential(credential)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to update user credential: %v", err)
	}

	return &identitypb.UpdateUserCredentialResponse{Credential: req}, nil
}

// DeleteUserCredential deletes an external credential by ID.
func (s *IdentityService) DeleteUserCredential(ctx context.Context,
	req *identitypb.DeleteUserCredentialRequest) (*identitypb.DeleteUserCredentialResponse, error) {
	if s.server.DB == nil {
		return nil, status.Errorf(codes.Unavailable, "database is not configured, cannot delete user credential")
	}

	err := s.server.DB.DeleteExternalCredential(req.Id)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to delete user credential: %v", err)
	}

	return &identitypb.DeleteUserCredentialResponse{Success: true}, nil
}
