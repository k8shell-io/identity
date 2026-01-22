package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/k8shell-io/common/pkg/gapi"
	commonpb "github.com/k8shell-io/common/pkg/gapi/commonpb"
	"github.com/k8shell-io/common/pkg/models"
	"github.com/k8shell-io/identity/pkg/api/identitypb"
	"github.com/k8shell-io/identity/pkg/api/typespb"
	"github.com/rs/zerolog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type IdentityService struct {
	server *Server
	log    *zerolog.Logger
	identitypb.UnimplementedIdentityServiceServer
}

func NewIdentityService(server *Server) *IdentityService {
	return &IdentityService{
		server: server,
		log:    server.log,
	}
}

// GetUsers retrieves a list of users with pagination support.
func (s *IdentityService) GetUsers(ctx context.Context, req *typespb.GetUsersRequest) (*typespb.UserList, error) {
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
		user, err := s.server.GetUser(req.Username)
		if err != nil {
			if errors.Is(err, models.ErrUserNotFound) {
				return nil, status.Error(codes.NotFound, "user not found")
			}
			s.log.Error().Err(err).Msg("failed to get user")
			return nil, status.Error(codes.Internal, "failed to get user")
		}
		return gapi.UserToProto(user), nil
	}

	user, err := s.server.DB.FindUserByAccessToken(req.Token)
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

func (s *IdentityService) AuthUserPublicKey(ctx context.Context,
	req *typespb.AuthUserPublicKeyRequest) (*typespb.AuthUserResponse, error) {
	valid, err := s.server.AuthenticateUser(req.Username, req.PublicKey)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to auth public key: %v", err)
	}
	response := &typespb.AuthUserResponse{Valid: valid}
	return response, nil
}

func (s *IdentityService) GetUserOnboardCapability(ctx context.Context,
	req *typespb.Username) (*commonpb.UserOnboardCapability, error) {
	cap, err := s.server.OnboardCapability(req.Username)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get onboard capability: %v", err)
	}
	return gapi.UserOnboardCapabilityToProto(cap), nil
}

func (s *IdentityService) OnboardUserDeviceFlow(ctx context.Context,
	req *typespb.Username) (*commonpb.OnboardUserDeviceFlow, error) {
	onboardUser, err := s.server.OnboardUserDeviceFlow(req.Username)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to onboard user: %v", err)
	}

	return gapi.OnboardUserDeviceFlowToProto(onboardUser), nil
}

func (s *IdentityService) OnboardUserWebFlow(ctx context.Context,
	req *typespb.OnboardUserWebFlowRequest) (*commonpb.OnboardUserWebFlow, error) {
	onboardUser, err := s.server.OnboardUserWebFlow(req.Provider, req.RedirectUri)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to onboard user via web flow: %v", err)
	}

	return gapi.OnboardUserWebFlowToProto(onboardUser), nil
}

func (s *IdentityService) CompleteUserWebFlow(ctx context.Context,
	req *typespb.CompleteUserWebFlowRequest) (*commonpb.User, error) {
	user, err := s.server.CompleteUserWebFlow(req.State, req.Code)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to complete user web flow: %v", err)
	}

	return gapi.UserToProto(user), nil
}

// Blueprint methods
func (s *IdentityService) GetBlueprintByUserStr(ctx context.Context,
	req *typespb.UserStr) (*typespb.Blueprint, error) {
	userStr, err := models.NewUserStr(req.Userstr, false)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid user string: %v", err)
	}

	blueprint, err := s.server.GetCustomBlueprint(userStr)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to get blueprint: %v", err)
	}

	jsonData, err := json.Marshal(blueprint)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to marshal blueprint to JSON: %v", err)
	}

	return &typespb.Blueprint{BlueprintJson: string(jsonData)}, nil
}

// ResolvePullRequestToRef resolves a repository pull request to its corresponding reference.
func (s *IdentityService) ResolvePullRequestToRef(ctx context.Context,
	req *typespb.RepoPullRequestRequest) (*typespb.RepoRefResponse, error) {
	repoRef, err := s.server.ResolveRepoPullRequestToRef(req.Username, req.RepoOwner, req.RepoName,
		int(req.PullRequestNumber))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to resolve pull request to ref: %v", err)
	}
	return &typespb.RepoRefResponse{RepoRef: repoRef}, nil
}

// External credentials methods
func (s *IdentityService) GetUserCredentials(ctx context.Context,
	req *typespb.Username) (*identitypb.GetUserCredentialsResponse, error) {

	credentials, err := s.server.GetUserExtCredentials(req.Username)
	if err != nil {
		return nil, fmt.Errorf("failed to get user credentials: %w", err)
	}
	pbCredentials := make([]*commonpb.ExternalCredential, len(credentials))
	for i, cred := range credentials {
		pbCredentials[i] = gapi.ExternalCredentialToProto(cred)
	}

	return &identitypb.GetUserCredentialsResponse{Credentials: pbCredentials}, nil
}

func (s *IdentityService) AddUserCredential(ctx context.Context,
	req *commonpb.ExternalCredential) (*identitypb.AddUserCredentialResponse, error) {
	credential := gapi.ProtoToExternalCredential(req)

	err := s.server.DB.AddExternalCredential(credential)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to add user credential: %v", err)
	}

	return &identitypb.AddUserCredentialResponse{Credential: req}, nil
}

func (s *IdentityService) UpdateUserCredential(ctx context.Context, req *commonpb.ExternalCredential) (*identitypb.UpdateUserCredentialResponse, error) {
	credential := gapi.ProtoToExternalCredential(req)

	err := s.server.DB.UpdateExternalCredential(credential)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to update user credential: %v", err)
	}

	return &identitypb.UpdateUserCredentialResponse{Credential: req}, nil
}

func (s *IdentityService) DeleteUserCredential(ctx context.Context,
	req *identitypb.DeleteUserCredentialRequest) (*identitypb.DeleteUserCredentialResponse, error) {
	err := s.server.DB.DeleteExternalCredential(req.Id)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to delete user credential: %v", err)
	}

	return &identitypb.DeleteUserCredentialResponse{Success: true}, nil
}
