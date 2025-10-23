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
	"github.com/rs/zerolog"
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
func (s *IdentityService) GetUsers(ctx context.Context, req *identitypb.GetUsersRequest) (*identitypb.UserList, error) {
	users, err := s.server.DB.ListUsers(int(req.Limit), int(req.Offset))
	if err != nil {
		return nil, fmt.Errorf("failed to get users: %w", err)
	}

	pbUsers := make([]*commonpb.User, len(users))
	for i, user := range users {
		pbUsers[i] = gapi.UserToProto(user)
	}

	return &identitypb.UserList{Users: pbUsers}, nil
}

// FindUser looks up a user by username or access token.
func (s *IdentityService) FindUser(ctx context.Context, req *identitypb.FindUserRequest) (*commonpb.User, error) {
	if req.Username != "" {
		if req.Token != "" {
			return nil, fmt.Errorf("only one of username or token can be provided")
		}

		user, err := s.server.GetUser(req.Username)
		if err != nil {
			return nil, fmt.Errorf("failed to get user: %w", err)
		}
		return gapi.UserToProto(user), nil
	}

	if req.Token != "" {
		if req.Username != "" {
			return nil, fmt.Errorf("only one of username or token can be provided")
		}

		user, err := s.server.DB.FindUserByAccessToken(req.Token)
		if err != nil {
			return nil, fmt.Errorf("failed to get user by token: %w", err)
		}
		if user == nil {
			return nil, errors.New("user not found for the provided token")
		}
		return gapi.UserToProto(user), nil
	}

	return nil, fmt.Errorf("invalid request: no username or token provided")
}

func (s *IdentityService) AuthUserPublicKey(ctx context.Context,
	req *identitypb.AuthUserPublicKeyRequest) (*identitypb.AuthUserResponse, error) {
	valid, err := s.server.AuthenticateUser(req.Username, req.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to auth public key: %w", err)
	}
	response := &identitypb.AuthUserResponse{Valid: valid}
	return response, nil
}

func (s *IdentityService) GetUserOnboardCapability(ctx context.Context,
	req *identitypb.Username) (*commonpb.UserOnboardCapability, error) {
	cap, err := s.server.OnboardCapability(req.Username)
	if err != nil {
		return nil, fmt.Errorf("failed to get onboard capability: %w", err)
	}
	return gapi.UserOnboardCapabilityToProto(cap), nil
}

func (s *IdentityService) OnboardUserDeviceFlow(ctx context.Context,
	req *identitypb.Username) (*commonpb.OnboardUserDeviceFlow, error) {
	onboardUser, err := s.server.OnboardUserDeviceFlow(req.Username)
	if err != nil {
		return nil, fmt.Errorf("failed to onboard user: %w", err)
	}

	return gapi.OnboardUserDeviceFlowToProto(onboardUser), nil
}

func (s *IdentityService) OnboardUserWebFlow(ctx context.Context,
	req *identitypb.OnboardUserWebFlowRequest) (*commonpb.OnboardUserWebFlow, error) {
	onboardUser, err := s.server.OnboardUserWebFlow(req.Provider, req.RedirectUri)
	if err != nil {
		return nil, fmt.Errorf("failed to onboard user via web flow: %w", err)
	}

	return gapi.OnboardUserWebFlowToProto(onboardUser), nil
}

func (s *IdentityService) CompleteUserWebFlow(ctx context.Context,
	req *identitypb.CompleteUserWebFlowRequest) (*commonpb.User, error) {
	user, err := s.server.CompleteUserWebFlow(req.Code, req.State)
	if err != nil {
		return nil, fmt.Errorf("failed to complete user web flow: %w", err)
	}

	return gapi.UserToProto(user), nil
}

// Blueprint methods
func (s *IdentityService) GetBlueprintByUserStr(ctx context.Context, req *identitypb.UserStr) (*identitypb.Blueprint, error) {
	userStr, err := models.NewUserStr(req.Userstr)
	if err != nil {
		return nil, fmt.Errorf("invalid user string: %w", err)
	}

	blueprint, err := s.server.GetCustomBlueprint(userStr)
	if err != nil {
		return nil, fmt.Errorf("failed to get blueprint: %w", err)
	}

	jsonData, err := json.Marshal(blueprint)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal blueprint to JSON: %w", err)
	}

	return &identitypb.Blueprint{BlueprintJson: string(jsonData)}, nil
}

// External credentials methods
func (s *IdentityService) GetUserCredentials(ctx context.Context,
	req *identitypb.Username) (*identitypb.GetUserCredentialsResponse, error) {
	credentials, err := s.server.DB.GetExternalCredentials(req.Username)
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
		return nil, fmt.Errorf("failed to add user credential: %w", err)
	}

	return &identitypb.AddUserCredentialResponse{Credential: req}, nil
}

func (s *IdentityService) UpdateUserCredential(ctx context.Context, req *commonpb.ExternalCredential) (*identitypb.UpdateUserCredentialResponse, error) {
	credential := gapi.ProtoToExternalCredential(req)

	err := s.server.DB.UpdateExternalCredential(credential)
	if err != nil {
		return nil, fmt.Errorf("failed to update user credential: %w", err)
	}

	return &identitypb.UpdateUserCredentialResponse{Credential: req}, nil
}

func (s *IdentityService) DeleteUserCredential(ctx context.Context,
	req *identitypb.DeleteUserCredentialRequest) (*identitypb.DeleteUserCredentialResponse, error) {
	err := s.server.DB.DeleteExternalCredential(req.Id)
	if err != nil {
		return nil, fmt.Errorf("failed to delete user credential: %w", err)
	}

	return &identitypb.DeleteUserCredentialResponse{Success: true}, nil
}
