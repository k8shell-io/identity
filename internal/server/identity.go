// Copyright 2025 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	commonv1 "github.com/k8shell-io/common/pkg/api/gen/go/common/v1"
	identityv1 "github.com/k8shell-io/common/pkg/api/gen/go/identity/v1"
	"github.com/k8shell-io/common/pkg/authz"
	"github.com/k8shell-io/common/pkg/gapi"
	"github.com/k8shell-io/common/pkg/models"
	"github.com/k8shell-io/common/pkg/userstr"
	"github.com/k8shell-io/common/pkg/utils"
	backend "github.com/k8shell-io/identity/internal/db"
	"github.com/rs/zerolog"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// minPasswordLength is the minimum length accepted by SetUserPassword.
const minPasswordLength = 8

// defaultUserShell is the login shell assigned by CreateUser when none is supplied.
const defaultUserShell = "/bin/sh"

// localUserSource tags users created via CreateUser as having no backing
// identity provider, distinguishing them from provider-synced users.
const localUserSource = "local"

// localUserExpiry is the expires_at set on users created via CreateUser.
// refreshUser re-fetches from the provider named by a user's Source once
// expires_at passes, and marks the user invalid if that provider can't be
// found; local users have no such provider, so this is set far enough out
// that it is never reached in practice.
const localUserExpiry = 100 * 365 * 24 * time.Hour

// webFlowStatePayload is embedded in the OAuth state parameter to carry
// CLI-specific data across the redirect round-trip without server-side storage.
// Detection: after base64url decoding, the legacy IDP state starts with a
// provider name (e.g. "oidc:..."), while our payload starts with '{'.
type webFlowStatePayload struct {
	IDPState  string `json:"s"`
	CliState  string `json:"c,omitempty"`
	CreatePat bool   `json:"p,omitempty"`
}

func wrapWebFlowState(idpState, cliState string, createPat bool) (string, error) {
	b, err := json.Marshal(webFlowStatePayload{IDPState: idpState, CliState: cliState, CreatePat: createPat})
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// unwrapWebFlowState decodes state produced by wrapWebFlowState.
// When state is a legacy (unwrapped) IDP state it is returned as idpState unchanged.
func unwrapWebFlowState(state string) (idpState, cliState string, createPat bool, err error) {
	b, err := base64.RawURLEncoding.DecodeString(state)
	if err != nil {
		return "", "", false, fmt.Errorf("decode state: %w", err)
	}
	if len(b) == 0 || b[0] != '{' {
		return state, "", false, nil
	}
	var p webFlowStatePayload
	if err := json.Unmarshal(b, &p); err != nil {
		return "", "", false, fmt.Errorf("unmarshal wrapped state: %w", err)
	}
	return p.IDPState, p.CliState, p.CreatePat, nil
}

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

	user, err := s.server.GetUserByUsername(req.Username, req.Source)
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

// userMatchesFilter reports whether user satisfies the GetUsers filters: an
// AND-of-ORs where roles and blueprints each match when the user has at least
// one of the listed values, and org matches when the user belongs to it. An
// empty/nil filter imposes no restriction on that dimension.
func userMatchesFilter(user *models.User, roles, blueprints []string, org string) bool {
	if len(roles) > 0 {
		matched := false
		for _, r := range roles {
			for _, userRole := range user.Roles {
				if string(userRole) == r {
					matched = true
					break
				}
			}
			if matched {
				break
			}
		}
		if !matched {
			return false
		}
	}
	if len(blueprints) > 0 {
		matched := false
		for _, b := range blueprints {
			for _, userBlueprint := range user.Blueprints {
				if userBlueprint == b {
					matched = true
					break
				}
			}
			if matched {
				break
			}
		}
		if !matched {
			return false
		}
	}
	if org != "" && user.Organization != org {
		return false
	}
	return true
}

// GetUsers retrieves users with pagination support, optionally filtered by
// role, blueprint, or organization.
func (s *IdentityService) GetUsers(ctx context.Context, req *identityv1.GetUsersRequest) (*identityv1.UserList, error) {
	if s.server.DB == nil {
		userList := make([]*commonv1.User, 0)
		localUsers := s.server.getLocalUsers()

		skipped := 0
		for _, user := range localUsers {
			if !userMatchesFilter(user, req.Roles, req.Blueprints, req.Org) {
				continue
			}
			if skipped < int(req.Offset) {
				skipped++
				continue
			}
			userList = append(userList, gapi.UserToProto(user))
			if len(userList) >= int(req.Limit) {
				break
			}
		}
		return &identityv1.UserList{Users: userList}, nil
	}

	users, err := s.server.DB.ListUsers(int(req.Limit), int(req.Offset), req.Roles, req.Blueprints, req.Org)
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
	if req.Username == "" {
		return nil, status.Error(codes.InvalidArgument, "no username provided")
	}

	if req.Username != "" {
		user, err := s.server.GetUserByUsername(req.Username, "")
		if err != nil {
			if errors.Is(err, models.ErrUserNotFound) {
				return nil, status.Error(codes.NotFound, "user not found")
			}
			s.log.Error().Err(err).Msg("failed to get user")
			return nil, propagateOrInternal(err, "failed to get user")
		}
		return gapi.UserToProto(user), nil
	}

	return nil, status.Error(codes.InvalidArgument,
		"invalid request: must provide either username or token")
}

// AuthUserPublicKey authenticates a user using an SSH public key. The key is
// always checked against identity.users.auth_keys first, regardless of the
// user's source — a provider-onboarded user may still have locally-added
// keys (see AddUserAuthKeys), and local users (source="local") have no
// backing identity provider at all. The upstream provider is only consulted
// when the DB has no matching key, and is skipped entirely for local users
// since they have no provider to fall back to. If the DB isn't configured,
// the local check is skipped and auth goes straight to the provider.
func (s *IdentityService) AuthUserPublicKey(ctx context.Context,
	req *identityv1.AuthUserPublicKeyRequest) (*identityv1.AuthUserResponse, error) {

	user, err := s.server.GetUserByUsername(req.Username, "")
	if err != nil {
		if errors.Is(err, models.ErrUserNotFound) || errors.Is(err, models.ErrUserIsNotValid) {
			return &identityv1.AuthUserResponse{Valid: false}, nil
		}
		return nil, propagateOrInternal(err, "error occured when finding user '%s': %s",
			req.Username, err.Error())
	}

	parsedKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(req.PublicKey))
	if err != nil {
		s.log.Warn().Msgf("Failed to parse provided public key for user '%s': %v", req.Username, err)
		return nil, nil
	}
	normalizedKey := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(parsedKey)))

	var authpb *identityv1.AuthUserResponse
	if s.server.DB != nil {
		authpb, err = s.matchStoredAuthKey(user.Username, normalizedKey)
		if err != nil {
			return nil, propagateOrInternal(err, "failed to check stored auth keys for user '%s': %s",
				req.Username, err.Error())
		}
	}

	if authpb == nil || !authpb.Valid {
		if user.Source == localUserSource {
			// local users have no backing identity provider to fall back to
			authpb = &identityv1.AuthUserResponse{Valid: false}
		} else {
			provider, ok := s.server.providerByName(user.Source)
			if !ok {
				return nil, status.Errorf(codes.NotFound, "no suitable identity provider found for user '%s'", req.Username)
			}
			authpb, err = provider.AuthUserPublicKey(context.Background(), &identityv1.AuthUserPublicKeyRequest{
				Username:  req.Username,
				PublicKey: normalizedKey,
			})
			if err != nil {
				return nil, propagateOrInternal(err, "failed to authenticate user '%s' with provider '%s': %s",
					req.Username, provider.Name(), err.Error())
			}
		}
	}

	if authpb != nil && authpb.Valid {
		if err := s.server.applyAuthPolicy(user, authz.UserAuthMethodPublicKey, authz.AuthSurfaceSSH); err != nil {
			return nil, status.Errorf(codes.PermissionDenied, "%v", err)
		}
	}
	return authpb, nil
}

// matchStoredAuthKey checks a normalized SSH public key against the keys
// stored in identity.users.auth_keys for a user, regardless of source.
func (s *IdentityService) matchStoredAuthKey(username, normalizedKey string) (*identityv1.AuthUserResponse, error) {
	keys, err := s.server.DB.ListUserAuthKeys(username)
	if err != nil {
		if errors.Is(err, models.ErrUserNotFound) {
			return &identityv1.AuthUserResponse{Valid: false}, nil
		}
		return nil, err
	}
	for _, k := range keys {
		if strings.TrimSpace(k) == normalizedKey {
			return &identityv1.AuthUserResponse{Valid: true}, nil
		}
	}
	return &identityv1.AuthUserResponse{Valid: false}, nil
}

// checkUserPassword resolves a user by username and verifies password against
// their stored bcrypt hash. It returns a nil user (with no error) when the
// user cannot be found, is invalid, or the password does not match.
func (s *IdentityService) checkUserPassword(username, password string) (*models.User, error) {
	user, err := s.server.GetUserByUsername(username, "")
	if err != nil {
		if errors.Is(err, models.ErrUserNotFound) || errors.Is(err, models.ErrUserIsNotValid) {
			return nil, nil
		}
		return nil, propagateOrInternal(err, "error occurred when finding user '%s': %s",
			username, err.Error())
	}

	if user.Password == "" || password == "" {
		return nil, nil
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		return nil, nil
	}

	return user, nil
}

// AuthUserPassword checks a password against the bcrypt password hash stored
// locally in the database. Unlike AuthUserPublicKey, this is never delegated to
// an identity provider — passwords are a k8Shell-local credential, resolved the
// same way as PATs and stored credentials.
//
// This RPC does not evaluate the user:auth authz policy itself: it is called
// by both SSH and web login surfaces, each of which evaluates user:auth with
// its own surface context before (or instead of) calling here — identity has
// no way to know which surface is calling. Callers that need to verify a
// password outside of login (e.g. requiring the current password before a
// change) can also call this RPC directly, since it carries no login-specific
// authorization of its own.
func (s *IdentityService) AuthUserPassword(ctx context.Context,
	req *identityv1.AuthUserPasswordRequest) (*identityv1.AuthUserResponse, error) {

	user, err := s.checkUserPassword(req.Username, req.Password)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return &identityv1.AuthUserResponse{Valid: false}, nil
	}

	return &identityv1.AuthUserResponse{Valid: true, User: gapi.UserToProto(user)}, nil
}

// SetUserPassword sets or clears a user's local password. The password is
// bcrypt-hashed before being persisted; the raw value is never stored or
// returned. Pass an empty password to clear it, disabling password auth.
func (s *IdentityService) SetUserPassword(ctx context.Context,
	req *identityv1.SetUserPasswordRequest) (*commonv1.User, error) {
	if req.Username == "" {
		return nil, status.Error(codes.InvalidArgument, "username is required")
	}
	if s.server.DB == nil {
		return nil, status.Error(codes.Unavailable, "database is not configured")
	}

	hash := ""
	if req.Password != "" {
		if len(req.Password) < minPasswordLength {
			return nil, status.Errorf(codes.InvalidArgument, "password must be at least %d characters", minPasswordLength)
		}
		hashed, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			if errors.Is(err, bcrypt.ErrPasswordTooLong) {
				return nil, status.Error(codes.InvalidArgument, "password is too long")
			}
			return nil, status.Errorf(codes.Internal, "failed to hash password: %v", err)
		}
		hash = string(hashed)
	}

	user, err := s.server.DB.SetUserPassword(req.Username, hash)
	if err != nil {
		if errors.Is(err, models.ErrUserNotFound) {
			return nil, status.Errorf(codes.NotFound, "user '%s' not found", req.Username)
		}
		return nil, status.Errorf(codes.Internal, "failed to set password for user '%s': %v", req.Username, err)
	}

	return gapi.UserToProto(user), nil
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
	if s.server.DB == nil {
		return nil, status.Error(codes.FailedPrecondition,
			"database is not configured, cannot onboard user via device flow")
	}

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
	if s.server.DB == nil {
		return nil, status.Error(codes.FailedPrecondition,
			"database is not configured, cannot onboard user via web flow")
	}

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

	if req.CliState != "" || req.CreatePat {
		s.log.Debug().Msgf("Wrapping web flow state for provider '%s' with CLI state and PAT creation flag", req.Provider)
		wrapped, err := wrapWebFlowState(authInfo.GetState(), req.CliState, req.CreatePat)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to wrap web flow state: %v", err)
		}
		u, err := url.Parse(authInfo.GetAuthUrl())
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to parse auth URL: %v", err)
		}
		q := u.Query()
		q.Set("state", wrapped)
		u.RawQuery = q.Encode()
		authInfo.AuthUrl = u.String()
		authInfo.State = wrapped
	}

	s.log.Info().Msgf("Initiated web flow onboarding for provider '%s', auth URL: %s",
		req.Provider, authInfo.GetAuthUrl())

	return authInfo, nil
}

// randomTokenSuffix returns a short random hex string used to give each web-flow
// login its own uniquely named access token, so logging in from one device does
// not invalidate a token already issued to another.
func randomTokenSuffix() (string, error) {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate token suffix: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// CompleteUserWebFlow completes web-flow onboarding and returns the resolved user.
func (s *IdentityService) CompleteUserWebFlow(ctx context.Context,
	req *identityv1.CompleteUserWebFlowRequest) (*identityv1.CompleteUserWebFlowResponse, error) {
	if s.server.DB == nil {
		return nil, status.Error(codes.FailedPrecondition,
			"database is not configured, cannot complete web flow and create user")
	}

	idpState, cliState, createPat, err := unwrapWebFlowState(req.State)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to decode web flow state: %v", err)
	}

	provider, _, err := utils.DecodeState(idpState)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to decode web flow state: %v", err)
	}

	p, ok := s.server.providerByName(provider)
	if !ok {
		return nil, status.Errorf(codes.NotFound,
			"no suitable identity provider found to complete web flow for provider '%s'", provider)
	}
	username, err := p.CompleteUserWebFlow(context.Background(), &identityv1.CompleteUserWebFlowRequest{
		State: idpState,
		Code:  req.Code,
	})
	if err != nil {
		return nil, propagateOrInternal(err, "failed to complete web flow for provider '%s': %v", provider, err)
	}

	user, err := s.server.GetUserByUsername(username.GetUsername(), provider)
	if err != nil {
		return nil, propagateOrInternal(err, "failed to get user '%s' after completing web flow for provider '%s': %v",
			username.GetUsername(), provider, err)
	}

	token, err := s.server.issueUserToken(user)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to issue token for user '%s'", user.Username)
	}

	resp := &identityv1.CompleteUserWebFlowResponse{UserToken: token}

	if createPat {
		scopes := []string{"*"}
		var patExpiresAt *time.Time

		policyResult, err := s.server.applyTokenCreatePolicy(user, authz.TokenCreateSourceWebFlow)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to evaluate token create policy for user '%s': %v",
				username.GetUsername(), err)
		}
		if policyResult != nil && !policyResult.Allowed {
			resp.PatError = fmt.Sprintf("Create token not allowed for user '%s'. %s",
				username.GetUsername(), policyResult.Reason)
			resp.CliState = cliState
		} else {
			if policyResult != nil {
				if scopesOb, ok := authz.ParseScopesObligation(policyResult.Obligations); ok {
					scopes = scopesOb.Scopes
				}
				if expiresInOb, ok := authz.ParseExpiresInObligation(
					policyResult.Obligations); ok && expiresInOb.Duration != nil {
					t := time.Now().Add(*expiresInOb.Duration)
					patExpiresAt = &t
				}
			}

			suffix, err := randomTokenSuffix()
			if err != nil {
				return nil, status.Errorf(codes.Internal, "failed to create access token for user '%s': %v",
					username.GetUsername(), err)
			}

			_, raw, err := s.server.DB.CreateAccessToken(username.GetUsername(),
				"OAuth-"+suffix, scopes, patExpiresAt)
			if err != nil {
				return nil, status.Errorf(codes.Internal, "failed to create access token for user '%s': %v",
					username.GetUsername(), err)
			}
			resp.Pat = raw
			resp.CliState = cliState
		}
	}

	s.server.provisionGitCredential(ctx, username.GetUsername(), p)

	return resp, nil
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

	user, err := s.server.GetUserByUsername(userStr.Username(), "")
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

// ListUserCredentials returns stored credentials for a user, or a single
// credential when req.Id is set.
func (s *IdentityService) ListUserCredentials(ctx context.Context,
	req *identityv1.ListUserCredentialsRequest) (*identityv1.ListUserCredentialsResponse, error) {
	if s.server.DB == nil {
		return nil, status.Errorf(codes.Unavailable, "database is not configured, cannot retrieve user credentials")
	}

	_, err := s.server.GetUserByUsername(req.Username, "")
	if err != nil {
		if errors.Is(err, models.ErrUserNotFound) {
			return nil, status.Errorf(codes.NotFound, "user '%s' not found", req.Username)
		}
		return nil, propagateOrInternal(err, "error occurred when getting user '%s': %v", req.Username, err)
	}

	creds, err := s.server.DB.ListUserCredentials(req.Username, req.Id)
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

// AddKubernetesUserCredential provisions a Kubernetes service-account credential for a user.
// req.Scope maps to the credential's service_scope and req.Subject maps to its subject.
func (s *IdentityService) AddKubernetesUserCredential(ctx context.Context,
	req *identityv1.AddKubernetesUserCredentialRequest) (*identityv1.AddKubernetesUserCredentialResponse, error) {
	if s.server.DB == nil {
		return nil, status.Errorf(codes.Unavailable, "database is not configured, cannot add user credential")
	}

	_, err := s.server.GetUserByUsername(req.Username, "")
	if err != nil {
		if errors.Is(err, models.ErrUserNotFound) {
			return nil, status.Errorf(codes.NotFound, "user '%s' not found", req.Username)
		}
		return nil, propagateOrInternal(err, "error occurred when getting user '%s': %v", req.Username, err)
	}

	cred, err := s.server.DB.AddKubernetesUserCredential(req.Username, req.Scope, req.Subject)
	if err != nil {
		if errors.Is(err, backend.ErrCredentialExists) {
			return nil, status.Errorf(codes.AlreadyExists, "%v", err)
		}
		return nil, status.Errorf(codes.Internal, "failed to add kubernetes user credential: %v", err)
	}

	return &identityv1.AddKubernetesUserCredentialResponse{Credential: gapi.UserCredentialToProto(cred)}, nil
}

// AddGitUserCredential stores a Git credential for a user. req.Scope maps to the credential's
// service_scope and req.Subject maps to its subject; req.Secret is stored as given.
func (s *IdentityService) AddGitUserCredential(ctx context.Context,
	req *identityv1.AddGitUserCredentialRequest) (*identityv1.AddGitUserCredentialResponse, error) {
	if s.server.DB == nil {
		return nil, status.Errorf(codes.Unavailable, "database is not configured, cannot add user credential")
	}

	_, err := s.server.GetUserByUsername(req.Username, "")
	if err != nil {
		if errors.Is(err, models.ErrUserNotFound) {
			return nil, status.Errorf(codes.NotFound, "user '%s' not found", req.Username)
		}
		return nil, propagateOrInternal(err, "error occurred when getting user '%s': %v", req.Username, err)
	}

	cred, err := s.server.DB.AddGitUserCredential(req.Username, req.Scope, req.Subject, req.Secret)
	if err != nil {
		if errors.Is(err, backend.ErrCredentialExists) {
			return nil, status.Errorf(codes.AlreadyExists, "%v", err)
		}
		return nil, status.Errorf(codes.Internal, "failed to add git user credential: %v", err)
	}

	return &identityv1.AddGitUserCredentialResponse{Credential: gapi.UserCredentialToProto(cred)}, nil
}

// AddRegistryUserCredential stores a container registry credential for a user. req.Scope maps
// to the credential's service_scope and req.Subject maps to its subject; req.Secret is stored
// as given.
func (s *IdentityService) AddRegistryUserCredential(ctx context.Context,
	req *identityv1.AddRegistryUserCredentialRequest) (*identityv1.AddRegistryUserCredentialResponse, error) {
	if s.server.DB == nil {
		return nil, status.Errorf(codes.Unavailable, "database is not configured, cannot add user credential")
	}

	_, err := s.server.GetUserByUsername(req.Username, "")
	if err != nil {
		if errors.Is(err, models.ErrUserNotFound) {
			return nil, status.Errorf(codes.NotFound, "user '%s' not found", req.Username)
		}
		return nil, propagateOrInternal(err, "error occurred when getting user '%s': %v", req.Username, err)
	}

	cred, err := s.server.DB.AddRegistryUserCredential(req.Username, req.Scope, req.Subject, req.Secret)
	if err != nil {
		if errors.Is(err, backend.ErrCredentialExists) {
			return nil, status.Errorf(codes.AlreadyExists, "%v", err)
		}
		return nil, status.Errorf(codes.Internal, "failed to add registry user credential: %v", err)
	}

	return &identityv1.AddRegistryUserCredentialResponse{Credential: gapi.UserCredentialToProto(cred)}, nil
}

// UpdateUserCredential partially updates a credential by ID. Only fields set (non-nil) in req
// are applied. Credentials provisioned by the onboarding flow (credential_source matching
// "idp.k8shell.io/*") may only have Active updated.
func (s *IdentityService) UpdateUserCredential(ctx context.Context,
	req *identityv1.UpdateUserCredentialRequest) (*identityv1.UpdateUserCredentialResponse, error) {
	if s.server.DB == nil {
		return nil, status.Errorf(codes.Unavailable, "database is not configured, cannot update user credential")
	}

	var scope, subject, secret *string
	if req.Scope != nil {
		v := req.Scope.GetValue()
		scope = &v
	}
	if req.Subject != nil {
		v := req.Subject.GetValue()
		subject = &v
	}
	if req.Secret != nil {
		v := req.Secret.GetValue()
		secret = &v
	}
	var active *bool
	if req.Active != nil {
		v := req.Active.GetValue()
		active = &v
	}

	cred, err := s.server.DB.UpdateUserCredential(req.Id, scope, subject, secret, active)
	if err != nil {
		if errors.Is(err, models.ErrUserNotFound) {
			return nil, status.Errorf(codes.NotFound, "credential '%d' not found", req.Id)
		}
		if errors.Is(err, backend.ErrProtectedCredential) {
			return nil, status.Errorf(codes.FailedPrecondition,
				"credential '%d' was created by the onboarding process; only active can be updated", req.Id)
		}
		return nil, status.Errorf(codes.Internal, "failed to update user credential: %v", err)
	}

	return &identityv1.UpdateUserCredentialResponse{Credential: gapi.UserCredentialToProto(cred)}, nil
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

// RemoveUserCredential removes a single credential owned by a user, by ID.
func (s *IdentityService) RemoveUserCredential(ctx context.Context,
	req *identityv1.RemoveUserCredentialRequest) (*identityv1.RemoveUserCredentialResponse, error) {
	if s.server.DB == nil {
		return nil, status.Errorf(codes.Unavailable, "database is not configured, cannot remove user credential")
	}

	err := s.server.DB.RemoveUserCredential(req.Username, req.Id)
	if err != nil {
		if errors.Is(err, models.ErrUserNotFound) {
			return nil, status.Errorf(codes.NotFound, "credential not found for user '%s', id '%d'", req.Username, req.Id)
		}
		return nil, status.Errorf(codes.Internal, "failed to remove user credential: %v", err)
	}

	return &identityv1.RemoveUserCredentialResponse{Success: true}, nil
}

// validateAuthKeys checks that every entry is a well-formed SSH public key in
// authorized_keys format, returning an error naming the first offending entry.
func validateAuthKeys(authKeys []string) error {
	for _, k := range authKeys {
		_, _, _, rest, err := ssh.ParseAuthorizedKey([]byte(k))
		if err != nil || len(bytes.TrimSpace(rest)) > 0 {
			if err == nil {
				err = fmt.Errorf("unexpected trailing data")
			}
			return fmt.Errorf("invalid SSH public key %q: %w", k, err)
		}
	}
	return nil
}

// CreateUser creates a new local user record (source="local"), i.e. one with
// no backing identity provider. Username and email must both be unique;
// unlike username, email has no DB-level uniqueness constraint so it is
// checked here. When not supplied: uid defaults to the next free value at or
// above db.localUserUIDFloor; gid defaults to the resolved uid, giving the
// user their own private group; shell defaults to /bin/sh; sudo and locked
// default to false; fullname may be left empty.
//
// Unlike user:onboard/user:auth/token:create, this RPC has no per-call authz
// check here: those evaluate policy for a self-service subject (the caller
// and the acted-on user are the same person), but CreateUser is admin-on-
// behalf-of-someone-else and this service has no way to identify the calling
// admin (no per-caller JWT is verified from incoming gRPC context anywhere in
// this service, only the gapi service-account allowlist). Authorizing which
// admins may call CreateUser is the API server's responsibility, enforced
// before it reaches this RPC — same as every other admin mutation here
// (UpdateUser, AddUserRoles, SetUserPassword, etc.).
func (s *IdentityService) CreateUser(ctx context.Context,
	req *identityv1.CreateUserRequest) (*commonv1.User, error) {
	if req.Username == "" {
		return nil, status.Error(codes.InvalidArgument, "username is required")
	}
	if req.Organization == "" {
		return nil, status.Error(codes.InvalidArgument, "organization is required")
	}
	if s.server.DB == nil {
		return nil, status.Error(codes.Unavailable, "database is not configured")
	}

	username := strings.ToLower(req.Username)

	if _, err := s.server.DB.FindUser(username, ""); err == nil {
		return nil, status.Errorf(codes.AlreadyExists, "user '%s' already exists", username)
	} else if !errors.Is(err, models.ErrUserNotFound) {
		return nil, status.Errorf(codes.Internal, "failed to check for existing user '%s': %v", username, err)
	}

	if req.Email != "" {
		if _, err := s.server.DB.FindUserByEmail(req.Email); err == nil {
			return nil, status.Errorf(codes.AlreadyExists, "a user with email '%s' already exists", req.Email)
		} else if !errors.Is(err, models.ErrUserNotFound) {
			return nil, status.Errorf(codes.Internal, "failed to check for existing email '%s': %v", req.Email, err)
		}
	}

	hash := ""
	if req.Password != "" {
		if len(req.Password) < minPasswordLength {
			return nil, status.Errorf(codes.InvalidArgument, "password must be at least %d characters", minPasswordLength)
		}
		hashed, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			if errors.Is(err, bcrypt.ErrPasswordTooLong) {
				return nil, status.Error(codes.InvalidArgument, "password is too long")
			}
			return nil, status.Errorf(codes.Internal, "failed to hash password: %v", err)
		}
		hash = string(hashed)
	}

	uid := req.GetUid()
	if uid == 0 {
		next, err := s.server.DB.NextAvailableUID()
		if err != nil {
			if errors.Is(err, backend.ErrUIDRangeExhausted) {
				return nil, status.Error(codes.ResourceExhausted,
					"no available uid for auto-assignment; supply one explicitly")
			}
			return nil, status.Errorf(codes.Internal, "failed to allocate uid for user '%s': %v", username, err)
		}
		uid = next
	}
	gid := req.GetGid()
	if gid == 0 {
		gid = uid
	}

	shell := req.Shell
	if shell == "" {
		shell = defaultUserShell
	}

	roles := make([]models.Role, len(req.GetRoles()))
	for i, r := range req.GetRoles() {
		roles[i] = models.Role(r)
	}

	user := &models.User{
		Username:     username,
		Organization: req.Organization,
		IsValid:      true,
		ExpiresAt:    time.Now().Add(localUserExpiry),
		UID:          uid,
		GID:          gid,
		Fullname:     req.Fullname,
		Email:        req.Email,
		Password:     hash,
		Shell:        shell,
		Sudo:         req.Sudo,
		Locked:       req.Locked,
		Roles:        roles,
		Blueprints:   req.GetBlueprints(),
		Source:       localUserSource,
	}

	if err := s.server.DB.CreateUser(user); err != nil {
		switch {
		case errors.Is(err, backend.ErrUsernameExists):
			return nil, status.Errorf(codes.AlreadyExists, "user '%s' already exists", username)
		case errors.Is(err, backend.ErrUIDExists):
			return nil, status.Errorf(codes.AlreadyExists, "uid %d is already in use", uid)
		case errors.Is(err, models.ErrInvalidParameters):
			return nil, status.Errorf(codes.InvalidArgument, "%v", err)
		}
		return nil, status.Errorf(codes.Internal, "failed to create user '%s': %v", username, err)
	}

	return gapi.UserToProto(user), nil
}

// UpdateUser applies a partial update to a user record. Only non-nil wrapper
// fields and non-empty repeated fields in the request are applied.
func (s *IdentityService) UpdateUser(ctx context.Context,
	req *identityv1.UpdateUserRequest) (*commonv1.User, error) {
	if req.Username == "" {
		return nil, status.Error(codes.InvalidArgument, "username is required")
	}
	if s.server.DB == nil {
		return nil, status.Error(codes.Unavailable, "database is not configured")
	}

	user, err := s.server.DB.FindUser(req.Username, "")
	if err != nil {
		if errors.Is(err, models.ErrUserNotFound) {
			return nil, status.Errorf(codes.NotFound, "user '%s' not found", req.Username)
		}
		return nil, status.Errorf(codes.Internal, "failed to get user '%s': %v", req.Username, err)
	}

	if v := req.GetFullname(); v != nil {
		user.Fullname = v.GetValue()
	}
	if v := req.GetSudo(); v != nil {
		user.Sudo = v.GetValue()
	}
	if v := req.GetLocked(); v != nil {
		user.Locked = v.GetValue()
	}
	if v := req.GetShell(); v != nil {
		user.Shell = v.GetValue()
	}
	if len(req.GetRoles()) > 0 {
		roles := make([]models.Role, len(req.GetRoles()))
		for i, r := range req.GetRoles() {
			roles[i] = models.Role(r)
		}
		user.Roles = roles
	}
	if len(req.GetBlueprints()) > 0 {
		user.Blueprints = req.GetBlueprints()
	}
	if v := req.GetOrg(); v != nil {
		user.Organization = v.GetValue()
	}
	if v := req.GetEmail(); v != nil {
		user.Email = v.GetValue()
	}
	if v := req.GetUid(); v != nil {
		user.UID = v.GetValue()
	}
	if v := req.GetGid(); v != nil {
		user.GID = v.GetValue()
	}

	if err := s.server.DB.UpdateUser(user); err != nil {
		if errors.Is(err, models.ErrInvalidParameters) {
			return nil, status.Errorf(codes.InvalidArgument, "failed to update user '%s': %v", req.Username, err)
		}
		return nil, status.Errorf(codes.Internal, "failed to update user '%s': %v", req.Username, err)
	}

	return gapi.UserToProto(user), nil
}

// DeleteUser permanently removes a user record by username. Credentials and
// access tokens owned by the user are removed along with it (ON DELETE
// CASCADE at the DB level).
//
// Like CreateUser, this RPC has no per-call authz check here: the acted-on
// user cannot authorize their own deletion, and this service has no way to
// identify the calling admin. Authorizing which admins may call DeleteUser
// against the user:delete contract is the API server's responsibility,
// enforced before it reaches this RPC.
func (s *IdentityService) DeleteUser(ctx context.Context,
	req *identityv1.DeleteUserRequest) (*identityv1.DeleteUserResponse, error) {
	if req.Username == "" {
		return nil, status.Error(codes.InvalidArgument, "username is required")
	}
	if s.server.DB == nil {
		return nil, status.Error(codes.Unavailable, "database is not configured")
	}

	if err := s.server.DB.DeleteUser(req.Username); err != nil {
		if errors.Is(err, models.ErrUserNotFound) {
			return nil, status.Errorf(codes.NotFound, "user '%s' not found", req.Username)
		}
		return nil, status.Errorf(codes.Internal, "failed to delete user '%s': %v", req.Username, err)
	}

	return &identityv1.DeleteUserResponse{Success: true}, nil
}

// AddUserRoles adds one or more roles to a user without affecting existing roles.
func (s *IdentityService) AddUserRoles(ctx context.Context,
	req *identityv1.UserRolesRequest) (*commonv1.User, error) {
	if req.Username == "" {
		return nil, status.Error(codes.InvalidArgument, "username is required")
	}
	if len(req.GetRoles()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "at least one role is required")
	}
	if s.server.DB == nil {
		return nil, status.Error(codes.Unavailable, "database is not configured")
	}

	user, err := s.server.DB.AddUserRoles(req.Username, req.GetRoles())
	if err != nil {
		if errors.Is(err, models.ErrUserNotFound) {
			return nil, status.Errorf(codes.NotFound, "user '%s' not found", req.Username)
		}
		return nil, status.Errorf(codes.Internal, "failed to add roles for user '%s': %v", req.Username, err)
	}

	return gapi.UserToProto(user), nil
}

// RemoveUserRoles removes one or more roles from a user.
func (s *IdentityService) RemoveUserRoles(ctx context.Context,
	req *identityv1.UserRolesRequest) (*commonv1.User, error) {
	if req.Username == "" {
		return nil, status.Error(codes.InvalidArgument, "username is required")
	}
	if len(req.GetRoles()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "at least one role is required")
	}
	if s.server.DB == nil {
		return nil, status.Error(codes.Unavailable, "database is not configured")
	}

	user, err := s.server.DB.RemoveUserRoles(req.Username, req.GetRoles())
	if err != nil {
		if errors.Is(err, models.ErrUserNotFound) {
			return nil, status.Errorf(codes.NotFound, "user '%s' not found", req.Username)
		}
		return nil, status.Errorf(codes.Internal, "failed to remove roles for user '%s': %v", req.Username, err)
	}

	return gapi.UserToProto(user), nil
}

// AddUserBlueprints grants a user access to one or more blueprints.
func (s *IdentityService) AddUserBlueprints(ctx context.Context,
	req *identityv1.UserBlueprintsRequest) (*commonv1.User, error) {
	if req.Username == "" {
		return nil, status.Error(codes.InvalidArgument, "username is required")
	}
	if len(req.GetBlueprints()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "at least one blueprint is required")
	}
	if s.server.DB == nil {
		return nil, status.Error(codes.Unavailable, "database is not configured")
	}

	user, err := s.server.DB.AddUserBlueprints(req.Username, req.GetBlueprints())
	if err != nil {
		if errors.Is(err, models.ErrUserNotFound) {
			return nil, status.Errorf(codes.NotFound, "user '%s' not found", req.Username)
		}
		return nil, status.Errorf(codes.Internal, "failed to add blueprints for user '%s': %v", req.Username, err)
	}

	return gapi.UserToProto(user), nil
}

// RemoveUserBlueprints revokes access to one or more blueprints from a user.
func (s *IdentityService) RemoveUserBlueprints(ctx context.Context,
	req *identityv1.UserBlueprintsRequest) (*commonv1.User, error) {
	if req.Username == "" {
		return nil, status.Error(codes.InvalidArgument, "username is required")
	}
	if len(req.GetBlueprints()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "at least one blueprint is required")
	}
	if s.server.DB == nil {
		return nil, status.Error(codes.Unavailable, "database is not configured")
	}

	user, err := s.server.DB.RemoveUserBlueprints(req.Username, req.GetBlueprints())
	if err != nil {
		if errors.Is(err, models.ErrUserNotFound) {
			return nil, status.Errorf(codes.NotFound, "user '%s' not found", req.Username)
		}
		return nil, status.Errorf(codes.Internal, "failed to remove blueprints for user '%s': %v", req.Username, err)
	}

	return gapi.UserToProto(user), nil
}

// formatAuthKey renders an SSH public key as either its raw material or its
// SHA256 fingerprint, depending on format. Keys that fail to parse are
// returned unchanged.
func formatAuthKey(key string, format identityv1.AuthKeyFormat) string {
	if format != identityv1.AuthKeyFormat_AUTH_KEY_FORMAT_DIGEST {
		return key
	}
	parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(key))
	if err != nil {
		return key
	}
	return ssh.FingerprintSHA256(parsed)
}

// listUpstreamAuthKeys queries user's upstream identity provider (if any) for
// its registered SSH public keys via the provider's ListUserAuthKeys RPC.
// Keys are returned with raw (unformatted) key material and their source
// defaulted to the provider's name when the provider doesn't set one. A
// provider that doesn't support the call, or is unavailable, yields nil
// rather than an error.
func (s *IdentityService) listUpstreamAuthKeys(ctx context.Context, user *models.User) []*identityv1.UserAuthKey {
	provider, ok := s.server.providerByName(user.Source)
	if !ok {
		return nil
	}
	resp, err := provider.ListUserAuthKeys(ctx, &identityv1.Username{Username: user.Username})
	if err != nil {
		s.log.Warn().Err(err).Msgf(
			"failed to list auth keys from provider '%s' for user '%s'", provider.Name(), user.Username)
		return nil
	}
	keys := resp.GetAuthKeys()
	for _, k := range keys {
		if k.GetSource() == "" {
			k.Source = provider.Name()
		}
	}
	return keys
}

// ListUserAuthKeys returns all SSH public keys registered for a user, either
// as full key material or as SHA256 fingerprints depending on req.Format.
//
// Keys stored locally (via AddUserAuthKeys) are reported with source
// "local". The user's upstream identity provider is also consulted via its
// ListUserAuthKeys RPC; those keys are reported with the source it returns,
// falling back to the provider's name. A provider that doesn't support the
// call (or is unavailable) is skipped rather than failing the request.
// Upstream provider keys are always ordered before local keys.
func (s *IdentityService) ListUserAuthKeys(ctx context.Context,
	req *identityv1.ListUserAuthKeysRequest) (*identityv1.ListUserAuthKeysResponse, error) {
	if req.Username == "" {
		return nil, status.Error(codes.InvalidArgument, "username is required")
	}
	if s.server.DB == nil {
		return nil, status.Error(codes.Unavailable, "database is not configured")
	}

	user, err := s.server.GetUserByUsername(req.Username, "")
	if err != nil {
		if errors.Is(err, models.ErrUserNotFound) {
			return nil, status.Errorf(codes.NotFound, "user '%s' not found", req.Username)
		}
		return nil, propagateOrInternal(err, "error occurred when getting user '%s': %v", req.Username, err)
	}

	keys, err := s.server.DB.ListUserAuthKeys(user.Username)
	if err != nil {
		if errors.Is(err, models.ErrUserNotFound) {
			return nil, status.Errorf(codes.NotFound, "user '%s' not found", req.Username)
		}
		return nil, status.Errorf(codes.Internal, "failed to list auth keys for user '%s': %v", req.Username, err)
	}

	var authKeys []*identityv1.UserAuthKey

	for _, k := range s.listUpstreamAuthKeys(ctx, user) {
		authKeys = append(authKeys, &identityv1.UserAuthKey{
			Key:    formatAuthKey(k.GetKey(), req.GetFormat()),
			Source: k.GetSource(),
		})
	}

	for _, k := range keys {
		authKeys = append(authKeys, &identityv1.UserAuthKey{Key: formatAuthKey(k, req.GetFormat()), Source: "local"})
	}

	return &identityv1.ListUserAuthKeysResponse{AuthKeys: authKeys}, nil
}

// AddUserAuthKeys registers one or more SSH public keys for a user.
func (s *IdentityService) AddUserAuthKeys(ctx context.Context,
	req *identityv1.UserAuthKeysRequest) (*commonv1.User, error) {
	if req.Username == "" {
		return nil, status.Error(codes.InvalidArgument, "username is required")
	}
	if len(req.GetAuthKeys()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "at least one auth key is required")
	}
	if err := validateAuthKeys(req.GetAuthKeys()); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	if s.server.DB == nil {
		return nil, status.Error(codes.Unavailable, "database is not configured")
	}

	authUser, err := s.server.GetUserByUsername(req.Username, "")
	if err != nil {
		if errors.Is(err, models.ErrUserNotFound) {
			return nil, status.Errorf(codes.NotFound, "user '%s' not found", req.Username)
		}
		return nil, propagateOrInternal(err, "error occurred when getting user '%s': %v", req.Username, err)
	}

	for _, upstream := range s.listUpstreamAuthKeys(ctx, authUser) {
		for _, k := range req.GetAuthKeys() {
			if k == upstream.GetKey() {
				return nil, status.Errorf(codes.AlreadyExists,
					"auth key %q already exists for user '%s' via provider '%s'",
					k, req.Username, upstream.GetSource())
			}
		}
	}

	user, err := s.server.DB.AddUserAuthKeys(req.Username, req.GetAuthKeys())
	if err != nil {
		switch {
		case errors.Is(err, models.ErrUserNotFound):
			return nil, status.Errorf(codes.NotFound, "user '%s' not found", req.Username)
		case errors.Is(err, backend.ErrAuthKeyExists):
			return nil, status.Errorf(codes.AlreadyExists, "%v", err)
		}
		return nil, status.Errorf(codes.Internal, "failed to add auth keys for user '%s': %v", req.Username, err)
	}

	return gapi.UserToProto(user), nil
}

// RemoveUserAuthKey removes a single SSH public key from a user, identified
// by its index in the list returned by ListUserAuthKeys. Only keys with
// source "local" can be removed this way; keys reported under any other
// source are managed by their identity provider, not this service.
func (s *IdentityService) RemoveUserAuthKey(ctx context.Context,
	req *identityv1.RemoveUserAuthKeyRequest) (*commonv1.User, error) {
	if req.Username == "" {
		return nil, status.Error(codes.InvalidArgument, "username is required")
	}
	if s.server.DB == nil {
		return nil, status.Error(codes.Unavailable, "database is not configured")
	}

	list, err := s.ListUserAuthKeys(ctx, &identityv1.ListUserAuthKeysRequest{
		Username: req.Username,
		Format:   identityv1.AuthKeyFormat_AUTH_KEY_FORMAT_NORMAL,
	})
	if err != nil {
		return nil, err
	}

	keys := list.GetAuthKeys()
	if int(req.GetIndex()) >= len(keys) {
		return nil, status.Errorf(codes.InvalidArgument,
			"invalid auth key index %d for user '%s'", req.GetIndex(), req.Username)
	}
	if src := keys[req.GetIndex()].GetSource(); src != "local" {
		return nil, status.Errorf(codes.FailedPrecondition,
			"auth key at index %d for user '%s' is managed by provider '%s' and cannot be removed locally",
			req.GetIndex(), req.Username, src)
	}

	// ListUserAuthKeys prepends upstream provider keys before local ones, so
	// the requested index must be translated to its position within the
	// DB-only auth_keys array that db.RemoveUserAuthKey operates on.
	var localIndex uint32
	for _, k := range keys[:req.GetIndex()] {
		if k.GetSource() == "local" {
			localIndex++
		}
	}

	user, err := s.server.DB.RemoveUserAuthKey(req.Username, localIndex)
	if err != nil {
		switch {
		case errors.Is(err, models.ErrUserNotFound):
			return nil, status.Errorf(codes.NotFound, "user '%s' not found", req.Username)
		case errors.Is(err, models.ErrInvalidParameters):
			return nil, status.Errorf(codes.InvalidArgument, "%v", err)
		}
		return nil, status.Errorf(codes.Internal, "failed to remove auth key for user '%s': %v", req.Username, err)
	}

	return gapi.UserToProto(user), nil
}

func (s *IdentityService) GetAvailableIdentityProviders(
	ctx context.Context,
	req *identityv1.GetAvailableIdentityProvidersRequest,
) (*identityv1.GetAvailableIdentityProvidersResponse, error) {
	activeProviders := s.server.orderedProviders("")
	resp := make([]*identityv1.IdentityProviderInfo, len(activeProviders))
	for i, activeProvider := range activeProviders {
		resp[i] = &identityv1.IdentityProviderInfo{
			Name:         activeProvider.Name(),
			Capabilities: activeProvider.Capabilities(),
		}
	}

	return &identityv1.GetAvailableIdentityProvidersResponse{
		Providers: resp,
	}, nil
}

// CreateAccessToken issues a new Personal Access Token for a user.
// The raw token is returned once in the response and is not recoverable after that.
func (s *IdentityService) CreateAccessToken(ctx context.Context,
	req *identityv1.CreateAccessTokenRequest) (*identityv1.CreateAccessTokenResponse, error) {
	if s.server.DB == nil {
		return nil, status.Error(codes.Unavailable, "database is not configured, cannot create access token")
	}
	if req.Username == "" {
		return nil, status.Error(codes.InvalidArgument, "username is required")
	}
	if req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}
	if err := authz.ValidateScopes(req.GetScopes()); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}

	if _, err := s.server.GetUserByUsername(req.Username, ""); err != nil {
		if errors.Is(err, models.ErrUserNotFound) {
			return nil, status.Errorf(codes.NotFound, "user '%s' not found", req.Username)
		}
		return nil, propagateOrInternal(err, "error occurred when getting user '%s': %v", req.Username, err)
	}

	var expiresAt *time.Time
	if ts := req.GetExpiresAt(); ts != nil {
		t := ts.AsTime()
		expiresAt = &t
	}

	if req.GetRenew() {
		existing, err := s.server.DB.GetActiveAccessTokenByName(req.Username, req.Name)
		if err != nil && !errors.Is(err, models.ErrUserNotFound) {
			return nil, status.Errorf(codes.Internal, "failed to look up access token: %v", err)
		}
		if err == nil {
			raw, err := s.server.DB.RenewAccessToken(existing.ID, req.GetScopes(), expiresAt)
			if err != nil {
				return nil, status.Errorf(codes.Internal, "failed to renew access token: %v", err)
			}
			return &identityv1.CreateAccessTokenResponse{Id: existing.ID, Token: raw}, nil
		}
	}

	id, raw, err := s.server.DB.CreateAccessToken(req.Username, req.Name, req.GetScopes(), expiresAt)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create access token: %v", err)
	}

	return &identityv1.CreateAccessTokenResponse{Id: id, Token: raw}, nil
}

// ListAccessTokens returns access token metadata (no raw tokens or hashes) for a user.
func (s *IdentityService) ListAccessTokens(ctx context.Context,
	req *identityv1.Username) (*identityv1.ListAccessTokensResponse, error) {
	if s.server.DB == nil {
		return nil, status.Error(codes.Unavailable, "database is not configured, cannot list access tokens")
	}
	if req.Username == "" {
		return nil, status.Error(codes.InvalidArgument, "username is required")
	}

	tokens, err := s.server.DB.ListAccessTokens(req.Username)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to list access tokens: %v", err)
	}

	infos := make([]*identityv1.AccessTokenInfo, len(tokens))
	for i, t := range tokens {
		info := &identityv1.AccessTokenInfo{
			Id:        t.ID,
			Username:  t.Username,
			Name:      t.Name,
			Scopes:    t.Scopes,
			CreatedAt: timestamppb.New(t.CreatedAt),
			IsActive:  t.IsActive,
		}
		if t.ExpiresAt != nil {
			info.ExpiresAt = timestamppb.New(*t.ExpiresAt)
		}
		if t.LastUsedAt != nil {
			info.LastUsedAt = timestamppb.New(*t.LastUsedAt)
		}
		if t.TokenPreview != nil {
			info.TokenPreview = *t.TokenPreview
		}
		infos[i] = info
	}

	return &identityv1.ListAccessTokensResponse{Tokens: infos}, nil
}

// RevokeAccessToken soft-deletes an access token by ID, enforcing username ownership.
func (s *IdentityService) RevokeAccessToken(ctx context.Context,
	req *identityv1.RevokeAccessTokenRequest) (*identityv1.RevokeAccessTokenResponse, error) {
	if s.server.DB == nil {
		return nil, status.Error(codes.Unavailable, "database is not configured, cannot revoke access token")
	}
	if req.Username == "" {
		return nil, status.Error(codes.InvalidArgument, "username is required")
	}

	if err := s.server.DB.RevokeAccessToken(req.Id, req.Username); err != nil {
		if errors.Is(err, models.ErrUserNotFound) {
			return nil, status.Errorf(codes.NotFound, "access token %d not found for user '%s'", req.Id, req.Username)
		}
		return nil, status.Errorf(codes.Internal, "failed to revoke access token: %v", err)
	}

	return &identityv1.RevokeAccessTokenResponse{Success: true}, nil
}

// ResolveAccessToken looks up a raw k8sh_ token, updates last_used_at, and returns
// the owning user and the token's scopes. Called by API gateways on every k8sh_ request.
func (s *IdentityService) ResolveAccessToken(ctx context.Context,
	req *identityv1.ResolveAccessTokenRequest) (*identityv1.ResolveAccessTokenResponse, error) {
	if s.server.DB == nil {
		return nil, status.Error(codes.Unavailable, "database is not configured, cannot resolve access token")
	}
	if req.Token == "" {
		return nil, status.Error(codes.InvalidArgument, "token is required")
	}

	token, err := s.server.DB.ResolveAccessToken(req.Token)
	if err != nil {
		if errors.Is(err, models.ErrUserNotFound) {
			return nil, status.Error(codes.Unauthenticated, "invalid or expired access token")
		}
		return nil, status.Errorf(codes.Internal, "failed to resolve access token: %v", err)
	}

	user, err := s.server.GetUserByUsername(token.Username, "")
	if err != nil {
		if errors.Is(err, models.ErrUserNotFound) || errors.Is(err, models.ErrUserIsNotValid) {
			return nil, status.Error(codes.Unauthenticated, "invalid or expired access token")
		}
		return nil, propagateOrInternal(err, "error occurred when getting user '%s': %v", token.Username, err)
	}

	var userToken string
	if d := req.GetExpiry(); d != nil {
		userToken, err = s.server.issueUserTokenWithExpiry(user, d.AsDuration())
	} else {
		userToken, err = s.server.issueUserToken(user)
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to issue token for user '%s': %v", user.Username, err)
	}

	return &identityv1.ResolveAccessTokenResponse{
		User:      gapi.UserToProto(user),
		Scopes:    token.Scopes,
		UserToken: userToken,
	}, nil
}
