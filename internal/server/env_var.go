// Copyright 2026 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"context"
	"errors"

	identityv1 "github.com/k8shell-io/common/pkg/api/gen/go/identity/v1"
	"github.com/k8shell-io/common/pkg/models"
	backend "github.com/k8shell-io/identity/internal/db"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// envVarToProto converts a Go model to its protobuf representation. Value is
// returned in full — callers doing a list-style read must call
// redactSecretEnvVars afterward, per the EnvVar.value doc in
// identity/v1/types.proto.
func envVarToProto(v *models.EnvVar) *identityv1.EnvVar {
	if v == nil {
		return nil
	}
	return &identityv1.EnvVar{
		Key:       v.Key,
		Value:     v.Value,
		IsSecret:  v.IsSecret,
		Origin:    v.Origin,
		CreatedAt: timestamppb.New(v.CreatedAt),
		UpdatedAt: timestamppb.New(v.UpdatedAt),
	}
}

// redactSecretEnvVars blanks Value and sets Redacted on every secret entry.
// List calls redact secrets; Get/Add/Update return them in full.
func redactSecretEnvVars(pbVars []*identityv1.EnvVar) {
	for _, v := range pbVars {
		if v.IsSecret {
			v.Value = ""
			v.Redacted = true
		}
	}
}

// *** Organization environment variables

// ListOrganizationEnvVars returns the environment variables defined
// directly on an organization, with secret values redacted.
func (s *IdentityService) ListOrganizationEnvVars(ctx context.Context,
	req *identityv1.ListOrganizationEnvVarsRequest) (*identityv1.EnvVarList, error) {
	if req.GetOrg() == "" {
		return nil, status.Error(codes.InvalidArgument, "org is required")
	}
	if s.server.DB == nil {
		return nil, status.Error(codes.Unavailable, "database is not configured")
	}

	vars, err := s.server.DB.ListOrganizationEnvVars(req.GetOrg())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to list environment variables for organization '%s': %v", req.GetOrg(), err)
	}

	pbVars := make([]*identityv1.EnvVar, len(vars))
	for i, v := range vars {
		pbVars[i] = envVarToProto(v)
	}
	redactSecretEnvVars(pbVars)

	return &identityv1.EnvVarList{EnvVars: pbVars}, nil
}

// GetOrganizationEnvVar retrieves a single organization environment
// variable in full, including its value even when is_secret is true.
func (s *IdentityService) GetOrganizationEnvVar(ctx context.Context,
	req *identityv1.GetOrganizationEnvVarRequest) (*identityv1.EnvVar, error) {
	if req.GetOrg() == "" {
		return nil, status.Error(codes.InvalidArgument, "org is required")
	}
	if req.GetKey() == "" {
		return nil, status.Error(codes.InvalidArgument, "key is required")
	}
	if s.server.DB == nil {
		return nil, status.Error(codes.Unavailable, "database is not configured")
	}

	v, err := s.server.DB.GetOrganizationEnvVar(req.GetOrg(), req.GetKey())
	if err != nil {
		switch {
		case errors.Is(err, backend.ErrEnvVarNotFound):
			return nil, status.Errorf(codes.NotFound, "environment variable '%s' not found for organization '%s'", req.GetKey(), req.GetOrg())
		case errors.Is(err, models.ErrInvalidParameters):
			return nil, status.Errorf(codes.InvalidArgument, "%v", err)
		}
		return nil, status.Errorf(codes.Internal, "failed to get environment variable '%s' for organization '%s': %v", req.GetKey(), req.GetOrg(), err)
	}

	return envVarToProto(v), nil
}

// AddOrganizationEnvVar creates a new environment variable on an
// organization.
func (s *IdentityService) AddOrganizationEnvVar(ctx context.Context,
	req *identityv1.AddOrganizationEnvVarRequest) (*identityv1.EnvVar, error) {
	if req.GetOrg() == "" {
		return nil, status.Error(codes.InvalidArgument, "org is required")
	}
	if req.GetKey() == "" {
		return nil, status.Error(codes.InvalidArgument, "key is required")
	}
	if s.server.DB == nil {
		return nil, status.Error(codes.Unavailable, "database is not configured")
	}

	v, err := s.server.DB.AddOrganizationEnvVar(req.GetOrg(), req.GetKey(), req.GetValue(), req.GetIsSecret())
	if err != nil {
		switch {
		case errors.Is(err, backend.ErrEnvVarExists):
			return nil, status.Errorf(codes.AlreadyExists, "environment variable '%s' already exists for organization '%s'", req.GetKey(), req.GetOrg())
		case errors.Is(err, models.ErrInvalidParameters):
			return nil, status.Errorf(codes.InvalidArgument, "%v", err)
		}
		return nil, status.Errorf(codes.Internal, "failed to add environment variable '%s' for organization '%s': %v", req.GetKey(), req.GetOrg(), err)
	}

	return envVarToProto(v), nil
}

// UpdateOrganizationEnvVar partially updates an existing organization
// environment variable's value and/or is_secret flag.
func (s *IdentityService) UpdateOrganizationEnvVar(ctx context.Context,
	req *identityv1.UpdateOrganizationEnvVarRequest) (*identityv1.EnvVar, error) {
	if req.GetOrg() == "" {
		return nil, status.Error(codes.InvalidArgument, "org is required")
	}
	if req.GetKey() == "" {
		return nil, status.Error(codes.InvalidArgument, "key is required")
	}
	if s.server.DB == nil {
		return nil, status.Error(codes.Unavailable, "database is not configured")
	}

	var value *string
	if req.Value != nil {
		v := req.Value.GetValue()
		value = &v
	}
	var isSecret *bool
	if req.IsSecret != nil {
		v := req.IsSecret.GetValue()
		isSecret = &v
	}

	v, err := s.server.DB.UpdateOrganizationEnvVar(req.GetOrg(), req.GetKey(), value, isSecret)
	if err != nil {
		switch {
		case errors.Is(err, backend.ErrEnvVarNotFound):
			return nil, status.Errorf(codes.NotFound, "environment variable '%s' not found for organization '%s'", req.GetKey(), req.GetOrg())
		case errors.Is(err, models.ErrInvalidParameters):
			return nil, status.Errorf(codes.InvalidArgument, "%v", err)
		}
		return nil, status.Errorf(codes.Internal, "failed to update environment variable '%s' for organization '%s': %v", req.GetKey(), req.GetOrg(), err)
	}

	return envVarToProto(v), nil
}

// DeleteOrganizationEnvVar removes an environment variable from an
// organization.
func (s *IdentityService) DeleteOrganizationEnvVar(ctx context.Context,
	req *identityv1.DeleteOrganizationEnvVarRequest) (*identityv1.DeleteOrganizationEnvVarResponse, error) {
	if req.GetOrg() == "" {
		return nil, status.Error(codes.InvalidArgument, "org is required")
	}
	if req.GetKey() == "" {
		return nil, status.Error(codes.InvalidArgument, "key is required")
	}
	if s.server.DB == nil {
		return nil, status.Error(codes.Unavailable, "database is not configured")
	}

	if err := s.server.DB.DeleteOrganizationEnvVar(req.GetOrg(), req.GetKey()); err != nil {
		switch {
		case errors.Is(err, backend.ErrEnvVarNotFound):
			return nil, status.Errorf(codes.NotFound, "environment variable '%s' not found for organization '%s'", req.GetKey(), req.GetOrg())
		case errors.Is(err, models.ErrInvalidParameters):
			return nil, status.Errorf(codes.InvalidArgument, "%v", err)
		}
		return nil, status.Errorf(codes.Internal, "failed to delete environment variable '%s' for organization '%s': %v", req.GetKey(), req.GetOrg(), err)
	}

	return &identityv1.DeleteOrganizationEnvVarResponse{Success: true}, nil
}

// *** User environment variables

// ListUserEnvVars returns the effective environment variables for a user:
// their organization's variables, overridden by any of the user's own,
// with secret values redacted.
func (s *IdentityService) ListUserEnvVars(ctx context.Context,
	req *identityv1.ListUserEnvVarsRequest) (*identityv1.EnvVarList, error) {
	if req.GetUsername() == "" {
		return nil, status.Error(codes.InvalidArgument, "username is required")
	}
	if s.server.DB == nil {
		return nil, status.Error(codes.Unavailable, "database is not configured")
	}

	user, err := s.server.GetUserByUsername(req.GetUsername(), "")
	if err != nil {
		if errors.Is(err, models.ErrUserNotFound) {
			return nil, status.Errorf(codes.NotFound, "user '%s' not found", req.GetUsername())
		}
		return nil, propagateOrInternal(err, "error occurred when getting user '%s': %v", req.GetUsername(), err)
	}

	vars, err := s.server.DB.ListEffectiveUserEnvVars(user.Username, user.Organization)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to list environment variables for user '%s': %v", req.GetUsername(), err)
	}

	pbVars := make([]*identityv1.EnvVar, len(vars))
	for i, v := range vars {
		pbVars[i] = envVarToProto(v)
	}
	redactSecretEnvVars(pbVars)

	return &identityv1.EnvVarList{EnvVars: pbVars}, nil
}

// GetUserEnvVar retrieves a single effective environment variable for a
// user, in full, including its value even when is_secret is true.
func (s *IdentityService) GetUserEnvVar(ctx context.Context,
	req *identityv1.GetUserEnvVarRequest) (*identityv1.EnvVar, error) {
	if req.GetUsername() == "" {
		return nil, status.Error(codes.InvalidArgument, "username is required")
	}
	if req.GetKey() == "" {
		return nil, status.Error(codes.InvalidArgument, "key is required")
	}
	if s.server.DB == nil {
		return nil, status.Error(codes.Unavailable, "database is not configured")
	}

	user, err := s.server.GetUserByUsername(req.GetUsername(), "")
	if err != nil {
		if errors.Is(err, models.ErrUserNotFound) {
			return nil, status.Errorf(codes.NotFound, "user '%s' not found", req.GetUsername())
		}
		return nil, propagateOrInternal(err, "error occurred when getting user '%s': %v", req.GetUsername(), err)
	}

	v, err := s.server.DB.GetEffectiveUserEnvVar(user.Username, user.Organization, req.GetKey())
	if err != nil {
		switch {
		case errors.Is(err, backend.ErrEnvVarNotFound):
			return nil, status.Errorf(codes.NotFound, "environment variable '%s' not found for user '%s'", req.GetKey(), req.GetUsername())
		case errors.Is(err, models.ErrInvalidParameters):
			return nil, status.Errorf(codes.InvalidArgument, "%v", err)
		}
		return nil, status.Errorf(codes.Internal, "failed to get environment variable '%s' for user '%s': %v", req.GetKey(), req.GetUsername(), err)
	}

	return envVarToProto(v), nil
}

// AddUserEnvVar creates a new environment variable owned by the user,
// overriding any organization value with the same key.
func (s *IdentityService) AddUserEnvVar(ctx context.Context,
	req *identityv1.AddUserEnvVarRequest) (*identityv1.EnvVar, error) {
	if req.GetUsername() == "" {
		return nil, status.Error(codes.InvalidArgument, "username is required")
	}
	if req.GetKey() == "" {
		return nil, status.Error(codes.InvalidArgument, "key is required")
	}
	if s.server.DB == nil {
		return nil, status.Error(codes.Unavailable, "database is not configured")
	}

	_, err := s.server.GetUserByUsername(req.GetUsername(), "")
	if err != nil {
		if errors.Is(err, models.ErrUserNotFound) {
			return nil, status.Errorf(codes.NotFound, "user '%s' not found", req.GetUsername())
		}
		return nil, propagateOrInternal(err, "error occurred when getting user '%s': %v", req.GetUsername(), err)
	}

	v, err := s.server.DB.AddUserEnvVar(req.GetUsername(), req.GetKey(), req.GetValue(), req.GetIsSecret())
	if err != nil {
		switch {
		case errors.Is(err, backend.ErrEnvVarExists):
			return nil, status.Errorf(codes.AlreadyExists, "environment variable '%s' already exists for user '%s'", req.GetKey(), req.GetUsername())
		case errors.Is(err, models.ErrInvalidParameters):
			return nil, status.Errorf(codes.InvalidArgument, "%v", err)
		}
		return nil, status.Errorf(codes.Internal, "failed to add environment variable '%s' for user '%s': %v", req.GetKey(), req.GetUsername(), err)
	}

	return envVarToProto(v), nil
}

// UpdateUserEnvVar partially updates an existing user-owned environment
// variable override. Returns NotFound if the user has no override for key —
// AddUserEnvVar must be used to create one first.
func (s *IdentityService) UpdateUserEnvVar(ctx context.Context,
	req *identityv1.UpdateUserEnvVarRequest) (*identityv1.EnvVar, error) {
	if req.GetUsername() == "" {
		return nil, status.Error(codes.InvalidArgument, "username is required")
	}
	if req.GetKey() == "" {
		return nil, status.Error(codes.InvalidArgument, "key is required")
	}
	if s.server.DB == nil {
		return nil, status.Error(codes.Unavailable, "database is not configured")
	}

	var value *string
	if req.Value != nil {
		v := req.Value.GetValue()
		value = &v
	}
	var isSecret *bool
	if req.IsSecret != nil {
		v := req.IsSecret.GetValue()
		isSecret = &v
	}

	v, err := s.server.DB.UpdateUserEnvVar(req.GetUsername(), req.GetKey(), value, isSecret)
	if err != nil {
		switch {
		case errors.Is(err, backend.ErrEnvVarNotFound):
			return nil, status.Errorf(codes.NotFound,
				"environment variable '%s' not found for user '%s' (use AddUserEnvVar to create an override first)",
				req.GetKey(), req.GetUsername())
		case errors.Is(err, models.ErrInvalidParameters):
			return nil, status.Errorf(codes.InvalidArgument, "%v", err)
		}
		return nil, status.Errorf(codes.Internal, "failed to update environment variable '%s' for user '%s': %v", req.GetKey(), req.GetUsername(), err)
	}

	return envVarToProto(v), nil
}

// DeleteUserEnvVar removes a user-owned environment variable, restoring the
// organization's value (if any) as the effective value.
func (s *IdentityService) DeleteUserEnvVar(ctx context.Context,
	req *identityv1.DeleteUserEnvVarRequest) (*identityv1.DeleteUserEnvVarResponse, error) {
	if req.GetUsername() == "" {
		return nil, status.Error(codes.InvalidArgument, "username is required")
	}
	if req.GetKey() == "" {
		return nil, status.Error(codes.InvalidArgument, "key is required")
	}
	if s.server.DB == nil {
		return nil, status.Error(codes.Unavailable, "database is not configured")
	}

	if err := s.server.DB.DeleteUserEnvVar(req.GetUsername(), req.GetKey()); err != nil {
		switch {
		case errors.Is(err, backend.ErrEnvVarNotFound):
			return nil, status.Errorf(codes.NotFound, "environment variable '%s' not found for user '%s'", req.GetKey(), req.GetUsername())
		case errors.Is(err, models.ErrInvalidParameters):
			return nil, status.Errorf(codes.InvalidArgument, "%v", err)
		}
		return nil, status.Errorf(codes.Internal, "failed to delete environment variable '%s' for user '%s': %v", req.GetKey(), req.GetUsername(), err)
	}

	return &identityv1.DeleteUserEnvVarResponse{Success: true}, nil
}
