// Copyright 2025 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"context"
	"errors"
	"strings"

	identityv1 "github.com/k8shell-io/common/pkg/api/gen/go/identity/v1"
	"github.com/k8shell-io/common/pkg/models"
	backend "github.com/k8shell-io/identity/internal/db"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// roleToProto converts a Go model to its protobuf representation.
func roleToProto(r *models.RoleInfo) *identityv1.Role {
	if r == nil {
		return nil
	}
	return &identityv1.Role{
		Name:        r.Name,
		Description: r.Description,
		Org:         r.Org,
		CreatedAt:   timestamppb.New(r.CreatedAt),
		UserCount:   int32(r.UserCount),
	}
}

// validateRoleAssignment checks that every role in roles is registered,
// returning codes.InvalidArgument naming every unknown role at once. A
// nil/empty roles slice is always valid. Shared by CreateUser, UpdateUser,
// and AddUserRoles so the three write paths cannot drift apart; deliberately
// not called by RemoveUserRoles, which must stay able to remove a stale or
// since-deleted role.
func (s *IdentityService) validateRoleAssignment(roles []string) error {
	if len(roles) == 0 {
		return nil
	}

	missing, err := s.server.DB.MissingRoles(roles)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to validate roles: %v", err)
	}
	if len(missing) > 0 {
		return status.Errorf(codes.InvalidArgument, "unknown role(s): %s", strings.Join(missing, ", "))
	}
	return nil
}

// ListRoles returns the roles that may be assigned to users, optionally
// filtered by organization.
func (s *IdentityService) ListRoles(ctx context.Context,
	req *identityv1.ListRolesRequest) (*identityv1.RoleList, error) {
	if s.server.DB == nil {
		return nil, status.Error(codes.Unavailable, "database is not configured")
	}

	roles, err := s.server.DB.ListRoles(req.GetOrg())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to list roles: %v", err)
	}

	pbRoles := make([]*identityv1.Role, len(roles))
	for i, r := range roles {
		pbRoles[i] = roleToProto(r)
	}

	return &identityv1.RoleList{Roles: pbRoles}, nil
}

// CreateRole registers a new assignable role.
func (s *IdentityService) CreateRole(ctx context.Context,
	req *identityv1.CreateRoleRequest) (*identityv1.Role, error) {
	if req.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}
	if s.server.DB == nil {
		return nil, status.Error(codes.Unavailable, "database is not configured")
	}

	role, err := s.server.DB.CreateRole(req.GetName(), req.GetDescription(), req.GetOrg())
	if err != nil {
		switch {
		case errors.Is(err, backend.ErrRoleExists):
			return nil, status.Errorf(codes.AlreadyExists, "role '%s' already exists", req.GetName())
		case errors.Is(err, models.ErrInvalidParameters):
			return nil, status.Errorf(codes.InvalidArgument, "%v", err)
		}
		return nil, status.Errorf(codes.Internal, "failed to create role '%s': %v", req.GetName(), err)
	}

	return roleToProto(role), nil
}

// UpdateRole updates a role's description. Name and org are immutable and
// cannot be changed.
func (s *IdentityService) UpdateRole(ctx context.Context,
	req *identityv1.UpdateRoleRequest) (*identityv1.Role, error) {
	if req.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}
	if s.server.DB == nil {
		return nil, status.Error(codes.Unavailable, "database is not configured")
	}

	var description *string
	if req.Description != nil {
		description = &req.Description.Value
	}

	role, err := s.server.DB.UpdateRole(req.GetName(), req.GetOrg(), description)
	if err != nil {
		if errors.Is(err, backend.ErrRoleNotFound) {
			return nil, status.Errorf(codes.NotFound, "role '%s' not found", req.GetName())
		}
		return nil, status.Errorf(codes.Internal, "failed to update role '%s': %v", req.GetName(), err)
	}

	return roleToProto(role), nil
}

// DeleteRole removes a role from the registry. Fails if any user still holds
// the role, since cascading the role off every user would be a silent
// privilege change.
func (s *IdentityService) DeleteRole(ctx context.Context,
	req *identityv1.DeleteRoleRequest) (*identityv1.DeleteRoleResponse, error) {
	if req.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}
	if s.server.DB == nil {
		return nil, status.Error(codes.Unavailable, "database is not configured")
	}

	if err := s.server.DB.DeleteRole(req.GetName(), req.GetOrg()); err != nil {
		switch {
		case errors.Is(err, backend.ErrRoleNotFound):
			return nil, status.Errorf(codes.NotFound, "role '%s' not found", req.GetName())
		case errors.Is(err, backend.ErrRoleInUse):
			return nil, status.Errorf(codes.FailedPrecondition,
				"role '%s' is still assigned to at least one user", req.GetName())
		}
		return nil, status.Errorf(codes.Internal, "failed to delete role '%s': %v", req.GetName(), err)
	}

	return &identityv1.DeleteRoleResponse{Success: true}, nil
}
