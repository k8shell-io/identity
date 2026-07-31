// Copyright 2025 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"context"
	"errors"
	"strings"

	identityv1 "github.com/k8shell-io/common/pkg/api/gen/go/identity/v1"
	"github.com/k8shell-io/common/pkg/models"
	"github.com/k8shell-io/common/pkg/utils"
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
		UserCount:   utils.SafeIntToInt32(r.UserCount),
		Blueprints:  r.Blueprints,
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

// ListRoles returns the roles assignable within req.Org: those scoped to it
// plus all global roles.
func (s *IdentityService) ListRoles(ctx context.Context,
	req *identityv1.ListRolesRequest) (*identityv1.RoleList, error) {
	if req.GetOrg() == "" {
		return nil, status.Error(codes.InvalidArgument, "org is required")
	}
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

// ListGlobalRoles returns the roles assignable across every organization.
// Global roles can only be listed, never created, updated, or deleted.
func (s *IdentityService) ListGlobalRoles(ctx context.Context,
	req *identityv1.ListGlobalRolesRequest) (*identityv1.RoleList, error) {
	if s.server.DB == nil {
		return nil, status.Error(codes.Unavailable, "database is not configured")
	}

	roles, err := s.server.DB.ListGlobalRoles()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to list global roles: %v", err)
	}

	pbRoles := make([]*identityv1.Role, len(roles))
	for i, r := range roles {
		pbRoles[i] = roleToProto(r)
	}

	return &identityv1.RoleList{Roles: pbRoles}, nil
}

// CreateRole registers a new assignable role scoped to org. Global roles
// cannot be created through this RPC — only listed, via ListGlobalRoles.
func (s *IdentityService) CreateRole(ctx context.Context,
	req *identityv1.CreateRoleRequest) (*identityv1.Role, error) {
	if req.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}
	if req.GetOrg() == "" {
		return nil, status.Error(codes.InvalidArgument, "org is required")
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
// cannot be changed. org is required; global roles cannot be updated through
// this RPC.
func (s *IdentityService) UpdateRole(ctx context.Context,
	req *identityv1.UpdateRoleRequest) (*identityv1.Role, error) {
	if req.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}
	if req.GetOrg() == "" {
		return nil, status.Error(codes.InvalidArgument, "org is required")
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
		switch {
		case errors.Is(err, backend.ErrRoleNotFound):
			return nil, status.Errorf(codes.NotFound, "role '%s' not found", req.GetName())
		case errors.Is(err, backend.ErrRoleIsGlobal):
			return nil, status.Errorf(codes.FailedPrecondition,
				"role '%s' is a global role and cannot be updated", req.GetName())
		}
		return nil, status.Errorf(codes.Internal, "failed to update role '%s': %v", req.GetName(), err)
	}

	return roleToProto(role), nil
}

// DeleteRole removes a role from the registry. Fails if any user still holds
// the role, since cascading the role off every user would be a silent
// privilege change. org is required; global roles cannot be removed through
// this RPC.
func (s *IdentityService) DeleteRole(ctx context.Context,
	req *identityv1.DeleteRoleRequest) (*identityv1.DeleteRoleResponse, error) {
	if req.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}
	if req.GetOrg() == "" {
		return nil, status.Error(codes.InvalidArgument, "org is required")
	}
	if s.server.DB == nil {
		return nil, status.Error(codes.Unavailable, "database is not configured")
	}

	if err := s.server.DB.DeleteRole(req.GetName(), req.GetOrg()); err != nil {
		switch {
		case errors.Is(err, backend.ErrRoleNotFound):
			return nil, status.Errorf(codes.NotFound, "role '%s' not found", req.GetName())
		case errors.Is(err, backend.ErrRoleIsGlobal):
			return nil, status.Errorf(codes.FailedPrecondition,
				"role '%s' is a global role and cannot be deleted", req.GetName())
		case errors.Is(err, backend.ErrRoleInUse):
			return nil, status.Errorf(codes.FailedPrecondition,
				"role '%s' is still assigned to at least one user", req.GetName())
		}
		return nil, status.Errorf(codes.Internal, "failed to delete role '%s': %v", req.GetName(), err)
	}

	return &identityv1.DeleteRoleResponse{Success: true}, nil
}

// AddRoleBlueprints grants a role one or more blueprints; every user holding
// the role gains access to them. org is required; global roles are not
// supported through this RPC.
func (s *IdentityService) AddRoleBlueprints(ctx context.Context,
	req *identityv1.RoleBlueprintsRequest) (*identityv1.Role, error) {
	if req.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}
	if req.GetOrg() == "" {
		return nil, status.Error(codes.InvalidArgument, "org is required")
	}
	if len(req.GetBlueprints()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "at least one blueprint is required")
	}
	if s.server.DB == nil {
		return nil, status.Error(codes.Unavailable, "database is not configured")
	}

	role, err := s.server.DB.AddRoleBlueprints(req.GetName(), req.GetOrg(), req.GetBlueprints())
	if err != nil {
		switch {
		case errors.Is(err, backend.ErrRoleNotFound):
			return nil, status.Errorf(codes.NotFound, "role '%s' not found", req.GetName())
		case errors.Is(err, backend.ErrRoleIsGlobal):
			return nil, status.Errorf(codes.FailedPrecondition,
				"role '%s' is a global role and cannot be granted blueprints", req.GetName())
		}
		return nil, status.Errorf(codes.Internal, "failed to add blueprints for role '%s': %v", req.GetName(), err)
	}

	return roleToProto(role), nil
}

// RemoveRoleBlueprints revokes one or more blueprints from a role. org is
// required; global roles are not supported through this RPC.
func (s *IdentityService) RemoveRoleBlueprints(ctx context.Context,
	req *identityv1.RoleBlueprintsRequest) (*identityv1.Role, error) {
	if req.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}
	if req.GetOrg() == "" {
		return nil, status.Error(codes.InvalidArgument, "org is required")
	}
	if len(req.GetBlueprints()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "at least one blueprint is required")
	}
	if s.server.DB == nil {
		return nil, status.Error(codes.Unavailable, "database is not configured")
	}

	role, err := s.server.DB.RemoveRoleBlueprints(req.GetName(), req.GetOrg(), req.GetBlueprints())
	if err != nil {
		switch {
		case errors.Is(err, backend.ErrRoleNotFound):
			return nil, status.Errorf(codes.NotFound, "role '%s' not found", req.GetName())
		case errors.Is(err, backend.ErrRoleIsGlobal):
			return nil, status.Errorf(codes.FailedPrecondition,
				"role '%s' is a global role and cannot have blueprints revoked", req.GetName())
		}
		return nil, status.Errorf(codes.Internal, "failed to remove blueprints for role '%s': %v", req.GetName(), err)
	}

	return roleToProto(role), nil
}
