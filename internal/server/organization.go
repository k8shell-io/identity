// Copyright 2025 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"context"
	"errors"

	identityv1 "github.com/k8shell-io/common/pkg/api/gen/go/identity/v1"
	queryv1 "github.com/k8shell-io/common/pkg/api/gen/go/query/v1"
	"github.com/k8shell-io/common/pkg/authz"
	"github.com/k8shell-io/common/pkg/models"
	"github.com/k8shell-io/common/pkg/query"
	"github.com/k8shell-io/common/pkg/utils"
	backend "github.com/k8shell-io/identity/internal/db"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// organizationToProto converts a Go model to its protobuf representation.
func organizationToProto(o *models.Organization) *identityv1.Organization {
	if o == nil {
		return nil
	}
	return &identityv1.Organization{
		Name:           o.Name,
		Description:    o.Description,
		CreatedAt:      timestamppb.New(o.CreatedAt),
		AdminUsernames: o.AdminUsernames,
		UserCount:      utils.SafeIntToInt32(o.UserCount),
		ReadOnly:       o.ReadOnly,
	}
}

// ListOrganizations returns the registered organizations.
func (s *IdentityService) ListOrganizations(ctx context.Context,
	req *identityv1.ListOrganizationsRequest) (*identityv1.OrganizationList, error) {
	if s.server.DB == nil {
		return nil, status.Error(codes.Unavailable, "database is not configured")
	}

	orgs, err := s.server.DB.ListOrganizations()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to list organizations: %v", err)
	}

	pbOrgs := make([]*identityv1.Organization, len(orgs))
	for i, o := range orgs {
		pbOrgs[i] = organizationToProto(o)
	}

	return &identityv1.OrganizationList{Organizations: pbOrgs}, nil
}

// GetOrganization retrieves a single organization by name.
func (s *IdentityService) GetOrganization(ctx context.Context,
	req *identityv1.GetOrganizationRequest) (*identityv1.Organization, error) {
	if req.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}
	if s.server.DB == nil {
		return nil, status.Error(codes.Unavailable, "database is not configured")
	}

	org, err := s.server.DB.GetOrganization(req.GetName())
	if err != nil {
		if errors.Is(err, backend.ErrOrganizationNotFound) {
			return nil, status.Errorf(codes.NotFound, "organization '%s' not found", req.GetName())
		}
		return nil, status.Errorf(codes.Internal, "failed to get organization '%s': %v", req.GetName(), err)
	}

	return organizationToProto(org), nil
}

// GetOrganizationsQuerySchema returns the descriptor advertising which
// organization fields are queryable/sortable via QueryOrganizations, and
// which operators are valid on each.
func (s *IdentityService) GetOrganizationsQuerySchema(ctx context.Context,
	req *identityv1.GetOrganizationsQuerySchemaRequest) (*queryv1.Descriptor, error) {
	return organizationsQueryDescriptor, nil
}

// QueryOrganizations retrieves organizations matching a generic
// query.v1.Payload, as advertised by GetOrganizationsQuerySchema.
// req.Query.Obligations carries the authz obligations map from the
// gateway's policy evaluation (never client-supplied — see the field's doc
// in query.proto) and is enforced as a mandatory scoping constraint,
// independent of the caller's own Filters, the same way QueryUsers already
// enforces its obligations. org:list reuses the same "org" key as
// user:list/session:list (see authz.ParseOrgObligation) — a subject belongs
// to exactly one organization, so this is a single value, not a list.
func (s *IdentityService) QueryOrganizations(ctx context.Context,
	req *identityv1.QueryOrganizationsRequest) (*identityv1.OrganizationList, error) {
	if err := query.Validate(organizationsQueryDescriptor, req.Query); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid query: %v", err)
	}

	if s.server.DB == nil {
		return nil, status.Error(codes.Unavailable, "organization query requires a database backend")
	}

	orgOb, _ := authz.ParseOrgObligation(req.Query.GetObligations())

	orgs, err := s.server.DB.ListOrganizationsQuery(organizationsQueryDescriptor, organizationsQueryFieldMap, req.Query, orgOb.Org)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to query organizations: %v", err)
	}

	pbOrgs := make([]*identityv1.Organization, len(orgs))
	for i, o := range orgs {
		pbOrgs[i] = organizationToProto(o)
	}

	return &identityv1.OrganizationList{Organizations: pbOrgs}, nil
}

// CreateOrganization registers a new organization.
func (s *IdentityService) CreateOrganization(ctx context.Context,
	req *identityv1.CreateOrganizationRequest) (*identityv1.Organization, error) {
	if req.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}
	if s.server.DB == nil {
		return nil, status.Error(codes.Unavailable, "database is not configured")
	}

	org, err := s.server.DB.CreateOrganization(req.GetName(), req.GetDescription())
	if err != nil {
		if errors.Is(err, backend.ErrOrganizationExists) {
			return nil, status.Errorf(codes.AlreadyExists, "organization '%s' already exists", req.GetName())
		}
		return nil, status.Errorf(codes.Internal, "failed to create organization '%s': %v", req.GetName(), err)
	}

	return organizationToProto(org), nil
}

// UpdateOrganization updates an organization's description. The name is
// immutable and used only to identify the organization. Fails for the
// built-in "default" organization, which is read-only.
func (s *IdentityService) UpdateOrganization(ctx context.Context,
	req *identityv1.UpdateOrganizationRequest) (*identityv1.Organization, error) {
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

	org, err := s.server.DB.UpdateOrganization(req.GetName(), description)
	if err != nil {
		switch {
		case errors.Is(err, backend.ErrOrganizationNotFound):
			return nil, status.Errorf(codes.NotFound, "organization '%s' not found", req.GetName())
		case errors.Is(err, backend.ErrOrganizationReadOnly):
			return nil, status.Errorf(codes.FailedPrecondition,
				"organization '%s' is read-only and cannot be updated", req.GetName())
		}
		return nil, status.Errorf(codes.Internal, "failed to update organization '%s': %v", req.GetName(), err)
	}

	return organizationToProto(org), nil
}

// DeleteOrganization removes an organization from the registry, cascading
// its org-scoped roles. Fails if any user still belongs to it, or if it's
// the built-in "default" organization, which is read-only.
func (s *IdentityService) DeleteOrganization(ctx context.Context,
	req *identityv1.DeleteOrganizationRequest) (*identityv1.DeleteOrganizationResponse, error) {
	if req.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}
	if s.server.DB == nil {
		return nil, status.Error(codes.Unavailable, "database is not configured")
	}

	if err := s.server.DB.DeleteOrganization(req.GetName()); err != nil {
		switch {
		case errors.Is(err, backend.ErrOrganizationNotFound):
			return nil, status.Errorf(codes.NotFound, "organization '%s' not found", req.GetName())
		case errors.Is(err, backend.ErrOrganizationInUse):
			return nil, status.Errorf(codes.FailedPrecondition,
				"organization '%s' is still referenced by at least one user", req.GetName())
		case errors.Is(err, backend.ErrOrganizationReadOnly):
			return nil, status.Errorf(codes.FailedPrecondition,
				"organization '%s' is read-only and cannot be deleted", req.GetName())
		}
		return nil, status.Errorf(codes.Internal, "failed to delete organization '%s': %v", req.GetName(), err)
	}

	return &identityv1.DeleteOrganizationResponse{Success: true}, nil
}
