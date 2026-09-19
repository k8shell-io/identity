// Copyright 2026 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"context"
	"errors"

	identityv1 "github.com/k8shell-io/common/pkg/api/gen/go/identity/v1"
	"github.com/k8shell-io/common/pkg/models"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const (
	// maxUserSettingsDataBytes mirrors chk_user_settings_data_size in
	// db/migrations/000003_user_settings.up.sql — checked here too since
	// api-server's own ~64KB cap can be bypassed by other internal callers.
	maxUserSettingsDataBytes = 64 * 1024

	// minSessionIdleTimeoutSeconds / maxSessionIdleTimeoutSeconds bound
	// ControlledSettings.session_idle_timeout_seconds: 1 minute to 24 hours.
	minSessionIdleTimeoutSeconds = 60
	maxSessionIdleTimeoutSeconds = 86400
)

// controlledSettingsToProto converts the controlled-settings columns of a
// models.UserSettings to their protobuf representation.
func controlledSettingsToProto(s *models.UserSettings) *identityv1.ControlledSettings {
	c := &identityv1.ControlledSettings{}
	if s.SessionIdleTimeoutSeconds != nil {
		c.SessionIdleTimeoutSeconds = wrapperspb.Int32(*s.SessionIdleTimeoutSeconds)
	}
	return c
}

// validateControlledSettings extracts and range-checks the controlled
// settings from a PutUserSettingsRequest. A nil field is left nil (unset —
// use the platform default); a set field outside its valid range is
// rejected with InvalidArgument.
func validateControlledSettings(c *identityv1.ControlledSettings) (*int32, error) {
	if c == nil || c.SessionIdleTimeoutSeconds == nil {
		return nil, nil
	}
	v := c.SessionIdleTimeoutSeconds.GetValue()
	if v < minSessionIdleTimeoutSeconds || v > maxSessionIdleTimeoutSeconds {
		return nil, status.Errorf(codes.InvalidArgument,
			"session_idle_timeout_seconds must be between %d and %d, got %d",
			minSessionIdleTimeoutSeconds, maxSessionIdleTimeoutSeconds, v)
	}
	return &v, nil
}

// GetUserSettings retrieves a user's stored settings. A user with no
// settings row returns the zero-value response, not a NotFound error.
func (s *IdentityService) GetUserSettings(ctx context.Context,
	req *identityv1.GetUserSettingsRequest) (*identityv1.GetUserSettingsResponse, error) {
	if req.GetUsername() == "" {
		return nil, status.Error(codes.InvalidArgument, "username is required")
	}
	if s.server.DB == nil {
		return nil, status.Error(codes.Unavailable, "database is not configured")
	}

	settings, err := s.server.DB.GetUserSettings(req.GetUsername())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get settings for user '%s': %v", req.GetUsername(), err)
	}

	resp := &identityv1.GetUserSettingsResponse{
		Version:    settings.Version,
		Data:       settings.Data,
		Controlled: controlledSettingsToProto(settings),
	}
	if settings.Version > 0 {
		resp.UpdatedAt = timestamppb.New(settings.UpdatedAt)
	}
	return resp, nil
}

// PutUserSettings replaces a user's settings (last-write-wins UPSERT, no
// version-conflict check).
func (s *IdentityService) PutUserSettings(ctx context.Context,
	req *identityv1.PutUserSettingsRequest) (*identityv1.PutUserSettingsResponse, error) {
	if req.GetUsername() == "" {
		return nil, status.Error(codes.InvalidArgument, "username is required")
	}
	if len(req.GetData()) > maxUserSettingsDataBytes {
		return nil, status.Errorf(codes.InvalidArgument, "data exceeds maximum size of %d bytes", maxUserSettingsDataBytes)
	}
	if s.server.DB == nil {
		return nil, status.Error(codes.Unavailable, "database is not configured")
	}

	sessionIdleTimeout, err := validateControlledSettings(req.GetControlled())
	if err != nil {
		return nil, err
	}

	if _, err := s.server.GetUserByUsername(req.GetUsername(), ""); err != nil {
		if errors.Is(err, models.ErrUserNotFound) {
			return nil, status.Errorf(codes.NotFound, "user '%s' not found", req.GetUsername())
		}
		return nil, propagateOrInternal(err, "error occurred when getting user '%s': %v", req.GetUsername(), err)
	}

	settings, err := s.server.DB.PutUserSettings(req.GetUsername(), req.GetData(), sessionIdleTimeout)
	if err != nil {
		if errors.Is(err, models.ErrInvalidParameters) {
			return nil, status.Errorf(codes.InvalidArgument, "%v", err)
		}
		return nil, status.Errorf(codes.Internal, "failed to put settings for user '%s': %v", req.GetUsername(), err)
	}

	return &identityv1.PutUserSettingsResponse{
		Version:   settings.Version,
		UpdatedAt: timestamppb.New(settings.UpdatedAt),
	}, nil
}
