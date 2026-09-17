// Copyright 2026 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"context"
	"errors"
	"time"

	identityv1 "github.com/k8shell-io/common/pkg/api/gen/go/identity/v1"
	"github.com/k8shell-io/common/pkg/models"
	backend "github.com/k8shell-io/identity/internal/db"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// announcementToProto converts a Go model to its protobuf representation.
func announcementToProto(a *models.Announcement) *identityv1.Announcement {
	if a == nil {
		return nil
	}
	pb := &identityv1.Announcement{
		Id:           a.ID,
		Translations: announcementTranslationsToProto(a.Translations),
		CreatedBy:    a.CreatedBy,
		Orgs:         a.Orgs,
		CreatedAt:    timestamppb.New(a.CreatedAt),
		UpdatedAt:    timestamppb.New(a.UpdatedAt),
		ReadCount:    a.ReadCount,
		IsRead:       a.IsRead,
	}
	if a.StartsAt != nil {
		pb.StartsAt = timestamppb.New(*a.StartsAt)
	}
	if a.EndsAt != nil {
		pb.EndsAt = timestamppb.New(*a.EndsAt)
	}
	if a.ReadAt != nil {
		pb.ReadAt = timestamppb.New(*a.ReadAt)
	}
	return pb
}

func announcementListToProto(list []*models.Announcement) *identityv1.AnnouncementList {
	pbList := make([]*identityv1.Announcement, len(list))
	for i, a := range list {
		pbList[i] = announcementToProto(a)
	}
	return &identityv1.AnnouncementList{Announcements: pbList}
}

func announcementTranslationsToProto(translations []models.AnnouncementTranslation) []*identityv1.AnnouncementTranslation {
	pb := make([]*identityv1.AnnouncementTranslation, len(translations))
	for i, t := range translations {
		pb[i] = &identityv1.AnnouncementTranslation{Lang: t.Lang, Title: t.Title, Body: t.Body}
	}
	return pb
}

func announcementTranslationsFromProto(pb []*identityv1.AnnouncementTranslation) []models.AnnouncementTranslation {
	translations := make([]models.AnnouncementTranslation, len(pb))
	for i, t := range pb {
		translations[i] = models.AnnouncementTranslation{Lang: t.GetLang(), Title: t.GetTitle(), Body: t.GetBody()}
	}
	return translations
}

// CreateAnnouncement creates a new announcement. It is global when orgs is
// empty, otherwise scoped to the listed organizations.
func (s *IdentityService) CreateAnnouncement(_ context.Context,
	req *identityv1.CreateAnnouncementRequest) (*identityv1.Announcement, error) {
	if len(req.GetTranslations()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "at least one translation is required")
	}
	if req.GetCreatedBy() == "" {
		return nil, status.Error(codes.InvalidArgument, "created_by is required")
	}
	if s.server.DB == nil {
		return nil, status.Error(codes.Unavailable, "database is not configured")
	}

	a := &models.Announcement{
		Translations: announcementTranslationsFromProto(req.GetTranslations()),
		CreatedBy:    req.GetCreatedBy(),
		Orgs:         req.GetOrgs(),
	}
	if req.StartsAt != nil {
		t := req.GetStartsAt().AsTime()
		a.StartsAt = &t
	}
	if req.EndsAt != nil {
		t := req.GetEndsAt().AsTime()
		a.EndsAt = &t
	}

	created, err := s.server.DB.CreateAnnouncement(a)
	if err != nil {
		if errors.Is(err, models.ErrInvalidParameters) {
			return nil, status.Errorf(codes.InvalidArgument, "%v", err)
		}
		return nil, status.Errorf(codes.Internal, "failed to create announcement: %v", err)
	}

	return announcementToProto(created), nil
}

// GetAnnouncement retrieves a single announcement by id, including its
// read_count (the number of distinct users who have read it).
func (s *IdentityService) GetAnnouncement(_ context.Context,
	req *identityv1.GetAnnouncementRequest) (*identityv1.Announcement, error) {
	if s.server.DB == nil {
		return nil, status.Error(codes.Unavailable, "database is not configured")
	}

	a, err := s.server.DB.GetAnnouncement(req.GetId())
	if err != nil {
		if errors.Is(err, backend.ErrAnnouncementNotFound) {
			return nil, status.Errorf(codes.NotFound, "announcement '%d' not found", req.GetId())
		}
		return nil, status.Errorf(codes.Internal, "failed to get announcement '%d': %v", req.GetId(), err)
	}

	return announcementToProto(a), nil
}

// UpdateAnnouncement partially updates an announcement's translations, org
// scope, and/or validity period.
func (s *IdentityService) UpdateAnnouncement(_ context.Context,
	req *identityv1.UpdateAnnouncementRequest) (*identityv1.Announcement, error) {
	if s.server.DB == nil {
		return nil, status.Error(codes.Unavailable, "database is not configured")
	}

	var startsAt *time.Time
	if req.StartsAt != nil {
		t := req.GetStartsAt().AsTime()
		startsAt = &t
	}
	var endsAt *time.Time
	if req.EndsAt != nil {
		t := req.GetEndsAt().AsTime()
		endsAt = &t
	}

	updated, err := s.server.DB.UpdateAnnouncement(req.GetId(), announcementTranslationsFromProto(req.GetTranslations()),
		req.GetOrgs(), req.GetClearOrgs(),
		startsAt, req.GetClearStartsAt(),
		endsAt, req.GetClearEndsAt(),
	)
	if err != nil {
		switch {
		case errors.Is(err, backend.ErrAnnouncementNotFound):
			return nil, status.Errorf(codes.NotFound, "announcement '%d' not found", req.GetId())
		case errors.Is(err, models.ErrInvalidParameters):
			return nil, status.Errorf(codes.InvalidArgument, "%v", err)
		}
		return nil, status.Errorf(codes.Internal, "failed to update announcement '%d': %v", req.GetId(), err)
	}

	return announcementToProto(updated), nil
}

// DeleteAnnouncement permanently removes an announcement, along with its
// read tracking.
func (s *IdentityService) DeleteAnnouncement(_ context.Context,
	req *identityv1.DeleteAnnouncementRequest) (*identityv1.DeleteAnnouncementResponse, error) {
	if s.server.DB == nil {
		return nil, status.Error(codes.Unavailable, "database is not configured")
	}

	if err := s.server.DB.DeleteAnnouncement(req.GetId()); err != nil {
		if errors.Is(err, backend.ErrAnnouncementNotFound) {
			return nil, status.Errorf(codes.NotFound, "announcement '%d' not found", req.GetId())
		}
		return nil, status.Errorf(codes.Internal, "failed to delete announcement '%d': %v", req.GetId(), err)
	}

	return &identityv1.DeleteAnnouncementResponse{Success: true}, nil
}

// ListAnnouncements returns announcements for administration: every
// announcement, optionally filtered to those that apply to org, each with
// its read_count populated. Unlike ListUnreadAnnouncements/
// ListUserAnnouncements it is not scoped to a requesting user and is not
// filtered by validity period.
func (s *IdentityService) ListAnnouncements(_ context.Context,
	req *identityv1.ListAnnouncementsRequest) (*identityv1.AnnouncementList, error) {
	if s.server.DB == nil {
		return nil, status.Error(codes.Unavailable, "database is not configured")
	}

	list, err := s.server.DB.ListAnnouncements(req.GetOrg(), int(req.GetLimit()), int(req.GetOffset()))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to list announcements: %v", err)
	}

	return announcementListToProto(list), nil
}

// ListUnreadAnnouncements returns announcements that apply to username's
// organization (global or scoped to it), currently fall within their
// validity period, and that username has not yet read.
func (s *IdentityService) ListUnreadAnnouncements(_ context.Context,
	req *identityv1.ListUnreadAnnouncementsRequest) (*identityv1.AnnouncementList, error) {
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

	list, err := s.server.DB.ListUnreadAnnouncements(user.Username, user.Organization)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to list unread announcements for user '%s': %v", req.GetUsername(), err)
	}

	return announcementListToProto(list), nil
}

// ListUserAnnouncements returns every announcement that applies to
// username's organization (global or scoped to it), regardless of validity
// period or read status, with is_read/read_at populated per announcement so
// a client can distinguish ones already seen.
func (s *IdentityService) ListUserAnnouncements(_ context.Context,
	req *identityv1.ListUserAnnouncementsRequest) (*identityv1.AnnouncementList, error) {
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

	list, err := s.server.DB.ListUserAnnouncements(user.Username, user.Organization)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to list announcements for user '%s': %v", req.GetUsername(), err)
	}

	return announcementListToProto(list), nil
}

// MarkAnnouncementRead records that username has read an announcement.
// Idempotent — marking an already-read announcement again does not change
// its original read_at.
func (s *IdentityService) MarkAnnouncementRead(_ context.Context,
	req *identityv1.MarkAnnouncementReadRequest) (*identityv1.MarkAnnouncementReadResponse, error) {
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

	if err := s.server.DB.MarkAnnouncementRead(req.GetId(), user.Username); err != nil {
		switch {
		case errors.Is(err, backend.ErrAnnouncementNotFound):
			return nil, status.Errorf(codes.NotFound, "announcement '%d' not found", req.GetId())
		case errors.Is(err, models.ErrInvalidParameters):
			return nil, status.Errorf(codes.InvalidArgument, "%v", err)
		}
		return nil, status.Errorf(codes.Internal, "failed to mark announcement '%d' read for user '%s': %v", req.GetId(), req.GetUsername(), err)
	}

	return &identityv1.MarkAnnouncementReadResponse{Success: true}, nil
}
