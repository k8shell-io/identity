// Copyright 2026 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	identityv1 "github.com/k8shell-io/common/pkg/api/gen/go/identity/v1"
	"github.com/k8shell-io/common/pkg/models"
	"github.com/k8shell-io/identity/internal/mail"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// mailKindNotification is the identity.mail_sends kind recorded for
// NotifyUser mail, counted against the shared daily recipient cap.
const mailKindNotification = "notification"

// sendNotificationMail delivers a NotifyUser message, using the injectable
// notifyMailSender when set (tests) and the SMTP-backed mail package otherwise.
func (s *Server) sendNotificationMail(to, subject, body string) (string, error) {
	if s.notifyMailSender != nil {
		return s.notifyMailSender(to, subject, body)
	}
	return mail.SendNotificationEmail(mail.Config{
		Host:     s.smtpCfg.Host,
		Port:     s.smtpCfg.Port,
		Username: s.smtpCfg.Username,
		Password: s.smtpCfg.Password,
		From:     s.smtpCfg.From,
	}, to, subject, body)
}

// notificationUserSettings is the scoped view of identity.user_settings.data
// that NotifyUser needs (like announcementUserSettings, an exception to the
// blob being opaque). A nil flag means the user never set it.
type notificationUserSettings struct {
	Notifications struct {
		WorkspaceStopWarning *bool `json:"workspaceStopWarning"`
		WorkspaceStopped     *bool `json:"workspaceStopped"`
		WorkspaceTerminated  *bool `json:"workspaceTerminated"`
	} `json:"notifications"`
}

// notificationAllowed reports whether the user's settings permit emailing a
// message of the given category. Notifications are operational, so this
// fails open: a missing key, unknown category, missing/unparseable settings,
// or a DB error all allow the send; only an explicit false opts out.
func (s *Server) notificationAllowed(username, category string) bool {
	if s.DB == nil {
		return true
	}
	settings, err := s.DB.GetUserSettings(username)
	if err != nil {
		s.log.Warn().Err(err).Str("username", username).
			Msg("notify user: failed to load user settings; sending anyway")
		return true
	}
	if len(settings.Data) == 0 {
		return true
	}
	var parsed notificationUserSettings
	if err := json.Unmarshal(settings.Data, &parsed); err != nil {
		s.log.Warn().Err(err).Str("username", username).
			Msg("notify user: failed to parse user settings; sending anyway")
		return true
	}
	var flag *bool
	switch category {
	case "workspace.stop-warning":
		flag = parsed.Notifications.WorkspaceStopWarning
	case "workspace.stopped":
		flag = parsed.Notifications.WorkspaceStopped
	case "workspace.terminated":
		flag = parsed.Notifications.WorkspaceTerminated
	}
	return flag == nil || *flag
}

// maskEmail hides most of an address's local part so it can be logged for
// triage without writing the full address: "alice@example.com" becomes
// "a***@example.com".
func maskEmail(addr string) string {
	local, domain, ok := strings.Cut(addr, "@")
	if !ok || local == "" {
		return "***"
	}
	return local[:1] + "***@" + domain
}

// NotifyUser emails a one-off, caller-worded message to a single user.
// Unlike RequestPasswordReset (whose outcome callers discard), the caller of
// NotifyUser is a service that needs to know whether the message was
// accepted, so failures are returned as errors rather than swallowed:
//
//   - InvalidArgument: a required field is empty
//   - NotFound: the user does not exist
//   - FailedPrecondition: the user has no email address
//   - Unavailable: SMTP is not configured, or the relay send failed
//   - ResourceExhausted: the shared daily recipient cap is reached
//
// If the user's settings opt out of the category (notifications.workspaceStopWarning,
// workspaceStopped, workspaceTerminated = false), nothing is sent and the call
// succeeds.
//
// Success means the relay accepted the message, not that it was delivered.
func (s *IdentityService) NotifyUser(ctx context.Context,
	req *identityv1.NotifyUserRequest) (*identityv1.NotifyUserResponse, error) {
	if req.GetUsername() == "" {
		return nil, status.Error(codes.InvalidArgument, "username is required")
	}
	if strings.TrimSpace(req.GetTitle()) == "" {
		return nil, status.Error(codes.InvalidArgument, "title is required")
	}
	if strings.TrimSpace(req.GetBody()) == "" {
		return nil, status.Error(codes.InvalidArgument, "body is required")
	}
	if req.GetCategory() == "" {
		return nil, status.Error(codes.InvalidArgument, "category is required")
	}

	if !s.server.smtpCfg.Enabled && s.server.notifyMailSender == nil {
		return nil, status.Error(codes.Unavailable, "email delivery is not configured")
	}

	user, err := s.server.GetUserByUsername(req.Username, "")
	if err != nil {
		if errors.Is(err, models.ErrUserNotFound) {
			return nil, status.Errorf(codes.NotFound, "user '%s' not found", req.Username)
		}
		return nil, s.mapUserLookupError(err, req.Username)
	}
	if user.Email == "" {
		return nil, status.Errorf(codes.FailedPrecondition, "user '%s' has no email address", req.Username)
	}

	if !s.server.notificationAllowed(req.Username, req.Category) {
		s.log.Info().Str("username", req.Username).Str("category", req.Category).
			Msg("notify user: user opted out of this notification; skipping")
		return &identityv1.NotifyUserResponse{}, nil
	}

	budget, err := s.server.remainingMailBudget()
	if err != nil {
		// remainingMailBudget fails closed; for an explicit service call,
		// report it instead of silently dropping the message.
		s.log.Warn().Err(err).Str("username", req.Username).
			Msg("notify user: failed to check daily recipient budget")
		return nil, status.Error(codes.Unavailable, "could not check the daily mail budget")
	}
	if budget <= 0 {
		s.log.Warn().Str("username", req.Username).Str("category", req.Category).
			Msg("notify user: daily recipient cap reached; not sending")
		return nil, status.Error(codes.ResourceExhausted, "daily email recipient cap reached")
	}

	cfg := s.server.smtpCfg
	logger := s.log.With().Str("username", req.Username).Str("category", req.Category).
		Str("recipient", maskEmail(user.Email)).Str("smtp_host", cfg.Host).Int("smtp_port", cfg.Port).
		Str("smtp_from", cfg.From).Logger()
	logger.Debug().Int("subject_bytes", len(req.Title)).Int("body_bytes", len(req.Body)).
		Int("mail_budget", budget).Msg("notify user: sending")

	started := time.Now()
	reply, err := s.server.sendNotificationMail(user.Email, req.Title, req.Body)
	elapsed := time.Since(started)
	if err != nil {
		logger.Error().Err(err).Dur("elapsed", elapsed).Msg("notify user: failed to send email")
		return nil, status.Error(codes.Unavailable, "failed to send email")
	}
	// smtp_reply is the relay's answer to the message (for Gmail it contains
	// the queue id): the handle for tracing delivery on the relay side.
	logger.Info().Str("smtp_reply", reply).Dur("elapsed", elapsed).
		Msg("notify user: relay accepted message")

	if s.server.DB != nil {
		if err := s.server.DB.RecordMailSend(mailKindNotification, user.Email); err != nil {
			s.log.Warn().Err(err).Str("username", req.Username).
				Msg("notify user: failed to record mail send for rate accounting")
		}
	}

	s.log.Info().Str("username", req.Username).Str("category", req.Category).
		Str("workspace", req.Workspace).Msg("notify user: notification sent")
	return &identityv1.NotifyUserResponse{}, nil
}

// mapUserLookupError passes through gRPC status errors from the user lookup
// (PermissionDenied, Unavailable, ...) and reports anything else as Internal.
func (s *IdentityService) mapUserLookupError(err error, username string) error {
	if _, ok := status.FromError(err); ok && status.Code(err) != codes.Unknown {
		return err
	}
	s.log.Error().Err(err).Str("username", username).Msg("notify user: failed to resolve user")
	return status.Errorf(codes.Internal, "failed to resolve user '%s'", username)
}
