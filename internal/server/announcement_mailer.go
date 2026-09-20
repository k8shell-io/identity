// Copyright 2026 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"context"
	"encoding/json"
	"math"
	"time"

	"github.com/k8shell-io/common/pkg/models"
	backend "github.com/k8shell-io/identity/internal/db"
	"github.com/k8shell-io/identity/internal/mail"
)

// announcementEmailFallbackSubject is used when AnnouncementEmailConfig.
// Subjects has no entry for a resolved language, and no "en" entry to fall
// back to either. Announcement.Name is an admin-only label, never shown to
// end users, so it must never be used as the email subject.
const announcementEmailFallbackSubject = "New k8shell announcement"

// announcementEmailSubject returns the configured subject line for lang
// (AnnouncementEmailConfig.Subjects), falling back to the configured "en"
// subject, then to announcementEmailFallbackSubject, when lang has no entry
// of its own.
func (s *Server) announcementEmailSubject(lang string) string {
	if subject, ok := s.announcementEmailCfg.Subjects[lang]; ok {
		return subject
	}
	if subject, ok := s.announcementEmailCfg.Subjects["en"]; ok {
		return subject
	}
	return announcementEmailFallbackSubject
}

// announcementUserSettings is the one deliberate, scoped exception to
// identity.user_settings.data being treated as fully opaque everywhere
// else: the announcement mailer needs these two keys to decide whether, and
// in what language, to email a user. Every other field in the blob is
// ignored, and both fields default harmlessly (skip the user) on a missing
// key or an unparseable blob.
type announcementUserSettings struct {
	Language             *string `json:"language"`
	AnnouncementsByEmail bool    `json:"announcementsByEmail"`
}

// startAnnouncementEmailSender starts a background goroutine that
// periodically emails active, email-eligible announcements to opted-in
// users. It is a no-op when the database is not configured.
func (s *Server) startAnnouncementEmailSender(ctx context.Context) {
	if s.DB == nil {
		return
	}
	go s.runAnnouncementEmailSender(ctx)
}

func (s *Server) runAnnouncementEmailSender(ctx context.Context) {
	s.sendEligibleAnnouncementEmails()

	ticker := time.NewTicker(s.announcementEmailCfg.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.sendEligibleAnnouncementEmails()
		}
	}
}

// remainingMailBudget returns how many more recipients may be emailed in
// the current trailing-24h window (identity.mail_sends), across every mail
// kind — see MailRateLimitConfig.DailyRecipientCap. Returns a very large
// number when the cap is disabled. On a DB error it fails closed (returns 0
// budget) so a transient failure never bypasses the cap.
func (s *Server) remainingMailBudget() (int, error) {
	if s.mailRateLimitCfg.DailyRecipientCap <= 0 || s.DB == nil {
		return math.MaxInt32, nil
	}
	count, err := s.DB.CountMailSendsSince(time.Now().Add(-24 * time.Hour))
	if err != nil {
		return 0, err
	}
	remaining := s.mailRateLimitCfg.DailyRecipientCap - count
	if remaining < 0 {
		remaining = 0
	}
	return remaining, nil
}

// dateOnly formats t (already converted to the relevant location) as a
// comparable calendar date, ignoring time-of-day.
func dateOnly(t time.Time) string {
	return t.Format("2006-01-02")
}

// sendEligibleAnnouncementEmails is one tick of the announcement mailer: it
// lists every currently email-eligible announcement, applies the
// activation-day/send-hour gate, and hands each one that's due a share of
// the remaining daily recipient budget. Announcements are processed in
// ListEmailEligibleAnnouncements' activation order, so when the budget runs
// out mid-tick, earlier-activated announcements are always served first —
// later ones simply pick up their remaining candidates on a later tick once
// the rolling window has room again.
func (s *Server) sendEligibleAnnouncementEmails() {
	if !s.smtpCfg.Enabled {
		s.log.Debug().Msg("announcement mailer: tick skipped, smtp is not configured")
		return
	}

	announcements, err := s.DB.ListEmailEligibleAnnouncements()
	if err != nil {
		s.log.Warn().Err(err).Msg("announcement mailer: failed to list eligible announcements")
		return
	}
	if len(announcements) == 0 {
		s.log.Debug().Msg("announcement mailer: tick found no email-eligible announcements")
		return
	}

	budget, err := s.remainingMailBudget()
	if err != nil {
		s.log.Warn().Err(err).Msg("announcement mailer: failed to check daily recipient budget; skipping this tick")
		return
	}
	s.log.Info().Int("eligible_announcements", len(announcements)).Int("recipient_budget", budget).
		Msg("announcement mailer: tick triggered")
	if budget <= 0 {
		s.log.Debug().Msg("announcement mailer: tick skipped, daily recipient budget exhausted")
		return
	}

	today := dateOnly(time.Now().In(s.announcementEmailLoc))

	for _, a := range announcements {
		if budget <= 0 {
			s.log.Debug().Msg("announcement mailer: recipient budget exhausted mid-tick; remaining announcements deferred")
			break
		}

		activation := a.CreatedAt
		if a.StartsAt != nil {
			activation = *a.StartsAt
		}
		activationDay := dateOnly(activation.In(s.announcementEmailLoc))

		if today < activationDay {
			s.log.Debug().Int32("announcement_id", a.ID).Str("activation_day", activationDay).
				Msg("announcement mailer: not yet activated; skipping")
			continue
		}
		if today == activationDay && time.Now().In(s.announcementEmailLoc).Hour() < s.announcementEmailSendHour {
			s.log.Debug().Int32("announcement_id", a.ID).Int("send_hour", s.announcementEmailSendHour).
				Msg("announcement mailer: activation day but before send hour; skipping")
			continue
		}

		s.log.Info().Int32("announcement_id", a.ID).Str("name", a.Name).
			Msg("announcement mailer: announcement due, evaluating candidates")
		budget -= s.sendAnnouncementEmails(a, budget)
	}
}

// sendAnnouncementEmails sends a to up to budget of its still-eligible
// candidates (see ListAnnouncementEmailCandidates) and returns how many
// were actually sent.
func (s *Server) sendAnnouncementEmails(a *models.Announcement, budget int) int {
	candidates, err := s.DB.ListAnnouncementEmailCandidates(a.ID, a.Orgs, a.Roles)
	if err != nil {
		s.log.Warn().Err(err).Int32("announcement_id", a.ID).
			Msg("announcement mailer: failed to list candidates")
		return 0
	}
	s.log.Debug().Int32("announcement_id", a.ID).Int("candidates", len(candidates)).
		Msg("announcement mailer: candidates matching targeting rules")

	sent := 0
	for _, c := range candidates {
		if sent >= budget {
			break
		}
		if s.sendAnnouncementEmailToCandidate(a, c) {
			sent++
		}
	}
	return sent
}

// sendAnnouncementEmailToCandidate sends a's email to c if, and only if, c
// has opted in (announcementsByEmail) and a translation matches c's
// resolved language. Returns whether an email was actually sent.
//
// Language resolution: c's user_settings "language" key when present and
// non-empty, else "en". If no translation matches the resolved language —
// including the "en" default itself — the user is skipped with a logged
// warning; there is no further fallback to some other translation.
func (s *Server) sendAnnouncementEmailToCandidate(a *models.Announcement, c *backend.AnnouncementEmailCandidate) bool {
	settings, err := s.DB.GetUserSettings(c.Username)
	if err != nil {
		s.log.Warn().Err(err).Str("username", c.Username).
			Msg("announcement mailer: evaluated candidate: failed to load user settings")
		return false
	}

	var parsed announcementUserSettings
	if len(settings.Data) > 0 {
		if err := json.Unmarshal(settings.Data, &parsed); err != nil {
			s.log.Warn().Err(err).Str("username", c.Username).
				Msg("announcement mailer: evaluated candidate: failed to parse user settings; skipping")
			return false
		}
	}
	if !parsed.AnnouncementsByEmail {
		s.log.Debug().Int32("announcement_id", a.ID).Str("username", c.Username).
			Msg("announcement mailer: evaluated candidate: not opted in (announcementsByEmail=false); skipping")
		return false
	}

	lang := "en"
	if parsed.Language != nil && *parsed.Language != "" {
		lang = *parsed.Language
	}

	var body string
	found := false
	for _, t := range a.Translations {
		if t.Lang == lang {
			body = t.Body
			found = true
			break
		}
	}
	if !found {
		s.log.Warn().Int32("announcement_id", a.ID).Str("username", c.Username).Str("language", lang).
			Msg("announcement mailer: evaluated candidate: no translation for user's language; skipping")
		return false
	}

	claimed, err := s.DB.ClaimAnnouncementEmailSend(a.ID, c.Username)
	if err != nil {
		s.log.Warn().Err(err).Int32("announcement_id", a.ID).Str("username", c.Username).
			Msg("announcement mailer: evaluated candidate: failed to claim send")
		return false
	}
	if !claimed {
		s.log.Debug().Int32("announcement_id", a.ID).Str("username", c.Username).
			Msg("announcement mailer: evaluated candidate: already sent/claimed; skipping")
		return false
	}

	mailCfg := mail.Config{
		Host:     s.smtpCfg.Host,
		Port:     s.smtpCfg.Port,
		Username: s.smtpCfg.Username,
		Password: s.smtpCfg.Password,
		From:     s.smtpCfg.From,
	}
	if err := mail.SendAnnouncementEmail(mailCfg, c.Email, s.announcementEmailSubject(lang), body); err != nil {
		s.log.Error().Err(err).Int32("announcement_id", a.ID).Str("username", c.Username).
			Msg("announcement mailer: evaluated candidate: failed to send email")
		if unclaimErr := s.DB.UnclaimAnnouncementEmailSend(a.ID, c.Username); unclaimErr != nil {
			s.log.Warn().Err(unclaimErr).Int32("announcement_id", a.ID).Str("username", c.Username).
				Msg("announcement mailer: failed to unclaim send after send failure")
		}
		return false
	}

	if err := s.DB.RecordMailSend("announcement", c.Email); err != nil {
		s.log.Warn().Err(err).Str("username", c.Username).
			Msg("announcement mailer: failed to record mail send for rate accounting")
	}

	s.log.Info().Int32("announcement_id", a.ID).Str("username", c.Username).Str("language", lang).
		Msg("announcement mailer: evaluated candidate: sent")
	return true
}
