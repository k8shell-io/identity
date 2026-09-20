// Copyright 2026 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/nats-io/nats.go"
)

// checkAndSetPasswordResetCooldown reports whether username is currently
// within the post-request cooldown window (see PasswordResetConfig.
// CooldownDuration). When it is not, this call atomically starts a new
// cooldown window via a CAS create, so a racing concurrent call sees the
// cooldown as already active rather than both proceeding. It fails open
// (not in cooldown) when the cooldown KV bucket is unavailable (NATS
// disabled).
func (s *Server) checkAndSetPasswordResetCooldown(username string) (inCooldown bool, err error) {
	if s.passwordResetCooldownKV == nil {
		return false, nil
	}
	if _, err := s.passwordResetCooldownKV.Create(username, []byte{}); err != nil {
		if errors.Is(err, nats.ErrKeyExists) {
			return true, nil
		}
		return false, err
	}
	return false, nil
}

// hashResetToken returns hex(sha256(raw)), the KV key a raw reset token is
// stored/looked up under, so the raw bearer token itself is never persisted
// anywhere.
func hashResetToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// issuePasswordResetToken generates a new single-use reset token for
// username, stores hash(token) -> username in the reset-token KV, and
// returns the raw token to embed in the confirmation email. Returns an
// error when the token KV is unavailable (NATS disabled) — the caller
// treats that as a send failure to log-and-swallow.
func (s *Server) issuePasswordResetToken(username string) (raw string, err error) {
	if s.passwordResetTokenKV == nil {
		return "", fmt.Errorf("password reset token store is not configured (NATS disabled)")
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate reset token: %w", err)
	}
	raw = base64.RawURLEncoding.EncodeToString(b)
	if _, err := s.passwordResetTokenKV.Set(hashResetToken(raw), []byte(username)); err != nil {
		return "", fmt.Errorf("store reset token: %w", err)
	}
	return raw, nil
}

// lookupPasswordResetToken resolves a raw token to the username it was
// issued for. Returns a wrapped nats.ErrKeyNotFound for an unknown or
// expired token — ConfirmPasswordReset maps that to codes.InvalidArgument.
func (s *Server) lookupPasswordResetToken(raw string) (username string, err error) {
	if s.passwordResetTokenKV == nil {
		return "", fmt.Errorf("password reset token store is not configured (NATS disabled)")
	}
	entry, err := s.passwordResetTokenKV.Get(hashResetToken(raw))
	if err != nil {
		return "", err
	}
	return string(entry.Value()), nil
}

// consumePasswordResetToken deletes a redeemed token. It must only be
// called after the password update it authorizes has already succeeded (see
// ConfirmPasswordReset) — never before, so a transient failure elsewhere
// never wastes a still-valid token. It is best-effort: a delete failure here
// just leaves a harmless single-use mapping that the bucket TTL will clean
// up, since the token has already served its purpose.
func (s *Server) consumePasswordResetToken(raw string) error {
	if s.passwordResetTokenKV == nil {
		return nil
	}
	err := s.passwordResetTokenKV.Delete(hashResetToken(raw))
	if err != nil && errors.Is(err, nats.ErrKeyNotFound) {
		return nil
	}
	return err
}

// buildPasswordResetConfirmURL appends token to base as a "token" query
// parameter, using "&" instead of "?" when base already carries a query
// string.
func buildPasswordResetConfirmURL(base, token string) string {
	sep := "?"
	if strings.Contains(base, "?") {
		sep = "&"
	}
	return fmt.Sprintf("%s%stoken=%s", base, sep, url.QueryEscape(token))
}
