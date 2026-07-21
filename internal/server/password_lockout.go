// Copyright 2026 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	natsc "github.com/k8shell-io/common/pkg/nats"
	"github.com/nats-io/nats.go"
)

// passwordLockoutCASRetries bounds the compare-and-swap retry loop used by
// recordPasswordFailure, mirroring the retry idiom used by
// JetStreamKV.AcquireLock for the same underlying KV primitives.
const passwordLockoutCASRetries = 5

// checkPasswordLockout reports whether username is currently locked out of
// password authentication, and until when. It fails open (not locked) when
// the lockout KV bucket is unavailable (NATS disabled) or the stored entry
// can't be read, since bcrypt comparison remains the primary defense and a
// missing lockout bucket should not itself deny logins.
func (s *Server) checkPasswordLockout(username string) (locked bool, until time.Time, err error) {
	if s.passwordLockoutKV == nil {
		return false, time.Time{}, nil
	}

	entry, err := s.passwordLockoutKV.Get(username)
	if err != nil {
		if errors.Is(err, nats.ErrKeyNotFound) {
			return false, time.Time{}, nil
		}
		return false, time.Time{}, err
	}

	var state natsc.PasswordLockoutState
	if jsonErr := json.Unmarshal(entry.Value(), &state); jsonErr != nil {
		return false, time.Time{}, nil
	}
	if state.LockedUntil == 0 {
		return false, time.Time{}, nil
	}

	lockedUntil := time.Unix(state.LockedUntil, 0)
	if time.Now().After(lockedUntil) {
		return false, time.Time{}, nil
	}
	return true, lockedUntil, nil
}

// recordPasswordFailure increments the failed-attempt counter for username,
// locking the account once the configured MaxAttempts is reached. It
// returns whether the account is locked as a result of (or already because
// of) this call, and until when. It is a no-op returning (false, zero, nil)
// when the lockout KV bucket is unavailable.
func (s *Server) recordPasswordFailure(username string) (locked bool, until time.Time, err error) {
	if s.passwordLockoutKV == nil {
		return false, time.Time{}, nil
	}

	for i := 0; i < passwordLockoutCASRetries; i++ {
		var state natsc.PasswordLockoutState
		var revision uint64

		entry, getErr := s.passwordLockoutKV.Get(username)
		switch {
		case getErr == nil:
			revision = entry.Revision()
			if jsonErr := json.Unmarshal(entry.Value(), &state); jsonErr != nil {
				state = natsc.PasswordLockoutState{}
			}
			if state.LockedUntil != 0 {
				lockedUntil := time.Unix(state.LockedUntil, 0)
				if time.Now().Before(lockedUntil) {
					// Already locked: report it without extending the window.
					return true, lockedUntil, nil
				}
				// Previous lockout has expired; start a fresh window.
				state = natsc.PasswordLockoutState{}
			}
		case errors.Is(getErr, nats.ErrKeyNotFound):
			state = natsc.PasswordLockoutState{}
		default:
			return false, time.Time{}, getErr
		}

		state.FailedAttempts++
		lockedNow := state.FailedAttempts >= s.passwordLockoutCfg.MaxAttempts
		var lockedUntil time.Time
		if lockedNow {
			lockedUntil = time.Now().Add(s.passwordLockoutCfg.LockDuration)
			state.LockedUntil = lockedUntil.Unix()
		}

		payload, marshalErr := json.Marshal(&state)
		if marshalErr != nil {
			return false, time.Time{}, marshalErr
		}

		var casErr error
		if revision == 0 {
			_, casErr = s.passwordLockoutKV.Create(username, payload)
		} else {
			_, casErr = s.passwordLockoutKV.Update(username, payload, revision)
		}
		if casErr == nil {
			return lockedNow, lockedUntil, nil
		}
		if errors.Is(casErr, nats.ErrKeyExists) {
			continue // lost a race with a concurrent failed attempt; retry
		}
		return false, time.Time{}, casErr
	}

	return false, time.Time{}, fmt.Errorf("password lockout: exceeded CAS retries updating state for %q", username)
}

// resetPasswordLockout clears any failure counter/lockout for username. It
// is called after a successful password authentication.
func (s *Server) resetPasswordLockout(username string) error {
	if s.passwordLockoutKV == nil {
		return nil
	}
	err := s.passwordLockoutKV.Delete(username)
	if err != nil && errors.Is(err, nats.ErrKeyNotFound) {
		return nil
	}
	return err
}
