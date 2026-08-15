// Copyright 2026 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package db

import (
	"context"
	"errors"
	"fmt"
	"path"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	queryv1 "github.com/k8shell-io/common/pkg/api/gen/go/query/v1"
	"github.com/k8shell-io/common/pkg/db"
	"github.com/k8shell-io/common/pkg/models"
	pkgquery "github.com/k8shell-io/common/pkg/query"
)

// ErrOnboardRuleExists is returned by CreateOnboardRule when a rule with the
// same (idp, username_pattern) already exists — regardless of org, see
// onboard_rules_uniq in db/migrations/000002_onboard_rules.up.sql.
var ErrOnboardRuleExists = errors.New("onboard rule already exists")

// ErrOnboardRuleNotFound is returned when no onboard rule with the given id
// exists, or (for ApproveWaitlistEntry/RejectWaitlistEntry) when the rule
// exists but is no longer in the waitlist action.
var ErrOnboardRuleNotFound = errors.New("onboard rule not found")

// OnboardDecision is the outcome of resolving a username's onboarding
// attempt against identity.onboard_rules: whether it's allowed at all, the
// org it should be placed into, and the roles/sudo it should be granted
// when allowed. RuleID identifies the row the decision came from (used to
// upsert a waitlist entry keyed off the same table, and for logging).
type OnboardDecision struct {
	Action models.OnboardAction
	Org    string
	Roles  []string
	Sudo   bool
	RuleID int32
}

// onboardRuleSelectColumns is the shared column list for reading a full
// identity.onboard_rules row, used by every function that returns a
// *models.OnboardRule so a change to the schema only needs to update one
// place.
const onboardRuleSelectColumns = `id, idp, username_pattern, org, action, status, priority, roles, sudo,
	COALESCE(fullname, ''), COALESCE(email, ''), COALESCE(note, ''),
	requested_at, decided_at, COALESCE(decided_by, ''), created_at, updated_at`

// scanOnboardRule reads a single onboardRuleSelectColumns row (from either
// QueryRow or a Rows.Next() iteration — both satisfy pgx.Row's Scan method).
func scanOnboardRule(row pgx.Row) (*models.OnboardRule, error) {
	var r models.OnboardRule
	var action, statusStr string
	if err := row.Scan(&r.ID, &r.IDP, &r.UsernamePattern, &r.Org, &action, &statusStr, &r.Priority, &r.Roles, &r.Sudo,
		&r.Fullname, &r.Email, &r.Note, &r.RequestedAt, &r.DecidedAt, &r.DecidedBy, &r.CreatedAt, &r.UpdatedAt); err != nil {
		return nil, err
	}
	r.Action = models.OnboardAction(action)
	r.Status = models.OnboardStatus(statusStr)
	return &r, nil
}

// nonNilRoles coalesces a nil roles slice to an empty (non-nil) one. pgx
// encodes a nil Go slice as SQL NULL rather than an empty array, which
// would violate identity.onboard_rules.roles' NOT NULL constraint whenever
// a caller creates/updates a rule with no roles at all.
func nonNilRoles(roles []string) []string {
	if roles == nil {
		return []string{}
	}
	return roles
}

// onboardRulePgError translates constraint-violation errors from
// identity.onboard_rules writes into sentinel errors; returns nil (meaning
// "not a recognized constraint violation") otherwise. The onboard_rules_uniq
// violation is deliberately not handled here — CreateOnboardRule builds a
// more useful message for it naming the org that actually owns the
// conflicting row (see onboardRuleExistsError), since uniqueness excludes
// org and the conflict may be with a different org than the one requested.
func onboardRulePgError(err error, org string, action models.OnboardAction) error {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return nil
	}
	switch {
	case pgErr.Code == "23503":
		return fmt.Errorf("%w: organization %q does not exist", models.ErrInvalidParameters, org)
	case pgErr.Code == "23514" && pgErr.ConstraintName == "chk_onboard_rule_action":
		return fmt.Errorf("%w: invalid action %q", models.ErrInvalidParameters, action)
	case pgErr.Code == "23514" && pgErr.ConstraintName == "chk_onboard_rule_status":
		return fmt.Errorf("%w: invalid status", models.ErrInvalidParameters)
	}
	return nil
}

// onboardRuleExistsError builds an ErrOnboardRuleExists message for a
// conflicting (idp, username_pattern), without naming the org that actually
// owns it when that differs from requestedOrg — since onboard_rules_uniq
// excludes org from the key, the conflict may belong to a different
// (tenant) org than the caller's own, and its name is deliberately not
// leaked to a caller who only knows their own org. Falls back to the same
// generic wording if the lookup itself fails for any reason (never lets a
// bookkeeping error hide the original AlreadyExists).
func (d *DB) onboardRuleExistsError(idp, usernamePattern, requestedOrg string) error {
	var existingOrg string
	err := d.Pool.QueryRow(context.Background(),
		`SELECT org FROM identity.onboard_rules WHERE idp=$1 AND username_pattern=$2`,
		idp, usernamePattern).Scan(&existingOrg)
	if err == nil && existingOrg != requestedOrg {
		return fmt.Errorf("%w: idp=%q pattern=%q already exists in another organization",
			ErrOnboardRuleExists, idp, usernamePattern)
	}
	return fmt.Errorf("%w: idp=%q pattern=%q org=%q", ErrOnboardRuleExists, idp, usernamePattern, requestedOrg)
}

// CreateOnboardRule registers a new onboard rule. Callers are responsible
// for validating rule.Roles against rule.Org first (see
// MissingRolesForOrg) — the DB layer only enforces the org FK and the
// action CHECK constraint.
func (d *DB) CreateOnboardRule(rule *models.OnboardRule) (*models.OnboardRule, error) {
	row := d.Pool.QueryRow(context.Background(),
		`INSERT INTO identity.onboard_rules (idp, username_pattern, org, action, priority, roles, sudo, note)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		 RETURNING `+onboardRuleSelectColumns,
		rule.IDP, rule.UsernamePattern, rule.Org, string(rule.Action), rule.Priority, nonNilRoles(rule.Roles), rule.Sudo, rule.Note,
	)
	created, err := scanOnboardRule(row)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == "onboard_rules_uniq" {
			return nil, d.onboardRuleExistsError(rule.IDP, rule.UsernamePattern, rule.Org)
		}
		if translated := onboardRulePgError(err, rule.Org, rule.Action); translated != nil {
			return nil, translated
		}
		return nil, fmt.Errorf("insert onboard rule: %w", err)
	}
	return created, nil
}

// UpdateOnboardRule fully replaces the mutable fields of an onboard rule.
// idp/username_pattern/org are immutable — delete and recreate the rule to
// change them. Returns ErrOnboardRuleNotFound when no rule with that id
// exists.
func (d *DB) UpdateOnboardRule(id int32, action models.OnboardAction, priority int32,
	roles []string, sudo bool, note string) (*models.OnboardRule, error) {
	row := d.Pool.QueryRow(context.Background(),
		`UPDATE identity.onboard_rules
		 SET action=$2, priority=$3, roles=$4, sudo=$5, note=$6, updated_at=now()
		 WHERE id=$1
		 RETURNING `+onboardRuleSelectColumns,
		id, string(action), priority, nonNilRoles(roles), sudo, note,
	)
	updated, err := scanOnboardRule(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("%w: id %d", ErrOnboardRuleNotFound, id)
	}
	if err != nil {
		if translated := onboardRulePgError(err, "", action); translated != nil {
			return nil, translated
		}
		return nil, fmt.Errorf("update onboard rule: %w", err)
	}
	return updated, nil
}

// GetOnboardRule retrieves a single onboard rule by id. Returns
// ErrOnboardRuleNotFound when no rule with that id exists. Used by
// UpdateOnboardRule's caller to look up the rule's (immutable) org before
// validating role assignability against it.
func (d *DB) GetOnboardRule(id int32) (*models.OnboardRule, error) {
	row := d.Pool.QueryRow(context.Background(),
		`SELECT `+onboardRuleSelectColumns+` FROM identity.onboard_rules WHERE id=$1`, id)
	rule, err := scanOnboardRule(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("%w: id %d", ErrOnboardRuleNotFound, id)
	}
	if err != nil {
		return nil, fmt.Errorf("get onboard rule: %w", err)
	}
	return rule, nil
}

// DeleteOnboardRule removes an onboard rule by id. Returns
// ErrOnboardRuleNotFound when no rule with that id exists.
func (d *DB) DeleteOnboardRule(id int32) error {
	result, err := d.Pool.Exec(context.Background(), `DELETE FROM identity.onboard_rules WHERE id=$1`, id)
	if err != nil {
		return fmt.Errorf("delete onboard rule: %w", err)
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("%w: id %d", ErrOnboardRuleNotFound, id)
	}
	return nil
}

// onboardRulesQuerySelectSQL is the shared SELECT/FROM header for
// QueryOnboardRules, aliased "r" so callers can add WHERE conditions
// unambiguously.
const onboardRulesQuerySelectSQL = `SELECT ` + onboardRuleSelectColumns + " FROM identity.onboard_rules r\n"

// QueryOnboardRules returns onboard rules matching a generic
// query.v1.Payload, built against desc/fm via common/pkg/query. Callers
// must have already run query.Validate(desc, payload). A frontend renders
// the pending approval queue by filtering action = 'waitlist', and manages
// standing rules with any other filter — there's no separate "list
// waitlist" query.
func (d *DB) QueryOnboardRules(desc *queryv1.Descriptor, fm pkgquery.FieldMap,
	payload *queryv1.Payload) ([]*models.OnboardRule, error) {
	limit, offset := db.AdjustListLimit(int(payload.GetPage().GetLimit()), int(payload.GetPage().GetOffset()))

	sqlQuery, args, err := pkgquery.BuildQuery(onboardRulesQuerySelectSQL, desc, fm, payload, nil, limit, offset)
	if err != nil {
		return nil, err
	}

	rows, err := d.Pool.Query(context.Background(), sqlQuery, args...)
	if err != nil {
		return nil, fmt.Errorf("query onboard rules: %w", err)
	}
	defer rows.Close()

	var rules []*models.OnboardRule
	for rows.Next() {
		rule, err := scanOnboardRule(rows)
		if err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}
	return rules, rows.Err()
}

// ResolveOnboardDecision resolves whether username may onboard via idp, and
// what it should get if so, by matching identity.onboard_rules. An
// exact-username row (no wildcard in username_pattern) always outranks a
// wildcard pattern row, regardless of priority; within either group the
// row with the lowest priority wins (ties broken by the lower row id, for
// determinism). When nothing matches at all — not even a catch-all
// (username_pattern='*') row for the idp — this fails closed and returns
// OnboardActionReject: a real deployment is expected to always define at
// least a catch-all rule per idp it uses, so reaching this path signals a
// missing rule, not an intentional "allow everyone" default.
func (d *DB) ResolveOnboardDecision(idp, username string) (*OnboardDecision, error) {
	rows, err := d.Pool.Query(context.Background(),
		`SELECT id, username_pattern, org, action, priority, roles, sudo
		 FROM identity.onboard_rules WHERE idp = $1 OR idp = '*'`, idp)
	if err != nil {
		return nil, fmt.Errorf("resolve onboard decision: %w", err)
	}
	defer rows.Close()

	type candidate struct {
		id       int32
		org      string
		action   string
		priority int32
		roles    []string
		sudo     bool
	}
	var exact, pattern []candidate
	for rows.Next() {
		var c candidate
		var usernamePattern string
		if err := rows.Scan(&c.id, &usernamePattern, &c.org, &c.action, &c.priority, &c.roles, &c.sudo); err != nil {
			return nil, err
		}
		if strings.Contains(usernamePattern, "*") {
			if matched, matchErr := path.Match(usernamePattern, username); matchErr == nil && matched {
				pattern = append(pattern, c)
			}
		} else if usernamePattern == username {
			exact = append(exact, c)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	best := func(cands []candidate) *candidate {
		var winner *candidate
		for i := range cands {
			c := &cands[i]
			if winner == nil || c.priority < winner.priority || (c.priority == winner.priority && c.id < winner.id) {
				winner = c
			}
		}
		return winner
	}

	winner := best(exact)
	if winner == nil {
		winner = best(pattern)
	}
	if winner == nil {
		return &OnboardDecision{Action: models.OnboardActionReject}, nil
	}

	return &OnboardDecision{
		Action: models.OnboardAction(winner.action),
		Org:    winner.org,
		Roles:  winner.roles,
		Sudo:   winner.sudo,
		RuleID: winner.id,
	}, nil
}

// UpsertWaitlistEntry records a pending onboarding attempt as a concrete
// (exact-username) row with action='waitlist', status='pending', carrying
// over the org/roles/sudo the matched rule already resolved to. This must
// be an upsert rather than a plain insert-if-new: the matched rule itself
// can already be this exact (idp, username_pattern) row — e.g. an
// admin-authored one-off "waitlist this specific user" rule, not a
// wildcard pattern — in which case "inserting" a new row always conflicts
// with itself, and previously used ON CONFLICT DO NOTHING, which silently
// left status stuck at whatever it was (typically 'none') and never
// advanced it to 'pending'. DO UPDATE fixes that while still behaving
// correctly on a genuine repeat attempt while already pending: action/
// status/roles/sudo/fullname/email are refreshed to the latest resolved
// values (harmless no-ops when unchanged), and requested_at is preserved
// via COALESCE rather than reset to now() on every retry.
func (d *DB) UpsertWaitlistEntry(idp, username, org string, roles []string, sudo bool, fullname, email string) error {
	_, err := d.Pool.Exec(context.Background(),
		`INSERT INTO identity.onboard_rules AS o (idp, username_pattern, org, action, status, roles, sudo, fullname, email, requested_at)
		 VALUES ($1, $2, $3, 'waitlist', 'pending', $4, $5, $6, $7, now())
		 ON CONFLICT (idp, username_pattern) DO UPDATE
		     SET action='waitlist', status='pending', roles=EXCLUDED.roles, sudo=EXCLUDED.sudo,
		         fullname=EXCLUDED.fullname, email=EXCLUDED.email,
		         requested_at=COALESCE(o.requested_at, EXCLUDED.requested_at), updated_at=now()`,
		idp, username, org, nonNilRoles(roles), sudo, fullname, email)
	if err != nil {
		return fmt.Errorf("upsert onboard waitlist entry: %w", err)
	}
	return nil
}

// MarkRejectedByRule records a rule-driven (non-admin) rejection as a
// concrete (exact-username) row with action='reject', status='rejected' —
// distinct from RejectWaitlistEntry, which is an admin rejecting a
// previously-waitlisted request. Called when ResolveOnboardDecision
// resolves to OnboardActionReject via an actual matched rule (org is
// always non-empty in that case; the fail-closed "nothing matched at all"
// case has no org to record against and is not persisted here). Idempotent
// via upsert: a repeat attempt against an already-rejected row just
// refreshes updated_at.
func (d *DB) MarkRejectedByRule(idp, username, org string, roles []string, sudo bool, fullname, email string) error {
	_, err := d.Pool.Exec(context.Background(),
		`INSERT INTO identity.onboard_rules (idp, username_pattern, org, action, status, roles, sudo, fullname, email)
		 VALUES ($1, $2, $3, 'reject', 'rejected', $4, $5, $6, $7)
		 ON CONFLICT (idp, username_pattern) DO UPDATE
		     SET action='reject', status='rejected', updated_at=now()`,
		idp, username, org, nonNilRoles(roles), sudo, fullname, email)
	if err != nil {
		return fmt.Errorf("mark onboard rule rejected: %w", err)
	}
	return nil
}

// MarkOnboarded records a successful onboarding as a concrete
// (exact-username) row with action='allow', status='onboarded'. Called
// only after the user has actually been created in identity.users —
// status is the outcome of a confirmed onboarding, not an optimistic
// projection. If a waitlist row already exists for this (idp, username)
// (the common approval path), it's updated in place; otherwise a new row
// is inserted, e.g. for a user who onboarded directly via a pattern rule
// with no prior waitlist entry.
func (d *DB) MarkOnboarded(idp, username, org string, roles []string, sudo bool, fullname, email string) error {
	_, err := d.Pool.Exec(context.Background(),
		`INSERT INTO identity.onboard_rules (idp, username_pattern, org, action, status, roles, sudo, fullname, email)
		 VALUES ($1, $2, $3, 'allow', 'onboarded', $4, $5, $6, $7)
		 ON CONFLICT (idp, username_pattern) DO UPDATE
		     SET action='allow', status='onboarded', roles=EXCLUDED.roles, sudo=EXCLUDED.sudo, updated_at=now()`,
		idp, username, org, nonNilRoles(roles), sudo, fullname, email)
	if err != nil {
		return fmt.Errorf("mark onboard rule onboarded: %w", err)
	}
	return nil
}

// RevokeOnboardRule reverts a concrete (exact-username) row after the user
// it tracked has been deleted from identity.users: action is set back to
// 'reject' and status to 'none', so deleting an account doesn't leave a
// standing 'allow' rule quietly letting the same identity back in on their
// next login — re-admitting them again requires an explicit decision (e.g.
// UpdateOnboardRule, or a fresh admin-authored rule). It's a no-op (not an
// error) if there is no matching row at all — deleting a user has no
// obligation to have one (e.g. one created directly via CreateUser,
// bypassing onboarding entirely).
func (d *DB) RevokeOnboardRule(idp, username, org string) error {
	_, err := d.Pool.Exec(context.Background(),
		`UPDATE identity.onboard_rules SET action='reject', status='none', updated_at=now()
		 WHERE idp=$1 AND username_pattern=$2 AND org=$3`,
		idp, username, org)
	if err != nil {
		return fmt.Errorf("revoke onboard rule: %w", err)
	}
	return nil
}

// MoveOnboardRuleOrg updates a concrete (exact-username) onboard rule's org
// to follow the user it tracks after an admin moves that user to a
// different organization — otherwise the tracking row would keep pointing
// at an org the user no longer belongs to, and a later onboarding attempt
// resolving through this row (e.g. after the account is deleted and would
// re-onboard) would place them back into the org they were moved out of.
// roles is cleared at the same time: identity.onboard_rules.roles is only
// validated against the rule's own org at the application layer (see
// MissingRolesForOrg), so nothing on the old role list can be assumed valid
// once the rule belongs to a different org — mirrors the same drop UpdateUser
// applies to the user's own role list on an org change. It's a no-op (not an
// error) if there is no matching row at all — a user onboarded without going
// through the onboard_rules flow (e.g. created directly via CreateUser) has
// no tracking row to move.
func (d *DB) MoveOnboardRuleOrg(idp, username, oldOrg, newOrg string) error {
	_, err := d.Pool.Exec(context.Background(),
		`UPDATE identity.onboard_rules SET org=$4, roles='{}', updated_at=now()
		 WHERE idp=$1 AND username_pattern=$2 AND org=$3`,
		idp, username, oldOrg, newOrg)
	if err != nil {
		return fmt.Errorf("move onboard rule org: %w", err)
	}
	return nil
}

// ApproveWaitlistEntry flips a pending onboard rule's action to 'allow' and
// status to 'approved', and records who decided it. Status moves to
// 'onboarded' separately, by MarkOnboarded, once the user actually logs in —
// approval alone does not onboard them. Returns ErrOnboardRuleNotFound when
// no rule with that id is currently in the waitlist action (already decided,
// or never requested).
func (d *DB) ApproveWaitlistEntry(id int32, decidedBy string) (*models.OnboardRule, error) {
	row := d.Pool.QueryRow(context.Background(),
		`UPDATE identity.onboard_rules
		 SET action='allow', status='approved', decided_at=now(), decided_by=$2, updated_at=now()
		 WHERE id=$1 AND action='waitlist'
		 RETURNING `+onboardRuleSelectColumns,
		id, decidedBy,
	)
	rule, err := scanOnboardRule(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("%w: id %d", ErrOnboardRuleNotFound, id)
	}
	if err != nil {
		return nil, fmt.Errorf("approve onboard waitlist entry: %w", err)
	}
	return rule, nil
}

// RejectWaitlistEntry flips a pending onboard rule's action to 'reject' so
// the same user can't immediately re-trigger a fresh waitlist entry by
// retrying onboarding. An empty note leaves the row's existing note
// unchanged. Returns ErrOnboardRuleNotFound when no rule with that id is
// currently in the waitlist action.
func (d *DB) RejectWaitlistEntry(id int32, decidedBy, note string) (*models.OnboardRule, error) {
	row := d.Pool.QueryRow(context.Background(),
		`UPDATE identity.onboard_rules
		 SET action='reject', status='rejected', decided_at=now(), decided_by=$2, note=COALESCE(NULLIF($3, ''), note), updated_at=now()
		 WHERE id=$1 AND action='waitlist'
		 RETURNING `+onboardRuleSelectColumns,
		id, decidedBy, note,
	)
	rule, err := scanOnboardRule(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("%w: id %d", ErrOnboardRuleNotFound, id)
	}
	if err != nil {
		return nil, fmt.Errorf("reject onboard waitlist entry: %w", err)
	}
	return rule, nil
}
