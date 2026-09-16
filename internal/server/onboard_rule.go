// Copyright 2026 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"context"
	"errors"
	"regexp"
	"strings"

	commonv1 "github.com/k8shell-io/common/pkg/api/gen/go/common/v1"
	identityv1 "github.com/k8shell-io/common/pkg/api/gen/go/identity/v1"
	queryv1 "github.com/k8shell-io/common/pkg/api/gen/go/query/v1"
	"github.com/k8shell-io/common/pkg/models"
	"github.com/k8shell-io/common/pkg/query"
	backend "github.com/k8shell-io/identity/internal/db"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// onboardRuleToProto converts a Go model to its protobuf representation.
func onboardRuleToProto(r *models.OnboardRule) *identityv1.OnboardRule {
	if r == nil {
		return nil
	}
	pb := &identityv1.OnboardRule{
		Id:              r.ID,
		Idp:             r.IDP,
		UsernamePattern: r.UsernamePattern,
		Org:             r.Org,
		Action:          string(r.Action),
		Status:          string(r.Status),
		Priority:        r.Priority,
		Roles:           r.Roles,
		Sudo:            r.Sudo,
		Fullname:        r.Fullname,
		Email:           r.Email,
		Note:            r.Note,
		DecidedBy:       r.DecidedBy,
		CreatedAt:       timestamppb.New(r.CreatedAt),
		UpdatedAt:       timestamppb.New(r.UpdatedAt),
	}
	if r.RequestedAt != nil {
		pb.RequestedAt = timestamppb.New(*r.RequestedAt)
	}
	if r.DecidedAt != nil {
		pb.DecidedAt = timestamppb.New(*r.DecidedAt)
	}
	return pb
}

// validOnboardActions are the only values identity.onboard_rules.action
// accepts (enforced again by the chk_onboard_rule_action CHECK constraint;
// validated here first so a bad value gets a clean InvalidArgument instead
// of a raw constraint-violation error).
var validOnboardActions = map[string]bool{
	string(models.OnboardActionAllow):    true,
	string(models.OnboardActionReject):   true,
	string(models.OnboardActionWaitlist): true,
}

// validateOnboardRule checks the fields shared by CreateOnboardRule and
// UpdateOnboardRule: action is one of allow/reject/waitlist, and roles are
// each assignable within org (org-scoped-or-global, same resolution
// ListRoles(org) uses) — a rule can never grant a role that isn't actually
// assignable in the org it places users into.
func (s *IdentityService) validateOnboardRule(action, org string, roles []string) error {
	if !validOnboardActions[action] {
		return status.Errorf(codes.InvalidArgument, "invalid action %q: must be one of allow, reject, waitlist", action)
	}
	if len(roles) == 0 {
		return nil
	}
	missing, err := s.server.DB.MissingRolesForOrg(roles, org)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to validate roles: %v", err)
	}
	if len(missing) > 0 {
		return status.Errorf(codes.InvalidArgument, "unknown or unassignable role(s) for org '%s': %s", org, strings.Join(missing, ", "))
	}
	return nil
}

// commaNewlineRunRE matches a ',' followed by one or more newlines (each
// optionally surrounded by horizontal whitespace) — the only newline
// placement normalizeUsernamePattern treats as legitimate, e.g. pasting one
// already comma-terminated entry per line.
var commaNewlineRunRE = regexp.MustCompile(`,[ \t]*(?:\r?\n[ \t]*)+`)

// normalizeUsernamePattern strips newlines that immediately follow a ','
// (optionally through blank lines/horizontal whitespace) from a
// username_pattern — the same treatment as any other incidental whitespace
// around a list entry (see DB.ResolveOnboardDecision, which trims each entry
// it splits on ','). It does NOT touch a newline anywhere else in the
// pattern: e.g. "tomvit\nestaho,jlklklk" has a newline between "tomvit" and
// "estaho" with no comma in between, so stripping it here would silently
// merge two distinct entries into the single bogus username
// "tomvitestaho" — left alone, validateUsernamePattern rejects it instead.
// The whole pattern is trimmed first so a single trailing newline (e.g. from
// a textarea/paste) doesn't need special-casing below.
func normalizeUsernamePattern(pattern string) string {
	pattern = strings.TrimSpace(pattern)
	if !strings.Contains(pattern, ",") {
		return pattern
	}
	return commaNewlineRunRE.ReplaceAllString(pattern, ",")
}

// duplicateUsernameKey lowercases and trims a username_pattern entry for
// duplicate detection, so e.g. "Alice" and "alice" are treated as the same
// entry regardless of case.
func duplicateUsernameKey(u string) string {
	return strings.ToLower(strings.TrimSpace(u))
}

// validUsernameRE matches a single valid username within username_pattern:
// letters, digits, '.', '_', and '-' — the character set common identity
// providers (GitHub, GitLab, Linux-style logins) actually issue usernames
// in. Applied to every entry, whether username_pattern is a comma-delimited
// list or a single exact username; the '*' wildcard is checked separately
// and never reaches this.
var validUsernameRE = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// validateUsernamePattern checks username_pattern's comma-delimited-list
// form: no empty entries (a stray leading/trailing/double comma), and not
// combined with a '*' wildcard — a rule is either a wildcard, a single exact
// username, or a plain comma-delimited list of usernames, never a mix (see
// DB.ResolveOnboardDecision, which matches a list entry-by-entry rather than
// as a glob). A raw newline is always rejected here: by the time this runs,
// normalizeUsernamePattern has already stripped every newline that
// legitimately followed a ',' (a comma-terminated entry on its own line), so
// anything left is a newline DB.ResolveOnboardDecision has no delimiter
// semantics for — e.g. "tomvit\nestaho,jlklklk", where the newline sits
// between two entries with no comma between them. Saving that as-is would
// silently merge "tomvit" and "estaho" into a single, never-matching
// username instead of surfacing the missing comma as a mistake. Every
// non-wildcard entry is also checked against validUsernameRE, so garbage
// like "fdsf%sdf" is rejected instead of being saved as a rule that can
// never match a real username. Within a comma-delimited list, the same
// username appearing twice (case-insensitively, e.g. "alice,Alice") is
// rejected outright rather than silently collapsed — a caller who wrote a
// name twice almost certainly meant to write two different names, and
// silently deduplicating would hide that mistake.
func validateUsernamePattern(pattern string) error {
	if strings.ContainsAny(pattern, "\r\n") {
		return status.Error(codes.InvalidArgument,
			"username_pattern cannot contain a newline except immediately after a ',' separator")
	}
	if !strings.Contains(pattern, ",") {
		if pattern == "*" {
			return nil
		}
		if !validUsernameRE.MatchString(pattern) {
			return status.Errorf(codes.InvalidArgument,
				"username_pattern %q is not a valid username: only letters, digits, '.', '_', and '-' are allowed", pattern)
		}
		return nil
	}
	if strings.Contains(pattern, "*") {
		return status.Error(codes.InvalidArgument,
			"username_pattern cannot combine a comma-delimited list of usernames with a '*' wildcard")
	}
	seen := make(map[string]bool)
	for _, raw := range strings.Split(pattern, ",") {
		u := strings.TrimSpace(raw)
		if u == "" {
			return status.Error(codes.InvalidArgument,
				"username_pattern's comma-delimited list contains an empty username")
		}
		if !validUsernameRE.MatchString(u) {
			return status.Errorf(codes.InvalidArgument,
				"username_pattern's comma-delimited list contains an invalid username %q: only letters, digits, '.', '_', and '-' are allowed", u)
		}
		key := duplicateUsernameKey(u)
		if seen[key] {
			return status.Errorf(codes.InvalidArgument,
				"username_pattern's comma-delimited list contains %q more than once", u)
		}
		seen[key] = true
	}
	return nil
}

// CreateOnboardRule registers a new onboard rule: a standing wildcard policy
// (username_pattern='*'), a standing list policy (a comma-delimited list of
// usernames), or a one-off decision for a specific username.
func (s *IdentityService) CreateOnboardRule(ctx context.Context,
	req *identityv1.CreateOnboardRuleRequest) (*identityv1.OnboardRule, error) {
	if req.GetIdp() == "" {
		return nil, status.Error(codes.InvalidArgument, "idp is required")
	}
	if req.GetUsernamePattern() == "" {
		return nil, status.Error(codes.InvalidArgument, "username_pattern is required")
	}
	usernamePattern := normalizeUsernamePattern(req.GetUsernamePattern())
	if err := validateUsernamePattern(usernamePattern); err != nil {
		return nil, err
	}
	if req.GetOrg() == "" {
		return nil, status.Error(codes.InvalidArgument, "org is required")
	}
	if s.server.DB == nil {
		return nil, status.Error(codes.Unavailable, "database is not configured")
	}
	if err := s.validateOnboardRule(req.GetAction(), req.GetOrg(), req.GetRoles()); err != nil {
		return nil, err
	}

	rule, err := s.server.DB.CreateOnboardRule(&models.OnboardRule{
		IDP:             req.GetIdp(),
		UsernamePattern: usernamePattern,
		Org:             req.GetOrg(),
		Action:          models.OnboardAction(req.GetAction()),
		Priority:        req.GetPriority(),
		Roles:           req.GetRoles(),
		Sudo:            req.GetSudo(),
		Note:            req.GetNote(),
	})
	if err != nil {
		switch {
		case errors.Is(err, backend.ErrOnboardRuleExists):
			return nil, status.Errorf(codes.AlreadyExists, "%v", err)
		case errors.Is(err, models.ErrInvalidParameters):
			return nil, status.Errorf(codes.InvalidArgument, "%v", err)
		}
		return nil, status.Errorf(codes.Internal, "failed to create onboard rule: %v", err)
	}

	return onboardRuleToProto(rule), nil
}

// UpdateOnboardRule fully replaces the mutable fields of an onboard rule,
// including username_pattern. idp/org are immutable — delete and recreate
// the rule to change them.
func (s *IdentityService) UpdateOnboardRule(ctx context.Context,
	req *identityv1.UpdateOnboardRuleRequest) (*identityv1.OnboardRule, error) {
	if req.GetId() == 0 {
		return nil, status.Error(codes.InvalidArgument, "id is required")
	}
	if req.GetUsernamePattern() == "" {
		return nil, status.Error(codes.InvalidArgument, "username_pattern is required")
	}
	usernamePattern := normalizeUsernamePattern(req.GetUsernamePattern())
	if err := validateUsernamePattern(usernamePattern); err != nil {
		return nil, err
	}
	if s.server.DB == nil {
		return nil, status.Error(codes.Unavailable, "database is not configured")
	}

	// org isn't known from the request itself (it's immutable, not carried
	// on UpdateOnboardRuleRequest), so role validation needs the existing
	// row's org first.
	existing, err := s.server.DB.GetOnboardRule(req.GetId())
	if err != nil {
		if errors.Is(err, backend.ErrOnboardRuleNotFound) {
			return nil, status.Errorf(codes.NotFound, "onboard rule '%d' not found", req.GetId())
		}
		return nil, status.Errorf(codes.Internal, "failed to look up onboard rule '%d': %v", req.GetId(), err)
	}

	if err := s.validateOnboardRule(req.GetAction(), existing.Org, req.GetRoles()); err != nil {
		return nil, err
	}

	rule, err := s.server.DB.UpdateOnboardRule(req.GetId(), usernamePattern, models.OnboardAction(req.GetAction()),
		req.GetPriority(), req.GetRoles(), req.GetSudo(), req.GetNote(), req.GetFullname(), req.GetEmail())
	if err != nil {
		switch {
		case errors.Is(err, backend.ErrOnboardRuleNotFound):
			return nil, status.Errorf(codes.NotFound, "onboard rule '%d' not found", req.GetId())
		case errors.Is(err, backend.ErrOnboardRuleExists):
			return nil, status.Errorf(codes.AlreadyExists, "%v", err)
		case errors.Is(err, models.ErrInvalidParameters):
			return nil, status.Errorf(codes.InvalidArgument, "%v", err)
		}
		return nil, status.Errorf(codes.Internal, "failed to update onboard rule '%d': %v", req.GetId(), err)
	}

	return onboardRuleToProto(rule), nil
}

// DeleteOnboardRule removes an onboard rule from the registry.
func (s *IdentityService) DeleteOnboardRule(ctx context.Context,
	req *identityv1.DeleteOnboardRuleRequest) (*identityv1.DeleteOnboardRuleResponse, error) {
	if req.GetId() == 0 {
		return nil, status.Error(codes.InvalidArgument, "id is required")
	}
	if s.server.DB == nil {
		return nil, status.Error(codes.Unavailable, "database is not configured")
	}

	if err := s.server.DB.DeleteOnboardRule(req.GetId()); err != nil {
		if errors.Is(err, backend.ErrOnboardRuleNotFound) {
			return nil, status.Errorf(codes.NotFound, "onboard rule '%d' not found", req.GetId())
		}
		return nil, status.Errorf(codes.Internal, "failed to delete onboard rule '%d': %v", req.GetId(), err)
	}

	return &identityv1.DeleteOnboardRuleResponse{Success: true}, nil
}

// GetOnboardRulesQuerySchema returns the descriptor advertising which
// onboard rule fields are queryable/sortable via QueryOnboardRules, and
// which operators are valid on each.
func (s *IdentityService) GetOnboardRulesQuerySchema(ctx context.Context,
	req *identityv1.GetOnboardRulesQuerySchemaRequest) (*queryv1.Descriptor, error) {
	return onboardRulesQueryDescriptor, nil
}

// QueryOnboardRules retrieves onboard rules matching a generic
// query.v1.Payload, as advertised by GetOnboardRulesQuerySchema. A frontend
// renders the pending approval queue by filtering action = "waitlist", and
// manages standing rules with any other filter — there is no separate
// "list waitlist" RPC.
func (s *IdentityService) QueryOnboardRules(ctx context.Context,
	req *identityv1.QueryOnboardRulesRequest) (*identityv1.OnboardRuleList, error) {
	if err := query.Validate(onboardRulesQueryDescriptor, req.Query); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid query: %v", err)
	}
	if s.server.DB == nil {
		return nil, status.Error(codes.Unavailable, "onboard rule query requires a database backend")
	}

	rules, err := s.server.DB.QueryOnboardRules(onboardRulesQueryDescriptor, onboardRulesQueryFieldMap, req.Query)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to query onboard rules: %v", err)
	}

	pbRules := make([]*identityv1.OnboardRule, len(rules))
	for i, r := range rules {
		pbRules[i] = onboardRuleToProto(r)
	}

	return &identityv1.OnboardRuleList{Rules: pbRules}, nil
}

// ApproveOnboardRequest approves a pending ("waitlist") onboard rule, flipping
// its action to "allow". It deliberately does not onboard the user itself —
// that happens lazily on their next login/web-flow attempt via the normal
// refreshUser/ResolveOnboardDecision path, same as any other allow rule.
// Onboarding eagerly here, at approval time, would pre-empt that: e.g.
// CompleteUserWebFlow's freshly-onboarded signal (used to deliver a
// provider's follow-up action exactly once) is derived from the user record
// being created during that call, which never happens if approval already
// created it out of band.
func (s *IdentityService) ApproveOnboardRequest(ctx context.Context,
	req *identityv1.ApproveOnboardRuleRequest) (*commonv1.User, error) {
	if req.GetId() == 0 {
		return nil, status.Error(codes.InvalidArgument, "id is required")
	}
	if s.server.DB == nil {
		return nil, status.Error(codes.Unavailable, "database is not configured")
	}

	if _, err := s.server.DB.ApproveWaitlistEntry(req.GetId(), req.GetDecidedBy()); err != nil {
		if errors.Is(err, backend.ErrOnboardRuleNotFound) {
			return nil, status.Errorf(codes.NotFound, "no pending onboard request '%d' found", req.GetId())
		}
		return nil, status.Errorf(codes.Internal, "failed to approve onboard request '%d': %v", req.GetId(), err)
	}

	return &commonv1.User{}, nil
}

// RejectOnboardRequest rejects a pending ("waitlist") onboard rule,
// flipping its action to "reject" so the same user can't immediately
// re-trigger a fresh waitlist entry by retrying onboarding.
func (s *IdentityService) RejectOnboardRequest(ctx context.Context,
	req *identityv1.RejectOnboardRuleRequest) (*identityv1.OnboardRule, error) {
	if req.GetId() == 0 {
		return nil, status.Error(codes.InvalidArgument, "id is required")
	}
	if s.server.DB == nil {
		return nil, status.Error(codes.Unavailable, "database is not configured")
	}

	rule, err := s.server.DB.RejectWaitlistEntry(req.GetId(), req.GetDecidedBy(), req.GetNote())
	if err != nil {
		if errors.Is(err, backend.ErrOnboardRuleNotFound) {
			return nil, status.Errorf(codes.NotFound, "no pending onboard request '%d' found", req.GetId())
		}
		return nil, status.Errorf(codes.Internal, "failed to reject onboard request '%d': %v", req.GetId(), err)
	}

	return onboardRuleToProto(rule), nil
}
