// Copyright 2025 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/k8shell-io/common/pkg/authz"
	"github.com/k8shell-io/common/pkg/config"
	"github.com/k8shell-io/common/pkg/db"
	"github.com/k8shell-io/common/pkg/gapi"
	natsc "github.com/k8shell-io/common/pkg/nats"
	"github.com/k8shell-io/common/pkg/validator"
	"github.com/k8shell-io/identity/internal/providers/file"
)

// KubernetesSATokenConfig controls on-demand service-account token issuance
// via the Kubernetes TokenRequest API.
type KubernetesSATokenConfig struct {
	// Enabled controls whether SA token issuance is enabled. Defaults to true.
	Enabled *bool `yaml:"enabled"`

	// TTL is the requested token lifetime. Must be >= 10 minutes (Kubernetes
	// enforced minimum). Defaults to 1 hour when unset or zero.
	TTL time.Duration `yaml:"ttl" validate:"omitempty,gt=0"`

	// Audiences lists the audiences embedded in issued tokens.
	// Defaults to ["https://kubernetes.default.svc.cluster.local"] when empty.
	Audiences []string `yaml:"audiences" validate:"omitempty,dive,uri"`
}

// KubernetesConfig contains configuration for Kubernetes secret management
// and distributed leader election.
type KubernetesConfig struct {
	// SAToken configures on-demand service-account token issuance.
	SAToken KubernetesSATokenConfig `yaml:"saToken"`
}

// Config contains server configuration loaded from YAML.
type Config struct {
	// GrpcConfig configures the gRPC server.
	GrpcConfig gapi.ServerConfig `yaml:"grpc" validate:"required"`

	// Nats configures the NATS client.
	Nats natsc.NATSClientConfig `yaml:"nats"`

	// DB configures the database connection.
	DB db.DBConfig `yaml:"db"`

	// LocalProviders configures local file-based identity providers.
	LocalProviders file.FileUserProviderConfig `yaml:"localProviders"`

	// RemoteProviders configures remote identity provider clients.
	RemoteProviders []gapi.ClientConfig `yaml:"remoteProviders" validate:"omitempty,dive"`

	// JWTIssuer configures JWT token issuance.
	JWTIssuer authz.JWTIssuerConfig `yaml:"jwtIssuer" validate:"required"`

	// Kubernetes configures Kubernetes secret management and distributed
	// leader election for the token refresh loop.
	Kubernetes KubernetesConfig `yaml:"kubernetes" validate:"required"`

	// Authz configures the authorization gRPC client used for policy evaluation.
	Authz gapi.ClientConfig `yaml:"authz"`

	// PasswordLockout configures brute-force protection for AuthUserPassword.
	PasswordLockout PasswordLockoutConfig `yaml:"passwordLockout"`

	// SMTP configures the outbound mail relay used to send password-reset email.
	SMTP SMTPConfig `yaml:"smtp"`

	// PasswordReset tunes the password-reset token/cooldown lifecycle.
	PasswordReset PasswordResetConfig `yaml:"passwordReset"`

	// AnnouncementEmail tunes the periodic sender that emails active,
	// email-eligible announcements to opted-in users.
	AnnouncementEmail AnnouncementEmailConfig `yaml:"announcementEmail"`

	// MailRateLimit caps total outbound email volume (summed across every
	// mail kind identity sends) in a trailing 24h window.
	MailRateLimit MailRateLimitConfig `yaml:"mailRateLimit"`

	// OnboardRules declares default identity.onboard_rules rows to insert
	// once at startup — see Server.seedOnboardRules. Without at least a
	// catch-all rule per (idp, org) a fresh deployment's onboard_rules table
	// is empty and ResolveOnboardDecision fails closed, rejecting everyone.
	OnboardRules []OnboardRuleConfig `yaml:"onboardRules" validate:"omitempty,dive"`

	// configDir is the directory containing the loaded configuration file.
	configDir string
}

// OnboardRuleConfig declares a default identity.onboard_rules row, inserted
// once at startup by Server.seedOnboardRules if no row already exists for
// the same (IDP, UsernamePattern, Org) — from a prior seed, an
// admin-authored rule, or a system-inserted waitlist/rejection row. Config
// changes here therefore never clobber a rule an admin has since edited via
// the API, and it's safe for multiple service instances to seed the same
// config concurrently at startup.
type OnboardRuleConfig struct {
	// IDP is the identity provider name this rule applies to, "local", or
	// "*" for any provider.
	IDP string `yaml:"idp" validate:"required"`

	// UsernamePattern is '*' (any username), a comma-delimited list of
	// usernames, or a single exact username.
	UsernamePattern string `yaml:"usernamePattern" validate:"required"`

	// Org is the organization matching users are placed into.
	Org string `yaml:"org" validate:"required"`

	// Action is the onboarding decision this rule resolves to.
	Action string `yaml:"action" validate:"required,oneof=allow reject waitlist"`

	// Priority ranks this rule among other matching rules of the same
	// specificity (exact-username vs. pattern) — lower wins. Defaults to 0.
	Priority int32 `yaml:"priority"`

	// Roles are granted to the user when Action is "allow". Must be valid
	// within Org (org-scoped-or-global).
	Roles []string `yaml:"roles"`

	// Sudo grants sudo access when Action is "allow".
	Sudo bool `yaml:"sudo"`

	// Note is an optional admin comment recorded on the rule.
	Note string `yaml:"note"`
}

// PasswordLockoutConfig configures brute-force protection for
// AuthUserPassword. Tracking is keyed by username in identity's own NATS KV
// storage, so it applies consistently regardless of which caller (SSH,
// web login, or any other gRPC client) invokes AuthUserPassword. It has no
// effect when NATS is disabled.
type PasswordLockoutConfig struct {
	// MaxAttempts is the number of consecutive failed password attempts
	// before an account is locked. Defaults to 5 when zero.
	MaxAttempts int `yaml:"maxAttempts" validate:"omitempty,gt=0"`

	// LockDuration is how long an account stays locked once MaxAttempts is
	// reached. Defaults to 15 minutes when zero.
	LockDuration time.Duration `yaml:"lockDuration" validate:"omitempty,gt=0"`
}

// SMTPConfig configures the outbound mail relay identity uses to send
// password-reset email. When Enabled is false (the default), or the relay is
// unreachable, RequestPasswordReset logs and swallows the send failure
// rather than returning an error to the caller.
type SMTPConfig struct {
	// Enabled turns on SMTP sending. Defaults to false.
	Enabled bool `yaml:"enabled"`

	// Host and Port address the SMTP relay. Required when Enabled.
	Host string `yaml:"host" validate:"required_if=Enabled true"`
	Port int    `yaml:"port" validate:"required_if=Enabled true"`

	// Username and Password authenticate to the relay via PLAIN auth. Leave
	// both empty for an unauthenticated relay.
	Username string `yaml:"username"`
	Password string `yaml:"password"`

	// From is the envelope/header From address on outgoing mail. Required
	// when Enabled.
	From string `yaml:"from" validate:"required_if=Enabled true"`
}

// PasswordResetConfig tunes the password-reset token lifecycle. Tracking is
// stored in identity's own NATS KV storage and has no effect when NATS is
// disabled.
type PasswordResetConfig struct {
	// TokenTTL bounds how long an issued reset link stays valid. Defaults to
	// 1 hour when zero. Only takes effect the first time the underlying KV
	// bucket is created — see Server.NewServer.
	TokenTTL time.Duration `yaml:"tokenTTL" validate:"omitempty,gt=0"`

	// CooldownDuration is how long a username must wait between
	// RequestPasswordReset calls before a new one actually sends email.
	// Defaults to 60 seconds when zero. Same first-creation-only caveat as
	// TokenTTL.
	CooldownDuration time.Duration `yaml:"cooldownDuration" validate:"omitempty,gt=0"`
}

// AnnouncementEmailConfig tunes the periodic sender that emails active,
// email-eligible announcements to opted-in users (see
// Server.startAnnouncementEmailSender). It reuses SMTPConfig — there is no
// separate relay configuration for announcement email.
type AnnouncementEmailConfig struct {
	// Interval is how often the sender checks for eligible announcements
	// and candidates. Defaults to 1 minute when zero.
	Interval time.Duration `yaml:"interval" validate:"omitempty,gt=0"`

	// SendHour is the hour of day (0-23, evaluated in Timezone) at or after
	// which sends are allowed to start on an announcement's activation day
	// (its StartsAt, or CreatedAt when StartsAt is unset). A *int (rather
	// than int) because 0 (midnight) is itself a valid explicit value,
	// indistinguishable from "unset" if this were a plain int with a
	// zero-defaults-to-9 rule — same reasoning as
	// KubernetesSATokenConfig.Enabled. Defaults to 9 when nil.
	SendHour *int `yaml:"sendHour" validate:"omitempty,gte=0,lte=23"`

	// Timezone is the IANA timezone name SendHour and each announcement's
	// activation day are evaluated in. Defaults to "UTC" when empty. An
	// invalid value fails server startup rather than silently falling back,
	// since a wrong timezone would misfire every send.
	Timezone string `yaml:"timezone"`

	// Subjects maps a language — the same value resolved from a candidate's
	// user_settings "language" key used to pick their translation (see
	// announcementUserSettings) — to the email subject line used for that
	// language. A language with no entry falls back to Subjects["en"], then
	// to a fixed generic subject if that's missing too. Defaults to
	// {"en": "New k8Shell announcement", "cs": "Nové oznámení k8Shell"} when
	// unset. Not limited to en/cs — add any language key the deployment
	// needs translations for.
	Subjects map[string]string `yaml:"subjects"`
}

// MailRateLimitConfig caps total outbound email volume (summed across every
// mail kind identity sends — see identity.mail_sends) in a trailing 24h
// window. Exists to respect a rate-limited relay's send cap, e.g. a
// personal Gmail account's undocumented ~500-recipients/24h limit.
type MailRateLimitConfig struct {
	// DailyRecipientCap is the maximum number of recipients emailed across
	// all mail kinds in any trailing 24h window. 0 (the default) disables
	// the cap.
	DailyRecipientCap int `yaml:"dailyRecipientCap" validate:"omitempty,gte=0"`
}

// LoadConfig loads server configuration from configFile and validates it.
func LoadConfig(configFile string) (*Config, error) {
	var cfg Config
	err := config.LoadConfig(configFile, &cfg)
	if err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}

	absPath, err := filepath.Abs(configFile)
	if err != nil {
		return nil, fmt.Errorf("resolve config file path: %w", err)
	}
	cfg.configDir = filepath.Dir(absPath)

	if errs := validator.NewValidator(&cfg); !errs.IsValid() {
		return nil, fmt.Errorf("invalid configuration:\n%s", errs.ErrorMessages())
	}

	return &cfg, nil
}
