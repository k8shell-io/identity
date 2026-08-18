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

	// UsernamePattern is an exact username, or a pattern containing '*'.
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
