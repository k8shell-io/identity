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

	// Organizations configures organization management.
	Organizations OrganizationsConfig `yaml:"organizations"`

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

	// configDir is the directory containing the loaded configuration file.
	configDir string
}

// OrganizationsConfig configures organization management.
type OrganizationsConfig struct {
	// AutoCreate lists organization names that are created automatically when a
	// user with that organization is first seen. Use ["*"] to allow all organizations.
	AutoCreate []string `yaml:"autoCreate"`
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
