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
	"github.com/k8shell-io/identity/internal/providers/file"
)

// KubernetesConfig contains configuration for Kubernetes secret management
// and distributed leader election.
type KubernetesConfig struct {
	// Namespace is the Kubernetes namespace where user token secrets are created.
	Namespace string `yaml:"namespace"`

	// LeaseName is the name of the Lease object used for leader election when
	// the database is not configured. Defaults to "identity-token-refresh".
	LeaseName string `yaml:"leaseName"`

	// RefreshInterval is how often the background loop checks for near-expiry
	// tokens. Defaults to 15 minutes.
	RefreshInterval time.Duration `yaml:"refreshInterval"`

	// RefreshLookahead is the remaining-lifetime threshold below which a token
	// is considered due for renewal. Defaults to 20 minutes.
	RefreshLookahead time.Duration `yaml:"refreshLookahead"`

	// ClusterAudiences lists the audiences embedded in service-account tokens
	// issued for Kubernetes cluster access via GetKubernetesServiceAccountToken.
	// Defaults to ["https://kubernetes.default.svc"] when empty.
	ClusterAudiences []string `yaml:"clusterAudiences"`
}

// Config contains server configuration loaded from YAML.
type Config struct {
	// GrpcConfig configures the gRPC server.
	GrpcConfig gapi.ServerConfig `yaml:"grpc"`

	// Nats configures the NATS client.
	Nats natsc.NATSClientConfig `yaml:"nats"`

	// DB configures the database connection.
	DB db.DBConfig `yaml:"db"`

	// Organizations configures organization management.
	Organizations OrganizationsConfig `yaml:"organizations"`

	// LocalProviders configures local file-based identity providers.
	LocalProviders file.FileUserProviderConfig `yaml:"localProviders"`

	// RemoteProviders configures remote identity provider clients.
	RemoteProviders []gapi.ClientConfig `yaml:"remoteProviders"`

	// JWTIssuer configures JWT token issuance.
	JWTIssuer authz.JWTIssuerConfig `yaml:"jwtIssuer"`

	// Kubernetes configures Kubernetes secret management and distributed
	// leader election for the token refresh loop.
	Kubernetes KubernetesConfig `yaml:"kubernetes"`

	// configDir is the directory containing the loaded configuration file.
	configDir string
}

// OrganizationsConfig configures organization management.
type OrganizationsConfig struct {
	// AutoCreate lists organization names that are created automatically when a
	// user with that organization is first seen. Use ["*"] to allow all organizations.
	AutoCreate []string `yaml:"autoCreate"`
}

// LoadConfig loads server configuration from configFile.
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

	return &cfg, nil
}
