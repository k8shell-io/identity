package server

import (
	"fmt"
	"path/filepath"

	"github.com/k8shell-io/common/pkg/authz"
	"github.com/k8shell-io/common/pkg/config"
	"github.com/k8shell-io/common/pkg/db"
	"github.com/k8shell-io/common/pkg/gapi"
	natsc "github.com/k8shell-io/common/pkg/nats"
	"github.com/k8shell-io/identity/internal/providers/file"
)

// Config contains server configuration loaded from YAML.
type Config struct {
	// GrpcConfig configures the gRPC server.
	GrpcConfig gapi.ServerConfig `yaml:"grpc"`

	// Nats configures the NATS client.
	Nats natsc.NATSClientConfig `yaml:"nats"`

	// DB configures the database connection.
	DB db.DBConfig `yaml:"db"`

	// LocalProviders configures local file-based identity providers.
	LocalProviders file.FileUserProviderConfig `yaml:"localProviders"`

	// RemoteProviders configures remote identity provider clients.
	RemoteProviders []gapi.ClientConfig `yaml:"remoteProviders"`

	// JWTIssuer configures JWT token issuance.
	JWTIssuer authz.JWTIssuerConfig `yaml:"jwtIssuer"`

	// configDir is the directory containing the loaded configuration file.
	configDir string
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
