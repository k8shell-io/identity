// Copyright 2025 the k8Shell authors

package server

import (
	"fmt"
	"path/filepath"

	"github.com/k8shell-io/common/pkg/config"
	"github.com/k8shell-io/common/pkg/db"
	"github.com/k8shell-io/common/pkg/gapi"
	natsc "github.com/k8shell-io/common/pkg/nats"
	"github.com/k8shell-io/identity/internal/providers/file"
)

// Config represents the server configuration structure.
type Config struct {
	GrpcConfig      gapi.ServerConfig           `yaml:"grpc"`
	Nats            natsc.NATSClientConfig      `yaml:"nats"`
	DB              db.DBConfig                 `yaml:"db"`
	LocalProviders  file.FileUserProviderConfig `yaml:"localProviders"`
	RemoteProviders []gapi.ClientConfig         `yaml:"remoteProviders"`

	// ConfigDir is the directory where the configuration file is located.
	configDir string
}

// LoadConfig loads the server configuration from the specified YAML file.
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
