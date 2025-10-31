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
	"github.com/k8shell-io/identity/internal/providers/github"
	"github.com/k8shell-io/identity/internal/providers/usermap"
	"gopkg.in/yaml.v3"
)

// Config represents the server configuration structure.
type Config struct {
	GrpcConfig        gapi.ServerConfig      `yaml:"grpc"`
	Nats              natsc.NATSClientConfig `yaml:"nats"`
	DB                db.DBConfig            `yaml:"db"`
	IdentityProviders []yaml.Node            `yaml:"identityProviders"`

	// ConfigDir is the directory where the configuration file is located.
	configDir string
}

// LoadConfig loads the server configuration from the specified YAML file.
// It processes environment variable substitutions and custom tags like !file.
// It also validates the identity providers defined in the configuration.
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

	// validate identity providers
	for _, node := range cfg.IdentityProviders {
		var raw map[string]any
		if err := node.Decode(&raw); err != nil {
			return nil, fmt.Errorf("decode raw provider map: %w", err)
		}

		id, ok := raw["id"].(string)
		if !ok {
			return nil, fmt.Errorf("missing or invalid provider 'id' field")
		}

		switch id {
		case "file":
			var fileProvCfg file.FileUserProviderConfig
			if err := node.Decode(&fileProvCfg); err != nil {
				return nil, fmt.Errorf("file provider config decode: %w", err)
			}

		case "usermap":
			var usermapProvCfg usermap.UserMapProviderConfig
			if err := node.Decode(&usermapProvCfg); err != nil {
				return nil, fmt.Errorf("usermap provider config decode: %w", err)
			}

		case "github":
			var githubProvCfg github.GitHubProviderConfig
			if err := node.Decode(&githubProvCfg); err != nil {
				return nil, fmt.Errorf("github provider config decode: %w", err)
			}

		default:
			return nil, fmt.Errorf("unknown identity provider id: %s", id)
		}

	}
	return &cfg, nil
}
