// Copyright 2025 the k8Shell authors
// Package server implements the main server logic for the K8Shell Identity service.
// It initializes the server, loads configuration, sets up identity providers,
// and provides methods for user authentication and management.

package server

import (
	"fmt"

	log "github.com/k8shell-io/common/logger"
	"github.com/k8shell-io/identity/internal/backend"
	"github.com/k8shell-io/identity/internal/providers/file"
	"github.com/k8shell-io/identity/internal/providers/github"
	"github.com/k8shell-io/identity/internal/providers/usermap"
	identModels "github.com/k8shell-io/identity/pkg/models"
	"github.com/rs/zerolog"
)

// Server represents the main server structure for the K8Shell Identity service.
type Server struct {
	DBConfig   backend.DBConfig
	HttpConfig HttpConfig

	DB                *backend.DB
	IdentityProviders []identModels.IdentityProvider
	RestApi           *RESTApiService
	log               *zerolog.Logger
}

// NewServer initializes a new Server instance with the provided configuration file.
// It loads the server configuration, initializes the database connection,
// and sets up the identity providers based on the configuration.
func NewServer(configFile string) (*Server, error) {
	server := &Server{
		log: log.NewLogger("server"),
	}

	server.log.Info().Msgf("Loading server configuration from %s", configFile)

	// Load the server configuration
	config, err := LoadConfig(configFile)
	if err != nil {
		return nil, err
	}
	server.HttpConfig = config.Http
	server.DBConfig = config.DB

	server.DB, err = backend.NewDB(server.DBConfig, "")
	if err != nil {
		return nil, fmt.Errorf("create database pool: %w", err)
	}

	err = server.LoadProviders(config)
	if err != nil {
		return nil, fmt.Errorf("load identity providers: %w", err)
	}

	server.RestApi, err = NewRESTAPI(server.HttpConfig, server)
	if err != nil {
		return nil, fmt.Errorf("create REST API service: %w", err)
	}

	return server, nil
}

// LoadProviders initializes the identity providers based on the configuration.
func (s *Server) LoadProviders(config *Config) error {
	for _, node := range config.IdentityProviders {
		var raw map[string]any
		if err := node.Decode(&raw); err != nil {
			return fmt.Errorf("decode raw provider map: %w", err)
		}

		id, ok := raw["id"].(string)
		if !ok {
			return fmt.Errorf("missing or invalid provider 'id' field")
		}

		s.log.Debug().Msgf("Loading identity provider %s", id)

		switch id {
		case "file":
			var fileProvCfg file.FileUserProviderConfig
			if err := node.Decode(&fileProvCfg); err != nil {
				return fmt.Errorf("file provider config decode: %w", err)
			}
			p, err := file.NewFileUserProvider(fileProvCfg, config.configDir)
			if err != nil {
				return fmt.Errorf("file provider creation: %w", err)
			}
			s.IdentityProviders = append(s.IdentityProviders, p)

		case "usermap":
			var usermapProvCfg usermap.UserMapProviderConfig
			if err := node.Decode(&usermapProvCfg); err != nil {
				return fmt.Errorf("usermap provider config decode: %w", err)
			}
			p, err := usermap.NewUserMapProvider(usermapProvCfg, config.configDir, config.Cache)
			if err != nil {
				return fmt.Errorf("usermap provider creation: %w", err)
			}
			s.IdentityProviders = append(s.IdentityProviders, p)

		case "github":
			var githubProvCfg github.GitHubProviderConfig
			if err := node.Decode(&githubProvCfg); err != nil {
				return fmt.Errorf("github provider config decode: %w", err)
			}
			p, err := github.NewGitHubProvider(githubProvCfg, config.Cache, s.DB, config.configDir)
			if err != nil {
				return fmt.Errorf("github provider creation: %w", err)
			}
			s.IdentityProviders = append(s.IdentityProviders, p)

		default:
			return fmt.Errorf("unknown identity provider id: %s", id)
		}
	}
	return nil
}
