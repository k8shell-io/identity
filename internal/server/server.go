// Copyright 2025 the k8Shell authors
// Package server implements the main server logic for the K8Shell Identity service.
// It initializes the server, loads configuration, sets up identity providers,
// and provides methods for user authentication and management.

package server

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/k8shell-io/common/pkg/gapi"
	log "github.com/k8shell-io/common/pkg/logger"
	"github.com/k8shell-io/identity/internal/backend"
	"github.com/k8shell-io/identity/internal/providers/file"
	"github.com/k8shell-io/identity/internal/providers/github"
	"github.com/k8shell-io/identity/internal/providers/usermap"
	"github.com/k8shell-io/identity/pkg/api/identitypb"
	identModels "github.com/k8shell-io/identity/pkg/models"
	"github.com/rs/zerolog"
	"google.golang.org/grpc"
)

// Server represents the main server structure for the K8Shell Identity service.
type Server struct {
	DB                *backend.DB
	IdentityProviders []identModels.IdentityProvider
	grpc              *gapi.Server
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

	config, err := LoadConfig(configFile)
	if err != nil {
		return nil, err
	}

	server.DB, err = backend.NewDB(config.DB)
	if err != nil {
		return nil, fmt.Errorf("create database pool: %w", err)
	}

	err = server.LoadProviders(config)
	if err != nil {
		return nil, fmt.Errorf("load identity providers: %w", err)
	}

	server.grpc, err = gapi.NewServer(&config.GrpcConfig, true)
	if err != nil {
		return nil, fmt.Errorf("create gRPC server: %w", err)
	}

	server.grpc.RegisterService(func(s *grpc.Server) error {
		identitypb.RegisterIdentityServiceServer(s, NewIdentityService(server))
		return nil
	})

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

// Start starts the gRPC server and waits for shutdown signals
func (s *Server) Serve() error {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	errChan := make(chan error, 1)
	go func() {
		s.log.Info().Msg("Starting gRPC server")
		if err := s.grpc.Start(); err != nil {
			errChan <- fmt.Errorf("gRPC server error: %v", err)
		}
	}()

	select {
	case sig := <-sigChan:
		s.log.Info().Msgf("Received signal %v, shutting down gracefully", sig)
		s.grpc.Stop()
		s.log.Info().Msg("Server shutdown complete")
		return nil
	case err := <-errChan:
		s.log.Error().Err(err).Msg("Server error occurred")
		return err
	}
}
