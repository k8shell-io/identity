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
	natsc "github.com/k8shell-io/common/pkg/nats"
	"github.com/k8shell-io/identity/internal/backend"
	"github.com/k8shell-io/identity/pkg/api"
	"github.com/k8shell-io/identity/pkg/api/identitypb"
	"github.com/rs/zerolog"
	"google.golang.org/grpc"
)

// Server represents the main server structure for the K8Shell Identity service.
type Server struct {
	DB                *backend.DB
	IdentityProviders map[string]*api.IdpClient
	grpc              *gapi.Server
	nats              *natsc.NATSClient
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

	server.nats, err = natsc.NewNATSClient(config.Nats)
	if err != nil {
		return nil, fmt.Errorf("create NATS client: %w", err)
	}

	if server.nats == nil {
		server.log.Warn().Msg("NATS client is not configured; caching and messaging features will be disabled")
	}

	server.grpc, err = gapi.NewServer(&config.GrpcConfig, true)
	if err != nil {
		return nil, fmt.Errorf("create gRPC server: %w", err)
	}

	server.grpc.RegisterService(func(s *grpc.Server) error {
		identitypb.RegisterIdentityServiceServer(s, NewIdentityService(server))
		return nil
	})

	err = server.loadProviders(config)
	if err != nil {
		return nil, fmt.Errorf("load identity providers: %w", err)
	}

	return server, nil
}

// LoadProviders initializes the identity providers based on the configuration.
func (s *Server) loadProviders(config *Config) error {
	for _, idpCfg := range config.IdentityProviders {
		client, err := api.NewIdpClient(idpCfg)
		if err != nil {
			return fmt.Errorf("create identity provider client '%s': %w", idpCfg.Address, err)
		}

		if s.IdentityProviders == nil {
			s.IdentityProviders = make(map[string]*api.IdpClient)
		}
		if s.IdentityProviders[client.Name] != nil {
			return fmt.Errorf("duplicate identity provider name '%s' from address '%s'", client.Name, idpCfg.Address)
		}
		s.IdentityProviders[client.Name] = client
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
