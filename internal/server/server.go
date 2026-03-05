// Copyright 2025 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Package server implements the main server logic for the k8Shell Identity service.
// It initializes the server, loads configuration, sets up identity providers, and
// provides methods for user authentication and management.
package server

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/k8shell-io/common/pkg/gapi"
	log "github.com/k8shell-io/common/pkg/logger"
	"github.com/k8shell-io/common/pkg/models"
	natsc "github.com/k8shell-io/common/pkg/nats"
	backend "github.com/k8shell-io/identity/internal/db"
	"github.com/k8shell-io/identity/internal/providers/file"
	"github.com/k8shell-io/identity/pkg/api"
	"github.com/k8shell-io/identity/pkg/api/identitypb"
	"github.com/k8shell-io/identity/pkg/api/typespb"
	"github.com/rs/zerolog"
	"google.golang.org/grpc"
)

// Server represents the identity service runtime and its dependencies.
type Server struct {
	// DB provides persistent user storage.
	DB *backend.DB

	// IdentityProviders maps provider name to provider client.
	IdentityProviders map[string]api.IdpClient

	grpc *gapi.Server
	nats *natsc.NATSClient
	log  *zerolog.Logger
}

// NewServer initializes a new Server from the provided configuration file.
// It loads configuration, initializes the database connection, and sets up
// identity providers.
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

	err = server.grpc.RegisterService(func(s *grpc.Server) error {
		identitypb.RegisterIdentityServiceServer(s, NewIdentityService(server))
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("register identity service: %w", err)
	}

	err = server.loadProviders(config)
	if err != nil {
		return nil, fmt.Errorf("load identity providers: %w", err)
	}

	return server, nil
}

// loadProviders initializes identity providers from the loaded configuration.
func (s *Server) loadProviders(config *Config) error {
	s.IdentityProviders = make(map[string]api.IdpClient)

	if config.LocalProviders.Enabled {
		fileProviders, err := file.NewFileUserProvider(config.LocalProviders, config.configDir)
		if err != nil {
			return fmt.Errorf("create file user provider: %w", err)
		}
		s.IdentityProviders[file.FILE_PROVIDER_NAME] = fileProviders
	}

	for _, idpCfg := range config.RemoteProviders {
		client, err := api.NewIdpClient(idpCfg)
		if err != nil {
			return fmt.Errorf("create identity provider client '%s': %w", idpCfg.Address, err)
		}

		if s.IdentityProviders == nil {
			s.IdentityProviders = make(map[string]api.IdpClient)
		}
		if s.IdentityProviders[client.Name()] != nil {
			return fmt.Errorf("duplicate identity provider name '%s' from address '%s'", client.Name(), idpCfg.Address)
		}
		s.IdentityProviders[client.Name()] = client
		s.log.Info().Msgf("Loaded identity provider '%s' from address '%s'", client.Name(), idpCfg.Address)
	}

	return nil
}

// Serve starts the gRPC server and blocks until shutdown signals are received
// or an error occurs.
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

// refreshUser refreshes user data from configured identity providers when the
// user is missing, expired, or invalid.
func (s *Server) refreshUser(username string, user *models.User) (*models.User, error) {
	var err error

	if user == nil || time.Now().After(user.ExpiresAt) || !user.IsValid {
		var foundUser *models.User
		for _, provider := range s.IdentityProviders {
			if user != nil && provider.Name() != user.Source {
				continue
			}
			userpb, err := provider.FindUser(context.Background(), &typespb.FindUserRequest{
				Username: username,
			})
			if err != nil {
				s.log.Warn().Msgf("Failed to look up user '%s' via provider '%s': %v", username, provider.Name(), err)
				continue
			}
			foundUser = gapi.ProtoToUser(userpb)

			if foundUser != nil {
				s.normalizeUser(foundUser)
				expiresAt := time.Now().Add(time.Duration(provider.UserMaxAge()) * time.Second)
				foundUser.ExpiresAt = expiresAt
				if user != nil {
					user.ExpiresAt = expiresAt
				}
				break
			}
		}

		if foundUser != nil && user == nil {
			err = s.DB.CreateUser(foundUser)
			if err != nil {
				return nil, fmt.Errorf("failed to create user '%s' in database: %w", username, err)
			}
			user = foundUser
		} else if foundUser != nil && user != nil {
			err = s.DB.UpdateUser(foundUser)
			if err != nil {
				return nil, fmt.Errorf("failed to update user '%s' in database: %w", username, err)
			}
			foundUser.AccessToken = user.AccessToken
			foundUser.Locked = user.Locked
			foundUser.FailedLogins = user.FailedLogins
			user = foundUser
		} else if foundUser == nil && user != nil {
			user.IsValid = false
			err = s.DB.UpdateUser(user)
			if err != nil {
				return nil, fmt.Errorf("failed to mark user '%s' as invalid in database: %w", username, err)
			}
		} else {
			user = nil
		}
	}
	return user, nil
}

// GetUser retrieves a user by username from the database.
// It refreshes the user data when needed by querying configured identity providers.
func (s *Server) GetUser(username string) (*models.User, error) {
	user, err := s.DB.FindUser(username)
	if err != nil && !errors.Is(err, models.ErrUserNotFound) {
		return nil, fmt.Errorf("error occured when finding user '%s': %w", username, err)
	}

	// refresh user in the database
	user, err = s.refreshUser(username, user)
	if err != nil {
		return nil, fmt.Errorf("error occured when refreshing user '%s': %w", username, err)
	}

	if user == nil {
		return nil, fmt.Errorf("user '%s' not found: %w", username, models.ErrUserNotFound)
	}

	if !user.IsValid {
		return nil, fmt.Errorf("user '%s' is not valid: %w", username, models.ErrUserIsNotValid)
	}

	return user, nil
}

// normalizeUser normalizes user attributes and applies default UID/GID values.
func (s *Server) normalizeUser(user *models.User) {
	if user == nil {
		return
	}
	user.Username = strings.ToLower(user.Username)
	if user.UID == 0 {
		user.UID = 100000
	}
	if user.GID == 0 {
		user.GID = 100000
	}
}
