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
	"sort"
	"strings"
	"syscall"
	"time"

	"sync"

	"github.com/k8shell-io/common/pkg/authz"
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
	"k8s.io/client-go/kubernetes"
)

// Server represents the identity service runtime and its dependencies.
type Server struct {
	// DB provides persistent user storage.
	DB *backend.DB

	// IdentityProviders maps provider name to provider client.
	IdentityProviders map[string]api.IdpClient

	// JWT issues signed JWT tokens for authenticated users.
	// It is nil when JWT issuance is disabled in config.
	JWT *authz.JWTIssuer

	// Verifier parses and validates JWT tokens for GetUserByAccessToken.
	// It is nil when JWT verification could not be initialized.
	Verifier *authz.JWTVerifier

	// jwtExpiry is the lifetime of issued JWTs, copied from JWTIssuerConfig so
	// the token refresh loop can compute expiry times without re-reading config.
	jwtExpiry time.Duration

	// k8sClient is the Kubernetes API client used to manage user token secrets.
	// It is nil when Kubernetes integration is disabled or unavailable.
	k8sClient *kubernetes.Clientset

	// k8sCfg holds the resolved Kubernetes configuration.
	k8sCfg KubernetesConfig

	// tokenCache tracks expiry times for issued tokens keyed by username.
	// Used so that ensureToken can skip re-issuing a token that is still valid.
	// The token string itself is never held in memory; Kubernetes Secrets are
	// the source of truth.
	tokenCache sync.Map // map[string]time.Time

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

	if config.DB.Enabled {
		server.log.Info().Msg("Database is enabled; initializing database connection")
		server.DB, err = backend.NewDB(config.DB, config.Organizations.AutoCreate)
		if err != nil {
			return nil, fmt.Errorf("create database pool: %w", err)
		}
	} else {
		server.log.Warn().Msg("Database is disabled in configuration; server will run without persistent storage")
	}

	server.nats, err = natsc.NewNATSClient(config.Nats)
	if err != nil {
		return nil, fmt.Errorf("create NATS client: %w", err)
	}

	if server.nats == nil {
		server.log.Warn().Msg("NATS client is not configured; caching and messaging features will be disabled")
	}

	server.log.Info().Msgf("Initializing JWT issuer: issuer=%s method=%s expiry=%s",
		config.JWTIssuer.Issuer, config.JWTIssuer.SigningMethod, config.JWTIssuer.Expiry)
	server.JWT, err = authz.NewJWTIssuer(config.JWTIssuer)
	if err != nil {
		return nil, fmt.Errorf("initialize JWT issuer: %w", err)
	}
	server.jwtExpiry = config.JWTIssuer.Expiry
	if server.jwtExpiry == 0 {
		server.jwtExpiry = time.Hour
	}

	// Build verifier config by inheriting issuer fields; PublicKeyFile can be
	// overridden explicitly for rs256/es256.
	verifierCfg := authz.JWTVerifierConfig{
		Issuer:         config.JWTIssuer.Issuer,
		Audience:       config.JWTIssuer.Audience,
		SigningMethod:  config.JWTIssuer.SigningMethod,
		SecretKey:      config.JWTIssuer.SecretKey,
		PrivateKeyFile: config.JWTIssuer.PrivateKeyFile,
	}
	server.Verifier, err = authz.NewJWTVerifier(verifierCfg)
	if err != nil {
		server.log.Warn().Err(err).Msg("failed to initialize JWT verifier; token-based lookup will be unavailable")
		server.Verifier = nil
	}

	if config.Kubernetes.Enabled {
		server.k8sCfg = config.Kubernetes
		server.k8sClient, err = initKubernetesClient(config.Kubernetes)
		if err != nil {
			server.log.Warn().Err(err).Msg("failed to initialize Kubernetes client; token secret management will be disabled")
			server.k8sClient = nil
		} else {
			server.log.Info().Msgf("Kubernetes client initialized; token secrets will be written to namespace '%s'",
				config.Kubernetes.Namespace)
		}
	} else {
		server.log.Warn().Msg("Kubernetes integration is disabled; token secrets will not be managed")
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

// getLocalUsers retrieves users from local file-based identity providers for in-memory user management.
// This is used when the server is running without a database, allowing to serve users defined in local files.
func (s *Server) getLocalUsers() []*models.User {
	var users []*models.User
	for _, provider := range s.IdentityProviders {
		if provider.Name() == file.FILE_PROVIDER_NAME {
			fileProvider := provider.(*file.FileUserProvider)
			userList := fileProvider.GetUsers()
			for _, user := range userList {
				s.normalizeUser(user)
				users = append(users, user)
			}
		}
	}
	return users
}

// loadProviders initializes identity providers from the loaded configuration.
func (s *Server) loadProviders(config *Config) error {
	s.IdentityProviders = make(map[string]api.IdpClient)

	if config.LocalProviders.Enabled {
		s.log.Info().Msg("Loading local file-based identity provider")
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

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	s.startTokenRefreshLoop(ctx)

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
		cancel()
		s.grpc.Stop()
		s.log.Info().Msg("Server shutdown complete")
		return nil
	case err := <-errChan:
		s.log.Error().Err(err).Msg("Server error occurred")
		return err
	}
}

// orderedProviders returns identity providers in deterministic (name-sorted) order.
// When source is non-empty only the provider matching that name is included.
func (s *Server) orderedProviders(source string) []api.IdpClient {
	names := make([]string, 0, len(s.IdentityProviders))
	for name := range s.IdentityProviders {
		if source == "" || name == source {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	result := make([]api.IdpClient, 0, len(names))
	for _, name := range names {
		result = append(result, s.IdentityProviders[name])
	}
	return result
}

// refreshUser refreshes user data from configured identity providers when the
// user is missing, expired, or invalid.
func (s *Server) refreshUser(username string, user *models.User) (*models.User, bool, error) {
	if user == nil || time.Now().After(user.ExpiresAt) || !user.IsValid {
		var foundUser *models.User
		source := ""
		if user != nil {
			source = user.Source
		}
		for _, provider := range s.orderedProviders(source) {
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
				foundUser.ExpiresAt = time.Now().Add(time.Duration(provider.UserMaxAge()) * time.Second)
				break
			}
		}

		createUser := (foundUser != nil && user == nil)
		updateUser := (foundUser != nil && user != nil)
		invalidateUser := (foundUser == nil && user != nil)

		if createUser || updateUser {
			if createUser {
				err := s.DB.CreateUser(foundUser)
				if err != nil {
					return nil, false, fmt.Errorf("failed to create user '%s' in database: %w", username, err)
				}
			} else if updateUser {
				foundUser.Shell = user.Shell
				foundUser.Sudo = user.Sudo
				foundUser.Locked = user.Locked
				err := s.DB.UpdateUser(foundUser)
				if err != nil {
					return nil, false, fmt.Errorf("failed to update user '%s' in database: %w", username, err)
				}
			}

			user = foundUser
			refreshed, err := s.ensureToken(user, true)
			if err != nil {
				s.log.Error().Err(err).Msgf("failed to ensure token for new user '%s'", username)
			}

			return user, refreshed, nil

		}

		if invalidateUser {
			user.IsValid = false
			err := s.DB.UpdateUser(user)
			if err != nil {
				return nil, false, fmt.Errorf("failed to mark user '%s' as invalid in database: %w", username, err)
			}
			s.log.Warn().Msgf("User '%s' marked as invalid because it could not be found in any provider", username)
			return user, false, nil
		}
	}

	return user, false, nil
}

// GetUserByUsername retrieves a user by username from the database.
// It refreshes the user data when needed by querying configured identity providers.
func (s *Server) GetUserByUsername(username string) (*models.User, bool, error) {
	if s.DB == nil {
		for _, user := range s.getLocalUsers() {
			if user.Username == username {
				if refreshed, err := s.ensureToken(user, false); err != nil {
					s.log.Error().Err(err).Msgf("failed to ensure token for user '%s'", username)
				} else if refreshed {
					return user, true, nil
				}
				return user, false, nil
			}
		}
		return nil, false, fmt.Errorf("user '%s' not found: %w", username, models.ErrUserNotFound)
	}

	user, err := s.DB.FindUser(username)
	if err != nil && !errors.Is(err, models.ErrUserNotFound) {
		return nil, false, fmt.Errorf("error occured when finding user '%s': %w", username, err)
	}

	// refresh user in the database
	var refreshed bool
	user, refreshed, err = s.refreshUser(username, user)
	if err != nil {
		return nil, false, fmt.Errorf("error occured when refreshing user '%s': %w", username, err)
	}

	if user == nil {
		return nil, false, fmt.Errorf("user '%s' not found: %w", username, models.ErrUserNotFound)
	}

	if !user.IsValid {
		return nil, false, fmt.Errorf("user '%s' is not valid: %w", username, models.ErrUserIsNotValid)
	}

	return user, refreshed, nil
}

// GetUserByAccessToken retrieves a user by verifying the provided JWT access token.
// In the DB path the token's JTI is matched against the stored current_token_id to
// support revocation. In the file-provider path the subject claim is used directly.
func (s *Server) GetUserByAccessToken(token string) (*models.User, error) {
	if s.Verifier == nil {
		return nil, fmt.Errorf("JWT verification is not configured")
	}

	claims, err := s.Verifier.VerifyToken(token)
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	if s.DB == nil {
		// File-provider path: signature is already verified; look up by subject.
		for _, user := range s.getLocalUsers() {
			if user.Username == claims.Subject {
				return user, nil
			}
		}
		return nil, fmt.Errorf("user '%s' not found: %w", claims.Subject, models.ErrUserNotFound)
	}

	// DB path: match JTI against current_token_id to support revocation.
	user, err := s.DB.FindUserByTokenID(context.Background(), claims.ID)
	if err != nil {
		return nil, fmt.Errorf("token not recognized: %w", err)
	}

	if !user.IsValid {
		return nil, fmt.Errorf("user '%s' is not valid: %w", user.Username, models.ErrUserIsNotValid)
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
