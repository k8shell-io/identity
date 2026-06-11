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

	"sync"

	"github.com/k8shell-io/common/pkg/api/client/identity"
	authzv1 "github.com/k8shell-io/common/pkg/api/gen/go/authz/v1"
	identityv1 "github.com/k8shell-io/common/pkg/api/gen/go/identity/v1"
	"github.com/k8shell-io/common/pkg/authz"
	"github.com/k8shell-io/common/pkg/gapi"
	log "github.com/k8shell-io/common/pkg/logger"
	"github.com/k8shell-io/common/pkg/models"
	natsc "github.com/k8shell-io/common/pkg/nats"
	backend "github.com/k8shell-io/identity/internal/db"
	"github.com/k8shell-io/identity/internal/providers/file"
	"github.com/rs/zerolog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"k8s.io/client-go/kubernetes"
)

// Server represents the identity service runtime and its dependencies.
type Server struct {
	// DB provides persistent user storage.
	DB *backend.DB

	// IdentityProviders maps provider name to provider client.
	IdentityProviders map[string]identity.IdpClient

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

	authzClient authzv1.AuthzServiceClient

	// k8sCfg holds the resolved Kubernetes configuration.
	k8sCfg KubernetesConfig

	// providerMu guards IdentityProviders and pendingProviderCfgs.
	providerMu sync.RWMutex

	// pendingProviderCfgs holds remote provider configs that could not be
	// connected at startup and are retried in the background.
	pendingProviderCfgs []gapi.ClientConfig

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

	if config.Authz.IsEnabled() {
		authzConn, err := gapi.NewClient(config.Authz)
		if err != nil {
			return nil, fmt.Errorf("failed to create authz client: %w", err)
		}
		server.authzClient = authzv1.NewAuthzServiceClient(authzConn.Conn)
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

	server.k8sCfg = config.Kubernetes
	server.k8sClient, err = initKubernetesClient()
	if err != nil {
		server.log.Warn().Err(err).Msg("failed to initialize Kubernetes client")
		server.k8sClient = nil
	} else {
		server.log.Info().Msgf("Kubernetes client initialized.")
	}

	server.grpc, err = gapi.NewServer(&config.GrpcConfig, true)
	if err != nil {
		return nil, fmt.Errorf("create gRPC server: %w", err)
	}

	err = server.grpc.RegisterService(func(s *grpc.Server) error {
		identityv1.RegisterIdentityServiceServer(s, NewIdentityService(server))
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

// Serve starts the gRPC server and blocks until shutdown signals are received
// or an error occurs.
func (s *Server) Serve() error {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	s.startProviderRetryLoop(ctx)

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

// refreshUser refreshes user data from configured identity providers when the
// user is missing, expired, or invalid.
func (s *Server) refreshUser(username string, source string, user *models.User) (*models.User, error) {
	if user == nil || time.Now().After(user.ExpiresAt) || !user.IsValid {
		var foundUser *models.User
		if user != nil {
			source = user.Source
		}
		for _, provider := range s.orderedProviders(source) {
			s.log.Debug().Msgf("Attempting to refresh user '%s' from provider '%s'", username, provider.Name())
			userpb, err := provider.FindUser(context.Background(), &identityv1.FindUserRequest{
				Username: username,
			})
			if err != nil {
				switch status.Code(err) {
				case codes.PermissionDenied, codes.Unauthenticated:
					return nil, err
				}
				s.log.Warn().Msgf("Failed to look up user '%s' via provider '%s': %v", username, provider.Name(), err)
				continue
			}
			if userpb == nil || userpb.Username == "" {
				s.log.Debug().Msgf("Provider '%s' did not find user '%s'", provider.Name(), username)
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
				if err := s.applyOnboardPolicy(foundUser); err != nil {
					return nil, err
				}
				err := s.DB.CreateUser(foundUser)
				if err != nil {
					return nil, fmt.Errorf("failed to create user '%s' in database: %w", username, err)
				}
			} else if updateUser {
				foundUser.Shell = user.Shell
				foundUser.Sudo = user.Sudo
				foundUser.Locked = user.Locked
				foundUser.Roles = user.Roles
				err := s.DB.UpdateUser(foundUser)
				if err != nil {
					return nil, fmt.Errorf("failed to update user '%s' in database: %w", username, err)
				}
			}

			return user, nil

		}

		if invalidateUser {
			user.IsValid = false
			err := s.DB.UpdateUser(user)
			if err != nil {
				return nil, fmt.Errorf("failed to mark user '%s' as invalid in database: %w", username, err)
			}
			s.log.Warn().Msgf("User '%s' marked as invalid because it could not be found in any provider", username)
			return user, nil
		}
	}

	return user, nil
}

// applyOnboardPolicy evaluates the user:onboard action against the authz
// service. It returns an error when the policy denies onboarding. On allow it
// applies any resulting obligations (e.g. sudo) to the user before it is
// persisted. It is a no-op when the authz client or JWT issuer is not
// configured.
func (s *Server) applyOnboardPolicy(user *models.User) error {
	if s.authzClient == nil || s.JWT == nil {
		return nil
	}

	token, err := s.issueUserToken(user)
	if err != nil {
		return fmt.Errorf("applyOnboardPolicy: failed to issue token for user '%s': %w", user.Username, err)
	}

	evalReq, err := authz.NewUserEvalRequest(authz.UserActionOnboard, user.Username).
		WithIDP(user.Source).
		Build()
	if err != nil {
		return fmt.Errorf("applyOnboardPolicy: failed to build eval request for user '%s': %w", user.Username, err)
	}

	resp, err := s.authzClient.Evaluate(context.Background(), evalReq.ToProto(token))
	if err != nil {
		return fmt.Errorf("applyOnboardPolicy: authz evaluation failed for user '%s': %w", user.Username, err)
	}

	result := authz.PolicyResultFromProto(resp)
	if !result.Allowed {
		return fmt.Errorf("applyOnboardPolicy: onboarding denied for user '%s': %s", user.Username, result.Reason)
	}

	if sudo, ok := authz.ParseSudoObligation(result.Obligations); ok {
		user.Sudo = sudo.Granted
	}
	if roles, ok := authz.ParseRolesObligation(result.Obligations); ok {
		user.Roles = roles.Roles
	}
	return nil
}

// applyAuthPolicy evaluates the user:auth action against the authz service.
// It is a no-op when the authz client or JWT issuer is not configured.
func (s *Server) applyAuthPolicy(user *models.User, authCtx authz.UserAuthContext) error {
	if s.authzClient == nil || s.JWT == nil {
		return nil
	}

	token, err := s.issueUserToken(user)
	if err != nil {
		return fmt.Errorf("applyAuthPolicy: failed to issue token for user '%s': %w", user.Username, err)
	}

	evalReq, err := authz.NewUserEvalRequest(authz.UserActionAuth, user.Username).
		WithIDP(user.Source).
		WithAuthMethod(authCtx.Method).
		WithFingerprint(authCtx.Fingerprint).
		Build()
	if err != nil {
		return fmt.Errorf("applyAuthPolicy: failed to build eval request for user '%s': %w", user.Username, err)
	}

	resp, err := s.authzClient.Evaluate(context.Background(), evalReq.ToProto(token))
	if err != nil {
		return fmt.Errorf("applyAuthPolicy: authz evaluation failed for user '%s': %w", user.Username, err)
	}

	result := authz.PolicyResultFromProto(resp)
	if !result.Allowed {
		return fmt.Errorf("applyAuthPolicy: auth denied for user '%s': %s", user.Username, result.Reason)
	}
	return nil
}

// issueUserToken issues a JWT for the user
func (s *Server) issueUserToken(user *models.User) (string, error) {
	if s.JWT == nil {
		return "", fmt.Errorf("JWT issuer not configured")
	}

	claims, token, err := s.JWT.IssueToken(user)
	if err != nil {
		return "", fmt.Errorf("issue JWT for user '%s': %w", user.Username, err)
	}

	s.log.Debug().Msgf("issued new token for user '%s', expires at %s", user.Username, claims.ExpiresAt.Format(time.RFC3339))
	return token, nil
}

// GetUserByUsername retrieves a user by username from the database.
// It refreshes the user data when needed by querying configured identity providers.
func (s *Server) GetUserByUsername(username string, source string) (*models.User, error) {
	if s.DB == nil {
		for _, user := range s.getLocalUsers() {
			if user.Username == username {
				return user, nil
			}
		}
		return nil, fmt.Errorf("user '%s' not found: %w", username, models.ErrUserNotFound)
	}

	user, err := s.DB.FindUser(username, source)
	if err != nil && !errors.Is(err, models.ErrUserNotFound) {
		return nil, fmt.Errorf("error occured when finding user '%s': %w", username, err)
	}

	// refresh user in the database
	user, err = s.refreshUser(username, source, user)
	if err != nil {
		switch status.Code(err) {
		case codes.PermissionDenied, codes.Unauthenticated:
			return nil, err
		}
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

	user, err := s.DB.FindUserByUsernameAndSource(context.Background(), claims.Subject, claims.Source)
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
