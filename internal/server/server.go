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
	"slices"
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

	// jwtIssuerCfg is the full JWT issuer configuration, retained so that
	// issueUserTokenWithExpiry can construct a temporary issuer with a custom expiry.
	jwtIssuerCfg authz.JWTIssuerConfig

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

	// passwordLockoutKV stores per-username password brute-force tracking
	// state (see PasswordLockoutState). It is nil when NATS is disabled, in
	// which case password lockout tracking is skipped.
	passwordLockoutKV *natsc.JetStreamKV

	// passwordLockoutCfg is the resolved (defaults-applied) lockout config.
	passwordLockoutCfg PasswordLockoutConfig
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
		server.log.Warn().Msg("password lockout tracking will be disabled without NATS")
	} else {
		server.passwordLockoutKV, err = server.nats.NewKV(natsc.BucketOptions{
			Bucket: natsc.PASSWORD_LOCKOUT_BUCKET,
		})
		if err != nil {
			return nil, fmt.Errorf("create password lockout KV bucket: %w", err)
		}
	}

	server.passwordLockoutCfg = config.PasswordLockout
	if server.passwordLockoutCfg.MaxAttempts == 0 {
		server.passwordLockoutCfg.MaxAttempts = 5
	}
	if server.passwordLockoutCfg.LockDuration == 0 {
		server.passwordLockoutCfg.LockDuration = 15 * time.Minute
	}

	server.log.Info().Msgf("Initializing JWT issuer: issuer=%s method=%s expiry=%s",
		config.JWTIssuer.Issuer, config.JWTIssuer.SigningMethod, config.JWTIssuer.Expiry)
	server.JWT, err = authz.NewJWTIssuer(config.JWTIssuer)
	if err != nil {
		return nil, fmt.Errorf("initialize JWT issuer: %w", err)
	}
	server.jwtIssuerCfg = config.JWTIssuer
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
	s.startAccessTokenJanitor(ctx)

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

// applyOnboardHint folds an onboarding decision an identity provider computed for
// this specific user (typically from CompleteUserWebFlow) into decision, which was
// otherwise resolved purely from identity.onboard_rules. hint's action, when one of
// the concrete actions, replaces decision.Action outright; any other value (notably
// OnboardActionNotDefined, but also anything unrecognized, defensively) leaves
// decision.Action untouched. hint.Roles, when non-empty, replaces decision.Roles
// after dropping any role that isn't assignable within decision.Org (see
// filterRolesForOrg) — a provider can't grant a role the org doesn't recognize.
// hint.Sudo, when non-nil, replaces decision.Sudo — proto3 optional gives the
// provider a way to say nothing about sudo (nil, defer to the db) as distinct from
// explicitly granting or revoking it (non-nil). decision.Org is never touched: the
// provider has no say in org placement, and if nothing in identity.onboard_rules
// matched this idp at all (the fail-closed case, decision.Org == ""), the hint is
// ignored entirely — there is no org to place the user into regardless of what the
// provider decided.
func (s *Server) applyOnboardHint(decision *backend.OnboardDecision, username string, hint *models.OnboardUserRule) {
	if hint == nil || decision.Org == "" {
		return
	}
	switch hint.Action {
	case models.OnboardActionAllow, models.OnboardActionReject, models.OnboardActionWaitlist:
		decision.Action = hint.Action
	}
	if len(hint.Roles) > 0 {
		decision.Roles = s.filterRolesForOrg(username, hint.Roles, decision.Org)
	}
	if hint.Sudo != nil {
		decision.Sudo = *hint.Sudo
	}
}

// filterRolesForOrg drops roles from an identity provider's onboarding hint that
// aren't assignable within org (org-scoped-or-global — the same resolution
// MissingRolesForOrg uses elsewhere for onboard_rules), logging a warning for
// each one dropped. Mirrors filterKnownRoles's fail-open behavior: a provider
// naming an unknown role must never block onboarding, so the role is dropped
// rather than the whole attempt rejected.
func (s *Server) filterRolesForOrg(username string, roles []string, org string) []string {
	if len(roles) == 0 {
		return roles
	}

	missing, err := s.DB.MissingRolesForOrg(roles, org)
	if err != nil {
		s.log.Warn().Err(err).Msgf(
			"filterRolesForOrg: failed to validate onboard hint roles for user '%s', keeping as returned", username)
		return roles
	}
	if len(missing) == 0 {
		return roles
	}

	unknown := make(map[string]struct{}, len(missing))
	for _, m := range missing {
		unknown[m] = struct{}{}
	}
	kept := make([]string, 0, len(roles))
	for _, r := range roles {
		if _, ok := unknown[r]; ok {
			s.log.Warn().Msgf(
				"dropping role '%s' from identity provider onboarding hint for user '%s': not a valid role for org '%s'",
				r, username, org)
			continue
		}
		kept = append(kept, r)
	}
	return kept
}

// refreshUser refreshes user data from configured identity providers when the
// user is missing, expired, or invalid. hint, when non-nil, is an onboarding
// decision an identity provider computed for this specific user (see
// applyOnboardHint) — nil for every caller except GetUserByUsernameWithOnboardHint.
// The second return value reports whether this call created the user in the
// database (as opposed to finding or updating an existing one).
func (s *Server) refreshUser(username string, source string, user *models.User,
	hint *models.OnboardUserRule) (*models.User, bool, error) {
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
					return nil, false, err
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
				foundUser.Roles = s.filterKnownRoles(foundUser.Username, foundUser.Roles)
				break
			}
		}

		createUser := (foundUser != nil && user == nil)
		updateUser := (foundUser != nil && user != nil)
		invalidateUser := (foundUser == nil && user != nil)

		if createUser {
			existing, err := s.DB.FindUser(username, "")
			if err != nil && !errors.Is(err, models.ErrUserNotFound) {
				return nil, false, fmt.Errorf("failed to check for existing user '%s' in database: %w", username, err)
			}
			if existing != nil && existing.Source != foundUser.Source {
				return nil, false, status.Errorf(codes.AlreadyExists,
					"username '%s' is already registered under provider '%s', cannot onboard via provider '%s'",
					username, existing.Source, foundUser.Source)
			}

			if err := s.checkEmailConflict(foundUser); err != nil {
				return nil, false, err
			}

			decision, err := s.DB.ResolveOnboardDecision(foundUser.Source, foundUser.Username)
			if err != nil {
				return nil, false, fmt.Errorf("failed to resolve onboard decision for user '%s': %w", username, err)
			}
			s.applyOnboardHint(decision, foundUser.Username, hint)

			switch decision.Action {
			case models.OnboardActionReject:
				// decision.Org is only empty in the fail-closed "nothing
				// matched at all" case (see ResolveOnboardDecision) — there's
				// no rule and no org to record a rejection against, so it's
				// deliberately not persisted. A real matched reject rule
				// always has decision.Org set.
				if decision.Org != "" {
					if err := s.DB.MarkRejectedByRule(foundUser.Source, foundUser.Username, decision.Org,
						decision.Roles, decision.Sudo, foundUser.Fullname, foundUser.Email); err != nil {
						s.log.Warn().Err(err).Msgf("failed to record onboard rejection for user '%s'", username)
					}
				}
				return nil, false, status.Errorf(codes.PermissionDenied,
					"onboarding not permitted for user '%s' via provider '%s'", username, foundUser.Source)
			case models.OnboardActionWaitlist:
				if err := s.DB.UpsertWaitlistEntry(foundUser.Source, foundUser.Username, decision.Org,
					decision.Roles, decision.Sudo, foundUser.Fullname, foundUser.Email); err != nil {
					return nil, false, fmt.Errorf("failed to add user '%s' to onboarding waitlist: %w", username, err)
				}
				return nil, false, status.Errorf(codes.FailedPrecondition,
					"user '%s' has been added to the onboarding waitlist and is awaiting admin approval: %v",
					username, models.ErrOnboardingPending)
			case models.OnboardActionAllow:
				foundUser.Organization = decision.Org
				if len(decision.Roles) > 0 {
					roles := make([]models.Role, len(decision.Roles))
					for i, r := range decision.Roles {
						roles[i] = models.Role(r)
					}
					foundUser.Roles = s.filterKnownRoles(foundUser.Username, roles)
				}
				foundUser.Sudo = decision.Sudo
			}

			err = s.DB.CreateUser(foundUser)
			if err != nil {
				return nil, false, fmt.Errorf("failed to create user '%s' in database: %w", username, err)
			}

			// Status bookkeeping is best-effort: the user is already
			// created, so a failure here must not fail the onboarding
			// itself or risk it being retried into a duplicate-user error.
			if err := s.DB.MarkOnboarded(foundUser.Source, foundUser.Username, foundUser.Organization,
				decision.Roles, decision.Sudo, foundUser.Fullname, foundUser.Email); err != nil {
				s.log.Warn().Err(err).Msgf("failed to record onboarded status for user '%s'", username)
			}

			return foundUser, true, nil
		}

		if updateUser {
			user.IsValid = foundUser.IsValid
			user.ExpiresAt = foundUser.ExpiresAt
			err := s.DB.UpdateUser(user)
			if err != nil {
				return nil, false, fmt.Errorf("failed to update user '%s' in database: %w", username, err)
			}
			return user, false, nil
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

// filterKnownRoles drops roles returned by an identity provider that are not
// registered in the role registry, logging a warning for each. This is the
// only role ingress path that isn't one of the four explicit role-assignment
// RPCs (which reject unknown roles outright via validateRoleAssignment) — a
// misconfigured or malicious IdP must not be able to silently mint roles by
// way of onboarding or login, but an unknown role here should never block
// the login/onboarding itself, so it is dropped rather than rejected.
func (s *Server) filterKnownRoles(username string, roles []models.Role) []models.Role {
	if len(roles) == 0 {
		return roles
	}

	names := make([]string, len(roles))
	for i, r := range roles {
		names[i] = string(r)
	}
	missing, err := s.DB.MissingRoles(names)
	if err != nil {
		s.log.Warn().Err(err).Msgf("filterKnownRoles: failed to validate roles for user '%s', keeping as returned", username)
		return roles
	}
	if len(missing) == 0 {
		return roles
	}

	unknown := make(map[string]struct{}, len(missing))
	for _, m := range missing {
		unknown[m] = struct{}{}
	}
	kept := make([]models.Role, 0, len(roles))
	for _, r := range roles {
		if _, ok := unknown[string(r)]; ok {
			s.log.Warn().Msgf("dropping unknown role '%s' for user '%s' returned by identity provider", r, username)
			continue
		}
		kept = append(kept, r)
	}
	return kept
}

// checkEmailConflict returns codes.AlreadyExists when foundUser's email is
// already registered to a different username. Empty emails are never checked,
// since they are not unique identifiers.
func (s *Server) checkEmailConflict(foundUser *models.User) error {
	if foundUser.Email == "" {
		return nil
	}

	existing, err := s.DB.FindUserByEmail(foundUser.Email)
	if err != nil && !errors.Is(err, models.ErrUserNotFound) {
		return fmt.Errorf("failed to check for existing email '%s' in database: %w", foundUser.Email, err)
	}
	if existing != nil && existing.Username != foundUser.Username {
		return status.Errorf(codes.AlreadyExists,
			"email '%s' is already registered to user '%s'", foundUser.Email, existing.Username)
	}
	return nil
}

// applyTokenCreatePolicy evaluates the token:create action against the authz
// service and returns the policy result so the caller can apply obligations
// (scopes, expires_in). Returns nil result when the authz client or JWT issuer
// is not configured.
func (s *Server) applyTokenCreatePolicy(user *models.User, source authz.TokenCreateSource) (*authz.PolicyResult, error) {
	if s.authzClient == nil || s.JWT == nil {
		return nil, nil
	}

	token, err := s.issueUserToken(user)
	if err != nil {
		return nil, fmt.Errorf("applyTokenCreatePolicy: failed to issue token for user '%s': %w", user.Username, err)
	}

	evalReq, err := authz.NewUserTokenCreateEvalRequest(user.Username).
		WithSource(source).
		Build()
	if err != nil {
		return nil, fmt.Errorf("applyTokenCreatePolicy: failed to build eval request for user '%s': %w", user.Username, err)
	}

	evalProto := evalReq.ToProto(token)
	evalProto.Package = "user"
	resp, err := s.authzClient.Evaluate(context.Background(), evalProto)
	if err != nil {
		return nil, fmt.Errorf("applyTokenCreatePolicy: authz evaluation failed for user '%s': %w", user.Username, err)
	}

	return authz.PolicyResultFromProto(resp), nil
}

// applyAuthPolicy evaluates the user:auth action against the authz service and
// confirms that method is among the auth_methods the policy permits for the
// user on the given surface. It is a no-op when the authz client or JWT
// issuer is not configured.
func (s *Server) applyAuthPolicy(user *models.User, method authz.UserAuthMethod, surface authz.AuthSurface) error {
	if s.authzClient == nil || s.JWT == nil {
		return nil
	}

	token, err := s.issueUserToken(user)
	if err != nil {
		return fmt.Errorf("applyAuthPolicy: failed to issue token for user '%s': %w", user.Username, err)
	}

	evalReq, err := authz.NewUserAuthEvalRequest(user.Username).
		WithIDP(user.Source).
		WithSurface(surface).
		Build()
	if err != nil {
		return fmt.Errorf("applyAuthPolicy: failed to build eval request for user '%s': %w", user.Username, err)
	}

	evalProto := evalReq.ToProto(token)
	evalProto.Package = "user"
	resp, err := s.authzClient.Evaluate(context.Background(), evalProto)
	if err != nil {
		return fmt.Errorf("applyAuthPolicy: authz evaluation failed for user '%s': %w", user.Username, err)
	}

	result := authz.PolicyResultFromProto(resp)
	if !result.Allowed {
		return fmt.Errorf("applyAuthPolicy: auth denied for user '%s': %s", user.Username, result.Reason)
	}

	obligation, ok := authz.ParseAuthMethodsObligation(result.Obligations)
	if !ok || !slices.Contains(obligation.Methods, method) {
		return fmt.Errorf("applyAuthPolicy: auth method '%s' not permitted for user '%s'", method, user.Username)
	}
	return nil
}

// issueUserToken issues a JWT for the user using the server's configured expiry.
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

// issueUserTokenWithExpiry issues a JWT for the user with a caller-supplied expiry,
// overriding the server default. Used by ResolveAccessToken so that the API gateway
// can request a JWT lifetime matched to the PAT session length.
func (s *Server) issueUserTokenWithExpiry(user *models.User, expiry time.Duration) (string, error) {
	if s.JWT == nil {
		return "", fmt.Errorf("JWT issuer not configured")
	}

	cfg := s.jwtIssuerCfg
	cfg.Expiry = expiry
	issuer, err := authz.NewJWTIssuer(cfg)
	if err != nil {
		return "", fmt.Errorf("create JWT issuer with custom expiry: %w", err)
	}

	claims, token, err := issuer.IssueToken(user)
	if err != nil {
		return "", fmt.Errorf("issue JWT for user '%s': %w", user.Username, err)
	}

	s.log.Debug().Msgf("issued token for user '%s' with custom expiry, expires at %s", user.Username, claims.ExpiresAt.Format(time.RFC3339))
	return token, nil
}

// GetUserByUsername retrieves a user by username from the database.
// It refreshes the user data when needed by querying configured identity providers.
func (s *Server) GetUserByUsername(username string, source string) (*models.User, error) {
	user, _, err := s.getUserByUsername(username, source, nil)
	return user, err
}

// GetUserByUsernameWithOnboardHint behaves like GetUserByUsername, but additionally
// takes an onboarding decision an identity provider computed for this specific user
// (e.g. from IdentityProviderService.CompleteUserWebFlow) and, when the user doesn't
// already exist, folds it into the onboarding decision otherwise resolved purely from
// identity.onboard_rules (see refreshUser). The second return value reports whether
// this call actually created the user (as opposed to finding an existing one) — used
// by callers that must only act on a fresh onboarding once, such as attaching a
// provider-supplied follow-up action to the response.
func (s *Server) GetUserByUsernameWithOnboardHint(username string, source string,
	hint *models.OnboardUserRule) (*models.User, bool, error) {
	return s.getUserByUsername(username, source, hint)
}

func (s *Server) getUserByUsername(username string, source string,
	hint *models.OnboardUserRule) (*models.User, bool, error) {
	if s.DB == nil {
		for _, user := range s.getLocalUsers() {
			if user.Username == username {
				return user, false, nil
			}
		}
		return nil, false, fmt.Errorf("user '%s' not found: %w", username, models.ErrUserNotFound)
	}

	user, err := s.DB.FindUser(username, source)
	if err != nil && !errors.Is(err, models.ErrUserNotFound) {
		return nil, false, fmt.Errorf("error occured when finding user '%s': %w", username, err)
	}

	// refresh user in the database
	user, freshlyOnboarded, err := s.refreshUser(username, source, user, hint)
	if err != nil {
		switch status.Code(err) {
		case codes.PermissionDenied, codes.Unauthenticated, codes.AlreadyExists, codes.FailedPrecondition:
			return nil, false, err
		}
		return nil, false, fmt.Errorf("error occured when refreshing user '%s': %w", username, err)
	}

	if user == nil {
		return nil, false, fmt.Errorf("user '%s' not found: %w", username, models.ErrUserNotFound)
	}

	if !user.IsValid {
		return nil, false, fmt.Errorf("user '%s' is not valid: %w", username, models.ErrUserIsNotValid)
	}

	return user, freshlyOnboarded, nil
}

// GetUserByEmail retrieves a user by email from the database. Unlike
// GetUserByUsername it does not query identity providers directly (they have
// no email-based lookup), but if the cached record is expired or invalid it
// is refreshed from providers by username, same as GetUserByUsername.
func (s *Server) GetUserByEmail(email string) (*models.User, error) {
	if s.DB == nil {
		for _, user := range s.getLocalUsers() {
			if user.Email == email {
				return user, nil
			}
		}
		return nil, fmt.Errorf("user with email '%s' not found: %w", email, models.ErrUserNotFound)
	}

	user, err := s.DB.FindUserByEmail(email)
	if err != nil && !errors.Is(err, models.ErrUserNotFound) {
		return nil, fmt.Errorf("error occured when finding user with email '%s': %w", email, err)
	}
	if user == nil {
		return nil, fmt.Errorf("user with email '%s' not found: %w", email, models.ErrUserNotFound)
	}

	user, _, err = s.refreshUser(user.Username, user.Source, user, nil)
	if err != nil {
		switch status.Code(err) {
		case codes.PermissionDenied, codes.Unauthenticated:
			return nil, err
		}
		return nil, fmt.Errorf("error occured when refreshing user '%s': %w", user.Username, err)
	}

	if user == nil {
		return nil, fmt.Errorf("user with email '%s' not found: %w", email, models.ErrUserNotFound)
	}

	if !user.IsValid {
		return nil, fmt.Errorf("user '%s' is not valid: %w", user.Username, models.ErrUserIsNotValid)
	}

	return user, nil
}

// GetUserByAccessToken retrieves a user by verifying the provided JWT access token.
// In the DB path the verified subject and source claims are used to look up the user.
// In the file-provider path the subject claim is used directly.
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
