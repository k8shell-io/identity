// Copyright 2025 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/k8shell-io/common/pkg/authz"
	"github.com/k8shell-io/common/pkg/models"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
)

const (
	defaultSecretPrefix     = "identity-token-"
	defaultLeaseName        = "identity-token-refresh"
	defaultRefreshInterval  = 15 * time.Minute
	defaultRefreshLookahead = 20 * time.Minute
	// tokenRefreshClaimTTL is the maximum time an instance may hold a claim on
	// a user's token refresh slot. If the instance crashes the claim expires
	// automatically and another instance can reclaim the slot
	tokenRefreshClaimTTL = 10 * time.Minute
	// tokenRefreshBatchSize is the maximum number of users claimed per tick
	tokenRefreshBatchSize = 50
	// tokenSecretWaitTimeout is how long getTokenFromKubernetesSecret polls for
	// a missing Secret after triggering a refresh. When this instance is the
	// leader it issues the token directly and does not poll. This timeout only
	// applies to non-leader instances waiting for the remote leader to act, so
	// it is set to match the worst-case leader response time (RetryPeriod of
	// the lease election plus a Kubernetes API round-trip).
	tokenSecretWaitTimeout = 10 * time.Second

	// Labels on managed Kubernetes Secrets
	labelManagedBy      = "app.kubernetes.io/managed-by"
	labelManagedByVal   = "identity"
	labelUsername       = "identity.k8shell.io/username"
	annotationExpiresAt = "identity.k8shell.io/expires-at"
)

// initKubernetesClient builds a Kubernetes client from the provided config.
// When KubeconfigPath is empty it tries in-cluster config first, then falls
// back to $KUBECONFIG / ~/.kube/config for local development.
func initKubernetesClient() (*kubernetes.Clientset, error) {
	restCfg, err := buildRestConfig()
	if err != nil {
		return nil, fmt.Errorf("build kubeconfig: %w", err)
	}
	return kubernetes.NewForConfig(restCfg)
}

// buildRestConfig builds a Kubernetes REST config using
// in-cluster config first, then falls back to $KUBECONFIG / ~/.kube/config
// for local development.
func buildRestConfig() (*rest.Config, error) {
	cfg, err := rest.InClusterConfig()
	if err == nil {
		return cfg, nil
	}
	// Fall back to local kubeconfig for development.
	kubeconfig := os.Getenv("KUBECONFIG")
	if kubeconfig == "" {
		kubeconfig = clientcmd.RecommendedHomeFile
	}
	return clientcmd.BuildConfigFromFlags("", kubeconfig)
}

// issueAndStoreToken issues a JWT for the user, persists it to the DB (when
// configured), and writes it to a Kubernetes Secret.
func (s *Server) issueAndStoreToken(user *models.User) (string, error) {
	if s.JWT == nil {
		return "", fmt.Errorf("JWT issuer not configured")
	}

	claims, token, err := s.JWT.IssueToken(user)
	if err != nil {
		return "", fmt.Errorf("issue JWT for user '%s': %w", user.Username, err)
	}

	if s.DB != nil {
		if err := s.DB.SetUserToken(context.Background(), user.Username, claims.ID, claims.ExpiresAt.Time); err != nil {
			return "", fmt.Errorf("store token for user '%s': %w", user.Username, err)
		}
	}

	if err := s.upsertKubernetesSecret(user.Username, token, claims.ExpiresAt.Time); err != nil {
		return "", fmt.Errorf("upsert k8s secret for user '%s': %w", user.Username, err)
	}

	s.log.Debug().Msgf("issued new token for user '%s', expires at %s", user.Username, claims.ExpiresAt.Format(time.RFC3339))
	s.tokenCache.Store(user.Username, claims)
	return token, nil
}

// ensureToken issues and stores a token for the user only when one is absent
// or approaching expiry. When forceRefresh is true it unconditionally issues a new token, ignoring the cache.
func (s *Server) ensureToken(user *models.User, forceRefresh bool) (refreshed bool, token string, err error) {
	if !forceRefresh {
		lookahead := s.k8sCfg.RefreshLookahead
		if lookahead == 0 {
			lookahead = defaultRefreshLookahead
		}
		threshold := time.Now().Add(lookahead)
		found := false

		if v, ok := s.tokenCache.Load(user.Username); ok {
			found = true
			if claims, ok := v.(*authz.UserClaims); ok && claims.ExpiresAt.After(threshold) {
				return false, "", nil
			}
		}

		if !found {
			claims, err := s.refreshLocalCache(user)
			if err != nil {
				s.log.Debug().Err(err).Msgf("failed to refresh local cache for user '%s'", user.Username)
			} else {
				if claims.ExpiresAt.After(threshold) {
					return false, "", nil
				}
			}
		}
	}

	token, err = s.issueAndStoreToken(user)
	if err != nil {
		return false, "", err
	}
	return true, token, nil
}

// refreshLocalCache attempts to refresh the local token cache for the user by
// reading the token from Kubernetes and verifying it. If successful it updates
// the cache and returns the claims. If the token is missing or invalid it
// evicts the cache entry and returns an error.
func (s *Server) refreshLocalCache(user *models.User) (*authz.UserClaims, error) {
	token, err := s.getTokenFromKubernetesSecret(user)
	if err != nil {
		s.tokenCache.Delete(user.Username)
		return nil, err
	}

	if token == "" {
		s.tokenCache.Delete(user.Username)
		return nil, fmt.Errorf("no token found in Kubernetes secret for user '%s'", user.Username)
	}

	claims, err := s.Verifier.VerifyToken(token)
	if err != nil {
		s.tokenCache.Delete(user.Username)
		return nil, fmt.Errorf("failed to verify token from Kubernetes secret for user '%s': %w", user.Username, err)
	}

	s.tokenCache.Store(user.Username, claims)
	return claims, nil
}

// triggerRefresh sends a non-blocking signal on refreshNow to wake up
// whichever token-refresh loop is running and start an immediate cycle.
func (s *Server) triggerRefresh() {
	select {
	case s.refreshNow <- struct{}{}:
	default:
	}
}

// getTokenFromKubernetesSecret reads the JWT string from the user's managed
// Kubernetes Secret. When the Secret does not exist the token is invalidated
// in the DB (when configured), the local cache entry is evicted, and a refresh
// cycle is triggered immediately. The function then polls for the secret to
// appear for up to tokenSecretWaitTimeout before returning an error.
func (s *Server) getTokenFromKubernetesSecret(user *models.User) (string, error) {
	namespace := s.k8sCfg.Namespace
	secretName := defaultSecretPrefix + user.Username

	secret, err := s.k8sClient.CoreV1().Secrets(namespace).Get(context.Background(),
		secretName, metav1.GetOptions{})
	if err != nil {
		if !k8serrors.IsNotFound(err) {
			return "", fmt.Errorf("get secret '%s/%s': %w", namespace, secretName, err)
		}

		s.tokenCache.Delete(user.Username)
		if s.DB != nil {
			if dbErr := s.DB.InvalidateUserToken(context.Background(), user.Username); dbErr != nil {
				s.log.Error().Err(dbErr).Msgf("failed to invalidate DB token for user '%s'", user.Username)
			}
		}
		s.log.Warn().Msgf("token secret '%s/%s' not found for user '%s'; invalidated and triggered refresh",
			namespace, secretName, user.Username)

		// If this instance is the current lease leader, issue the token directly
		// so the secret is available immediately. Non-leaders cannot issue tokens
		// (triggerRefresh only signals the local channel, not the remote leader),
		// so they poll and wait for the leader to re-create the secret.
		if s.DB == nil && s.isLeader.Load() == 1 {
			token, issueErr := s.issueAndStoreToken(user)
			if issueErr != nil {
				return "", fmt.Errorf("failed to issue token for user '%s': %w", user.Username, issueErr)
			}
			return token, nil
		}

		// DB path or non-leader: trigger the refresh loop and poll for the secret.
		s.triggerRefresh()
		deadline := time.Now().Add(tokenSecretWaitTimeout)
		poll := time.NewTicker(100 * time.Millisecond)
		defer poll.Stop()
		for time.Now().Before(deadline) {
			<-poll.C
			secret, err = s.k8sClient.CoreV1().Secrets(namespace).Get(context.Background(),
				secretName, metav1.GetOptions{})
			if err == nil {
				return string(secret.Data["token"]), nil
			}
			if !k8serrors.IsNotFound(err) {
				return "", fmt.Errorf("get secret '%s/%s': %w", namespace, secretName, err)
			}
		}
		return "", fmt.Errorf("token secret '%s/%s' not available after %s", namespace, secretName, tokenSecretWaitTimeout)
	}
	return string(secret.Data["token"]), nil
}

// upsertKubernetesSecret creates or updates the Kubernetes Secret that holds
// the user's JWT token.
func (s *Server) upsertKubernetesSecret(username, token string, expiresAt time.Time) error {
	namespace := s.k8sCfg.Namespace
	secretName := defaultSecretPrefix + username

	desired := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: namespace,
			Labels: map[string]string{
				labelManagedBy: labelManagedByVal,
				labelUsername:  username,
			},
			Annotations: map[string]string{
				annotationExpiresAt: expiresAt.Format(time.RFC3339),
			},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			"token": []byte(token),
		},
	}

	secrets := s.k8sClient.CoreV1().Secrets(namespace)
	existing, err := secrets.Get(context.Background(), secretName, metav1.GetOptions{})
	if k8serrors.IsNotFound(err) {
		if _, err = secrets.Create(context.Background(), desired, metav1.CreateOptions{}); err != nil {
			return fmt.Errorf("create k8s secret '%s/%s': %w", namespace, secretName, err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("get k8s secret '%s/%s': %w", namespace, secretName, err)
	}

	desired.ResourceVersion = existing.ResourceVersion
	if _, err = secrets.Update(context.Background(), desired, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("update k8s secret '%s/%s': %w", namespace, secretName, err)
	}
	return nil
}

// startTokenRefreshLoop launches the background token-refresh goroutine.
// When the DB is configured it uses SELECT FOR UPDATE SKIP LOCKED so that
// multiple instances share the work without duplication.
// When the DB is absent (file-provider only) it uses Kubernetes Lease leader
// election so that exactly one instance runs the loop at a time.
func (s *Server) startTokenRefreshLoop(ctx context.Context) {
	if s.DB != nil {
		go s.runDBTokenRefreshLoop(ctx)
	} else {
		go s.runLeaseTokenRefreshLoop(ctx)
	}
}

// *** Database-based token refresh loop with SELECT FOR UPDATE SKIP LOCKED ***

// runDBTokenRefreshLoop runs a ticker that continuously claims and refreshes
// near-expiry user tokens using Postgres FOR UPDATE SKIP LOCKED.
// An immediate cycle can be triggered by sending to s.refreshNow.
func (s *Server) runDBTokenRefreshLoop(ctx context.Context) {
	interval := s.k8sCfg.RefreshInterval
	if interval == 0 {
		interval = defaultRefreshInterval
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Reconcile K8s Secrets against DB state once on startup, then process
	// near-expiry tokens and orphan cleanup on every subsequent tick.
	// s.reconcileSecrets(ctx)
	s.refreshExpiredTokensFromDB(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.refreshExpiredTokensFromDB(ctx)
		case <-s.refreshNow:
			s.refreshExpiredTokensFromDB(ctx)
		}
	}
}

// refreshExpiredTokensFromDB claims a batch of near-expiry users from the DB
// and re-issues their tokens.
func (s *Server) refreshExpiredTokensFromDB(ctx context.Context) {
	lookahead := s.k8sCfg.RefreshLookahead
	if lookahead == 0 {
		lookahead = defaultRefreshLookahead
	}

	expiresBeforeTime := time.Now().Add(lookahead)
	claimUntil := time.Now().Add(tokenRefreshClaimTTL)

	s.log.Debug().Msgf("claiming users with tokens expiring before %s", expiresBeforeTime.Format(time.RFC3339))
	usernames, err := s.DB.ClaimUsersForTokenRefresh(ctx, expiresBeforeTime, claimUntil, tokenRefreshBatchSize)
	if err != nil {
		s.log.Error().Err(err).Msg("failed to claim users for token refresh")
		return
	}

	for _, username := range usernames {
		user, refreshed, err := s.GetUserByUsername(username)
		if err != nil {
			s.log.Warn().Err(err).Msgf("token refresh: failed to get user '%s'", username)
			continue
		}
		if refreshed {
			continue
		}
		if _, _, err := s.ensureToken(user, true); err != nil {
			s.log.Error().Err(err).Msgf("token refresh: failed to ensure token for user '%s'", username)
		}
	}
}

// *** Kubernetes Lease-based token refresh loop (no-DB path) ***

// runLeaseTokenRefreshLoop acquires a Kubernetes Lease (leader election) and,
// while holding the lease, runs a ticker to refresh tokens for all local file
// provider users. Only one instance holds the lease at a time.
func (s *Server) runLeaseTokenRefreshLoop(ctx context.Context) {
	if s.k8sClient == nil {
		s.log.Warn().Msg("no Kubernetes client available; token refresh loop disabled")
		return
	}

	leaseName := s.k8sCfg.LeaseName
	if leaseName == "" {
		leaseName = defaultLeaseName
	}
	leaseNamespace := s.k8sCfg.Namespace

	identity, err := os.Hostname()
	if err != nil {
		identity = fmt.Sprintf("identity-%d", time.Now().UnixNano())
	}

	lock := &resourcelock.LeaseLock{
		LeaseMeta: metav1.ObjectMeta{
			Name:      leaseName,
			Namespace: leaseNamespace,
		},
		Client: s.k8sClient.CoordinationV1(),
		LockConfig: resourcelock.ResourceLockConfig{
			Identity: identity,
		},
	}

	leaderelection.RunOrDie(ctx, leaderelection.LeaderElectionConfig{
		Lock:            lock,
		LeaseDuration:   60 * time.Second,
		RenewDeadline:   30 * time.Second,
		RetryPeriod:     5 * time.Second,
		ReleaseOnCancel: true,
		Callbacks: leaderelection.LeaderCallbacks{
			OnStartedLeading: func(ctx context.Context) {
				s.log.Info().Msgf("acquired leader lease '%s/%s'; starting token refresh loop", leaseNamespace, leaseName)
				s.isLeader.Store(1)
				s.runFileProviderTokenRefreshLoop(ctx)
			},
			OnStoppedLeading: func() {
				s.isLeader.Store(0)
				s.log.Info().Msg("lost leader lease; token refresh loop stopped")
			},
			OnNewLeader: func(newIdentity string) {
				if newIdentity != identity {
					s.log.Info().Msgf("token refresh leader is '%s'", newIdentity)
				}
			},
		},
	})
}

// runFileProviderTokenRefreshLoop refreshes tokens for all local file-provider
// users on a ticker. Called only by the leader instance.
// An immediate cycle can be triggered by sending to s.refreshNow.
func (s *Server) runFileProviderTokenRefreshLoop(ctx context.Context) {
	interval := s.k8sCfg.RefreshInterval
	if interval == 0 {
		interval = defaultRefreshInterval
	}

	s.log.Info().Msgf("starting file-provider token refresh loop, interval: %s, lookahead: %s",
		interval.String(), s.k8sCfg.RefreshLookahead.String())

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Reconcile K8s Secrets against file-provider state immediately on leader
	// election, then process near-expiry tokens and orphan cleanup each tick.
	// s.reconcileSecrets(ctx)
	s.refreshLocalUserTokens()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.refreshLocalUserTokens()
		case <-s.refreshNow:
			s.refreshLocalUserTokens()
		}
	}
}

// refreshLocalUserTokens issues tokens for file-provider users whose token is
// absent or approaching expiry. Uses the same ensureToken logic as on-demand
// lookups so that tokens are not re-issued on every background tick.
func (s *Server) refreshLocalUserTokens() {
	for _, user := range s.getLocalUsers() {
		if _, _, err := s.ensureToken(user, false); err != nil {
			s.log.Error().Err(err).Msgf("token refresh: failed to ensure token for local user '%s'", user.Username)
		}
	}
}
