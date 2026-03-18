// Copyright 2025 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"context"
	"fmt"
	"os"
	"time"

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
	// automatically and another instance can reclaim the slot.
	tokenRefreshClaimTTL = 10 * time.Minute
	// tokenRefreshBatchSize is the maximum number of users claimed per tick.
	tokenRefreshBatchSize = 50
)

// initKubernetesClient builds a Kubernetes client from the provided config.
// When KubeconfigPath is empty it tries in-cluster config first, then falls
// back to $KUBECONFIG / ~/.kube/config for local development.
func initKubernetesClient(cfg KubernetesConfig) (*kubernetes.Clientset, error) {
	restCfg, err := buildRestConfig(cfg.KubeconfigPath)
	if err != nil {
		return nil, fmt.Errorf("build kubeconfig: %w", err)
	}
	return kubernetes.NewForConfig(restCfg)
}

func buildRestConfig(kubeconfigPath string) (*rest.Config, error) {
	if kubeconfigPath != "" {
		return clientcmd.BuildConfigFromFlags("", kubeconfigPath)
	}
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
// configured), and writes it to a Kubernetes Secret (when configured).
// On success it records the token expiry in tokenCache so that ensureToken
// can skip re-issuing while the token is still valid.
// Errors are non-fatal at the call site: the background loop will retry.
func (s *Server) issueAndStoreToken(user *models.User) error {
	if s.JWT == nil {
		return nil
	}

	token, err := s.JWT.IssueToken(user)
	if err != nil {
		return fmt.Errorf("issue JWT for user '%s': %w", user.Username, err)
	}
	expiresAt := time.Now().Add(s.jwtExpiry)

	if s.DB != nil {
		if err := s.DB.SetUserToken(context.Background(), user.Username, token, expiresAt); err != nil {
			return fmt.Errorf("store token for user '%s': %w", user.Username, err)
		}
	}

	if s.k8sClient != nil {
		if err := s.upsertKubernetesSecret(user.Username, token); err != nil {
			return fmt.Errorf("upsert k8s secret for user '%s': %w", user.Username, err)
		}
	}

	s.tokenCache.Store(user.Username, expiresAt)
	return nil
}

// ensureToken issues and stores a token for the user only when one is absent
// or approaching expiry. This is used in the no-DB path so that file-provider
// users still get a K8s Secret without re-issuing on every single lookup.
func (s *Server) ensureToken(user *models.User) error {
	lookahead := s.k8sCfg.RefreshLookahead
	if lookahead == 0 {
		lookahead = defaultRefreshLookahead
	}
	threshold := time.Now().Add(lookahead)

	if v, ok := s.tokenCache.Load(user.Username); ok {
		if expiresAt, ok := v.(time.Time); ok && expiresAt.After(threshold) {
			return nil // token is still valid
		}
	}

	return s.issueAndStoreToken(user)
}

// upsertKubernetesSecret creates or updates the Kubernetes Secret that holds
// the user's JWT token.
func (s *Server) upsertKubernetesSecret(username, token string) error {
	prefix := s.k8sCfg.SecretPrefix
	if prefix == "" {
		prefix = defaultSecretPrefix
	}

	namespace := s.k8sCfg.Namespace
	secretName := prefix + username

	desired := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: namespace,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "identity",
				"identity.k8shell.io/username": username,
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

// runDBTokenRefreshLoop runs a ticker that continuously claims and refreshes
// near-expiry user tokens using Postgres FOR UPDATE SKIP LOCKED.
func (s *Server) runDBTokenRefreshLoop(ctx context.Context) {
	interval := s.k8sCfg.RefreshInterval
	if interval == 0 {
		interval = defaultRefreshInterval
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Refresh immediately on start, then on every tick.
	s.refreshExpiredTokensFromDB(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
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

	usernames, err := s.DB.ClaimUsersForTokenRefresh(ctx, expiresBeforeTime, claimUntil, tokenRefreshBatchSize)
	if err != nil {
		s.log.Error().Err(err).Msg("failed to claim users for token refresh")
		return
	}

	for _, username := range usernames {
		user, err := s.GetUserByUsername(username)
		if err != nil {
			s.log.Warn().Err(err).Msgf("token refresh: failed to get user '%s'", username)
			continue
		}
		if err := s.issueAndStoreToken(user); err != nil {
			s.log.Error().Err(err).Msgf("token refresh: failed to issue/store token for user '%s'", username)
		}
	}
}

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
	leaseNamespace := s.k8sCfg.LeaseNamespace
	if leaseNamespace == "" {
		leaseNamespace = s.k8sCfg.Namespace
	}

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
				s.runFileProviderTokenRefreshLoop(ctx)
			},
			OnStoppedLeading: func() {
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
func (s *Server) runFileProviderTokenRefreshLoop(ctx context.Context) {
	interval := s.k8sCfg.RefreshInterval
	if interval == 0 {
		interval = defaultRefreshInterval
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Refresh immediately on election, then on every tick.
	s.refreshLocalUserTokens()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.refreshLocalUserTokens()
		}
	}
}

// refreshLocalUserTokens issues tokens for file-provider users whose token is
// absent or approaching expiry. Uses the same ensureToken logic as on-demand
// lookups so that tokens are not re-issued on every background tick.
func (s *Server) refreshLocalUserTokens() {
	for _, user := range s.getLocalUsers() {
		if err := s.ensureToken(user); err != nil {
			s.log.Error().Err(err).Msgf("token refresh: failed to ensure token for local user '%s'", user.Username)
		}
	}
}
