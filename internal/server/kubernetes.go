// Copyright 2025 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	authenticationv1 "k8s.io/api/authentication/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// ErrServiceAccountNotFound indicates the Kubernetes service account
// referenced by a credential no longer exists in the cluster.
var ErrServiceAccountNotFound = errors.New("service account not found")

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

// issueKubernetesServiceAccountToken requests a short-lived bound service-account
// token from the Kubernetes TokenRequest API. The token audience is set to
// s.k8sCfg.SAToken.Audiences (defaulting to ["https://kubernetes.default.svc.cluster.local"]).
// When namespace is empty the server's configured default namespace is used.
// expirationSeconds controls the token TTL; values ≤ 0 use a 1-hour default.
func (s *Server) issueKubernetesServiceAccountToken(ctx context.Context, namespace, serviceAccountName string, expirationSeconds int64) (string, time.Time, error) {
	if s.k8sClient == nil {
		return "", time.Time{}, fmt.Errorf("kubernetes client not configured")
	}
	if namespace == "" {
		return "", time.Time{}, fmt.Errorf("namespace must be specified for service account token issuance")
	}

	audiences := s.k8sCfg.SAToken.Audiences
	if len(audiences) == 0 {
		audiences = []string{"https://kubernetes.default.svc.cluster.local"}
	}

	expSec := expirationSeconds
	if expSec <= 0 {
		expSec = 3600
	}

	tokenReq := &authenticationv1.TokenRequest{
		Spec: authenticationv1.TokenRequestSpec{
			Audiences:         audiences,
			ExpirationSeconds: &expSec,
		},
	}

	result, err := s.k8sClient.CoreV1().ServiceAccounts(namespace).CreateToken(
		ctx, serviceAccountName, tokenReq, metav1.CreateOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return "", time.Time{}, fmt.Errorf("service account '%s/%s': %w", namespace, serviceAccountName, ErrServiceAccountNotFound)
		}
		return "", time.Time{}, fmt.Errorf("create token for service account '%s/%s': %w", namespace, serviceAccountName, err)
	}

	return result.Status.Token, result.Status.ExpirationTimestamp.Time, nil
}
