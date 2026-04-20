// Copyright 2025 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/k8shell-io/common/pkg/api/client/identity"
	"github.com/k8shell-io/common/pkg/gapi"
	"github.com/k8shell-io/identity/internal/providers/file"
)

// providerRetryInterval is how often unavailable providers are retried.
const providerRetryInterval = 30 * time.Second

// loadProviders initializes identity providers from the loaded configuration.
func (s *Server) loadProviders(config *Config) error {
	s.IdentityProviders = make(map[string]identity.IdpClient)

	if config.LocalProviders.Enabled {
		s.log.Info().Msg("Loading local file-based identity provider")
		fileProviders, err := file.NewFileUserProvider(config.LocalProviders, config.configDir)
		if err != nil {
			return fmt.Errorf("create file user provider: %w", err)
		}
		s.IdentityProviders[file.FILE_PROVIDER_NAME] = fileProviders
	}

	for _, idpCfg := range config.RemoteProviders {
		client, err := identity.NewIdpClient(idpCfg)
		if err != nil {
			s.log.Warn().Msgf("Identity provider at '%s' unavailable at startup; will retry in background: %v", idpCfg.Address, err)
			s.pendingProviderCfgs = append(s.pendingProviderCfgs, idpCfg)
			continue
		}
		if s.IdentityProviders[client.Name()] != nil {
			return fmt.Errorf("duplicate identity provider name '%s' from address '%s'", client.Name(), idpCfg.Address)
		}
		s.IdentityProviders[client.Name()] = client
		s.log.Info().Msgf("Loaded identity provider '%s' from address '%s'", client.Name(), idpCfg.Address)
	}

	return nil
}

// startProviderRetryLoop starts a background goroutine that retries connecting
// to any remote identity providers that were unavailable at startup. It exits
// once all providers have connected.
func (s *Server) startProviderRetryLoop(ctx context.Context) {
	s.providerMu.RLock()
	pending := len(s.pendingProviderCfgs)
	s.providerMu.RUnlock()
	if pending == 0 {
		return
	}
	go s.runProviderRetryLoop(ctx)
}

func (s *Server) runProviderRetryLoop(ctx context.Context) {
	ticker := time.NewTicker(providerRetryInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.retryPendingProviders()
			s.providerMu.RLock()
			remaining := len(s.pendingProviderCfgs)
			s.providerMu.RUnlock()
			if remaining == 0 {
				return
			}
		}
	}
}

// retryPendingProviders attempts to connect to any pending remote identity providers.
func (s *Server) retryPendingProviders() {
	s.providerMu.RLock()
	pending := make([]gapi.ClientConfig, len(s.pendingProviderCfgs))
	copy(pending, s.pendingProviderCfgs)
	s.providerMu.RUnlock()

	var stillPending []gapi.ClientConfig
	for _, cfg := range pending {
		client, err := identity.NewIdpClient(cfg)
		if err != nil {
			s.log.Warn().Msgf("Identity provider at '%s' still unavailable: %v", cfg.Address, err)
			stillPending = append(stillPending, cfg)
			continue
		}
		s.providerMu.Lock()
		if s.IdentityProviders[client.Name()] != nil {
			s.providerMu.Unlock()
			s.log.Warn().Msgf("Identity provider '%s' already registered; skipping duplicate from '%s'", client.Name(), cfg.Address)
			_ = client.Close()
			continue
		}
		s.IdentityProviders[client.Name()] = client
		s.providerMu.Unlock()
		s.log.Info().Msgf("Identity provider '%s' connected from address '%s'", client.Name(), cfg.Address)
	}

	s.providerMu.Lock()
	s.pendingProviderCfgs = stillPending
	s.providerMu.Unlock()
}

// providerByName returns the named identity provider under a read lock.
func (s *Server) providerByName(name string) (identity.IdpClient, bool) {
	s.providerMu.RLock()
	defer s.providerMu.RUnlock()
	p, ok := s.IdentityProviders[name]
	return p, ok
}

// orderedProviders returns identity providers in deterministic (name-sorted) order.
// When source is non-empty only the provider matching that name is included.
func (s *Server) orderedProviders(source string) []identity.IdpClient {
	s.providerMu.RLock()
	defer s.providerMu.RUnlock()
	names := make([]string, 0, len(s.IdentityProviders))
	for name := range s.IdentityProviders {
		if source == "" || name == source {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	result := make([]identity.IdpClient, 0, len(names))
	for _, name := range names {
		result = append(result, s.IdentityProviders[name])
	}
	return result
}
