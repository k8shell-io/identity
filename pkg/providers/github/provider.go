package github

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/bradfitz/gomemcache/memcache"
	"github.com/k8shell-io/identity/pkg/backend"
	"github.com/k8shell-io/identity/pkg/common"
	"github.com/k8shell-io/identity/pkg/log"
	"github.com/k8shell-io/identity/pkg/models"
	"github.com/rs/zerolog"
	"golang.org/x/crypto/ssh"
)

type GitHubProviderConfig struct {
	ID           string            `yaml:"id"`
	UserMaxAge   int               `yaml:"userMaxAge"`
	ClientID     string            `yaml:"clientId"`
	ClientSecret string            `yaml:"clientSecret"`
	Scopes       []string          `yaml:"scopes"`
	Template     string            `yaml:"template"`
	ExtraFields  map[string]string `yaml:"extra,omitempty"`
}

type GitHubProvider struct {
	config     GitHubProviderConfig
	memcache   *memcache.Client
	httpClient *http.Client
	log        *zerolog.Logger
	db         *backend.DB
	template   *common.UserTemplate
}

func NewGitHubProvider(cfg GitHubProviderConfig, cacheCfg backend.CacheConfig, db *backend.DB, baseDir string) (*GitHubProvider, error) {
	memcache := backend.NewCache(cacheCfg)
	template, err := common.NewUserTemplate(cfg.Template, baseDir)
	if err != nil {
		return nil, fmt.Errorf("load user template '%s': %w", cfg.Template, err)
	}
	provider := &GitHubProvider{
		config:     cfg,
		memcache:   memcache,
		httpClient: &http.Client{},
		log:        log.NewLogger("github"),
		db:         db,
		template:   template,
	}
	return provider, nil
}

func (p *GitHubProvider) Name() string {
	return "github"
}

func (p *GitHubProvider) UserMaxAge() int {
	if p.config.UserMaxAge <= 0 {
		return 3600 // default to 1 hour if not set
	}
	return p.config.UserMaxAge
}

func (p *GitHubProvider) FindUser(username string) (*models.User, error) {
	providerInfo, err := p.db.GetUserProviderInfo(username, p.Name())
	if err != nil {
		return nil, fmt.Errorf("failed to get user provider info for '%s': %w", username, err)
	}

	if providerInfo == nil {
		return nil, fmt.Errorf("%w: user '%s' was not onboard with provider %s", models.ErrUserNotOnboarded,
			username, p.Name())
	}

	if providerInfo.Status != "ready" {
		return nil, fmt.Errorf("user '%s' is not ready with provider %s, onboarding status: %s", username, p.Name(),
			providerInfo.Status)
	}

	// get user resource
	userData, err := MakeRequest(p.httpClient, "GET", GITHUB_USER_URL, providerInfo.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("failed to make request to GitHub API: %w", err)
	}

	// get emails resource
	emailsData := any("[]")
	if contains(p.config.Scopes, "user:email") {
		emailsData, err = MakeRequest(p.httpClient, "GET", GITHUB_EMAILS_URL, providerInfo.AccessToken)
		if err != nil {
			return nil, fmt.Errorf("failed to make request to GitHub API: %w", err)
		}
	}

	resource := map[string]any{
		"user":   userData,
		"emails": emailsData,
	}

	user, err := p.template.Eval(resource, p.config.ExtraFields)
	if err != nil {
		return nil, fmt.Errorf("template evaluation failed: %w", err)
	}
	user.Source = p.Name()

	return user, nil
}

func (p *GitHubProvider) OnboardUserDeviceFlow(username string) (*models.OnboardUser, error) {
	providerInfo, err := p.db.GetUserProviderInfo(username, p.Name())
	if err != nil {
		return nil, fmt.Errorf("failed to get user provider info for '%s': %w", username, err)
	}

	if providerInfo != nil {
		if providerInfo.Status == "ready" {
			return nil, fmt.Errorf("user '%s' is already onboarded with provider %s", username, p.Name())
		}
		if providerInfo.Status == "pending" {
			return nil, fmt.Errorf("user '%s' is already in onboarding process with provider %s", username, p.Name())
		}
		if providerInfo.Status == "expired" {
			err = p.db.DeleteUserProviderInfo(username, p.Name())
			if err != nil {
				return nil, fmt.Errorf("failed to delete expired user provider info for '%s': %w", username, err)
			}
			p.log.Info().Msgf("Reset expired onboarding for user '%s' with provider %s", username, p.Name())
			providerInfo = nil
		} else {
			return nil, fmt.Errorf("user '%s' is not ready with provider %s, onboarding status: %s", username, p.Name(),
				providerInfo.Status)
		}
	}

	resp, err := getDeviceCode(p.httpClient, p.config.ClientID, p.config.Scopes)
	if err != nil {
		return nil, fmt.Errorf("failed to get device code: %w", err)
	}

	onboardUser := &models.OnboardUser{
		Provider:        p.Name(),
		Username:        username,
		UserCode:        resp.UserCode,
		VerificationUrl: resp.VerificationURI,
		ExpiresIn:       resp.ExpiresIn,
	}

	err = p.db.CreateUserProviderInfo(&backend.ProviderInfo{
		Status:          "pending",
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
		Username:        username,
		Provider:        p.Name(),
		UserCode:        resp.UserCode,
		VerificationURI: resp.VerificationURI,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to save user provider info: %w", err)
	}

	go p.pollForAccessToken(username, resp.DeviceCode, resp.Interval, resp.ExpiresIn)

	return onboardUser, nil
}

func (p *GitHubProvider) pollForAccessToken(username, deviceCode string, intervalSec, expiresIn int) {
	timeout := time.After(time.Duration(expiresIn) * time.Second)
	tick := time.Tick(time.Duration(intervalSec) * time.Second)
	for {
		select {
		case <-timeout:
			p.db.UpdateUserProviderStatus(username, p.Name(), "expired")
			return
		case <-tick:
			resp, err := getAccessToken(p.httpClient, p.config.ClientID, deviceCode)
			if err != nil {
				continue
			}
			switch resp.Error {
			case "":
				_ = p.db.UpdateUserProviderToken(&backend.ProviderInfo{
					Username:    username,
					Provider:    p.Name(),
					AccessToken: resp.AccessToken,
					Status:      "ready",
					UpdatedAt:   time.Now(),
				})
				return
			case "authorization_pending":
				continue
			case "slow_down":
				intervalSec += 5
				tick = time.Tick(time.Duration(intervalSec) * time.Second)
			default:
				p.db.UpdateUserProviderStatus(username, p.Name(), "error")
				return
			}
		}
	}
}

func (p *GitHubProvider) AuthPublicKey(user *models.User, key ssh.PublicKey) (bool, error) {
	providerInfo, err := p.db.GetUserProviderInfo(user.Username, p.Name())
	if err != nil {
		return false, fmt.Errorf("failed to get user provider info for '%s': %w", user.Username, err)
	}
	if providerInfo == nil || providerInfo.Status != "ready" {
		return false, fmt.Errorf("%w: user '%s' is not ready with provider %s", models.ErrUserNotOnboarded,
			user.Username, p.Name())
	}

	var keys []string
	if p.memcache != nil {
		CacheKeys := fmt.Sprintf("github:%s:keys", user.Username)
		cacheItem, err := p.memcache.Get(CacheKeys)
		if err == nil && cacheItem != nil {
			keys = strings.Split(strings.TrimSpace(string(cacheItem.Value)), "\n")
		}
		if err != nil && err != memcache.ErrCacheMiss {
			p.log.Warn().Err(err).Msgf("failed to get cached public keys for user '%s'", user.Username)
		}
	}

	if len(keys) == 0 {
		keys, err = getPublicKeys(p.httpClient, user.Username, providerInfo.AccessToken)
		if err != nil {
			return false, fmt.Errorf("failed to get public keys for user '%s': %w", user.Username, err)
		}

		if p.memcache != nil && len(keys) > 0 {
			// Cache the public keys for 10 seconds
			CacheKeys := fmt.Sprintf("github:%s:keys", user.Username)
			if err := p.memcache.Set(&memcache.Item{
				Key:        CacheKeys,
				Value:      []byte(strings.Join(keys, "\n")),
				Expiration: 10,
			}); err != nil {
				p.log.Warn().Err(err).Msgf("failed to cache public keys for user '%s'", user.Username)
			}
		}
	}

	parsedKeys, _, err := common.ParseKeyList(keys)
	if err != nil {
		return false, fmt.Errorf("failed to parse public keys for user '%s': %w", user.Username, err)
	}

	provided := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
	for _, k := range parsedKeys {
		if k == provided {
			return true, nil
		}
	}
	return false, nil
}

func contains(slice []string, value string) bool {
	for _, v := range slice {
		if v == value {
			return true
		}
	}
	return false
}
