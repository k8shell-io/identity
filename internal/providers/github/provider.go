package github

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/k8shell-io/common/pkg/cache"
	log "github.com/k8shell-io/common/pkg/logger"
	"github.com/k8shell-io/common/pkg/models"
	natsc "github.com/k8shell-io/common/pkg/nats"
	"github.com/k8shell-io/common/pkg/utils"
	"github.com/k8shell-io/identity/internal/backend"
	"github.com/k8shell-io/identity/internal/common"
	"github.com/k8shell-io/yaml-cel/pkg/yamlcel"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert/yaml"
	"golang.org/x/crypto/ssh"
)

const K8SHELL_FILENAME = ".k8shell"

type GitHubProviderConfig struct {
	ID           string            `yaml:"id"`
	UserMaxAge   int               `yaml:"userMaxAge"`
	ClientID     string            `yaml:"clientId"`
	ClientSecret string            `yaml:"clientSecret"`
	Scopes       []string          `yaml:"scopes"`
	Template     string            `yaml:"template"`
	ExtraFields  map[string]string `yaml:"extra,omitempty"`
	Allow        []string          `yaml:"allow,omitempty"`

	DefaultK8shellFile struct {
		Filename string `yaml:"filename"`
	} `yaml:"defaultK8shellFile,omitempty"`
}

type GitHubProvider struct {
	config                 GitHubProviderConfig
	baseDir                string
	cache                  cache.Cache
	httpClient             *http.Client
	log                    *zerolog.Logger
	db                     *backend.DB
	template               *yamlcel.CELTemplate
	defaultCustomBlueprint *models.CustomBlueprint
}

var ErrUnauthorized = errors.New("unauthorized")
var ErrWebFlowInProgress = errors.New("web flow state is already being processed")

func NewGitHubProvider(cfg GitHubProviderConfig, natsCfg natsc.NATSClientConfig, db *backend.DB,
	baseDir string) (*GitHubProvider, error) {
	template, err := yamlcel.NewTemplate(common.NormalizePath(cfg.Template, baseDir))
	if err != nil {
		return nil, fmt.Errorf("load user template '%s': %w", cfg.Template, err)
	}

	cache, err := cache.NewJetStreamCache(natsCfg, cache.BucketOptions{Bucket: "idp-github-cache"})
	if err != nil {
		return nil, fmt.Errorf("create cache: %w", err)
	}

	var cbp *models.CustomBlueprint
	if cfg.DefaultK8shellFile.Filename != "" {
		path := common.NormalizePath(cfg.DefaultK8shellFile.Filename, baseDir)
		_, err := os.Stat(path)
		if err != nil {
			return nil, fmt.Errorf("default k8shell file '%s' does not exist: %w", path, err)
		}

		fileContent, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("failed to read default k8shell file '%s': %w", path, err)
		}

		var k8shellFile models.K8shellFile
		err = yaml.Unmarshal(fileContent, &k8shellFile)
		if err != nil {
			return nil, fmt.Errorf("failed to parse default k8shell file '%s': %w", path, err)
		}

		var errors []string
		cbp, errors = models.ValidateK8shellFile(k8shellFile)
		if len(errors) > 0 {
			return nil, fmt.Errorf("failed to validate default k8shell file '%s': %v", path, errors)
		}
	}

	provider := &GitHubProvider{
		config:                 cfg,
		baseDir:                baseDir,
		cache:                  cache,
		httpClient:             &http.Client{},
		log:                    log.NewLogger("github"),
		db:                     db,
		template:               template,
		defaultCustomBlueprint: cbp,
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
		return nil, fmt.Errorf("%w: user '%s' was not onboarded with provider %s", models.ErrUserNotOnboarded,
			username, p.Name())
	}

	if providerInfo.Status != "ready" {
		return nil, fmt.Errorf("user '%s' is not ready with provider %s, onboarding status: %s", username, p.Name(),
			providerInfo.Status)
	}

	// get user resource
	userData, _, err := MakeRequest(p.httpClient, "GET", GITHUB_USER_URL, providerInfo.AccessToken, true)
	if err != nil {
		if errors.Is(err, ErrUnauthorized) {
			p.db.UpdateUserProviderStatus(username, p.Name(), "invalid")
			p.db.InvalidateUser(username)
		}
		return nil, fmt.Errorf("failed to make request to GitHub API: %w", err)
	}

	// get emails resource
	emailsData := any("[]")
	if contains(p.config.Scopes, "user:email") {
		emailsData, _, err = MakeRequest(p.httpClient, "GET", GITHUB_EMAILS_URL, providerInfo.AccessToken, true)
		if err != nil {
			if errors.Is(err, ErrUnauthorized) {
				p.db.UpdateUserProviderStatus(username, p.Name(), "invalid")
				p.db.InvalidateUser(username)
			}
			return nil, fmt.Errorf("failed to make request to GitHub API: %w", err)
		}
	}

	resource := map[string]any{
		"user":   userData,
		"emails": emailsData,
	}

	user, err := yamlcel.EvalToStruct[models.User](p.template, resource, p.config.ExtraFields, "user")
	if err != nil {
		return nil, fmt.Errorf("template evaluation failed: %w", err)
	}
	user.Source = p.Name()
	user.Username = strings.ToLower(user.Username) // normalize username to lowercase

	return user, nil
}

func (p *GitHubProvider) OnboardCapability(username string) (*models.OnboardCapability, error) {
	cap := &models.OnboardCapability{
		Provider:   p.Name(),
		Username:   username,
		CanOnboard: false,
	}

	if len(p.config.Allow) > 0 {
		if !contains(p.config.Allow, username) {
			return cap, nil // user is not allowed to onboard
		}
	}
	_, statusCode, err := MakeRequest(p.httpClient, "GET", fmt.Sprintf(GITHUB_PUBLIC_USER_URL, username), "", false)
	if err != nil {
		return nil, fmt.Errorf("failed to make request to GitHub API: %w", err)
	}
	switch statusCode {
	case http.StatusOK:
		cap.CanOnboard = true
	case http.StatusNotFound:
		cap.CanOnboard = false
	default:
		return nil, fmt.Errorf("unexpected status code: %d", statusCode)
	}
	return cap, nil
}

func (p *GitHubProvider) OnboardUserDeviceFlow(username string) (*models.OnboardUserDeviceFlow, error) {
	providerInfo, err := p.db.GetUserProviderInfo(username, p.Name())
	if err != nil {
		return nil, fmt.Errorf("failed to get user provider info for '%s': %w", username, err)
	}

	if providerInfo != nil {
		if providerInfo.Status == "ready" {
			return nil, fmt.Errorf("%w: user '%s' is already onboarded with provider %s",
				models.ErrAlreadyOnboarded, username, p.Name())
		}
		if providerInfo.Status == "pending" {
			expiresIn := int(time.Until(*providerInfo.ExpiresAt).Seconds())
			if expiresIn > 0 {
				return &models.OnboardUserDeviceFlow{
					Provider:        p.Name(),
					Username:        username,
					UserCode:        providerInfo.UserCode,
					VerificationUrl: providerInfo.VerificationURI,
					ExpiresIn:       expiresIn,
				}, nil
			}
		}

		// reset onboarding if status is not pending or ready
		p.log.Info().Msgf("Reset onboarding in status '%s' for user '%s' with provider %s",
			providerInfo.Status, username, p.Name())
		err = p.db.DeleteUserProviderInfo(username, p.Name())
		if err != nil {
			return nil, fmt.Errorf("failed to delete user provider info for '%s': %w", username, err)
		}
		providerInfo = nil
	}

	// check user exsists in github
	cap, err := p.OnboardCapability(username)
	if err != nil {
		return nil, fmt.Errorf("failed to check onboarding capability: %w", err)
	}
	if !cap.CanOnboard {
		return nil, fmt.Errorf("user '%s' cannot be onboarded", username)
	}

	// get user code via device flow
	resp, err := getDeviceCode(p.httpClient, p.config.ClientID, p.config.Scopes)
	if err != nil {
		return nil, fmt.Errorf("failed to get device code: %w", err)
	}

	onboardUser := &models.OnboardUserDeviceFlow{
		Provider:        p.Name(),
		Username:        username,
		UserCode:        resp.UserCode,
		VerificationUrl: resp.VerificationURI,
		ExpiresIn:       resp.ExpiresIn,
	}

	expiresAt := time.Now().Add(time.Duration(resp.ExpiresIn) * time.Second)
	err = p.db.CreateOrUpdateUserProviderInfo(&models.ProviderInfo{
		Status:          "pending",
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
		Username:        username,
		Provider:        p.Name(),
		UserCode:        resp.UserCode,
		DeviceCode:      resp.DeviceCode,
		ExpiresAt:       &expiresAt,
		VerificationURI: resp.VerificationURI,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to save user provider info: %w", err)
	}

	go p.pollForAccessToken(username, resp.DeviceCode, resp.Interval, resp.ExpiresIn)

	return onboardUser, nil
}

// OnboardUserWebFlow initiates the OAuth web flow for user onboarding.
func (p *GitHubProvider) OnboardUserWebFlow(redirectUri string) (*models.OnboardUserWebFlow, error) {
	if p.cache == nil {
		return nil, fmt.Errorf("cache is required for web flow onboarding")
	}

	nonce, err := randomURLSafeString(24)
	if err != nil {
		return nil, fmt.Errorf("generate state: %w", err)
	}
	state := utils.EncodeState(p.Name(), nonce)

	codeVerifier, err := randomURLSafeString(64)
	if err != nil {
		return nil, fmt.Errorf("generate code verifier: %w", err)
	}
	sum := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(sum[:])

	p.log.Debug().Msgf("Generated PKCE code challenge '%s' for state '%s'", codeChallenge, state)

	cacheKey := fmt.Sprintf("github:webflow:%s", state)
	cachePayload := map[string]any{
		"provider":        p.Name(),
		"client_id":       p.config.ClientID,
		"scopes":          p.config.Scopes,
		"code_verifier":   codeVerifier,
		"created_at_unix": time.Now().Unix(),
	}
	cacheBytes, err := json.Marshal(cachePayload)
	if err != nil {
		return nil, fmt.Errorf("marshal cache payload: %w", err)
	}
	if err := p.cache.Set(cacheKey, cacheBytes, time.Duration(10)*time.Minute); err != nil {
		return nil, fmt.Errorf("cache web flow context: %w", err)
	}

	u, _ := url.Parse("https://github.com/login/oauth/authorize")
	q := u.Query()
	q.Set("client_id", p.config.ClientID)
	q.Set("redirect_uri", redirectUri)
	if len(p.config.Scopes) > 0 {
		q.Set("scope", strings.Join(p.config.Scopes, " "))
	}
	q.Set("state", state)
	q.Set("code_challenge", codeChallenge)
	q.Set("code_challenge_method", "S256")
	q.Set("allow_signup", "false")
	u.RawQuery = q.Encode()

	p.log.Debug().Msgf("Generated GitHub OAuth authorize URL %s, state: '%s'", u.String(), state)

	return &models.OnboardUserWebFlow{
		Provider:         p.Name(),
		AuthorizationURL: u.String(),
		State:            state,
		ExpiresIn:        600,
	}, nil
}

// CompleteUserWebFlow completes the OAuth web flow for user onboarding.
// It exchanges the authorization code for an access token, retrieves user info, and creates the user in the system.
// It also checks if the user can onboard based on the allow list.
func (p *GitHubProvider) CompleteUserWebFlow(state string, code string) (string, error) {
	if p.cache == nil {
		return "", fmt.Errorf("cache is required for web flow onboarding")
	}

	if state == "" || code == "" {
		return "", fmt.Errorf("state and code must be provided")
	}

	p.log.Debug().Msgf("Completing GitHub web flow for state '%s'", state)

	// Acquire a per-state lock
	lockKey := fmt.Sprintf("githubwebflow-%s-lock", state)
	lock, err := p.cache.AcquireLock(lockKey, time.Duration(30)*time.Second)
	if err != nil {
		return "", fmt.Errorf("acquire web flow lock: %w", err)
	}
	defer func() {
		_ = lock.Release()
	}()

	cacheKey := fmt.Sprintf("githubwebflow-%s", state)
	cacheItem, err := p.cache.Get(cacheKey)
	if err != nil {
		if err == cache.ErrCacheMiss {
			return "", fmt.Errorf("invalid or expired state")
		}
		return "", fmt.Errorf("get web flow context from cache: %w", err)
	}

	var cachePayload map[string]any
	if err := json.Unmarshal(cacheItem, &cachePayload); err != nil {
		return "", fmt.Errorf("unmarshal web flow context from cache: %w", err)
	}

	clientID, ok := cachePayload["client_id"].(string)
	if !ok {
		return "", fmt.Errorf("invalid client_id in cached web flow context")
	}
	codeVerifier, ok := cachePayload["code_verifier"].(string)
	if !ok {
		return "", fmt.Errorf("invalid code_verifier in cached web flow context")
	}

	tokenResp, err := exchangeCodeForAccessToken(p.httpClient, clientID, p.config.ClientSecret, code, codeVerifier)
	if err != nil {
		return "", fmt.Errorf("exchange code for access token: %w", err)
	}

	if err := p.cache.Delete(cacheKey); err != nil && err != cache.ErrCacheMiss {
		p.log.Warn().Err(err).Msgf("failed to invalidate web flow cache for state '%s'", state)
	}

	userData, _, err := MakeRequest(p.httpClient, "GET", GITHUB_USER_URL, tokenResp.AccessToken, true)
	if err != nil {
		return "", fmt.Errorf("failed to make request to GitHub API: %w", err)
	}

	username, ok := userData.(map[string]interface{})["login"].(string)
	if !ok || username == "" {
		return "", fmt.Errorf("failed to get username from GitHub user data")
	}

	if len(p.config.Allow) > 0 && !contains(p.config.Allow, username) {
		return "", fmt.Errorf("user '%s' is not allowed to onboard", username)
	}

	err = p.db.CreateOrUpdateUserProviderInfo(&models.ProviderInfo{
		Status:      "ready",
		UpdatedAt:   time.Now(),
		Username:    username,
		Provider:    p.Name(),
		AccessToken: tokenResp.AccessToken,
	})
	if err != nil {
		return "", fmt.Errorf("failed to save user provider info: %w", err)
	}

	return username, nil
}

// randomURLSafeString returns a base64url string generated from n random bytes.
func randomURLSafeString(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
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
				// user should have completed the device flow
				// check if we can get user data
				userData, _, err := MakeRequest(p.httpClient, "GET", GITHUB_USER_URL, resp.AccessToken, true)
				if err != nil {
					p.log.Error().Err(err).Msgf("failed to get user data for '%s' from GitHub", username)
					p.db.UpdateUserProviderStatus(username, p.Name(), "error")
					return
				}

				// check if the username matches
				login, ok := userData.(map[string]interface{})["login"].(string)
				if !ok || !strings.EqualFold(login, username) {
					p.log.Error().Msgf("username mismatch: expected '%s', got '%v'", username, login)
					p.db.UpdateUserProviderStatus(username, p.Name(), "error")
					return
				}

				if p.db.UpdateUserProvider(username, p.Name(), resp.AccessToken, "", "ready") != nil {
					p.log.Error().Err(err).Msgf("failed to update user provider token for '%s'", username)
				}
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

func (p *GitHubProvider) AuthPublicKey(username string, key ssh.PublicKey) (bool, error) {
	providerInfo, err := p.db.GetUserProviderInfo(username, p.Name())
	if err != nil {
		return false, fmt.Errorf("failed to get user provider info for '%s': %w", username, err)
	}
	if providerInfo == nil || providerInfo.Status != "ready" {
		return false, fmt.Errorf("%w: user '%s' is not ready with provider %s", models.ErrUserNotOnboarded,
			username, p.Name())
	}

	var keys []string
	if p.cache != nil {
		CacheKeys := fmt.Sprintf("github:%s:keys", username)
		cacheItem, err := p.cache.Get(CacheKeys)
		if err == nil && cacheItem != nil {
			keys = strings.Split(strings.TrimSpace(string(cacheItem)), "\n")
		}
		if err != nil && err != cache.ErrCacheMiss {
			p.log.Warn().Err(err).Msgf("failed to get cached public keys for user '%s'", username)
		}
	}

	if len(keys) == 0 {
		keys, err = getPublicKeys(p.httpClient, username, providerInfo.AccessToken)
		if err != nil {
			if errors.Is(err, ErrUnauthorized) {
				p.db.UpdateUserProviderStatus(username, p.Name(), "invalid")
				p.db.InvalidateUser(username)
			}
			return false, fmt.Errorf("failed to get public keys for user '%s': %w", username, err)
		}

		if p.cache != nil && len(keys) > 0 {
			// Cache the public keys for 10 seconds
			CacheKeys := fmt.Sprintf("github:%s:keys", username)
			if err := p.cache.Set(CacheKeys,
				[]byte(strings.Join(keys, "\n")),
				time.Duration(10)*time.Second,
			); err != nil {
				p.log.Warn().Err(err).Msgf("failed to cache public keys for user '%s'", username)
			}
		}
	}

	parsedKeys, _, err := common.ParseKeyList(keys)
	if err != nil {
		return false, fmt.Errorf("failed to parse public keys for user '%s': %w", username, err)
	}

	provided := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
	for _, k := range parsedKeys {
		if k == provided {
			return true, nil
		}
	}
	return false, nil
}

func (p *GitHubProvider) GetUserToken(username string) (*models.UserToken, error) {
	providerInfo, err := p.db.GetUserProviderInfo(username, p.Name())
	if err != nil {
		return nil, fmt.Errorf("failed to get user provider info for '%s': %w", username, err)
	}

	if providerInfo == nil || providerInfo.Status != "ready" {
		return nil, fmt.Errorf("%w: user '%s' is not ready with provider %s", models.ErrUserNotOnboarded,
			username, p.Name())
	}

	return &models.UserToken{
		Provider: p.Name(),
		Address:  "github.com",
		Username: username,
		Token:    providerInfo.AccessToken,
	}, nil
}

func (p *GitHubProvider) GetCustomBlueprint(userStr *models.UserStr) (*models.CustomBlueprint, error) {
	if !userStr.HasCustomBlueprint {
		return nil, fmt.Errorf("user string does not use a custom blueprint")
	}

	useDefault := func(cause error, msg string) (*models.CustomBlueprint, error) {
		p.log.Warn().Err(cause).Msgf("%s; falling back to default custom blueprint", msg)
		if p.defaultCustomBlueprint == nil {
			return nil, fmt.Errorf("%s; no default custom blueprint configured: %w", msg, cause)
		}
		bp, err := deepCopyBlueprint(p.defaultCustomBlueprint)
		if err != nil {
			return nil, fmt.Errorf("failed to copy default custom blueprint: %w", err)
		}
		bp.Name = userStr.Blueprint
		bp.Metadata.Name = userStr.Blueprint
		bp.Metadata.RepoName = userStr.RepoName
		bp.Metadata.RepoOwner = userStr.RepoOwner
		bp.Metadata.RepoAddress = GITHUB_ADDRESS
		return bp, nil
	}

	token, err := p.GetUserToken(userStr.Username)
	if err != nil {
		return useDefault(err, fmt.Sprintf("get user token for %q failed", userStr.Username))
	}

	fileContent, err := GetFile(userStr.RepoOwner, userStr.RepoName, token.Token, K8SHELL_FILENAME, userStr.RepoRef)
	if err != nil {
		return useDefault(err, fmt.Sprintf("fetch %s from %s/%s failed", K8SHELL_FILENAME,
			userStr.RepoOwner, userStr.RepoName))
	}

	var k8shellFile models.K8shellFile
	if err := yaml.Unmarshal(fileContent, &k8shellFile); err != nil {
		return useDefault(err, fmt.Sprintf("parse %s in %s/%s failed", K8SHELL_FILENAME,
			userStr.RepoOwner, userStr.RepoName))
	}

	bp, valErrs := models.ValidateK8shellFile(k8shellFile)
	if len(valErrs) > 0 {
		return useDefault(fmt.Errorf("%v", valErrs), fmt.Sprintf("validate %s in %s/%s failed",
			K8SHELL_FILENAME, userStr.RepoOwner, userStr.RepoName))
	}

	bp.Name = userStr.Blueprint
	bp.Metadata.Name = userStr.Blueprint
	bp.Metadata.RepoName = userStr.RepoName
	bp.Metadata.RepoOwner = userStr.RepoOwner
	bp.Metadata.RepoAddress = GITHUB_ADDRESS
	return bp, nil
}

func contains(slice []string, value string) bool {
	for _, v := range slice {
		if v == value {
			return true
		}
	}
	return false
}

func deepCopyBlueprint(src *models.CustomBlueprint) (*models.CustomBlueprint, error) {
	if src == nil {
		return nil, nil
	}

	data, err := json.Marshal(src)
	if err != nil {
		return nil, err
	}

	var dst models.CustomBlueprint
	err = json.Unmarshal(data, &dst)
	if err != nil {
		return nil, err
	}

	return &dst, nil
}
