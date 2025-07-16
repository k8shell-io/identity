package usermap

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/k8shell-io/identity/internal/backend"
	"github.com/k8shell-io/identity/internal/common"
	"github.com/k8shell-io/identity/pkg/models"
	"github.com/k8shell-io/yaml-cel/pkg/yamlcel"
	"golang.org/x/crypto/ssh"
)

type UserMapProviderConfig struct {
	ID           string            `yaml:"id"`
	UserMaxAge   int               `yaml:"userMaxAge"`
	GrantType    string            `yaml:"grantType"`
	ClientId     string            `yaml:"clientId"`
	ClientSecret string            `yaml:"clientSecret"`
	TokenUrl     string            `yaml:"tokenUrl"`
	PeopleUrl    string            `yaml:"peopleUrl"`
	GitLabUrl    string            `yaml:"gitlabUrl"`
	Timeout      int               `yaml:"timeout"`
	Template     string            `yaml:"template"`
	ExtraFields  map[string]string `yaml:"extra,omitempty"`
	CacheTimeout int               `yaml:"cacheTimeout"`
}

type UserMapProvider struct {
	config     UserMapProviderConfig
	UsermapAPI *UsermapAPI
	template   *yamlcel.CELTemplate
}

func NewUserMapProvider(cfg UserMapProviderConfig, baseDir string, cacheCfg backend.CacheConfig) (*UserMapProvider, error) {
	template, err := yamlcel.NewTemplate(common.NormalizePath(cfg.Template, baseDir))
	if err != nil {
		return nil, fmt.Errorf("load user template '%s': %w", cfg.Template, err)
	}

	provider := &UserMapProvider{
		config:     cfg,
		UsermapAPI: NewUsermapAPI(cfg, cacheCfg, cfg.Timeout),
		template:   template,
	}

	return provider, nil
}

func (p *UserMapProvider) Name() string {
	return "usermap"
}

func (p *UserMapProvider) UserMaxAge() int {
	if p.config.UserMaxAge <= 0 {
		return 3600 // default to 1 hour if not set
	}
	return p.config.UserMaxAge
}

func (p *UserMapProvider) FindUser(username string) (*models.User, error) {
	// retrieve the user from the usermap API
	peopleResource, err := p.UsermapAPI.GetPeopleResource(username)
	if err != nil {
		return nil, fmt.Errorf("usermap lookup failed: %w", err)
	}
	if peopleResource == nil {
		return nil, nil
	}

	// evaluate the user template with the retrieved people resource
	resource, err := common.ToMap(peopleResource)
	if err != nil {
		return nil, fmt.Errorf("convert people resource to map: %w", err)
	}

	userObj, err := yamlcel.EvalToStruct[models.User](p.template, resource, p.config.ExtraFields, "user")
	if err != nil {
		return nil, fmt.Errorf("template evaluation failed: %w", err)
	}

	if !userObj.IsValid {
		return nil, nil
	}

	userObj.Source = p.Name()
	return userObj, nil
}

func (p *UserMapProvider) OnboardCapability(username string) (*models.OnBoardCapability, error) {
	// Usermap provider does not support onboarding via device code
	return nil, fmt.Errorf("%w: usermap provider does not support onboarding via device flow",
		models.ErrMethodNotSupported)
}

func (p *UserMapProvider) keysFromURL(username string) ([]string, []string, error) {
	if p.config.GitLabUrl == "" {
		return nil, nil, nil
	}

	client := &http.Client{
		Timeout: time.Duration(p.config.Timeout) * time.Millisecond,
	}

	url := fmt.Sprintf("%s/%s.keys", p.config.GitLabUrl, username)
	resp, err := client.Get(url)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to fetch keys for user %s: %w", username, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read response body: %w", err)
	}

	return common.ParseKeys(string(body))
}

func (p *UserMapProvider) AuthPublicKey(user *models.User, key ssh.PublicKey) (bool, error) {
	keys, _, err := p.keysFromURL(user.Username)
	if err != nil {
		return false, fmt.Errorf("failed to fetch keys for user %s: %w", user.Username, err)
	}

	provided := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
	for _, k := range keys {
		if k == provided {
			return true, nil
		}
	}

	return false, nil
}

func (p *UserMapProvider) OnboardUserDeviceFlow(username string) (*models.OnboardUser, error) {
	// Usermap provider does not support onboarding via device code
	return nil, fmt.Errorf("%w: usermap provider does not support onboarding via device flow",
		models.ErrMethodNotSupported)
}

func (p *UserMapProvider) GetRepositories(username string) ([]models.RepoInfo, error) {
	// Usermap provider does not support fetching repositories
	return nil, fmt.Errorf("%w: usermap provider does not support fetching repositories",
		models.ErrMethodNotSupported)
}
