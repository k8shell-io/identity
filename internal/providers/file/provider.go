package file

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/k8shell-io/common/pkg/models"
	"github.com/k8shell-io/identity/internal/common"
	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"
)

type FileUserProviderConfig struct {
	ID       string `yaml:"id"`
	Filename string `yaml:"filename"`
}

type FileUserProvider struct {
	config FileUserProviderConfig
	users  map[string]*models.User
	mutex  sync.RWMutex
}

type UserFile struct {
	Users []models.User `json:"users"`
}

func NewFileUserProvider(cfg FileUserProviderConfig, baseDir string) (*FileUserProvider, error) {
	provider := &FileUserProvider{
		config: cfg,
		users:  make(map[string]*models.User),
		mutex:  sync.RWMutex{},
	}
	err := provider.load(baseDir)
	if err != nil {
		return nil, err
	}

	return provider, nil
}

func (f *FileUserProvider) load(baseDir string) error {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	filename := f.config.Filename
	if !filepath.IsAbs(filename) {
		filename = filepath.Join(baseDir, filename)
	}

	var userFile UserFile
	data, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("read user file '%s': %w", filename, err)
	}

	if err := yaml.Unmarshal(data, &userFile); err != nil {
		return fmt.Errorf("unmarshal user file '%s': %w", filename, err)
	}

	for i := range userFile.Users {
		u := &userFile.Users[i]
		f.users[u.Username] = u
	}

	return nil
}

func (f *FileUserProvider) Name() string {
	return "file"
}

func (f *FileUserProvider) UserMaxAge() int {
	return 0
}

func (f *FileUserProvider) FindUser(username string) (*models.User, error) {
	f.mutex.RLock()
	defer f.mutex.RUnlock()

	user, exists := f.users[username]
	if !exists {
		return nil, nil
	}
	user.Source = f.Name()
	return user, nil
}

func (p *FileUserProvider) AuthPublicKey(username string, key ssh.PublicKey) (bool, error) {
	user, err := p.FindUser(username)
	if err != nil {
		return false, err
	}

	var authKeys string
	for _, k := range user.AuthKeys {
		authKeys += k + "\n"
	}

	keys, _, err := common.ParseKeys(authKeys)
	if err != nil {
		return false, fmt.Errorf("failed to parse keys for user %s: %w", user.Username, err)
	}

	provided := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
	for _, k := range keys {
		if k == provided {
			return true, nil
		}
	}

	return false, nil
}

func (f *FileUserProvider) OnboardCapability(username string) (*models.OnboardCapability, error) {
	// File user provider does not support onboarding via device code
	return nil, fmt.Errorf("%w: file user provider does not support onboarding via device flow",
		models.ErrMethodNotSupported)
}

func (p *FileUserProvider) OnboardUserDeviceFlow(username string) (*models.OnboardUserDeviceFlow, error) {
	// File user provider does not support onboarding via device code
	return nil, fmt.Errorf("%w: file user provider does not support onboarding via device flow",
		models.ErrMethodNotSupported)
}

func (f *FileUserProvider) GetUserToken(username string) (*models.UserToken, error) {
	// File user provider does not support user tokens
	return nil, fmt.Errorf("%w: file user provider does not support user tokens", models.ErrMethodNotSupported)
}

func (p *FileUserProvider) GetCustomBlueprint(userStr *models.UserStr) (*models.CustomBlueprint, error) {
	return nil, fmt.Errorf("%w: file user provider does not support custom blueprints", models.ErrMethodNotSupported)
}

func (f *FileUserProvider) OnboardUserWebFlow(redirectUri string) (*models.OnboardUserWebFlow, error) {
	return nil, fmt.Errorf("%w: file user provider does not support onboarding via web flow",
		models.ErrMethodNotSupported)
}

func (f *FileUserProvider) CompleteUserWebFlow(state string, code string) (*models.User, error) {
	return nil, fmt.Errorf("%w: file user provider does not support onboarding via web flow",
		models.ErrMethodNotSupported)
}
