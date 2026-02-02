package file

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/k8shell-io/common/pkg/gapi"
	"github.com/k8shell-io/common/pkg/gapi/commonpb"
	logger "github.com/k8shell-io/common/pkg/logger"
	"github.com/k8shell-io/common/pkg/models"
	"github.com/k8shell-io/identity/internal/common"
	"github.com/k8shell-io/identity/pkg/api/idppb"
	"github.com/k8shell-io/identity/pkg/api/typespb"
	"github.com/rs/zerolog"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gopkg.in/yaml.v3"
)

const FILE_PROVIDER_NAME = "idp.k8shell.io/file"

type FileUserProviderConfig struct {
	Enabled bool     `yaml:"enabled"`
	Files   []string `yaml:"files"`
}

type FileUserProvider struct {
	config       FileUserProviderConfig
	log          *zerolog.Logger
	users        map[string]*models.User
	mutex        sync.RWMutex
	name         string
	capabilities []string
	userMaxAge   uint32
	address      string
}

type UserFile struct {
	Users []models.User `json:"users"`
}

func NewFileUserProvider(cfg FileUserProviderConfig, baseDir string) (*FileUserProvider, error) {
	provider := &FileUserProvider{
		config:       cfg,
		users:        make(map[string]*models.User),
		mutex:        sync.RWMutex{},
		log:          logger.NewLogger("file-provider"),
		name:         FILE_PROVIDER_NAME,
		capabilities: []string{"find_user", "auth_public_key"},
		userMaxAge:   0,
		address:      "",
	}
	err := provider.load(baseDir)
	if err != nil {
		return nil, err
	}

	return provider, nil
}

func (f *FileUserProvider) Name() string           { return f.name }
func (f *FileUserProvider) Capabilities() []string { return f.capabilities }
func (f *FileUserProvider) UserMaxAge() uint32     { return f.userMaxAge }
func (f *FileUserProvider) Address() string        { return f.address }

func (f *FileUserProvider) Close() error {
	return nil
}

func (f *FileUserProvider) load(baseDir string) error {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	for _, filename := range f.config.Files {
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
			if f.users[u.Username] != nil {
				f.log.Warn().Msgf("duplicate user '%s' found in file '%s', ignoring duplicate", u.Username, filename)
			} else {
				f.users[u.Username] = u
			}
		}
	}

	return nil
}

func (f *FileUserProvider) ProviderInfo(ctx context.Context, in *idppb.ProviderInfoRequest,
	opts ...grpc.CallOption) (*idppb.ProviderInfoResponse, error) {
	return &idppb.ProviderInfoResponse{
		Name:         FILE_PROVIDER_NAME,
		Capabilities: []string{"find_user", "auth_public_key"},
		UserMaxAge:   0,
		Address:      "",
	}, nil
}

func (f *FileUserProvider) FindUser(ctx context.Context, in *typespb.FindUserRequest,
	opts ...grpc.CallOption) (*commonpb.User, error) {
	f.mutex.RLock()
	defer f.mutex.RUnlock()

	user, exists := f.users[in.Username]
	if !exists {
		return nil, nil
	}
	user.Source = FILE_PROVIDER_NAME
	return gapi.UserToProto(user), nil
}

func (f *FileUserProvider) OnboardCapability(ctx context.Context, in *typespb.Username,
	opts ...grpc.CallOption) (*commonpb.UserOnboardCapability, error) {
	return nil, status.Errorf(codes.Unimplemented, "file user provider does not support onboarding via device flow")
}

func (f *FileUserProvider) OnboardUserDeviceFlow(ctx context.Context, in *typespb.Username,
	opts ...grpc.CallOption) (*commonpb.OnboardUserDeviceFlow, error) {
	return nil, status.Errorf(codes.Unimplemented, "file user provider does not support onboarding via device flow")
}

func (f *FileUserProvider) AuthUserPublicKey(ctx context.Context, in *typespb.AuthUserPublicKeyRequest,
	opts ...grpc.CallOption) (*typespb.AuthUserResponse, error) {
	user, err := f.FindUser(ctx, &typespb.FindUserRequest{Username: in.Username})
	if err != nil {
		return nil, err
	}

	var authKeys string
	for _, k := range user.AuthKeys {
		authKeys += k + "\n"
	}

	keys, _, err := common.ParseKeys(authKeys)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to parse keys for user %s: %v", user.Username, err)
	}

	sshKey, err := ssh.ParsePublicKey([]byte(in.PublicKey))
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to parse provided public key: %v", err)
	}

	provided := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshKey)))
	for _, k := range keys {
		if k == provided {
			return &typespb.AuthUserResponse{Valid: true}, nil
		}
	}

	return &typespb.AuthUserResponse{Valid: false}, nil
}

func (f *FileUserProvider) GetUserToken(ctx context.Context, in *typespb.Username,
	opts ...grpc.CallOption) (*idppb.UserToken, error) {
	return nil, status.Errorf(codes.Unimplemented, "file user provider does not support user tokens")
}

func (f *FileUserProvider) GetBlueprintByUserStr(ctx context.Context, in *typespb.UserStr,
	opts ...grpc.CallOption) (*typespb.Blueprint, error) {
	return nil, status.Errorf(codes.Unimplemented, "file user provider does not support custom blueprints")
}

func (f *FileUserProvider) ResolvePullRequestToRef(ctx context.Context, in *typespb.RepoPullRequestRequest,
	opts ...grpc.CallOption) (*typespb.RepoRefResponse, error) {
	return nil, status.Errorf(codes.Unimplemented,
		"file user provider does not support resolving pull requests to refs")
}

func (f *FileUserProvider) CompleteUserWebFlow(ctx context.Context, in *typespb.CompleteUserWebFlowRequest,
	opts ...grpc.CallOption) (*commonpb.User, error) {
	return nil, status.Errorf(codes.Unimplemented,
		"file user provider does not support onboarding via web flow")
}

func (f *FileUserProvider) OnboardUserWebFlow(ctx context.Context, in *typespb.OnboardUserWebFlowRequest,
	opts ...grpc.CallOption) (*commonpb.OnboardUserWebFlow, error) {
	return nil, status.Errorf(codes.Unimplemented,
		"file user provider does not support onboarding via web flow")
}

// func (f *FileUserProvider) Name() string {
// 	return "file"
// }

// func (f *FileUserProvider) UserMaxAge() int {
// 	return 0
// }

// func (p *FileUserProvider) AuthPublicKey(username string, key ssh.PublicKey) (bool, error) {
// 	user, err := p.FindUser(username)
// 	if err != nil {
// 		return false, err
// 	}

// 	var authKeys string
// 	for _, k := range user.AuthKeys {
// 		authKeys += k + "\n"
// 	}

// 	keys, _, err := common.ParseKeys(authKeys)
// 	if err != nil {
// 		return false, fmt.Errorf("failed to parse keys for user %s: %w", user.Username, err)
// 	}

// 	provided := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
// 	for _, k := range keys {
// 		if k == provided {
// 			return true, nil
// 		}
// 	}

// 	return false, nil
// }

// func (f *FileUserProvider) OnboardCapability(username string) (*models.OnboardCapability, error) {
// 	// File user provider does not support onboarding via device code
// 	return nil, fmt.Errorf("%w: file user provider does not support onboarding via device flow",
// 		models.ErrMethodNotSupported)
// }

// func (p *FileUserProvider) OnboardUserDeviceFlow(username string) (*models.OnboardUserDeviceFlow, error) {
// 	// File user provider does not support onboarding via device code
// 	return nil, fmt.Errorf("%w: file user provider does not support onboarding via device flow",
// 		models.ErrMethodNotSupported)
// }

// func (f *FileUserProvider) GetUserToken(username string) (*models.UserToken, error) {
// 	// File user provider does not support user tokens
// 	return nil, fmt.Errorf("%w: file user provider does not support user tokens", models.ErrMethodNotSupported)
// }

// func (p *FileUserProvider) GetCustomBlueprint(userStr *models.UserStr) (*models.CustomBlueprint, error) {
// 	return nil, fmt.Errorf("%w: file user provider does not support custom blueprints", models.ErrMethodNotSupported)
// }

// func (f *FileUserProvider) OnboardUserWebFlow(redirectUri string) (*models.OnboardUserWebFlow, error) {
// 	return nil, fmt.Errorf("%w: file user provider does not support onboarding via web flow",
// 		models.ErrMethodNotSupported)
// }

// func (f *FileUserProvider) CompleteUserWebFlow(state string, code string) (string, error) {
// 	return "", fmt.Errorf("%w: file user provider does not support onboarding via web flow",
// 		models.ErrMethodNotSupported)
// }

// func (f *FileUserProvider) ResolvePullRequestRef(username string, repoOwner, repoName string,
// 	pullRequestNumber int) (string, error) {
// 	return "", fmt.Errorf("%w: file user provider does not support resolving pull requests to refs",
// 		models.ErrMethodNotSupported)
// }
