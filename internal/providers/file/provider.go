// Copyright 2025 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Package file implements a file-backed identity provider for k8Shell.
// It implements the idp gRPC interface and provides user data loaded from local YAML files.
// The provider supports user lookup by username and SSH public key authentication, but does
// not support onboarding or token management. This provider is intended for simple use cases
// and testing, and should not be used in production environments.
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
	"github.com/k8shell-io/identity/pkg/api/idppb"
	"github.com/k8shell-io/identity/pkg/api/typespb"
	"github.com/rs/zerolog"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gopkg.in/yaml.v3"
)

// FILE_PROVIDER_NAME is the canonical provider name for the file-backed identity provider.
const FILE_PROVIDER_NAME = "idp.k8shell.io/file"

// FileUserProviderConfig configures the file-backed identity provider.
type FileUserProviderConfig struct {
	// Enabled indicates whether the file-backed provider is enabled.
	Enabled bool `yaml:"enabled"`

	// Files lists user definition files to load.
	Files []string `yaml:"files"`
}

// FileUserProvider implements an identity provider backed by local user files.
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

// UserFile represents the schema of a user file.
type UserFile struct {
	// Users contains users loaded from the file.
	Users []models.User `json:"users"`
}

// NewFileUserProvider creates a new FileUserProvider and loads users from the configured files.
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

// Name returns the provider name.
func (f *FileUserProvider) Name() string { return f.name }

// Capabilities returns the capabilities supported by the provider.
func (f *FileUserProvider) Capabilities() []string { return f.capabilities }

// UserMaxAge returns the maximum age for cached user data in seconds.
func (f *FileUserProvider) UserMaxAge() uint32 { return f.userMaxAge }

// Address returns the provider address.
func (f *FileUserProvider) Address() string { return f.address }

// Close releases provider resources.
func (f *FileUserProvider) Close() error {
	return nil
}

// load reads configured user files and populates the in-memory user map.
func (f *FileUserProvider) load(baseDir string) error {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	for _, filename := range f.config.Files {
		if !filepath.IsAbs(filename) {
			filename = filepath.Join(baseDir, filename)
		}

		f.log.Debug().Msgf("Loading user file '%s'", filename)

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
			f.log.Debug().Msgf("Loaded user '%s' from file '%s'", u.Username, filename)
			if f.users[u.Username] != nil {
				f.log.Warn().Msgf("duplicate user '%s' found in file '%s', ignoring duplicate", u.Username, filename)
			} else {
				f.users[u.Username] = u
			}
		}
	}

	return nil
}

// GetUsers returns all users loaded by the provider.
func (f *FileUserProvider) GetUsers() []*models.User {
	f.mutex.RLock()
	defer f.mutex.RUnlock()

	var users []*models.User
	for _, u := range f.users {
		users = append(users, u)
	}
	return users
}

// ProviderInfo returns provider metadata and capabilities.
func (f *FileUserProvider) ProviderInfo(ctx context.Context, in *idppb.ProviderInfoRequest,
	opts ...grpc.CallOption) (*idppb.ProviderInfoResponse, error) {
	return &idppb.ProviderInfoResponse{
		Name:         FILE_PROVIDER_NAME,
		Capabilities: []string{"find_user", "auth_public_key"},
		UserMaxAge:   0,
		Address:      "",
	}, nil
}

// FindUser returns a user by username.
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

// OnboardCapability reports onboarding capability for the user.
func (f *FileUserProvider) OnboardCapability(ctx context.Context, in *typespb.Username,
	opts ...grpc.CallOption) (*commonpb.UserOnboardCapability, error) {
	return nil, status.Errorf(codes.Unimplemented, "file user provider does not support onboarding via device flow")
}

// OnboardUserDeviceFlow starts device-flow onboarding for the user.
func (f *FileUserProvider) OnboardUserDeviceFlow(ctx context.Context, in *typespb.Username,
	opts ...grpc.CallOption) (*commonpb.OnboardUserDeviceFlow, error) {
	return nil, status.Errorf(codes.Unimplemented, "file user provider does not support onboarding via device flow")
}

// AuthUserPublicKey authenticates a user by SSH public key.
func (f *FileUserProvider) AuthUserPublicKey(ctx context.Context, in *typespb.AuthUserPublicKeyRequest,
	opts ...grpc.CallOption) (*typespb.AuthUserResponse, error) {
	user, err := f.FindUser(ctx, &typespb.FindUserRequest{Username: in.Username})
	if err != nil {
		return nil, err
	}

	f.log.Debug().Msgf("Authenticating user '%s' via public key", in.Username)

	var authKeys string
	for _, k := range user.AuthKeys {
		authKeys += k + "\n"
	}

	keys, _, err := parseKeys(authKeys)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to parse keys for user %s: %v", user.Username, err)
	}

	f.log.Debug().Msgf("Parsed %d valid keys and %d ignored entries for user '%s'",
		len(keys), len(user.AuthKeys)-len(keys), user.Username)

	sshKey, err := ssh.ParsePublicKey([]byte(in.PublicKey))
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to parse provided public key: %v", err)
	}

	provided := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshKey)))
	for _, k := range keys {
		f.log.Debug().Msgf("Comparing provided key '%s' with user key '%s'", provided, k)
		if k == provided {
			return &typespb.AuthUserResponse{Valid: true}, nil
		}
	}

	return &typespb.AuthUserResponse{Valid: false}, nil
}

// GetUserToken returns a provider token for the user.
func (f *FileUserProvider) GetUserToken(ctx context.Context, in *typespb.Username,
	opts ...grpc.CallOption) (*idppb.UserToken, error) {
	return nil, status.Errorf(codes.Unimplemented, "file user provider does not support user tokens")
}

// GetBlueprintByUserStr returns a blueprint for the provided user string.
func (f *FileUserProvider) GetBlueprintByUserStr(ctx context.Context, in *typespb.UserStr,
	opts ...grpc.CallOption) (*typespb.Blueprint, error) {
	return nil, status.Errorf(codes.Unimplemented, "file user provider does not support custom blueprints")
}

// ResolvePullRequestToRef resolves a pull request to a repository reference.
func (f *FileUserProvider) ResolvePullRequestToRef(ctx context.Context, in *typespb.RepoPullRequestRequest,
	opts ...grpc.CallOption) (*typespb.RepoRefResponse, error) {
	return nil, status.Errorf(codes.Unimplemented,
		"file user provider does not support resolving pull requests to refs")
}

// CompleteUserWebFlow completes web-flow onboarding and returns the user.
func (f *FileUserProvider) CompleteUserWebFlow(ctx context.Context, in *typespb.CompleteUserWebFlowRequest,
	opts ...grpc.CallOption) (*commonpb.User, error) {
	return nil, status.Errorf(codes.Unimplemented,
		"file user provider does not support onboarding via web flow")
}

// OnboardUserWebFlow starts web-flow onboarding for the user.
func (f *FileUserProvider) OnboardUserWebFlow(ctx context.Context, in *typespb.OnboardUserWebFlowRequest,
	opts ...grpc.CallOption) (*commonpb.OnboardUserWebFlow, error) {
	return nil, status.Errorf(codes.Unimplemented,
		"file user provider does not support onboarding via web flow")
}

// parseKeyList parses a list of SSH public keys, returning valid keys and any ignored entries.
func parseKeyList(keys []string) ([]string, []string, error) {
	var valid []string
	var ignored []string

	for _, line := range keys {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		_, _, _, rest, err := ssh.ParseAuthorizedKey([]byte(line))
		if err != nil || len(rest) > 0 {
			ignored = append(ignored, line)
			continue
		}
		key, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(line))
		valid = append(valid, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))))
	}
	return valid, ignored, nil
}

// parseKeys parses SSH public keys from a string, returning valid keys and any ignored entries.
func parseKeys(content string) ([]string, []string, error) {
	lines := strings.Split(content, "\n")
	return parseKeyList(lines)
}
