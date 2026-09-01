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
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	commonv1 "github.com/k8shell-io/common/pkg/api/gen/go/common/v1"
	identityv1 "github.com/k8shell-io/common/pkg/api/gen/go/identity/v1"
	"github.com/k8shell-io/common/pkg/gapi"
	logger "github.com/k8shell-io/common/pkg/logger"
	"github.com/k8shell-io/common/pkg/models"
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
	users        map[string]*fileUser
	mutex        sync.RWMutex
	name         string
	capabilities []string
	userMaxAge   uint32
	address      string
}

// fileUser extends the shared user model with SSH public keys loaded from
// the user file. auth_keys is no longer part of models.User/common.v1.User
// (auth keys are now managed as a first-class concept via
// ListUserAuthKeys/AddUserAuthKeys/RemoveUserAuthKeys), so the file provider
// keeps them locally instead.
type fileUser struct {
	models.User `yaml:",inline"`
	AuthKeys    []string `yaml:"authKeys" json:"authKeys"`
}

// UserFile represents the schema of a user file.
type UserFile struct {
	// Users contains users loaded from the file.
	Users []fileUser `json:"users"`
}

// NewFileUserProvider creates a new FileUserProvider and loads users from the configured files.
func NewFileUserProvider(cfg FileUserProviderConfig, baseDir string) (*FileUserProvider, error) {
	provider := &FileUserProvider{
		config:       cfg,
		users:        make(map[string]*fileUser),
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

func (f *FileUserProvider) OnboardUserCapability(ctx context.Context, in *identityv1.Username,
	opts ...grpc.CallOption) (*commonv1.UserOnboardCapability, error) {
	return nil, status.Errorf(codes.Unimplemented, "file user provider does not support onboarding via device flow")
}

// resolveFileTags walks a yaml.Node tree and handles !file-tagged scalar nodes
// on the "password" and "authKeys" fields. Any other use of !file returns an
// error. "password" is replaced with the scalar file content. "authKeys" is
// replaced with a YAML sequence (one entry per non-empty, non-comment line)
// so it always decodes correctly into []string. Relative paths are resolved
// against baseDir.
func resolveFileTags(node *yaml.Node, baseDir string) error {
	if node.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(node.Content); i += 2 {
			key := node.Content[i].Value
			val := node.Content[i+1]
			if val.Tag == "!file" && val.Kind == yaml.ScalarNode {
				switch key {
				case "password":
					if err := resolveFileTagScalar(val, baseDir); err != nil {
						return err
					}
				case "authKeys":
					if err := resolveFileTagSequence(val, baseDir); err != nil {
						return err
					}
				default:
					return fmt.Errorf("!file tag is not allowed on field %q", key)
				}
			} else {
				if err := resolveFileTags(val, baseDir); err != nil {
					return err
				}
			}
		}
		return nil
	}

	for _, child := range node.Content {
		if err := resolveFileTags(child, baseDir); err != nil {
			return err
		}
	}
	return nil
}

// resolveFileTagScalar replaces a !file-tagged node with the trimmed file
// content as a plain scalar string (used for the "password" field).
func resolveFileTagScalar(node *yaml.Node, baseDir string) error {
	path := node.Value
	if !filepath.IsAbs(path) {
		path = filepath.Join(baseDir, path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("!file: read '%s': %w", path, err)
	}
	node.Tag = "!!str"
	node.Value = strings.TrimRight(string(data), "\r\n")
	return nil
}

// resolveFileTagSequence replaces a !file-tagged node with a YAML sequence
// where each non-empty, non-comment line of the file becomes one element
// (used for the "authKeys" field so it always decodes into []string).
func resolveFileTagSequence(node *yaml.Node, baseDir string) error {
	path := node.Value
	if !filepath.IsAbs(path) {
		path = filepath.Join(baseDir, path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("!file: read '%s': %w", path, err)
	}
	content := strings.TrimRight(string(data), "\r\n")
	node.Kind = yaml.SequenceNode
	node.Tag = "!!seq"
	node.Value = ""
	node.Content = nil
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		node.Content = append(node.Content, &yaml.Node{
			Kind:  yaml.ScalarNode,
			Tag:   "!!str",
			Value: line,
		})
	}
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

		data, err := os.ReadFile(filename)
		if err != nil {
			return fmt.Errorf("read user file '%s': %w", filename, err)
		}

		var doc yaml.Node
		if err := yaml.Unmarshal(data, &doc); err != nil {
			return fmt.Errorf("unmarshal user file '%s': %w", filename, err)
		}

		if doc.Kind == yaml.DocumentNode && len(doc.Content) > 0 {
			if err := resolveFileTags(doc.Content[0], filepath.Dir(filename)); err != nil {
				return fmt.Errorf("resolve !file tags in '%s': %w", filename, err)
			}
		}

		var userFile UserFile
		if err := doc.Decode(&userFile); err != nil {
			return fmt.Errorf("decode user file '%s': %w", filename, err)
		}

		for i := range userFile.Users {
			u := &userFile.Users[i]
			f.log.Debug().Msgf("Loaded user '%s' from file '%s'", u.Username, filename)
			if f.users[u.Username] != nil {
				f.log.Warn().Msgf("duplicate user '%s' found in file '%s', ignoring duplicate", u.Username, filename)
			} else {
				f.users[u.Username] = u
				f.users[u.Username].Source = FILE_PROVIDER_NAME
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
		user := u.User
		users = append(users, &user)
	}
	return users
}

// ProviderInfo returns provider metadata and capabilities.
func (f *FileUserProvider) ProviderInfo(ctx context.Context, in *identityv1.ProviderInfoRequest,
	opts ...grpc.CallOption) (*identityv1.ProviderInfoResponse, error) {
	return &identityv1.ProviderInfoResponse{
		Name:         FILE_PROVIDER_NAME,
		Capabilities: []string{"find_user", "auth_public_key"},
		UserMaxAge:   0,
		Address:      "",
	}, nil
}

// FindUser returns a user by username, re-evaluated as an onboarding decision.
// The file-backed provider has no onboarding rules of its own, so it always
// allows an existing file-defined user.
func (f *FileUserProvider) FindUser(ctx context.Context, in *identityv1.FindUserRequest,
	opts ...grpc.CallOption) (*commonv1.UserResult, error) {
	f.mutex.RLock()
	defer f.mutex.RUnlock()

	user, exists := f.users[in.Username]
	if !exists {
		return nil, nil
	}

	roles := make([]string, len(user.Roles))
	for i, r := range user.Roles {
		roles[i] = string(r)
	}
	sudo := user.Sudo

	return gapi.UserResultToProto(&models.UserResult{
		OnboardRule: models.OnboardUserRule{
			Username: user.Username,
			Fullname: user.Fullname,
			Email:    user.Email,
			Sudo:     &sudo,
			Action:   models.OnboardActionAllow,
			Roles:    roles,
		},
		ManageRepos: user.ManageRepos,
		GitAddress:  user.GitAddress,
	}), nil
}

// OnboardCapability reports onboarding capability for the user.
func (f *FileUserProvider) OnboardCapability(ctx context.Context, in *identityv1.Username,
	opts ...grpc.CallOption) (*commonv1.UserOnboardCapability, error) {
	return nil, status.Errorf(codes.Unimplemented, "file user provider does not support onboarding via device flow")
}

// OnboardUserDeviceFlow starts device-flow onboarding for the user.
func (f *FileUserProvider) OnboardUserDeviceFlow(ctx context.Context, in *identityv1.OnboardUserDeviceFlowRequest,
	opts ...grpc.CallOption) (*commonv1.OnboardUserDeviceFlow, error) {
	return nil, status.Errorf(codes.Unimplemented, "file user provider does not support onboarding via device flow")
}

// AuthUserPublicKey authenticates a user by SSH public key.
func (f *FileUserProvider) AuthUserPublicKey(ctx context.Context, in *identityv1.AuthUserPublicKeyRequest,
	opts ...grpc.CallOption) (*identityv1.AuthUserResponse, error) {
	f.mutex.RLock()
	user, exists := f.users[in.Username]
	f.mutex.RUnlock()
	if !exists {
		return nil, nil
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

	providedKeyStr := strings.TrimSpace(in.PublicKey)
	providedKeyStr = strings.ReplaceAll(providedKeyStr, "\\n", "\n")
	for _, line := range strings.Split(providedKeyStr, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			providedKeyStr = line
			break
		}
	}

	sshKey, _, _, rest, err := ssh.ParseAuthorizedKey([]byte(providedKeyStr))
	if err != nil || len(bytes.TrimSpace(rest)) > 0 {
		if err == nil {
			err = fmt.Errorf("unexpected trailing data")
		}
		return nil, status.Errorf(codes.InvalidArgument, "failed to parse provided public key: %v", err)
	}

	provided := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshKey)))
	for _, k := range keys {
		if k == provided {
			return &identityv1.AuthUserResponse{Valid: true}, nil
		}
	}

	return &identityv1.AuthUserResponse{Valid: false}, nil
}

// GetUserGitToken returns a git provider token for the user.
func (f *FileUserProvider) GetUserGitToken(ctx context.Context, in *identityv1.Username,
	opts ...grpc.CallOption) (*identityv1.UserToken, error) {
	return nil, status.Errorf(codes.Unimplemented, "file user provider does not support git tokens")
}

// ListUserAuthKeys is not supported by the file-backed provider.
func (f *FileUserProvider) ListUserAuthKeys(ctx context.Context, in *identityv1.Username,
	opts ...grpc.CallOption) (*identityv1.ListUserAuthKeysResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "file user provider does not support listing auth keys")
}

// GetBlueprintByUserStr returns a blueprint for the provided user string.
func (f *FileUserProvider) GetBlueprintByUserStr(ctx context.Context, in *identityv1.UserStr,
	opts ...grpc.CallOption) (*identityv1.Blueprint, error) {
	return nil, status.Errorf(codes.Unimplemented, "file user provider does not support custom blueprints")
}

// ResolvePullRequestToRef resolves a pull request to a repository reference.
func (f *FileUserProvider) ResolvePullRequestToRef(ctx context.Context, in *identityv1.RepoPullRequestRequest,
	opts ...grpc.CallOption) (*identityv1.RepoRefResponse, error) {
	return nil, status.Errorf(codes.Unimplemented,
		"file user provider does not support resolving pull requests to refs")
}

// ListRepoOwners is not supported by the file-backed provider: it has no
// upstream account to enumerate repository owners from.
func (f *FileUserProvider) ListRepoOwners(ctx context.Context, in *identityv1.Username,
	opts ...grpc.CallOption) (*identityv1.RepoOwnerList, error) {
	return nil, status.Errorf(codes.Unimplemented, "file user provider does not support listing repo owners")
}

// ListRepos is not supported by the file-backed provider.
func (f *FileUserProvider) ListRepos(ctx context.Context, in *identityv1.ListReposRequest,
	opts ...grpc.CallOption) (*identityv1.RepoList, error) {
	return nil, status.Errorf(codes.Unimplemented, "file user provider does not support listing repos")
}

// GetVersionInfo is not supported by the file-backed provider: it is an
// in-process provider, not a separately built and versioned service.
func (f *FileUserProvider) GetVersionInfo(ctx context.Context, in *commonv1.GetVersionInfoRequest,
	opts ...grpc.CallOption) (*commonv1.GetVersionInfoResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "file user provider does not report version info")
}

// CompleteUserWebFlow completes web-flow onboarding and returns the user.
func (f *FileUserProvider) CompleteUserWebFlow(ctx context.Context, in *identityv1.CompleteUserWebFlowRequest,
	opts ...grpc.CallOption) (*commonv1.UserResult, error) {
	return nil, status.Errorf(codes.Unimplemented,
		"file user provider does not support onboarding via web flow")
}

// OnboardUserWebFlow starts web-flow onboarding for the user.
func (f *FileUserProvider) OnboardUserWebFlow(ctx context.Context, in *identityv1.OnboardUserWebFlowRequest,
	opts ...grpc.CallOption) (*commonv1.OnboardUserWebFlow, error) {
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
