package models

import (
	"errors"
	"fmt"
	"time"
)

const (
	ChannelSession      string = "session"
	ChannelShell        string = "shell"
	ChannelPty          string = "pty"
	ChannelPortForward  string = "port-forward"
	ChannelSFTP         string = "sftp"
	ChannelSCP          string = "scp"
	ChannelExec         string = "exec"
	ChannelForwardAgent string = "forward-agent"
	ChannelSystemExec   string = "system-exec"
)

const (
	ChannelShortSh string = "sh"
	ChannelShortPt string = "pt"
	ChannelShortPf string = "pf"
	ChannelShortSf string = "sf"
	ChannelShortSc string = "sc"
	ChannelShortEx string = "ex"
	ChannelShortAf string = "af"
	ChannelShortSe string = "se"
)

const (
	RoleAdmin          string = "admin"
	RoleOrgAdmin       string = "org-admin"
	RoleWorkspaceAdmin string = "workspace-admin"
	RoleWorkspaceUser  string = "workspace-user"
)

const (
	AuthMethodPublicKey string = "publickey"
	AuthMethodPassword  string = "password"
)

var ErrMethodNotSupported = errors.New("method not supported")
var ErrUserNotFound = errors.New("user not found")
var ErrActiveSessionNotFound = errors.New("active session not found")
var ErrSessionNotFound = errors.New("session not found")
var ErrUserNotOnboarded = errors.New("user not onboarded")
var ErrUserIsNotValid = errors.New("user is not valid")
var ErrOnboardingPending = errors.New("onboarding pending")
var ErrAlreadyOnboarded = errors.New("user already onboarded")
var ErrUserNotAllowedOnboard = errors.New("user not allowed to onboard")
var ErrUserTokenNotSupported = errors.New("user token not supported by provider")

type User struct {
	Username     string    `yaml:"username"`
	Organization string    `yaml:"organization"`
	IsValid      bool      `yaml:"isValid"`
	ExpiresAt    time.Time `yaml:"expiresAt"`
	UID          uint32    `yaml:"uid"`
	GID          uint32    `yaml:"gid"`
	Fullname     string    `yaml:"fullname"`
	AccessToken  string    `yaml:"accessToken"`
	Email        string    `yaml:"email"`
	Password     string    `yaml:"password,omitempty"`
	Auths        []string  `yaml:"auths"`
	AuthKeys     []string  `yaml:"authKeys"`
	Locked       bool      `yaml:"locked"`
	FailedLogins int       `yaml:"failedLogins"`
	Channels     []string  `yaml:"channels"`
	Envs         []string  `yaml:"envs"`
	Roles        []string  `yaml:"roles"`
	Blueprints   []string  `yaml:"blueprints"`
	Source       string    `yaml:"source"`
}

type SSHSession struct {
	SessionID int32
	Username  string
	ProxyID   string
	ProxyPID  int
	Client    string
	ClientIP  string
	StartTime *time.Time
	EndTime   *time.Time
	Workspace string
	BytesIn   int64
	BytesOut  int64
	Channels  []string
	ProvTime  float32
}

func CreateSessionID(channel string, proxyID string, proxyPID int, channelNumber int) string {
	return fmt.Sprintf("%s-%s-%d-%d", channel, proxyID, proxyPID, channelNumber)
}

type Organization struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
}

// ProviderInfo holds information about a identity provider
type ProviderInfo struct {
	Status          string
	CreatedAt       time.Time
	UpdatedAt       time.Time
	Username        string
	Provider        string
	UserCode        string
	DeviceCode      string
	ExpiresAt       *time.Time
	VerificationURI string
	AccessToken     string
	RefreshToken    string
}

// API Request and Response Types

// AuthPublicKeyRequest represents the request body for user authentication
type AuthPublicKeyRequest struct {
	PublicKey string `json:"public_key"`
}

// AuthPublicKeyResponse represents the response body for user authentication
type AuthPublicKeyResponse struct {
	Authenticated bool `json:"authenticated"`
}

// CreateSSHSessionRequest represents the request body for creating an SSH session
type CreateSSHSessionRequest struct {
	Workspace string `json:"workspace"`
	ProxyID   string `json:"proxy_id"`
	ProxyPID  int    `json:"proxy_pid"`
	ClientIP  string `json:"client_ip"`
}

// UpdateSSHSessionRequest represents the request body for updating an SSH session
type UpdateSSHSessionRequest struct {
	BytesIn  int64    `json:"bytes_in"`
	BytesOut int64    `json:"bytes_out"`
	Client   string   `json:"client"`
	ProvTime float32  `json:"prov_time"`
	Channels []string `json:"channels"`
}
