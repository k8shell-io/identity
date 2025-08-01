package models

import (
	"errors"
	"fmt"
	"time"
)

type Channel string

const (
	ChannelShell        Channel = "shell"
	ChannelPty          Channel = "pty"
	ChannelPortForward  Channel = "port_forward"
	ChannelSFTP         Channel = "sftp"
	ChannelSCP          Channel = "scp"
	ChannelExec         Channel = "exec"
	ChannelForwardAgent Channel = "forward_agent"
	ChannelSystemExec   Channel = "system_exec"
)

type ChannelShort string

const (
	ChannelShortSh ChannelShort = "sh"
	ChannelShortPt ChannelShort = "pt"
	ChannelShortPf ChannelShort = "pf"
	ChannelShortSf ChannelShort = "sf"
	ChannelShortSc ChannelShort = "sc"
	ChannelShortEx ChannelShort = "ex"
	ChannelShortAf ChannelShort = "af"
	ChannelShortSe ChannelShort = "se"
)

type Role string

const (
	RoleAdmin          Role = "admin"
	RoleOrgAdmin       Role = "org-admin"
	RoleWorkspaceAdmin Role = "workspace-admin"
	RoleWorkspaceUser  Role = "workspace-user"
)

type AuthMethod string

const (
	AuthMethodPublicKey AuthMethod = "publickey"
	AuthMethodPassword  AuthMethod = "password"
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
	Username     string       `yaml:"username"`
	IsValid      bool         `yaml:"isValid"`
	ExpiresAt    time.Time    `yaml:"expiresAt"`
	UID          uint32       `yaml:"uid"`
	GID          uint32       `yaml:"gid"`
	Fullname     string       `yaml:"fullname"`
	AccessToken  string       `yaml:"accessToken"`
	Email        string       `yaml:"email"`
	Password     string       `yaml:"password,omitempty"`
	Auths        []AuthMethod `yaml:"auths"`
	AuthKeys     []string     `yaml:"authKeys"`
	Locked       bool         `yaml:"locked"`
	FailedLogins int          `yaml:"failedLogins"`
	Channels     []Channel    `yaml:"channels"`
	Envs         []string     `yaml:"envs"`
	Roles        []Role       `yaml:"roles"`
	Blueprints   []string     `yaml:"blueprints"`
	Source       string       `yaml:"source"`
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
	Channels  []ChannelShort
	ProvTime  float32
}

func CreateSessionID(channel ChannelShort, proxyID string, proxyPID int, channelNumber int) string {
	return fmt.Sprintf("%s-%s-%d-%d", channel, proxyID, proxyPID, channelNumber)
}

// API Request and Response Types

// AuthenticateUserRequest represents the request body for user authentication
type AuthenticateUserRequest struct {
	PublicKey string `json:"public_key"`
}

// AuthenticateUserResponse represents the response body for user authentication
type AuthenticateUserResponse struct {
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
