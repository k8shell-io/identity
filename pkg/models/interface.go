package models

import (
	"golang.org/x/crypto/ssh"
)

type OnboardUser struct {
	Provider        string `json:"provider"`
	Username        string `json:"username"`
	UserCode        string `json:"user_code"`
	VerificationUrl string `json:"verification_url"`
	ExpiresIn       int    `json:"expires_in"`
}

type OnBoardCapability struct {
	Provider   string `json:"provider"`
	Username   string `json:"username"`
	CanOnboard bool   `json:"can_onboard"`
}

type RepoInfo struct {
	Name  string `json:"name"`
	Owner struct {
		Login string `json:"login"`
	} `json:"owner"`
}

type IdentityProvider interface {
	Name() string
	UserMaxAge() int

	FindUser(username string) (*User, error)
	OnboardCapability(username string) (*OnBoardCapability, error)
	OnboardUserDeviceFlow(username string) (*OnboardUser, error)
	AuthPublicKey(user *User, key ssh.PublicKey) (bool, error)
	GetRepositories(username string) ([]RepoInfo, error)
}
