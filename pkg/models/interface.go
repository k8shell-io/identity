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

type UserToken struct {
	Provider string `json:"provider"`
	Address  string `json:"address"`
	Username string `json:"username"`
	Token    string `json:"token"`
}

type IdentityProvider interface {
	Name() string
	UserMaxAge() int

	FindUser(username string) (*User, error)
	OnboardCapability(username string) (*OnBoardCapability, error)
	OnboardUserDeviceFlow(username string) (*OnboardUser, error)
	AuthPublicKey(user *User, key ssh.PublicKey) (bool, error)
	GetUserToken(user *User) (*UserToken, error)
}
