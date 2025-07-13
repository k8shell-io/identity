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

type IdentityProvider interface {
	Name() string
	UserMaxAge() int

	FindUser(username string) (*User, error)
	CanOnboardUser(username string) (bool, error)
	OnboardUserDeviceFlow(username string) (*OnboardUser, error)
	AuthPublicKey(user *User, key ssh.PublicKey) (bool, error)
}
