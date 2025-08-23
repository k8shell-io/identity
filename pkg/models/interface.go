package models

import (
	"github.com/k8shell-io/common/models"
	"golang.org/x/crypto/ssh"
)

type IdentityProvider interface {
	Name() string
	UserMaxAge() int

	FindUser(username string) (*models.User, error)
	OnboardCapability(username string) (*models.OnboardCapability, error)
	OnboardUserDeviceFlow(username string) (*models.OnboardUser, error)
	AuthPublicKey(username string, key ssh.PublicKey) (bool, error)
	GetUserToken(username string) (*models.UserToken, error)
	GetCustomBlueprint(userStr *models.UserStr) (*models.CustomBlueprint, error)
}
