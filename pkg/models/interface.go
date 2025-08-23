package models

import (
	common "github.com/k8shell-io/common/models"
	"golang.org/x/crypto/ssh"
)

type IdentityProvider interface {
	Name() string
	UserMaxAge() int

	FindUser(username string) (*common.User, error)
	OnboardCapability(username string) (*common.OnboardCapability, error)
	OnboardUserDeviceFlow(username string) (*common.OnboardUser, error)
	AuthPublicKey(user *common.User, key ssh.PublicKey) (bool, error)
	GetUserToken(user *common.User) (*common.UserToken, error)
}
