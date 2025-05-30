package server

import (
	"errors"
	"fmt"
	"time"

	"github.com/k8shell-io/identity/pkg/models"
	"golang.org/x/crypto/ssh"
)

func (s *Server) refreshUser(username string, user *models.User) (*models.User, error) {
	var err error

	if user == nil || time.Now().After(user.ExpiresAt) {
		var foundUser *models.User
		for _, provider := range s.IdentityProviders {
			foundUser, err = provider.FindUser(username)
			if err != nil {
				s.log.Warn().Msgf("Error occurred while looking up user '%s' via provider '%s': %v", username, provider.Name(), err)
				continue
			}
			if foundUser != nil {
				expiresAt := time.Now().Add(time.Duration(provider.UserMaxAge()) * time.Second)
				foundUser.ExpiresAt = expiresAt
				if user != nil {
					user.ExpiresAt = expiresAt
				}
				break
			}
		}

		// create or update the user in the database
		if foundUser != nil && user == nil {
			// Create the new user if found in identity provider but not in DB
			err = s.DB.CreateUser(foundUser)
			if err != nil {
				return nil, fmt.Errorf("failed to create user '%s' in database: %w", username, err)
			}
			user = foundUser
		} else if foundUser != nil && user != nil {
			// Update existing user with new data from the identity provider
			err = s.DB.UpdateUser(foundUser)
			if err != nil {
				return nil, fmt.Errorf("failed to update user '%s' in database: %w", username, err)
			}
			user = foundUser
		} else if foundUser == nil && user != nil {
			// If user was not found in identity provider but it exists in the DB, mark as invalid
			user.IsValid = false
			err = s.DB.UpdateUser(user)
			if err != nil {
				return nil, fmt.Errorf("failed to mark user '%s' as invalid in database: %w", username, err)
			}
		} else {
			// No valid user was found
			user = nil
		}
	}
	return user, nil
}

func (s *Server) GetUser(username string) (*models.User, error) {
	user, err := s.DB.FindUser(username)
	if err != nil {
		return nil, fmt.Errorf("error occured when finding user '%s': %w", username, err)
	}

	// refresh user in the database
	user, err = s.refreshUser(username, user)
	if err != nil {
		return nil, fmt.Errorf("error occured when refreshing user '%s': %w", username, err)
	}
	return user, nil
}

func (s *Server) AuthenticateUser(username string, publicKey string) (bool, error) {
	user, err := s.DB.FindUser(username)
	if err != nil {
		return false, fmt.Errorf("error occured when finding user '%s': %w", username, err)
	}

	// refresh user in the database
	if user != nil {
		user, err = s.refreshUser(username, user)
		if err != nil {
			return false, fmt.Errorf("error occured when refreshing user '%s': %w", username, err)
		}
	}

	if user == nil || !user.IsValid {
		return false, nil
	}

	// authenticate the user with the public key using the identity providers
	for _, provider := range s.IdentityProviders {
		if provider.Name() == user.Source {
			parsedKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(publicKey))
			if err != nil {
				s.log.Warn().Msgf("Failed to parse provided public key for user '%s': %v", username, err)
				return false, nil
			}
			auth, err := provider.AuthPublicKey(user, parsedKey)
			if err != nil {
				return false, fmt.Errorf("error occurred while authenticating user '%s' with provider '%s': %w", username, provider.Name(), err)
			}
			return auth, nil
		}
	}

	return false, nil
}

func (s *Server) OnboardUser(username string) (*models.OnboardUser, error) {
	for _, provider := range s.IdentityProviders {
		onboardUser, err := provider.OnboardUserDeviceFlow(username)
		if err != nil && !errors.Is(err, models.ErrMethodNotSupported) {
			return nil, fmt.Errorf("error occurred while onboarding user '%s' with provider '%s': %w", username, provider.Name(), err)
		}
		if onboardUser != nil {
			return onboardUser, nil
		}
	}
	return nil, fmt.Errorf("no suitable identity provider found for onboarding user '%s'", username)
}
