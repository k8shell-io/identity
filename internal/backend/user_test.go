package backend_test

import (
	"strconv"
	"testing"
	"time"

	"github.com/k8shell-io/identity/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUserCRUDLifecycle(t *testing.T) {
	pool, reconstrce, err := createDBResource()
	require.NoError(t, err)
	defer func() {
		err := pool.Purge(reconstrce)
		assert.NoError(t, err)
	}()
	db, err := getDB(pool, reconstrce)
	if err != nil {
		t.Fatalf("Failed to get DB: %v", err)
	}
	defer db.Close()

	var firstUser *models.User
	for i := 0; i < 5; i++ {
		idstr := strconv.Itoa(i)
		user := &models.User{
			Username:     "user" + idstr,
			IsValid:      true,
			ExpiresAt:    time.Now().Add(24 * time.Hour),
			UID:          1000 + uint32(i),
			GID:          1000 + uint32(i),
			Fullname:     "User " + idstr,
			AccessToken:  "token" + idstr,
			Email:        "user" + idstr + "@test.com",
			Password:     "password" + idstr,
			Locked:       false,
			FailedLogins: 0,
			Auths:        []models.AuthMethod{"auth1"},
			AuthKeys:     []string{"key1"},
			Channels:     []models.Channel{"channel1"},
			Envs:         []string{"env1"},
			Roles:        []models.Role{"user"},
			Blueprints:   []string{"blueprint1"},
			Source:       "test",
		}
		if i == 0 {
			firstUser = user
		}
		err = db.CreateUser(user)
		require.NoError(t, err)
	}

	users, err := db.ListUsers(10, 0)
	require.NoError(t, err)
	assert.Len(t, users, 5)

	// Verify the first user is in the list
	foundUser := users[0]
	assert.NotNil(t, foundUser)
	require.NoError(t, err)
	assert.NotNil(t, foundUser)
	assert.Equal(t, firstUser.Username, foundUser.Username)
	assert.Equal(t, firstUser.Fullname, foundUser.Fullname)
	assert.Equal(t, firstUser.UID, foundUser.UID)
	assert.Equal(t, firstUser.GID, foundUser.GID)
	assert.Equal(t, firstUser.Email, foundUser.Email)
	assert.Equal(t, firstUser.AccessToken, foundUser.AccessToken)
	assert.NotNil(t, foundUser.ExpiresAt)
	assert.True(t, foundUser.IsValid)
	assert.Equal(t, firstUser.Auths, foundUser.Auths)
	assert.Equal(t, firstUser.AuthKeys, foundUser.AuthKeys)
	assert.Equal(t, firstUser.Channels, foundUser.Channels)
	assert.Equal(t, firstUser.Envs, foundUser.Envs)
	assert.Equal(t, firstUser.Roles, foundUser.Roles)
	assert.Equal(t, firstUser.Blueprints, foundUser.Blueprints)
	assert.Equal(t, firstUser.Source, foundUser.Source)
	assert.Equal(t, firstUser.Locked, foundUser.Locked)
	assert.Equal(t, firstUser.FailedLogins, foundUser.FailedLogins)
	assert.WithinDuration(t, firstUser.ExpiresAt, foundUser.ExpiresAt, time.Millisecond)

	// Update the user
	firstUser.IsValid = false
	firstUser.ExpiresAt = time.Now().Add(48 * time.Hour)
	firstUser.UID = 2000
	firstUser.GID = 2000
	firstUser.Fullname = "Updated User"
	firstUser.AccessToken = "updated_token"
	firstUser.Email = "test@test.com"
	firstUser.Password = "updated_password"
	firstUser.Locked = true
	firstUser.FailedLogins = 1
	firstUser.Auths = []models.AuthMethod{"auth2"}
	firstUser.AuthKeys = []string{"key2"}
	firstUser.Channels = []models.Channel{"channel2"}
	firstUser.Envs = []string{"env2"}
	firstUser.Roles = []models.Role{"admin"}
	firstUser.Blueprints = []string{"blueprint2"}
	firstUser.Source = "test_updated"
	err = db.UpdateUser(firstUser)
	require.NoError(t, err)

	updatedUser, err := db.FindUser(firstUser.Username)
	require.NoError(t, err)
	assert.NotNil(t, updatedUser)
	assert.Equal(t, firstUser.Username, updatedUser.Username)
	assert.Equal(t, firstUser.Fullname, updatedUser.Fullname)
	assert.Equal(t, firstUser.UID, updatedUser.UID)
	assert.Equal(t, firstUser.GID, updatedUser.GID)
	assert.Equal(t, firstUser.Email, updatedUser.Email)
	assert.Equal(t, firstUser.AccessToken, updatedUser.AccessToken)
	assert.NotNil(t, updatedUser.ExpiresAt)
	assert.False(t, updatedUser.IsValid)
	assert.Equal(t, firstUser.Auths, updatedUser.Auths)
	assert.Equal(t, firstUser.AuthKeys, updatedUser.AuthKeys)
	assert.Equal(t, firstUser.Channels, updatedUser.Channels)
	assert.Equal(t, firstUser.Envs, updatedUser.Envs)
	assert.Equal(t, firstUser.Roles, updatedUser.Roles)
	assert.Equal(t, firstUser.Blueprints, updatedUser.Blueprints)
	assert.Equal(t, firstUser.Source, updatedUser.Source)
	assert.Equal(t, firstUser.Locked, updatedUser.Locked)
	assert.Equal(t, firstUser.FailedLogins, updatedUser.FailedLogins)
	assert.WithinDuration(t, firstUser.ExpiresAt, updatedUser.ExpiresAt, time.Millisecond)

	// Delete the user
	err = db.DeleteUser(foundUser.Username)
	require.NoError(t, err)

	// Verify the user is deleted
	_, err = db.FindUser(foundUser.Username)
	require.Error(t, err)
	assert.Equal(t, models.ErrUserNotFound, err)

	// Verify the user is not in the list
	users, err = db.ListUsers(10, 0)
	require.NoError(t, err)
	assert.Len(t, users, 4)

	// Verify the deleted user is not in the list
	for _, u := range users {
		assert.NotEqual(t, foundUser.Username, u.Username)
	}
}
