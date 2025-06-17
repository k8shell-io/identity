package backend_test

import (
	"testing"
	"time"

	"github.com/k8shell-io/identity/internal/backend"
	"github.com/k8shell-io/identity/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProviderCRUDLifecycle(t *testing.T) {
	pool, reconstrce, err := createDBResource()
	require.NoError(t, err)
	defer func() {
		err := pool.Purge(reconstrce)
		assert.NoError(t, err)
	}()
	db, err := getDB(pool)
	if err != nil {
		t.Fatalf("Failed to get DB: %v", err)
	}
	defer db.Close()

	err = db.CreateUser(&models.User{
		Username:     "testuser",
		IsValid:      true,
		ExpiresAt:    time.Now().Add(24 * time.Hour),
		UID:          1001,
		GID:          1001,
		Fullname:     "Test User",
		AccessToken:  "testtoken",
		Email:        "test@test",
		Password:     "testpassword",
		Locked:       false,
		FailedLogins: 0,
		Auths:        []models.AuthMethod{"auth1"},
		AuthKeys:     []string{"key1"},
		Channels:     []models.Channel{"channel1"},
		Envs:         []string{"env1"},
		Roles:        []models.Role{"user"},
		Blueprints:   []string{"blueprint1"},
		Source:       "test",
	})
	require.NoError(t, err)

	db.CreateUserProviderInfo(&backend.ProviderInfo{
		Status:          "pending",
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
		Username:        "testuser",
		Provider:        "testprovider",
		UserCode:        "usercode123",
		DeviceCode:      "devicecode123",
		ExpiresAt:       nil,
		VerificationURI: "http://example.com/verify",
		AccessToken:     "accesstoken123",
		RefreshToken:    "refreshtoken123",
	})

	info, err := db.GetUserProviderInfo("testuser", "testprovider")
	require.NoError(t, err)
	assert.NotNil(t, info)
	assert.Equal(t, "pending", info.Status)
	assert.Equal(t, "testuser", info.Username)
	assert.Equal(t, "testprovider", info.Provider)
	assert.Equal(t, "usercode123", info.UserCode)
	assert.Equal(t, "devicecode123", info.DeviceCode)
	assert.Equal(t, "http://example.com/verify", info.VerificationURI)
	assert.Equal(t, "accesstoken123", info.AccessToken)
	assert.Equal(t, "refreshtoken123", info.RefreshToken)

	// Update the provider info
	err = db.UpdateUserProvider("testuser", "testprovider", "accesstoken1234", "", "ready")
	require.NoError(t, err)

	info, err = db.GetUserProviderInfo("testuser", "testprovider")
	require.NoError(t, err)
	assert.NotNil(t, info)
	assert.Equal(t, "ready", info.Status)
	assert.Equal(t, "accesstoken1234", info.AccessToken)
	assert.Equal(t, "", info.RefreshToken)
	assert.Equal(t, "testuser", info.Username)
	assert.Equal(t, "testprovider", info.Provider)

	// Update the provider status to pending
	err = db.UpdateUserProviderStatus("testuser", "testprovider", "pending")
	require.NoError(t, err)
	info, err = db.GetUserProviderInfo("testuser", "testprovider")
	require.NoError(t, err)
	assert.NotNil(t, info)
	assert.Equal(t, "pending", info.Status)

	// Update the provider status to error
	err = db.UpdateUserProviderStatus("testuser", "testprovider", "error")
	require.NoError(t, err)
	info, err = db.GetUserProviderInfo("testuser", "testprovider")
	require.NoError(t, err)
	assert.NotNil(t, info)
	assert.Equal(t, "error", info.Status)
	assert.Equal(t, "", info.UserCode)
	assert.Equal(t, "", info.DeviceCode)

	// Delete the provider info
	err = db.DeleteUserProviderInfo("testuser", "testprovider")
	require.NoError(t, err)

	// Verify that the provider info is deleted
	info, err = db.GetUserProviderInfo("testuser", "testprovider")
	if err != nil {
		t.Fatalf("Failed to get provider info: %v", err)
	}
	if info != nil {
		t.Errorf("Expected provider info to be nil after deletion, got: %+v", info)
	}

}
