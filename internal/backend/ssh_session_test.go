package backend_test

import (
	"strconv"
	"testing"
	"time"

	"github.com/k8shell-io/identity/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSSHSessionCRUDLifecycle(t *testing.T) {
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

	user := &models.User{
		Username:     "user1",
		IsValid:      true,
		ExpiresAt:    time.Now().Add(24 * time.Hour),
		UID:          1000,
		GID:          1000,
		Fullname:     "User1",
		AccessToken:  "token1",
		Email:        "user1@test.com",
		Password:     "password1",
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
	err = db.CreateUser(user)
	require.NoError(t, err)

	var firstSession *models.SSHSession
	for i := 0; i < 5; i++ {
		username := "user1"
		workspace := "workspace" + strconv.Itoa(i)
		proxyID := "proxy" + strconv.Itoa(i)
		proxyPID := 1000 + i
		clientIP := "192.168.1." + strconv.Itoa(i)
		s, err := db.CreateSSHSession(username, workspace, proxyID, proxyPID, clientIP)
		if i == 0 {
			firstSession = s
		}
		require.NoError(t, err)
	}

	s, err := db.FindSSHSession(firstSession.SessionID)
	require.NoError(t, err)
	assert.Equal(t, firstSession.SessionID, s.SessionID)
	assert.Equal(t, firstSession.Username, s.Username)
	assert.Equal(t, firstSession.Workspace, s.Workspace)
	assert.Equal(t, firstSession.ProxyID, s.ProxyID)
	assert.Equal(t, firstSession.ProxyPID, s.ProxyPID)
	assert.Equal(t, firstSession.ClientIP, s.ClientIP)

	// Update the session end time
	err = db.UpdateSSHSessionBytes(firstSession.SessionID, 1000, 2000)
	require.NoError(t, err)

	s, err = db.FindSSHSession(firstSession.SessionID)
	require.NoError(t, err)
	assert.Equal(t, int64(1000), s.BytesIn)
	assert.Equal(t, int64(2000), s.BytesOut)

	err = db.EndSSHSession(firstSession.SessionID)
	require.NoError(t, err)
	s, err = db.FindSSHSession(firstSession.SessionID)
	require.NoError(t, err)
	assert.NotNil(t, s.EndTime)
}
