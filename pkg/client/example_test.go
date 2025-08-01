package client_test

import (
	"context"
	"fmt"
	"log"
	"testing"
	"time"

	"github.com/k8shell-io/identity/pkg/client"
	"github.com/k8shell-io/identity/pkg/models"
)

// TestExample demonstrates how to use the Identity API client.
// This test requires a running identity service and will be skipped in automated testing.
func TestExample(t *testing.T) {
	// Skip this test unless explicitly requested
	if testing.Short() {
		t.Skip("Skipping example test in short mode")
	}
	// Create a new client
	c := client.New(client.Config{
		BaseURL: "http://localhost:9090",
		APIKey:  "6f16982b35ac2168f86c7978b7b42967538939b063598346139e0963510c",
		Timeout: 30 * time.Second,
	})

	ctx := context.Background()

	// List users
	users, err := c.ListUsers(ctx, 10, 0)
	if err != nil {
		log.Fatalf("Failed to list users: %v", err)
	}
	fmt.Printf("Found %d users\n", len(users))

	if len(users) > 0 {
		username := users[0].Username

		// Get a specific user
		user, err := c.GetUser(ctx, username)
		if err != nil {
			log.Fatalf("Failed to get user: %v", err)
		}
		fmt.Printf("User: %s (%s)\n", user.Username, user.Fullname)

		// Check onboarding capability
		capability, err := c.GetOnboardCapability(ctx, username)
		if err != nil {
			log.Fatalf("Failed to get onboard capability: %v", err)
		}
		fmt.Printf("User %s can onboard: %t\n", username, capability.CanOnboard)

		// Authenticate user (example public key)
		publicKey := "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ..."
		authResp, err := c.AuthenticateUser(ctx, username, publicKey)
		if err != nil {
			log.Fatalf("Failed to authenticate user: %v", err)
		}
		fmt.Printf("User %s authenticated: %t\n", username, authResp.Authenticated)

		// Create SSH session
		session, err := c.CreateSSHSession(ctx, username, "workspace1", "proxy123", 1234, "192.168.1.100")
		if err != nil {
			log.Fatalf("Failed to create SSH session: %v", err)
		}
		fmt.Printf("Created SSH session %d for user %s\n", session.SessionID, username)

		// Update SSH session
		channels := []models.ChannelShort{models.ChannelShortSh, models.ChannelShortPt}
		err = c.UpdateSSHSession(ctx, username, session.SessionID, 1024, 2048, "ssh-client", 0.5, channels)
		if err != nil {
			log.Fatalf("Failed to update SSH session: %v", err)
		}
		fmt.Printf("Updated SSH session %d\n", session.SessionID)

		// Get SSH session
		updatedSession, err := c.GetSSHSession(ctx, username, session.SessionID)
		if err != nil {
			log.Fatalf("Failed to get SSH session: %v", err)
		}
		fmt.Printf("SSH session %d has %d bytes in, %d bytes out\n",
			updatedSession.SessionID, updatedSession.BytesIn, updatedSession.BytesOut)

		// List SSH sessions
		sessions, err := c.ListSSHSessions(ctx, username, 10, 0, false)
		if err != nil {
			log.Fatalf("Failed to list SSH sessions: %v", err)
		}
		fmt.Printf("User %s has %d SSH sessions\n", username, len(sessions))

		// End SSH session
		err = c.EndSSHSession(ctx, username, session.SessionID)
		if err != nil {
			log.Fatalf("Failed to end SSH session: %v", err)
		}
		fmt.Printf("Ended SSH session %d\n", session.SessionID)

		// Get user token (if supported)
		token, err := c.GetUserToken(ctx, username)
		if err != nil {
			// This might fail if the provider doesn't support tokens
			fmt.Printf("Failed to get user token (might not be supported): %v\n", err)
		} else {
			fmt.Printf("Got token for user %s from provider %s\n", token.Username, token.Provider)
		}
	}
}

// Example shows basic usage of the Identity client.
func Example() {
	// Create a new client
	c := client.New(client.Config{
		BaseURL: "http://localhost:9090",
		APIKey:  "your-api-key-here",
		Timeout: 30 * time.Second,
	})

	ctx := context.Background()

	// List users
	users, err := c.ListUsers(ctx, 10, 0)
	if err != nil {
		log.Printf("Failed to list users: %v", err)
		return
	}

	fmt.Printf("Found %d users", len(users))
	// Output: Found 0 users
}
