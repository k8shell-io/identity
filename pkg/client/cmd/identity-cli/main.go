// Copyright 2025 the k8Shell authors

// Package main provides a simple CLI tool to demonstrate the Identity API client.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/k8shell-io/identity/pkg/client"
	"github.com/k8shell-io/identity/pkg/models"
)

func main() {
	var (
		baseURL  = flag.String("url", "http://localhost:8080", "Base URL of the identity service")
		apiKey   = flag.String("key", "", "API key for authentication")
		command  = flag.String("cmd", "list-users", "Command to run (list-users, get-user, auth-user, create-session, list-sessions)")
		username = flag.String("user", "", "Username for user-specific commands")
		publicKey = flag.String("pubkey", "", "Public key for authentication")
		workspace = flag.String("workspace", "", "Workspace for session creation")
		proxyID   = flag.String("proxy-id", "", "Proxy ID for session creation")
		proxyPID  = flag.Int("proxy-pid", 0, "Proxy PID for session creation")
		clientIP  = flag.String("client-ip", "", "Client IP for session creation")
		sessionID = flag.Int("session-id", 0, "Session ID for session-specific commands")
		limit     = flag.Int("limit", 10, "Limit for pagination")
		offset    = flag.Int("offset", 0, "Offset for pagination")
	)
	flag.Parse()

	if *apiKey == "" {
		if envKey := os.Getenv("IDENTITY_API_KEY"); envKey != "" {
			*apiKey = envKey
		} else {
			log.Fatal("API key is required (use -key flag or IDENTITY_API_KEY environment variable)")
		}
	}

	// Create client
	c := client.New(client.Config{
		BaseURL: *baseURL,
		APIKey:  *apiKey,
		Timeout: 30 * time.Second,
	})

	ctx := context.Background()

	switch *command {
	case "list-users":
		listUsers(ctx, c, *limit, *offset)
	case "get-user":
		if *username == "" {
			log.Fatal("Username is required for get-user command")
		}
		getUser(ctx, c, *username)
	case "auth-user":
		if *username == "" || *publicKey == "" {
			log.Fatal("Username and public key are required for auth-user command")
		}
		authenticateUser(ctx, c, *username, *publicKey)
	case "onboard-capability":
		if *username == "" {
			log.Fatal("Username is required for onboard-capability command")
		}
		getOnboardCapability(ctx, c, *username)
	case "onboard-user":
		if *username == "" {
			log.Fatal("Username is required for onboard-user command")
		}
		onboardUser(ctx, c, *username)
	case "get-token":
		if *username == "" {
			log.Fatal("Username is required for get-token command")
		}
		getUserToken(ctx, c, *username)
	case "create-session":
		if *username == "" || *workspace == "" || *proxyID == "" || *proxyPID == 0 || *clientIP == "" {
			log.Fatal("Username, workspace, proxy-id, proxy-pid, and client-ip are required for create-session command")
		}
		createSSHSession(ctx, c, *username, *workspace, *proxyID, *proxyPID, *clientIP)
	case "list-sessions":
		if *username == "" {
			log.Fatal("Username is required for list-sessions command")
		}
		listSSHSessions(ctx, c, *username, *limit, *offset)
	case "get-session":
		if *username == "" || *sessionID == 0 {
			log.Fatal("Username and session-id are required for get-session command")
		}
		getSSHSession(ctx, c, *username, int32(*sessionID))
	case "end-session":
		if *username == "" || *sessionID == 0 {
			log.Fatal("Username and session-id are required for end-session command")
		}
		endSSHSession(ctx, c, *username, int32(*sessionID))
	default:
		fmt.Printf("Unknown command: %s\n", *command)
		fmt.Println("Available commands: list-users, get-user, auth-user, onboard-capability, onboard-user, get-token, create-session, list-sessions, get-session, end-session")
		os.Exit(1)
	}
}

func listUsers(ctx context.Context, c *client.Client, limit, offset int) {
	users, err := c.ListUsers(ctx, limit, offset)
	if err != nil {
		log.Fatalf("Failed to list users: %v", err)
	}

	fmt.Printf("Found %d users:\n", len(users))
	for _, user := range users {
		fmt.Printf("  %s (%s) - Valid: %t, UID: %d, Roles: %v\n",
			user.Username, user.Fullname, user.IsValid, user.UID, user.Roles)
	}
}

func getUser(ctx context.Context, c *client.Client, username string) {
	user, err := c.GetUser(ctx, username)
	if err != nil {
		log.Fatalf("Failed to get user: %v", err)
	}

	fmt.Printf("User: %s\n", user.Username)
	fmt.Printf("  Full Name: %s\n", user.Fullname)
	fmt.Printf("  Email: %s\n", user.Email)
	fmt.Printf("  Valid: %t\n", user.IsValid)
	fmt.Printf("  UID: %d\n", user.UID)
	fmt.Printf("  GID: %d\n", user.GID)
	fmt.Printf("  Roles: %v\n", user.Roles)
	fmt.Printf("  Auth Methods: %v\n", user.Auths)
	fmt.Printf("  Channels: %v\n", user.Channels)
	fmt.Printf("  Source: %s\n", user.Source)
	if !user.ExpiresAt.IsZero() {
		fmt.Printf("  Expires At: %s\n", user.ExpiresAt.Format(time.RFC3339))
	}
}

func authenticateUser(ctx context.Context, c *client.Client, username, publicKey string) {
	resp, err := c.AuthenticateUser(ctx, username, publicKey)
	if err != nil {
		log.Fatalf("Failed to authenticate user: %v", err)
	}

	fmt.Printf("User %s authenticated: %t\n", username, resp.Authenticated)
}

func getOnboardCapability(ctx context.Context, c *client.Client, username string) {
	capability, err := c.GetOnboardCapability(ctx, username)
	if err != nil {
		log.Fatalf("Failed to get onboard capability: %v", err)
	}

	fmt.Printf("Onboard capability for %s:\n", username)
	fmt.Printf("  Provider: %s\n", capability.Provider)
	fmt.Printf("  Can Onboard: %t\n", capability.CanOnboard)
}

func onboardUser(ctx context.Context, c *client.Client, username string) {
	onboardUser, err := c.OnboardUser(ctx, username)
	if err != nil {
		log.Fatalf("Failed to onboard user: %v", err)
	}

	fmt.Printf("Onboarding initiated for %s:\n", username)
	fmt.Printf("  Provider: %s\n", onboardUser.Provider)
	fmt.Printf("  User Code: %s\n", onboardUser.UserCode)
	fmt.Printf("  Verification URL: %s\n", onboardUser.VerificationUrl)
	fmt.Printf("  Expires In: %d seconds\n", onboardUser.ExpiresIn)
}

func getUserToken(ctx context.Context, c *client.Client, username string) {
	token, err := c.GetUserToken(ctx, username)
	if err != nil {
		log.Fatalf("Failed to get user token: %v", err)
	}

	fmt.Printf("User token for %s:\n", username)
	fmt.Printf("  Provider: %s\n", token.Provider)
	fmt.Printf("  Address: %s\n", token.Address)
	fmt.Printf("  Token: %s\n", token.Token)
}

func createSSHSession(ctx context.Context, c *client.Client, username, workspace, proxyID string, proxyPID int, clientIP string) {
	session, err := c.CreateSSHSession(ctx, username, workspace, proxyID, proxyPID, clientIP)
	if err != nil {
		log.Fatalf("Failed to create SSH session: %v", err)
	}

	fmt.Printf("Created SSH session:\n")
	fmt.Printf("  Session ID: %d\n", session.SessionID)
	fmt.Printf("  Username: %s\n", session.Username)
	fmt.Printf("  Workspace: %s\n", session.Workspace)
	fmt.Printf("  Proxy ID: %s\n", session.ProxyID)
	fmt.Printf("  Proxy PID: %d\n", session.ProxyPID)
	fmt.Printf("  Client IP: %s\n", session.ClientIP)
	if session.StartTime != nil {
		fmt.Printf("  Start Time: %s\n", session.StartTime.Format(time.RFC3339))
	}
}

func listSSHSessions(ctx context.Context, c *client.Client, username string, limit, offset int) {
	sessions, err := c.ListSSHSessions(ctx, username, limit, offset, false)
	if err != nil {
		log.Fatalf("Failed to list SSH sessions: %v", err)
	}

	fmt.Printf("Found %d SSH sessions for %s:\n", len(sessions), username)
	for _, session := range sessions {
		fmt.Printf("  Session %d: %s -> %s", session.SessionID, session.Workspace, session.ClientIP)
		if session.StartTime != nil {
			fmt.Printf(" (started: %s)", session.StartTime.Format("2006-01-02 15:04:05"))
		}
		if session.EndTime != nil {
			fmt.Printf(" (ended: %s)", session.EndTime.Format("2006-01-02 15:04:05"))
		}
		fmt.Printf(" [%d bytes in, %d bytes out]\n", session.BytesIn, session.BytesOut)
	}
}

func getSSHSession(ctx context.Context, c *client.Client, username string, sessionID int32) {
	session, err := c.GetSSHSession(ctx, username, sessionID)
	if err != nil {
		log.Fatalf("Failed to get SSH session: %v", err)
	}

	fmt.Printf("SSH Session %d:\n", session.SessionID)
	fmt.Printf("  Username: %s\n", session.Username)
	fmt.Printf("  Workspace: %s\n", session.Workspace)
	fmt.Printf("  Proxy ID: %s\n", session.ProxyID)
	fmt.Printf("  Proxy PID: %d\n", session.ProxyPID)
	fmt.Printf("  Client: %s\n", session.Client)
	fmt.Printf("  Client IP: %s\n", session.ClientIP)
	fmt.Printf("  Bytes In: %d\n", session.BytesIn)
	fmt.Printf("  Bytes Out: %d\n", session.BytesOut)
	fmt.Printf("  Channels: %v\n", session.Channels)
	fmt.Printf("  Prov Time: %.2f\n", session.ProvTime)
	if session.StartTime != nil {
		fmt.Printf("  Start Time: %s\n", session.StartTime.Format(time.RFC3339))
	}
	if session.EndTime != nil {
		fmt.Printf("  End Time: %s\n", session.EndTime.Format(time.RFC3339))
	}
}

func endSSHSession(ctx context.Context, c *client.Client, username string, sessionID int32) {
	err := c.EndSSHSession(ctx, username, sessionID)
	if err != nil {
		log.Fatalf("Failed to end SSH session: %v", err)
	}

	fmt.Printf("SSH session %d for user %s has been ended\n", sessionID, username)
}
