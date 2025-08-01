package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/k8shell-io/identity/pkg/models"
)

func TestClient_ListUsers(t *testing.T) {
	// Mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check authorization header
		if r.Header.Get("Authorization") != "Bearer test-api-key" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Check method and path
		if r.Method != http.MethodGet || r.URL.Path != "/api/v1/users" {
			http.Error(w, "Not found", http.StatusNotFound)
			return
		}

		// Check query parameters
		limit := r.URL.Query().Get("limit")
		offset := r.URL.Query().Get("offset")

		if limit != "10" || offset != "5" {
			http.Error(w, "Invalid parameters", http.StatusBadRequest)
			return
		}

		// Return mock users
		users := []models.User{
			{Username: "user1", Fullname: "User One", IsValid: true, UID: 1001},
			{Username: "user2", Fullname: "User Two", IsValid: true, UID: 1002},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(users)
	}))
	defer server.Close()

	// Create client
	client := New(Config{
		BaseURL: server.URL,
		APIKey:  "test-api-key",
		Timeout: 5 * time.Second,
	})

	// Test
	users, err := client.ListUsers(context.Background(), 10, 5)
	if err != nil {
		t.Fatalf("ListUsers failed: %v", err)
	}

	if len(users) != 2 {
		t.Fatalf("Expected 2 users, got %d", len(users))
	}

	if users[0].Username != "user1" {
		t.Errorf("Expected username 'user1', got '%s'", users[0].Username)
	}
}

func TestClient_GetUser(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-api-key" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		if r.Method != http.MethodGet || r.URL.Path != "/api/v1/users/testuser" {
			http.Error(w, "Not found", http.StatusNotFound)
			return
		}

		user := models.User{
			Username: "testuser",
			Fullname: "Test User",
			Email:    "test@example.com",
			IsValid:  true,
			UID:      1001,
			GID:      1001,
			Roles:    []models.Role{models.RoleWorkspaceUser},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(user)
	}))
	defer server.Close()

	client := New(Config{
		BaseURL: server.URL,
		APIKey:  "test-api-key",
	})

	user, err := client.GetUser(context.Background(), "testuser")
	if err != nil {
		t.Fatalf("GetUser failed: %v", err)
	}

	if user.Username != "testuser" {
		t.Errorf("Expected username 'testuser', got '%s'", user.Username)
	}

	if user.Email != "test@example.com" {
		t.Errorf("Expected email 'test@example.com', got '%s'", user.Email)
	}
}

func TestClient_AuthenticateUser(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-api-key" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/users/testuser/authenticate" {
			http.Error(w, "Not found", http.StatusNotFound)
			return
		}

		var req models.AuthenticateUserRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		if req.PublicKey == "" {
			http.Error(w, "Public key required", http.StatusBadRequest)
			return
		}

		resp := models.AuthenticateUserResponse{
			Authenticated: true,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := New(Config{
		BaseURL: server.URL,
		APIKey:  "test-api-key",
	})

	resp, err := client.AuthenticateUser(context.Background(), "testuser", "ssh-rsa AAAAB3NzaC1yc2E...")
	if err != nil {
		t.Fatalf("AuthenticateUser failed: %v", err)
	}

	if !resp.Authenticated {
		t.Error("Expected user to be authenticated")
	}
}

func TestClient_CreateSSHSession(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-api-key" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/users/testuser/sessions" {
			http.Error(w, "Not found", http.StatusNotFound)
			return
		}

		var req models.CreateSSHSessionRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		if req.Workspace == "" || req.ProxyID == "" {
			http.Error(w, "Missing required fields", http.StatusBadRequest)
			return
		}

		now := time.Now()
		session := models.SSHSession{
			SessionID: 123,
			Username:  "testuser",
			ProxyID:   req.ProxyID,
			ProxyPID:  req.ProxyPID,
			ClientIP:  req.ClientIP,
			StartTime: &now,
			Workspace: req.Workspace,
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Location", "/api/v1/users/testuser/sessions/123")
		json.NewEncoder(w).Encode(session)
	}))
	defer server.Close()

	client := New(Config{
		BaseURL: server.URL,
		APIKey:  "test-api-key",
	})

	session, err := client.CreateSSHSession(context.Background(), "testuser", "workspace1", "proxy123", 1234, "192.168.1.100")
	if err != nil {
		t.Fatalf("CreateSSHSession failed: %v", err)
	}

	if session.SessionID != 123 {
		t.Errorf("Expected session ID 123, got %d", session.SessionID)
	}

	if session.Username != "testuser" {
		t.Errorf("Expected username 'testuser', got '%s'", session.Username)
	}

	if session.Workspace != "workspace1" {
		t.Errorf("Expected workspace 'workspace1', got '%s'", session.Workspace)
	}
}

func TestClient_UpdateSSHSession(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-api-key" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		if r.Method != http.MethodPatch || r.URL.Path != "/api/v1/users/testuser/sessions/123" {
			http.Error(w, "Not found", http.StatusNotFound)
			return
		}

		var req models.UpdateSSHSessionRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		if req.BytesIn != 1024 || req.BytesOut != 2048 {
			http.Error(w, "Invalid bytes", http.StatusBadRequest)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client := New(Config{
		BaseURL: server.URL,
		APIKey:  "test-api-key",
	})

	channels := []models.ChannelShort{models.ChannelShortSh, models.ChannelShortPt}
	err := client.UpdateSSHSession(context.Background(), "testuser", 123, 1024, 2048, "ssh-client", 0.5, channels)
	if err != nil {
		t.Fatalf("UpdateSSHSession failed: %v", err)
	}
}

func TestClient_EndSSHSession(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-api-key" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/users/testuser/sessions/123/end" {
			http.Error(w, "Not found", http.StatusNotFound)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client := New(Config{
		BaseURL: server.URL,
		APIKey:  "test-api-key",
	})

	err := client.EndSSHSession(context.Background(), "testuser", 123)
	if err != nil {
		t.Fatalf("EndSSHSession failed: %v", err)
	}
}

func TestClient_ErrorResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]any{
			"status": 404,
			"msg":    "User not found",
		})
	}))
	defer server.Close()

	client := New(Config{
		BaseURL: server.URL,
		APIKey:  "test-api-key",
	})

	_, err := client.GetUser(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("Expected error for non-existent user")
	}

	errorResp, ok := err.(ErrorResponse)
	if !ok {
		t.Fatalf("Expected ErrorResponse, got %T", err)
	}

	if errorResp.Status != 404 {
		t.Errorf("Expected status 404, got %d", errorResp.Status)
	}

	if errorResp.Msg != "User not found" {
		t.Errorf("Expected message 'User not found', got '%s'", errorResp.Msg)
	}
}

func TestClient_Unauthorized(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Unauthorized: invalid API key", http.StatusUnauthorized)
	}))
	defer server.Close()

	client := New(Config{
		BaseURL: server.URL,
		APIKey:  "invalid-key",
	})

	_, err := client.ListUsers(context.Background(), 10, 0)
	if err == nil {
		t.Fatal("Expected error for invalid API key")
	}

	if err.Error() != "HTTP 401: Unauthorized: invalid API key" {
		t.Errorf("Unexpected error message: %v", err)
	}
}
