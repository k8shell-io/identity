// Copyright 2025 the k8Shell authors

package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/k8shell-io/identity/pkg/models"
)

// Client represents a client for the K8Shell Identity REST API.
type Client struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
}

// Config represents the configuration for the Identity API client.
type Config struct {
	BaseURL    string        // Base URL of the identity service (e.g., "http://localhost:8080")
	APIKey     string        // API key for authentication
	Timeout    time.Duration // HTTP client timeout (default: 30 seconds)
	HTTPClient *http.Client  // Custom HTTP client (optional)
}

// ErrorResponse represents an error response from the API.
type ErrorResponse struct {
	Status int    `json:"status"`
	Msg    string `json:"msg"`
}

// Error implements the error interface for ErrorResponse.
func (e ErrorResponse) Error() string {
	return fmt.Sprintf("API error %d: %s", e.Status, e.Msg)
}

// New creates a new Identity API client with the given configuration.
func New(config Config) *Client {
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}

	httpClient := config.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{
			Timeout: config.Timeout,
		}
	}

	return &Client{
		baseURL:    config.BaseURL,
		apiKey:     config.APIKey,
		httpClient: httpClient,
	}
}

// doRequest performs an HTTP request and handles the response.
func (c *Client) doRequest(ctx context.Context, method, path string, body interface{}, result interface{}) error {
	var reqBody io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("failed to marshal request body: %w", err)
		}
		reqBody = bytes.NewReader(jsonBody)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reqBody)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode >= 400 {
		var errResp ErrorResponse
		if err := json.Unmarshal(respBody, &errResp); err != nil {
			return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
		}
		return errResp
	}

	if resp.StatusCode == http.StatusNoContent {
		return nil
	}

	if result != nil {
		if err := json.Unmarshal(respBody, result); err != nil {
			return fmt.Errorf("failed to unmarshal response: %w", err)
		}
	}

	return nil
}

// Users API

// ListUsers retrieves a paginated list of users.
func (c *Client) ListUsers(ctx context.Context, limit, offset int) ([]models.User, error) {
	params := url.Values{}
	if limit > 0 {
		params.Set("limit", strconv.Itoa(limit))
	}
	if offset > 0 {
		params.Set("offset", strconv.Itoa(offset))
	}

	path := "/api/v1/users"
	if len(params) > 0 {
		path += "?" + params.Encode()
	}

	var users []models.User
	err := c.doRequest(ctx, http.MethodGet, path, nil, &users)
	return users, err
}

// GetUser retrieves a user by their username.
func (c *Client) GetUser(ctx context.Context, username string) (*models.User, error) {
	path := fmt.Sprintf("/api/v1/users/%s", url.PathEscape(username))

	var user models.User
	err := c.doRequest(ctx, http.MethodGet, path, nil, &user)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// AuthenticateUser validates a user's SSH public key.
func (c *Client) AuthenticateUser(ctx context.Context, username, publicKey string) (*models.AuthenticateUserResponse, error) {
	path := fmt.Sprintf("/api/v1/users/%s/authenticate", url.PathEscape(username))
	req := models.AuthenticateUserRequest{PublicKey: publicKey}

	var resp models.AuthenticateUserResponse
	err := c.doRequest(ctx, http.MethodPost, path, req, &resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// OnboardUser initiates the Device Authorization Flow to onboard a user.
func (c *Client) OnboardUser(ctx context.Context, username string) (*models.OnboardUser, error) {
	path := fmt.Sprintf("/api/v1/users/%s/onboard", url.PathEscape(username))

	var onboardUser models.OnboardUser
	err := c.doRequest(ctx, http.MethodPost, path, nil, &onboardUser)
	if err != nil {
		return nil, err
	}
	return &onboardUser, nil
}

// GetOnboardCapability checks if a user can be onboarded.
func (c *Client) GetOnboardCapability(ctx context.Context, username string) (*models.OnBoardCapability, error) {
	path := fmt.Sprintf("/api/v1/users/%s/onboardcap", url.PathEscape(username))

	var capability models.OnBoardCapability
	err := c.doRequest(ctx, http.MethodGet, path, nil, &capability)
	if err != nil {
		return nil, err
	}
	return &capability, nil
}

// GetUserToken retrieves a user token for the specified username.
func (c *Client) GetUserToken(ctx context.Context, username string) (*models.UserToken, error) {
	path := fmt.Sprintf("/api/v1/users/%s/token", url.PathEscape(username))

	var token models.UserToken
	err := c.doRequest(ctx, http.MethodGet, path, nil, &token)
	if err != nil {
		return nil, err
	}
	return &token, nil
}

// SSH Sessions API

// ListSSHSessions retrieves a paginated list of SSH sessions for a user.
func (c *Client) ListSSHSessions(ctx context.Context, username string, limit, offset int, reverse bool) ([]models.SSHSession, error) {
	params := url.Values{}
	if limit > 0 {
		params.Set("limit", strconv.Itoa(limit))
	}
	if offset > 0 {
		params.Set("offset", strconv.Itoa(offset))
	}
	if reverse {
		params.Set("reverse", "true")
	}

	path := fmt.Sprintf("/api/v1/users/%s/sessions", url.PathEscape(username))
	if len(params) > 0 {
		path += "?" + params.Encode()
	}

	var sessions []models.SSHSession
	err := c.doRequest(ctx, http.MethodGet, path, nil, &sessions)
	return sessions, err
}

// GetSSHSession retrieves a specific SSH session by its ID for a user.
func (c *Client) GetSSHSession(ctx context.Context, username string, sessionID int32) (*models.SSHSession, error) {
	path := fmt.Sprintf("/api/v1/users/%s/sessions/%d", url.PathEscape(username), sessionID)

	var session models.SSHSession
	err := c.doRequest(ctx, http.MethodGet, path, nil, &session)
	if err != nil {
		return nil, err
	}
	return &session, nil
}

// CreateSSHSession creates a new SSH session for a user in a specified workspace.
func (c *Client) CreateSSHSession(ctx context.Context, username, workspace, proxyID string, proxyPID int, clientIP string) (*models.SSHSession, error) {
	path := fmt.Sprintf("/api/v1/users/%s/sessions", url.PathEscape(username))
	req := models.CreateSSHSessionRequest{
		Workspace: workspace,
		ProxyID:   proxyID,
		ProxyPID:  proxyPID,
		ClientIP:  clientIP,
	}

	var session models.SSHSession
	err := c.doRequest(ctx, http.MethodPost, path, req, &session)
	if err != nil {
		return nil, err
	}
	return &session, nil
}

// UpdateSSHSession updates an existing SSH session with new data.
func (c *Client) UpdateSSHSession(ctx context.Context, username string, sessionID int32, bytesIn, bytesOut int64, client string, provTime float32, channels []models.ChannelShort) error {
	path := fmt.Sprintf("/api/v1/users/%s/sessions/%d", url.PathEscape(username), sessionID)

	// Convert ChannelShort to string
	stringChannels := make([]string, len(channels))
	for i, ch := range channels {
		stringChannels[i] = string(ch)
	}

	req := models.UpdateSSHSessionRequest{
		BytesIn:  bytesIn,
		BytesOut: bytesOut,
		Client:   client,
		ProvTime: provTime,
		Channels: stringChannels,
	}

	return c.doRequest(ctx, http.MethodPatch, path, req, nil)
}

// EndSSHSession marks an SSH session as ended by setting the end time.
func (c *Client) EndSSHSession(ctx context.Context, username string, sessionID int32) error {
	path := fmt.Sprintf("/api/v1/users/%s/sessions/%d/end", url.PathEscape(username), sessionID)

	return c.doRequest(ctx, http.MethodPost, path, nil, nil)
}
