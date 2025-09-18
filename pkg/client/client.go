// Copyright 2025 the k8Shell authors

package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"

	"github.com/k8shell-io/common/apiclient"
	"github.com/k8shell-io/common/models"
)

// Client represents the identity API client
type Client struct {
	*apiclient.Client
}

// AuthPublicKeyRequest represents the request body for user authentication
type AuthPublicKeyRequest struct {
	PublicKey string `json:"public_key"`
}

// AuthPublicKeyResponse represents the response body for user authentication
type AuthPublicKeyResponse struct {
	Authenticated bool `json:"authenticated"`
}

// CreateSSHSessionRequest represents the request body for creating an SSH session
type CreateSSHSessionRequest struct {
	Workspace string `json:"workspace"`
	ProxyID   string `json:"proxy_id"`
	ProxyPID  int    `json:"proxy_pid"`
	ClientIP  string `json:"client_ip"`
}

// UpdateSSHSessionRequest represents the request body for updating an SSH session
type UpdateSSHSessionRequest struct {
	BytesIn  int64    `json:"bytes_in"`
	BytesOut int64    `json:"bytes_out"`
	Client   string   `json:"client"`
	Channels []string `json:"channels"`
}

// TokenRequest represents the request body for token-based user lookup.
type TokenRequest struct {
	Token string `json:"token" binding:"required"`
}

// // Error implements the error interface for ErrorResponse.
// func (e ErrorResponse) Error() string {
// 	return fmt.Sprintf("API error %d: %s", e.Status, e.Msg)
// }

// NewClient creates a new Identity API client with the given configuration.
func NewClient(config apiclient.Config) *Client {
	return &Client{
		Client: apiclient.NewClient(config, "identity-client"),
	}
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

	resp, err := c.MakeRequest(ctx, http.MethodGet, path, nil, "")
	if err != nil {
		return nil, err
	}

	var users []models.User
	err = c.HandleResponse(resp, &users)
	if err != nil {
		return nil, err
	}

	return users, nil
}

// GetUser retrieves a user by their username.
func (c *Client) GetUser(ctx context.Context, username string) (*models.User, error) {
	path := fmt.Sprintf("/api/v1/users/%s", url.PathEscape(username))

	resp, err := c.MakeRequest(ctx, http.MethodGet, path, nil, "")
	if err != nil {
		return nil, err
	}

	var user models.User
	err = c.HandleResponse(resp, &user)
	if err != nil {
		return nil, err
	}

	return &user, nil
}

func (c *Client) GetUserByToken(ctx context.Context, token string) (*models.User, error) {
	path := "/api/v1/users/lookup/token"
	req := TokenRequest{Token: token}

	reqBody, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := c.MakeRequest(ctx, http.MethodPost, path, bytes.NewReader(reqBody), "application/json")
	if err != nil {
		return nil, err
	}

	var user models.User
	err = c.HandleResponse(resp, &user)
	if err != nil {
		return nil, err
	}

	return &user, nil
}

// AuthPublicKey validates a user's SSH public key.
func (c *Client) AuthPublicKey(ctx context.Context, username, publicKey string) (*AuthPublicKeyResponse, error) {
	path := fmt.Sprintf("/api/v1/users/%s/authpublickey", url.PathEscape(username))
	req := AuthPublicKeyRequest{PublicKey: publicKey}

	reqBody, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := c.MakeRequest(ctx, http.MethodPost, path, bytes.NewReader(reqBody), "application/json")
	if err != nil {
		return nil, err
	}

	var authResp AuthPublicKeyResponse
	err = c.HandleResponse(resp, &authResp)
	if err != nil {
		return nil, err
	}

	return &authResp, nil
}

// OnboardUser initiates the Device Authorization Flow to onboard a user.
func (c *Client) OnboardUser(ctx context.Context, username string) (*models.OnboardUser, error) {
	path := fmt.Sprintf("/api/v1/users/%s/onboard", url.PathEscape(username))

	resp, err := c.MakeRequest(ctx, http.MethodPost, path, nil, "")
	if err != nil {
		return nil, err
	}

	var onboardUser models.OnboardUser
	err = c.HandleResponse(resp, &onboardUser)
	if err != nil {
		return nil, err
	}

	return &onboardUser, nil
}

// GetOnboardCapability checks if a user can be onboarded.
func (c *Client) GetOnboardCapability(ctx context.Context, username string) (*models.OnboardCapability, error) {
	path := fmt.Sprintf("/api/v1/users/%s/onboardcap", url.PathEscape(username))

	resp, err := c.MakeRequest(ctx, http.MethodGet, path, nil, "")
	if err != nil {
		return nil, err
	}

	var capability models.OnboardCapability
	err = c.HandleResponse(resp, &capability)
	if err != nil {
		return nil, err
	}

	return &capability, nil
}

// GetUserToken retrieves a user token for the specified username.
func (c *Client) GetUserToken(ctx context.Context, username string) (*models.UserToken, error) {
	path := fmt.Sprintf("/api/v1/users/%s/token", url.PathEscape(username))

	resp, err := c.MakeRequest(ctx, http.MethodGet, path, nil, "")
	if err != nil {
		return nil, err
	}

	var token models.UserToken
	err = c.HandleResponse(resp, &token)
	if err != nil {
		return nil, err
	}

	return &token, nil
}

// SSH Sessions API

// ListSSHSessions retrieves a paginated list of SSH sessions for a user.
func (c *Client) ListSSHSessions(ctx context.Context, username string, workspace string, limit, offset int,
	reverse bool) ([]models.SSHSession, error) {
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
	if workspace != "" {
		params.Set("workspace", workspace)
	}

	path := fmt.Sprintf("/api/v1/users/%s/sessions", url.PathEscape(username))
	if len(params) > 0 {
		path += "?" + params.Encode()
	}

	resp, err := c.MakeRequest(ctx, http.MethodGet, path, nil, "")
	if err != nil {
		return nil, err
	}

	var sessions []models.SSHSession
	err = c.HandleResponse(resp, &sessions)
	if err != nil {
		return nil, err
	}

	return sessions, nil
}

// GetSSHSession retrieves a specific SSH session by its ID for a user.
func (c *Client) GetSSHSession(ctx context.Context, username string, sessionID int32) (*models.SSHSession, error) {
	path := fmt.Sprintf("/api/v1/users/%s/sessions/%d", url.PathEscape(username), sessionID)

	resp, err := c.MakeRequest(ctx, http.MethodGet, path, nil, "")
	if err != nil {
		return nil, err
	}

	var session models.SSHSession
	err = c.HandleResponse(resp, &session)
	if err != nil {
		return nil, err
	}

	return &session, nil
}

// CreateSSHSession creates a new SSH session for a user in a specified workspace.
func (c *Client) CreateSSHSession(ctx context.Context, username, workspace, proxyID string, proxyPID int, clientIP string) (*models.SSHSession, error) {
	path := fmt.Sprintf("/api/v1/users/%s/sessions", url.PathEscape(username))
	req := CreateSSHSessionRequest{
		Workspace: workspace,
		ProxyID:   proxyID,
		ProxyPID:  proxyPID,
		ClientIP:  clientIP,
	}

	reqBody, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := c.MakeRequest(ctx, http.MethodPost, path, bytes.NewReader(reqBody), "application/json")
	if err != nil {
		return nil, err
	}

	var session models.SSHSession
	err = c.HandleResponse(resp, &session)
	if err != nil {
		return nil, err
	}

	return &session, nil
}

// UpdateSSHSession updates an existing SSH session with new data.
func (c *Client) UpdateSSHSession(ctx context.Context, username string, sessionID int32, bytesIn, bytesOut int64,
	client string, channels []string) error {
	path := fmt.Sprintf("/api/v1/users/%s/sessions/%d", url.PathEscape(username), sessionID)

	// Convert ChannelShort to string
	stringChannels := make([]string, len(channels))
	for i, ch := range channels {
		stringChannels[i] = string(ch)
	}

	req := UpdateSSHSessionRequest{
		BytesIn:  bytesIn,
		BytesOut: bytesOut,
		Client:   client,
		Channels: stringChannels,
	}

	reqBody, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := c.MakeRequest(ctx, http.MethodPatch, path, bytes.NewReader(reqBody), "application/json")
	if err != nil {
		return err
	}

	return c.HandleResponse(resp, nil)
}

// EndSSHSession marks an SSH session as ended by setting the end time.
func (c *Client) EndSSHSession(ctx context.Context, username string, sessionID int32) error {
	path := fmt.Sprintf("/api/v1/users/%s/sessions/%d/end", url.PathEscape(username), sessionID)

	resp, err := c.MakeRequest(ctx, http.MethodPost, path, nil, "")
	if err != nil {
		return err
	}

	return c.HandleResponse(resp, nil)
}

// Blueprints API

// GetBlueprintByUserStr retrieves a custom blueprint by userstr
func (c *Client) GetBlueprintByUserStr(ctx context.Context, userstr string) (*models.CustomBlueprint, error) {
	params := url.Values{}
	params.Set("userstr", userstr)

	path := "/api/v1/blueprints/lookup?" + params.Encode()

	resp, err := c.MakeRequest(ctx, http.MethodGet, path, nil, "")
	if err != nil {
		return nil, err
	}

	var blueprint models.CustomBlueprint
	err = c.HandleResponse(resp, &blueprint)
	if err != nil {
		return nil, err
	}

	return &blueprint, nil
}

// External Credentials API

// GetUserCredentials retrieves all external credentials for a user.
func (c *Client) GetUserCredentials(ctx context.Context, username string) ([]models.ExternalCredential, error) {
	path := fmt.Sprintf("/api/v1/users/%s/credentials", url.PathEscape(username))

	resp, err := c.MakeRequest(ctx, http.MethodGet, path, nil, "")
	if err != nil {
		return nil, err
	}

	var credentials []models.ExternalCredential
	err = c.HandleResponse(resp, &credentials)
	if err != nil {
		return nil, err
	}

	return credentials, nil
}

// AddUserCredential adds an external credential for the specified user.
func (c *Client) AddUserCredential(ctx context.Context, username string, credential models.ExternalCredential) error {
	path := fmt.Sprintf("/api/v1/users/%s/credentials", url.PathEscape(username))

	reqBody, err := json.Marshal(credential)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := c.MakeRequest(ctx, http.MethodPost, path, bytes.NewReader(reqBody), "application/json")
	if err != nil {
		return err
	}

	return c.HandleResponse(resp, nil)
}

// UpdateUserCredential updates an external credential for the specified user.
func (c *Client) UpdateUserCredential(ctx context.Context, username string, credentialID uint64,
	credential models.ExternalCredential) error {
	path := fmt.Sprintf("/api/v1/users/%s/credentials/%d", url.PathEscape(username), credentialID)

	reqBody, err := json.Marshal(credential)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := c.MakeRequest(ctx, http.MethodPut, path, bytes.NewReader(reqBody), "application/json")
	if err != nil {
		return err
	}

	return c.HandleResponse(resp, nil)
}

// DeleteUserCredential deletes an external credential for the specified user.
func (c *Client) DeleteUserCredential(ctx context.Context, username string, credentialID uint64) error {
	path := fmt.Sprintf("/api/v1/users/%s/credentials/%d", url.PathEscape(username), credentialID)

	resp, err := c.MakeRequest(ctx, http.MethodDelete, path, nil, "")
	if err != nil {
		return err
	}

	return c.HandleResponse(resp, nil)
}
