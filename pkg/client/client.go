// Copyright 2025 the k8Shell authors

package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/k8shell-io/common/models"
)

// Config represents the configuration for the Identity API client.
type Config struct {
	BaseURL             string `yaml:"baseURL"`
	APIKey              string `yaml:"APIKey"`
	Timeout             int    `yaml:"timeout"`
	MaxIdleConns        int    `yaml:"maxIdleConns"`
	MaxIdleConnsPerHost int    `yaml:"maxIdleConnsPerHost"`
	IdleConnTimeout     int    `yaml:"idleConnTimeout"`
	DialTimeout         int    `yaml:"dialTimeout"`
	KeepAlive           int    `yaml:"keepAlive"`
	TLSHandshakeTimeout int    `yaml:"tlsHandshakeTimeout"`
}

// setDefaults sets default values for Config fields that are zero
func (c *Config) setDefaults() {
	if c.Timeout == 0 {
		c.Timeout = 30
	}
	if c.MaxIdleConns == 0 {
		c.MaxIdleConns = 20
	}
	if c.MaxIdleConnsPerHost == 0 {
		c.MaxIdleConnsPerHost = 10
	}
	if c.IdleConnTimeout == 0 {
		c.IdleConnTimeout = 90
	}
	if c.DialTimeout == 0 {
		c.DialTimeout = 5
	}
	if c.KeepAlive == 0 {
		c.KeepAlive = 30
	}
	if c.TLSHandshakeTimeout == 0 {
		c.TLSHandshakeTimeout = 5
	}
}

// Client represents a client for the K8Shell Identity REST API.
type Client struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
}

// ErrorResponse represents an error response from the API.
type ErrorResponse struct {
	Status int    `json:"status"`
	Msg    string `json:"msg"`
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

// Error implements the error interface for ErrorResponse.
func (e ErrorResponse) Error() string {
	return fmt.Sprintf("API error %d: %s", e.Status, e.Msg)
}

// NewClient creates a new Identity API client with the given configuration.
func NewClient(config Config) *Client {
	config.setDefaults()

	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   time.Duration(config.DialTimeout) * time.Second,
			KeepAlive: time.Duration(config.KeepAlive) * time.Second,
		}).DialContext,
		MaxIdleConns:        config.MaxIdleConns,
		MaxIdleConnsPerHost: config.MaxIdleConnsPerHost,
		IdleConnTimeout:     time.Duration(config.IdleConnTimeout) * time.Second,
		TLSHandshakeTimeout: time.Duration(config.TLSHandshakeTimeout) * time.Second,
		DisableKeepAlives:   false,
	}

	return &Client{
		baseURL: config.BaseURL,
		apiKey:  config.APIKey,
		httpClient: &http.Client{
			Timeout:   time.Duration(config.Timeout) * time.Second,
			Transport: transport,
		},
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

// ForwardRequest forwards a HTTP request to the identity API
func (c *Client) ForwardRequest(cg *gin.Context, url string) {
	downstreamURL := c.baseURL + url

	req, err := http.NewRequest(cg.Request.Method, downstreamURL, cg.Request.Body)
	if err != nil {
		cg.JSON(http.StatusInternalServerError, gin.H{"msg": "Failed to create forward request"})
		cg.Abort()
		return
	}

	for k, v := range cg.Request.Header {
		if strings.ToLower(k) == "authorization" {
			continue
		}
		for _, vv := range v {
			req.Header.Add(k, vv)
		}
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		cg.JSON(http.StatusBadGateway, gin.H{"msg": "Forward request failed"})
		cg.Abort()
		return
	}
	defer resp.Body.Close()

	for k, v := range resp.Header {
		for _, vv := range v {
			cg.Writer.Header().Add(k, vv)
		}
	}
	cg.Status(resp.StatusCode)
	io.Copy(cg.Writer, resp.Body)
	cg.Abort()
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

func (c *Client) GetUserByToken(ctx context.Context, token string) (*models.User, error) {
	path := "/api/v1/users/lookup/token"
	req := TokenRequest{Token: token}

	var user models.User
	err := c.doRequest(ctx, http.MethodPost, path, req, &user)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// AuthPublicKey validates a user's SSH public key.
func (c *Client) AuthPublicKey(ctx context.Context, username, publicKey string) (*AuthPublicKeyResponse, error) {
	path := fmt.Sprintf("/api/v1/users/%s/authpublickey", url.PathEscape(username))
	req := AuthPublicKeyRequest{PublicKey: publicKey}

	var resp AuthPublicKeyResponse
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
func (c *Client) GetOnboardCapability(ctx context.Context, username string) (*models.OnboardCapability, error) {
	path := fmt.Sprintf("/api/v1/users/%s/onboardcap", url.PathEscape(username))

	var capability models.OnboardCapability
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
	req := CreateSSHSessionRequest{
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

	return c.doRequest(ctx, http.MethodPatch, path, req, nil)
}

// EndSSHSession marks an SSH session as ended by setting the end time.
func (c *Client) EndSSHSession(ctx context.Context, username string, sessionID int32) error {
	path := fmt.Sprintf("/api/v1/users/%s/sessions/%d/end", url.PathEscape(username), sessionID)

	return c.doRequest(ctx, http.MethodPost, path, nil, nil)
}

// Blueprints API

// GetBlueprintByUserStr retrieves a custom blueprint by userstr
func (c *Client) GetBlueprintByUserStr(ctx context.Context, userstr string) (*models.CustomBlueprint, error) {
	params := url.Values{}
	params.Set("userstr", userstr)

	path := "/api/v1/blueprints/lookup?" + params.Encode()

	var blueprint models.CustomBlueprint
	err := c.doRequest(ctx, http.MethodGet, path, nil, &blueprint)
	if err != nil {
		return nil, err
	}
	return &blueprint, nil
}

// External Credentials API

// GetUserCredentials retrieves all external credentials for a user.
func (c *Client) GetUserCredentials(ctx context.Context, username string) ([]models.ExternalCredential, error) {
	path := fmt.Sprintf("/api/v1/users/%s/credentials", url.PathEscape(username))

	var credentials []models.ExternalCredential
	err := c.doRequest(ctx, http.MethodGet, path, nil, &credentials)
	return credentials, err
}

// AddUserCredential adds an external credential for the specified user.
func (c *Client) AddUserCredential(ctx context.Context, username string, credential models.ExternalCredential) error {
	path := fmt.Sprintf("/api/v1/users/%s/credentials", url.PathEscape(username))

	return c.doRequest(ctx, http.MethodPost, path, credential, nil)
}

// UpdateUserCredential updates an external credential for the specified user.
func (c *Client) UpdateUserCredential(ctx context.Context, username string, credentialID uint64,
	credential models.ExternalCredential) error {
	path := fmt.Sprintf("/api/v1/users/%s/credentials/%d", url.PathEscape(username), credentialID)

	return c.doRequest(ctx, http.MethodPut, path, credential, nil)
}

// DeleteUserCredential deletes an external credential for the specified user.
func (c *Client) DeleteUserCredential(ctx context.Context, username string, credentialID uint64) error {
	path := fmt.Sprintf("/api/v1/users/%s/credentials/%d", url.PathEscape(username), credentialID)

	return c.doRequest(ctx, http.MethodDelete, path, nil, nil)
}
