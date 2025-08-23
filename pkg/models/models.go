package models

// API Request and Response Types

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
	ProvTime float32  `json:"prov_time"`
	Channels []string `json:"channels"`
}
