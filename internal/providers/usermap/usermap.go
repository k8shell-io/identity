package usermap

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	log "github.com/k8shell-io/common/pkg/logger"
	natsc "github.com/k8shell-io/common/pkg/nats"
	"github.com/rs/zerolog"
)

const tokenCacheKey = "usermap-token"

// PeopleModel represents the structure of a user returned by Usermap backend.
type PeopleModel struct {
	Username       string           `json:"username"`
	PersonalNumber int              `json:"personalNumber"`
	KosPersonID    int              `json:"kosPersonId"`
	FirstName      string           `json:"firstName"`
	LastName       string           `json:"lastName"`
	FullName       string           `json:"fullName"`
	Emails         []string         `json:"emails"`
	PreferredEmail string           `json:"preferredEmail"`
	Departments    []map[string]any `json:"departments"`
	Rooms          []string         `json:"rooms"`
	Phones         []string         `json:"phones"`
	Roles          []string         `json:"roles"`
	TechnicalRoles []string         `json:"technicalRoles"`
}

type UsermapAPI struct {
	config     UserMapProviderConfig
	cache      *natsc.JetStreamKV
	httpClient *http.Client
	log        *zerolog.Logger

	// Cached token values
	accessToken string
	tokenType   string
	expiresAt   int64
	scope       string
}

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
	ExpiresAt   int64  `json:"expires_at"`
}

func NewUsermapAPI(cfg UserMapProviderConfig, cache *natsc.JetStreamKV, httpTimeout int) *UsermapAPI {
	u := &UsermapAPI{
		log:        log.NewLogger("usermap"),
		config:     cfg,
		cache:      cache,
		httpClient: &http.Client{Timeout: time.Duration(httpTimeout) * time.Millisecond},
	}
	return u
}

func (u *UsermapAPI) invalidateToken() {
	if u.cache != nil {
		u.cache.Delete(tokenCacheKey)
	}
	u.accessToken = ""
	u.tokenType = ""
	u.expiresAt = 0
	u.scope = ""
}

func (u *UsermapAPI) ensureToken() error {
	if u.cache != nil {
		item, err := u.cache.Get(tokenCacheKey)
		if err == nil {
			var tokenResp TokenResponse
			if err := json.Unmarshal(item.Value(), &tokenResp); err == nil {
				if time.Now().Unix() < tokenResp.ExpiresAt {
					u.setTokenFromResponse(&tokenResp)
					u.log.Debug().Msgf("Using cached token, expires at %d", tokenResp.ExpiresAt)
					return nil
				}
			}
		}
	}

	// Fetch new token
	data := fmt.Sprintf("grant_type=%s", u.config.GrantType)
	req, _ := http.NewRequest("POST", u.config.TokenUrl, strings.NewReader(data))
	req.SetBasicAuth(u.config.ClientId, u.config.ClientSecret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := u.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("token request failed: %s", body)
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return fmt.Errorf("token decode failed: %w", err)
	}

	tokenResp.ExpiresAt = time.Now().Unix() + int64(tokenResp.ExpiresIn)
	u.setTokenFromResponse(&tokenResp)
	u.log.Debug().Msgf("New token acquired, expires at %d", tokenResp.ExpiresAt)

	if u.cache != nil {
		b, _ := json.Marshal(tokenResp)
		u.cache.Set(tokenCacheKey, b)
	}
	return nil
}

func (u *UsermapAPI) setTokenFromResponse(tr *TokenResponse) {
	u.accessToken = tr.AccessToken
	u.tokenType = tr.TokenType
	u.expiresAt = tr.ExpiresAt
	u.scope = tr.Scope
}

func (u *UsermapAPI) GetPeopleResource(username string) (*PeopleModel, error) {
	cacheKey := fmt.Sprintf("usermap-people-%s", username)

	if u.cache != nil {
		item, err := u.cache.Get(cacheKey)
		if err == nil {
			u.log.Debug().Msgf("User '%s' found in cache", username)
			var cached PeopleModel
			if err := json.Unmarshal(item.Value(), &cached); err == nil {
				return &cached, nil
			}
		}
	}

	if err := u.ensureToken(); err != nil {
		u.invalidateToken()
		return nil, fmt.Errorf("ensureToken failed: %w", err)
	}

	url := fmt.Sprintf("%s/%s", u.config.PeopleUrl, username)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", fmt.Sprintf("%s %s", u.tokenType, u.accessToken))

	resp, err := u.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to request user: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		u.invalidateToken()
		return nil, fmt.Errorf("failed to get user (%d)", resp.StatusCode)
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get user (%d): %s", resp.StatusCode, body)
	}

	var user PeopleModel
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, fmt.Errorf("invalid JSON response: %w", err)
	}

	if u.cache != nil && u.config.CacheTimeout > 0 {
		b, err := json.Marshal(user)
		if err != nil {
			u.log.Warn().Msgf("Failed to marshal user '%s' for caching: %v", username, err)
			return &user, nil
		}
		_, err = u.cache.Set(cacheKey, b)
		if err != nil {
			u.log.Warn().Msgf("Failed to cache user '%s': %v", username, err)
		} else {
			u.log.Debug().Msgf("User '%s' cached for %d seconds", username, u.config.CacheTimeout)
		}
	}

	return &user, nil
}
