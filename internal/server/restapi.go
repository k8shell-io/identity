// Copyright 2025 the k8Shell authors

package server

// @title        K8shell Identity API
// @version      1.1
// @description  This is the API documentation for the K8shell identity service.
//
// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	log "github.com/k8shell-io/common/logger"
	"github.com/k8shell-io/common/models"
	"github.com/k8shell-io/identity/internal/backend"
	"github.com/k8shell-io/identity/pkg/client"
	"github.com/rs/zerolog"
)

// API type aliases
type User = models.User
type SSHSession = models.SSHSession
type OnboardUser = models.OnboardUser
type OnboardCapability = models.OnboardCapability
type UserToken = models.UserToken

type AuthPublicKeyRequest = client.AuthPublicKeyRequest
type AuthPublicKeyResponse = client.AuthPublicKeyResponse
type CreateSSHSessionRequest = client.CreateSSHSessionRequest
type UpdateSSHSessionRequest = client.UpdateSSHSessionRequest

// HttpConfig represents the HTTP server configuration.
type HttpConfig struct {
	Port   int    `yaml:"port"`
	APIKey string `yaml:"APIKey"`
}

// RESTApiService represents the REST API service for the K8Shell Identity server.
type RESTApiService struct {
	httpConfig HttpConfig
	log        *zerolog.Logger
	server     *Server
	ginEngine  *gin.Engine
}

// NewRESTAPI creates a new REST API service
func NewRESTAPI(httpConfig HttpConfig, server *Server) (*RESTApiService, error) {
	log := log.NewLogger("api")

	gin.SetMode(gin.ReleaseMode)

	return &RESTApiService{
		httpConfig: httpConfig,
		log:        log,
		server:     server,
	}, nil
}

// apiKeyMiddleware checks for the presence of a valid API key in the request header
func (a *RESTApiService) apiKeyMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		const prefix = "Bearer "

		if !strings.HasPrefix(authHeader, prefix) {
			c.JSON(http.StatusUnauthorized, gin.H{
				"status": http.StatusUnauthorized,
				"msg":    "Unauthorized: missing or malformed Authorization header",
			})
			c.Abort()
			return
		}

		providedKey := strings.TrimPrefix(authHeader, prefix)
		expectedKey := a.httpConfig.APIKey

		if providedKey != expectedKey {
			c.JSON(http.StatusUnauthorized, gin.H{
				"status": http.StatusUnauthorized,
				"msg":    "Unauthorized: invalid API key",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

func (a *RESTApiService) customLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		latency := time.Since(start)

		status := c.Writer.Status()
		ip := c.ClientIP()
		method := c.Request.Method
		path := c.Request.URL.Path

		a.log.Info().
			Str("method", method).
			Int("status", status).
			Str("path", path).
			Str("ip", ip).
			Dur("duration", latency).
			Msg("request")
	}
}

// Initialize the router
func (a *RESTApiService) initializeRouter() *gin.Engine {
	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(a.customLogger())

	v1 := router.Group("/api/v1")
	v1.Use(a.apiKeyMiddleware())
	{
		users := v1.Group("/users")
		{
			users.GET("/", a.GetUsers)
			users.GET("/lookup", a.FindUserByUserStr)
			users.POST("/lookup/token", a.FindUserByToken)
			users.GET("/:username", a.FindUser)
			users.GET("/:username/onboardcap", a.OnboardCapability)
			users.POST("/:username/onboard", a.OnboardUserDeviceFlow)
			users.POST("/:username/authpublickey", a.AuthPublicKey)
			users.GET("/:username/credentials", a.GetUserExtCredentials)
			users.POST("/:username/credentials", a.AddUserExtCredential)
			users.PUT("/:username/credentials/:id", a.UpdateUserExtCredential)
			users.DELETE("/:username/credentials/:id", a.DeleteUserExtCredential)

			users.GET("/:username/sessions", a.GetSSHSessions)
			users.POST("/:username/sessions", a.CreateSSHSession)
			users.GET("/:username/sessions/:sessionId", a.GetSSHSession)
			users.PATCH("/:username/sessions/:sessionId", a.UpdateSSHSession)
			users.POST("/:username/sessions/:sessionId/end", a.EndSSHSession)
		}

		blueprints := v1.Group("/blueprints")
		{
			blueprints.GET("/lookup", a.GetBlueprintByUserStr)
		}
	}

	router.NoRoute(func(c *gin.Context) {
		a.log.Debug().Msgf("404 Not Found: %s %s", c.Request.Method, c.Request.URL.Path)
		c.JSON(http.StatusNotFound, gin.H{
			"status": http.StatusNotFound,
			"msg":    "404 route not found",
		})
	})

	return router
}

func (a *RESTApiService) Serve(ctx context.Context) {
	a.ginEngine = a.initializeRouter()

	server := &http.Server{
		Handler: a.ginEngine,
		Addr:    fmt.Sprintf(":%d", a.httpConfig.Port),
	}

	idleConnsClosed := make(chan struct{})
	go func() {
		<-ctx.Done()
		a.log.Info().Msg("Shutting down REST API server...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := server.Shutdown(shutdownCtx); err != nil {
			a.log.Error().Err(err).Msg("REST API server shutdown failed")
		} else {
			a.log.Info().Msg("REST API server shutdown complete")
		}
		close(idleConnsClosed)
	}()

	a.log.Info().Msgf("Starting API server on %s", server.Addr)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		a.log.Error().Err(err).Msg("Failed to start API server")
	}

	<-idleConnsClosed
}

// parseQueryInt parses an integer from a query parameter string.
func parseQueryInt(val string, defaultVal int) int {
	if val == "" {
		return defaultVal
	}
	i, err := strconv.Atoi(val)
	if err != nil || i < 0 {
		return defaultVal
	}
	return i
}

// HANDLERS
// ** USERS

// GetUsers returns a list of users.
func (a *RESTApiService) GetUsers(c *gin.Context) {
	limit := parseQueryInt(c.Query("limit"), backend.DefaultListLimit)
	offset := parseQueryInt(c.Query("offset"), 0)

	users, err := a.server.DB.ListUsers(limit, offset)
	if err != nil {
		a.log.Error().Err(err).Msg("Failed to list users from database")
		c.JSON(http.StatusInternalServerError, gin.H{
			"status": http.StatusInternalServerError,
			"msg":    "Failed to list users",
		})
		return
	}

	c.JSON(http.StatusOK, users)
}

// FindUser returns a user by username.
func (a *RESTApiService) FindUser(c *gin.Context) {
	username := c.Param("username")
	if username == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"status": http.StatusBadRequest,
			"msg":    "Username is required",
		})
		return
	}

	user, err := a.server.GetUser(username)
	if err != nil {
		a.log.Error().Err(err).Msgf("Failed to find user '%s'", username)
		if errors.Is(err, models.ErrUserNotFound) || errors.Is(err, models.ErrUserIsNotValid) {
			c.JSON(http.StatusNotFound, gin.H{
				"status": http.StatusNotFound,
				"msg":    fmt.Sprintf("User '%s' not found or invalid", username),
			})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{
				"status": http.StatusInternalServerError,
				"msg":    "Failed to find user",
			})
		}
		return
	}

	if user == nil {
		c.JSON(http.StatusNotFound, gin.H{
			"status": http.StatusNotFound,
			"msg":    fmt.Sprintf("User '%s' not found", username),
		})
		return
	}

	c.JSON(http.StatusOK, user)
}

// FindUserByUserStr returns a user by userstr (user string)
func (a *RESTApiService) FindUserByUserStr(c *gin.Context) {
	userstrParam := c.Query("userstr")
	if userstrParam == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"status": http.StatusBadRequest,
			"msg":    "userstr parameter is required",
		})
		return
	}

	userStr, err := models.NewUserStr(userstrParam)
	if err != nil {
		a.log.Error().Err(err).Msgf("Failed to create userstr from '%s'", userstrParam)
		c.JSON(http.StatusBadRequest, gin.H{
			"status": http.StatusBadRequest,
			"msg":    fmt.Sprintf("Invalid userstr: %v", err),
		})
		return
	}

	username := userStr.Username

	user, err := a.server.GetUser(username)
	if err != nil {
		a.log.Error().Err(err).Msgf("Failed to find user from userstr '%s'", userstrParam)
		if errors.Is(err, models.ErrUserNotFound) || errors.Is(err, models.ErrUserIsNotValid) {
			c.JSON(http.StatusNotFound, gin.H{
				"status": http.StatusNotFound,
				"msg":    fmt.Sprintf("User not found for userstr '%s'", userstrParam),
			})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{
				"status": http.StatusInternalServerError,
				"msg":    "Failed to find user",
			})
		}
		return
	}

	if user == nil {
		c.JSON(http.StatusNotFound, gin.H{
			"status": http.StatusNotFound,
			"msg":    fmt.Sprintf("User not found for userstr '%s'", userstrParam),
		})
		return
	}

	c.JSON(http.StatusOK, user)
}

// FindUserByToken retrieves a user by their access token (POST with body)
func (a *RESTApiService) FindUserByToken(c *gin.Context) {
	var req client.TokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"status": http.StatusBadRequest,
			"msg":    "Invalid request body",
		})
		return
	}

	user, err := a.server.DB.FindUserByAccessToken(req.Token)
	if err != nil {
		if errors.Is(err, models.ErrUserNotFound) {
			c.JSON(http.StatusUnauthorized, gin.H{
				"status": http.StatusNotFound,
				"msg":    "User not found for provided token",
			})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{
				"status": http.StatusInternalServerError,
				"msg":    "Failed to authenticate user",
			})
		}
		return
	}

	c.JSON(http.StatusOK, user)
}

// AuthPublicKey authenticates a user using their public key.
func (a *RESTApiService) AuthPublicKey(c *gin.Context) {
	username := c.Param("username")
	if username == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"status": http.StatusBadRequest,
			"msg":    "Username is required",
		})
		return
	}

	var req client.AuthPublicKeyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		a.log.Error().Err(err).Msg("Failed to decode request body")
		c.JSON(http.StatusBadRequest, gin.H{
			"status": http.StatusBadRequest,
			"msg":    "Invalid request body",
		})
		return
	}

	if req.PublicKey == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"status": http.StatusBadRequest,
			"msg":    "Public key is required",
		})
		return
	}

	isAuthenticated, err := a.server.AuthenticateUser(username, req.PublicKey)
	if err != nil {
		a.log.Error().Err(err).Msgf("Failed to authenticate user '%s'", username)
		c.JSON(http.StatusInternalServerError, gin.H{
			"status": http.StatusInternalServerError,
			"msg":    "Failed to authenticate user",
		})
		return
	}

	response := client.AuthPublicKeyResponse{
		Authenticated: isAuthenticated,
	}
	c.JSON(http.StatusOK, response)
}

// OnboardUserDeviceFlow initiates the Device Authorization Flow for onboarding a user.
func (a *RESTApiService) OnboardUserDeviceFlow(c *gin.Context) {
	username := c.Param("username")
	if username == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"status": http.StatusBadRequest,
			"msg":    "Username is required",
		})
		return
	}

	onboardUser, err := a.server.OnboardUserDeviceFlow(username)
	if err != nil {
		if errors.Is(err, models.ErrOnboardingPending) {
			c.JSON(http.StatusBadRequest, gin.H{
				"status": http.StatusBadRequest,
				"msg":    "User onboarding is already in progress",
			})
		} else if errors.Is(err, models.ErrUserNotFound) {
			c.JSON(http.StatusNotFound, gin.H{
				"status": http.StatusNotFound,
				"msg":    fmt.Sprintf("User '%s' not found", username),
			})
		} else if errors.Is(err, models.ErrAlreadyOnboarded) {
			c.JSON(http.StatusBadRequest, gin.H{
				"status": http.StatusBadRequest,
				"msg":    fmt.Sprintf("User '%s' is already onboarded", username),
			})
		} else {
			a.log.Error().Err(err).Msgf("Failed to onboard user '%s'", username)
			c.JSON(http.StatusBadRequest, gin.H{
				"status": http.StatusBadRequest,
				"msg":    "Failed to onboard user",
			})
		}
		return
	}

	c.JSON(http.StatusOK, onboardUser)
}

// OnboardCapability checks if a user can be onboarded.
func (a *RESTApiService) OnboardCapability(c *gin.Context) {
	username := c.Param("username")
	if username == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"status": http.StatusBadRequest,
			"msg":    "Username is required",
		})
		return
	}

	cap, err := a.server.OnboardCapability(username)
	if err != nil {
		a.log.Error().Err(err).Msgf("Failed to check if user '%s' can be onboarded", username)
		c.JSON(http.StatusInternalServerError, gin.H{
			"status": http.StatusInternalServerError,
			"msg":    "Failed to check onboarding capability",
		})
		return
	}

	c.JSON(http.StatusOK, cap)
}

// GetUserCredentials retrieves user credentials for the specified username.
func (a *RESTApiService) GetUserExtCredentials(c *gin.Context) {
	username := c.Param("username")
	if username == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"status": http.StatusBadRequest,
			"msg":    "Username is required",
		})
		return
	}

	credentials, err := a.server.GetUserExtCredentials(username)
	if err != nil {
		if errors.Is(err, models.ErrUserNotFound) {
			c.JSON(http.StatusNotFound, gin.H{
				"status": http.StatusNotFound,
				"msg":    fmt.Sprintf("User '%s' not found", username),
			})
		} else if errors.Is(err, models.ErrUserIsNotValid) {
			c.JSON(http.StatusBadRequest, gin.H{
				"status": http.StatusBadRequest,
				"msg":    fmt.Sprintf("User '%s' is not valid", username),
			})
		} else if errors.Is(err, models.ErrUserTokenNotSupported) {
			c.JSON(http.StatusNotImplemented, gin.H{
				"status": http.StatusNotImplemented,
				"msg":    fmt.Sprintf("User token not supported for '%s'", username),
			})
		} else {
			a.log.Error().Err(err).Msgf("Failed to get user token for '%s'", username)
			c.JSON(http.StatusInternalServerError, gin.H{
				"status": http.StatusInternalServerError,
				"msg":    "Failed to get user token",
			})
		}
		return
	}

	c.JSON(http.StatusOK, credentials)
}

// AddUserExtCredential adds an external credential for the specified user.
func (a *RESTApiService) AddUserExtCredential(c *gin.Context) {
	username := c.Param("username")
	if username == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"status": http.StatusBadRequest,
			"msg":    "Username is required",
		})
		return
	}

	var req models.ExternalCredential
	if err := c.ShouldBindJSON(&req); err != nil {
		a.log.Error().Err(err).Msg("Failed to decode request body")
		c.JSON(http.StatusBadRequest, gin.H{
			"status": http.StatusBadRequest,
			"msg":    "Invalid request body",
		})
		return
	}

	err := a.server.DB.AddExternalCredential(&models.ExternalCredential{
		Username:      username,
		ServiceName:   req.ServiceName,
		ServiceURL:    req.ServiceURL,
		ExternalID:    req.ExternalID,
		ExternalToken: req.ExternalToken,
	})
	if err != nil {
		if strings.Contains(err.Error(), "credential already exists") || strings.Contains(err.Error(), "required field") {
			c.JSON(http.StatusBadRequest, gin.H{
				"status": http.StatusBadRequest,
				"msg":    err.Error(),
			})
			return
		}

		a.log.Error().Err(err).Msgf("Failed to add external credential for user '%s'", username)
		c.JSON(http.StatusInternalServerError, gin.H{
			"status": http.StatusInternalServerError,
			"msg":    "Failed to add external credential",
		})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"status":  http.StatusCreated,
		"message": "External credential added successfully",
	})
}

// UpdateUserExtCredential updates an external credential for the specified user.
func (a *RESTApiService) UpdateUserExtCredential(c *gin.Context) {
	username := c.Param("username")
	idStr := c.Param("id")
	if username == "" || idStr == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"status": http.StatusBadRequest,
			"msg":    "Username and credential ID are required",
		})
		return
	}

	id, err := strconv.ParseInt(idStr, 10, 32)
	if err != nil || id <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"status": http.StatusBadRequest,
			"msg":    "Invalid credential ID",
		})
		return
	}

	var req models.ExternalCredential
	if err := c.ShouldBindJSON(&req); err != nil {
		a.log.Error().Err(err).Msg("Failed to decode request body")
		c.JSON(http.StatusBadRequest, gin.H{
			"status": http.StatusBadRequest,
			"msg":    "Invalid request body",
		})
		return
	}

	err = a.server.DB.UpdateExternalCredential(&models.ExternalCredential{
		ID:            uint64(id),
		Username:      username,
		ServiceName:   req.ServiceName,
		ServiceURL:    req.ServiceURL,
		ExternalID:    req.ExternalID,
		ExternalToken: req.ExternalToken,
	})

	if err != nil {
		if strings.Contains(err.Error(), "credential already exists") || strings.Contains(err.Error(), "required field") {
			c.JSON(http.StatusBadRequest, gin.H{
				"status": http.StatusBadRequest,
				"msg":    err.Error(),
			})
			return
		} else if strings.Contains(err.Error(), "no rows affected") {
			c.JSON(http.StatusNotFound, gin.H{
				"status": http.StatusNotFound,
				"msg":    fmt.Sprintf("Credential ID %d for user '%s' not found", id, username),
			})
			return
		}
		a.log.Error().Err(err).Msgf("Failed to update external credential ID %d for user '%s'", id, username)
		c.JSON(http.StatusInternalServerError, gin.H{
			"status": http.StatusInternalServerError,
			"msg":    "Failed to update external credential",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":  http.StatusOK,
		"message": "External credential updated successfully",
	})
}

// DeleteUserExtCredential deletes an external credential for the specified user.
func (a *RESTApiService) DeleteUserExtCredential(c *gin.Context) {
	username := c.Param("username")
	idStr := c.Param("id")
	if username == "" || idStr == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"status": http.StatusBadRequest,
			"msg":    "Username and credential ID are required",
		})
		return
	}

	id, err := strconv.ParseInt(idStr, 10, 32)
	if err != nil || id <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"status": http.StatusBadRequest,
			"msg":    "Invalid credential ID",
		})
		return
	}

	err = a.server.DB.DeleteExternalCredential(uint64(id))
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			c.JSON(http.StatusNotFound, gin.H{
				"status": http.StatusNotFound,
				"msg":    fmt.Sprintf("Credential ID %d for user '%s' not found", id, username),
			})
			return
		}
		a.log.Error().Err(err).Msgf("Failed to delete external credential ID %d for user '%s'", id, username)
		c.JSON(http.StatusInternalServerError, gin.H{
			"status": http.StatusInternalServerError,
			"msg":    "Failed to delete external credential",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":  http.StatusOK,
		"message": "External credential deleted successfully",
	})
}

// ** SSH SESSIONS

// GetSSHSessions retrieves a list of SSH sessions for a user.
func (a *RESTApiService) GetSSHSessions(c *gin.Context) {
	username := c.Param("username")
	workspace := c.Query("workspace")

	if username == "" && workspace == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"status": http.StatusBadRequest,
			"msg":    "Username or workspace is required",
		})
		return
	}

	limit := parseQueryInt(c.Query("limit"), backend.DefaultListLimit)
	offset := parseQueryInt(c.Query("offset"), 0)
	reverse := c.Query("reverse") == "true"

	sessions, err := a.server.GetSSHSessions(username, workspace, limit, offset, reverse)
	if err != nil {
		a.log.Error().Err(err).Msgf("Failed to get SSH sessions for user '%s'", username)
		c.JSON(http.StatusInternalServerError, gin.H{
			"status": http.StatusInternalServerError,
			"msg":    "Failed to get SSH sessions",
		})
		return
	}

	c.JSON(http.StatusOK, sessions)
}

// GetSSHSession retrieves a specific SSH session for a user.
func (a *RESTApiService) GetSSHSession(c *gin.Context) {
	username := c.Param("username")
	if username == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"status": http.StatusBadRequest,
			"msg":    "Username is required",
		})
		return
	}

	sessionIdStr := c.Param("sessionId")
	if sessionIdStr == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"status": http.StatusBadRequest,
			"msg":    "Session ID is required",
		})
		return
	}

	id64, err := strconv.ParseInt(sessionIdStr, 10, 32)
	if err != nil {
		a.log.Error().Err(err).Msgf("Invalid session ID '%s' for user '%s'", sessionIdStr, username)
		c.JSON(http.StatusBadRequest, gin.H{
			"status": http.StatusBadRequest,
			"msg":    "Invalid session ID",
		})
		return
	}
	sessionId := int32(id64)

	session, err := a.server.GetSSHSession(username, sessionId)
	if err != nil {
		a.log.Error().Err(err).Msgf("Failed to get SSH session '%d' for user '%s': %s", sessionId, username, err)
		if errors.Is(err, models.ErrSessionNotFound) {
			c.JSON(http.StatusNotFound, gin.H{
				"status": http.StatusNotFound,
				"msg":    fmt.Sprintf("Session ID %d for user '%s' not found", sessionId, username),
			})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{
				"status": http.StatusInternalServerError,
				"msg":    "Failed to get SSH session",
			})
		}
		return
	}

	c.JSON(http.StatusOK, session)
}

// CreateSSHSession creates a new SSH session for a user.
func (a *RESTApiService) CreateSSHSession(c *gin.Context) {
	username := c.Param("username")
	if username == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"status": http.StatusBadRequest,
			"msg":    "Username is required",
		})
		return
	}

	var req client.CreateSSHSessionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		a.log.Error().Err(err).Msg("Failed to decode request body")
		c.JSON(http.StatusBadRequest, gin.H{
			"status": http.StatusBadRequest,
			"msg":    "Invalid request body",
		})
		return
	}

	session, err := a.server.CreateSSHSession(username, req.Workspace, req.Blueprint, req.ProxyID,
		req.ProxyPID, req.ClientIP)
	if err != nil {
		a.log.Error().Err(err).Msgf("Failed to create SSH session for user '%s'", username)
		c.JSON(http.StatusInternalServerError, gin.H{
			"status": http.StatusInternalServerError,
			"msg":    "Failed to create SSH session",
		})
		return
	}

	c.Header("Location", fmt.Sprintf("/api/v1/users/%s/sessions/%d", username, session.SessionID))
	c.JSON(http.StatusOK, session)
}

// UpdateSSHSession updates an existing SSH session for a user.
func (a *RESTApiService) UpdateSSHSession(c *gin.Context) {
	username := c.Param("username")
	sessionIDStr := c.Param("sessionId")

	if username == "" || sessionIDStr == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"status": http.StatusBadRequest,
			"msg":    "Username and session ID are required",
		})
		return
	}

	sessionID, err := strconv.Atoi(sessionIDStr)
	if err != nil || sessionID <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"status": http.StatusBadRequest,
			"msg":    "Invalid session ID",
		})
		return
	}

	var req client.UpdateSSHSessionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		a.log.Error().Err(err).Msg("Failed to decode request body")
		c.JSON(http.StatusBadRequest, gin.H{
			"status": http.StatusBadRequest,
			"msg":    "Invalid request body",
		})
		return
	}

	err = a.server.UpdateSSHSession(username, int32(sessionID), req.BytesIn, req.BytesOut, req.Client,
		req.Channels)
	if err != nil {
		a.log.Error().Err(err).Msgf("Failed to update SSH session for user '%s': %s", username, err)
		if errors.Is(err, models.ErrActiveSessionNotFound) {
			c.JSON(http.StatusNotFound, gin.H{
				"status": http.StatusNotFound,
				"msg":    fmt.Sprintf("Session ID %d for user '%s' not found or already ended", sessionID, username),
			})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{
				"status": http.StatusInternalServerError,
				"msg":    "Failed to update SSH session",
			})
		}
		return
	}

	c.Status(http.StatusNoContent)
}

// EndSSHSession ends an existing SSH session for a user.
func (a *RESTApiService) EndSSHSession(c *gin.Context) {
	username := c.Param("username")
	sessionIDStr := c.Param("sessionId")

	if username == "" || sessionIDStr == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"status": http.StatusBadRequest,
			"msg":    "Username and session ID are required",
		})
		return
	}

	sessionID, err := strconv.Atoi(sessionIDStr)
	if err != nil || sessionID <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"status": http.StatusBadRequest,
			"msg":    "Invalid session ID",
		})
		return
	}

	err = a.server.EndSSHSession(username, int32(sessionID))
	if err != nil {
		a.log.Error().Err(err).Msgf("Failed to end SSH session for user '%s': %s", username, err)
		if errors.Is(err, models.ErrActiveSessionNotFound) {
			c.JSON(http.StatusNotFound, gin.H{
				"status": http.StatusNotFound,
				"msg":    fmt.Sprintf("Session ID %d for user '%s' not found or already ended", sessionID, username),
			})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{
				"status": http.StatusInternalServerError,
				"msg":    "Failed to end SSH session",
			})
		}
		return
	}

	c.Status(http.StatusNoContent)
}

// ** BLUEPRINTS

// GetBlueprintByUserStr retrieves a custom blueprint by userstr.
func (a *RESTApiService) GetBlueprintByUserStr(c *gin.Context) {
	userstrParam := c.Query("userstr")
	if userstrParam == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"status": http.StatusBadRequest,
			"msg":    "userstr parameter is required",
		})
		return
	}

	userStr, err := models.NewUserStr(userstrParam)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"status": http.StatusBadRequest,
			"msg":    fmt.Sprintf("Invalid userstr: %v", err),
		})
		return
	}

	customBlueprint, err := a.server.GetCustomBlueprint(userStr)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"status": http.StatusNotFound,
			"msg":    fmt.Sprintf("Blueprint not found: %v", err),
		})
		return
	}

	c.JSON(http.StatusOK, customBlueprint)
}
