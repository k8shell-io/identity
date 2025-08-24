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
	_ "github.com/k8shell-io/identity/docs"
	"github.com/k8shell-io/identity/internal/backend"
	"github.com/k8shell-io/identity/pkg/client"
	"github.com/rs/zerolog"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
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
			users.GET("/:username", a.FindUser)
			users.GET("/:username/onboardcap", a.OnboardCapability)
			users.POST("/:username/onboard", a.OnboardUserDeviceFlow)
			users.POST("/:username/authpublickey", a.AuthPublicKey)
			users.GET("/:username/token", a.GetUserToken)

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

	router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

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

// GetUsers godoc
// @Summary      List users
// @Description  Returns a paginated list of users.
// @Tags         users
// @Accept       json
// @Produce      json
// @Param        limit   query     int  false  "Number of users to return"
// @Param        offset  query     int  false  "Offset for pagination"
// @Success      200     {array}   User
// @Security     BearerAuth
// @Router       /api/v1/users [get]
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

// FindUser godoc
// @Summary      Get user details
// @Description  Retrieves information for a single user by username.
// @Tags         users
// @Accept       json
// @Produce      json
// @Param        username  path      string  true  "Username to look up"
// @Success      200       {object}  User
// @Failure      400       {string}  string  "Missing username"
// @Failure      404       {string}  string  "User not found"
// @Security     BearerAuth
// @Router       /api/v1/users/{username} [get]
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

// FindUserByUserStr godoc
// @Summary      Find user by userstr
// @Description  Retrieves a user by parsing a userstr structure.
// @Tags         users
// @Accept       json
// @Produce      json
// @Param        userstr   query     string  true  "Userstr to parse and lookup user"
// @Success      200       {object}  User
// @Failure      400       {string}  string  "Missing or invalid userstr"
// @Failure      404       {string}  string  "User not found"
// @Security     BearerAuth
// @Router       /api/v1/users/lookup [get]
func (a *RESTApiService) FindUserByUserStr(c *gin.Context) {
	userstrParam := c.Query("userstr")
	if userstrParam == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"status": http.StatusBadRequest,
			"msg":    "userstr parameter is required",
		})
		return
	}

	// TODO: Parse the userstr using your pkg/userstr package
	// parsedUserStr, err := userstr.Parse(userstrParam)
	// if err != nil {
	//     a.log.Error().Err(err).Msgf("Failed to parse userstr '%s'", userstrParam)
	//     c.JSON(http.StatusBadRequest, gin.H{
	//         "status": http.StatusBadRequest,
	//         "msg":    fmt.Sprintf("Invalid userstr: %v", err),
	//     })
	//     return
	// }

	// username := parsedUserStr.Username

	// For now, using userstrParam directly as username
	username := userstrParam

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

// AuthPublicKey godoc
// @Summary      Authenticate user by public key
// @Description  Validates a user's SSH public key to determine if authentication is allowed.
// @Tags         users
// @Accept       json
// @Produce      json
// @Param        username  path      string              			 true  "Username to authenticate"
// @Param        request   body      AuthPublicKeyRequest     true  "Public key request payload"
// @Success      200       {object}  AuthPublicKeyResponse
// @Failure      400       {string}  string  "Missing or invalid data"
// @Security     BearerAuth
// @Router       /api/v1/users/{username}/authpublickey [post]
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

// OnboardUserDeviceFlow godoc
// @Summary      Onboard user
// @Description  Initiates the Device Authorization Flow to onboard a user with a given username.
// @Tags         users
// @Accept       json
// @Produce      json
// @Param        username  path      string  true  "Username to onboard"
// @Success      200       {object}  OnboardUser
// @Failure      400       {string}  string  "Missing username"
// @Security     BearerAuth
// @Router       /api/v1/users/{username}/onboard [post]
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

// OnboardCapability godoc
// @Summary      Check if user can be onboarded
// @Description  Checks if a user can be onboarded using the Device Authorization Flow.
// @Tags         users
// @Accept       json
// @Produce      json
// @Param        username  path      string  true  "Username to check onboarding capability"
// @Success      200       {object}  OnboardCapability
// @Failure      404       {string}  string  "User not found"
// @Failure      500       {string}  string  "Failed to check onboarding capability"
// @Security     BearerAuth
// @Router       /api/v1/users/{username}/onboardcap [get]
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

// GetUserToken godoc
// @Summary      Get user token
// @Description  Retrieves a user token for the specified username.
// @Tags         users
// @Accept       json
// @Produce      json
// @Param        username  path      string  true  "Username to get token for"
// @Success      200       {object}  UserToken
// @Failure      400       {string}  string  "Missing username"
// @Failure      404       {string}  string  "User not found"
// @Failure      500       {string}  string  "Failed to get user token"
// @Security     BearerAuth
// @Router       /api/v1/users/{username}/token [get]
func (a *RESTApiService) GetUserToken(c *gin.Context) {
	username := c.Param("username")
	if username == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"status": http.StatusBadRequest,
			"msg":    "Username is required",
		})
		return
	}

	token, err := a.server.GetUserToken(username)
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

	c.JSON(http.StatusOK, token)
}

// ** SSH SESSIONS

// GetSSHSessions godoc
// @Summary      List SSH sessions for a user
// @Description  Returns a paginated list of SSH sessions for a user.
// @Tags         sessions
// @Accept       json
// @Produce      json
// @Param        username  path      string  true  "Username to list sessions for"
// @Param        limit     query     int     false  "Number of sessions to return"
// @Param        offset    query     int     false  "Offset for pagination"
// @Param        reverse   query     bool    false  "Reverse order of sessions"
// @Success      200       {array}   SSHSession
// @Failure      400       {string}  string  "Missing or invalid data"
// @Failure      404       {string}  string  "User not found"
// @Security     BearerAuth
// @Router       /api/v1/users/{username}/sessions [get]
func (a *RESTApiService) GetSSHSessions(c *gin.Context) {
	username := c.Param("username")
	if username == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"status": http.StatusBadRequest,
			"msg":    "Username is required",
		})
		return
	}

	limit := parseQueryInt(c.Query("limit"), backend.DefaultListLimit)
	offset := parseQueryInt(c.Query("offset"), 0)
	reverse := c.Query("reverse") == "true"

	sessions, err := a.server.GetSSHSessions(username, limit, offset, reverse)
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

// GetSSHSession godoc
// @Summary      Get SSH session by ID
// @Description  Retrieves a specific SSH session by its ID for a user.
// @Tags         sessions
// @Accept       json
// @Produce      json
// @Param        username   path      string  true  "Username to get session for"
// @Param        sessionId  path      int     true  "Session ID to retrieve"
// @Success      200        {object}  SSHSession
// @Failure      400        {string}  string  "Missing or invalid data"
// @Failure      404        {string}  string  "Session not found"
// @Failure      500        {string}  string  "Failed to get SSH session"
// @Security     BearerAuth
// @Router       /api/v1/users/{username}/sessions/{sessionId} [get]
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

// CreateSSHSession godoc
// @Summary      Create SSH session
// @Description  Creates a new SSH session for a user in a specified workspace.
// @Tags         sessions
// @Accept       json
// @Produce      json
// @Param        username  path      string                     true  "Username to create session for"
// @Param        request   body      CreateSSHSessionRequest    true  "SSH session request payload"
// @Success      200       {object}  SSHSession
// @Failure      400       {string}  string  "Missing or invalid data"
// @Failure      500       {string}  string  "Failed to create SSH session"
// @Security     BearerAuth
// @Router       /api/v1/users/{username}/sessions [post]
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

	session, err := a.server.CreateSSHSession(username, req.Workspace, req.ProxyID, req.ProxyPID, req.ClientIP)
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

// UpdateSSHSession godoc
// @Summary      Update SSH session
// @Description  Updates an existing SSH session with new data such as bytes in/out and client info.
// @Tags         sessions
// @Accept       json
// @Produce      json
// @Param        username   path      string                     true  "Username to update session for"
// @Param        sessionId  path      int                        true  "Session ID to update"
// @Param        request    body      UpdateSSHSessionRequest    true  "SSH session update request payload"
// @Success      204       {string}  string  "SSH session updated successfully"
// @Failure      400       {string}  string  "Missing or invalid data"
// @Failure      404       {string}  string  "Session not found"
// @Failure      500       {string}  string  "Failed to update SSH session"
// @Security     BearerAuth
// @Router       /api/v1/users/{username}/sessions/{sessionId} [patch]
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
		req.ProvTime, req.Channels)
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

// EndSSHSession godoc
// @Summary      End SSH session
// @Description  Marks an SSH session as ended by setting the end time.
// @Tags         sessions
// @Accept       json
// @Produce      json
// @Param        username   path      string  true  "Username to end session for"
// @Param        sessionId  path      int     true  "Session ID to end"
// @Success      204       {string}  string  "SSH session ended successfully"
// @Failure      400       {string}  string  "Missing or invalid data"
// @Failure      404       {string}  string  "Session not found"
// @Failure      500       {string}  string  "Failed to end SSH session"
// @Security     BearerAuth
// @Router       /api/v1/users/{username}/sessions/{sessionId}/end [post]
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

// GetBlueprintByUserStr godoc
// @Summary      Get blueprint by userstr
// @Description  Retrieves a custom blueprint definition from a user repository.
// @Tags         blueprints
// @Accept       json
// @Produce      json
// @Param        userstr   query     string  true  "Userstr containing repo owner and name"
// @Success      200       {object}  models.CustomBlueprint
// @Failure      400       {string}  string  "Missing or invalid userstr"
// @Security     BearerAuth
// @Router       /api/v1/blueprints/lookup [get]
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
