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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	_ "github.com/k8shell-io/identity/docs"
	"github.com/k8shell-io/identity/internal/backend"
	"github.com/k8shell-io/identity/internal/log"
	"github.com/k8shell-io/identity/pkg/models"
	"github.com/rs/zerolog"
	httpSwagger "github.com/swaggo/http-swagger"
)

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
}

// responseRecorder is a wrapper for http.ResponseWriter
// to capture the status code and response body.
type responseRecorder struct {
	http.ResponseWriter
	statusCode int
	body       bytes.Buffer
}

// WriteHeader captures the status code and forwards it to the original ResponseWriter
func (rec *responseRecorder) WriteHeader(code int) {
	rec.statusCode = code
	rec.ResponseWriter.WriteHeader(code)
}

// Write captures the response body and writes it to the original ResponseWriter
func (rec *responseRecorder) Write(data []byte) (int, error) {
	rec.body.Write(data)
	return rec.ResponseWriter.Write(data)
}

// writeJSONError writes a JSON error response with the given status code and message.
func writeJSONError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status": status,
		"msg":    msg,
	})
}

// * Models for REST API requests and responses

// AuthenticateUserRequest represents the request body for user authentication
type AuthenticateUserRequest struct {
	PublicKey string `json:"public_key"`
}

// AuthenticateUserResponse represents the response body for user authentication
type AuthenticateUserResponse struct {
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

// CanOnboardUserResponse represents the response body for checking if a user can be onboarded
type CanOnboardUserResponse struct {
	CanOnboard bool `json:"can_onboard"`
}

// NewRESTAPI creates a new REST API service
func NewRESTAPI(httpConfig HttpConfig, server *Server) (*RESTApiService, error) {
	log := log.NewLogger("api")

	return &RESTApiService{
		httpConfig: httpConfig,
		log:        log,
		server:     server,
	}, nil
}

// apiKeyMiddleware checks for the presence of a valid API key in the request header
// and allows access to the API endpoints only if the key matches the configured one.
func (a *RESTApiService) apiKeyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		const prefix = "Bearer "

		if !strings.HasPrefix(authHeader, prefix) {
			http.Error(w, "Unauthorized: missing or malformed Authorization header", http.StatusUnauthorized)
			return
		}

		providedKey := strings.TrimPrefix(authHeader, prefix)
		expectedKey := a.httpConfig.APIKey

		if providedKey != expectedKey {
			http.Error(w, "Unauthorized: invalid API key", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// Middleware to log requests and responses
func (a *RESTApiService) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.log.Debug().Msgf("Request: method %s, path %s", r.Method, r.URL.Path)
		rec := &responseRecorder{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(rec, r)
		a.log.Debug().Msgf("Response: status %d, body: %s", rec.statusCode, rec.body.String())
	})
}

// Initialize the router
func (a *RESTApiService) initializeRouter() *mux.Router {
	router := mux.NewRouter()

	// api router with API key middleware
	apiRouter := router.PathPrefix("/api/v1").Subrouter()
	apiRouter.Use(a.apiKeyMiddleware)
	apiRouter.Use(a.loggingMiddleware)

	// Define API endpoints
	apiRouter.HandleFunc("/users", a.GetUsers).Methods(http.MethodGet)
	apiRouter.HandleFunc("/users/{username}", a.FindUser).Methods(http.MethodGet)
	apiRouter.HandleFunc("/users/{username}/onboard", a.OnboardUserDeviceFlow).Methods(http.MethodPost)
	apiRouter.HandleFunc("/users/{username}/authenticate", a.AuthenticateUser).Methods(http.MethodPost)

	apiRouter.HandleFunc("/users/{username}/sessions", a.GetSSHSessions).Methods(http.MethodGet)
	apiRouter.HandleFunc("/users/{username}/sessions", a.CreateSSHSession).Methods(http.MethodPost)
	apiRouter.HandleFunc("/users/{username}/sessions/{sessionId}", a.GetSSHSession).Methods(http.MethodGet)
	apiRouter.HandleFunc("/users/{username}/sessions/{sessionId}", a.UpdateSSHSession).Methods(http.MethodPatch)
	apiRouter.HandleFunc("/users/{username}/sessions/{sessionId}/end", a.EndSSHSession).Methods(http.MethodPost)

	a.logRoutes(router)

	router.NotFoundHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.log.Debug().Msgf("404 Not Found: %s %s", r.Method, r.URL.Path)
		http.Error(w, "404 route not found", http.StatusNotFound)
	})

	router.PathPrefix("/swagger/").Handler(httpSwagger.WrapHandler)

	return router
}

func (a *RESTApiService) Serve(ctx context.Context) {
	server := &http.Server{
		Handler: a.initializeRouter(),
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

// logRoutes logs all registered routes in the router
func (a *RESTApiService) logRoutes(router *mux.Router) {
	err := router.Walk(func(route *mux.Route, router *mux.Router, ancestors []*mux.Route) error {
		path, err := route.GetPathTemplate()
		if err != nil {
			path = "<undefined>"
		}

		methods, err := route.GetMethods()
		if err != nil {
			methods = []string{"<any>"}
		}

		a.log.Debug().Msgf("Route: %s Methods: %v", path, methods)
		return nil
	})

	if err != nil {
		a.log.Error().Msgf("Error walking routes: %v", err)
	}
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
// @Param        limit   query     int  		false  "Number of users to return"
// @Param        offset  query     int  		false  "Offset for pagination"
// @Success      200     {array}   models.User
// @Security     BearerAuth
// @Router       /api/v1/users [get]
// GetUsers retrieves a list of users with pagination support.
func (a *RESTApiService) GetUsers(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	limit := parseQueryInt(query.Get("limit"), backend.DefaultListLimit)
	offset := parseQueryInt(query.Get("offset"), 0)

	users, err := a.server.DB.ListUsers(limit, offset)
	if err != nil {
		a.log.Error().Err(err).Msg("Failed to list users from database")
		writeJSONError(w, http.StatusInternalServerError, "Failed to list users")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(w).Encode(users); err != nil {
		a.log.Error().Err(err).Msg("Failed to encode users to JSON")
		writeJSONError(w, http.StatusInternalServerError, "Failed to encode users")
		return
	}
}

// FindUser godoc
// @Summary      Get user details
// @Description  Retrieves information for a single user by username.
// @Tags         users
// @Accept       json
// @Produce      json
// @Param        username  path      string         true  "Username to look up"
// @Success      200       {object}  models.User
// @Failure      400       {string}  string  		"Missing username"
// @Failure      404       {string}  string  		"User not found"
// @Security     BearerAuth
// @Router       /api/v1/users/{username} [get]
// FindUser retrieves a user by their username and returns their details.
func (a *RESTApiService) FindUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	username := vars["username"]
	if username == "" {
		writeJSONError(w, http.StatusBadRequest, "Username is required")
		return
	}

	user, err := a.server.GetUser(username)
	if err != nil {
		a.log.Error().Err(err).Msgf("Failed to find user '%s'", username)
		if errors.Is(err, models.ErrUserNotFound) {
			writeJSONError(w, http.StatusNotFound, fmt.Sprintf("User '%s' not found", username))
		} else {
			writeJSONError(w, http.StatusInternalServerError, "Failed to find user")
		}
		return
	}
	if user == nil {
		writeJSONError(w, http.StatusNotFound, fmt.Sprintf("User '%s' not found", username))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(user); err != nil {
		a.log.Error().Err(err).Msg("Failed to encode user JSON")
		writeJSONError(w, http.StatusInternalServerError, "Failed to encode user response")
		return
	}
}

// AuthenticateUser godoc
// @Summary      Authenticate user by public key
// @Description  Validates a user's SSH public key to determine if authentication is allowed.
// @Tags         users
// @Accept       json
// @Produce      json
// @Param        username  path      string                      true  "Username to authenticate"
// @Param        request   body      AuthenticateUserRequest     true  "Public key request payload"
// @Success      200       {object}  AuthenticateUserResponse
// @Failure      400       {string}  string  "Missing or invalid data"
// @Security     BearerAuth
// @Router       /api/v1/users/{username}/authenticate [post]
// AuthenticateUser checks if the user exists and is valid, then authenticates them using the provided public key.
func (a *RESTApiService) AuthenticateUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	username := vars["username"]
	if username == "" {
		writeJSONError(w, http.StatusBadRequest, "Username is required")
		return
	}

	var req AuthenticateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.log.Error().Err(err).Msg("Failed to decode request body")
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.PublicKey == "" {
		writeJSONError(w, http.StatusBadRequest, "Public key is required")
		return
	}

	isAuthenticated, err := a.server.AuthenticateUser(username, req.PublicKey)
	if err != nil {
		a.log.Error().Err(err).Msgf("Failed to authenticate user '%s'", username)
		writeJSONError(w, http.StatusInternalServerError, "Failed to authenticate user")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	var response AuthenticateUserResponse = AuthenticateUserResponse{
		Authenticated: isAuthenticated,
	}
	if err := json.NewEncoder(w).Encode(response); err != nil {
		a.log.Error().Err(err).Msg("Failed to encode authentication response")
		writeJSONError(w, http.StatusInternalServerError, "Failed to encode response")
		return
	}
}

// OnboardUserDeviceFlow godoc
// @Summary      Onboard user
// @Description  Initiates the Device Authorization Flow to onboard a user with a given username.
// @Tags         users
// @Accept       json
// @Produce      json
// @Param        username  path      string  true  "Username to onboard"
// @Success      200       {object}  models.OnboardUser
// @Failure      400       {string}  string  "Missing username"
// @Security     BearerAuth
// @Router       /api/v1/users/{username}/onboard [post]
// OnboardUserDeviceFlow initiates the Device Authorization Flow to onboard a user.
func (a *RESTApiService) OnboardUserDeviceFlow(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	username := vars["username"]
	if username == "" {
		writeJSONError(w, http.StatusBadRequest, "Username is required")
		return
	}

	onboardUser, err := a.server.OnboardUserDeviceFlow(username)
	if err != nil {
		if errors.Is(err, models.ErrOnboardingPending) {
			writeJSONError(w, http.StatusBadRequest, "User onboarding is already in progress")
			return
		} else if errors.Is(err, models.ErrUserNotFound) {
			writeJSONError(w, http.StatusNotFound, fmt.Sprintf("User '%s' not found", username))
			return
		} else if errors.Is(err, models.ErrAlreadyOnboarded) {
			writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("User '%s' is already onboarded", username))
			return
		} else {
			a.log.Error().Err(err).Msgf("Failed to onboard user '%s'", username)
			writeJSONError(w, http.StatusBadRequest, "Failed to onboard user")
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(onboardUser); err != nil {
		a.log.Error().Err(err).Msg("Failed to encode onboard user response")
		writeJSONError(w, http.StatusInternalServerError, "Failed to encode onboard user response")
		return
	}
}

// CanOnboardUser godoc
// @Summary      Check if user can be onboarded
// @Description  Checks if a user can be onboarded using the Device Authorization Flow.
// @Tags         users
// @Accept       json
// @Produce      json
// @Param        username  path      string  true  "Username to check onboarding capability"
// @Success      200       {object}  CanOnboardUserResponse
// @Failure      400       {string}  string  "Missing username"
// @Security     BearerAuth
// @Router       /api/v1/users/{username}/can_onboard [get]
// CanOnboardUser checks if a user can be onboarded using the Device Authorization Flow.
func (a *RESTApiService) CanOnboardUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	username := vars["username"]
	if username == "" {
		writeJSONError(w, http.StatusBadRequest, "Username is required")
		return
	}

	canOnboard, err := a.server.CanOnboardUser(username)
	if err != nil {
		a.log.Error().Err(err).Msgf("Failed to check if user '%s' can be onboarded", username)
		writeJSONError(w, http.StatusInternalServerError, "Failed to check onboarding capability")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	canOnboardResponse := CanOnboardUserResponse{
		CanOnboard: canOnboard,
	}
	if err := json.NewEncoder(w).Encode(canOnboardResponse); err != nil {
		a.log.Error().Err(err).Msg("Failed to encode onboarding capability response")
		writeJSONError(w, http.StatusInternalServerError, "Failed to encode onboarding capability response")
		return
	}
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
// @Success      200       {array}   models.SSHSession
// @Failure      400       {string}  string  "Missing or invalid data"
// @Failure      404       {string}  string  "User not found"
// @Security     BearerAuth
// @Router       /api/v1/users/{username}/sessions [get]
// GetSSHSessions retrieves a list of SSH sessions for a user with pagination and sorting options.
func (a *RESTApiService) GetSSHSessions(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	limit := parseQueryInt(query.Get("limit"), backend.DefaultListLimit)
	offset := parseQueryInt(query.Get("offset"), 0)
	reverse := query.Get("reverse") == "true"

	vars := mux.Vars(r)
	username := vars["username"]
	if username == "" {
		writeJSONError(w, http.StatusBadRequest, "Username is required")
		return
	}
	sessions, err := a.server.GetSSHSessions(username, limit, offset, reverse)
	if err != nil {
		a.log.Error().Err(err).Msgf("Failed to get SSH sessions for user '%s'", username)
		writeJSONError(w, http.StatusInternalServerError, "Failed to get SSH sessions")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(sessions); err != nil {
		a.log.Error().Err(err).Msg("Failed to encode SSH sessions response")
		writeJSONError(w, http.StatusInternalServerError, "Failed to encode SSH sessions response")
		return
	}
}

// GetSSHSession godoc
// @Summary      Get SSH session by ID
// @Description  Retrieves a specific SSH session by its ID for a user.
// @Tags         sessions
// @Accept       json
// @Produce      json
// @Param        username   path      string  true  "Username to get session for"
// @Param        sessionId  path      int     true  "Session ID to retrieve"
// @Success      200        {object}  models.SSHSession
// @Failure      400        {string}  string  "Missing or invalid data"
// @Failure      404        {string}  string  "Session not found"
// @Failure      500        {string}  string  "Failed to get SSH session"
// @Security     BearerAuth
// @Router       /api/v1/users/{username}/sessions/{sessionId} [get]
// GetSSHSession retrieves a specific SSH session by its ID for a user.
func (a *RESTApiService) GetSSHSession(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	username := vars["username"]
	if username == "" {
		writeJSONError(w, http.StatusBadRequest, "Username is required")
		return
	}

	sessionIdStr := vars["sessionId"]
	if sessionIdStr == "" {
		writeJSONError(w, http.StatusBadRequest, "Session ID is required")
		return
	}
	id64, err := strconv.ParseInt(sessionIdStr, 10, 32)
	if err != nil {
		a.log.Error().Err(err).Msgf("Invalid session ID '%s' for user '%s'", sessionIdStr, username)
		writeJSONError(w, http.StatusBadRequest, "Invalid session ID")
		return
	}
	sessionId := int32(id64)

	sessions, err := a.server.GetSSHSession(username, sessionId)
	if err != nil {
		a.log.Error().Err(err).Msgf("Failed to get SSH session '%d' for user '%s': %s", sessionId, username, err)
		if errors.Is(err, models.ErrSessionNotFound) {
			writeJSONError(w, http.StatusNotFound, fmt.Sprintf("Session ID %d for user '%s' not found", sessionId, username))
		} else {
			writeJSONError(w, http.StatusInternalServerError, "Failed to get SSH session")
		}
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(sessions); err != nil {
		a.log.Error().Err(err).Msg("Failed to encode SSH session response")
		writeJSONError(w, http.StatusInternalServerError, "Failed to encode SSH session response")
		return
	}
}

// CreateSSHSession godoc
// @Summary      Create SSH session
// @Description  Creates a new SSH session for a user in a specified workspace.
// @Tags         sessions
// @Accept       json
// @Produce      json
// @Param        username  path      string                     true  "Username to create session for"
// @Param        request   body      CreateSSHSessionRequest    true  "SSH session request payload"
// @Success      200       {object}  models.SSHSession
// @Failure      400       {string}  string  "Missing or invalid data"
// @Failure      500       {string}  string  "Failed to create SSH session"
// @Security     BearerAuth
// @Router       /api/v1/users/{username}/sessions [post]
func (a *RESTApiService) CreateSSHSession(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	username := vars["username"]
	if username == "" {
		writeJSONError(w, http.StatusBadRequest, "Username is required")
		return
	}

	var req CreateSSHSessionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.log.Error().Err(err).Msg("Failed to decode request body")
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	session, err := a.server.CreateSSHSession(username, req.Workspace, req.ProxyID, req.ProxyPID, req.ClientIP)
	if err != nil {
		a.log.Error().Err(err).Msgf("Failed to create SSH session for user '%s'", username)
		writeJSONError(w, http.StatusInternalServerError, "Failed to create SSH session")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Location", fmt.Sprintf("/api/v1/users/%s/sessions/%d", username, session.SessionID))
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(session); err != nil {
		a.log.Error().Err(err).Msg("Failed to encode SSH session")
		writeJSONError(w, http.StatusInternalServerError, "Failed to encode SSH session")
		return
	}
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
func (a *RESTApiService) UpdateSSHSession(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	username := vars["username"]
	sessionIDStr := vars["sessionId"]
	if username == "" || sessionIDStr == "" {
		writeJSONError(w, http.StatusBadRequest, "Username and session ID are required")
		return
	}

	sessionID, err := strconv.Atoi(sessionIDStr)
	if err != nil || sessionID <= 0 {
		writeJSONError(w, http.StatusBadRequest, "Invalid session ID")
		return
	}

	var req UpdateSSHSessionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.log.Error().Err(err).Msg("Failed to decode request body")
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	err = a.server.UpdateSSHSession(username, int32(sessionID), req.BytesIn, req.BytesOut, req.Client,
		req.ProvTime, req.Channels)
	if err != nil {
		a.log.Error().Err(err).Msgf("Failed to update SSH session for user '%s': %s", username, err)
		if errors.Is(err, models.ErrActiveSessionNotFound) {
			writeJSONError(w, http.StatusNotFound, fmt.Sprintf("Session ID %d for user '%s' not found or already ended", sessionID, username))
		} else {
			writeJSONError(w, http.StatusInternalServerError, "Failed to update SSH session")
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
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
func (a *RESTApiService) EndSSHSession(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	username := vars["username"]
	sessionIDStr := vars["sessionId"]
	if username == "" || sessionIDStr == "" {
		writeJSONError(w, http.StatusBadRequest, "Username and session ID are required")
		return
	}

	sessionID, err := strconv.Atoi(sessionIDStr)
	if err != nil || sessionID <= 0 {
		writeJSONError(w, http.StatusBadRequest, "Invalid session ID")
		return
	}

	err = a.server.EndSSHSession(username, int32(sessionID))
	if err != nil {
		a.log.Error().Err(err).Msgf("Failed to end SSH session for user '%s': %s", username, err)
		if errors.Is(err, models.ErrActiveSessionNotFound) {
			writeJSONError(w, http.StatusNotFound, fmt.Sprintf("Session ID %d for user '%s' not found or already ended", sessionID, username))
		} else {
			writeJSONError(w, http.StatusInternalServerError, "Failed to end SSH session")
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
