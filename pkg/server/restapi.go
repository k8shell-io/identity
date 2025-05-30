package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/k8shell-io/identity/pkg/backend"
	"github.com/k8shell-io/identity/pkg/log"
	"github.com/rs/zerolog"
)

type HttpConfig struct {
	Port   int    `yaml:"port"`
	APIKey string `yaml:"APIKey"`
}

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

// AuthenticateUserRequest represents the request body for user authentication
type AuthenticateUserRequest struct {
	PublicKey string `json:"public_key"`
}

// AuthenticateUserResponse represents the response body for user authentication
type AuthenticateUserResponse struct {
	Authenticated bool `json:"authenticated"`
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

// NewRESTAPI creates a new REST API service
func NewRESTAPI(httpConfig HttpConfig, server *Server) (*RESTApiService, error) {
	log := log.NewLogger("api")

	return &RESTApiService{
		httpConfig: httpConfig,
		log:        log,
		server:     server,
	}, nil
}

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

	// middlewares
	router.Use(a.apiKeyMiddleware)
	router.Use(a.loggingMiddleware)

	// Add token middleware
	apiRouter := router.PathPrefix("/api/v1").Subrouter()

	// Define API endpoints
	apiRouter.HandleFunc("/users", a.GetUsers).Methods(http.MethodGet)
	apiRouter.HandleFunc("/users/{username}", a.FindUser).Methods(http.MethodGet)
	apiRouter.HandleFunc("/users/{username}/onboard", a.OnboardUser).Methods(http.MethodPost)
	apiRouter.HandleFunc("/users/{username}/authenticate", a.AuthenticateUser).Methods(http.MethodPost)
	apiRouter.HandleFunc("/users", a.AddUser).Methods(http.MethodPost)
	a.logRoutes(router)

	router.NotFoundHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.log.Debug().Msgf("404 Not Found: %s %s", r.Method, r.URL.Path)
		http.Error(w, "404 route not found", http.StatusNotFound)
	})

	return router
}

func (a *RESTApiService) GetUsers(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	limit := parseQueryInt(query.Get("limit"), backend.DefaultListUserLimit)
	offset := parseQueryInt(query.Get("offset"), 0)

	users, err := a.server.DB.ListUsers(limit, offset)
	if err != nil {
		a.log.Error().Err(err).Msg("Failed to list users from database")
		http.Error(w, "Failed to list users", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(w).Encode(users); err != nil {
		a.log.Error().Err(err).Msg("Failed to encode users to JSON")
		http.Error(w, "Failed to encode users", http.StatusInternalServerError)
		return
	}
}

func (a *RESTApiService) FindUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	username := vars["username"]
	if username == "" {
		http.Error(w, "Username is required", http.StatusBadRequest)
		return
	}

	user, err := a.server.GetUser(username)
	if err != nil {
		a.log.Error().Err(err).Msgf("Failed to find user '%s'", username)
		http.Error(w, "Failed to find user", http.StatusInternalServerError)
		return
	}
	if user == nil {
		http.Error(w, fmt.Sprintf("User '%s' not found", username), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(user); err != nil {
		a.log.Error().Err(err).Msg("Failed to encode user JSON")
		http.Error(w, "Failed to encode user", http.StatusInternalServerError)
		return
	}
}

func (a *RESTApiService) AuthenticateUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	username := vars["username"]
	if username == "" {
		http.Error(w, "Username is required", http.StatusBadRequest)
		return
	}

	var req AuthenticateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.log.Error().Err(err).Msg("Failed to decode request body")
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.PublicKey == "" {
		http.Error(w, "Public key is required", http.StatusBadRequest)
		return
	}

	isAuthenticated, err := a.server.AuthenticateUser(username, req.PublicKey)
	if err != nil {
		a.log.Error().Err(err).Msgf("Failed to authenticate user '%s'", username)
		http.Error(w, "Authentication failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	var response AuthenticateUserResponse = AuthenticateUserResponse{
		Authenticated: isAuthenticated,
	}
	if err := json.NewEncoder(w).Encode(response); err != nil {
		a.log.Error().Err(err).Msg("Failed to encode authentication response")
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

func (a *RESTApiService) AddUser(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusCreated)
	w.Write([]byte("Not implemented"))
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

// OnboardUser handles user onboarding
func (a *RESTApiService) OnboardUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	username := vars["username"]
	if username == "" {
		http.Error(w, "Username is required", http.StatusBadRequest)
		return
	}

	onboardUser, err := a.server.OnboardUser(username)
	if err != nil {
		a.log.Error().Err(err).Msgf("Failed to onboard user '%s'", username)
		http.Error(w, "Failed to onboard user", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(onboardUser); err != nil {
		a.log.Error().Err(err).Msg("Failed to encode onboard user response")
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

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
