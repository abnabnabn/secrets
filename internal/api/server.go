// Package api implements the HTTP secrets manager interface, providing endpoints for
// secret management, token provisioning, and administrative tasks.
package api

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"tiny-secrets-manager/internal/config"
	"tiny-secrets-manager/internal/store"
)

// Storage defines the interface for the backend storage engine, enabling dependency injection.
type Storage interface {
	GetRoleByHash(ctx context.Context, hash []byte) (*store.RoleRecord, error)
	GetRoleByName(ctx context.Context, name string) (*store.RoleRecord, error)
	ExtendRoleExpiry(ctx context.Context, name string, newExpiry time.Time) error
	List(ctx context.Context, global bool, prefixes []string, after string, limit int) ([]string, error)
	Get(ctx context.Context, key string) ([]byte, error)
	Put(ctx context.Context, key string, plaintext []byte) error
	Delete(ctx context.Context, key string) error
	ListRoles(ctx context.Context) ([]store.RoleRecord, error)
	PutRole(ctx context.Context, name string, tokenHash []byte, policiesJSON []byte, isAdmin bool, canCreate bool, expiresAt *time.Time) error
	UpdateRole(ctx context.Context, name string, policiesJSON []byte, canCreate bool, expiresAt *time.Time) error
	UpdateRoleToken(ctx context.Context, name string, newTokenHash []byte) error
	DeleteRole(ctx context.Context, name string) error
	RegenerateRecoveryKeys(ctx context.Context) ([]string, error)
	GetAllSettings(ctx context.Context) (map[string]string, error)
	PutSetting(ctx context.Context, key, value string) error
	GetSetting(ctx context.Context, key string) (string, error)
	Backup(ctx context.Context, dst string) error
	DeleteExpiredRoles(ctx context.Context) (int64, error)
	GetAdmin(ctx context.Context, username string) (string, error)
}

type contextKey int

const clientCtxKey contextKey = iota

const maxPayloadBytes = 1 << 20 // 1MB constraint
const dbTimeout = 5 * time.Second

// Client represents an authenticated entity (Admin or Machine Token).
type Client struct {
	Name      string          `json:"name"`
	IsAdmin   bool            `json:"is_admin"`
	CanCreate bool            `json:"can_create"`
	Policies  []config.Policy `json:"policies"`
}

// Can evaluates if the client has permission to perform a specific HTTP method
// on a given secrets manager path, respecting strict segment matching and wildcards.
func (c Client) Can(method, path string) bool {
	if c.IsAdmin {
		return true
	}
	for _, p := range c.Policies {
		matched := false
		// Path Matching Logic:
		// 1. "*" matches everything.
		// 2. "prefix*" matches anything starting with the prefix (traditional starts-with).
		// 3. "prefix" (default) matches the exact key OR any sub-segment (prefix.segment).
		//    This prevents "home" from matching "homeowner" while allowing "home.secret".
		if p.Prefix == "*" {
			matched = true
		} else if strings.HasSuffix(p.Prefix, "*") {
			matched = strings.HasPrefix(path, strings.TrimSuffix(p.Prefix, "*"))
		} else {
			matched = path == p.Prefix || strings.HasPrefix(path, p.Prefix+".")
		}

		if matched {
			for _, m := range p.Methods {
				if m == method || m == "*" {
					return true
				}
			}
		}
	}
	return false
}

// Server holds the application state and dependencies for the API handlers.
type Server struct {
	store         Storage
	cfg           *config.Config
	logger        *slog.Logger
	version       string
	backupTrigger chan struct{}
}

// NewServer initializes a new API server instance.
func NewServer(s Storage, cfg *config.Config, logger *slog.Logger, version string) *Server {
	srv := &Server{
		store:         s,
		cfg:           cfg,
		logger:        logger,
		version:       version,
		backupTrigger: make(chan struct{}, 1),
	}
	go srv.backupLoop()
	return srv
}

// ErrorResponse represents a standardized JSON error message.
type ErrorResponse struct {
	Error  string `json:"error"`
	Status int    `json:"status"`
}

// respondError writes a structured JSON error to the response.
func (s *Server) respondError(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(ErrorResponse{
		Error:  message,
		Status: code,
	})
}

// respondJSON writes a structured JSON payload to the response.
func (s *Server) respondJSON(w http.ResponseWriter, code int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(payload)
}

// RegisterRoutes maps the secrets manager's API endpoints to their respective handlers.
func (s *Server) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/auth/login", s.handleLogin)
	mux.HandleFunc("POST /v1/auth/logout", s.handleLogout)
	mux.HandleFunc("GET /v1/auth/me", s.auth(s.handleAuthMe))
	mux.HandleFunc("GET /v1/secrets", s.auth(s.handleListSecrets))
	mux.HandleFunc("GET /v1/secrets/{key}", s.auth(s.handleGetSecret))
	mux.HandleFunc("PUT /v1/secrets/{key}", s.auth(s.handlePutSecret))
	mux.HandleFunc("DELETE /v1/secrets/{key}", s.auth(s.handleDeleteSecret))
	mux.HandleFunc("POST /v1/secrets/resolve", s.auth(s.handleResolveSecret))
	mux.HandleFunc("GET /v1/roles", s.auth(s.handleListRoles))
	mux.HandleFunc("POST /v1/roles", s.auth(s.handleCreateRole))
	mux.HandleFunc("PUT /v1/roles/{name}", s.auth(s.handleUpdateRole))
	mux.HandleFunc("DELETE /v1/roles/{name}", s.auth(s.handleDeleteRole))
	mux.HandleFunc("POST /v1/roles/{name}/regenerate", s.auth(s.handleRegenerateRoleToken))
	mux.HandleFunc("POST /v1/recovery-keys/regenerate", s.auth(s.handleRegenerateRecoveryKeys))

	mux.HandleFunc("GET /v1/system/settings", s.auth(s.handleGetSettings))
	mux.HandleFunc("PUT /v1/system/settings", s.auth(s.handlePutSettings))
	mux.HandleFunc("POST /v1/system/backup", s.auth(s.handleTriggerBackup))
}

var variableRegex = regexp.MustCompile(`\$\{([^}]+)\}`)

// resolveVariables parses text for ${key} patterns and replaces them with their
// corresponding secret values, provided the client has GET permission for them.
// A visited map is used to prevent infinite recursive resolution in case of circular references.
func (s *Server) resolveVariables(ctx context.Context, client Client, text string, visited map[string]bool) string {
	if visited == nil {
		visited = make(map[string]bool)
	}

	return variableRegex.ReplaceAllStringFunc(text, func(match string) string {
		key := variableRegex.FindStringSubmatch(match)[1]

		if visited[key] {
			return match // Stop recursive resolution on circular reference, leave as-is
		}

		if !client.Can(http.MethodGet, key) {
			return "" // Replace with empty string if not permitted
		}

		plaintext, err := s.store.Get(ctx, key)
		if err != nil {
			return "" // Missing or error fetching secret
		}

		var secretData struct {
			Value string `json:"value"`
		}
		var val string
		if err := json.Unmarshal(plaintext, &secretData); err == nil {
			val = secretData.Value
		} else {
			val = string(plaintext)
		}

		// Create a new visited map for this branch to allow same variable in different branches
		newVisited := make(map[string]bool, len(visited)+1)
		for k, v := range visited {
			newVisited[k] = v
		}
		newVisited[key] = true

		// Recursively resolve nested variables
		return s.resolveVariables(ctx, client, val, newVisited)
	})
}

func (s *Server) getSameSiteMode() http.SameSite {
	if s.cfg.Insecure {
		return http.SameSiteLaxMode
	}
	return http.SameSiteStrictMode
}

// SecurityMiddleware enforces HTTPS redirects, secure headers, and cookie attributes
// when running in secure mode (i.e. config.Insecure is false).
func (s *Server) SecurityMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-TSM-Version", s.version)
		if !s.cfg.Insecure {
			isHTTPS := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
			if !isHTTPS {
				if r.Method == http.MethodGet {
					target := "https://" + r.Host + r.URL.RequestURI()
					// #nosec G710 - We are intentionally redirecting to the exact same URL requested by the user, just with HTTPS
					http.Redirect(w, r, target, http.StatusMovedPermanently)
				} else {
					s.respondError(w, http.StatusForbidden, "HTTPS Required")
				}
				return
			}

			w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("Referrer-Policy", "no-referrer")
		}

		next.ServeHTTP(w, r)
	})
}

// auth is a middleware that handles token authentication and optional
// admin-driven token impersonation via the X-Impersonate-Token header.
func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var tokenStr string

		if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
			tokenStr = strings.TrimPrefix(h, "Bearer ")
		} else if cookie, err := r.Cookie("tsm_admin"); err == nil {
			tokenStr = cookie.Value
		}

		if tokenStr == "" {
			s.respondError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		tokenHash := sha256.Sum256([]byte(tokenStr))
		var client Client

		ctx, cancel := context.WithTimeout(r.Context(), dbTimeout)
		defer cancel()

		tr, err := s.store.GetRoleByHash(ctx, tokenHash[:])
		if err == sql.ErrNoRows {
			s.respondError(w, http.StatusUnauthorized, "unauthorized")
			return
		} else if err != nil {
			s.logger.Error("token db lookup failed", "err", err)
			s.respondError(w, http.StatusInternalServerError, "internal server error")
			return
		}

		if tr.ExpiresAt != nil && time.Now().After(*tr.ExpiresAt) {
			s.respondError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		if strings.HasPrefix(tr.Name, "session_") {
			// #nosec G118 - The goroutine must outlive the HTTP request, so context.Background() is correct
			go func() { _ = s.store.ExtendRoleExpiry(context.Background(), tr.Name, time.Now().Add(1*time.Hour)) }()
		}

		client.Name = tr.Name
		client.IsAdmin = tr.IsAdmin
		client.CanCreate = tr.CanCreate
		if client.IsAdmin {
			client.Policies = []config.Policy{{Prefix: "*", Methods: []string{"*"}}}
		} else {
			_ = json.Unmarshal(tr.Policies, &client.Policies)
		}

		if client.IsAdmin {
			if impersonate := r.Header.Get("X-Impersonate-Token"); impersonate != "" {
				tr, err := s.store.GetRoleByName(ctx, impersonate)
				if err == nil {
					client.IsAdmin = false
					client.Name = tr.Name
					client.CanCreate = tr.CanCreate
					_ = json.Unmarshal(tr.Policies, &client.Policies)
				} else if err != sql.ErrNoRows {
					s.logger.Error("token lookup for impersonation failed", "err", err)
					s.respondError(w, http.StatusInternalServerError, "internal server error")
					return
				}
			}
		}

		next(w, r.WithContext(context.WithValue(r.Context(), clientCtxKey, client)))
	}
}
