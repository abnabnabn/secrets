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
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"tiny-secrets-manager/internal/config"
	"tiny-secrets-manager/internal/store"
)

type contextKey int

const clientCtxKey contextKey = iota

const maxPayloadBytes = 1 << 20 // 1MB constraint
const dbTimeout = 5 * time.Second

// Client represents an authenticated entity (Admin or Machine Token).
type Client struct {
	Name     string          `json:"name"`
	IsAdmin  bool            `json:"is_admin"`
	Policies []config.Policy `json:"policies"`
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
	store        *store.Store
	cfg          *config.Config
	logger       *slog.Logger
	version      string
	backupNeeded atomic.Bool
	backupMutex  sync.Mutex
}

// NewServer initializes a new API server instance.
func NewServer(s *store.Store, cfg *config.Config, logger *slog.Logger, version string) *Server {
	srv := &Server{
		store:   s,
		cfg:     cfg,
		logger:  logger,
		version: version,
	}
	go srv.backupLoop()
	return srv
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
					http.Error(w, "HTTPS Required", http.StatusForbidden)
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
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		tokenHash := sha256.Sum256([]byte(tokenStr))
		var client Client

		ctx, cancel := context.WithTimeout(r.Context(), dbTimeout)
		defer cancel()

		tr, err := s.store.GetRoleByHash(ctx, tokenHash[:])
		if err == sql.ErrNoRows {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		} else if err != nil {
			s.logger.Error("token db lookup failed", "err", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		if tr.ExpiresAt != nil && time.Now().After(*tr.ExpiresAt) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		if strings.HasPrefix(tr.Name, "session_") {
			// #nosec G118 - The goroutine must outlive the HTTP request, so context.Background() is correct
			go func() { _ = s.store.ExtendRoleExpiry(context.Background(), tr.Name, time.Now().Add(1*time.Hour)) }()
		}

		client.Name = tr.Name
		client.IsAdmin = tr.IsAdmin
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
					_ = json.Unmarshal(tr.Policies, &client.Policies)
				} else if err != sql.ErrNoRows {
					s.logger.Error("token lookup for impersonation failed", "err", err)
					http.Error(w, "internal server error", http.StatusInternalServerError)
					return
				}
			}
		}

		next(w, r.WithContext(context.WithValue(r.Context(), clientCtxKey, client)))
	}
}
