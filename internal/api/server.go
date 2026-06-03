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
	"os"
	"os/exec"
	"strings"
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
	store  *store.Store
	cfg    *config.Config
	logger *slog.Logger
}

// NewServer initializes a new API server instance.
func NewServer(s *store.Store, cfg *config.Config, logger *slog.Logger) *Server {
	return &Server{
		store:  s,
		cfg:    cfg,
		logger: logger,
	}
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
		if !s.cfg.Insecure {
			isHTTPS := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
			if !isHTTPS {
				if r.Method == http.MethodGet {
					target := "https://" + r.Host + r.URL.RequestURI()
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

		client.Name = tr.Name
		client.IsAdmin = tr.IsAdmin
		if client.IsAdmin {
			client.Policies = []config.Policy{{Prefix: "*", Methods: []string{"*"}}}
		} else {
			json.Unmarshal(tr.Policies, &client.Policies)
		}

		if client.IsAdmin {
			if impersonate := r.Header.Get("X-Impersonate-Token"); impersonate != "" {
				tr, err := s.store.GetRoleByName(ctx, impersonate)
				if err == nil {
					client.IsAdmin = false
					client.Name = tr.Name
					json.Unmarshal(tr.Policies, &client.Policies)
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

// triggerBackup creates a consistent database snapshot and transfers it
// to the configured target (local filesystem or remote scp).
func (s *Server) triggerBackup() {
	if s.cfg.BackupTarget == "" {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Determine if target is remote (contains ':') or local
	isRemote := strings.Contains(s.cfg.BackupTarget, ":")

	if !isRemote {
		// Local backup: VACUUM INTO directly to the target
		// We use a temporary file and rename to ensure atomicity for the final file
		tmpFile := s.cfg.BackupTarget + ".tmp"
		if err := s.store.Backup(ctx, tmpFile); err != nil {
			s.logger.Error("local backup vacuum failed", "err", err)
			return
		}
		if err := os.Rename(tmpFile, s.cfg.BackupTarget); err != nil {
			s.logger.Error("local backup rename failed", "err", err)
			return
		}
		s.logger.Info("local database backup successful", "path", s.cfg.BackupTarget)
		return
	}

	// Remote backup (scp)
	tmpFile := s.cfg.DBPath + ".backup.tmp"
	defer os.Remove(tmpFile)

	if err := s.store.Backup(ctx, tmpFile); err != nil {
		s.logger.Error("remote backup vacuum failed", "err", err)
		return
	}

	cmd := exec.CommandContext(ctx, "scp", "-o", "StrictHostKeyChecking=no", tmpFile, s.cfg.BackupTarget)
	if out, err := cmd.CombinedOutput(); err != nil {
		s.logger.Error("scp backup failed", "err", err, "output", string(out))
		return
	}

	s.logger.Info("remote database backup successful", "target", s.cfg.BackupTarget)
}
