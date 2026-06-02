// Package api implements the HTTP vault interface, providing endpoints for
// secret management, token provisioning, and administrative tasks.
package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"secretd/internal/config"
	"secretd/internal/store"
	"golang.org/x/crypto/bcrypt"
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
// on a given vault path, respecting strict segment matching and wildcards.
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

// RegisterRoutes maps the vault's API endpoints to their respective handlers.
func (s *Server) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/auth/login", s.handleLogin)
	mux.HandleFunc("POST /v1/auth/logout", s.handleLogout)
	mux.HandleFunc("GET /v1/auth/me", s.auth(s.handleAuthMe))
	mux.HandleFunc("GET /v1/secrets", s.auth(s.handleListSecrets))
	mux.HandleFunc("GET /v1/secrets/{key}", s.auth(s.handleGetSecret))
	mux.HandleFunc("PUT /v1/secrets/{key}", s.auth(s.handlePutSecret))
	mux.HandleFunc("DELETE /v1/secrets/{key}", s.auth(s.handleDeleteSecret))
	mux.HandleFunc("GET /v1/tokens", s.auth(s.handleListTokens))
	mux.HandleFunc("POST /v1/tokens", s.auth(s.handleCreateToken))
	mux.HandleFunc("PUT /v1/tokens/{name}", s.auth(s.handleUpdateToken))
	mux.HandleFunc("DELETE /v1/tokens/{name}", s.auth(s.handleDeleteToken))
	mux.HandleFunc("POST /v1/recovery-keys/regenerate", s.auth(s.handleRegenerateRecoveryKeys))
}

func (s *Server) handleUpdateToken(w http.ResponseWriter, r *http.Request) {
	client := r.Context().Value(clientCtxKey).(Client)
	if !client.IsAdmin {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	name := r.PathValue("name")
	if name == "" {
		http.Error(w, "missing name", http.StatusBadRequest)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxPayloadBytes)
	var req struct {
		Policies []config.Policy `json:"policies"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid payload", http.StatusBadRequest)
		return
	}

	policiesJSON, _ := json.Marshal(req.Policies)
	ctx, cancel := context.WithTimeout(r.Context(), dbTimeout)
	defer cancel()

	if err := s.store.UpdateTokenPolicies(ctx, name, policiesJSON); err != nil {
		s.logger.Error("db update token error", "err", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	go s.triggerBackup()
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxPayloadBytes)
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid payload", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), dbTimeout)
	defer cancel()

	hash, err := s.store.GetAdmin(ctx, req.Username)
	if err == sql.ErrNoRows {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	} else if err != nil {
		s.logger.Error("admin lookup failed", "err", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.Password)); err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Generate a session token
	raw := make([]byte, 32)
	rand.Read(raw)
	sessionToken := base64.RawURLEncoding.EncodeToString(raw)
	tokenHash := sha256.Sum256([]byte(sessionToken))

	// Store session token in DB with admin privileges
	// We use a unique name for each session to avoid collisions
	sessionName := "session_" + req.Username + "_" + strconv.FormatInt(time.Now().UnixNano(), 10)
	if err := s.store.PutToken(ctx, sessionName, tokenHash[:], []byte("[]"), true); err != nil {
		s.logger.Error("failed to store session token", "err", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "secretd_admin",
		Value:    sessionToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   86400,
	})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     "secretd_admin",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
	w.WriteHeader(http.StatusNoContent)
}

// auth is a middleware that handles token authentication and optional 
// admin-driven token impersonation via the X-Impersonate-Token header.
func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var tokenStr string

		if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
			tokenStr = strings.TrimPrefix(h, "Bearer ")
		} else if cookie, err := r.Cookie("secretd_admin"); err == nil {
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

		tr, err := s.store.GetTokenByHash(ctx, tokenHash[:])
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
				tr, err := s.store.GetTokenByName(ctx, impersonate)
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

func (s *Server) handleAuthMe(w http.ResponseWriter, r *http.Request) {
	client := r.Context().Value(clientCtxKey).(Client)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(client)
}

func (s *Server) handleRegenerateRecoveryKeys(w http.ResponseWriter, r *http.Request) {
	client := r.Context().Value(clientCtxKey).(Client)
	if !client.IsAdmin {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), dbTimeout)
	defer cancel()

	keys, err := s.store.RegenerateRecoveryKeys(ctx)
	if err != nil {
		s.logger.Error("failed to regenerate recovery keys", "err", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	go s.triggerBackup()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string][]string{"recovery_keys": keys})
}

func (s *Server) handleGetSecret(w http.ResponseWriter, r *http.Request) {
	client := r.Context().Value(clientCtxKey).(Client)
	key := r.PathValue("key")
	if !client.Can(r.Method, key) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), dbTimeout)
	defer cancel()

	plaintext, err := s.store.Get(ctx, key)
	if err == sql.ErrNoRows {
		http.NotFound(w, r)
		return
	} else if err != nil {
		s.logger.Error("secret retrieval failed", "err", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"key": key, "value": string(plaintext)})
}

func (s *Server) handlePutSecret(w http.ResponseWriter, r *http.Request) {
	client := r.Context().Value(clientCtxKey).(Client)
	key := r.PathValue("key")
	if !client.Can(r.Method, key) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxPayloadBytes)
	var body struct{ Value string `json:"value"` }
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), dbTimeout)
	defer cancel()

	if err := s.store.Put(ctx, key, []byte(body.Value)); err != nil {
		s.logger.Error("secret insertion failed", "err", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	go s.triggerBackup()
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleDeleteSecret(w http.ResponseWriter, r *http.Request) {
	client := r.Context().Value(clientCtxKey).(Client)
	key := r.PathValue("key")
	if !client.Can(r.Method, key) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	
	ctx, cancel := context.WithTimeout(r.Context(), dbTimeout)
	defer cancel()

	if err := s.store.Delete(ctx, key); err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	go s.triggerBackup()
	w.WriteHeader(http.StatusNoContent)
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

func (s *Server) handleListSecrets(w http.ResponseWriter, r *http.Request) {
	client := r.Context().Value(clientCtxKey).(Client)
	var allowedPrefixes []string
	globalList := false

	if client.IsAdmin {
		globalList = true
	} else {
		for _, p := range client.Policies {
			for _, m := range p.Methods {
				if m == "LIST" || m == "*" {
					if p.Prefix == "*" {
						globalList = true
						break
					}
					allowedPrefixes = append(allowedPrefixes, p.Prefix)
				}
			}
			if globalList { break }
		}
	}

	if !globalList && len(allowedPrefixes) == 0 {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	limit := 1000
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 5000 {
			limit = l
		}
	}

	ctx, cancel := context.WithTimeout(r.Context(), dbTimeout)
	defer cancel()

	keys, err := s.store.List(ctx, globalList, allowedPrefixes, r.URL.Query().Get("after"), limit)
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(keys)
}

func (s *Server) handleListTokens(w http.ResponseWriter, r *http.Request) {
	client := r.Context().Value(clientCtxKey).(Client)
	if !client.IsAdmin {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), dbTimeout)
	defer cancel()

	tokens, err := s.store.ListTokens(ctx)
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tokens)
}

func (s *Server) handleCreateToken(w http.ResponseWriter, r *http.Request) {
	client := r.Context().Value(clientCtxKey).(Client)
	if !client.IsAdmin {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxPayloadBytes)
	var req struct {
		Name     string          `json:"name"`
		Policies []config.Policy `json:"policies"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
		http.Error(w, "invalid payload", http.StatusBadRequest)
		return
	}

	policiesJSON, _ := json.Marshal(req.Policies)
	raw := make([]byte, 32)
	rand.Read(raw)
	tokenStr := base64.RawURLEncoding.EncodeToString(raw)
	hash := sha256.Sum256([]byte(tokenStr))

	ctx, cancel := context.WithTimeout(r.Context(), dbTimeout)
	defer cancel()

	if err := s.store.PutToken(ctx, req.Name, hash[:], policiesJSON, false); err != nil {
		s.logger.Error("db put token error", "err", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	go s.triggerBackup()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": tokenStr})
}

func (s *Server) handleDeleteToken(w http.ResponseWriter, r *http.Request) {
	client := r.Context().Value(clientCtxKey).(Client)
	if !client.IsAdmin {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), dbTimeout)
	defer cancel()

	if err := s.store.DeleteToken(ctx, r.PathValue("name")); err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	go s.triggerBackup()
	w.WriteHeader(http.StatusNoContent)
}
