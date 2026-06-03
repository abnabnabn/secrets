package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"

	"tiny-secrets-manager/internal/config"
	"tiny-secrets-manager/internal/store"
)

func (s *Server) handleListRoles(w http.ResponseWriter, r *http.Request) {
	client := r.Context().Value(clientCtxKey).(Client)
	if !client.IsAdmin {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), dbTimeout)
	defer cancel()

	tokens, err := s.store.ListRoles(ctx)
	if err != nil {
		s.logger.Error("failed to list roles", "err", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	// Filter out internal session tokens and the default admin token
	filtered := make([]store.RoleRecord, 0)
	for _, t := range tokens {
		if !strings.HasPrefix(t.Name, "session_") && t.Name != "admin" {
			filtered = append(filtered, t)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(filtered); err != nil {
		s.logger.Error("failed to encode roles", "err", err)
	}
}

func (s *Server) handleCreateRole(w http.ResponseWriter, r *http.Request) {
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

	if err := s.store.PutRole(ctx, req.Name, hash[:], policiesJSON, false); err != nil {
		s.logger.Error("db put role error", "err", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	go s.triggerBackup()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]string{"token": tokenStr}); err != nil {
		s.logger.Error("failed to encode token response", "err", err)
	}
}

func (s *Server) handleUpdateRole(w http.ResponseWriter, r *http.Request) {
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

	if err := s.store.UpdateRolePolicies(ctx, name, policiesJSON); err != nil {
		s.logger.Error("db update role error", "err", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	go s.triggerBackup()
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleDeleteRole(w http.ResponseWriter, r *http.Request) {
	client := r.Context().Value(clientCtxKey).(Client)
	if !client.IsAdmin {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), dbTimeout)
	defer cancel()

	if err := s.store.DeleteRole(ctx, r.PathValue("name")); err != nil {
		s.logger.Error("role deletion failed", "err", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	go s.triggerBackup()
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleRegenerateRoleToken(w http.ResponseWriter, r *http.Request) {
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

	raw := make([]byte, 32)
	rand.Read(raw)
	tokenStr := base64.RawURLEncoding.EncodeToString(raw)
	hash := sha256.Sum256([]byte(tokenStr))

	ctx, cancel := context.WithTimeout(r.Context(), dbTimeout)
	defer cancel()

	if err := s.store.UpdateRoleToken(ctx, name, hash[:]); err != nil {
		s.logger.Error("db update role token error", "err", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	go s.triggerBackup()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]string{"token": tokenStr}); err != nil {
		s.logger.Error("failed to encode token response", "err", err)
	}
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
	if err := json.NewEncoder(w).Encode(map[string][]string{"recovery_keys": keys}); err != nil {
		s.logger.Error("failed to encode recovery keys", "err", err)
	}
}
