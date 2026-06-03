package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"
)

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

	var secretData struct {
		Value  string `json:"value"`
		EnvKey string `json:"env_key,omitempty"`
	}

	if err := json.Unmarshal(plaintext, &secretData); err != nil {
		// Fallback for legacy raw string secrets
		secretData.Value = string(plaintext)
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]string{"key": key, "value": secretData.Value, "env_key": secretData.EnvKey}); err != nil {
		s.logger.Error("failed to encode secret", "err", err)
	}
}

func (s *Server) handlePutSecret(w http.ResponseWriter, r *http.Request) {
	client := r.Context().Value(clientCtxKey).(Client)
	key := r.PathValue("key")
	if !client.Can(r.Method, key) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxPayloadBytes)
	var body struct {
		Value  string `json:"value"`
		EnvKey string `json:"env_key,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	payload, err := json.Marshal(body)
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), dbTimeout)
	defer cancel()

	if err := s.store.Put(ctx, key, payload); err != nil {
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
		s.logger.Error("secret deletion failed", "err", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	go s.triggerBackup()
	w.WriteHeader(http.StatusNoContent)
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
			if globalList {
				break
			}
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
		s.logger.Error("secret list failed", "err", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(keys); err != nil {
		s.logger.Error("failed to encode secret list", "err", err)
	}
}
