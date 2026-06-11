package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"

	"tiny-secrets-manager/internal/config"
)

func (s *Server) handleGetSecret(w http.ResponseWriter, r *http.Request) {
	client := r.Context().Value(clientCtxKey).(Client)
	key := r.PathValue("key")
	if !client.Can(r.Method, key) {
		s.respondError(w, http.StatusForbidden, "forbidden")
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
		s.respondError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	var secretData struct {
		Value    string `json:"value"`
		RawValue string `json:"raw_value,omitempty"`
		EnvKey   string `json:"env_key,omitempty"`
	}

	if err := json.Unmarshal(plaintext, &secretData); err != nil {
		// Fallback for legacy raw string secrets
		secretData.Value = string(plaintext)
	}

	resolvedValue := s.resolveVariables(ctx, client, secretData.Value, nil)

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]string{
		"key":       key,
		"value":     resolvedValue,
		"raw_value": secretData.Value,
		"env_key":   secretData.EnvKey,
	}); err != nil {
		s.logger.Error("failed to encode secret", "err", err)
	}
}

func (s *Server) handleResolveSecret(w http.ResponseWriter, r *http.Request) {
	client := r.Context().Value(clientCtxKey).(Client)

	r.Body = http.MaxBytesReader(w, r.Body, maxPayloadBytes)
	var body struct {
		Value string `json:"value"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		s.respondError(w, http.StatusBadRequest, "invalid json")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), dbTimeout)
	defer cancel()

	resolvedValue := s.resolveVariables(ctx, client, body.Value, nil)

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]string{"value": resolvedValue}); err != nil {
		s.logger.Error("failed to encode resolved secret", "err", err)
	}
}

func (s *Server) handlePutSecret(w http.ResponseWriter, r *http.Request) {
	client := r.Context().Value(clientCtxKey).(Client)
	key := r.PathValue("key")

	ctx, cancel := context.WithTimeout(r.Context(), dbTimeout)
	defer cancel()

	_, err := s.store.Get(ctx, key)
	if err != nil && err != sql.ErrNoRows {
		s.logger.Error("failed to check if secret exists", "err", err)
		s.respondError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	exists := err == nil

	if exists {
		if !client.Can(http.MethodPut, key) {
			s.respondError(w, http.StatusForbidden, "forbidden")
			return
		}
	} else {
		if !client.CanCreate && !client.IsAdmin {
			s.respondError(w, http.StatusForbidden, "forbidden")
			return
		}
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxPayloadBytes)
	var body struct {
		Value        string   `json:"value"`
		EnvKey       string   `json:"env_key,omitempty"`
		GrantMethods []string `json:"grant_methods,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		s.respondError(w, http.StatusBadRequest, "invalid json")
		return
	}

	payloadBody := map[string]string{"value": body.Value}
	if body.EnvKey != "" {
		payloadBody["env_key"] = body.EnvKey
	}
	payload, err := json.Marshal(payloadBody)
	if err != nil {
		s.respondError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	if err := s.store.Put(ctx, key, payload); err != nil {
		s.logger.Error("secret insertion failed", "err", err)
		s.respondError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	if !exists && !client.IsAdmin {
		tr, err := s.store.GetRoleByName(ctx, client.Name)
		if err == nil {
			var policies []config.Policy
			_ = json.Unmarshal(tr.Policies, &policies)

			methods := body.GrantMethods
			if len(methods) == 0 {
				methods = []string{"GET", "PUT"}
			}

			policies = append(policies, config.Policy{
				Prefix:  key,
				Methods: methods,
			})
			policiesBytes, _ := json.Marshal(policies)

			if err := s.store.UpdateRole(ctx, client.Name, policiesBytes, tr.CanCreate, tr.ExpiresAt); err != nil {
				s.logger.Error("failed to update role policies for new secret", "err", err)
			}
		}
	}

	s.flagBackupNeeded()
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleDeleteSecret(w http.ResponseWriter, r *http.Request) {
	client := r.Context().Value(clientCtxKey).(Client)
	key := r.PathValue("key")
	if !client.Can(r.Method, key) {
		s.respondError(w, http.StatusForbidden, "forbidden")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), dbTimeout)
	defer cancel()

	if err := s.store.Delete(ctx, key); err != nil {
		s.logger.Error("secret deletion failed", "err", err)
		s.respondError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	s.flagBackupNeeded()
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
		s.respondError(w, http.StatusForbidden, "forbidden")
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
		s.respondError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(keys); err != nil {
		s.logger.Error("failed to encode secret list", "err", err)
	}
}
