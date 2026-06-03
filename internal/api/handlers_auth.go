package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"golang.org/x/crypto/bcrypt"
)

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
	if err := s.store.PutRole(ctx, sessionName, tokenHash[:], []byte("[]"), true); err != nil {
		s.logger.Error("failed to store session token", "err", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "tsm_admin",
		Value:    sessionToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   !s.cfg.Insecure,
		SameSite: s.getSameSiteMode(),
		MaxAge:   86400,
	})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     "tsm_admin",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   !s.cfg.Insecure,
		SameSite: s.getSameSiteMode(),
		MaxAge:   -1,
	})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleAuthMe(w http.ResponseWriter, r *http.Request) {
	client := r.Context().Value(clientCtxKey).(Client)
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(client); err != nil {
		s.logger.Error("failed to encode client", "err", err)
	}
}
