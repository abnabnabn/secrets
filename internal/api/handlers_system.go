package api

import (
	"encoding/json"
	"net/http"
)

func (s *Server) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	client := r.Context().Value(clientCtxKey).(Client)
	if !client.IsAdmin {
		s.respondError(w, http.StatusForbidden, "forbidden")
		return
	}

	ctx := r.Context()
	settings, err := s.store.GetAllSettings(ctx)
	if err != nil {
		s.logger.Error("failed to get settings", "err", err)
		s.respondError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	s.respondJSON(w, http.StatusOK, settings)
}

func (s *Server) handlePutSettings(w http.ResponseWriter, r *http.Request) {
	client := r.Context().Value(clientCtxKey).(Client)
	if !client.IsAdmin {
		s.respondError(w, http.StatusForbidden, "forbidden")
		return
	}

	var req map[string]string
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.respondError(w, http.StatusBadRequest, "invalid payload")
		return
	}

	ctx := r.Context()
	for k, v := range req {
		if err := s.store.PutSetting(ctx, k, v); err != nil {
			s.logger.Error("failed to update setting", "err", err)
			s.respondError(w, http.StatusInternalServerError, "internal server error")
			return
		}
	}

	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleTriggerBackup(w http.ResponseWriter, r *http.Request) {
	client := r.Context().Value(clientCtxKey).(Client)
	if !client.IsAdmin {
		s.respondError(w, http.StatusForbidden, "forbidden")
		return
	}

	if err := s.runBackup(); err != nil {
		s.logger.Error("manual backup failed", "err", err)
		s.respondError(w, http.StatusInternalServerError, "backup failed: "+err.Error())
		return
	}

	w.WriteHeader(http.StatusOK)
}
