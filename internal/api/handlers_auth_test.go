package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandleLogin(t *testing.T) {
	_, db, mux, _ := setupTestServer(t)
	defer db.Close()

	t.Run("success", func(t *testing.T) {
		body := map[string]string{
			"username": "admin",
			"password": "testpass",
		}
		b, _ := json.Marshal(body)
		req := httptest.NewRequest("POST", "/v1/auth/login", bytes.NewBuffer(b))
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusNoContent, rec.Code)
		
		// Ensure cookie is set
		cookies := rec.Result().Cookies()
		require.Len(t, cookies, 1)
		assert.Equal(t, "tsm_admin", cookies[0].Name)
		assert.NotEmpty(t, cookies[0].Value)
	})

	t.Run("invalid_credentials", func(t *testing.T) {
		body := map[string]string{
			"username": "admin",
			"password": "wrongpassword",
		}
		b, _ := json.Marshal(body)
		req := httptest.NewRequest("POST", "/v1/auth/login", bytes.NewBuffer(b))
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})
}

func TestHandleLogout(t *testing.T) {
	_, db, mux, _ := setupTestServer(t)
	defer db.Close()

	req := httptest.NewRequest("POST", "/v1/auth/logout", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNoContent, rec.Code)
	cookies := rec.Result().Cookies()
	require.Len(t, cookies, 1)
	assert.Equal(t, "tsm_admin", cookies[0].Name)
	assert.Equal(t, "", cookies[0].Value)
	assert.Equal(t, -1, cookies[0].MaxAge)
}

func TestHandleAuthMe(t *testing.T) {
	_, db, mux, adminToken := setupTestServer(t)
	defer db.Close()

	req := httptest.NewRequest("GET", "/v1/auth/me", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	
	var client Client
	err := json.NewDecoder(rec.Body).Decode(&client)
	require.NoError(t, err)

	assert.Equal(t, "admin", client.Name)
	assert.True(t, client.IsAdmin)
}
