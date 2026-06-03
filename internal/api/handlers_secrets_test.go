package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandlePutAndGetSecret(t *testing.T) {
	_, db, mux, adminToken := setupTestServer(t)
	defer db.Close()

	// 1. Put Secret
	t.Run("put_secret", func(t *testing.T) {
		body := map[string]string{"value": "my-super-secret-value", "env_key": "MY_ENV_KEY"}
		b, _ := json.Marshal(body)
		
		req := httptest.NewRequest("PUT", "/v1/secrets/test.key", bytes.NewBuffer(b))
		req.Header.Set("Authorization", "Bearer "+adminToken)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusNoContent, rec.Code)
	})

	// 2. Get Secret
	t.Run("get_secret_success", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/v1/secrets/test.key", nil)
		req.Header.Set("Authorization", "Bearer "+adminToken)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		
		var resp map[string]string
		err := json.NewDecoder(rec.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Equal(t, "test.key", resp["key"])
		assert.Equal(t, "my-super-secret-value", resp["value"])
		assert.Equal(t, "MY_ENV_KEY", resp["env_key"])
	})

	// 3. Get Missing Secret
	t.Run("get_secret_not_found", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/v1/secrets/missing.key", nil)
		req.Header.Set("Authorization", "Bearer "+adminToken)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusNotFound, rec.Code)
	})
}

func TestHandleDeleteSecret(t *testing.T) {
	_, db, mux, adminToken := setupTestServer(t)
	defer db.Close()

	// Insert secret directly
	err := db.Put(context.Background(), "delete.me", []byte("val"))
	require.NoError(t, err)

	// Delete via API
	req := httptest.NewRequest("DELETE", "/v1/secrets/delete.me", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNoContent, rec.Code)

	// Verify deletion
	_, err = db.Get(context.Background(), "delete.me")
	assert.Error(t, err) // Should be sql.ErrNoRows or similar
}

func TestHandleListSecrets(t *testing.T) {
	_, db, mux, adminToken := setupTestServer(t)
	defer db.Close()

	// Seed secrets
	secrets := []string{"app.db.pass", "app.api.key", "shared.token"}
	for _, k := range secrets {
		err := db.Put(context.Background(), k, []byte("val"))
		require.NoError(t, err)
	}

	req := httptest.NewRequest("GET", "/v1/secrets", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var keys []string
	err := json.NewDecoder(rec.Body).Decode(&keys)
	require.NoError(t, err)

	assert.ElementsMatch(t, secrets, keys)
}
