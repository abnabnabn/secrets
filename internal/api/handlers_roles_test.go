package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"tiny-secrets-manager/internal/config"
	"tiny-secrets-manager/internal/store"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandleRoleLifecycle(t *testing.T) {
	_, db, mux, adminToken := setupTestServer(t)
	defer db.Close()

	// 1. Create Role
	t.Run("create_role", func(t *testing.T) {
		body := map[string]interface{}{
			"name": "test-machine",
			"policies": []config.Policy{
				{Prefix: "app.*", Methods: []string{"GET"}},
			},
		}
		b, _ := json.Marshal(body)

		req := httptest.NewRequest("POST", "/v1/roles", bytes.NewBuffer(b))
		req.Header.Set("Authorization", "Bearer "+adminToken)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		
		var resp map[string]string
		err := json.NewDecoder(rec.Body).Decode(&resp)
		require.NoError(t, err)
		assert.NotEmpty(t, resp["token"])
	})

	// 2. List Roles
	t.Run("list_roles", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/v1/roles", nil)
		req.Header.Set("Authorization", "Bearer "+adminToken)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		
		var tokens []store.RoleRecord
		err := json.NewDecoder(rec.Body).Decode(&tokens)
		require.NoError(t, err)
		
		// admin and test-machine (admin is filtered out though)
		require.Len(t, tokens, 1)
		assert.Equal(t, "test-machine", tokens[0].Name)
	})

	// 3. Update Role
	t.Run("update_role", func(t *testing.T) {
		body := map[string]interface{}{
			"policies": []config.Policy{
				{Prefix: "*", Methods: []string{"GET", "PUT"}},
			},
		}
		b, _ := json.Marshal(body)

		req := httptest.NewRequest("PUT", "/v1/roles/test-machine", bytes.NewBuffer(b))
		req.Header.Set("Authorization", "Bearer "+adminToken)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusNoContent, rec.Code)
	})

	// 4. Regenerate Role
	t.Run("regenerate_role", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/v1/roles/test-machine/regenerate", nil)
		req.Header.Set("Authorization", "Bearer "+adminToken)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)

		var resp map[string]string
		err := json.NewDecoder(rec.Body).Decode(&resp)
		require.NoError(t, err)
		assert.NotEmpty(t, resp["token"])
	})

	// 5. Delete Role
	t.Run("delete_role", func(t *testing.T) {
		req := httptest.NewRequest("DELETE", "/v1/roles/test-machine", nil)
		req.Header.Set("Authorization", "Bearer "+adminToken)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusNoContent, rec.Code)
	})
}

func TestHandleRegenerateRecoveryKeys(t *testing.T) {
	_, db, mux, adminToken := setupTestServer(t)
	defer db.Close()

	req := httptest.NewRequest("POST", "/v1/recovery-keys/regenerate", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp map[string][]string
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)

	keys := resp["recovery_keys"]
	require.Len(t, keys, 3)
	for _, k := range keys {
		assert.NotEmpty(t, k)
	}
}
