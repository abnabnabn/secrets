package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"tiny-secrets-manager/internal/config"

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

	// 4. Role attempts to create new secret without CREATE permission
	roleToken := "role-token"
	roleHash := sha256.Sum256([]byte(roleToken))
	// Empty policy initially
	emptyPolicies, _ := json.Marshal([]config.Policy{})
	require.NoError(t, db.PutRole(context.Background(), "my-role", roleHash[:], emptyPolicies, false, false, nil))

	t.Run("role_creates_secret_forbidden", func(t *testing.T) {
		body := map[string]interface{}{"value": "role-created-value"}
		b, _ := json.Marshal(body)

		req := httptest.NewRequest("PUT", "/v1/secrets/role.new.key", bytes.NewBuffer(b))
		req.Header.Set("Authorization", "Bearer "+roleToken)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	// 5. Grant global CREATE permission and try again
	require.NoError(t, db.UpdateRole(context.Background(), "my-role", emptyPolicies, true, nil))

	t.Run("role_creates_secret", func(t *testing.T) {
		body := map[string]interface{}{
			"value":         "role-created-value",
			"grant_methods": []string{"GET", "PUT"},
		}
		b, _ := json.Marshal(body)

		req := httptest.NewRequest("PUT", "/v1/secrets/role.new.key", bytes.NewBuffer(b))
		req.Header.Set("Authorization", "Bearer "+roleToken)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusNoContent, rec.Code)

		// Verify role has GET, PUT now for the new secret
		tr, err := db.GetRoleByName(context.Background(), "my-role")
		require.NoError(t, err)
		var policies []config.Policy
		err = json.Unmarshal(tr.Policies, &policies)
		require.NoError(t, err)
		assert.Len(t, policies, 1)
		assert.Equal(t, "role.new.key", policies[0].Prefix)
		assert.ElementsMatch(t, []string{"GET", "PUT"}, policies[0].Methods)
	})

	t.Run("role_update_existing_secret_without_permission", func(t *testing.T) {
		body := map[string]interface{}{"value": "hacked-value"}
		b, _ := json.Marshal(body)

		req := httptest.NewRequest("PUT", "/v1/secrets/test.key", bytes.NewBuffer(b))
		req.Header.Set("Authorization", "Bearer "+roleToken)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusForbidden, rec.Code)
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

func TestHandleResolveSecret(t *testing.T) {
	_, db, mux, adminToken := setupTestServer(t)
	defer db.Close()

	// 1. Put secrets
	secretsMap := map[string]string{
		"name.first": "john",
		"name.last":  "smith",
		"name.full":  "${name.first}.${name.last}",
		"nested":     "hello ${name.full}",
	}
	for k, v := range secretsMap {
		body := map[string]string{"value": v}
		b, _ := json.Marshal(body)
		req := httptest.NewRequest("PUT", "/v1/secrets/"+k, bytes.NewBuffer(b))
		req.Header.Set("Authorization", "Bearer "+adminToken)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		require.Equal(t, http.StatusNoContent, rec.Code)
	}

	// 2. Resolve Secret via API
	t.Run("resolve_secret", func(t *testing.T) {
		body := map[string]string{"value": "User is ${nested}"}
		b, _ := json.Marshal(body)
		req := httptest.NewRequest("POST", "/v1/secrets/resolve", bytes.NewBuffer(b))
		req.Header.Set("Authorization", "Bearer "+adminToken)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)

		var resp map[string]string
		err := json.NewDecoder(rec.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Equal(t, "User is hello john.smith", resp["value"])
	})

	// 3. Get Secret that has variables
	t.Run("get_secret_with_variables", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/v1/secrets/name.full", nil)
		req.Header.Set("Authorization", "Bearer "+adminToken)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)

		var resp map[string]string
		err := json.NewDecoder(rec.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Equal(t, "name.full", resp["key"])
		assert.Equal(t, "john.smith", resp["value"])
		assert.Equal(t, "${name.first}.${name.last}", resp["raw_value"])
	})

	// 4. Test permission constraints (limited token)
	limitedToken := "limited-token"
	limitedHash := sha256.Sum256([]byte(limitedToken))
	limitedPolicies, _ := json.Marshal([]config.Policy{
		{Prefix: "name.full", Methods: []string{"GET"}},
		{Prefix: "name.first", Methods: []string{"GET"}},
		// Intentionally missing name.last
	})
	require.NoError(t, db.PutRole(context.Background(), "limited", limitedHash[:], limitedPolicies, false, false, nil))

	t.Run("get_secret_limited_permission", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/v1/secrets/name.full", nil)
		req.Header.Set("Authorization", "Bearer "+limitedToken)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)

		var resp map[string]string
		err := json.NewDecoder(rec.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Equal(t, "name.full", resp["key"])
		// Because name.last is denied, it resolves to empty string, leaving "john."
		assert.Equal(t, "john.", resp["value"])
	})

	// 5. Test circular reference
	err := db.Put(context.Background(), "circle1", []byte("${circle2}"))
	require.NoError(t, err)
	err = db.Put(context.Background(), "circle2", []byte("${circle1}"))
	require.NoError(t, err)

	t.Run("get_secret_circular_reference", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/v1/secrets/circle1", nil)
		req.Header.Set("Authorization", "Bearer "+adminToken)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)

		var resp map[string]string
		err := json.NewDecoder(rec.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Equal(t, "circle1", resp["key"])
		// Should break the cycle safely and leave the unresolved variable
		assert.Equal(t, "${circle2}", resp["value"])
	})
}
