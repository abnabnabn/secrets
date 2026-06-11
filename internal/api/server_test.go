package api

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"tiny-secrets-manager/internal/config"
	"tiny-secrets-manager/internal/store"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

func setupTestServer(t *testing.T) (*Server, *store.Store, *http.ServeMux, string) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	cfg := &config.Config{Insecure: true}

	// Use in-memory SQLite for testing
	masterKeyB64 := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" // 32 bytes of zeros, base64 encoded
	db, err := store.New(":memory:", masterKeyB64, "", logger)
	require.NoError(t, err)

	// Seed admin user
	adminPass := "testpass"
	hash, err := bcrypt.GenerateFromPassword([]byte(adminPass), bcrypt.DefaultCost)
	require.NoError(t, err)
	err = db.PutAdmin(context.Background(), "admin", string(hash))
	require.NoError(t, err)

	// Seed admin token
	adminToken := "test-admin-token"
	tokenHash := sha256.Sum256([]byte(adminToken))
	pJSON, _ := json.Marshal([]config.Policy{{Prefix: "*", Methods: []string{"*"}}})
	if err := db.PutRole(context.Background(), "admin", tokenHash[:], pJSON, true, false, nil); err != nil {
		t.Fatalf("failed to insert mock admin token: %v", err)
	}

	srv := NewServer(db, cfg, logger, "test-version")
	mux := http.NewServeMux()
	srv.RegisterRoutes(mux)

	return srv, db, mux, adminToken
}

func TestServer_SecurityMiddleware_SecureMode(t *testing.T) {
	s := &Server{
		cfg: &config.Config{Insecure: false},
	}

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := s.SecurityMiddleware(nextHandler)

	// 1. HTTP GET requests should be redirected to HTTPS
	req := httptest.NewRequest("GET", "http://example.com/some/path?foo=bar", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMovedPermanently, rec.Code)
	assert.Equal(t, "https://example.com/some/path?foo=bar", rec.Header().Get("Location"))

	// 2. HTTP POST requests should be blocked with 403 Forbidden
	req = httptest.NewRequest("POST", "http://example.com/api", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Body.String(), "HTTPS Required")

	// 3. HTTPS requests (via X-Forwarded-Proto) should pass through and set security headers
	req = httptest.NewRequest("GET", "http://example.com/some/path", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("Strict-Transport-Security"), "max-age=")
	assert.Equal(t, "DENY", rec.Header().Get("X-Frame-Options"))
	assert.Equal(t, "nosniff", rec.Header().Get("X-Content-Type-Options"))
	assert.Equal(t, "no-referrer", rec.Header().Get("Referrer-Policy"))
}

func TestServer_SecurityMiddleware_InsecureMode(t *testing.T) {
	s := &Server{
		cfg: &config.Config{Insecure: true},
	}

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := s.SecurityMiddleware(nextHandler)

	// 1. HTTP GET requests should pass through without redirection
	req := httptest.NewRequest("GET", "http://example.com/some/path", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Empty(t, rec.Header().Get("Location"))
	assert.Empty(t, rec.Header().Get("Strict-Transport-Security"))

	// 2. HTTP POST requests should pass through
	req = httptest.NewRequest("POST", "http://example.com/api", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestServer_CookieSameSiteAndSecure(t *testing.T) {
	// 1. Secure Mode
	sSecure := &Server{
		cfg: &config.Config{Insecure: false},
	}
	assert.Equal(t, http.SameSiteStrictMode, sSecure.getSameSiteMode())

	// 2. Insecure Mode
	sInsecure := &Server{
		cfg: &config.Config{Insecure: true},
	}
	assert.Equal(t, http.SameSiteLaxMode, sInsecure.getSameSiteMode())
}

func TestClient_Can(t *testing.T) {
	admin := Client{IsAdmin: true}
	assert.True(t, admin.Can("GET", "any.path"))
	assert.True(t, admin.Can("DELETE", "any.path"))

	client := Client{
		IsAdmin: false,
		Policies: []config.Policy{
			{Prefix: "app.db.pass", Methods: []string{"GET", "PUT"}},
			{Prefix: "app.api.*", Methods: []string{"GET"}},
			{Prefix: "shared", Methods: []string{"*"}},
		},
	}

	// Exact match tests
	assert.True(t, client.Can("GET", "app.db.pass"))
	assert.True(t, client.Can("PUT", "app.db.pass"))
	assert.False(t, client.Can("DELETE", "app.db.pass"))
	assert.True(t, client.Can("GET", "app.db.pass.extra")) // Default prefix allows sub-segments

	// Star prefix tests
	assert.True(t, client.Can("GET", "app.api.key"))
	assert.True(t, client.Can("GET", "app.api.token"))
	assert.False(t, client.Can("PUT", "app.api.key"))
	assert.False(t, client.Can("GET", "app.apikey")) // prefix* needs to match exactly the prefix

	// Sub-segment tests (shared should match shared and shared.foo, but not shared_foo)
	assert.True(t, client.Can("GET", "shared"))
	assert.True(t, client.Can("PUT", "shared.foo"))
	assert.True(t, client.Can("DELETE", "shared.bar"))
	assert.False(t, client.Can("GET", "shared_foo"))

	// Global wildcard policy test
	globalClient := Client{
		IsAdmin: false,
		Policies: []config.Policy{
			{Prefix: "*", Methods: []string{"GET"}},
		},
	}
	assert.True(t, globalClient.Can("GET", "anything"))
	assert.False(t, globalClient.Can("PUT", "anything"))
}
