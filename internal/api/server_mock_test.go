package api

import (
	"bytes"
	"context"
	"database/sql"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
	"tiny-secrets-manager/internal/config"
	"tiny-secrets-manager/internal/store"

	"golang.org/x/crypto/bcrypt"
)

type MockStorage struct {
	GetRoleByHashFunc func(ctx context.Context, hash []byte) (*store.RoleRecord, error)
	GetAdminFunc      func(ctx context.Context, username string) (string, error)
	ListRolesFunc     func(ctx context.Context) ([]store.RoleRecord, error)
	PutRoleFunc       func(ctx context.Context, name string, tokenHash []byte, policiesJSON []byte, isAdmin bool, canCreate bool, expiresAt *time.Time) error
}

func (m *MockStorage) GetRoleByHash(ctx context.Context, hash []byte) (*store.RoleRecord, error) {
	if m.GetRoleByHashFunc != nil {
		return m.GetRoleByHashFunc(ctx, hash)
	}
	return nil, nil
}
func (m *MockStorage) GetRoleByName(ctx context.Context, name string) (*store.RoleRecord, error) {
	return nil, nil
}
func (m *MockStorage) ExtendRoleExpiry(ctx context.Context, name string, newExpiry time.Time) error {
	return nil
}
func (m *MockStorage) List(ctx context.Context, global bool, prefixes []string, after string, limit int) ([]string, error) {
	return nil, nil
}
func (m *MockStorage) Get(ctx context.Context, key string) ([]byte, error)         { return nil, nil }
func (m *MockStorage) Put(ctx context.Context, key string, plaintext []byte) error { return nil }
func (m *MockStorage) Delete(ctx context.Context, key string) error                { return nil }
func (m *MockStorage) ListRoles(ctx context.Context) ([]store.RoleRecord, error) {
	if m.ListRolesFunc != nil {
		return m.ListRolesFunc(ctx)
	}
	return nil, nil
}
func (m *MockStorage) PutRole(ctx context.Context, name string, tokenHash []byte, policiesJSON []byte, isAdmin bool, canCreate bool, expiresAt *time.Time) error {
	if m.PutRoleFunc != nil {
		return m.PutRoleFunc(ctx, name, tokenHash, policiesJSON, isAdmin, canCreate, expiresAt)
	}
	return nil
}
func (m *MockStorage) UpdateRole(ctx context.Context, name string, policiesJSON []byte, canCreate bool, expiresAt *time.Time) error {
	return nil
}
func (m *MockStorage) UpdateRoleToken(ctx context.Context, name string, newTokenHash []byte) error {
	return nil
}
func (m *MockStorage) DeleteRole(ctx context.Context, name string) error             { return nil }
func (m *MockStorage) RegenerateRecoveryKeys(ctx context.Context) ([]string, error)  { return nil, nil }
func (m *MockStorage) GetAllSettings(ctx context.Context) (map[string]string, error) { return nil, nil }
func (m *MockStorage) PutSetting(ctx context.Context, key, value string) error       { return nil }
func (m *MockStorage) GetSetting(ctx context.Context, key string) (string, error)    { return "", nil }
func (m *MockStorage) Backup(ctx context.Context, dst string) error                  { return nil }
func (m *MockStorage) DeleteExpiredRoles(ctx context.Context) (int64, error)         { return 0, nil }
func (m *MockStorage) GetAdmin(ctx context.Context, username string) (string, error) {
	if m.GetAdminFunc != nil {
		return m.GetAdminFunc(ctx, username)
	}
	return "", nil
}

func TestRespondErrorJSONFormat(t *testing.T) {
	s := NewServer(&MockStorage{}, &config.Config{}, slog.New(slog.NewJSONHandler(io.Discard, nil)), "test")

	w := httptest.NewRecorder()

	s.respondError(w, http.StatusTeapot, "I am a teapot")

	res := w.Result()
	if res.StatusCode != http.StatusTeapot {
		t.Errorf("expected status %d, got %d", http.StatusTeapot, res.StatusCode)
	}

	if res.Header.Get("Content-Type") != "application/json" {
		t.Errorf("expected application/json, got %s", res.Header.Get("Content-Type"))
	}

	body, _ := io.ReadAll(res.Body)
	expected := `{"error":"I am a teapot","status":418}` + "\n"
	if string(body) != expected {
		t.Errorf("expected body %q, got %q", expected, string(body))
	}
}

func TestBackupTriggerChannel(t *testing.T) {
	s := NewServer(&MockStorage{}, &config.Config{}, slog.New(slog.NewJSONHandler(io.Discard, nil)), "test")

	// Flag a backup. The channel has a buffer of 1.
	s.flagBackupNeeded()

	// Try flagging again to ensure the non-blocking channel implementation doesn't deadlock.
	s.flagBackupNeeded()

	select {
	case <-s.backupTrigger:
		// Passed
	default:
		t.Error("expected backupTrigger channel to have an item")
	}
}

func TestHandlersSystem_Settings(t *testing.T) {
	// 1. Success case
	mock := &MockStorage{
		GetAdminFunc: func(ctx context.Context, username string) (string, error) {
			return "", nil
		},
	}
	s := NewServer(mock, &config.Config{}, slog.New(slog.NewJSONHandler(io.Discard, nil)), "test")

	client := Client{Name: "admin", IsAdmin: true}
	req := httptest.NewRequest(http.MethodGet, "/v1/system/settings", nil)
	req = req.WithContext(context.WithValue(req.Context(), clientCtxKey, client))

	w := httptest.NewRecorder()
	s.handleGetSettings(w, req)

	if w.Result().StatusCode != http.StatusOK {
		t.Errorf("expected 200 OK, got %d", w.Result().StatusCode)
	}

	// 2. Forbidden case
	nonAdmin := Client{Name: "user", IsAdmin: false}
	reqForbidden := httptest.NewRequest(http.MethodGet, "/v1/system/settings", nil)
	reqForbidden = reqForbidden.WithContext(context.WithValue(reqForbidden.Context(), clientCtxKey, nonAdmin))

	wForbidden := httptest.NewRecorder()
	s.handleGetSettings(wForbidden, reqForbidden)

	if wForbidden.Result().StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden, got %d", wForbidden.Result().StatusCode)
	}

	// 3. PutSettings Invalid JSON
	reqPutBad := httptest.NewRequest(http.MethodPut, "/v1/system/settings", bytes.NewBufferString("{bad-json}"))
	reqPutBad = reqPutBad.WithContext(context.WithValue(reqPutBad.Context(), clientCtxKey, client))
	wPutBad := httptest.NewRecorder()
	s.handlePutSettings(wPutBad, reqPutBad)

	if wPutBad.Result().StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 Bad Request, got %d", wPutBad.Result().StatusCode)
	}
}

func TestHandlersRoles_List(t *testing.T) {
	mock := &MockStorage{
		GetAdminFunc: func(ctx context.Context, username string) (string, error) { return "", nil },
		ListRolesFunc: func(ctx context.Context) ([]store.RoleRecord, error) {
			return []store.RoleRecord{{Name: "test-role"}}, nil
		},
	}
	s := NewServer(mock, &config.Config{}, slog.New(slog.NewJSONHandler(io.Discard, nil)), "test")

	client := Client{Name: "admin", IsAdmin: true}
	req := httptest.NewRequest(http.MethodGet, "/v1/roles", nil)
	req = req.WithContext(context.WithValue(req.Context(), clientCtxKey, client))

	w := httptest.NewRecorder()
	s.handleListRoles(w, req)

	if w.Result().StatusCode != http.StatusOK {
		t.Errorf("expected 200 OK, got %d", w.Result().StatusCode)
	}
}

func TestHandlersRoles_Create(t *testing.T) {
	mock := &MockStorage{}
	s := NewServer(mock, &config.Config{}, slog.New(slog.NewJSONHandler(io.Discard, nil)), "test")

	client := Client{Name: "admin", IsAdmin: true}
	req := httptest.NewRequest(http.MethodPost, "/v1/roles", bytes.NewBufferString(`{"name": "test-role", "policies": [{"prefix":"*","methods":["*"]}]}`))
	req = req.WithContext(context.WithValue(req.Context(), clientCtxKey, client))

	w := httptest.NewRecorder()
	s.handleCreateRole(w, req)

	if w.Result().StatusCode != http.StatusOK {
		t.Errorf("expected 200 OK, got %d", w.Result().StatusCode)
	}
}

func TestHandlersAuth_Login(t *testing.T) {
	mock := &MockStorage{
		GetAdminFunc: func(ctx context.Context, username string) (string, error) {
			if username == "admin" {
				hash, _ := bcrypt.GenerateFromPassword([]byte("testpass"), 4)
				return string(hash), nil
			}
			return "", sql.ErrNoRows
		},
		PutRoleFunc: func(ctx context.Context, name string, tokenHash []byte, policiesJSON []byte, isAdmin bool, canCreate bool, expiresAt *time.Time) error {
			return nil
		},
	}
	s := NewServer(mock, &config.Config{}, slog.New(slog.NewJSONHandler(io.Discard, nil)), "test")

	// 1. Valid Login
	reqValid := httptest.NewRequest(http.MethodPost, "/v1/auth/login", bytes.NewBufferString(`{"username": "admin", "password": "testpass"}`))
	wValid := httptest.NewRecorder()
	s.handleLogin(wValid, reqValid)

	if wValid.Result().StatusCode != http.StatusOK {
		t.Errorf("expected 200 OK, got %d", wValid.Result().StatusCode)
	}

	// 2. Invalid Password
	reqInvalid := httptest.NewRequest(http.MethodPost, "/v1/auth/login", bytes.NewBufferString(`{"username": "admin", "password": "wrong"}`))
	wInvalid := httptest.NewRecorder()
	s.handleLogin(wInvalid, reqInvalid)

	if wInvalid.Result().StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized, got %d", wInvalid.Result().StatusCode)
	}

	// 3. Invalid Username
	reqBadUser := httptest.NewRequest(http.MethodPost, "/v1/auth/login", bytes.NewBufferString(`{"username": "nope", "password": "testpass"}`))
	wBadUser := httptest.NewRecorder()
	s.handleLogin(wBadUser, reqBadUser)

	if wBadUser.Result().StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized, got %d", wBadUser.Result().StatusCode)
	}
}
