package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestStore(t *testing.T) *Store {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	// Generate a random 32-byte master key
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	masterKeyB64 := base64.StdEncoding.EncodeToString(key)

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	st, err := New(dbPath, masterKeyB64, "", logger)
	require.NoError(t, err)
	return st
}

func TestStore_Initialization(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "init.db")

	key := make([]byte, 32)
	_, _ = rand.Read(key)
	masterKeyB64 := base64.StdEncoding.EncodeToString(key)
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	// Initial creation
	st, err := New(dbPath, masterKeyB64, "", logger)
	require.NoError(t, err)
	assert.NotNil(t, st.dek)
	st.Close()

	// Reopen existing
	st2, err := New(dbPath, masterKeyB64, "", logger)
	require.NoError(t, err)
	assert.Equal(t, st.dek, st2.dek) // DEK should be exactly the same
	st2.Close()
}

func TestStore_Secrets(t *testing.T) {
	st := newTestStore(t)
	defer st.Close()
	ctx := context.Background()

	// 1. Put
	err := st.Put(ctx, "app.db.pass", []byte("s3cr3t"))
	require.NoError(t, err)

	err = st.Put(ctx, "app.db.user", []byte("admin"))
	require.NoError(t, err)

	// 2. Get
	val, err := st.Get(ctx, "app.db.pass")
	require.NoError(t, err)
	assert.Equal(t, []byte("s3cr3t"), val)

	_, err = st.Get(ctx, "non.existent")
	assert.ErrorIs(t, err, sql.ErrNoRows)

	// 3. List
	keys, err := st.List(ctx, false, []string{"app.db.*"}, "", 100)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"app.db.pass", "app.db.user"}, keys)

	// 4. Update
	err = st.Put(ctx, "app.db.pass", []byte("newpass"))
	require.NoError(t, err)
	val, _ = st.Get(ctx, "app.db.pass")
	assert.Equal(t, []byte("newpass"), val)

	// 5. Delete
	err = st.Delete(ctx, "app.db.user")
	require.NoError(t, err)

	keys, _ = st.List(ctx, true, nil, "", 100)
	assert.ElementsMatch(t, []string{"app.db.pass"}, keys)
}

func TestStore_Roles(t *testing.T) {
	st := newTestStore(t)
	defer st.Close()
	ctx := context.Background()

	hash1 := sha256.Sum256([]byte("token1"))
	hash2 := sha256.Sum256([]byte("token2"))

	policies := []byte(`[{"prefix": "app.*", "methods": ["GET"]}]`)

	// 1. Put Role
	err := st.PutRole(ctx, "role1", hash1[:], policies, false, false, nil)
	if err != nil {
		t.Fatalf("failed to put role1: %v", err)
	}
	err = st.PutRole(ctx, "role2", hash2[:], policies, true, false, nil) // admin
	require.NoError(t, err)

	// 2. GetRoleByHash
	r1, err := st.GetRoleByHash(ctx, hash1[:])
	require.NoError(t, err)
	assert.Equal(t, "role1", r1.Name)
	assert.False(t, r1.IsAdmin)

	// 3. GetRoleByName
	r2, err := st.GetRoleByName(ctx, "role2")
	require.NoError(t, err)
	assert.Equal(t, "role2", r2.Name)
	assert.True(t, r2.IsAdmin)

	// 4. List Roles
	roles, err := st.ListRoles(ctx)
	require.NoError(t, err)
	assert.Len(t, roles, 2)

	// 5. Delete Role
	err = st.DeleteRole(ctx, "role1")
	require.NoError(t, err)

	_, err = st.GetRoleByName(ctx, "role1")
	assert.ErrorIs(t, err, sql.ErrNoRows)
}

func TestStore_Admins(t *testing.T) {
	st := newTestStore(t)
	defer st.Close()
	ctx := context.Background()

	// 1. Check before init
	_, err := st.GetAdmin(ctx, "admin")
	assert.ErrorIs(t, err, sql.ErrNoRows)

	// 2. Init Admin
	err = st.PutAdmin(ctx, "admin", "hashed_password")
	require.NoError(t, err)

	// 3. Check Admin
	hash, err := st.GetAdmin(ctx, "admin")
	require.NoError(t, err)
	assert.Equal(t, "hashed_password", hash)

	// 4. Update
	err = st.PutAdmin(ctx, "admin", "new_hash")
	require.NoError(t, err)

	hash, _ = st.GetAdmin(ctx, "admin")
	assert.Equal(t, "new_hash", hash)
}

func newTestStoreWithPath(t *testing.T) (*Store, string) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	key := make([]byte, 32)
	_, _ = rand.Read(key)
	masterKeyB64 := base64.StdEncoding.EncodeToString(key)

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	st, err := New(dbPath, masterKeyB64, "", logger)
	require.NoError(t, err)
	return st, dbPath
}

func TestStore_RebindRecoveryKey(t *testing.T) {
	st, dbPath := newTestStoreWithPath(t)
	ctx := context.Background()

	// Test RegenerateRecoveryKeys instead of Rebind
	keys, err := st.RegenerateRecoveryKeys(ctx)
	require.NoError(t, err)
	assert.Len(t, keys, 3)

	st.Close()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	wrongMasterKey := make([]byte, 32)
	_, _ = rand.Read(wrongMasterKey)
	wrongB64 := base64.StdEncoding.EncodeToString(wrongMasterKey)

	// Since master key is wrong, try open with the first recovery key
	stRecovered, err := New(dbPath, wrongB64, keys[0], logger)
	require.NoError(t, err)
	assert.NotNil(t, stRecovered.dek)
	stRecovered.Close()
}

func TestStore_DeleteExpiredRoles(t *testing.T) {
	st := newTestStore(t)
	defer st.Close()
	ctx := context.Background()

	// Create a token that expires in the past
	hash1 := sha256.Sum256([]byte("past_token"))
	past := time.Now().Add(-1 * time.Hour)
	err := st.PutRole(ctx, "past_role", hash1[:], []byte("[]"), false, false, &past)
	require.NoError(t, err)

	// Create a token that expires in the future
	hash2 := sha256.Sum256([]byte("future_token"))
	future := time.Now().Add(1 * time.Hour)
	err = st.PutRole(ctx, "future_role", hash2[:], []byte("[]"), false, false, &future)
	require.NoError(t, err)

	// Run cleanup
	deleted, err := st.DeleteExpiredRoles(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(1), deleted)

	// Verify past_role is gone
	_, err = st.GetRoleByName(ctx, "past_role")
	assert.ErrorIs(t, err, sql.ErrNoRows)

	// Verify future_role is still there
	r, err := st.GetRoleByName(ctx, "future_role")
	require.NoError(t, err)
	assert.Equal(t, "future_role", r.Name)
}

func TestStore_LegacyMigration(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "legacy.db")

	// 1. Manually create a legacy DB without user_version and without can_create/expires_at
	db, err := sql.Open("sqlite", dbPath)
	require.NoError(t, err)

	legacyQueries := []string{
		`CREATE TABLE IF NOT EXISTS encryption_slots (
			slot_name TEXT PRIMARY KEY,
			nonce BLOB NOT NULL,
			wrapped_dek BLOB NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS secrets (
			key TEXT PRIMARY KEY,
			nonce BLOB NOT NULL,
			ciphertext BLOB NOT NULL,
			updated_at TIMESTAMP NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS roles (
			name TEXT PRIMARY KEY,
			hash BLOB NOT NULL UNIQUE,
			policies_json TEXT NOT NULL,
			is_admin INTEGER DEFAULT 0,
			created_at TIMESTAMP NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS admins (
			username TEXT PRIMARY KEY,
			password_hash TEXT NOT NULL,
			created_at TIMESTAMP NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS settings (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL,
			updated_at TIMESTAMP NOT NULL
		)`,
	}
	for _, q := range legacyQueries {
		_, err = db.Exec(q)
		require.NoError(t, err)
	}

	// Ensure columns don't exist
	_, err = db.Exec("INSERT INTO roles (name, hash, policies_json, created_at, expires_at) VALUES ('test', 'hash', '[]', CURRENT_TIMESTAMP, NULL)")
	assert.Error(t, err) // Should fail because expires_at doesn't exist

	db.Close()

	// 2. Open with New() to trigger migration
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	masterKeyB64 := base64.StdEncoding.EncodeToString(key)
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	st, err := New(dbPath, masterKeyB64, "", logger)
	require.NoError(t, err)
	defer st.Close()

	// 3. Verify user_version is now 1
	var userVersion int
	err = st.db.QueryRow("PRAGMA user_version").Scan(&userVersion)
	require.NoError(t, err)
	assert.Equal(t, 1, userVersion)

	// 4. Verify columns exist now by creating a role that uses them
	ctx := context.Background()
	past := time.Now().Add(-1 * time.Hour)
	err = st.PutRole(ctx, "migrated_role", []byte("hash2"), []byte("[]"), false, true, &past)
	require.NoError(t, err)

	r, err := st.GetRoleByName(ctx, "migrated_role")
	require.NoError(t, err)
	assert.True(t, r.CanCreate)
	assert.NotNil(t, r.ExpiresAt)
}
