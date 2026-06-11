// Package store provides an encrypted SQLite storage backend.
// It uses "Envelope Encryption": secrets are encrypted with an ephemeral
// Data Encryption Key (DEK), which is itself stored encrypted in the database
// using a Master Key (Primary KEK) or emergency Recovery Keys.
package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"
	"tiny-secrets-manager/internal/crypto"
)

// Store manages the database connection and encryption state.
type Store struct {
	db     *sql.DB
	dekBox *crypto.Box // Box initialized with the DEK for fast secret access
	dek    []byte      // The raw Data Encryption Key
}

// RoleRecord represents a machine identity and its associated policies.
type RoleRecord struct {
	Name      string          `json:"name"`
	IsAdmin   bool            `json:"is_admin"`
	Policies  json.RawMessage `json:"policies"`
	CanCreate bool            `json:"can_create"`
	CreatedAt time.Time       `json:"created_at"`
	ExpiresAt *time.Time      `json:"expires_at"`
}

// New initializes the database, ensures schema integrity, and resolves the
// internal Data Encryption Key (DEK) using provided credentials.
func New(dsn string, masterKeyB64, recoveryKeyB64 string, logger *slog.Logger) (*Store, error) {
	if !strings.Contains(dsn, "?") {
		dsn += "?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=busy_timeout(5000)"
	} else {
		dsn += "&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=busy_timeout(5000)"
	}

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	db.SetMaxOpenConns(16)
	db.SetMaxIdleConns(4)
	db.SetConnMaxLifetime(time.Hour)

	if err := initSchema(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to init schema: %w", err)
	}

	dekBox, dek, err := resolveDEK(db, masterKeyB64, recoveryKeyB64, logger)
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to resolve DEK: %w", err)
	}

	return &Store{db: db, dekBox: dekBox, dek: dek}, nil
}

func initSchema(db *sql.DB) error {
	var userVersion int
	if err := db.QueryRow("PRAGMA user_version").Scan(&userVersion); err != nil {
		return fmt.Errorf("failed to read user_version: %w", err)
	}

	if userVersion == 0 {
		var count int
		err := db.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='encryption_slots'").Scan(&count)
		if err != nil {
			return fmt.Errorf("failed to check for existing tables: %w", err)
		}

		if count > 0 {
			// Legacy database without user_version
			// We apply the known ALTERs just in case they haven't been run
			alters := []string{
				`ALTER TABLE roles ADD COLUMN expires_at TIMESTAMP`,
				`ALTER TABLE roles ADD COLUMN can_create INTEGER DEFAULT 0`,
			}
			for _, q := range alters {
				if _, err := db.Exec(q); err != nil {
					if !strings.Contains(err.Error(), "duplicate column name") {
						return fmt.Errorf("failed legacy migration: %w", err)
					}
				}
			}
			// Mark as V1
			if _, err := db.Exec("PRAGMA user_version = 1"); err != nil {
				return fmt.Errorf("failed to set user_version: %w", err)
			}
			userVersion = 1
		} else {
			// Brand new database
			queries := []string{
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
					can_create INTEGER DEFAULT 0,
					created_at TIMESTAMP NOT NULL,
					expires_at TIMESTAMP
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
			for _, q := range queries {
				if _, err := db.Exec(q); err != nil {
					return fmt.Errorf("failed to create tables: %w", err)
				}
			}
			if _, err := db.Exec("PRAGMA user_version = 1"); err != nil {
				return fmt.Errorf("failed to set user_version: %w", err)
			}
			userVersion = 1
		}
	}

	// Future migrations would be handled like this:
	// if userVersion < 2 {
	//     _, err := db.Exec(`...`)
	//     db.Exec("PRAGMA user_version = 2")
	//     userVersion = 2
	// }

	return nil
}

// resolveDEK implements the multi-slot credential resolution logic:
// 1. Attempts to decrypt the DEK using the primary Master Key.
// 2. If that fails, attempts to use a one-time emergency Recovery Key.
// 3. If the database is empty, bootstraps a new DEK and generates recovery keys.
func resolveDEK(db *sql.DB, masterKeyB64, recoveryKeyB64 string, logger *slog.Logger) (*crypto.Box, []byte, error) {
	var dek []byte

	// 1. Decrypt via primary KEK
	if masterKeyB64 != "" {
		dek = decryptWithPrimaryBox(db, masterKeyB64)
	}

	// 2. Decrypt via Single-Use Recovery Keys
	if len(dek) == 0 && recoveryKeyB64 != "" {
		dek = decryptWithRecoveryKey(db, recoveryKeyB64, masterKeyB64)
	}

	// 3. Native Database Bootstrap
	if len(dek) == 0 {
		var count int
		if err := db.QueryRow("SELECT COUNT(*) FROM encryption_slots").Scan(&count); err == nil && count > 0 {
			return nil, nil, errors.New("database locked: decryption slots exist but validation credentials failed")
		}

		var err error
		dek, err = bootstrapDEK(db, masterKeyB64, logger)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to bootstrap DEK: %w", err)
		}
	}

	box, err := crypto.NewBoxFromBytes(dek)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create crypto box: %w", err)
	}
	return box, dek, nil
}

func decryptWithPrimaryBox(db *sql.DB, masterKeyB64 string) []byte {
	var pNonce, pWrapped []byte
	err := db.QueryRow("SELECT nonce, wrapped_dek FROM encryption_slots WHERE slot_name = 'primary'").Scan(&pNonce, &pWrapped)
	if err != nil {
		return nil
	}

	primaryBox, err := crypto.NewBox(masterKeyB64)
	if err != nil {
		return nil
	}

	dek, _ := primaryBox.Decrypt(pNonce, pWrapped, []byte("primary"))
	return dek
}

func decryptWithRecoveryKey(db *sql.DB, recoveryKeyB64, masterKeyB64 string) []byte {
	recoveryBox, err := crypto.NewBox(recoveryKeyB64)
	if err != nil {
		return nil
	}

	rows, err := db.Query("SELECT slot_name, nonce, wrapped_dek FROM encryption_slots WHERE slot_name LIKE 'backup_%'")
	if err != nil {
		return nil
	}
	defer rows.Close()

	for rows.Next() {
		var slotName string
		var bNonce, bWrapped []byte
		if err := rows.Scan(&slotName, &bNonce, &bWrapped); err != nil {
			continue
		}

		decrypted, err := recoveryBox.Decrypt(bNonce, bWrapped, []byte(slotName))
		if err == nil && len(decrypted) == 32 {
			dek := decrypted

			// Remove the used recovery key
			_, _ = db.Exec("DELETE FROM encryption_slots WHERE slot_name = ?", slotName)

			// If we have a new master key, re-encrypt the DEK with it immediately
			if masterKeyB64 != "" {
				if primaryBox, err := crypto.NewBox(masterKeyB64); err == nil {
					if n, c, err := primaryBox.Encrypt(dek, []byte("primary")); err == nil {
						_, _ = db.Exec("INSERT OR REPLACE INTO encryption_slots (slot_name, nonce, wrapped_dek) VALUES ('primary', ?, ?)", n, c)
					}
				}
			}

			return dek
		}
	}
	return nil
}

func bootstrapDEK(db *sql.DB, masterKeyB64 string, logger *slog.Logger) ([]byte, error) {
	if masterKeyB64 == "" {
		return nil, errors.New("master_key is required to initialize encryption slots")
	}

	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		return nil, err
	}

	primaryBox, err := crypto.NewBox(masterKeyB64)
	if err != nil {
		return nil, err
	}

	n, c, err := primaryBox.Encrypt(dek, []byte("primary"))
	if err != nil {
		return nil, err
	}

	if _, err = db.Exec("INSERT INTO encryption_slots (slot_name, nonce, wrapped_dek) VALUES ('primary', ?, ?)", n, c); err != nil {
		return nil, err
	}

	logger.Info("========================================================================")
	logger.Info("                        EMERGENCY RECOVERY KEYS                         ")
	logger.Info("========================================================================")

	for i := 0; i < 3; i++ {
		bk := make([]byte, 32)
		_, _ = rand.Read(bk)
		bkB64 := base64.StdEncoding.EncodeToString(bk)

		backupBox, _ := crypto.NewBox(bkB64)
		slotName := "backup_" + strconv.Itoa(i)
		bn, bc, _ := backupBox.Encrypt(dek, []byte(slotName))
		_, _ = db.Exec("INSERT INTO encryption_slots (slot_name, nonce, wrapped_dek) VALUES (?, ?, ?)", slotName, bn, bc)

		_, _ = os.Stdout.WriteString("  Recovery Key " + strconv.Itoa(i) + ": " + bkB64 + "\n")
	}
	logger.Info("========================================================================")

	return dek, nil
}

// RegenerateRecoveryKeys replaces all existing recovery key slots with a new
// set of three single-use keys.
func (s *Store) RegenerateRecoveryKeys(ctx context.Context) ([]string, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	_, err = tx.ExecContext(ctx, "DELETE FROM encryption_slots WHERE slot_name LIKE 'backup_%'")
	if err != nil {
		return nil, err
	}

	keys := make([]string, 3)
	for i := 0; i < 3; i++ {
		rawKey := make([]byte, 32)
		_, _ = rand.Read(rawKey)
		b64Key := base64.StdEncoding.EncodeToString(rawKey)
		keys[i] = b64Key

		backupBox, err := crypto.NewBox(b64Key)
		if err != nil {
			return nil, err
		}

		slotName := "backup_" + strconv.Itoa(i)
		n, c, err := backupBox.Encrypt(s.dek, []byte(slotName))
		if err != nil {
			return nil, err
		}

		_, err = tx.ExecContext(ctx, "INSERT INTO encryption_slots (slot_name, nonce, wrapped_dek) VALUES (?, ?, ?)", slotName, n, c)
		if err != nil {
			return nil, err
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return keys, nil
}

// Backup creates a consistent snapshot of the database using VACUUM INTO.
func (s *Store) Backup(ctx context.Context, destPath string) error {
	// VACUUM INTO is a safe way to create a consistent copy of a live SQLite database
	_, err := s.db.ExecContext(ctx, "VACUUM INTO ?", destPath)
	return err
}

// Close closes the underlying database connection.
func (s *Store) Close() error { return s.db.Close() }

// Get retrieves and decrypts a secret by its key.
func (s *Store) Get(ctx context.Context, key string) ([]byte, error) {
	var nonce, ciphertext []byte
	err := s.db.QueryRowContext(ctx, "SELECT nonce, ciphertext FROM secrets WHERE key = ?", key).Scan(&nonce, &ciphertext)
	if err != nil {
		return nil, err
	}
	return s.dekBox.Decrypt(nonce, ciphertext, []byte(key))
}

// Put encrypts and stores a secret key-value pair, overwriting if it exists.
func (s *Store) Put(ctx context.Context, key string, plaintext []byte) error {
	nonce, ciphertext, err := s.dekBox.Encrypt(plaintext, []byte(key))
	if err != nil {
		return err
	}

	_, err = s.db.ExecContext(ctx, `
		INSERT INTO secrets(key, nonce, ciphertext, updated_at) 
		VALUES (?, ?, ?, ?) 
		ON CONFLICT(key) DO UPDATE SET 
			nonce=excluded.nonce, 
			ciphertext=excluded.ciphertext, 
			updated_at=excluded.updated_at`,
		key, nonce, ciphertext, time.Now())
	return err
}

// Delete permanently removes a secret key from the database.
func (s *Store) Delete(ctx context.Context, key string) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM secrets WHERE key = ?", key)
	return err
}

func escapeLike(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(s, `\`, `\\`), `%`, `\%`), `_`, `\_`)
}

// List returns a sorted list of secret keys, optionally filtered by policy prefixes.
func (s *Store) List(ctx context.Context, global bool, prefixes []string, after string, limit int) ([]string, error) {
	var query strings.Builder
	var args []any
	query.WriteString("SELECT key FROM secrets WHERE ")
	if !global {
		query.WriteString("(")
		for i, pfx := range prefixes {
			if i > 0 {
				query.WriteString(" OR ")
			}

			if pfx == "*" {
				query.WriteString("1=1")
			} else if strings.HasSuffix(pfx, "*") {
				// Traditional starts-with
				query.WriteString("key LIKE ? ESCAPE '\\'")
				args = append(args, escapeLike(strings.TrimSuffix(pfx, "*"))+"%")
			} else {
				// Segment-aware: exact match OR starts with prefix + dot
				query.WriteString("(key = ? OR key LIKE ? ESCAPE '\\')")
				args = append(args, pfx, escapeLike(pfx)+".%")
			}
		}
		query.WriteString(") AND ")
	}
	query.WriteString("(? = '' OR key > ?) ORDER BY key ASC LIMIT ?")
	args = append(args, after, after, limit)

	rows, err := s.db.QueryContext(ctx, query.String(), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	keys := make([]string, 0, limit)
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, nil
}

// PutRole stores a new hashed machine role and its policies.
func (s *Store) PutRole(ctx context.Context, name string, hash []byte, policiesJSON []byte, isAdmin bool, canCreate bool, expiresAt *time.Time) error {
	adminFlag := 0
	if isAdmin {
		adminFlag = 1
	}
	createFlag := 0
	if canCreate {
		createFlag = 1
	}
	_, err := s.db.ExecContext(ctx, "INSERT INTO roles (name, hash, policies_json, is_admin, can_create, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)", name, hash, string(policiesJSON), adminFlag, createFlag, time.Now(), expiresAt)
	return err
}

// UpdateRole updates the policy JSON and expiration for an existing role name.
func (s *Store) UpdateRole(ctx context.Context, name string, policiesJSON []byte, canCreate bool, expiresAt *time.Time) error {
	createFlag := 0
	if canCreate {
		createFlag = 1
	}
	_, err := s.db.ExecContext(ctx, "UPDATE roles SET policies_json = ?, can_create = ?, expires_at = ? WHERE name = ?", string(policiesJSON), createFlag, expiresAt, name)
	return err
}

// GetRoleByHash retrieves a role record using the SHA256 hash of the role string.
func (s *Store) GetRoleByHash(ctx context.Context, hash []byte) (*RoleRecord, error) {
	var tr RoleRecord
	var p string
	var isAdmin, canCreate int
	var expiresAt sql.NullTime
	err := s.db.QueryRowContext(ctx, "SELECT name, policies_json, is_admin, can_create, created_at, expires_at FROM roles WHERE hash = ?", hash).Scan(&tr.Name, &p, &isAdmin, &canCreate, &tr.CreatedAt, &expiresAt)
	if err != nil {
		return nil, err
	}
	tr.Policies = json.RawMessage(p)
	tr.IsAdmin = isAdmin == 1
	tr.CanCreate = canCreate == 1
	if expiresAt.Valid {
		tr.ExpiresAt = &expiresAt.Time
	}
	return &tr, nil
}

// GetRoleByName retrieves a role record by its unique identity name.
func (s *Store) GetRoleByName(ctx context.Context, name string) (*RoleRecord, error) {
	var tr RoleRecord
	var p string
	var isAdmin, canCreate int
	var expiresAt sql.NullTime
	err := s.db.QueryRowContext(ctx, "SELECT name, policies_json, is_admin, can_create, created_at, expires_at FROM roles WHERE name = ?", name).Scan(&tr.Name, &p, &isAdmin, &canCreate, &tr.CreatedAt, &expiresAt)
	if err != nil {
		return nil, err
	}
	tr.Policies = json.RawMessage(p)
	tr.IsAdmin = isAdmin == 1
	tr.CanCreate = canCreate == 1
	if expiresAt.Valid {
		tr.ExpiresAt = &expiresAt.Time
	}
	return &tr, nil
}

// ListRoles returns all registered machine roles, sorted by name.
func (s *Store) ListRoles(ctx context.Context) ([]RoleRecord, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT name, policies_json, is_admin, can_create, created_at, expires_at FROM roles ORDER BY name ASC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var res []RoleRecord
	for rows.Next() {
		var tr RoleRecord
		var p string
		var isAdmin, canCreate int
		var expiresAt sql.NullTime
		if err := rows.Scan(&tr.Name, &p, &isAdmin, &canCreate, &tr.CreatedAt, &expiresAt); err != nil {
			return nil, err
		}
		tr.Policies = json.RawMessage(p)
		tr.IsAdmin = isAdmin == 1
		tr.CanCreate = canCreate == 1
		if expiresAt.Valid {
			tr.ExpiresAt = &expiresAt.Time
		}
		res = append(res, tr)
	}
	return res, nil
}

// ExtendRoleExpiry updates the expiration time of a role.
func (s *Store) ExtendRoleExpiry(ctx context.Context, name string, expiresAt time.Time) error {
	_, err := s.db.ExecContext(ctx, "UPDATE roles SET expires_at = ? WHERE name = ?", expiresAt, name)
	return err
}

// DeleteExpiredRoles permanently removes any roles whose expiration date has passed.
func (s *Store) DeleteExpiredRoles(ctx context.Context) (int64, error) {
	res, err := s.db.ExecContext(ctx, "DELETE FROM roles WHERE expires_at IS NOT NULL AND expires_at < ?", time.Now())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// DeleteRole revokes a machine role by name.
func (s *Store) DeleteRole(ctx context.Context, name string) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM roles WHERE name = ?", name)
	return err
}

// UpdateRoleToken updates the token hash for an existing role.
func (s *Store) UpdateRoleToken(ctx context.Context, name string, newHash []byte) error {
	_, err := s.db.ExecContext(ctx, "UPDATE roles SET hash = ? WHERE name = ?", newHash, name)
	return err
}

// PutAdmin creates or updates an admin user in the database.
func (s *Store) PutAdmin(ctx context.Context, username, passwordHash string) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO admins (username, password_hash, created_at) 
		VALUES (?, ?, ?) 
		ON CONFLICT(username) DO UPDATE SET 
			password_hash=excluded.password_hash`,
		username, passwordHash, time.Now())
	return err
}

// GetAdmin retrieves an admin's password hash by username.
func (s *Store) GetAdmin(ctx context.Context, username string) (string, error) {
	var hash string
	err := s.db.QueryRowContext(ctx, "SELECT password_hash FROM admins WHERE username = ?", username).Scan(&hash)
	return hash, err
}

// CountAdmins returns the number of administrative accounts in the database.
func (s *Store) CountAdmins(ctx context.Context) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM admins").Scan(&count)
	return count, err
}

// PutSetting creates or updates a system setting.
func (s *Store) PutSetting(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO settings (key, value, updated_at)
		VALUES (?, ?, ?)
		ON CONFLICT(key) DO UPDATE SET
			value=excluded.value, updated_at=excluded.updated_at`,
		key, value, time.Now())
	return err
}

// GetSetting retrieves a system setting by key. Returns empty string if not found.
func (s *Store) GetSetting(ctx context.Context, key string) (string, error) {
	var val string
	err := s.db.QueryRowContext(ctx, "SELECT value FROM settings WHERE key = ?", key).Scan(&val)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return val, err
}

// GetAllSettings retrieves all system settings.
func (s *Store) GetAllSettings(ctx context.Context) (map[string]string, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT key, value FROM settings")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	settings := make(map[string]string)
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		settings[k] = v
	}
	return settings, nil
}
