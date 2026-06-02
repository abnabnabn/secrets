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
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"secretd/internal/crypto"
	_ "modernc.org/sqlite"
)

// Store manages the database connection and encryption state.
type Store struct {
	db     *sql.DB
	dekBox *crypto.Box // Box initialized with the DEK for fast secret access
	dek    []byte      // The raw Data Encryption Key
}

// TokenRecord represents a machine identity and its associated policies.
type TokenRecord struct {
	Name      string          `json:"name"`
	IsAdmin   bool            `json:"is_admin"`
	Policies  json.RawMessage `json:"policies"`
	CreatedAt time.Time       `json:"created_at"`
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
		return nil, err
	}

	db.SetMaxOpenConns(16)
	db.SetMaxIdleConns(4)
	db.SetConnMaxLifetime(time.Hour)

	if err := initSchema(db); err != nil {
		db.Close()
		return nil, err
	}

	dekBox, dek, err := resolveDEK(db, masterKeyB64, recoveryKeyB64, logger)
	if err != nil {
		db.Close()
		return nil, err
	}

	return &Store{db: db, dekBox: dekBox, dek: dek}, nil
}

func initSchema(db *sql.DB) error {
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
		`CREATE TABLE IF NOT EXISTS tokens (
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
	}
	for _, q := range queries {
		if _, err := db.Exec(q); err != nil {
			return err
		}
	}
	return nil
}

// resolveDEK implements the multi-slot credential resolution logic:
// 1. Attempts to decrypt the DEK using the primary Master Key.
// 2. If that fails, attempts to use a one-time emergency Recovery Key.
// 3. If the database is empty, bootstraps a new DEK and generates recovery keys.
func resolveDEK(db *sql.DB, masterKeyB64, recoveryKeyB64 string, logger *slog.Logger) (*crypto.Box, []byte, error) {
	var dek []byte

	// 1. Decrypt via primary KEK
	var pNonce, pWrapped []byte
	err := db.QueryRow("SELECT nonce, wrapped_dek FROM encryption_slots WHERE slot_name = 'primary'").Scan(&pNonce, &pWrapped)
	if err == nil && masterKeyB64 != "" {
		primaryBox, pErr := crypto.NewBox(masterKeyB64)
		if pErr == nil {
			dek, _ = primaryBox.Decrypt(pNonce, pWrapped, []byte("primary"))
		}
	}

	// 2. Decrypt via Single-Use Recovery Keys
	if len(dek) == 0 && recoveryKeyB64 != "" {
		recoveryBox, rErr := crypto.NewBox(recoveryKeyB64)
		if rErr == nil {
			rows, qErr := db.Query("SELECT slot_name, nonce, wrapped_dek FROM encryption_slots WHERE slot_name LIKE 'backup_%'")
			if qErr == nil {
				defer rows.Close()
				for rows.Next() {
					var slotName string
					var bNonce, bWrapped []byte
					if err := rows.Scan(&slotName, &bNonce, &bWrapped); err == nil {
						decrypted, dErr := recoveryBox.Decrypt(bNonce, bWrapped, []byte(slotName))
						if dErr == nil && len(decrypted) == 32 {
							dek = decrypted
							db.Exec("DELETE FROM encryption_slots WHERE slot_name = ?", slotName)
							if masterKeyB64 != "" {
								primaryBox, pErr := crypto.NewBox(masterKeyB64)
								if pErr == nil {
									n, c, _ := primaryBox.Encrypt(dek, []byte("primary"))
									db.Exec("INSERT OR REPLACE INTO encryption_slots (slot_name, nonce, wrapped_dek) VALUES ('primary', ?, ?)", n, c)
								}
							}
							break
						}
					}
				}
			}
		}
	}

	// 3. Native Database Bootstrap
	if len(dek) == 0 {
		var count int
		db.QueryRow("SELECT COUNT(*) FROM encryption_slots").Scan(&count)
		if count > 0 {
			return nil, nil, errors.New("database locked: decryption slots exist but validation credentials failed")
		}

		if masterKeyB64 == "" {
			return nil, nil, errors.New("master_key is required to initialize encryption slots")
		}

		dek = make([]byte, 32)
		if _, err := rand.Read(dek); err != nil {
			return nil, nil, err
		}

		primaryBox, err := crypto.NewBox(masterKeyB64)
		if err != nil {
			return nil, nil, err
		}
		n, c, _ := primaryBox.Encrypt(dek, []byte("primary"))
		if _, err = db.Exec("INSERT INTO encryption_slots (slot_name, nonce, wrapped_dek) VALUES ('primary', ?, ?)", n, c); err != nil {
			return nil, nil, err
		}

		logger.Info("========================================================================")
		logger.Info("                        EMERGENCY RECOVERY KEYS                         ")
		logger.Info("========================================================================")
		
		for i := 0; i < 3; i++ {
			bk := make([]byte, 32)
			rand.Read(bk)
			bkB64 := base64.StdEncoding.EncodeToString(bk)
			
			backupBox, _ := crypto.NewBox(bkB64)
			slotName := "backup_" + strconv.Itoa(i)
			bn, bc, _ := backupBox.Encrypt(dek, []byte(slotName))
			db.Exec("INSERT INTO encryption_slots (slot_name, nonce, wrapped_dek) VALUES (?, ?, ?)", slotName, bn, bc)
			
			os.Stdout.WriteString("  Recovery Key " + strconv.Itoa(i) + ": " + bkB64 + "\n")
		}
		logger.Info("========================================================================")
	}

	box, err := crypto.NewBoxFromBytes(dek)
	if err != nil {
		return nil, nil, err
	}
	return box, dek, nil
}

// RegenerateRecoveryKeys replaces all existing recovery key slots with a new
// set of three single-use keys.
func (s *Store) RegenerateRecoveryKeys(ctx context.Context) ([]string, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	_, err = tx.ExecContext(ctx, "DELETE FROM encryption_slots WHERE slot_name LIKE 'backup_%'")
	if err != nil {
		return nil, err
	}

	keys := make([]string, 3)
	for i := 0; i < 3; i++ {
		rawKey := make([]byte, 32)
		rand.Read(rawKey)
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

func escapeLike(s string) string { return strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(s, `\`, `\\`), `%`, `\%`), `_`, `\_`) }

// List returns a sorted list of secret keys, optionally filtered by policy prefixes.
func (s *Store) List(ctx context.Context, global bool, prefixes []string, after string, limit int) ([]string, error) {
	var query strings.Builder
	var args []any
	query.WriteString("SELECT key FROM secrets WHERE ")
	if !global {
		query.WriteString("(")
		for i, pfx := range prefixes {
			if i > 0 { query.WriteString(" OR ") }
			
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
	if err != nil { return nil, err }
	defer rows.Close()

	keys := make([]string, 0, limit)
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil { return nil, err }
		keys = append(keys, k)
	}
	return keys, nil
}

// PutToken stores a new hashed machine token and its policies.
func (s *Store) PutToken(ctx context.Context, name string, hash []byte, policiesJSON []byte, isAdmin bool) error {
	adminFlag := 0
	if isAdmin {
		adminFlag = 1
	}
	_, err := s.db.ExecContext(ctx, "INSERT INTO tokens (name, hash, policies_json, is_admin, created_at) VALUES (?, ?, ?, ?, ?)", name, hash, string(policiesJSON), adminFlag, time.Now())
	return err
}

// UpdateTokenPolicies updates the policy JSON for an existing token name.
func (s *Store) UpdateTokenPolicies(ctx context.Context, name string, policiesJSON []byte) error {
	_, err := s.db.ExecContext(ctx, "UPDATE tokens SET policies_json = ? WHERE name = ?", string(policiesJSON), name)
	return err
}

// GetTokenByHash retrieves a token record using the SHA256 hash of the token string.
func (s *Store) GetTokenByHash(ctx context.Context, hash []byte) (*TokenRecord, error) {
	var tr TokenRecord
	var p string
	var isAdmin int
	err := s.db.QueryRowContext(ctx, "SELECT name, policies_json, is_admin, created_at FROM tokens WHERE hash = ?", hash).Scan(&tr.Name, &p, &isAdmin, &tr.CreatedAt)
	if err != nil { return nil, err }
	tr.Policies = json.RawMessage(p)
	tr.IsAdmin = isAdmin == 1
	return &tr, nil
}

// GetTokenByName retrieves a token record by its unique identity name.
func (s *Store) GetTokenByName(ctx context.Context, name string) (*TokenRecord, error) {
	var tr TokenRecord
	var p string
	var isAdmin int
	err := s.db.QueryRowContext(ctx, "SELECT name, policies_json, is_admin, created_at FROM tokens WHERE name = ?", name).Scan(&tr.Name, &p, &isAdmin, &tr.CreatedAt)
	if err != nil { return nil, err }
	tr.Policies = json.RawMessage(p)
	tr.IsAdmin = isAdmin == 1
	return &tr, nil
}

// ListTokens returns all registered machine tokens, sorted by name.
func (s *Store) ListTokens(ctx context.Context) ([]TokenRecord, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT name, policies_json, is_admin, created_at FROM tokens ORDER BY name ASC")
	if err != nil { return nil, err }
	defer rows.Close()

	var res []TokenRecord
	for rows.Next() {
		var tr TokenRecord
		var p string
		var isAdmin int
		if err := rows.Scan(&tr.Name, &p, &isAdmin, &tr.CreatedAt); err != nil { return nil, err }
		tr.Policies = json.RawMessage(p)
		tr.IsAdmin = isAdmin == 1
		res = append(res, tr)
	}
	return res, nil
}

// DeleteToken revokes a machine token by name.
func (s *Store) DeleteToken(ctx context.Context, name string) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM tokens WHERE name = ?", name)
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
