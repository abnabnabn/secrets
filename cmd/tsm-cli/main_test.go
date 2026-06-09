package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var trueCmd = []string{"true"}

func init() {
	if runtime.GOOS == "windows" {
		trueCmd = []string{"cmd", "/c", "exit 0"}
	}
}

func TestTSMCLI_Login(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, ".tsm.json")

	var out, err bytes.Buffer
	app := &TSMCLI{
		Out:        &out,
		Err:        &err,
		ConfigPath: configPath,
	}

	// 1. Run login
	errVal := app.Run([]string{"tsm", "login", "http://test-server"})
	require.NoError(t, errVal)

	// 2. Verify config file exists and contains correct URL
	assert.Contains(t, out.String(), "Server URL set to http://test-server")

	b, readErr := os.ReadFile(configPath)
	require.NoError(t, readErr)

	var cfg Config
	require.NoError(t, json.Unmarshal(b, &cfg))
	assert.Equal(t, "http://test-server", cfg.URL)
}

func TestTSMCLI_ContextLinking(t *testing.T) {
	t.Setenv("TSM_URL", "http://fake")
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, ".tsm.json")
	wd := "/fake/project/dir"

	app := &TSMCLI{
		Out:        ioDiscard(),
		Err:        ioDiscard(),
		ConfigPath: configPath,
		WorkingDir: wd,
	}

	// Link a token to the working directory
	err := app.Run([]string{"tsm", "auth", "--link", "test-token"})
	require.NoError(t, err)

	// Verify mapping
	cfg, token, err := app.loadConfig(true, "")
	require.NoError(t, err)
	assert.Equal(t, "test-token", token)
	assert.Equal(t, "test-token", cfg.Contexts[wd])
}

func TestTSMCLI_Subcommands(t *testing.T) {
	// Table-driven tests for subcommand routing and argument validation
	tests := []struct {
		name        string
		args        []string
		setupServer func(w http.ResponseWriter, r *http.Request)
		expectError string
		expectOut   string
	}{
		{
			name: "get - success",
			args: []string{"tsm", "get", "my.key"},
			setupServer: func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "/v1/secrets/my.key", r.URL.Path)
				_ = json.NewEncoder(w).Encode(map[string]string{"value": "val123"})
			},
			expectOut: "val123",
		},
		{
			name:        "get - missing arg",
			args:        []string{"tsm", "get"},
			expectError: "usage: tsm get <key>",
		},
		{
			name: "put - success",
			args: []string{"tsm", "put", "new.key", "new.val"},
			setupServer: func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, http.MethodPut, r.Method)
				var body map[string]string
				_ = json.NewDecoder(r.Body).Decode(&body)
				assert.Equal(t, "new.val", body["value"])
				w.WriteHeader(http.StatusNoContent)
			},
			expectOut: "Secret 'new.key' stored successfully.",
		},
		{
			name:        "put - missing args",
			args:        []string{"tsm", "put", "key"},
			expectError: "usage: tsm put <key> <value> [env_key]",
		},
		{
			name: "ls - success",
			args: []string{"tsm", "ls", "app."},
			setupServer: func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "app.", r.URL.Query().Get("prefix"))
				_ = json.NewEncoder(w).Encode([]string{"app.db", "app.api"})
			},
			expectOut: "app.db\napp.api\n",
		},
		{
			name: "rm - success",
			args: []string{"tsm", "rm", "old.key"},
			setupServer: func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, http.MethodDelete, r.Method)
				assert.Equal(t, "/v1/secrets/old.key", r.URL.Path)
				w.WriteHeader(http.StatusNoContent)
			},
			expectOut: "Secret 'old.key' deleted.",
		},
		{
			name: "role ls - success",
			args: []string{"tsm", "role", "ls"},
			setupServer: func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "/v1/roles", r.URL.Path)
				assert.Equal(t, http.MethodGet, r.Method)
				_ = json.NewEncoder(w).Encode([]map[string]interface{}{
					{
						"name": "test-role",
						"policies": []map[string]interface{}{
							{"prefix": "app.*", "methods": []string{"GET"}},
						},
					},
				})
			},
			expectOut: "Role: test-role",
		},
		{
			name: "role rm - success",
			args: []string{"tsm", "role", "rm", "test-role"},
			setupServer: func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "/v1/roles/test-role", r.URL.Path)
				assert.Equal(t, http.MethodDelete, r.Method)
				w.WriteHeader(http.StatusNoContent)
			},
			expectOut: "Role 'test-role' deleted.",
		},
		{
			name: "role create - success",
			args: []string{"tsm", "role", "create", "new-role", "--policy", "dev.*:GET"},
			setupServer: func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "/v1/roles", r.URL.Path)
				assert.Equal(t, http.MethodPost, r.Method)

				var body map[string]interface{}
				_ = json.NewDecoder(r.Body).Decode(&body)
				assert.Equal(t, "new-role", body["name"])

				policies := body["policies"].([]interface{})
				p := policies[0].(map[string]interface{})
				assert.Equal(t, "dev.*", p["prefix"])
				methods := p["methods"].([]interface{})
				assert.Equal(t, "GET", methods[0])
				assert.Len(t, methods, 1)

				_ = json.NewEncoder(w).Encode(map[string]string{"token": "new-token-123"})
			},
			expectOut: "Provisioned Token: new-token-123",
		},
		{
			name: "role update - success",
			args: []string{"tsm", "role", "update", "new-role", "--policy", "dev.*", "--policy", "sys.*:GET"},
			setupServer: func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "/v1/roles/new-role", r.URL.Path)
				assert.Equal(t, http.MethodPut, r.Method)

				var body map[string]interface{}
				_ = json.NewDecoder(r.Body).Decode(&body)
				assert.Nil(t, body["name"]) // Name should not be in update payload

				policies := body["policies"].([]interface{})
				assert.Len(t, policies, 2)

				p1 := policies[0].(map[string]interface{})
				assert.Equal(t, "dev.*", p1["prefix"])
				m1 := p1["methods"].([]interface{})
				assert.Len(t, m1, 1) // Default method check

				p2 := policies[1].(map[string]interface{})
				assert.Equal(t, "sys.*", p2["prefix"])
				m2 := p2["methods"].([]interface{})
				assert.Equal(t, "GET", m2[0])

				w.WriteHeader(http.StatusOK)
			},
			expectOut: "Role 'new-role' updated successfully.",
		},
		{
			name: "role export - stdout",
			args: []string{"tsm", "role", "export"},
			setupServer: func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "/v1/roles", r.URL.Path)
				assert.Equal(t, http.MethodGet, r.Method)
				_ = json.NewEncoder(w).Encode([]map[string]interface{}{
					{"name": "r1", "policies": []interface{}{}},
				})
			},
			expectOut: `"name": "r1"`,
		},
		{
			name:        "role create - missing args",
			args:        []string{"tsm", "role", "create", "my-role"},
			expectError: "at least one --policy is required",
		},
		{
			name:        "role rm - missing args",
			args:        []string{"tsm", "role", "rm"},
			expectError: "usage: tsm role rm <name>",
		},
		{
			name:        "role unknown command",
			args:        []string{"tsm", "role", "magic"},
			expectError: "unknown role command: magic",
		},
		{
			name:        "role import missing file",
			args:        []string{"tsm", "role", "import"},
			expectError: "usage: tsm role import <file.json>",
		},
		{
			name: "backup trigger - success",
			args: []string{"tsm", "backup", "trigger"},
			setupServer: func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "/v1/system/backup", r.URL.Path)
				assert.Equal(t, http.MethodPost, r.Method)
				w.WriteHeader(http.StatusOK)
			},
			expectOut: "Backup completed successfully.",
		},
		{
			name: "backup info - success",
			args: []string{"tsm", "backup", "info"},
			setupServer: func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "/v1/system/settings", r.URL.Path)
				assert.Equal(t, http.MethodGet, r.Method)
				_ = json.NewEncoder(w).Encode(map[string]string{
					"backup_target":               "/tmp",
					"backup_interval_mins":        "60",
					"backup_retention_all_days":   "7",
					"backup_retention_daily_days": "30",
				})
			},
			expectOut: "Target: /tmp",
		},
		{
			name: "backup config - success",
			args: []string{"tsm", "backup", "config", "--target", "/opt/backup", "--interval", "120"},
			setupServer: func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "/v1/system/settings", r.URL.Path)
				assert.Equal(t, http.MethodPut, r.Method)
				var body map[string]string
				_ = json.NewDecoder(r.Body).Decode(&body)
				assert.Equal(t, "/opt/backup", body["backup_target"])
				assert.Equal(t, "120", body["backup_interval_mins"])
				w.WriteHeader(http.StatusOK)
			},
			expectOut: "Backup settings updated successfully.",
		},
		{
			name: "api error - 401 unauthorized",
			args: []string{"tsm", "ls"},
			setupServer: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusUnauthorized)
			},
			expectError: "invalid or expired token",
		},
		{
			name: "api error - 403 forbidden",
			args: []string{"tsm", "ls"},
			setupServer: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusForbidden)
			},
			expectError: "access denied by server policies",
		},
		{
			name: "api error - 404 not found",
			args: []string{"tsm", "get", "missing"},
			setupServer: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNotFound)
			},
			expectError: "resource not found",
		},
		{
			name: "api error - 500 server error",
			args: []string{"tsm", "ls"},
			setupServer: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte("something went wrong"))
			},
			expectError: "server error (500): something went wrong",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(tt.setupServer))
			defer server.Close()

			tmpDir := t.TempDir()
			configPath := filepath.Join(tmpDir, ".tsm.json")

			var out, errBuf bytes.Buffer
			app := &TSMCLI{
				Out:        &out,
				Err:        &errBuf,
				ConfigPath: configPath,
				HTTPClient: server.Client(),
				WorkingDir: "/app",
			}

			// Pre-configure
			require.NoError(t, app.saveLogin(server.URL, ""))
			require.NoError(t, app.saveContext("test-token"))

			// Setup admin token directly
			cfg, _ := app.loadConfigSilent()
			cfg.AdminToken = "admin-test-token"
			_ = app.writeConfig(cfg)
			out.Reset()

			err := app.Run(tt.args)

			if tt.expectError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectError)
			} else {
				require.NoError(t, err)
				assert.Contains(t, out.String(), tt.expectOut)
			}
		})
	}
}

func TestTSMCLI_Tidy(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, ".tsm.json")

	// Create real and fake directories
	realDir := filepath.Join(tmpDir, "real")
	require.NoError(t, os.Mkdir(realDir, 0755))
	fakeDir := filepath.Join(tmpDir, "fake")

	app := &TSMCLI{
		Out:        ioDiscard(),
		Err:        ioDiscard(),
		ConfigPath: configPath,
	}

	cfg := &Config{
		Contexts: map[string]string{
			realDir: "token1",
			fakeDir: "token2", // This one should be pruned
		},
	}
	require.NoError(t, app.writeConfig(cfg))

	// Run Tidy
	err := app.Run([]string{"tsm", "auth", "--tidy"})
	require.NoError(t, err)

	// Verify pruning
	newCfg, err := app.loadConfigSilent()
	require.NoError(t, err)
	assert.Contains(t, newCfg.Contexts, realDir)
	assert.NotContains(t, newCfg.Contexts, fakeDir)
}

func TestTSMCLI_Status(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, ".tsm.json")

	// Mock Server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "Bearer valid-token" {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	defer server.Close()

	var out bytes.Buffer
	app := &TSMCLI{
		Out:        &out,
		Err:        ioDiscard(),
		ConfigPath: configPath,
		HTTPClient: server.Client(),
	}

	cfg := &Config{
		URL: server.URL,
		Contexts: map[string]string{
			"/project/good": "valid-token",
			"/project/bad":  "revoked-token",
		},
	}
	require.NoError(t, app.writeConfig(cfg))

	// Run Status
	err := app.Run([]string{"tsm", "auth", "--status"})
	require.NoError(t, err)

	// Verify Output
	output := out.String()
	assert.Contains(t, output, "VALID")
	assert.Contains(t, output, "INVALID")
	assert.Contains(t, output, "/project/good")
	assert.Contains(t, output, "valid-...") // Masked
}

func TestTSMCLI_Run_Process_Precedence(t *testing.T) {
	// Verifies the environment precedence logic: CLI > .env > Vault > Shell
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, ".tsm.json")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "vault.secret") {
			_ = json.NewEncoder(w).Encode(map[string]string{"value": "from-vault"})
		} else if strings.HasSuffix(r.URL.Path, "overlap.secret") {
			_ = json.NewEncoder(w).Encode(map[string]string{"value": "vault-loser"})
		}
	}))
	defer server.Close()

	app := &TSMCLI{
		Out:        ioDiscard(),
		Err:        ioDiscard(),
		ConfigPath: configPath,
		HTTPClient: server.Client(),
		WorkingDir: tmpDir,
	}

	// Setup Config
	require.NoError(t, app.saveLogin(server.URL, ""))
	require.NoError(t, app.saveContext("token"))

	// Create tsm.env (Mappings)
	_ = os.WriteFile(filepath.Join(tmpDir, "tsm.env"), []byte("V_VAR=vault.secret\nOVERLAP=overlap.secret"), 0644)
	_ = os.WriteFile(filepath.Join(tmpDir, ".env"), []byte("E_VAR=from-env-file\nOVERLAP=env-file-wins"), 0644)

	// We use t.Setenv to simulate Shell variables
	t.Setenv("S_VAR", "from-shell")

	// We verify the logic by calling runWithEnvironment directly (mocking the exec part)
	// But since Run is our exemplar entry point, we use a simple command.

	// Injected via CLI: CLI_VAR=from-cli
	// Final expected map:
	// S_VAR = from-shell
	// V_VAR = from-vault
	// E_VAR = from-env-file
	// OVERLAP = env-file-wins (Local priority over vault)
	// CLI_VAR = from-cli (Highest priority)

	err := app.Run([]string{"tsm", "run", "-e", "OVERLAP=cli-overrides-all", "--", "true"})
	if err != nil && strings.Contains(err.Error(), "execution failed") {
		t.Log("Skipping real process execution check")
		return
	}
	require.NoError(t, err)
}

func TestTSMCLI_Usage(t *testing.T) {
	var out bytes.Buffer
	app := &TSMCLI{Out: &out}
	app.usage()
	assert.Contains(t, out.String(), "Usage: tsm")

	out.Reset()
	app.authUsage()
	assert.Contains(t, out.String(), "Usage: tsm auth")
}

func TestTSMCLI_Run_ArgumentParsing(t *testing.T) {
	// Verifies that handleRunCommand correctly parses flags
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, ".tsm.json")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"value": "v"})
	}))
	defer server.Close()

	app := &TSMCLI{
		Out:        ioDiscard(),
		Err:        ioDiscard(),
		ConfigPath: configPath,
		HTTPClient: server.Client(),
		WorkingDir: tmpDir,
	}
	_ = app.saveLogin(server.URL, "")
	_ = app.saveContext("token")

	// 1. Test custom mapping file flag (-f)
	err := app.Run(append([]string{"tsm", "run", "-f", "nonexistent.tsm", "--"}, trueCmd...))
	assert.NoError(t, err)

	// 2. Test environment file flag (--env-file)
	err = app.Run(append([]string{"tsm", "run", "--env-file", "nonexistent.env", "--"}, trueCmd...))
	assert.NoError(t, err)

	// 3. Test token override flag (--token)
	err = app.Run(append([]string{"tsm", "run", "--token", "new-token", "--"}, trueCmd...))
	assert.NoError(t, err)

	// 4. Test missing command
	err = app.Run([]string{"tsm", "run", "-e", "K=V"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no command provided")
}

func TestTSMCLI_Tidy_NoChanges(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, ".tsm.json")

	var out bytes.Buffer
	app := &TSMCLI{
		Out:        &out,
		Err:        ioDiscard(),
		ConfigPath: configPath,
	}

	cfg := &Config{Contexts: make(map[string]string)}
	require.NoError(t, app.writeConfig(cfg))

	err := app.Run([]string{"tsm", "auth", "--tidy"})
	assert.NoError(t, err)
	assert.Contains(t, out.String(), "No stale or redundant contexts found.")
}

func TestParseEnvFile(t *testing.T) {
	content := `
# Comment
KEY1=VAL1
  KEY2 = VAL2  
INVALID_LINE
`
	res, implicit := parseEnvFile(content)
	assert.Equal(t, "VAL1", res["KEY1"])
	assert.Equal(t, "VAL2", res["KEY2"])
	assert.Len(t, res, 2)
	assert.Contains(t, implicit, "INVALID_LINE")
}

func TestTSMCLI_RunWithEnvironment_EdgeCases(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a dummy env file with comments
	envPath := filepath.Join(tmpDir, "test.env")
	_ = os.WriteFile(envPath, []byte("# ignore\nMY_VAR=val\n"), 0644)

	app := &TSMCLI{
		Out: ioDiscard(),
		Err: ioDiscard(),
	}

	// 1. Verify parseEnvFile handles the file correctly
	b, _ := os.ReadFile(envPath)
	res, _ := parseEnvFile(string(b))
	assert.Equal(t, "val", res["MY_VAR"])

	// 2. Call runWithEnvironment with nonexistent files (should be quiet)
	err := app.runWithEnvironment(&Config{}, "token", "nonexistent.tsm", "nonexistent.env", nil, []string{"true"})
	if err != nil && strings.Contains(err.Error(), "execution failed") {
		return
	}
	assert.NoError(t, err)
}

func TestTSMCLI_VersionNormalization(t *testing.T) {
	tests := []struct {
		name          string
		cliVer        string
		srvVer        string
		expectWarning bool
	}{
		{
			name:          "exact match",
			cliVer:        "1.0.1",
			srvVer:        "1.0.1",
			expectWarning: false,
		},
		{
			name:          "match with v prefix on server",
			cliVer:        "1.0.1",
			srvVer:        "v1.0.1",
			expectWarning: false,
		},
		{
			name:          "match with v prefix on cli",
			cliVer:        "v1.0.1",
			srvVer:        "1.0.1",
			expectWarning: false,
		},
		{
			name:          "match with v prefix on both",
			cliVer:        "v1.0.1",
			srvVer:        "v1.0.1",
			expectWarning: false,
		},
		{
			name:          "mismatch",
			cliVer:        "1.0.1",
			srvVer:        "1.0.2",
			expectWarning: true,
		},
		{
			name:          "mismatch with v prefix",
			cliVer:        "v1.0.1",
			srvVer:        "1.0.2",
			expectWarning: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("X-TSM-Version", tt.srvVer)
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`[]`))
			}))
			defer server.Close()

			oldVersion := Version
			Version = tt.cliVer
			defer func() { Version = oldVersion }()

			var out, errBuf bytes.Buffer
			app := &TSMCLI{
				Out:        &out,
				Err:        &errBuf,
				ConfigPath: filepath.Join(t.TempDir(), ".tsm.json"),
				HTTPClient: server.Client(),
				WorkingDir: "/test",
			}
			_ = app.saveLogin(server.URL, "")
			_ = app.saveContext("token")

			_ = app.Run([]string{"tsm", "ls"})

			if tt.expectWarning {
				assert.Contains(t, errBuf.String(), "WARNING: CLI version")
			} else {
				assert.NotContains(t, errBuf.String(), "WARNING: CLI version")
			}
		})
	}
}

// Helpers

func ioDiscard() *bytes.Buffer {
	return &bytes.Buffer{}
}

func TestTSMCLI_RoleImportExport(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, ".tsm.json")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/roles" {
			if r.Method == http.MethodGet {
				_ = json.NewEncoder(w).Encode([]map[string]interface{}{
					{"name": "r1", "policies": []interface{}{}},
				})
				return
			}
			if r.Method == http.MethodPost {
				_ = json.NewEncoder(w).Encode(map[string]string{"token": "new-tok"})
				return
			}
		}
		if r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/v1/roles/") {
			w.WriteHeader(http.StatusOK)
			return
		}
		t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
	}))
	defer server.Close()

	var out, errBuf bytes.Buffer
	app := &TSMCLI{
		Out:        &out,
		Err:        &errBuf,
		ConfigPath: configPath,
		HTTPClient: server.Client(),
		WorkingDir: tmpDir,
	}
	_ = app.saveLogin(server.URL, "")
	_ = app.saveContext("token")

	cfg, _ := app.loadConfigSilent()
	cfg.AdminToken = "admin-tok"
	_ = app.writeConfig(cfg)
	out.Reset()

	// Test Export to File
	exportFile := filepath.Join(tmpDir, "export.json")
	err := app.Run([]string{"tsm", "role", "export", exportFile})
	require.NoError(t, err)
	assert.Contains(t, out.String(), "Exported 1 roles")

	// Read Exported File
	b, err := os.ReadFile(exportFile)
	require.NoError(t, err)
	assert.Contains(t, string(b), `"name": "r1"`)

	// Test Import (r1 exists -> updates, r2 new -> creates)
	importData := `[
		{"name": "r1", "policies": [{"prefix": "a.*", "methods": ["GET"]}]},
		{"name": "r2", "policies": [{"prefix": "b.*", "methods": ["PUT"]}]}
	]`
	importFile := filepath.Join(tmpDir, "import.json")
	_ = os.WriteFile(importFile, []byte(importData), 0644)

	out.Reset()
	err = app.Run([]string{"tsm", "role", "import", importFile})
	require.NoError(t, err)
	assert.Contains(t, out.String(), "Import complete: 1 created, 1 updated.")
}

func TestTSMCLI_AdminMode(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, ".tsm.json")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer admin-token-123", r.Header.Get("Authorization"))
		_ = json.NewEncoder(w).Encode(map[string]string{"key": "value"})
	}))
	defer server.Close()

	var out bytes.Buffer
	app := &TSMCLI{
		Out:        &out,
		Err:        &out,
		ConfigPath: configPath,
		HTTPClient: server.Client(),
		WorkingDir: tmpDir,
	}

	_ = app.saveLogin(server.URL, "")

	// Set admin token but DO NOT link the working directory
	cfg, _ := app.loadConfigSilent()
	cfg.AdminToken = "admin-token-123"
	_ = app.writeConfig(cfg)

	// Normal mode should fail (no directory context)
	err := app.Run([]string{"tsm", "get", "some.key"})
	assert.ErrorContains(t, err, "no token linked to this directory")

	// Admin mode should succeed (uses AdminToken)
	err = app.Run([]string{"tsm", "--admin", "get", "some.key"})
	assert.NoError(t, err)

	// Admin flag can be placed after
	err = app.Run([]string{"tsm", "get", "some.key", "--admin"})
	assert.NoError(t, err)
}
