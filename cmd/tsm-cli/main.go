package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/term"
)

var Version = "dev"

// Config represents the local CLI configuration stored in ~/.tsm.json.
type Config struct {
	URL        string            `json:"url"`                   // Server base URL
	AdminToken string            `json:"admin_token,omitempty"` // Global admin token
	Contexts   map[string]string `json:"contexts"`              // Filesystem path -> machine token mapping
}

const (
	defaultTimeout = 10 * time.Second
	configFilename = ".tsm.json"
)

// TSMCLI encapsulates the dependencies for the CLI application,
// allowing for easy mocking in tests.
type TSMCLI struct {
	Out        io.Writer
	Err        io.Writer
	ConfigPath string
	HTTPClient *http.Client
	WorkingDir string
}

func main() {
	home, _ := os.UserHomeDir()
	app := &TSMCLI{
		Out:        os.Stdout,
		Err:        os.Stderr,
		ConfigPath: filepath.Join(home, configFilename),
		HTTPClient: &http.Client{Timeout: defaultTimeout},
	}

	if err := app.Run(os.Args); err != nil {
		fmt.Fprintf(app.Err, "Error: %v\n", err)
		os.Exit(1)
	}
}

// Run is the entry point for the CLI logic.
func (c *TSMCLI) Run(args []string) error {
	if len(args) < 2 {
		c.usage()
		return nil
	}

	var cleanArgs []string
	useAdminMode := false
	globalToken := ""
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--admin" && (len(args) < 3 || args[1] != "auth") {
			useAdminMode = true
		} else if arg == "--token" && i+1 < len(args) {
			globalToken = args[i+1]
			i++
		} else {
			cleanArgs = append(cleanArgs, arg)
		}
	}
	args = cleanArgs

	if len(args) < 2 {
		c.usage()
		return nil
	}

	if c.WorkingDir == "" {
		wd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("failed to get working directory: %w", err)
		}
		c.WorkingDir = wd
	}

	cmd := args[1]

	// 1. Commands that don't require any pre-existing configuration
	switch cmd {
	case "help", "--help", "-h":
		c.usage()
		return nil
	case "version", "--version", "-v":
		fmt.Fprintf(c.Out, "tsm CLI version %s\n", Version)
		return nil
	case "login":
		var url, username string
		argsList := args[2:]
		for i := 0; i < len(argsList); i++ {
			if argsList[i] == "-u" && i+1 < len(argsList) {
				username = argsList[i+1]
				i++
			} else if !strings.HasPrefix(argsList[i], "-") {
				url = argsList[i]
			}
		}

		cfg, _ := c.loadConfigSilent()
		if url == "" {
			if cfg.URL != "" {
				url = cfg.URL
			} else {
				return errors.New("usage: tsm login [url] [-u username]\nError: url required if not previously configured")
			}
		}

		return c.saveLogin(url, username)
	}

	// 2. Handle 'auth' commands
	if cmd == "auth" {
		if len(args) < 3 {
			c.authUsage()
			return nil
		}
		cfg, _ := c.loadConfigSilent()
		switch args[2] {
		case "--link":
			if len(args) < 4 {
				return errors.New("usage: tsm auth --link <token>")
			}
			return c.saveContext(args[3])
		case "--tidy":
			return c.tidyContexts(cfg)
		case "--status":
			return c.statusContexts(cfg)
		case "--admin":
			if len(args) < 4 {
				return errors.New("usage: tsm auth --admin <token>")
			}
			cfg.AdminToken = args[3]
			if err := c.writeConfig(cfg); err != nil {
				return err
			}
			fmt.Fprintln(c.Out, "Admin token saved globally.")
			return nil
		default:
			c.authUsage()
			return nil
		}
	}

	// 3. Command specific loading
	if cmd == "role" {
		if len(args) < 3 {
			c.roleUsage()
			return nil
		}
		cfg, _, err := c.loadConfig(false, globalToken)
		if err != nil {
			return err
		}
		if cfg.AdminToken == "" {
			return errors.New("no admin token configured. Run 'tsm auth --admin <token>' to set it")
		}
		return c.handleRoleCommand(cfg, cfg.AdminToken, args[2:])
	}

	if cmd == "backup" {
		if len(args) < 3 {
			c.backupUsage()
			return nil
		}
		cfg, _, err := c.loadConfig(false, globalToken)
		if err != nil {
			return err
		}
		if cfg.AdminToken == "" {
			return errors.New("no admin token configured. Run 'tsm auth --admin <token>' to set it")
		}
		return c.handleBackupCommand(cfg, cfg.AdminToken, args[2:])
	}

	// 4. All other commands require a resolved configuration and token
	requireDirectoryToken := !useAdminMode
	cfg, activeToken, err := c.loadConfig(requireDirectoryToken, globalToken)
	if err != nil {
		return err
	}

	if useAdminMode {
		if cfg.AdminToken == "" {
			return errors.New("no admin token configured. Run 'tsm auth --admin <token>' to set it")
		}
		activeToken = cfg.AdminToken
	}

	switch cmd {
	case "get":
		if len(args) < 3 {
			return errors.New("usage: tsm get <key>")
		}
		return c.getSecret(cfg, activeToken, args[2])
	case "put":
		if len(args) < 4 {
			return errors.New("usage: tsm put <key> <value> [env_key]")
		}
		envKey := ""
		grantMethods := []string{}
		for i := 4; i < len(args); i++ {
			if args[i] == "--grant" && i+1 < len(args) {
				grantMethods = strings.Split(strings.ToUpper(args[i+1]), ",")
				i++
			} else if !strings.HasPrefix(args[i], "--") && envKey == "" {
				envKey = args[i]
			}
		}
		return c.putSecret(cfg, activeToken, args[2], args[3], envKey, grantMethods)
	case "ls", "list":
		prefix := ""
		if len(args) > 2 {
			prefix = args[2]
		}
		return c.listSecrets(cfg, activeToken, prefix)
	case "rm", "delete":
		if len(args) < 3 {
			return errors.New("usage: tsm rm <key>")
		}
		return c.deleteSecret(cfg, activeToken, args[2])
	case "run":
		return c.handleRunCommand(cfg, activeToken, args[2:])
	default:
		c.usage()
		return fmt.Errorf("unknown command: %s", cmd)
	}
}

func (c *TSMCLI) usage() {
	fmt.Fprintln(c.Out, "Usage: tsm [global flags] <command> [arguments]")
	fmt.Fprintln(c.Out, "\nGlobal Flags:")
	fmt.Fprintln(c.Out, "  --admin             - Run the command in Admin Mode using the global admin token")
	fmt.Fprintln(c.Out, "\nCommands:")
	fmt.Fprintln(c.Out, "  version             - Print the CLI version")
	fmt.Fprintln(c.Out, "  login [url]         - Set the server URL and/or authenticate")
	fmt.Fprintln(c.Out, "  auth <flags>        - Manage directory/token contexts")
	fmt.Fprintln(c.Out, "  get <key>           - Fetch and print a secret value")
	fmt.Fprintln(c.Out, "  put <key> <value> [env] [--grant methods] - Store a secret value with an optional default environment variable mapping")
	fmt.Fprintln(c.Out, "  ls [prefix]         - List all available secret keys")
	fmt.Fprintln(c.Out, "  rm <key>            - Permanently delete a secret")
	fmt.Fprintln(c.Out, "  role <cmd>          - Manage roles (create, ls, rm)")
	fmt.Fprintln(c.Out, "  backup <cmd>        - Manage backups (trigger, config, info)")
	fmt.Fprintln(c.Out, "  run [flags] -- <cmd> - Run a command with injected secrets")
	fmt.Fprintln(c.Out, "\nRun Flags:")
	fmt.Fprintln(c.Out, "  --token <token>     - Explicitly provide a token for this run")
	fmt.Fprintln(c.Out, "  -f, --file <path>   - TSM mapping file (default: tsm.env)")
	fmt.Fprintln(c.Out, "  --env-file <path>   - Standard .env file (default: .env)")
	fmt.Fprintln(c.Out, "  -e KEY=VAL          - Explicit environment override")
}

func (c *TSMCLI) authUsage() {
	fmt.Fprintln(c.Out, "Usage: tsm auth <flag>")
	fmt.Fprintln(c.Out, "\nFlags:")
	fmt.Fprintln(c.Out, "  --link <token>  - Link current directory to a token")
	fmt.Fprintln(c.Out, "  --admin <token> - Set the global admin token for role management")
	fmt.Fprintln(c.Out, "  --tidy          - Prune stale or redundant context mappings")
	fmt.Fprintln(c.Out, "  --status        - Show active contexts and validate tokens")
}

func (c *TSMCLI) roleUsage() {
	fmt.Fprintln(c.Out, "Usage: tsm role <command> [arguments]")
	fmt.Fprintln(c.Out, "\nCommands:")
	fmt.Fprintln(c.Out, "  ls                                       - List all roles")
	fmt.Fprintln(c.Out, "  create <name> [--can-create] --policy <prefix>[:<methods>] - Create a new role")
	fmt.Fprintln(c.Out, "  update <name> [--can-create] --policy <prefix>[:<methods>] - Update an existing role's policies")
	fmt.Fprintln(c.Out, "  rm <name>                                - Delete a role")
	fmt.Fprintln(c.Out, "  export [file.json]                       - Export all roles as JSON")
	fmt.Fprintln(c.Out, "  import <file.json>                       - Bulk create/update roles from JSON")
}

func (c *TSMCLI) backupUsage() {
	fmt.Fprintln(c.Out, "Usage: tsm backup <command> [arguments]")
	fmt.Fprintln(c.Out, "\nCommands:")
	fmt.Fprintln(c.Out, "  trigger                                  - Immediately run a backup")
	fmt.Fprintln(c.Out, "  config --target <path> [flags]           - Set backup target and retention")
	fmt.Fprintln(c.Out, "      --interval <mins>                      (default 5)")
	fmt.Fprintln(c.Out, "      --keep-all <days>                      (default 1)")
	fmt.Fprintln(c.Out, "      --keep-daily <days>                    (default 30)")
	fmt.Fprintln(c.Out, "  info                                     - Show backup configuration")
}

func (c *TSMCLI) loadConfig(requireDirectoryToken bool, overrideToken string) (*Config, string, error) {
	cfg, _ := c.loadConfigSilent()

	if envURL := os.Getenv("TSM_URL"); envURL != "" {
		cfg.URL = envURL
	}

	if cfg.URL == "" {
		return nil, "", errors.New("TSM URL not set. Run 'tsm login <url>' or set TSM_URL environment variable")
	}
	cfg.URL = strings.TrimSuffix(cfg.URL, "/")

	var bestMatch string
	var activeToken string

	if overrideToken != "" {
		activeToken = overrideToken
	} else {
		for p, token := range cfg.Contexts {
			if strings.HasPrefix(c.WorkingDir, p) {
				if len(p) > len(bestMatch) {
					bestMatch = p
					activeToken = token
				}
			}
		}
	}

	if activeToken == "" && requireDirectoryToken {
		return nil, "", fmt.Errorf("no token linked to this directory (%s).\nRun 'tsm auth --link <token>' to associate it", c.WorkingDir)
	}

	return cfg, activeToken, nil
}

func (c *TSMCLI) loadConfigSilent() (*Config, error) {
	b, err := os.ReadFile(c.ConfigPath)
	if err != nil {
		return &Config{Contexts: make(map[string]string)}, nil
	}

	var cfg Config
	if err := json.Unmarshal(b, &cfg); err != nil {
		return &Config{Contexts: make(map[string]string)}, fmt.Errorf("invalid config file: %w", err)
	}
	if cfg.Contexts == nil {
		cfg.Contexts = make(map[string]string)
	}
	return &cfg, nil
}

func (c *TSMCLI) writeConfig(cfg *Config) error {
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}
	return os.WriteFile(c.ConfigPath, b, 0600)
}

func (c *TSMCLI) saveLogin(serverURL, username string) error {
	cfg, _ := c.loadConfigSilent()
	cfg.URL = strings.TrimSuffix(serverURL, "/")
	if err := c.writeConfig(cfg); err != nil {
		return err
	}
	fmt.Fprintf(c.Out, "Server URL set to %s\n", cfg.URL)

	if username == "" {
		return nil
	}

	fmt.Fprintf(c.Out, "Password for %s: ", username)
	passwordBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return fmt.Errorf("\nfailed to read password: %w", err)
	}
	fmt.Fprintln(c.Out)

	reqBody, _ := json.Marshal(map[string]string{
		"username": username,
		"password": string(passwordBytes),
	})

	req, err := http.NewRequest("POST", cfg.URL+"/v1/auth/login", bytes.NewReader(reqBody))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("login failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("login failed (HTTP %d): %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}

	var res struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil || res.Token == "" {
		return errors.New("login failed: server did not return a valid admin token")
	}

	cfg.AdminToken = res.Token
	if err := c.writeConfig(cfg); err != nil {
		return err
	}

	fmt.Fprintln(c.Out, "Login successful. Global Admin Mode token securely saved.")
	return nil
}

func (c *TSMCLI) saveContext(token string) error {
	cfg, _ := c.loadConfigSilent()
	cfg.Contexts[c.WorkingDir] = token
	if err := c.writeConfig(cfg); err != nil {
		return err
	}
	fmt.Fprintf(c.Out, "Linked directory %s to token.\n", c.WorkingDir)
	return nil
}

func maskToken(token string) string {
	if len(token) <= 10 {
		return "**********"
	}
	return token[:6] + "..." + token[len(token)-4:]
}

func (c *TSMCLI) tidyContexts(cfg *Config) error {
	fmt.Fprintln(c.Out, "Pruning stale contexts...")
	changed := false

	for path := range cfg.Contexts {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			fmt.Fprintf(c.Out, "- Removed: %s (Directory not found)\n", path)
			delete(cfg.Contexts, path)
			changed = true
		}
	}

	for path, token := range cfg.Contexts {
		for parentPath, parentToken := range cfg.Contexts {
			if path != parentPath && strings.HasPrefix(path, parentPath) && token == parentToken {
				fmt.Fprintf(c.Out, "- Removed: %s (Redundant, parent %s mapped to same token)\n", path, parentPath)
				delete(cfg.Contexts, path)
				changed = true
				break
			}
		}
	}

	if changed {
		if err := c.writeConfig(cfg); err != nil {
			return err
		}
		fmt.Fprintln(c.Out, "\nCleanup complete.")
	} else {
		fmt.Fprintln(c.Out, "No stale or redundant contexts found.")
	}
	return nil
}

func (c *TSMCLI) statusContexts(cfg *Config) error {
	if len(cfg.Contexts) == 0 {
		fmt.Fprintln(c.Out, "No active contexts found.")
		return nil
	}

	if cfg.URL == "" {
		fmt.Fprintln(c.Out, "Warning: Server URL not set. Run 'tsm login <url>' to enable API validation.")
		fmt.Fprintln(c.Out, "Showing local contexts only:")
		for path, token := range cfg.Contexts {
			fmt.Fprintf(c.Out, "[      ] %-40s (Token: %s)\n", path, maskToken(token))
		}
		return nil
	}

	fmt.Fprintln(c.Out, "Validating active contexts...")

	tokenStatus := make(map[string]string)

	for path, token := range cfg.Contexts {
		status, ok := tokenStatus[token]
		if !ok {
			_, err := c.apiRequest(token, "GET", "auth/me", nil)
			if err == nil {
				status = "✅ VALID"
			} else if strings.Contains(err.Error(), "invalid") || strings.Contains(err.Error(), "denied") {
				status = "❌ INVALID"
			} else {
				status = "⚠️ ERROR"
			}
			tokenStatus[token] = status
		}

		fmt.Fprintf(c.Out, "[%s] %-40s (Token: %s)\n", status, path, maskToken(token))
		if status == "❌ INVALID" {
			fmt.Fprintf(c.Out, "           -> Action required: Run 'tsm auth --link' with a valid token.\n")
		} else if status == "⚠️ ERROR" {
			fmt.Fprintf(c.Out, "           -> Network error or server unreachable.\n")
		}
	}
	return nil
}

func (c *TSMCLI) apiRequest(token, method, path string, body []byte) ([]byte, error) {
	cfg, _ := c.loadConfigSilent()
	if envURL := os.Getenv("TSM_URL"); envURL != "" {
		cfg.URL = envURL
	}
	url := fmt.Sprintf("%s/v1/%s", strings.TrimSuffix(cfg.URL, "/"), strings.TrimPrefix(path, "/"))
	// #nosec G107 G704 - The CLI is explicitly designed to communicate with the user's configured server URL
	req, err := http.NewRequestWithContext(context.Background(), method, url, bytes.NewBuffer(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	// #nosec G107 G704 - The CLI is designed to communicate with the user-configured TSM server
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("network error: %w", err)
	}
	defer resp.Body.Close()

	if srvVer := resp.Header.Get("X-TSM-Version"); srvVer != "" && Version != "dev" && srvVer != "dev" {
		normalizedSrvVer := strings.TrimPrefix(srvVer, "v")
		normalizedCliVer := strings.TrimPrefix(Version, "v")
		if normalizedSrvVer != normalizedCliVer {
			fmt.Fprintf(c.Err, "WARNING: CLI version (%s) does not match Server version (%s)\n", Version, srvVer)
		}
	}

	switch resp.StatusCode {
	case http.StatusOK, http.StatusNoContent, http.StatusCreated:
		// OK
	case http.StatusUnauthorized:
		return nil, errors.New("invalid or expired token (if using admin mode, run 'tsm login -u <username>' to re-authenticate)")
	case http.StatusForbidden:
		return nil, errors.New("access denied by server policies")
	case http.StatusNotFound:
		return nil, errors.New("resource not found")
	default:
		msg, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("server error (%d): %s", resp.StatusCode, string(msg))
	}

	return io.ReadAll(resp.Body)
}

func (c *TSMCLI) getSecret(cfg *Config, token, key string) error {
	data, err := c.apiRequest(token, "GET", "secrets/"+key, nil)
	if err != nil {
		return err
	}
	var res struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(data, &res); err != nil {
		return fmt.Errorf("failed to parse server response: %w", err)
	}
	fmt.Fprint(c.Out, res.Value)
	return nil
}

func (c *TSMCLI) putSecret(cfg *Config, token, key, value, envKey string, grantMethods []string) error {
	payload := map[string]interface{}{"value": value}
	if envKey != "" {
		payload["env_key"] = envKey
	}
	if len(grantMethods) > 0 {
		payload["grant_methods"] = grantMethods
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	_, err = c.apiRequest(token, "PUT", "secrets/"+key, body)
	if err != nil {
		return err
	}
	fmt.Fprintf(c.Out, "Secret '%s' stored successfully.\n", key)
	return nil
}

func (c *TSMCLI) listSecrets(cfg *Config, token, prefix string) error {
	path := "secrets"
	if prefix != "" {
		path += "?prefix=" + prefix
	}
	data, err := c.apiRequest(token, "GET", path, nil)
	if err != nil {
		return err
	}
	var keys []string
	if err := json.Unmarshal(data, &keys); err != nil {
		return fmt.Errorf("failed to parse server response: %w", err)
	}
	for _, k := range keys {
		fmt.Fprintln(c.Out, k)
	}
	return nil
}

func (c *TSMCLI) deleteSecret(cfg *Config, token, key string) error {
	_, err := c.apiRequest(token, "DELETE", "secrets/"+key, nil)
	if err != nil {
		return err
	}
	fmt.Fprintf(c.Out, "Secret '%s' deleted.\n", key)
	return nil
}

func parseEnvFile(content string) (map[string]string, []string) {
	explicit := make(map[string]string)
	var implicit []string
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			explicit[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		} else {
			implicit = append(implicit, strings.TrimSpace(parts[0]))
		}
	}
	return explicit, implicit
}

func (c *TSMCLI) handleRunCommand(cfg *Config, activeToken string, args []string) error {
	var tsmEnv = "tsm.env"
	var dotEnv = ".env"
	var cliEnvs []string
	var targetCmd []string

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			targetCmd = args[i+1:]
			break
		}
		switch arg {
		case "-f", "--file":
			if i+1 < len(args) {
				tsmEnv = args[i+1]
				i++
			}
		case "--env-file":
			if i+1 < len(args) {
				dotEnv = args[i+1]
				i++
			}
		case "-e":
			if i+1 < len(args) {
				cliEnvs = append(cliEnvs, args[i+1])
				i++
			}
		}
	}

	if len(targetCmd) == 0 {
		c.usage()
		return errors.New("no command provided to run")
	}

	return c.runWithEnvironment(cfg, activeToken, tsmEnv, dotEnv, cliEnvs, targetCmd)
}

func (c *TSMCLI) runWithEnvironment(cfg *Config, token, tsmEnvPath, dotEnvPath string, cliEnvs []string, targetCmd []string) error {
	envMap := make(map[string]string)
	for _, e := range os.Environ() {
		parts := strings.SplitN(e, "=", 2)
		envMap[parts[0]] = parts[1]
	}

	// 1. TSM Mappings (Pointers)
	// #nosec G304 G703 - The CLI is explicitly designed to read local .env files
	if b, err := os.ReadFile(tsmEnvPath); err == nil {
		mappings, implicit := parseEnvFile(string(b))
		for envKey, secretKey := range mappings {
			data, err := c.apiRequest(token, "GET", "secrets/"+secretKey, nil)
			if err == nil {
				var res struct {
					Value string `json:"value"`
				}
				if err := json.Unmarshal(data, &res); err == nil {
					envMap[envKey] = res.Value
				}
			}
		}

		for _, secretKey := range implicit {
			data, err := c.apiRequest(token, "GET", "secrets/"+secretKey, nil)
			if err == nil {
				var res struct {
					Value  string `json:"value"`
					EnvKey string `json:"env_key"`
				}
				if err := json.Unmarshal(data, &res); err == nil {
					if res.EnvKey != "" {
						envMap[res.EnvKey] = res.Value
					} else {
						fmt.Fprintf(os.Stderr, "Warning: implicit secret '%s' has no env_key configured, skipping\n", secretKey)
					}
				}
			}
		}
	}

	// 2. Standard .env (Literals) - Local priority
	// #nosec G304 G703 - The CLI is explicitly designed to read local .env files
	if b, err := os.ReadFile(dotEnvPath); err == nil {
		literals, _ := parseEnvFile(string(b))
		for k, v := range literals {
			envMap[k] = v
		}
	}

	// 3. CLI Overrides (-e) - Ultimate priority
	for _, e := range cliEnvs {
		parts := strings.SplitN(e, "=", 2)
		if len(parts) == 2 {
			envMap[parts[0]] = parts[1]
		}
	}

	// #nosec G204 G702 - The CLI is specifically designed to wrap and execute arbitrary commands for the user
	cmd := exec.Command(targetCmd[0], targetCmd[1:]...)
	cmd.Env = make([]string, 0, len(envMap))
	for k, v := range envMap {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			os.Exit(exitErr.ExitCode())
		}
		return fmt.Errorf("command execution failed: %w", err)
	}
	return nil
}

func parsePolicies(args []string) ([]map[string]interface{}, error) {
	var policies []map[string]interface{}
	// Backward compatibility mapping for old --prefix and --methods
	var oldPrefix, oldMethods string
	hasOldArgs := false

	for i := 2; i < len(args); i++ {
		if args[i] == "--policy" && i+1 < len(args) {
			policyStr := args[i+1]
			parts := strings.SplitN(policyStr, ":", 2)
			prefix := parts[0]
			methods := "GET" // Default
			if len(parts) == 2 {
				methods = strings.ToUpper(parts[1])
			}
			policies = append(policies, map[string]interface{}{
				"prefix":  prefix,
				"methods": strings.Split(methods, ","),
			})
			i++
		} else if args[i] == "--prefix" && i+1 < len(args) {
			oldPrefix = args[i+1]
			hasOldArgs = true
			i++
		} else if args[i] == "--methods" && i+1 < len(args) {
			oldMethods = strings.ToUpper(args[i+1])
			hasOldArgs = true
			i++
		}
	}

	if hasOldArgs {
		if oldMethods == "" {
			oldMethods = "GET"
		}
		policies = append(policies, map[string]interface{}{
			"prefix":  oldPrefix,
			"methods": strings.Split(oldMethods, ","),
		})
	}

	if len(policies) == 0 {
		return nil, errors.New("at least one --policy is required")
	}
	return policies, nil
}

func (c *TSMCLI) handleRoleCommand(cfg *Config, token string, args []string) error {
	cmd := args[0]
	switch cmd {
	case "ls", "list":
		data, err := c.apiRequest(token, "GET", "roles", nil)
		if err != nil {
			return err
		}
		var roles []map[string]interface{}
		if err := json.Unmarshal(data, &roles); err != nil {
			return fmt.Errorf("failed to parse response: %w", err)
		}
		if len(roles) == 0 {
			fmt.Fprintln(c.Out, "No machine roles found.")
			return nil
		}
		for _, r := range roles {
			fmt.Fprintf(c.Out, "Role: %s\n", r["name"])
			if policies, ok := r["policies"].([]interface{}); ok {
				for _, pInf := range policies {
					if pMap, ok := pInf.(map[string]interface{}); ok {
						var methods []string
						if mArr, ok := pMap["methods"].([]interface{}); ok {
							for _, m := range mArr {
								methods = append(methods, fmt.Sprintf("%v", m))
							}
						}
						fmt.Fprintf(c.Out, "  - Prefix: %s, Methods: [%s]\n", pMap["prefix"], strings.Join(methods, ", "))
					}
				}
			}
			if cc, ok := r["can_create"].(bool); ok && cc {
				fmt.Fprintln(c.Out, "  - Global Permission: Can Create Secrets")
			}
		}
		return nil
	case "rm", "delete":
		if len(args) < 2 {
			return errors.New("usage: tsm role rm <name>")
		}
		_, err := c.apiRequest(token, "DELETE", "roles/"+args[1], nil)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.Out, "Role '%s' deleted.\n", args[1])
		return nil
	case "create":
		if len(args) < 2 {
			return errors.New("usage: tsm role create <name> [--can-create] --policy <prefix>[:<methods>] [...]")
		}
		canCreate := false
		var cleanArgs []string
		for _, a := range args {
			if a == "--can-create" {
				canCreate = true
			} else {
				cleanArgs = append(cleanArgs, a)
			}
		}
		args = cleanArgs
		name := args[1]
		policies, err := parsePolicies(args)
		if err != nil {
			return err
		}

		reqBody := map[string]interface{}{
			"name":       name,
			"policies":   policies,
			"can_create": canCreate,
		}
		body, err := json.Marshal(reqBody)
		if err != nil {
			return err
		}
		data, err := c.apiRequest(token, "POST", "roles", body)
		if err != nil {
			return err
		}
		var res map[string]string
		if err := json.Unmarshal(data, &res); err != nil {
			return fmt.Errorf("failed to parse response: %w", err)
		}
		fmt.Fprintf(c.Out, "Role '%s' created successfully.\nProvisioned Token: %s\n", name, res["token"])
		return nil
	case "update":
		if len(args) < 2 {
			return errors.New("usage: tsm role update <name> [--can-create] --policy <prefix>[:<methods>] [...]")
		}
		canCreate := false
		var cleanArgs []string
		for _, a := range args {
			if a == "--can-create" {
				canCreate = true
			} else {
				cleanArgs = append(cleanArgs, a)
			}
		}
		args = cleanArgs
		name := args[1]
		policies, err := parsePolicies(args)
		if err != nil {
			return err
		}

		reqBody := map[string]interface{}{
			"policies":   policies,
			"can_create": canCreate,
		}
		body, err := json.Marshal(reqBody)
		if err != nil {
			return err
		}
		_, err = c.apiRequest(token, "PUT", "roles/"+name, body)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.Out, "Role '%s' updated successfully.\n", name)
		return nil
	case "export":
		data, err := c.apiRequest(token, "GET", "roles", nil)
		if err != nil {
			return err
		}
		var roles []map[string]interface{}
		if err := json.Unmarshal(data, &roles); err != nil {
			return fmt.Errorf("failed to parse response: %w", err)
		}
		var export []map[string]interface{}
		for _, r := range roles {
			export = append(export, map[string]interface{}{
				"name":       r["name"],
				"policies":   r["policies"],
				"can_create": r["can_create"],
			})
		}
		b, _ := json.MarshalIndent(export, "", "  ")
		if len(args) >= 2 {
			// #nosec G306 G703 - The CLI is explicitly instructed by the user to write an export file
			if err := os.WriteFile(args[1], b, 0644); err != nil {
				return err
			}
			fmt.Fprintf(c.Out, "Exported %d roles to %s\n", len(export), args[1])
		} else {
			fmt.Fprintln(c.Out, string(b))
		}
		return nil
	case "import":
		if len(args) < 2 {
			return errors.New("usage: tsm role import <file.json>")
		}
		// #nosec G304 G703 - The CLI is explicitly instructed by the user to read an import file
		b, err := os.ReadFile(args[1])
		if err != nil {
			return err
		}
		var importRoles []map[string]interface{}
		if err := json.Unmarshal(b, &importRoles); err != nil {
			return fmt.Errorf("failed to parse JSON: %w", err)
		}

		data, err := c.apiRequest(token, "GET", "roles", nil)
		if err != nil {
			return err
		}
		var existingRoles []map[string]interface{}
		_ = json.Unmarshal(data, &existingRoles)
		existingMap := make(map[string]bool)
		for _, r := range existingRoles {
			if name, ok := r["name"].(string); ok {
				existingMap[name] = true
			}
		}

		createdCount := 0
		updatedCount := 0
		for _, r := range importRoles {
			name, ok := r["name"].(string)
			if !ok || name == "" {
				continue
			}
			policies, ok := r["policies"].([]interface{})
			if !ok {
				continue
			}

			canCreate, _ := r["can_create"].(bool)

			if existingMap[name] {
				reqBody := map[string]interface{}{"policies": policies, "can_create": canCreate}
				body, _ := json.Marshal(reqBody)
				if _, err := c.apiRequest(token, "PUT", "roles/"+name, body); err != nil {
					fmt.Fprintf(c.Out, "Failed to update role '%s': %v\n", name, err)
				} else {
					updatedCount++
				}
			} else {
				reqBody := map[string]interface{}{"name": name, "policies": policies, "can_create": canCreate}
				body, _ := json.Marshal(reqBody)
				data, err := c.apiRequest(token, "POST", "roles", body)
				if err != nil {
					fmt.Fprintf(c.Out, "Failed to create role '%s': %v\n", name, err)
				} else {
					var res map[string]string
					_ = json.Unmarshal(data, &res)
					fmt.Fprintf(c.Out, "Created role '%s'. Provisioned Token: %s\n", name, res["token"])
					createdCount++
				}
			}
		}
		fmt.Fprintf(c.Out, "Import complete: %d created, %d updated.\n", createdCount, updatedCount)
		return nil

	default:
		c.roleUsage()
		return fmt.Errorf("unknown role command: %s", cmd)
	}
}

func (c *TSMCLI) handleBackupCommand(cfg *Config, token string, args []string) error {
	if len(args) == 0 {
		c.backupUsage()
		return nil
	}

	subCmd := args[0]
	switch subCmd {
	case "trigger":
		_, err := c.apiRequest(token, "POST", "system/backup", nil)
		if err != nil {
			return fmt.Errorf("failed to trigger backup: %w", err)
		}
		fmt.Fprintln(c.Out, "Backup completed successfully.")
		return nil

	case "info":
		data, err := c.apiRequest(token, "GET", "system/settings", nil)
		if err != nil {
			return fmt.Errorf("failed to fetch settings: %w", err)
		}
		var settings map[string]string
		_ = json.Unmarshal(data, &settings)
		fmt.Fprintln(c.Out, "Backup Configuration:")
		fmt.Fprintf(c.Out, "  Target: %s\n", settings["backup_target"])
		fmt.Fprintf(c.Out, "  Interval: %s mins\n", settings["backup_interval_mins"])
		fmt.Fprintf(c.Out, "  Keep All: %s days\n", settings["backup_retention_all_days"])
		fmt.Fprintf(c.Out, "  Keep Daily: %s days\n", settings["backup_retention_daily_days"])
		return nil

	case "config":
		settings := make(map[string]string)
		for i := 1; i < len(args); i++ {
			switch args[i] {
			case "--target":
				if i+1 < len(args) {
					settings["backup_target"] = args[i+1]
					i++
				}
			case "--interval":
				if i+1 < len(args) {
					settings["backup_interval_mins"] = args[i+1]
					i++
				}
			case "--keep-all":
				if i+1 < len(args) {
					settings["backup_retention_all_days"] = args[i+1]
					i++
				}
			case "--keep-daily":
				if i+1 < len(args) {
					settings["backup_retention_daily_days"] = args[i+1]
					i++
				}
			}
		}

		if len(settings) == 0 {
			c.backupUsage()
			return errors.New("no configuration values provided")
		}

		body, _ := json.Marshal(settings)
		_, err := c.apiRequest(token, "PUT", "system/settings", body)
		if err != nil {
			return fmt.Errorf("failed to update backup settings: %w", err)
		}
		fmt.Fprintln(c.Out, "Backup settings updated successfully.")
		return nil

	default:
		c.backupUsage()
		return fmt.Errorf("unknown backup command: %s", subCmd)
	}
}
