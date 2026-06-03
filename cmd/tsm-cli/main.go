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
)

// Config represents the local CLI configuration stored in ~/.tsm.json.
type Config struct {
	URL      string            `json:"url"`      // Server base URL
	Contexts map[string]string `json:"contexts"` // Filesystem path -> machine token mapping
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
	case "login":
		if len(args) < 3 {
			return errors.New("usage: tsm login <url>")
		}
		return c.saveLogin(args[2])
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
		default:
			c.authUsage()
			return nil
		}
	}

	// 3. All other commands require a resolved configuration and token
	cfg, activeToken, err := c.loadConfig()
	if err != nil {
		return err
	}

	switch cmd {
	case "get":
		if len(args) < 3 {
			return errors.New("usage: tsm get <key>")
		}
		return c.getSecret(cfg, activeToken, args[2])
	case "put":
		if len(args) < 4 {
			return errors.New("usage: tsm put <key> <value>")
		}
		return c.putSecret(cfg, activeToken, args[2], args[3])
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
	fmt.Fprintln(c.Out, "Usage: tsm <command> [arguments]")
	fmt.Fprintln(c.Out, "\nCommands:")
	fmt.Fprintln(c.Out, "  login <url>         - Set the server URL")
	fmt.Fprintln(c.Out, "  auth <flags>        - Manage directory/token contexts")
	fmt.Fprintln(c.Out, "  get <key>           - Fetch and print a secret value")
	fmt.Fprintln(c.Out, "  put <key> <value>   - Store a secret value")
	fmt.Fprintln(c.Out, "  ls [prefix]         - List all available secret keys")
	fmt.Fprintln(c.Out, "  rm <key>            - Permanently delete a secret")
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
	fmt.Fprintln(c.Out, "  --link <token> - Link current directory to a token")
	fmt.Fprintln(c.Out, "  --tidy         - Prune stale or redundant context mappings")
	fmt.Fprintln(c.Out, "  --status       - Show active contexts and validate tokens")
}

func (c *TSMCLI) loadConfig() (*Config, string, error) {
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

	for p, token := range cfg.Contexts {
		if strings.HasPrefix(c.WorkingDir, p) {
			if len(p) > len(bestMatch) {
				bestMatch = p
				activeToken = token
			}
		}
	}

	if activeToken == "" {
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

func (c *TSMCLI) saveLogin(url string) error {
	cfg, _ := c.loadConfigSilent()
	cfg.URL = url
	if err := c.writeConfig(cfg); err != nil {
		return err
	}
	fmt.Fprintf(c.Out, "Server URL set to %s\n", url)
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
	req, err := http.NewRequestWithContext(context.Background(), method, url, bytes.NewBuffer(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("network error: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK, http.StatusNoContent, http.StatusCreated:
		// OK
	case http.StatusUnauthorized:
		return nil, errors.New("invalid or expired token")
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

func (c *TSMCLI) putSecret(cfg *Config, token, key, value string) error {
	body, err := json.Marshal(map[string]string{"value": value})
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
		case "--token":
			if i+1 < len(args) {
				activeToken = args[i+1]
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
