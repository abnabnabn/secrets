package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type Config struct {
	URL   string `json:"url"`
	Token string `json:"token"`
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}

	cfg := loadConfig()
	cmd := os.Args[1]

	switch cmd {
	case "get":
		if len(os.Args) < 3 { usage() }
		getSecret(cfg, os.Args[2])
	case "put":
		if len(os.Args) < 4 { usage() }
		putSecret(cfg, os.Args[2], os.Args[3])
	case "ls", "list":
		prefix := ""
		if len(os.Args) > 2 { prefix = os.Args[2] }
		listSecrets(cfg, prefix)
	case "rm", "delete":
		if len(os.Args) < 3 { usage() }
		deleteSecret(cfg, os.Args[2])
	case "login":
		if len(os.Args) < 4 { usage() }
		saveLogin(os.Args[2], os.Args[3])
	case "run":
		var tsmEnv = "tsm.env"
		var dotEnv = ".env"
		var cliEnvs []string
		var targetCmd []string
		for i := 2; i < len(os.Args); i++ {
			arg := os.Args[i]
			if arg == "--" {
				targetCmd = os.Args[i+1:]
				break
			}
			if (arg == "-f" || arg == "--file") && i+1 < len(os.Args) {
				tsmEnv = os.Args[i+1]
				i++
			} else if arg == "--env-file" && i+1 < len(os.Args) {
				dotEnv = os.Args[i+1]
				i++
			} else if arg == "-e" && i+1 < len(os.Args) {
				cliEnvs = append(cliEnvs, os.Args[i+1])
				i++
			}
		}
		if len(targetCmd) == 0 { usage() }
		runCommand(cfg, tsmEnv, dotEnv, cliEnvs, targetCmd)
	case "help", "--help", "-h":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", cmd)
		usage()
	}
}

func usage() {
	fmt.Println("Usage: tsm <command> [arguments]")
	fmt.Println("\nCommands:")
	fmt.Println("  get <key>           - Fetch and print a secret value")
	fmt.Println("  put <key> <value>   - Store a secret value")
	fmt.Println("  ls [prefix]         - List all available secret keys")
	fmt.Println("  rm <key>            - Permanently delete a secret")
	fmt.Println("  login <url> <token> - Save credentials to ~/.tsm.json")
	fmt.Println("  run [flags] -- <cmd> - Run a command with injected secrets")
	fmt.Println("\nRun Flags:")
	fmt.Println("  -f, --file <path>   - TSM mapping file (default: tsm.env)")
	fmt.Println("  --env-file <path>   - Standard .env file (default: .env)")
	fmt.Println("  -e KEY=VAL          - Explicit environment override")
	fmt.Println("\nExample:")
	fmt.Println("  tsm run -e DEBUG=true -- npm start")
	fmt.Println("\nConfiguration:")
	fmt.Println("  Environment variables TSM_URL and TSM_TOKEN override the config file.")
	os.Exit(1)
}

func loadConfig() *Config {
	cfg := &Config{
		URL:   os.Getenv("TSM_URL"),
		Token: os.Getenv("TSM_TOKEN"),
	}

	if cfg.URL != "" && cfg.Token != "" {
		return cfg
	}

	home, _ := os.UserHomeDir()
	path := filepath.Join(home, ".tsm.json")
	if b, err := os.ReadFile(path); err == nil {
		var saved Config
		if err := json.Unmarshal(b, &saved); err == nil {
			if cfg.URL == "" { cfg.URL = saved.URL }
			if cfg.Token == "" { cfg.Token = saved.Token }
		}
	}

	if cfg.URL == "" || cfg.Token == "" {
		fmt.Fprintln(os.Stderr, "Error: TSM_URL and TSM_TOKEN must be set via env vars or 'tsm login'")
		os.Exit(1)
	}
	cfg.URL = strings.TrimSuffix(cfg.URL, "/")
	return cfg
}

func saveLogin(url, token string) {
	home, err := os.UserHomeDir()
	if err != nil { panic(err) }
	path := filepath.Join(home, ".tsm.json")
	
	cfg := Config{URL: url, Token: token}
	b, _ := json.MarshalIndent(cfg, "", "  ")
	
	if err := os.WriteFile(path, b, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to save config: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Credentials saved to %s\n", path)
}

func apiRequest(cfg *Config, method, path string, body []byte) ([]byte, error) {
	url := fmt.Sprintf("%s/v1/%s", cfg.URL, strings.TrimPrefix(path, "/"))
	req, _ := http.NewRequest(method, url, bytes.NewBuffer(body))
	req.Header.Set("Authorization", "Bearer "+cfg.Token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("network error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("invalid or expired token")
	}
	if resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("access denied by access policies")
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("secret not found")
	}
	if resp.StatusCode >= 400 {
		msg, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("server error (%d): %s", resp.StatusCode, string(msg))
	}

	data, _ := io.ReadAll(resp.Body)
	return data, nil
}

func getSecret(cfg *Config, key string) {
	data, err := apiRequest(cfg, "GET", "secrets/"+key, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	var res struct{ Value string `json:"value"` }
	json.Unmarshal(data, &res)
	fmt.Print(res.Value)
}

func putSecret(cfg *Config, key, value string) {
	body, _ := json.Marshal(map[string]string{"value": value})
	_, err := apiRequest(cfg, "PUT", "secrets/"+key, body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Secret '%s' stored successfully.\n", key)
}

func listSecrets(cfg *Config, prefix string) {
	path := "secrets"
	if prefix != "" { path += "?prefix=" + prefix }
	data, err := apiRequest(cfg, "GET", path, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	var keys []string
	json.Unmarshal(data, &keys)
	for _, k := range keys {
		fmt.Println(k)
	}
}

func deleteSecret(cfg *Config, key string) {
	_, err := apiRequest(cfg, "DELETE", "secrets/"+key, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Secret '%s' deleted.\n", key)
}

func parseEnvFile(content string) map[string]string {
	res := make(map[string]string)
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			res[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return res
}

func runCommand(cfg *Config, tsmEnvPath, dotEnvPath string, cliEnvs []string, targetCmd []string) {
	envMap := make(map[string]string)
	for _, e := range os.Environ() {
		parts := strings.SplitN(e, "=", 2)
		envMap[parts[0]] = parts[1]
	}

	// 1. TSM Mappings (Pointers)
	if b, err := os.ReadFile(tsmEnvPath); err == nil {
		mappings := parseEnvFile(string(b))
		for envKey, secretKey := range mappings {
			data, err := apiRequest(cfg, "GET", "secrets/"+secretKey, nil)
			if err == nil {
				var res struct{ Value string `json:"value"` }
				json.Unmarshal(data, &res)
				envMap[envKey] = res.Value
			}
		}
	}

	// 2. Standard .env (Literals) - Local priority
	if b, err := os.ReadFile(dotEnvPath); err == nil {
		literals := parseEnvFile(string(b))
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
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
