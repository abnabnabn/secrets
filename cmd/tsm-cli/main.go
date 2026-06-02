package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
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
	case "help", "--help", "-h":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", cmd)
		usage()
	}
}

func usage() {
	fmt.Println("Usage: secret <command> [arguments]")
	fmt.Println("\nCommands:")
	fmt.Println("  get <key>           - Fetch and print a secret value")
	fmt.Println("  put <key> <value>   - Store a secret value")
	fmt.Println("  ls [prefix]         - List all available secret keys")
	fmt.Println("  rm <key>            - Permanently delete a secret")
	fmt.Println("  login <url> <token> - Save credentials to ~/.tsm.json")
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
		fmt.Fprintln(os.Stderr, "Error: TSM_URL and TSM_TOKEN must be set via env vars or 'secret login'")
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

func apiRequest(cfg *Config, method, path string, body []byte) []byte {
	url := fmt.Sprintf("%s/v1/%s", cfg.URL, strings.TrimPrefix(path, "/"))
	req, _ := http.NewRequest(method, url, bytes.NewBuffer(body))
	req.Header.Set("Authorization", "Bearer "+cfg.Token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Network error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		fmt.Fprintln(os.Stderr, "Error: Invalid or expired token")
		os.Exit(1)
	}
	if resp.StatusCode == http.StatusForbidden {
		fmt.Fprintln(os.Stderr, "Error: Access denied by access policies")
		os.Exit(1)
	}
	if resp.StatusCode == http.StatusNotFound {
		fmt.Fprintln(os.Stderr, "Error: Secret not found")
		os.Exit(1)
	}
	if resp.StatusCode >= 400 {
		msg, _ := io.ReadAll(resp.Body)
		fmt.Fprintf(os.Stderr, "Server error (%d): %s\n", resp.StatusCode, string(msg))
		os.Exit(1)
	}

	data, _ := io.ReadAll(resp.Body)
	return data
}

func getSecret(cfg *Config, key string) {
	data := apiRequest(cfg, "GET", "secrets/"+key, nil)
	var res struct{ Value string `json:"value"` }
	json.Unmarshal(data, &res)
	fmt.Print(res.Value)
}

func putSecret(cfg *Config, key, value string) {
	body, _ := json.Marshal(map[string]string{"value": value})
	apiRequest(cfg, "PUT", "secrets/"+key, body)
	fmt.Printf("Secret '%s' stored successfully.\n", key)
}

func listSecrets(cfg *Config, prefix string) {
	path := "secrets"
	if prefix != "" { path += "?prefix=" + prefix } // Note: Backend handles prefix filtering
	data := apiRequest(cfg, "GET", path, nil)
	var keys []string
	json.Unmarshal(data, &keys)
	for _, k := range keys {
		fmt.Println(k)
	}
}

func deleteSecret(cfg *Config, key string) {
	apiRequest(cfg, "DELETE", "secrets/"+key, nil)
	fmt.Printf("Secret '%s' deleted.\n", key)
}
