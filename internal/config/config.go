// Package config manages the application settings, supporting JSON configuration
// files and environment variable overrides.
package config

import (
	"encoding/json"
	"os"
)

// Policy defines the access rules for a specific key prefix.
type Policy struct {
	Prefix  string   `json:"prefix"`
	Methods []string `json:"methods"`
}

// Config represents the full application configuration state.
type Config struct {
	MasterKey    string `json:"master_key"`
	Listen       string `json:"listen"`
	DBPath       string `json:"db_path"`
	BackupTarget string `json:"backup_target"`
}

// Load initializes the configuration. It first attempts to load values from
// the provided JSON path, then applies overrides from environment variables.
// Environment variables always take precedence.
func Load(path string) (*Config, error) {
	cfg := &Config{
		Listen: "0.0.0.0:8090",
		DBPath: "secretd.db",
	}

	if path != "" {
		b, err := os.ReadFile(path)
		if err == nil {
			if err := json.Unmarshal(b, cfg); err != nil {
				return nil, err
			}
		} else if !os.IsNotExist(err) {
			return nil, err
		}
	}

	if envKey := os.Getenv("SECRETD_MASTER_KEY"); envKey != "" {
		cfg.MasterKey = envKey
	}
	if envListen := os.Getenv("SECRETD_LISTEN"); envListen != "" {
		cfg.Listen = envListen
	}
	if envDB := os.Getenv("SECRETD_DB_PATH"); envDB != "" {
		cfg.DBPath = envDB
	}
	if envBackupTarget := os.Getenv("SECRETD_BACKUP_TARGET"); envBackupTarget != "" {
		cfg.BackupTarget = envBackupTarget
	}

	return cfg, nil
}
