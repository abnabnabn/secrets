package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"tiny-secrets-manager/internal/api"
	"tiny-secrets-manager/internal/config"
	"tiny-secrets-manager/internal/store"
	"tiny-secrets-manager/public"

	"golang.org/x/crypto/bcrypt"
)

func generateRandomString(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func bootstrap(logger *slog.Logger) (*config.Config, error) {
	configPath := "config.json"
	
	// 1. Check if we have an existing config
	if _, err := os.Stat(configPath); err == nil {
		return config.Load(configPath)
	}

	// 2. No config found - Auto-generate infrastructure
	logger.Info("no configuration found, initiating self-bootstrap...")
	
	mKey := make([]byte, 32)
	rand.Read(mKey)
	
	cfg := &config.Config{
		MasterKey: base64.StdEncoding.EncodeToString(mKey),
		Listen:    "0.0.0.0:8090",
		DBPath:    "tsm.db",
	}

	out, _ := json.MarshalIndent(cfg, "", "  ")
	if err := os.WriteFile(configPath, out, 0600); err != nil {
		return nil, fmt.Errorf("failed to write config: %w", err)
	}
	
	logger.Info("infrastructure configuration generated", "path", configPath)
	return cfg, nil
}

func main() {
	if len(os.Args) >= 3 && os.Args[1] == "--hash" {
		hash, err := bcrypt.GenerateFromPassword([]byte(os.Args[2]), bcrypt.DefaultCost)
		if err != nil {
			panic(err)
		}
		os.Stdout.Write(hash)
		os.Stdout.WriteString("\n")
		return
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	var configPath string
	if len(os.Args) >= 2 {
		configPath = os.Args[1]
	}

	var cfg *config.Config
	var err error

	if configPath == "" {
		cfg, err = bootstrap(logger)
	} else {
		cfg, err = config.Load(configPath)
	}

	if err != nil {
		logger.Error("failed to load config", "err", err)
		os.Exit(1)
	}

	recoveryKey := os.Getenv("TSM_RECOVERY_KEY")
	db, err := store.New(cfg.DBPath, cfg.MasterKey, recoveryKey, logger)
	if err != nil {
		logger.Error("failed to init store", "err", err)
		os.Exit(1)
	}
	defer db.Close()

	// Check if we need to seed an initial admin user
	ctx := context.Background()
	adminCount, _ := db.CountAdmins(ctx)
	if adminCount == 0 {
		user := os.Getenv("TSM_ADMIN_USER")
		if user == "" { user = "admin" }
		
		pass := os.Getenv("TSM_ADMIN_PASS")
		isAutoPass := pass == ""
		if isAutoPass { pass = generateRandomString(12) }

		token := os.Getenv("TSM_ADMIN_TOKEN")
		isAutoToken := token == ""
		if isAutoToken { token = generateRandomString(32) }

		hash, _ := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
		db.PutAdmin(ctx, user, string(hash))
		
		tokenHash := sha256.Sum256([]byte(token))
		policies := []config.Policy{{Prefix: "*", Methods: []string{"*"}}}
		pJSON, _ := json.Marshal(policies)
		db.PutToken(ctx, "admin", tokenHash[:], pJSON, true)

		fmt.Println("\n" + `========================================================================`)
		fmt.Println(`                        INITIAL SETUP COMPLETE                          `)
		fmt.Println(`========================================================================`)
		fmt.Printf("  Username: %s\n", user)
		fmt.Printf("  Password: %s\n", pass)
		fmt.Printf("  Admin API Token: %s\n", token)
		fmt.Println("")
		fmt.Println(`  [IMPORTANT] These credentials have been seeded into the database.`)
		fmt.Println(`              This is the ONLY time the password and token will be shown.`)
		fmt.Println(`========================================================================` + "\n")
	}

	fmt.Println(`
  _____  _____ __  __ 
 |_   _|/ ____|  \/  |
   | | | (___ | \  / |
   | |  \___ \| |\/| |
   | |  ____) | |  | |
   |_| |_____/|_|  |_|
  Tiny Secrets Manager
`)

	srv := api.NewServer(db, cfg, logger)
	mux := http.NewServeMux()
	srv.RegisterRoutes(mux)
	mux.Handle("/", http.FileServer(http.FS(public.FS)))

	httpServer := &http.Server{
		Addr:         cfg.Listen,
		Handler:      http.TimeoutHandler(mux, 15*time.Second, "request timed out"),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 20 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	go func() {
		logger.Info("listening", "addr", cfg.Listen)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("listen error", "err", err)
			os.Exit(1)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("shutting down server...")
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		logger.Error("server forced to shutdown", "err", err)
	}
	logger.Info("shutdown complete")
}
