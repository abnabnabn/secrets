package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"secretd/internal/api"
	"secretd/internal/config"
	"secretd/internal/store"
	"secretd/public"

	"golang.org/x/crypto/bcrypt"
)

// main is the entry point for the vault server. It handles configuration loading,
// storage initialization (including encryption slot resolution), and starting 
// the HTTP server with graceful shutdown support.
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

	cfg, err := config.Load(configPath)
	if err != nil {
		logger.Error("failed to load config", "err", err)
		os.Exit(1)
	}

	recoveryKey := os.Getenv("SECRETD_RECOVERY_KEY")

	db, err := store.New(cfg.DBPath, cfg.MasterKey, recoveryKey, logger)
	if err != nil {
		logger.Error("failed to init store", "err", err)
		os.Exit(1)
	}
	defer db.Close()

	// Seed Admin credentials if provided via environment (used by 'make setup')
	if user := os.Getenv("SECRETD_ADMIN_USER"); user != "" {
		pass := os.Getenv("SECRETD_ADMIN_PASS")
		hash, _ := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
		if err := db.PutAdmin(context.Background(), user, string(hash)); err != nil {
			logger.Error("failed to seed admin user", "err", err)
		} else {
			logger.Info("admin user seeded successfully", "username", user)
		}
	}

	if token := os.Getenv("SECRETD_ADMIN_TOKEN"); token != "" {
		hash := sha256.Sum256([]byte(token))
		policies := []config.Policy{{Prefix: "*", Methods: []string{"*"}}}
		policiesJSON, _ := json.Marshal(policies)
		if err := db.PutToken(context.Background(), "admin", hash[:], policiesJSON, true); err != nil {
			logger.Error("failed to seed admin token", "err", err)
		} else {
			logger.Info("admin token seeded successfully")
		}
	}

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
