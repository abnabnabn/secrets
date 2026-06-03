package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
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
	var insecureFlag bool
	var adminUserFlag string
	var adminPassFlag string
	var adminTokenFlag string
	var masterKeyFlag string
	var listenFlag string
	var dbPathFlag string
	var backupTargetFlag string
	var recoveryKeyFlag string

	flag.BoolVar(&insecureFlag, "insecure", false, "Disable secure mode")
	flag.StringVar(&adminUserFlag, "admin-user", "", "Admin username")
	flag.StringVar(&adminPassFlag, "admin-pass", "", "Admin password")
	flag.StringVar(&adminTokenFlag, "admin-token", "", "Admin API token")
	flag.StringVar(&masterKeyFlag, "master-key", "", "Master key")
	flag.StringVar(&listenFlag, "listen", "", "Listen address")
	flag.StringVar(&dbPathFlag, "db-path", "", "Database path")
	flag.StringVar(&backupTargetFlag, "backup-target", "", "Backup target")
	flag.StringVar(&recoveryKeyFlag, "recovery-key", "", "Recovery key")

	flag.Parse()

	if flag.NArg() > 0 {
		configPath = flag.Arg(0)
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

	if insecureFlag {
		cfg.Insecure = true
	}
	if masterKeyFlag != "" {
		cfg.MasterKey = masterKeyFlag
	}
	if listenFlag != "" {
		cfg.Listen = listenFlag
	}
	if dbPathFlag != "" {
		cfg.DBPath = dbPathFlag
	}
	if backupTargetFlag != "" {
		cfg.BackupTarget = backupTargetFlag
	}

	recoveryKey := recoveryKeyFlag
	if recoveryKey == "" {
		recoveryKey = os.Getenv("TSM_RECOVERY_KEY")
	}

	db, err := store.New(cfg.DBPath, cfg.MasterKey, recoveryKey, logger)
	if err != nil {
		logger.Error("failed to init store", "err", err)
		os.Exit(1)
	}
	defer db.Close()

	if err := seedAdminUser(context.Background(), db, adminUserFlag, adminPassFlag, adminTokenFlag); err != nil {
		logger.Error("failed to seed admin user", "err", err)
		os.Exit(1)
	}

	if err := runServer(cfg, db, logger); err != nil {
		logger.Error("server error", "err", err)
		os.Exit(1)
	}
}

func seedAdminUser(ctx context.Context, db *store.Store, adminUser, adminPass, adminToken string) error {
	adminCount, err := db.CountAdmins(ctx)
	if err != nil {
		return fmt.Errorf("failed to count admins: %w", err)
	}
	if adminCount > 0 {
		return nil
	}

	user := adminUser
	if user == "" {
		user = os.Getenv("TSM_ADMIN_USER")
	}
	if user == "" {
		user = "admin"
	}

	pass := adminPass
	if pass == "" {
		pass = os.Getenv("TSM_ADMIN_PASS")
	}
	if pass == "" {
		pass = generateRandomString(12)
	}

	token := adminToken
	if token == "" {
		token = os.Getenv("TSM_ADMIN_TOKEN")
	}
	if token == "" {
		token = generateRandomString(32)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	if err := db.PutAdmin(ctx, user, string(hash)); err != nil {
		return fmt.Errorf("failed to create admin: %w", err)
	}

	tokenHash := sha256.Sum256([]byte(token))
	policies := []config.Policy{{Prefix: "*", Methods: []string{"*"}}}
	pJSON, _ := json.Marshal(policies)
	if err := db.PutRole(ctx, "admin", tokenHash[:], pJSON, true); err != nil {
		return fmt.Errorf("failed to create admin role: %w", err)
	}

	fmt.Println("\n" + `========================================================================`)
	fmt.Println(`                        INITIAL SETUP COMPLETE                          `)
	fmt.Println(`========================================================================`)
	fmt.Printf("  Username: %s\n", user)
	fmt.Printf("  Password: %s\n", pass)
	fmt.Printf("  Admin API Token: %s\n", token)
	fmt.Println("")
	fmt.Println(`  [IMPORTANT] These credentials have been seeded into the database.`)
	fmt.Println(`              This is the ONLY time the password and token will be shown.`)
	fmt.Println(`========================================================================`)

	return nil
}

func runServer(cfg *config.Config, db *store.Store, logger *slog.Logger) error {
	fmt.Print(`
  _____  _____ __  __ 
 |_   _|/ ____|  \/  |
   | | | (___ | \  / |
   | |  \___ \| |\/| |
   | |  ____) | |  | |
   |_| |_____/|_|  |_|
  Tiny Secrets Manager

`)

	if cfg.Insecure {
		fmt.Println("  ========================================================")
		fmt.Println("  WARNING: Server is running in INSECURE mode.")
		fmt.Println("           HTTPS enforcement and secure cookies are disabled.")
		fmt.Println("           Do NOT use this mode in production!")
		fmt.Println("  ========================================================")
		fmt.Println()
	}

	srv := api.NewServer(db, cfg, logger)
	mux := http.NewServeMux()
	srv.RegisterRoutes(mux)
	mux.Handle("/", http.FileServer(http.FS(public.FS)))

	httpServer := &http.Server{
		Addr:         cfg.Listen,
		Handler:      http.TimeoutHandler(srv.SecurityMiddleware(mux), 15*time.Second, "request timed out"),
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
		return fmt.Errorf("server shutdown failed: %w", err)
	}
	logger.Info("shutdown complete")
	return nil
}
