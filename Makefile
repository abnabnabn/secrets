.PHONY: all build build-server build-cli run test clean tidy setup run-env install uninstall

BIN_DIR := bin
BINARY := $(BIN_DIR)/secretd
CLI_BINARY := $(BIN_DIR)/secret
MAIN_PKG := ./cmd/secretd
CLI_PKG := ./cmd/secret

all: tidy build

setup:
	@echo "Evaluating module workspace state..."
	@if [ ! -f go.mod ]; then \
		echo "go.mod missing. Initializing module namespace 'secretd'..."; \
		go mod init secretd; \
	fi
	@echo "Resolving source imports and downloading dependencies..."
	go mod tidy
	go mod download
	@if [ ! -f config.json ]; then \
		echo "Generating config.json and initializing Database Enclosure natively..."; \
		echo 'package main' > init_config.go; \
		echo 'import (' >> init_config.go; \
		echo '	"crypto/rand"' >> init_config.go; \
		echo '	"encoding/base64"' >> init_config.go; \
		echo '	"encoding/json"' >> init_config.go; \
		echo '	"fmt"' >> init_config.go; \
		echo '	"os"' >> init_config.go; \
		echo ')' >> init_config.go; \
		echo 'func generatePassword() string {' >> init_config.go; \
		echo '	b := make([]byte, 12)' >> init_config.go; \
		echo '	rand.Read(b)' >> init_config.go; \
		echo '	return base64.RawURLEncoding.EncodeToString(b)' >> init_config.go; \
		echo '}' >> init_config.go; \
		echo 'func main() {' >> init_config.go; \
		echo '	b, _ := os.ReadFile("config.example.json")' >> init_config.go; \
		echo '	var cfg map[string]interface{}' >> init_config.go; \
		echo '	json.Unmarshal(b, &cfg)' >> init_config.go; \
		echo '	if cfg == nil { cfg = make(map[string]interface{}) }' >> init_config.go; \
		echo '	m := make([]byte, 32)' >> init_config.go; \
		echo '	rand.Read(m)' >> init_config.go; \
		echo '	cfg["master_key"] = base64.StdEncoding.EncodeToString(m)' >> init_config.go; \
		echo '	out, _ := json.MarshalIndent(cfg, "", "  ")' >> init_config.go; \
		echo '	os.WriteFile("config.json", out, 0600)' >> init_config.go; \
		echo '	adminUser := os.Getenv("ADMIN_USER")' >> init_config.go; \
		echo '	if adminUser == "" { adminUser = "admin" }' >> init_config.go; \
		echo '	rawPass := os.Getenv("ADMIN_PASS")' >> init_config.go; \
		echo '	if rawPass == "" { rawPass = generatePassword() }' >> init_config.go; \
		echo '	adminToken := os.Getenv("ADMIN_TOKEN")' >> init_config.go; \
		echo '	if adminToken == "" { ' >> init_config.go; \
		echo '		t := make([]byte, 32)' >> init_config.go; \
		echo '		rand.Read(t)' >> init_config.go; \
		echo '		adminToken = base64.RawURLEncoding.EncodeToString(t)' >> init_config.go; \
		echo '	}' >> init_config.go; \
		echo '	fmt.Println("========================================================================")' >> init_config.go; \
		echo '	fmt.Println("                        UI ADMIN CREDENTIALS                            ")' >> init_config.go; \
		echo '	fmt.Println("========================================================================")' >> init_config.go; \
		echo '	if os.Getenv("ADMIN_PASS") != "" || os.Getenv("ADMIN_USER") != "" {' >> init_config.go; \
		echo '		fmt.Println("Using CUSTOM credentials provided via environment variables.")' >> init_config.go; \
		echo '	} else {' >> init_config.go; \
		echo '		fmt.Println("Use these randomly generated credentials to log in:")' >> init_config.go; \
		echo '	}' >> init_config.go; \
		echo '	fmt.Println("")' >> init_config.go; \
		echo '	fmt.Printf("  Username: %s\\n", adminUser)' >> init_config.go; \
		echo '	fmt.Printf("  Password: %s\\n", rawPass)' >> init_config.go; \
		echo '	fmt.Printf("  Admin API Token: %s\\n", adminToken)' >> init_config.go; \
		echo '	fmt.Println("")' >> init_config.go; \
		echo '	fmt.Println("  [NOTE] These have been seeded into the encrypted database and")' >> init_config.go; \
		echo '	fmt.Println("         are NOT stored in config.json.")' >> init_config.go; \
		echo '	fmt.Println("========================================================================")' >> init_config.go; \
		echo '	os.Setenv("SECRETD_ADMIN_USER", adminUser)' >> init_config.go; \
		echo '	os.Setenv("SECRETD_ADMIN_PASS", rawPass)' >> init_config.go; \
		echo '	os.Setenv("SECRETD_ADMIN_TOKEN", adminToken)' >> init_config.go; \
		echo '}' >> init_config.go; \
		go run init_config.go; \
		rm -f init_config.go; \
		echo "Configuration scaffolded. Seeding admin user on first boot..."; \
	else \
		echo "config.json already exists. Skipping configuration scaffold."; \
	fi

build: build-server build-cli

build-server:
	@echo "Building server binary (with minification)..."
	@mkdir -p $(BIN_DIR)
	@cp public/index.html public/index.html.bak
	@go run cmd/prebuild/main.go public/index.html public/index.html
	@go build -ldflags="-s -w" -trimpath -o $(BINARY) $(MAIN_PKG)
	@mv public/index.html.bak public/index.html

build-cli:
	@echo "Building CLI binary..."
	@mkdir -p $(BIN_DIR)
	@go build -ldflags="-s -w" -trimpath -o $(CLI_BINARY) $(CLI_PKG)

run: build-server
	@echo "Starting secretd via config file..."
	$(BINARY) config.json

run-env: build-server
	@echo "Starting secretd via environment variables (no config file on disk)..."
	@export SECRETD_MASTER_KEY=$$(grep "master_key" config.json | cut -d '"' -f 4) && \
	export SECRETD_ADMIN_TOKEN=$$(grep "admin_token" config.json | cut -d '"' -f 4) && \
	export SECRETD_ADMIN_USERNAME=$$(grep "admin_username" config.json | cut -d '"' -f 4) && \
	export SECRETD_ADMIN_PASSWORD_HASH=$$(grep "admin_password_hash" config.json | cut -d '"' -f 4) && \
	export SECRETD_LISTEN="0.0.0.0:8090" && \
	export SECRETD_DB_PATH="secretd.db" && \
	$(BINARY)

test:
	@echo "Running tests..."
	go test -v -race ./...

clean:
	@echo "Cleaning up..."
	@rm -rf $(BIN_DIR)
	@rm -f *.db *.db-shm *.db-wal

tidy:
	@echo "Tidying go modules..."
	go mod tidy

install: build
	@echo "Installing binaries to $(PREFIX)/bin..."
	@mkdir -p $(PREFIX)/bin
	@cp $(BINARY) $(PREFIX)/bin/secretd
	@cp $(CLI_BINARY) $(PREFIX)/bin/secret
	@chmod 755 $(PREFIX)/bin/secretd $(PREFIX)/bin/secret

uninstall:
	@echo "Removing binaries from $(PREFIX)/bin..."
	@rm -f $(PREFIX)/bin/secretd $(PREFIX)/bin/secret
