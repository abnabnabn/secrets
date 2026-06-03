.PHONY: all build build-server build-cli run test clean tidy setup run-env install uninstall dev-link dev-unlink lint fmt vulncheck

BIN_DIR := bin
BINARY := $(BIN_DIR)/tiny-secrets-manager
CLI_BINARY := $(BIN_DIR)/tsm
MAIN_PKG := ./cmd/tsm-server
CLI_PKG := ./cmd/tsm-cli
LOCAL_BIN_DIR := $(HOME)/.local/bin

all: tidy fmt lint vulncheck build

setup: tidy fmt lint vulncheck build
	@echo ""
	@echo "========================================================================"
	@echo "                        WORKSPACE READY                                 "
	@echo "========================================================================"
	@echo "  Run './bin/tiny-secrets-manager' to start the server."
	@echo "  Tiny Secrets Manager will auto-generate its configuration and seed the initial"
	@echo "  admin credentials on the first run."
	@echo "========================================================================"
	@echo ""

build: build-server build-cli

build-server:
	@echo "Building Tiny Secrets Manager server binary..."
	@mkdir -p $(BIN_DIR)
	@go run cmd/prebuild/main.go
	@go build -ldflags="-s -w" -trimpath -o $(BINARY) $(MAIN_PKG)

build-cli:
	@echo "Building Tiny Secrets Manager CLI binary..."
	@mkdir -p $(BIN_DIR)
	@go build -ldflags="-s -w" -trimpath -o $(CLI_BINARY) $(CLI_PKG)

run: build-server
	@echo "Starting Tiny Secrets Manager..."
	$(BINARY)

run-env: build-server
	@echo "Starting Tiny Secrets Manager via environment variables (no config file on disk)..."
	@export TSM_MASTER_KEY=$$(grep "master_key" config.json | cut -d '"' -f 4) && \
	export TSM_ADMIN_TOKEN=$$(grep "admin_token" config.json | cut -d '"' -f 4) && \
	export TSM_ADMIN_USERNAME=$$(grep "admin_username" config.json | cut -d '"' -f 4) && \
	export TSM_ADMIN_PASSWORD_HASH=$$(grep "admin_password_hash" config.json | cut -d '"' -f 4) && \
	export TSM_LISTEN="0.0.0.0:8090" && \
	export TSM_DB_PATH="tsm.db" && \
	$(BINARY)

test:
	@echo "Running tests with coverage and summary..."
	go run gotest.tools/gotestsum@latest --format pkgname -- -race -coverprofile=coverage.out ./...
	@echo ""
	@echo "========================================================================"
	@echo "                        COVERAGE SUMMARY                                "
	@echo "========================================================================"
	@go tool cover -func=coverage.out

clean:
	@echo "Cleaning up..."
	@rm -rf $(BIN_DIR)
	@rm -rf public/assets
	@rm -f public/index.html
	@rm -f *.db *.db-shm *.db-wal

tidy:
	@echo "Tidying go modules..."
	go mod tidy

fmt:
	@echo "Formatting code..."
	go fmt ./...

lint:
	@echo "Linting code..."
	go vet ./...
	go run github.com/golangci/golangci-lint/cmd/golangci-lint@latest run

vulncheck:
	@echo "Running vulnerability check..."
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

install: build
	@echo "Installing binaries to $(PREFIX)/bin..."
	@mkdir -p $(PREFIX)/bin
	@cp $(BINARY) $(PREFIX)/bin/tiny-secrets-manager
	@cp $(CLI_BINARY) $(PREFIX)/bin/tsm
	@chmod 755 $(PREFIX)/bin/tiny-secrets-manager $(PREFIX)/bin/tsm

uninstall:
	@echo "Removing binaries from $(PREFIX)/bin..."
	@rm -f $(PREFIX)/bin/tiny-secrets-manager $(PREFIX)/bin/tsm

dev-link: build
	@echo "Creating symlinks in $(LOCAL_BIN_DIR)..."
	@mkdir -p $(LOCAL_BIN_DIR)
	@ln -sf $(CURDIR)/$(BINARY) $(LOCAL_BIN_DIR)/tiny-secrets-manager
	@ln -sf $(CURDIR)/$(CLI_BINARY) $(LOCAL_BIN_DIR)/tsm
	@if echo ":$(PATH):" | grep -q ":$(LOCAL_BIN_DIR):"; then \
		echo "Success! Binaries are linked and available in your PATH."; \
	else \
		echo ""; \
		echo "========================================================================"; \
		echo "WARNING: $(LOCAL_BIN_DIR) is NOT in your PATH."; \
		echo "To run the binaries from anywhere, add this to your .bashrc or .zshrc:"; \
		echo "  export PATH=\"\$$PATH:$(LOCAL_BIN_DIR)\""; \
		echo "========================================================================"; \
		echo ""; \
	fi

dev-unlink:
	@echo "Removing symlinks from $(LOCAL_BIN_DIR)..."
	@rm -f $(LOCAL_BIN_DIR)/tiny-secrets-manager $(LOCAL_BIN_DIR)/tsm
