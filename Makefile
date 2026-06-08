.PHONY: help all build build-server build-cli run test clean tidy setup run-env install uninstall dev-link dev-unlink lint fmt vulncheck redeploy setup-backup-dir

BIN_DIR := bin
BINARY := $(BIN_DIR)/tiny-secrets-manager
CLI_BINARY := $(BIN_DIR)/tsm
MAIN_PKG := ./cmd/tsm-server
CLI_PKG := ./cmd/tsm-cli
LOCAL_BIN_DIR := $(HOME)/.local/bin
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -s -w -X main.Version=$(VERSION)
PREFIX ?= /usr/local

.DEFAULT_GOAL := help

help:
	@echo "Tiny Secrets Manager - Makefile"
	@echo ""
	@echo "Available commands:"
	@echo "  make help           - Show this help message"
	@echo "  make all            - Run format, lint, vulnerabilities check, and build"
	@echo "  make setup          - Build and prepare the workspace for first run"
	@echo "  make build          - Build both the server and the CLI binaries"
	@echo "  make build-server   - Build the server binary only"
	@echo "  make build-cli      - Build the CLI binary only"
	@echo "  make run            - Build and start the server"
	@echo "  make run-env        - Build and start the server via environment variables"
	@echo "  make test           - Run all tests with coverage"
	@echo "  make clean          - Remove binaries, generated assets, and test databases"
	@echo "  make tidy           - Tidy Go modules"
	@echo "  make fmt            - Format Go code"
	@echo "  make lint           - Run Go vet and golangci-lint"
	@echo "  make vulncheck      - Run Go vulnerability check"
	@echo "  make install        - Install binaries and systemd service (requires sudo)"
	@echo "  make uninstall      - Remove binaries and systemd service (requires sudo)"
	@echo "  make redeploy       - Build, test, stop service, install, and restart service (requires sudo)"
	@echo "  make setup-backup-dir - Create and permission the backup directory (requires sudo, needs TSM_BACKUP_TARGET set)"
	@echo "  make dev-link       - Create symlinks in ~/.local/bin for local development"
	@echo "  make dev-unlink     - Remove symlinks from ~/.local/bin"
	@echo "  make install-ansible-plugin - Install the TSM Ansible lookup plugin globally for the current user"

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
	@go build -ldflags="$(LDFLAGS)" -trimpath -o $(BINARY) $(MAIN_PKG)

build-cli:
	@echo "Building Tiny Secrets Manager CLI binary..."
	@mkdir -p $(BIN_DIR)
	@go build -ldflags="$(LDFLAGS)" -trimpath -o $(CLI_BINARY) $(CLI_PKG)

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

install:
	@if [ ! -f $(BINARY) ] || [ ! -f $(CLI_BINARY) ]; then \
		echo "Error: Binaries not found in $(BIN_DIR)/. Please run 'make build' as your normal user first."; \
		exit 1; \
	fi
	@echo "Installing binaries to $(PREFIX)/bin..."
	@mkdir -p $(PREFIX)/bin
	@cp $(BINARY) $(PREFIX)/bin/tiny-secrets-manager
	@cp $(CLI_BINARY) $(PREFIX)/bin/tsm
	@chmod 755 $(PREFIX)/bin/tiny-secrets-manager $(PREFIX)/bin/tsm
	@if command -v systemctl >/dev/null 2>&1; then \
		echo "Linux systemctl detected, setting up systemd service..."; \
		if ! id tsm >/dev/null 2>&1; then \
			useradd -r -s /sbin/nologin tsm; \
		fi; \
		mkdir -p /etc/tiny-secrets-manager /var/lib/tiny-secrets-manager; \
		chown tsm:tsm /var/lib/tiny-secrets-manager /etc/tiny-secrets-manager; \
		if [ -n "$$TSM_ADMIN_PASS" ] || [ -n "$$TSM_ADMIN_USER" ] || [ -n "$$TSM_BACKUP_TARGET" ]; then \
			echo "Seeding database with provided credentials/settings..."; \
			$(MAKE) setup-backup-dir; \
			sudo -u tsm env TSM_ADMIN_PASS="$$TSM_ADMIN_PASS" TSM_ADMIN_USER="$$TSM_ADMIN_USER" TSM_BACKUP_TARGET="$$TSM_BACKUP_TARGET" sh -c "cd /var/lib/tiny-secrets-manager && $(PREFIX)/bin/tiny-secrets-manager -seed-only /etc/tiny-secrets-manager/config.json"; \
		fi; \
		cp scripts/tiny-secrets-manager.service /etc/systemd/system/tiny-secrets-manager.service; \
		if [ -n "$$TSM_LISTEN" ] || [ -n "$$TSM_INSECURE" ]; then \
			echo "Configuring systemd environment overrides..."; \
			mkdir -p /etc/systemd/system/tiny-secrets-manager.service.d; \
			echo "[Service]" > /etc/systemd/system/tiny-secrets-manager.service.d/override.conf; \
			if [ -n "$$TSM_LISTEN" ]; then echo "Environment=\"TSM_LISTEN=$$TSM_LISTEN\"" >> /etc/systemd/system/tiny-secrets-manager.service.d/override.conf; fi; \
			if [ -n "$$TSM_INSECURE" ]; then echo "Environment=\"TSM_INSECURE=$$TSM_INSECURE\"" >> /etc/systemd/system/tiny-secrets-manager.service.d/override.conf; fi; \
		fi; \
		systemctl daemon-reload; \
		if systemctl is-active --quiet tiny-secrets-manager; then \
			systemctl restart tiny-secrets-manager; \
			echo "Tiny Secrets Manager service restarted."; \
		else \
			echo "Service installed but not started. Enable and start it via: sudo systemctl enable --now tiny-secrets-manager"; \
		fi; \
	fi

uninstall:
	@echo "Removing binaries from $(PREFIX)/bin..."
	@rm -f $(PREFIX)/bin/tiny-secrets-manager $(PREFIX)/bin/tsm
	@if command -v systemctl >/dev/null 2>&1; then \
		echo "Cleaning up Linux systemd service and data..."; \
		if systemctl is-active --quiet tiny-secrets-manager; then \
			systemctl stop tiny-secrets-manager; \
		fi; \
		if systemctl is-enabled --quiet tiny-secrets-manager 2>/dev/null; then \
			systemctl disable tiny-secrets-manager; \
		fi; \
		rm -f /etc/systemd/system/tiny-secrets-manager.service; \
		rm -rf /etc/systemd/system/tiny-secrets-manager.service.d; \
		systemctl daemon-reload; \
		rm -rf /etc/tiny-secrets-manager /var/lib/tiny-secrets-manager; \
		if id tsm >/dev/null 2>&1; then \
			userdel tsm; \
		fi; \
		echo "Cleanup complete. Systemd service, data directories, and user have been removed."; \
	fi

redeploy: build test
	@echo "Redeploying service..."
	@if command -v systemctl >/dev/null 2>&1; then \
		echo "Stopping tiny-secrets-manager..."; \
		sudo systemctl stop tiny-secrets-manager || true; \
		echo "Installing new binaries..."; \
		sudo $(MAKE) install; \
		echo "Starting tiny-secrets-manager..."; \
		sudo systemctl restart tiny-secrets-manager; \
		echo "Redeploy complete."; \
	else \
		echo "Error: systemctl not found, cannot redeploy service."; \
		exit 1; \
	fi

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
		echo ""; \
	fi

setup-backup-dir:
	@if [ -n "$$TSM_BACKUP_TARGET" ]; then \
		echo "Ensuring backup directory $$TSM_BACKUP_TARGET exists with correct permissions..."; \
		mkdir -p "$$TSM_BACKUP_TARGET"; \
		if id tsm >/dev/null 2>&1; then \
			if [ -n "$$SUDO_USER" ]; then \
				chown tsm:$$SUDO_USER "$$TSM_BACKUP_TARGET"; \
				chmod 750 "$$TSM_BACKUP_TARGET"; \
			else \
				chown tsm:tsm "$$TSM_BACKUP_TARGET"; \
				chmod 700 "$$TSM_BACKUP_TARGET"; \
			fi; \
		else \
			echo "Warning: tsm user not found. Permissions not set."; \
		fi; \
	fi

dev-unlink:
	@echo "Removing symlinks from $(LOCAL_BIN_DIR)..."
	@rm -f $(LOCAL_BIN_DIR)/tiny-secrets-manager $(LOCAL_BIN_DIR)/tsm

install-ansible-plugin:
	@echo "Installing Ansible lookup plugin to ~/.ansible/plugins/lookup/..."
	@mkdir -p $(HOME)/.ansible/plugins/lookup/
	@cp plugins/ansible/lookup/tsm.py $(HOME)/.ansible/plugins/lookup/
	@echo "Done! You can now use lookup('tsm', 'key') in your playbooks."
