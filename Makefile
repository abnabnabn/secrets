.PHONY: all build build-server build-cli run test clean tidy setup run-env install uninstall

BIN_DIR := bin
BINARY := $(BIN_DIR)/tiny-secrets-manager
CLI_BINARY := $(BIN_DIR)/tsm
MAIN_PKG := ./cmd/tsm-server
CLI_PKG := ./cmd/tsm-cli

all: tidy build

setup: tidy build
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
	@echo "Building Tiny Secrets Manager server binary (with minification)..."
	@mkdir -p $(BIN_DIR)
	@cp public/index.html public/index.html.bak
	@go run cmd/prebuild/main.go public/index.html public/index.html
	@go build -ldflags="-s -w" -trimpath -o $(BINARY) $(MAIN_PKG)
	@mv public/index.html.bak public/index.html

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
	@cp $(BINARY) $(PREFIX)/bin/tiny-secrets-manager
	@cp $(CLI_BINARY) $(PREFIX)/bin/tsm
	@chmod 755 $(PREFIX)/bin/tiny-secrets-manager $(PREFIX)/bin/tsm

uninstall:
	@echo "Removing binaries from $(PREFIX)/bin..."
	@rm -f $(PREFIX)/bin/tiny-secrets-manager $(PREFIX)/bin/tsm
