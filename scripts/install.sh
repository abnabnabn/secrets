#!/bin/bash
set -e

INSTALL_CLI=false
INSTALL_SERVER=false
SCRIPT_SOURCE="github"
DEST_DIR="/usr/local/bin"
SERVER_URL=""
INSTALL_SYSTEMD=false

usage() {
    echo "Usage: $0 [options]"
    echo ""
    echo "Installation Options:"
    echo "  --cli               Install the tsm CLI binary"
    if [ "$SCRIPT_SOURCE" = "github" ]; then
        echo "  --server            Install the tiny-secrets-manager server binary"
        echo "  --systemd           Configure and start systemd service (requires --server)"
    fi
    echo "  --dest <path>       Destination directory (default: /usr/local/bin)"
    echo "  --url <url>         Server URL for CLI auto-login (e.g., http://localhost:8090)"
    echo ""
    echo "Server Configuration Options (optional, falls back to TSM_* env vars):"
    echo "  --listen <addr>     Server bind address (e.g., 0.0.0.0:8090)"
    echo "  --admin-user <user> Seed Admin username"
    echo "  --admin-pass <pass> Seed Admin password"
    echo "  --admin-token <tok> Seed Admin token"
    echo "  --backup-target <p> Auto-backup path (e.g., /var/backups/tsm/ OR user@host:/backups/)"
    echo "  --insecure          Run server in insecure mode"
    echo "  --help              Show this help message"
    echo ""
}

while [[ "$#" -gt 0 ]]; do
    case $1 in
        --cli) INSTALL_CLI=true ;;
        --server) INSTALL_SERVER=true ;;
        --systemd|--systemctl) INSTALL_SYSTEMD=true ;;
        --url) SERVER_URL="$2"; shift ;;
        --dest) DEST_DIR="$2"; shift ;;
        --listen) TSM_LISTEN_ARG="$2"; shift ;;
        --admin-user) TSM_ADMIN_USER_ARG="$2"; shift ;;
        --admin-pass) TSM_ADMIN_PASS_ARG="$2"; shift ;;
        --admin-token) TSM_ADMIN_TOKEN_ARG="$2"; shift ;;
        --backup-target) TSM_BACKUP_TARGET_ARG="$2"; shift ;;
        --insecure) TSM_INSECURE_ARG=true ;;
        --help|-h) usage; exit 0 ;;
        *) echo "Unknown option: $1"; usage; exit 1 ;;
    esac
    shift
done

# Load configuration priorities: 1) CLI Args, 2) Environment Vars
SERVER_URL=${SERVER_URL:-$TSM_URL}
TSM_LISTEN=${TSM_LISTEN_ARG:-$TSM_LISTEN}
TSM_ADMIN_USER=${TSM_ADMIN_USER_ARG:-$TSM_ADMIN_USER}
TSM_ADMIN_PASS=${TSM_ADMIN_PASS_ARG:-$TSM_ADMIN_PASS}
TSM_ADMIN_TOKEN=${TSM_ADMIN_TOKEN_ARG:-$TSM_ADMIN_TOKEN}
TSM_BACKUP_TARGET=${TSM_BACKUP_TARGET_ARG:-$TSM_BACKUP_TARGET}
TSM_INSECURE=${TSM_INSECURE_ARG:-$TSM_INSECURE}

if [ "$INSTALL_CLI" = true ] && [ -z "$SERVER_URL" ] && [ -n "$TSM_LISTEN" ]; then
    if [[ "$TSM_LISTEN" == *":"* ]]; then
        HOST=$(echo "$TSM_LISTEN" | cut -d: -f1)
        PORT=$(echo "$TSM_LISTEN" | cut -d: -f2)
        if [ "$HOST" = "0.0.0.0" ]; then HOST="127.0.0.1"; fi
        if [ "$TSM_INSECURE" = "true" ]; then
            SERVER_URL="http://${HOST}:${PORT}"
        else
            SERVER_URL="https://${HOST}:${PORT}"
        fi
        echo "Inferred SERVER_URL from TSM_LISTEN: $SERVER_URL"
    fi
fi

if [ "$INSTALL_CLI" = true ] && [ -z "$SERVER_URL" ]; then
    echo "Error: Server URL is required for CLI installation."
    echo "The CLI needs a server URL to perform the initial login configuration."
    echo ""
    echo "Provide it via --url or the TSM_URL environment variable."
    echo "Example: $0 --cli --url http://localhost:8090"
    echo ""
    usage
    exit 1
fi

if [ "$INSTALL_CLI" = false ] && [ "$INSTALL_SERVER" = false ]; then
    echo "Error: You must specify either --cli or --server."
    echo ""
    usage
    exit 1
fi

if [ "$INSTALL_SERVER" = true ] && [ "$SCRIPT_SOURCE" = "docker" ]; then
    echo "Error: This script is hosted by a Tiny Secrets Manager server and can only be used to install the CLI."
    echo "To install a new server, please download the universal script directly from GitHub:"
    echo "curl -sSL https://raw.githubusercontent.com/abnabnabn/tiny-secrets-manager/main/scripts/install.sh | bash -s -- --server"
    exit 1
fi

echo "Ensuring directory $DEST_DIR exists and is writable..."
if ! mkdir -p "$DEST_DIR" 2>/dev/null || ! touch "$DEST_DIR/.tsm_test" 2>/dev/null; then
    echo "Error: You do not have write permissions for $DEST_DIR."
    echo "Please specify a different destination directory you have access to, or run the script as a user with appropriate permissions."
    echo "Example (custom directory): $0 --dest ~/.local/bin"
    echo "Example (with sudo):        sudo $0"
    exit 1
else
    rm -f "$DEST_DIR/.tsm_test"
fi

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$OS" in
  linux*)   OS="linux" ;;
  darwin*)  OS="darwin" ;;
  *)        echo "Unsupported OS: $OS"; exit 1 ;;
esac

ARCH=$(uname -m)
case "$ARCH" in
  x86_64)   ARCH="amd64" ;;
  amd64)    ARCH="amd64" ;;
  arm64)    ARCH="arm64" ;;
  aarch64)  ARCH="arm64" ;;
  *)        echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

SERVER_BINARY_NAME="tsm-server-${OS}-${ARCH}"
CLI_BINARY_NAME="tsm-${OS}-${ARCH}"

REPO_URL="https://github.com/abnabnabn/tiny-secrets-manager"
SERVER_GITHUB_URL="${REPO_URL}/releases/latest/download/${SERVER_BINARY_NAME}"
CLI_GITHUB_URL="${REPO_URL}/releases/latest/download/${CLI_BINARY_NAME}"

SERVER_DEST="${DEST_DIR}/tiny-secrets-manager"
CLI_DEST="${DEST_DIR}/tsm"

# Utility to check if a URL exists
check_url() {
    local url=$1
    if command -v curl >/dev/null 2>&1; then
        curl -sLfI "$url" >/dev/null 2>&1
    elif command -v wget >/dev/null 2>&1; then
        wget --spider -q "$url" >/dev/null 2>&1
    else
        echo "Error: curl or wget is required."
        exit 1
    fi
}

if [ "$INSTALL_SERVER" = true ]; then
    echo "Checking availability of $SERVER_GITHUB_URL..."
    if ! check_url "$SERVER_GITHUB_URL"; then
        echo "Error: Server binary for ${OS}/${ARCH} is not available on GitHub Releases yet."
        exit 1
    fi
fi

if [ "$INSTALL_CLI" = true ]; then
    if [ "$SCRIPT_SOURCE" = "docker" ]; then
        CLI_DOWNLOAD_URL="${SERVER_URL}/cli/${CLI_BINARY_NAME}"
    else
        CLI_DOWNLOAD_URL="$CLI_GITHUB_URL"
        if [ -n "$SERVER_URL" ]; then
            if check_url "${SERVER_URL}/cli/${CLI_BINARY_NAME}"; then
                CLI_DOWNLOAD_URL="${SERVER_URL}/cli/${CLI_BINARY_NAME}"
                echo "Found CLI on local server (${SERVER_URL}), optimizing download..."
            fi
        fi
    fi

    echo "Checking availability of $CLI_DOWNLOAD_URL..."
    if ! check_url "$CLI_DOWNLOAD_URL"; then
        if [ "$SCRIPT_SOURCE" = "docker" ]; then
            echo "Error: CLI binary for ${OS}/${ARCH} is not available on the local server."
        else
            echo "Error: CLI binary for ${OS}/${ARCH} is not available."
        fi
        exit 1
    fi
fi

download_file() {
    local url=$1
    local dest=$2
    echo "Downloading from ${url}..."
    if command -v curl >/dev/null 2>&1; then
        curl -sSLf "$url" -o "$dest" || { echo "Failed to download from GitHub."; exit 1; }
    else
        wget -qO "$dest" "$url" || { echo "Failed to download from GitHub."; exit 1; }
    fi
    chmod +x "$dest"
}

if [ "$INSTALL_SERVER" = true ]; then
    echo "Installing Tiny Secrets Manager Server..."
    download_file "$SERVER_GITHUB_URL" "$SERVER_DEST"
    echo "Successfully installed server to ${SERVER_DEST}"

    if [ "$INSTALL_SYSTEMD" = true ]; then
        if ! command -v systemctl >/dev/null 2>&1; then
            echo "Error: systemctl not found. Cannot configure systemd service."
            exit 1
        fi

        if [ "$EUID" -ne 0 ]; then
            echo "Error: --systemd requires root privileges. Please run script with sudo."
            exit 1
        fi

        echo "Configuring systemd service..."
        if ! id tsm >/dev/null 2>&1; then
            useradd -r -s /sbin/nologin tsm
        fi

        mkdir -p /etc/tiny-secrets-manager /var/lib/tiny-secrets-manager
        chown tsm:tsm /var/lib/tiny-secrets-manager /etc/tiny-secrets-manager

        if [ -n "$TSM_ADMIN_PASS" ] || [ -n "$TSM_ADMIN_USER" ] || [ -n "$TSM_BACKUP_TARGET" ]; then
            echo "Seeding database with provided credentials/settings..."
            sudo -u tsm env TSM_ADMIN_PASS="$TSM_ADMIN_PASS" TSM_ADMIN_USER="$TSM_ADMIN_USER" TSM_ADMIN_TOKEN="$TSM_ADMIN_TOKEN" TSM_BACKUP_TARGET="$TSM_BACKUP_TARGET" sh -c "cd /var/lib/tiny-secrets-manager && ${SERVER_DEST} -seed-only /etc/tiny-secrets-manager/config.json"
        fi

        SERVICE_URL="${REPO_URL}/raw/main/scripts/tiny-secrets-manager.service"
        download_file "$SERVICE_URL" /etc/systemd/system/tiny-secrets-manager.service

        if [ -n "$TSM_LISTEN" ] || [ "$TSM_INSECURE" = "true" ]; then
            mkdir -p /etc/systemd/system/tiny-secrets-manager.service.d
            echo "[Service]" > /etc/systemd/system/tiny-secrets-manager.service.d/override.conf
            if [ -n "$TSM_LISTEN" ]; then echo "Environment=\"TSM_LISTEN=$TSM_LISTEN\"" >> /etc/systemd/system/tiny-secrets-manager.service.d/override.conf; fi
            if [ "$TSM_INSECURE" = "true" ]; then echo "Environment=\"TSM_INSECURE=true\"" >> /etc/systemd/system/tiny-secrets-manager.service.d/override.conf; fi
        fi

        systemctl daemon-reload
        systemctl enable --now tiny-secrets-manager
        echo "Successfully started tiny-secrets-manager.service"
    fi
fi

if [ "$INSTALL_CLI" = true ]; then
    echo "Installing Tiny Secrets Manager CLI..."
    download_file "$CLI_DOWNLOAD_URL" "$CLI_DEST"
    echo "Successfully installed CLI to ${CLI_DEST}"
    
    if [ -n "$SERVER_URL" ]; then
        echo "Configuring tsm to use server: $SERVER_URL"
        if [ -n "$SUDO_USER" ]; then
            sudo -u "$SUDO_USER" "$CLI_DEST" login "$SERVER_URL" > /dev/null 2>&1 || true
        else
            "$CLI_DEST" login "$SERVER_URL" > /dev/null 2>&1 || true
        fi
    fi

    echo "Run 'tsm --help' to get started!"
fi

if ! echo ":$PATH:" | grep -q ":$DEST_DIR:"; then
    echo ""
    echo "========================================================================"
    echo "WARNING: $DEST_DIR is NOT in your PATH."
    echo "To run the tools from anywhere, add this to your .bashrc or .zshrc:"
    echo "  export PATH=\"\$PATH:$DEST_DIR\""
    echo "========================================================================"
    echo ""
fi
