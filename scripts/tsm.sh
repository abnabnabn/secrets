#!/usr/bin/env bash

# Minimal Bash CLI for tsm
# Dependencies: curl, jq

CONFIG_FILE="$HOME/.tsm.json"

usage() {
    echo "Usage: secret.sh <command> [arguments]"
    echo ""
    echo "Commands:"
    echo "  get <key>           - Fetch and print a secret value"
    echo "  put <key> <value>   - Store a secret value"
    echo "  ls [prefix]         - List all available secret keys"
    echo "  rm <key>            - Permanently delete a secret"
    echo "  login <url> <token> - Save credentials to $CONFIG_FILE"
    echo ""
    echo "Configuration:"
    echo "  Environment variables TSM_URL and TSM_TOKEN override the config file."
    exit 1
}

# Load credentials
URL="${TSM_URL}"
TOKEN="${TSM_TOKEN}"

if [[ -z "$URL" || -z "$TOKEN" ]]; then
    if [[ -f "$CONFIG_FILE" ]]; then
        URL=$(jq -r '.url' "$CONFIG_FILE" 2>/dev/null)
        TOKEN=$(jq -r '.token' "$CONFIG_FILE" 2>/dev/null)
    fi
fi

if [[ "$1" == "login" ]]; then
    if [[ -z "$2" || -z "$3" ]]; then usage; fi
    mkdir -p "$(dirname "$CONFIG_FILE")"
    printf '{"url": "%s", "token": "%s"}' "$2" "$3" > "$CONFIG_FILE"
    chmod 600 "$CONFIG_FILE"
    echo "Credentials saved to $CONFIG_FILE"
    exit 0
fi

# Ensure URL and TOKEN are set for other commands
if [[ -z "$URL" || -z "$TOKEN" ]]; then
    echo "Error: TSM_URL and TSM_TOKEN must be set via env vars or 'secret.sh login'" >&2
    exit 1
fi

URL="${URL%/}" # Strip trailing slash

case "$1" in
    get)
        if [[ -z "$2" ]]; then usage; fi
        curl -s -f -H "Authorization: Bearer $TOKEN" "$URL/v1/secrets/$2" | jq -r '.value'
        ;;
    put)
        if [[ -z "$2" || -z "$3" ]]; then usage; fi
        curl -s -f -X PUT -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
            -d "{\"value\": \"$3\"}" "$URL/v1/secrets/$2" > /dev/null
        echo "Secret '$2' stored."
        ;;
    ls|list)
        QUERY=""
        if [[ -n "$2" ]]; then QUERY="?prefix=$2"; fi
        curl -s -f -H "Authorization: Bearer $TOKEN" "$URL/v1/secrets$QUERY" | jq -r '.[]'
        ;;
    rm|delete)
        if [[ -z "$2" ]]; then usage; fi
        curl -s -f -X DELETE -H "Authorization: Bearer $TOKEN" "$URL/v1/secrets/$2" > /dev/null
        echo "Secret '$2' deleted."
        ;;
    *)
        usage
        ;;
esac
