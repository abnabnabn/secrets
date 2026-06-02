#!/usr/bin/env bash

# Minimal Bash CLI for tsm
# Dependencies: curl, jq

CONFIG_FILE="$HOME/.tsm.json"

usage() {
    echo "Usage: tsm.sh <command> [arguments]"
    echo ""
    echo "Commands:"
    echo "  get <key>           - Fetch and print a secret value"
    echo "  put <key> <value>   - Store a secret value"
    echo "  ls [prefix]         - List all available secret keys"
    echo "  rm <key>            - Permanently delete a secret"
    echo "  login <url> <token> - Save credentials to $CONFIG_FILE"
    echo "  run [flags] -- <cmd> - Run a command with injected secrets"
    echo ""
    echo "Run Flags:"
    echo "  -f, --file <path>   - TSM mapping file (default: tsm.env)"
    echo "  --env-file <path>   - Standard .env file (default: .env)"
    echo "  -e KEY=VAL          - Explicit environment override"
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
    echo "Error: TSM_URL and TSM_TOKEN must be set via env vars or 'tsm.sh login'" >&2
    exit 1
fi

URL="${URL%/}" # Strip trailing slash

parse_env_file() {
    local file="$1"
    if [[ ! -f "$file" ]]; then return; fi
    grep -v '^#' "$file" | grep '=' | while IFS='=' read -r key val; do
        key=$(echo "$key" | xargs)
        val=$(echo "$val" | xargs)
        echo "$key=$val"
    done
}

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
    run)
        shift
        TSM_ENV="tsm.env"
        DOT_ENV=".env"
        declare -a CLI_ENVS
        
        while [[ "$#" -gt 0 ]]; do
            case "$1" in
                -f|--file) TSM_ENV="$2"; shift 2 ;;
                --env-file) DOT_ENV="$2"; shift 2 ;;
                -e) CLI_ENVS+=("$2"); shift 2 ;;
                --) shift; break ;;
                *) echo "Unknown argument: $1"; usage ;;
            esac
        done
        
        if [[ "$#" -eq 0 ]]; then usage; fi

        # 1. TSM Mappings
        if [[ -f "$TSM_ENV" ]]; then
            while IFS='=' read -r env_key secret_key; do
                val=$(curl -s -f -H "Authorization: Bearer $TOKEN" "$URL/v1/secrets/$secret_key" | jq -r '.value' 2>/dev/null)
                if [[ "$val" != "null" && -n "$val" ]]; then
                    export "$env_key=$val"
                fi
            done < <(parse_env_file "$TSM_ENV")
        fi

        # 2. Standard .env (Literals)
        if [[ -f "$DOT_ENV" ]]; then
            while IFS='=' read -r key val; do
                export "$key=$val"
            done < <(parse_env_file "$DOT_ENV")
        fi

        # 3. CLI Overrides
        for e in "${CLI_ENVS[@]}"; do
            export "$e"
        done

        exec "$@"
        ;;
    *)
        usage
        ;;
esac
