# Tiny Secrets Manager

A lightweight, high-performance, XChaCha20-Poly1305 encrypted secrets manager backed by a pure Go SQLite implementation. Designed for localized machine-to-machine (M2M) deployments and administrative ease, providing a secure, hardened enclosure for sensitive configuration.

## Key Features

* **Secure by Design:** Uses XChaCha20-Poly1305 envelope encryption. Secrets are encrypted with an ephemeral 256-bit Data Encryption Key (DEK), which is itself wrapped in multiple "slots" using a primary Master Key and three emergency Recovery Keys.
* **Pure Go SQLite:** Built with `modernc.org/sqlite`, ensuring zero-CGO portability and a simplified supply chain. Operates in WAL mode for high concurrency.
* **Advanced Access Control:** Granular Policy-Based Access Control (PBAC). Tokens can be restricted to specific key prefixes (using dot-notation like `app.dev.db`) and specific operations (`GET`, `LIST`, `PUT`, `DELETE`).
* **Interactive Admin GUI:** A built-in React/Tailwind management interface allows admins to:
    * Manage secrets with full CRUD support.
    * Provision, edit, and clone machine tokens.
    * **Audit Mode:** "View As" any token to simulate and verify its exact permission boundary.
* **Automated Disaster Recovery:** 
    * Every change triggers an automated, consistent database backup using `VACUUM INTO`.
    * Supports both local filesystem targets and remote off-site backups via `scp`.
* **Hardened Deployment:** Optimized for containerization using minimal **Chainguard** base images for maximum security and minimal attack surface.

## Getting Started

### 1. Installation & Setup
Follow these steps in order to prepare and start the Tiny Secrets Manager.

```bash
# 1. Initialize the project (tidies modules and builds all binaries)
make setup

# 2. Start the server
# Option A: Zero-Config (Random credentials will be generated and printed)
make run

# Option B: Custom Admin (Set your own credentials on first boot)
TSM_ADMIN_USER=admin TSM_ADMIN_PASS=mypassword make run
```

### 2. Self-Bootstrapping
The `tiny-secrets-manager` binary is designed to be self-sufficient. If no `config.json` is found on the first run, it will:
1.  **Generate Infrastructure:** Creates a `config.json` with a random 256-bit Master Key.
2.  **Initialize Database:** Creates an encrypted `tsm.db` enclosure.
3.  **Seed Admin:** Creates the initial administrator account.
4.  **Display Credentials:** **The initial username, password, and API token will be printed to the console exactly once.**

### 3. Environment Variables
You can customize the server's behavior by passing environment variables. These can be used with `make run` or when executing the binary directly.

| Variable | Usage | Default |
|----------|-------|---------|
| `TSM_ADMIN_USER` | (Seed Only) Custom username for initial admin. | `admin` |
| `TSM_ADMIN_PASS` | (Seed Only) Custom password for initial admin. | *Random* |
| `TSM_ADMIN_TOKEN`| (Seed Only) Custom API token for initial admin. | *Random* |
| `TSM_MASTER_KEY` | 32-byte Base64 encryption key. | *Auto-generated* |
| `TSM_LISTEN` | Bind address and port. | `0.0.0.0:8090` |
| `TSM_DB_PATH` | Path to the SQLite database file. | `tsm.db` |

**Example: Starting with a custom port and admin password**
```bash
TSM_LISTEN="127.0.0.1:9000" TSM_ADMIN_PASS="secure-password" ./bin/tiny-secrets-manager
```

### 4. Running with Docker (Recommended)
The project includes a hardened `Dockerfile` based on Chainguard images.

```bash
# Start with Docker Compose
docker compose up -d
```
*Note: You can edit the `environment` section in `docker-compose.yaml` to set your initial credentials.*

## API & Integration

### Standalone CLI
The project includes two versions of a standalone CLI for managing secrets:
1.  **Go CLI (`bin/tsm`)**: Robust, statically linked (no dependencies), works on any OS. (~6MB)
2.  **Bash CLI (`tsm.sh`)**: Extremely minimal (~2KB), requires `curl` and `jq`.

**1. Setup:**
```bash
# To build the Go CLI:
make build-cli

# To use the Bash CLI:
chmod +x tsm.sh
```

**2. Configuration:**
Set environment variables or use the `login` command:
```bash
# Option A: Environment Variables
export TSM_URL="http://localhost:8090"
export TSM_TOKEN="your-token-here"

# Option B: Persistent Login
./bin/tsm login http://localhost:8090 your-token-here
```

**3. Usage Examples:**
```bash
./bin/tsm ls
./bin/tsm get app.db.password
./bin/tsm put app.api.key "value"
```

### Ansible Integration
To securely fetch secrets dynamically within Ansible playbooks, use the provided lookup plugin in `plugins/ansible/lookup/tsm.py`.

**Example Playbook Usage:**
```yaml
- name: Start Database Container
  community.docker.docker_container:
    name: my_db
    image: postgres:latest
    env:
      POSTGRES_PASSWORD: "{{ lookup('tsm', 'app.db.password') }}"
```

## Development

*   **`make setup`**: Full initialization (tidy + build). Recommended for first-time use.
*   **`make build`**: Compiles stripped, optimized binaries for the server and CLI.
*   **`make run`**: Builds the server and starts it.
*   **`make test`**: Runs the Go test suite with the race detector enabled.
*   **`make clean`**: Removes binaries, local database files, and the `config.json`.
*   **`make tidy`**: Cleans up and synchronizes Go module dependencies.
