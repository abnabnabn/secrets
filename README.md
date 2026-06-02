# secretd

A lightweight, high-performance, XChaCha20-Poly1305 encrypted secrets vault backed by a pure Go SQLite implementation. Designed for localized machine-to-machine (M2M) deployments and administrative ease, providing a secure, hardened enclosure for sensitive configuration.

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

### 1. Quick Setup (Local)
The `setup` target initializes Go modules, generates a `config.json` with a secure random master key, and seeds the initial administrative user into the encrypted database.

```bash
# Generate configuration and seed admin credentials
make setup
```

#### Customizing Admin Credentials
By default, `make setup` generates a random password for the `admin` user. You can provide a custom username and password during setup using environment variables:

```bash
ADMIN_USER=myadmin ADMIN_PASS=mypassword make setup
```

> **Note:** These credentials are encrypted and stored inside the database enclosure. They are **never** stored in `config.json`.

### 2. Running with Docker (Recommended)
The project includes a `Dockerfile` using Chainguard's hardened images.

```bash
# Start the vault with Docker Compose
docker compose up -d
```

#### Docker Custom Configuration
To use custom credentials with Docker, you must seed them during the initial volume creation or provide them via environment variables on the first run. The vault stores admin credentials in the encrypted database, not in the environment after the first boot.

**Seeding a custom admin on first run:**
```bash
# In your docker-compose.yaml or .env:
SECRETD_ADMIN_USER=myadmin
SECRETD_ADMIN_PASS=mypassword
SECRETD_ADMIN_TOKEN=my-secure-api-token
```

**Global Environment Variables:**
| Environment Variable | Description |
|----------------------|-------------|
| `SECRETD_MASTER_KEY` | 32-byte Base64 encoded master encryption key. |
| `SECRETD_BACKUP_TARGET` | Local path (`/backups/db.bak`) or SCP target (`user@host:/path/`). |
| `SECRETD_LISTEN` | Listen address (default: `0.0.0.0:8090`). |
| `SECRETD_ADMIN_USER` | (Seed Only) Username for initial admin creation. |
| `SECRETD_ADMIN_PASS` | (Seed Only) Password for initial admin creation. |
| `SECRETD_ADMIN_TOKEN` | (Seed Only) Token for initial admin API access. |

**Generating a Bcrypt Hash:**
If you need to generate a password hash manually (e.g., for manual database inserts):
```bash
# Generate a hash for 'mypassword' using the secretd binary
go run ./cmd/secretd --hash mypassword
```

## API & Integration

### Standalone CLI
The project includes two versions of a standalone CLI for managing secrets:
1.  **Go CLI (`bin/secret`)**: Robust, statically linked (no dependencies), works on any OS. (~6MB)
2.  **Bash CLI (`secret.sh`)**: Extremely minimal (~2KB), requires `curl` and `jq`.

**1. Setup:**
```bash
# To build the Go CLI:
make build-cli

# To use the Bash CLI:
chmod +x secret.sh
```

**2. Configuration:**
Set environment variables or use the `login` command:
```bash
# Option A: Environment Variables
export SECRETD_URL="http://localhost:8090"
export SECRETD_TOKEN="your-token-here"

# Option B: Persistent Login
./bin/secret login http://localhost:8090 your-token-here
```

**3. Usage Examples:**
```bash
./bin/secret ls
./bin/secret get app.db.password
./bin/secret put app.api.key "value"
```

### Ansible Integration
To securely fetch secrets dynamically within Ansible playbooks, use the provided lookup plugin in `plugins/ansible/lookup/secretd.py`.

**Example Playbook Usage:**
```yaml
- name: Start Database Container
  community.docker.docker_container:
    name: my_db
    image: postgres:latest
    env:
      POSTGRES_PASSWORD: "{{ lookup('secretd', 'app.db.password') }}"
```

## Development

* **Build:** `make build` - Generates a stripped, optimized binary.
* **Test:** `make test` - Runs the Go test suite (race detector enabled).
* **Setup:** `make setup` - Scaffolds configuration and keys.
* **Clean:** `make clean` - Removes binaries and local database files.
