# Tiny Secrets Manager

[![Build and Publish Docker Image](https://github.com/abnabnabn/tiny-secrets-manager/actions/workflows/docker-publish.yml/badge.svg)](https://github.com/abnabnabn/tiny-secrets-manager/actions/workflows/docker-publish.yml)


You might be thinking why another secrets manager? We got sick of managing secrets and env file across multiple projects and different computers, and decided to use a password manage to take care of all of this.

We had some fairly simple requirements - we *really* didn't want to lose the secrets, wanted it to be lightweight and not use up much ram (so it can run in limited resources), and we wanted to be able to control what apps could see what keys.  
Surely someone must have done this already? Maybe they have, but if so it was too hard to find!  Some options seemed pretty heavy (eg hashicorp vault), some have a load of nodejs or python overheads which made them too big, some didn't have a backup mechanism that worked well for us, and others seemed like they were no longer being actively maintained.

So, introducing **Tiny Secrets Manager**. It's tiny (~10MB), gives you granular key-level control, and backs up instantly whenever a key changes. It has an admin GUI, a CLI, emergency recovery keys, and even an Ansible plugin. It's also fully container-friendly, with pre-built, hardened images ready for x86 and ARM.

If there are features you want that aren't included, raise a feature request—we will add anything useful to our backlog as long as it aligns with our core values (tiny, safe, fully local).

## Key Features

* **Ultra-Lightweight Footprint:** Statically compiled binary (~10MB) with zero-dependency execution and extremely low memory overhead.
* **Secure by Design:** Uses XChaCha20-Poly1305 envelope encryption. Secrets are encrypted with an ephemeral 256-bit Data Encryption Key (DEK), which is itself wrapped in multiple "slots" using a primary Master Key and three emergency Recovery Keys.
* **Role-Based Access Control (RBAC):** Restrict application permissions down to individual keys or custom groups of keys using policy-driven Roles, ensuring clients and machines only see authorized secrets.
* **Interactive Admin GUI & CLI:** A built-in React management interface for visual audits and permissions simulation, paired with a robust CLI supporting context-based token resolution.
* **Offline-Ready:** All front-end assets (React, Tailwind CSS) are bundled directly into the Go binary. No internet access is required to run or manage the server in air-gapped environments.
* **Pure Go SQLite:** Built with `modernc.org/sqlite`, ensuring zero-CGO portability and a simplified supply chain. Operates in WAL mode for high concurrency.
* **Automated Disaster Recovery:** 
    * Every change triggers an automated database backup using `VACUUM INTO` on every addition or change.
    * Supports both local filesystem targets and remote off-site backups via `scp`.
* **Ansible Lookup Plugin:** Integrates secrets retrieval directly into your IaC process for automated configuration management.
* **Hardened Containerization:** Pre-built multi-architecture (Linux x86 and ARM) Chainguard-based images optimized for containerized environments with a minimal attack surface.

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

### 3. Environment Variables & CLI Options
You can customize the server's behavior by passing environment variables or CLI flags. These can be used with `make run` or when executing the binary directly.

| Variable / Flag | Usage | Default |
|-----------------|-------|---------|
| `TSM_ADMIN_USER` | (Seed Only) Custom username for initial admin. | `admin` |
| `TSM_ADMIN_PASS` | (Seed Only) Custom password for initial admin. | *Random* |
| `TSM_ADMIN_TOKEN`| (Seed Only) Custom API token for initial admin. | *Random* |
| `TSM_MASTER_KEY` | 32-byte Base64 encryption key. | *Auto-generated* |
| `TSM_LISTEN` | Bind address and port. | `0.0.0.0:8090` |
| `TSM_DB_PATH` | Path to the SQLite database file. | `tsm.db` |
| `TSM_INSECURE` or `--insecure` | Bypass HTTPS enforcement and use less strict (Lax) cookie settings. Useful for local development over HTTP. | `false` |

**Security Note (Secure by Default):**
By default, Tiny Secrets Manager operates in **Secure Mode**. In this mode:
* Cookies are set with `SameSite: Strict` and `Secure: true`.
* HTTP traffic is automatically redirected to HTTPS (GET requests) or rejected with `403 Forbidden` (non-GET requests).
* Security headers (`Strict-Transport-Security` / HSTS, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, and `Referrer-Policy: no-referrer`) are actively injected.

To run locally without SSL/TLS (e.g. over plain HTTP on localhost), pass the `--insecure` flag or set the `TSM_INSECURE=true` environment variable:
```bash
# Run with CLI flag
./bin/tiny-secrets-manager --insecure

# Run with environment variable
TSM_INSECURE=true ./bin/tiny-secrets-manager
```

**Example: Starting with a custom port and admin password**
```bash
TSM_LISTEN="127.0.0.1:9000" TSM_ADMIN_PASS="secure-password" ./bin/tiny-secrets-manager --insecure
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
The project includes a robust, statically linked Go CLI for managing and injecting secrets.

**1. Setup:**

*   **Option A: Download Binary (Recommended)**
    Download the pre-compiled binary for your OS and architecture from the **[GitHub Releases](https://github.com/abnabnabn/tiny-secrets-manager/releases)** page.
*   **Option B: Build from Source**
    ```bash
    # Requires Go 1.25+
    make build-cli
    ```

**2. Configuration:**
Tiny Secrets Manager uses a **Context-Based Authentication** system. Instead of global environment variables, you link specific directories to specific machine tokens. This information is stored in a protected central file (`~/.tsm.json`).

```bash
# 1. Set your server URL
./bin/tsm login http://localhost:8090

# 2. Link your current project directory to a specific token
cd ~/projects/my-app
./bin/tsm auth --link your-machine-token-here

# 3. Audit active contexts and validate tokens
./bin/tsm auth --status

# 4. Clean up stale or redundant directory mappings
./bin/tsm auth --tidy
```

Once linked, the CLI will automatically use the correct token whenever you are inside that directory or its subdirectories.

**3. Usage Examples:**
```bash
# No token needed - automatically resolved from context
./bin/tsm ls
./bin/tsm get app.db.password
```

**4. Context Management Details:**
*   **`--status`**: Performs a read-only audit of all mapped directories. It masks tokens (e.g., `tsm_tk_abcd...1234`) and pings the server to verify if each token is still valid or has been revoked.
*   **`--tidy`**: Performs local housekeeping. It removes entries for directories that no longer exist on your machine and prunes redundant child-directory mappings if a parent is already linked to the same token.

**4. Running Applications with Secrets:**
The `run` command allows you to execute programs with environment variables injected directly from the secrets manager.

*   **Explicit Mapping:** Create a `tsm.env` file in your project root:
    ```text
    DATABASE_URL=app.prod.db_url
    API_KEY=app.prod.api_key
```
*   **Automatic Resolution:** The CLI resolves the token based on your current directory context.
*   **Explicit Token (Override):** You can manually provide a token for a single run using the `--token` flag:
    ```bash
    ./bin/tsm run --token xxxxx -- ./my-app
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
*   **`make test`**: Runs the Go test suite with the race detector enabled. (Executed automatically on push via GitHub Actions).
*   **`make clean`**: Removes binaries, local database files, and the `config.json`.
*   **`make tidy`**: Cleans up and synchronizes Go module dependencies.
*   **`make dev-link`**: Creates symlinks in `~/.local/bin` to your local project binaries. Allows you to run `tsm` from any directory while developing. No root required.
*   **`make dev-unlink`**: Removes the development symlinks.
