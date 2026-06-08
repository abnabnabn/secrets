# Tiny Secrets Manager: Complete Setup & Migration Guide

This guide walks you through the entire lifecycle of Tiny Secrets Manager—from spinning up the server, to managing secrets and roles, and finally injecting secrets into your applications.

---

## 1. Initial Server Setup

Tiny Secrets Manager is designed to be zero-configuration on first boot. The easiest way to run it is via Docker.

### Using Docker (Recommended)
1. Ensure you have Docker and Docker Compose installed.
2. Run the server using the provided `docker-compose.yaml`:
   ```bash
   docker compose up -d
   ```
3. Check the logs to retrieve your auto-generated admin credentials and **Emergency Recovery Keys**. 
   ```bash
   docker compose logs
   ```
   *(Alternatively, you can force specific credentials and backup settings on first boot by passing `TSM_ADMIN_USER`, `TSM_ADMIN_PASS`, `TSM_ADMIN_TOKEN`, and `TSM_BACKUP_TARGET` as environment variables).*

### Using Pre-built Binaries (GitHub Releases)
If you prefer running the raw server binary directly on your host machine without Docker, you can download the latest pre-compiled release from GitHub using our universal installation script.
1. Run the script to install the server:
   ```bash
   curl -sSL https://raw.githubusercontent.com/abnabnabn/tiny-secrets-manager/main/scripts/install.sh | bash -s -- --server --backup-target /var/backups/tsm/
   ```
   *(The default install location is /usr/local/bin. You can also pass `--dest <install-path>` to install it somewhere else, eg `--dest ~/.local/bin`. The `--backup-target` flag is optional but recommended to set up automated backups on boot).*
2. Run the server:
   ```bash
   tiny-secrets-manager
   ```

### Building From Source
If you want to compile the server yourself from the source code:
1. Compile the server (this builds the server, CLI, and web UI):
   ```bash
   make setup
   make build
   ```
2. You can optionally link the generated binaries (`tiny-secrets-manager` and `tsm`) into your `$PATH` (typically `~/.local/bin`) by running:
   ```bash
   make dev-link
   ```
3. Run the server:
   ```bash
   tiny-secrets-manager
   ```

On its very first boot (regardless of the installation method), the console will print your initial auto-generated `Username`, `Password`, `Admin API Token`, and **three Emergency Recovery Keys**.

> [!CAUTION]
> **This is the only time the Recovery Keys will be printed!** You must securely store them somewhere completely isolated from the server (like a physical safe or offline password manager) immediately. They are the only way to recover your vault if you lose the Master Key!

---

## 2. The Two Interfaces: Web GUI vs CLI

Once your server is running, you have two distinct ways to interact with it:

1. **The Web GUI:** Open your browser and navigate to your server's URL (e.g., `http://localhost:8090`). Here you can log in with your admin credentials to visually manage secrets, create roles, and audit access.
2. **The CLI (`tsm`):** A command-line tool that can do everything the GUI can do, plus dynamically inject secrets into your applications at runtime. 

In the Web GUI, make sure to check out the **System Settings** tab to configure your automated background backups and retention policy.

### Note on Backups and File Permissions
Because Tiny Secrets Manager is designed to be highly secure, it runs as a limited, unprivileged process (or a minimal Docker container). This means it cannot bypass OS rules to write backups into root-owned directories.
- **Docker Users:** If you want local backups, map a volume (e.g., `-v /your/host/backups:/backups`) and ensure the host directory is writable by the container. Then set your backup target to the internal path (`/backups/`).
- **Binary / Linux Users:** If you install via `make install`, the daemon runs as the `tsm` user. You can use the Makefile to cleanly create a secure backup directory with the right permissions:
  ```bash
  TSM_BACKUP_TARGET="/storage/tsm-backups/" sudo make setup-backup-dir
  ```

While the Web GUI is fantastic for administration and visual management, the **CLI is required on your client machines** (developer laptops, CI/CD runners, production servers) to actually consume those secrets.

---

## 3. Installing the CLI

To use the CLI, you must install it on the machine that needs it. There are three ways to get it, depending on how you run the server:

### Option A: If you are using Docker (Recommended)
When running the server via Docker, the container hosts all the pre-compiled CLI binaries on its own internal file server. You can install it on your client machines directly from the server:
```bash
# Replace localhost:8090 with your actual server URL if running remotely
curl -sSL http://localhost:8090/install.sh | bash -s http://localhost:8090
```
*(This script automatically detects your OS and processor architecture to fetch the perfectly matched binary).*

### Option B: From GitHub Releases
If you aren't using Docker and just want the pre-compiled binary, you can download it directly from GitHub using our universal installation script.  It would have already been installed for you in step 1, but if you need it on another computer you can install as follows:
```bash
curl -sSL https://raw.githubusercontent.com/abnabnabn/tiny-secrets-manager/main/scripts/install.sh | bash -s -- --cli
```

### Option C: If you built from Source
If you prefer to compile the tools yourself, you must first build them as your normal user.
```bash
make build
```
Once compiled, you can install the binaries globally:
```bash
make dev-link # (Symlinks into ~/.local/bin, no sudo required)
# OR
sudo make install # (Copies to /usr/local/bin)
```
> [!TIP]
> **Systemd Auto-Setup (Linux)**
> If you run `sudo make install` on a Linux system with `systemctl`, the Makefile will automatically set up the server as a background service following security best practices. It creates a dedicated `tsm` system user, provisions `/etc/tiny-secrets-manager` for configuration, `/var/lib/tiny-secrets-manager` for the database, and installs a systemd service. 
> 
> **Bootstrap Variables:**
> You can pass `TSM_ADMIN_USER=... TSM_ADMIN_PASS=... TSM_BACKUP_TARGET=... sudo make install` to automatically provision the admin credentials and backup settings directly into the encrypted vault during installation. The installer securely seeds the database and discards the variables before the daemon ever starts.
> 
> **Runtime Variables:**
> You can also pass `TSM_LISTEN="0.0.0.0:80" TSM_INSECURE=true sudo make install`. The Makefile will automatically create a systemd drop-in override (`/etc/systemd/system/tiny-secrets-manager.service.d/override.conf`) to bind these runtime variables to the service!
> 
> To enable and start it manually: `sudo systemctl enable --now tiny-secrets-manager`

- To use the CLI on **other machines**, you will need to manually copy the generated `tsm` binary from your `bin/` directory to those machines.  If you're building from source then you shouldn't need help here!

---

## 4. Authenticating the CLI

Before using the CLI, you must authenticate it. How you authenticate depends on **what you want to do**.

### Path A: Administrator Setup
*Use this path if you are setting up the system, managing roles, or creating global secrets via the command line instead of the Web GUI.*

Log into the CLI as an administrator to gain elevated privileges. 
```bash
tsm login http://localhost:8090 -u admin
# You will be securely prompted for your password
```
*(Note: This creates a temporary admin session that automatically expires after 1 hour of inactivity).*

### Path B: Client / Machine Setup
*Use this path if you are on a production server, in a CI pipeline, or a developer fetching secrets for a specific project. You do NOT need admin credentials for this.*

If an administrator has already provisioned a machine role token (either via the Web GUI or CLI), you can bind that token to your current project directory:
```bash
cd ~/projects/my-app
tsm auth --link <YOUR_MACHINE_TOKEN>
```
Whenever you run `tsm` commands inside this directory, it will automatically use that specific token.

---

## 5. Managing Roles & Secrets

### Step 5a: Create a Machine Role
You don't want your applications running as a global Admin. Instead, create a **Role** that grants the application "Least Privilege" access.

> [!WARNING]
> Be careful when granting the `LIST` permission to applications! `LIST` allows a token to discover all secret keys under a prefix, which means a compromised app could scan and steal every secret it has access to. 
> 
> **Best Practice:** Applications generally only need the `GET` permission to retrieve the exact secrets they require. Reserve the `LIST` permission for human User roles or auditing tools.

* **Via the Web GUI:** Navigate to the Roles page, create a new role called `my-prod-app`, and add a policy for `app.prod.*` with just the `GET` method.
* **Via the CLI (Requires Admin Privileges - Path A):**
  ```bash
  tsm role create my-prod-app --policy "app.prod.*:GET"
  ```
The system will generate a new, raw API token. You can now use this token for **Path B** on your application servers.

### Step 5b: Add a Secret
You can create secrets as long as your authenticated token has `PUT` permissions for that specific path. 

When adding a secret via the CLI, you can optionally provide a third argument: the **Environment Key** (`env_key`). This defines what environment variable name should automatically be used when applications fetch this secret later.

* **Via the Web GUI:** Navigate to the Secrets page and add your key-value pairs (and optionally the Env Key).
* **Via the CLI:**
  ```bash
  # Basic secret creation
  tsm put app.prod.db.password "my_super_secret_password"
  
  # Secret creation with an explicit environment mapping (e.g. STRIPE_API_KEY)
  tsm put app.prod.stripe.key "sk_live_123456789" STRIPE_API_KEY
  ```

---

## 6. Retrieving Data & Automated Injection

Now that you have your roles, secrets, and authenticated CLI set up, you are ready to start using them!

The CLI supports manually fetching secrets (via `tsm get`), managing them (via `tsm put`), and automatically injecting them into your applications at runtime (via `tsm run`).

For full instructions, examples, and documentation on how to use these commands, please see the **[CLI Guide](cli-guide.md)**.

---

## 7. Troubleshooting & Emergency Recovery

The `tsm.db` file is fully encrypted. To decrypt it, the server relies on the Master Key (passed via `TSM_MASTER_KEY`). If the Master Key is permanently lost (e.g., your orchestration system goes down and destroys the environment variable), your vault is locked.

To unlock it, you must use one of the three **Emergency Recovery Keys** generated during the initial setup.

### How to Recover a Locked Vault
1. Locate one of your saved Emergency Recovery Keys.
2. Start the server (either via Docker or the binary) and pass the recovery key instead of the master key, using the `TSM_RECOVERY_KEY` environment variable:
   ```bash
   TSM_RECOVERY_KEY="<YOUR_RECOVERY_KEY>" ./bin/tsm-server
   ```
   *(Or set it in your `docker-compose.yaml` if using Docker).*
3. The server will use the Recovery Key to decrypt the vault, securely rotate the internal encryption keys, and automatically generate a **brand new** Master Key.
4. Check the server logs! It will print the new Master Key. Save it, and update your configuration to use this new `TSM_MASTER_KEY` moving forward.
5. The Recovery Key you used is permanently burned (single-use). If you want to replenish your backup keys, you can regenerate them from the Web GUI or via the API.
