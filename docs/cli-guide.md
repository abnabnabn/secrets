# Tiny Secrets Manager: CLI Guide

The `tsm` command-line interface provides everything you need to manage your secrets and seamlessly inject them into your applications. 

## Initial Setup & Authentication

Before you can interact with the server, you need to point the CLI to it and authenticate the current directory.

### `tsm login`
Set the target server URL and optionally authenticate to provision your global Admin Mode token.
```bash
# Just set the server URL
tsm login https://secrets.internal.example.com:8090

# Authenticate as an admin (prompts for password securely)
tsm login https://secrets.internal.example.com:8090 -u admin

> **Note**: Admin sessions created via `tsm login` have a built-in 1-hour idle timeout. The session token will automatically expire if not used for 1 hour, and the server will periodically prune these expired tokens.
```

### `tsm auth --link`
Link a specific role token to your current directory. The CLI resolves tokens based on your current working directory, allowing you to have different tokens for different projects on the same machine.
```bash
tsm auth --link eyJhbGci...
```

### `tsm auth --status`
Check the status of your authentication, showing the active token and the resolved server URL.
```bash
tsm auth --status
```

### `tsm auth --tidy`
Clean up any stale tokens in your configuration (e.g., if you deleted a project directory, this removes its lingering token binding).
```bash
tsm auth --tidy
```

### `tsm auth --admin`
Set your global Admin token. This is used exclusively for administrative commands (like `tsm role ...`) or when bypassing directory tokens using the `--admin` flag.
```bash
tsm auth --admin eyJhbGci...
```

---

## Admin Mode vs Normal Mode

The CLI operates in two modes to prevent privilege escalation:

- **Normal Mode (Default)**: Commands (`get`, `put`, `ls`, `rm`, `run`) use the token linked to the *current directory* (the machine token). If no directory token is linked, the command fails. This ensures that an application running `tsm run` can **never** accidentally inherit your global admin permissions.
- **Admin Mode (`--admin`)**: By appending the `--admin` flag to any data command (e.g., `tsm ls --admin`), the CLI bypasses the local directory context and uses your global Admin token. 
- **Role Commands**: Commands under `tsm role` inherently require administrative privileges. They automatically run in Admin Mode without needing the flag.

## Secret Management

These commands require you to be authenticated. The active token dictates which secrets you are permitted to read, write, or list based on your Role policies.

### `tsm ls` (or `tsm list`)
List all secret keys available to your current role. 
```bash
# List all secrets accessible by the directory token
tsm ls

# List all secrets using Admin Mode (bypasses directory token)
tsm ls --admin

# List secrets starting with a specific prefix
tsm ls app.prod
```

### `tsm get`
Fetch and print the decrypted payload of a specific secret.
```bash
tsm get app.prod.database.password
```

### `tsm put`
Create or update a secret. You can optionally provide a third argument to set an `env_key` fallback (used during implicit `tsm run` injections).
```bash
# Basic usage
tsm put app.prod.database.password "s3cr3t_p@ssw0rd"

# With an env_key fallback
tsm put app.prod.database.password "s3cr3t_p@ssw0rd" DB_PASS
```

### `tsm rm` (or `tsm delete`)
Permanently delete a secret from the vault.
```bash
tsm rm app.prod.database.password
```

---

## Role Management

As an Administrator, you can manage machine roles directly from the CLI. This allows you to fully automate token provisioning via your CI/CD pipelines or Infrastructure as Code (e.g., Terraform/Ansible) without needing to use the Web GUI.

### `tsm role ls`
List all machine roles and their associated policies.
```bash
tsm role ls
```

### `tsm role create`
Create a new role and provision its token. This command takes one or more `--policy` flags, and an optional `--can-create` flag. 
Format: `[--can-create] --policy <prefix>[:<methods>]` (methods default to `GET,LIST`).

**Available Methods for Policies:**
- `GET`: Read the value of a specific secret.
- `LIST`: Discover secret keys under this prefix.
- `PUT`: Create or update secrets under this prefix.
- `DELETE`: Remove secrets under this prefix.

**Global Permissions:**
- `--can-create`: A global flag allowing the role to generate entirely new secrets (automatically granting them GET and PUT access to the new key).
```bash
# Provision a token that can only read secrets starting with app.prod.
tsm role create my-prod-server --policy app.prod.*

# Provision a token with multiple policies
tsm role create my-hybrid-server --policy app.prod.*:GET,LIST --policy system.shared.*:GET

# Provision a token that can read and write to a specific secret
tsm role create my-backup-server --policy system.backup.key:GET,PUT
```

### `tsm role update`
Update the policies of an existing role. This completely replaces the previous policies and global flags.
```bash
# Add a new prefix to the role and grant global create permissions
tsm role update my-prod-server --can-create --policy app.prod.* --policy system.global.*:GET
```

### `tsm role rm`
Permanently delete a role and instantly invalidate its token.
```bash
tsm role rm my-prod-server
```

### `tsm role export`
Export all role definitions (names and policies) to standard output or a JSON file.
```bash
tsm role export roles.json
```

### `tsm role import`
Bulk create or update roles from a JSON file. 
- If a role exists, it will be updated (replacing its policies). 
- If a role does not exist, it will be created and its new token will be printed.
```bash
tsm role import roles.json
```

---

## Backup Management

As an Administrator, you can configure the automated background backup daemon and trigger manual backups directly from the CLI.

### `tsm backup info`
View the current backup configuration, including the target path and retention policies.
```bash
tsm backup info
```

### `tsm backup config`
Update the automated backup configuration. The server runs a background loop that checks for changes at the specified interval and writes a database snapshot to the target path.

**Flags:**
- `--target <path>`: Local directory path or remote SSH target (e.g., `/var/lib/backups/` or `user@host:/backups/`).
- `--interval <mins>`: How often the daemon checks if a backup is needed (default `5`).
- `--keep-all <days>`: Keep every single backup file generated over the last N days (default `1`).
- `--keep-daily <days>`: For files older than `--keep-all`, retain exactly one backup per day for the next N days (default `30`). Backups older than `--keep-all` + `--keep-daily` are deleted.

```bash
# Configure local backups to a directory
tsm backup config --target /var/backups/tsm/ --interval 10 --keep-all 3 --keep-daily 60

# Configure remote SCP backups (Note: pruning logic only applies to local targets)
tsm backup config --target user@192.168.1.50:/home/user/backups/
```

### `tsm backup trigger`
Immediately force a synchronous database backup. This bypasses the interval check but safely locks the database to prevent overlaps.
```bash
tsm backup trigger
```

---

## Application Execution (Environment Injection)

The most powerful feature of the CLI is `tsm run`. This command evaluates your secrets configuration, dynamically retrieves the required secrets from the vault, sets them as environment variables, and executes your application.

### `tsm run`
```bash
tsm run -- [your_command_here]
```

#### Why not just inject everything the Role has access to?
You might wonder why `tsm run` requires you to specify the exact keys you want in a `tsm.env` file, rather than just fetching all secrets your Role can read. This is a deliberate security design choice:
- **Least Privilege at Runtime:** Even if a Role has access to 50 secrets (e.g., across an entire `prod.*` namespace), a specific microservice might only need 2 of them. Injecting all 50 secrets into the environment increases the risk of exposure if the app crashes (dumping its environment) or if a malicious dependency tries to scrape environment variables.
- **Explicit Dependencies:** Your `tsm.env` acts as a clear, version-controllable manifest of exactly what secrets the application needs to run.

#### How it resolves variables (Order of Precedence):
1. **TSM Mapping File (`tsm.env`)**: 
   - By default, the CLI looks for a `tsm.env` file in the current directory.
   - It supports *explicit mapping* (`DB_PASS=app.prod.db.pass`) where it fetches the secret and sets the `DB_PASS` env var.
   - It also supports *implicit mapping* (just `app.prod.db.pass` on a line). The CLI will fetch the secret, check if the vault has an `env_key` configured for it, and automatically inject it under that key.
2. **Standard `.env` File**: 
   - Looks for a standard `.env` file containing literal values (e.g. `PORT=8080`) and injects them. 
   - Values here override `tsm.env`.
3. **CLI Overrides (`-e`)**: 
   - You can pass inline overrides.
   - These have the highest priority and override everything else.

#### Example `tsm.env` File:
```env
# Explicit mapping: Set the 'DB_PASSWORD' env var using the value from 'app.prod.db.pass'
DB_PASSWORD=app.prod.db.pass

# Implicit mapping: Fetch 'app.prod.api_key', read its attached 'env_key' from the database, 
# and use that as the environment variable name
app.prod.api_key

# Another explicit mapping
STRIPE_SECRET=app.prod.stripe.secret
```

#### Example Usage:
```bash
# Run a Node app with default files (tsm.env and .env)
tsm run -- node server.js

# Specify a custom TSM mapping file
tsm run -f custom.tsm.env -- node server.js

# Specify a custom standard .env file
tsm run --env-file .env.production -- node server.js

# Override a variable manually
tsm run -e PORT=9000 -e DEBUG=true -- node server.js

# Temporarily override the active token
tsm run --token <temporary_token> -- node server.js
```
