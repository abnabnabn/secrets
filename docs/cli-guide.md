# Tiny Secrets Manager: CLI Guide

The `tsm` command-line interface provides everything you need to manage your secrets and seamlessly inject them into your applications. 

## Initial Setup & Authentication

Before you can interact with the server, you need to point the CLI to it and authenticate the current directory.

### `tsm login`
Set the target server URL. This configuration is stored globally for your user profile.
```bash
tsm login https://secrets.internal.example.com:8090
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

---

## Secret Management

These commands require you to be authenticated. The active token dictates which secrets you are permitted to read, write, or list based on your Role policies.

### `tsm ls` (or `tsm list`)
List all secret keys available to your current role. 
```bash
# List all secrets
tsm ls

# List secrets starting with a specific prefix
tsm ls app.prod
```

### `tsm get`
Fetch and print the decrypted payload of a specific secret.
```bash
tsm get app.prod.database.password
```

### `tsm put`
Create or update a secret.
```bash
tsm put app.prod.database.password "s3cr3t_p@ssw0rd"
```

### `tsm rm` (or `tsm delete`)
Permanently delete a secret from the vault.
```bash
tsm rm app.prod.database.password
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
