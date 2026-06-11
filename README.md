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
* **Role-Based Access Control (RBAC):** Restrict application permissions down to individual keys or custom groups of keys using policy-driven Roles, ensuring clients and machines only see authorized secrets. Tokens can be configured with expiration dates, and CLI admin sessions automatically enforce an idle timeout. Roles can be granted `GET`, `PUT`, `LIST`, and `DELETE` permissions on specific prefixes. Additionally, roles can be granted a global `can_create` flag. With this global flag, roles can generate new secrets and will automatically receive `GET` and `PUT` access to the created keys.
* **Variable Substitution:** Secrets can dynamically reference other secrets using `${secret.key}` syntax. Variables are resolved securely at retrieval time, meaning clients will only receive the substituted value if they possess `GET` permission for the nested variables. Unauthorized or missing variables automatically resolve to an empty string. This also supports recursive resolution! For example, if `name.first` is `john`, `name.last` is `smith`, `name.full` is `${name.first}.${name.last}`, and `greeting` is `hello ${name.full}`, fetching `greeting` will recursively resolve all the way down to `hello john.smith` (provided the client's role has read permissions for all referenced keys).
* **Interactive Admin GUI & CLI:** A built-in React management interface for visual audits and permissions simulation, paired with a robust CLI supporting context-based token resolution.
* **Offline-Ready:** All front-end assets (React, Tailwind CSS) are bundled directly into the Go binary. No internet access is required to run or manage the server in air-gapped environments.
* **Pure Go SQLite:** Built with `modernc.org/sqlite`, ensuring zero-CGO portability and a simplified supply chain. Operates in WAL mode for high concurrency.
* **Automated Disaster Recovery:** 
    * Runs a dedicated background daemon that performs scheduled, non-blocking database backups using `VACUUM INTO`.
    * Supports automated pruning using a powerful `Keep All / Keep Daily` tier retention policy.
    * Supports both local filesystem targets and remote off-site backups via `scp`.
* **Ansible Lookup Plugin:** Integrates secrets retrieval directly into your IaC process for automated configuration management.
* **Hardened Containerization:** Pre-built multi-architecture (Linux x86 and ARM) Chainguard-based images optimized for containerized environments with a minimal attack surface.

## Documentation

We have comprehensive guides depending on what you are trying to do:

* **[Complete Setup & Migration Guide](docs/setup-guide.md)**
  Everything you need to know about spinning up the server, configuring environment variables, running via Docker, managing backups, and initial bootstrapping.
* **[CLI Guide](docs/cli-guide.md)**
  Full reference for the `tsm` command-line tool, including how to authenticate, manage roles, manually retrieve secrets, and use `tsm run` to automatically inject secrets into your applications.
* **[Ansible Plugin Setup Guide](docs/ansible-plugin.md)**
  Instructions for installing and using the built-in Ansible lookup plugin (`tsm.py`) to fetch secrets directly within your playbooks.

## Quick Start (Docker)

If you just want to take it for a quick spin using Docker Compose:

```bash
# Start the server using the default configuration
docker compose up -d

# Check the logs to retrieve your auto-generated admin credentials and Emergency Recovery Keys
docker compose logs
```

For custom configurations (like pre-seeding an admin password or configuring a backup volume), please refer to the **[Setup Guide](docs/setup-guide.md)**.
