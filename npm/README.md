# SikkerKey CLI

The official command-line interface for [SikkerKey](https://sikkerkey.com) — secrets management with Ed25519 machine authentication.

## Installation

```bash
npm install -g sikkerkey
```

Or run without installing:

```bash
npx sikkerkey
```

## Quick Start

### 1. Connect to your vault

```bash
sikkerkey connect <vault-id>
```

Selects which bootstrapped vault identity to use. If only one vault is registered on this machine, it auto-selects.

### 2. Read a secret

```bash
sikkerkey get <secret-id>

# Read a specific field from a structured secret
sikkerkey get <secret-id> password

# JSON output for scripting
sikkerkey get <secret-id> -o json
```

Project access is determined by grants on the dashboard. There is no client-side unlock step — the CLI fetches accessible secrets live from the server.

### 3. List what you have access to

```bash
sikkerkey list secrets       # all granted secrets, grouped by application/project
sikkerkey list projects      # all projects this machine is in
sikkerkey list applications  # applications grouping those projects
sikkerkey list vaults        # bootstrapped vaults on this laptop
```

### 4. Scope commands to an application (optional)

Projects can be grouped into applications (for example a service's Production / Staging / Dev set). Set an active application to scope subsequent commands to just its projects:

```bash
sikkerkey list applications              # applications you can access
sikkerkey set application <app-id>       # scope to one application
sikkerkey set application none           # back to global (all projects)
sikkerkey set application                # show the current scope
```

While an application is set, `list secrets`, `list projects`, `export`, and `run --all` show only that application's projects. The scope is stored locally per vault, and an explicit `--project` always overrides it. Leaving it unset behaves exactly as before.

### 5. Export secrets

```bash
sikkerkey export
sikkerkey export --format json
sikkerkey export --project production --format dotenv > .env
```

Exports all secrets the machine has access to (or, when an application scope is set, just that application's secrets). Supports `env`, `json`, `yaml`, and `dotenv` formats. `--project` accepts either a project name or id and overrides any application scope.

### 6. Inject secrets into a process

```bash
# Inject specific secrets
sikkerkey run --secret <id> --secret <id> -- node app.js

# Inject all secrets from a project
sikkerkey run --all --project production -- node app.js

# Auto-restart on secret changes
sikkerkey run --watch --all --project production -- node app.js
```

You must specify which secrets to inject with `--secret` or `--all`. With `--all` and no `--project`, an active application scope (if set) limits injection to that application. The `--watch` flag polls for changes and restarts the process automatically when secrets are rotated.

## Commands

### Setup

| Command | Description |
|---------|-------------|
| `connect <vault-id>` | Select a vault identity |
| `set application <id>\|none` | Scope commands to an application (or back to global) |

### Config

| Command | Description |
|---------|-------------|
| `rename vault <old> <new>` | Rename the local alias for a vault |
| `delete vault <name>` | Remove a bootstrapped vault from this machine |

### Secrets

| Command | Description |
|---------|-------------|
| `get <id> [field] [-o json]` | Read a secret value or field |

### Operations

| Command | Description |
|---------|-------------|
| `list secrets\|projects\|applications\|vaults` | List resources (secrets group by application/project) |
| `export [--project <name>] [--format env\|json\|yaml\|dotenv]` | Export secrets in various formats (honors the active application scope) |
| `run --secret <id>\|--all [--project <name>] [--watch] -- <cmd>` | Inject secrets as env vars and run a command (`--all` honors the active application scope) |

### Sync Agent

| Command | Description |
|---------|-------------|
| `agent start --secret <id>` | Run a sync agent in the foreground |
| `agent configure --secret <id> ...` | Configure database connection for a secret |
| `agent install --secret <id>` | Install as a system service |
| `agent list` | Show running agents |
| `agent stop --secret <id>` | Stop an agent |
| `agent remove --secret <id>` | Remove agent config |
| `agent test --secret <id>` | Test database connection |

### Info

| Command | Description |
|---------|-------------|
| `whoami` | Print machine identity and the active application scope |
| `status` | Check connectivity and authentication |
| `completion bash\|zsh\|fish` | Generate shell completions |
| `version` | Print version |

## Machine Authentication

SikkerKey uses Ed25519 signatures for machine authentication — no API keys, no tokens, no sessions. Every request is signed with the machine's private key, which never leaves the machine.

After bootstrapping, the machine must be approved in the SikkerKey dashboard before it can access any secrets. Project membership and per-secret grants are also managed in the dashboard; the CLI reflects those grants live and does not cache project state locally. The only local preference is the optional application scope set with `sikkerkey set application`, which just filters what the listing and export commands show.

## Supported Platforms

| OS | Architecture |
|----|-------------|
| Linux | x64, arm64 |
| macOS | x64, arm64 (Apple Silicon) |
| Windows | x64 |

## Documentation

Full documentation: [docs.sikkerkey.com](https://docs.sikkerkey.com)

- [CLI Overview](https://docs.sikkerkey.com/docs/cli/overview)
- [Setup Commands](https://docs.sikkerkey.com/docs/cli/setup)
- [Secret Commands](https://docs.sikkerkey.com/docs/cli/secrets)
- [Operations](https://docs.sikkerkey.com/docs/cli/operations)
- [Sync Agent Commands](https://docs.sikkerkey.com/docs/cli/agent)

## License

MIT. Source: [github.com/SikkerKeyOfficial/sikkerkey-cli](https://github.com/SikkerKeyOfficial/sikkerkey-cli)
