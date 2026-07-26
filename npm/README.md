# SikkerKey CLI

The official command-line interface for [SikkerKey](https://sikkerkey.com), secrets management with Ed25519 machine authentication.

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

Project access is determined by grants on the dashboard, resolved server-side on every read.

### 3. List what you have access to

```bash
sikkerkey list secrets       # all granted secrets, grouped by application/project
sikkerkey list projects      # all projects this machine is in
sikkerkey list applications  # applications grouping those projects
sikkerkey list vaults        # bootstrapped vaults on this machine
```

Each secret is listed with its kind, so `[certificate]`, `[leased]`, `[structured]`, `[managed]` and `[canary]` are distinguishable at a glance.

### 4. Get a certificate

```bash
sikkerkey certificate <secret-id>

# Ask for a shorter one than the credential's maximum
sikkerkey certificate <secret-id> --validity 15m
```

```
Loaded certificate for deploy, valid 1h0m
ssh deploy@prod-box.example.com
```

A keypair is generated on this machine for each request and only the public half is sent. The signed certificate is loaded into your ssh-agent with a lifetime matching its own validity, so `ssh <user>@<host>` works with no further arguments and the key is dropped when the certificate expires. Where no ssh-agent is reachable, the key and certificate are written to `~/.sikkerkey/certificates/` and the printed command names the key with `-i`.

### 5. Scope commands to an application (optional)

Projects can be grouped into applications (for example a service's Production / Staging / Dev set). Set an active application to scope subsequent commands to just its projects:

```bash
sikkerkey list applications              # applications you can access
sikkerkey set application <app-id>       # scope to one application
sikkerkey set application none           # back to global (all projects)
sikkerkey set application                # show the current scope
```

While an application is set, `list secrets`, `list projects`, `export`, and `run --all` show only that application's projects. The scope is stored locally per vault, and an explicit `--project` always overrides it.

### 6. Export secrets

```bash
sikkerkey export
sikkerkey export --format json
sikkerkey export --project production --format dotenv > .env
```

Exports all secrets the machine has access to (or, when an application scope is set, just that application's secrets). Supports `env`, `json`, `yaml`, and `dotenv` formats. `--project` accepts either a project name or id and overrides any application scope.

### 7. Inject secrets into a process

```bash
# Inject specific secrets
sikkerkey run --secret <id> --secret <id> -- node app.js

# Inject all secrets from a project
sikkerkey run --all --project production -- node app.js

# Auto-restart on secret changes
sikkerkey run --watch --all --project production -- node app.js
```

Specify which secrets to inject with `--secret` or `--all`. With `--all` and no `--project`, an active application scope limits injection to that application. The `--watch` flag polls for changes and restarts the process automatically when secrets are rotated.

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
| `certificate <id> [--validity <dur>]` | Get a certificate and load it for use |

### Operations

| Command | Description |
|---------|-------------|
| `list secrets\|projects\|applications\|vaults` | List resources (secrets group by application/project) |
| `export [--project <name>] [--format env\|json\|yaml\|dotenv]` | Export secrets in various formats (honors the active application scope) |
| `run --secret <id>\|--all [--project <name>] [--watch] -- <cmd>` | Inject secrets as env vars and run a command (`--all` honors the active application scope) |
| `cache` | Manage the on-disk fallback cache for offline reads |

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

Every command accepts `--help` for its full usage.

## Machine Authentication

SikkerKey authenticates machines with Ed25519 signatures. Every request is signed with the machine's private key, which stays on the machine that generated it.

After bootstrapping, the machine must be approved in the SikkerKey dashboard before it can access any secrets. Project membership and per-secret grants are managed in the dashboard, and the CLI reflects those grants live. The only local preference is the optional application scope set with `sikkerkey set application`, which filters what the listing and export commands show.

## Certificates

`sikkerkey certificate` asks SikkerKey to sign a public key this machine just generated. The private half is created in memory for that request and handed only to the local ssh-agent, so the signing service issues certificates rather than keys.

## Offline Cache

`sikkerkey cache` manages an opt-in encrypted fallback cache so reads keep working when the retrieval plane is unreachable. The cache format is shared with every SikkerKey SDK and each implementation is tested against the same golden vector, so a `.skc` file written by one client decrypts byte-identically in the others.

## Supported Platforms

| OS | Architecture |
|----|-------------|
| Linux | x64, arm64 |
| macOS | x64, arm64 (Apple Silicon) |
| Windows | x64 |

On Windows the ssh-agent is a named pipe, so `sikkerkey certificate` writes the key and certificate to `~/.sikkerkey/certificates/` there.

## Documentation

[sikkerkey.com/docs/tools/cli](https://sikkerkey.com/docs/tools/cli)

## License

MIT. Source: [github.com/SikkerKeyOfficial/sikkerkey-cli](https://github.com/SikkerKeyOfficial/sikkerkey-cli)
