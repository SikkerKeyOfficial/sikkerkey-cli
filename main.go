package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/SikkerKeyOfficial/sikkerkey-cli/internal/agent"
	_ "github.com/SikkerKeyOfficial/sikkerkey-cli/internal/agent/providers"
	"github.com/SikkerKeyOfficial/sikkerkey-cli/internal/auth"
	"github.com/SikkerKeyOfficial/sikkerkey-cli/internal/cache"
	"github.com/SikkerKeyOfficial/sikkerkey-cli/internal/client"
	"github.com/SikkerKeyOfficial/sikkerkey-cli/internal/config"
	"github.com/SikkerKeyOfficial/sikkerkey-cli/internal/sshcert"
	"github.com/SikkerKeyOfficial/sikkerkey-cli/internal/x509cert"
)

// version is set at build time via `-ldflags="-X main.version=<vX.Y.Z>"`.
// "dev" is the default for unbuilt or local-development binaries.
var version = "dev"

// resolveVersion reports the version to print. Release binaries published to npm
// are cross-compiled with the -ldflags stamp above. Binaries produced by
// `go install github.com/SikkerKeyOfficial/sikkerkey-cli@latest` carry no
// ldflags, so fall back to the module version the Go toolchain records in the
// build info; without this those installs would all report "dev".
func resolveVersion() string {
	if version != "dev" {
		return version
	}
	info, ok := debug.ReadBuildInfo()
	if !ok || info.Main.Version == "" || info.Main.Version == "(devel)" {
		return version
	}
	// Module versions carry a leading "v" that the ldflags stamp does not, so
	// trim it and both install paths report the same string.
	return strings.TrimPrefix(info.Main.Version, "v")
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	// Check for <command> --help
	cmd := os.Args[1]
	for _, a := range os.Args[2:] {
		if a == "--help" || a == "-h" {
			if _, ok := commandHelp[cmd]; ok {
				printCommandHelp(cmd)
				return
			}
		}
	}

	switch cmd {
	case "connect":
		cmdConnect(os.Args[2:])
	case "set":
		cmdSet(os.Args[2:])
	case "rename":
		cmdRename(os.Args[2:])
	case "get":
		cmdGet(os.Args[2:])
	case "certificate":
		cmdCertificate(os.Args[2:])
	case "list":
		cmdList(os.Args[2:])
	case "run":
		cmdRun(os.Args[2:]) // run parses --project itself before --
	case "export":
		cmdExport(os.Args[2:])
	case "cache":
		cmdCache(os.Args[2:])
	case "completion":
		cmdCompletion(os.Args[2:])
	case "delete":
		cmdDelete(os.Args[2:])
	case "agent":
		cmdAgent(os.Args[2:])
	case "whoami":
		cmdWhoami()
	case "status":
		cmdStatus()
	case "version":
		fmt.Println("sikkerkey " + resolveVersion())
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`sikkerkey - SikkerKey secrets CLI

Usage:
  sikkerkey <command> [arguments]

Setup:
  connect        Select a vault identity
  set            Scope commands to an application (set application <id|none>)

Config:
  rename         Rename a vault alias
  delete         Remove a vault

Secrets:
  get            Fetch a secret value or field
  certificate    Get a certificate and load it for use

Operations:
  export         Export secrets in env, json, yaml, or dotenv format
  run            Inject secrets as env vars and run a command
  list           List secrets, vaults, projects, or applications
  cache          Manage the on-disk fallback cache (offline reads)

Agent:
  agent          Manage sync agents for database credential rotation

Info:
  whoami         Print machine identity info
  status         Check connectivity and authentication
  completion     Print shell completion script
  version        Print version

Run 'sikkerkey <command> --help' for details on a specific command.`)
}

var commandHelp = map[string]string{
	"connect": `Usage:
  sikkerkey connect <vault_id>               select a vault identity
  sikkerkey connect <vault_id> --alias myvault   select and alias it
  sikkerkey connect                           show current vault
  sikkerkey connect --list                    list all bootstrapped vaults
  sikkerkey connect --clear                   clear default vault

Selects which bootstrapped vault identity to use for subsequent commands.
Accepts vault IDs or aliases. Project access is determined by grants on
the dashboard; no local unlock step is required.`,

	"rename": `Usage:
  sikkerkey rename vault <vault_id_or_alias> <new_name>

Renames the local alias for a vault. This is a local-only change — it
does not affect anything on the server. Project names are canonical
on the server side and cannot be aliased locally.`,

	"cache": `Usage:
  sikkerkey cache enable         turn on the on-disk fallback cache
  sikkerkey cache disable        turn it off (cached files are kept until cleared)
  sikkerkey cache status         show whether it's on and how many secrets are cached
  sikkerkey cache clear          delete all cached secrets for the current vault

The fallback cache lets reads keep working when machines.sikkerkey.com is
unreachable. While enabled, every secret you read is written to an encrypted
per-secret file under ~/.sikkerkey/vaults/<vault>/cache/, and served from there
only when the server can't be reached (a network failure, or a gateway/origin
error like 502/504 or a Cloudflare 52x). An authoritative answer — access
denied, deleted, bad auth — is never served from the cache.

Each entry is AES-256-GCM encrypted under a key derived from this machine's
identity, so a cached file is useless if copied off the machine without the
private key.

Force a cache read — to verify it works, or when you know you're offline — by
adding --offline to get, run, or export:
  sikkerkey get <secret_id> --offline
  sikkerkey run --all --offline -- ./app
  sikkerkey export --offline

Off by default. When disabled, reads never touch the cache.`,

	"certificate": `Usage:
  sikkerkey certificate <secret_id>
  sikkerkey certificate <secret_id> --validity 15m

Requests a certificate from a certificate secret. A keypair is generated on
this machine for each request and only the public half is sent, so the
private key never leaves the machine. The type is detected automatically.

SSH certificates load into your ssh-agent and print the connection to use:

  $ sikkerkey certificate sk_a1b2c3d4
  Loaded certificate for deploy, valid 1h0m
  ssh deploy@prod-box.example.com

With no ssh-agent running, the key and certificate are written to
~/.sikkerkey/certificates/ and the ssh command names the key with -i.

X.509 certificates are written to ~/.sikkerkey/certificates/ as the leaf,
its key, and the issuing CA chain, for a TLS client to load:

  $ sikkerkey certificate sk_9f8e7d6c
  Issued certificate for svc-payments, valid 1h0m
    cert:  ~/.sikkerkey/certificates/sikkerkey-sk_9f8e7d6c.crt
    key:   ~/.sikkerkey/certificates/sikkerkey-sk_9f8e7d6c.key
    chain: ~/.sikkerkey/certificates/sikkerkey-sk_9f8e7d6c.chain.pem

Options:
      --validity <dur>    request a shorter certificate, e.g. 15m or 2h
                          (the credential's configured maximum is the cap)

Exit code 0 on success, 1 on error.`,

	"get": `Usage:
  sikkerkey get <secret_id>
  sikkerkey get <secret_id> <field>
  sikkerkey get <secret_id> -o json

Prints the secret value to stdout. Without a field name, prints the
raw value (or full JSON for structured secrets). With a field name,
extracts and prints that single field.

Options:
  -o, --output <format>   plain (default) or json
                          json wraps the output with id, value, and
                          parsed fields (if structured)
      --offline           read from the local cache without the network
                          (see 'sikkerkey cache')

Exit code 0 on success, 1 on error.`,

	"run": `Usage:
  sikkerkey run --secret <id> -- <command> [args...]
  sikkerkey run --secret <id> --secret <id> -- <command> [args...]
  sikkerkey run --all -- <command> [args...]
  sikkerkey run --all --project production -- <command> [args...]
  sikkerkey run --all --dry-run

Injects secrets as environment variables and runs a command. You must
specify which secrets to inject: either --secret for specific secrets,
or --all for everything the machine has access to. If an application scope
is set (sikkerkey set application), --all is limited to that application
unless --project is given.

Variable names come from the secret name with --all (uppercased,
non-alphanumeric chars replaced by underscores; structured secrets
expand to SECRETNAME_FIELDNAME). With --secret, names come from the
secret ID instead (SK_<ID>_FIELDNAME), so explicitly-picked secrets
can't collide even when they share a name.

The child process inherits the current environment plus the secrets.
Signals (SIGINT, SIGTERM) are forwarded to the child.

Required (one of):
  --secret <id>      inject a specific secret (repeatable)
  --all              inject all accessible secrets

Options:
  --project <name>   scope --all to a specific project
  --prefix <str>     prefix all env var names
  --watch            poll for changes and restart the process automatically
  --dry-run          show what env vars would be injected, don't run anything
  --show-values      show real values in dry-run (default: masked with ****)
  --offline          inject from the local cache without the network
                     (see 'sikkerkey cache'; can't be combined with --watch)`,

	"set": `Usage:
  sikkerkey set application <id>     scope list output to an application
  sikkerkey set application none     return to global (all projects)
  sikkerkey set application          show the current application scope

Scopes 'list secrets', 'list projects', 'export', and 'run --all' to a single
application. The scope is stored locally per vault; leaving it unset (or
'none') behaves globally, exactly as before. An explicit --project overrides it.`,

	"list": `Usage:
  sikkerkey list secrets
  sikkerkey list vaults
  sikkerkey list projects
  sikkerkey list applications

List secrets, vaults, projects, or applications.

  secrets        all secrets this machine can access, grouped by project
  vaults         bootstrapped vaults on this machine (* = default)
  projects       projects this machine has been granted access to
  applications   applications grouping those projects (* = current scope)

When an application scope is set ('sikkerkey set application <id>'), 'list
secrets' and 'list projects' show only that application's projects.`,

	"export": `Usage:
  sikkerkey export
  sikkerkey export --format json
  sikkerkey export --format dotenv > .env
  sikkerkey export --project production --format yaml

Exports secrets the machine has access to. Without --project, exports
all secrets across all granted projects — or, when an application scope is
set (sikkerkey set application), just that application's secrets. With
--project, exports only that project's secrets (name or id), overriding any
application scope. Structured secrets expand to one entry per field
(SECRETNAME_FIELDNAME).

Options:
  --format <type>    env, json, yaml, dotenv (default: env)
  --project <name>   export only this project's secrets (name or id)
  --offline          export from the local cache without the network
                     (see 'sikkerkey cache'; ignores --project)`,

	"completion": `Usage:
  sikkerkey completion bash
  sikkerkey completion zsh
  sikkerkey completion fish

Prints a shell completion script to stdout. Add to your shell profile:

  bash:  sikkerkey completion bash >> ~/.bashrc
  zsh:   sikkerkey completion zsh >> ~/.zshrc
  fish:  sikkerkey completion fish > ~/.config/fish/completions/sikkerkey.fish`,

	"delete": `Usage:
  sikkerkey delete vault <vault_id_or_alias>

Removes the vault's directory on this machine, including the identity
files and private key. Accepts a vault id or alias. The machine row
on the server is not affected — revoke from the dashboard separately.`,

	"whoami": `Usage:
  sikkerkey whoami

Prints the machine identity: machine ID, name, vault, API URL, and
private key path.`,

	"status": `Usage:
  sikkerkey status

Verifies the private key is readable, authenticates against the API,
and reports how many secrets are accessible. Exit code 0 if healthy,
1 if any check fails.`,

	"agent": `Usage:
  sikkerkey agent start --secret <secret_id>
  sikkerkey agent configure --secret <secret_id> --provider postgresql --host localhost --port 5432 --admin-user postgres --admin-pass s3cret
  sikkerkey agent install --secret <secret_id>
  sikkerkey agent install --secret <secret_id> --now
  sikkerkey agent list
  sikkerkey agent stop --secret <secret_id>
  sikkerkey agent remove --secret <secret_id>
  sikkerkey agent test --secret <secret_id>

Manages sync agents that watch for secret rotations and apply new
credentials to external systems (databases, caches).

Subcommands:
  start       run a sync agent in the foreground (blocks until interrupted)
  configure   set up the database connection for a secret
  install     generate and install a system service (systemd/launchd/Windows)
  list        show running agents
  stop        stop a running agent
  remove      remove agent config for a secret
  test        test the database connection

Options (configure):
  --secret <id>         secret to sync (required)
  --provider <type>     database type: postgresql, mysql, mongodb, redis, mssql
  --host <host>         database host
  --port <port>         database port
  --database <name>     database name (if applicable)
  --admin-user <user>   admin username for credential management
  --admin-pass <pass>   admin password
  --username-field <f>  secret field containing the target username (default: "username")
  --password-field <f>  secret field containing the password to sync (default: "password")
  --poll-interval <s>   seconds between checks (default: 10)`,
}

func printCommandHelp(cmd string) {
	help, ok := commandHelp[cmd]
	if !ok {
		fmt.Fprintf(os.Stderr, "no help for '%s'\n", cmd)
		os.Exit(1)
	}
	fmt.Println(help)
}

// sikkerkey connect [<vault_id>] [--alias <name>] [--list] [--clear]
func cmdConnect(args []string) {
	gc := config.LoadGlobalConfig()

	if len(args) == 0 {
		// Show current
		if gc.DefaultVault == "" {
			fmt.Println("no vault connected")
			fmt.Println("run: sikkerkey connect <vault_id>")
		} else {
			alias := ""
			for a, id := range gc.VaultAliases {
				if id == gc.DefaultVault {
					alias = a
					break
				}
			}
			if alias != "" {
				fmt.Printf("connected: %s (%s)\n", gc.DefaultVault, alias)
			} else {
				fmt.Printf("connected: %s\n", gc.DefaultVault)
			}
		}
		return
	}

	if args[0] == "--list" {
		vaults := config.ListVaults()
		if len(vaults) == 0 {
			fmt.Println("no vaults found")
			return
		}
		aliasFor := make(map[string]string)
		for alias, id := range gc.VaultAliases {
			aliasFor[id] = alias
		}
		for _, v := range vaults {
			marker := "  "
			if v == gc.DefaultVault {
				marker = "* "
			}
			if alias, ok := aliasFor[v]; ok {
				fmt.Printf("%s%s (%s)\n", marker, v, alias)
			} else {
				fmt.Printf("%s%s\n", marker, v)
			}
		}
		return
	}

	if args[0] == "--clear" {
		gc.DefaultVault = ""
		if err := config.SaveGlobalConfig(gc); err != nil {
			fmt.Fprintf(os.Stderr, "error: %s\n", err)
			os.Exit(1)
		}
		fmt.Println("disconnected")
		return
	}

	// Connect to a vault
	input := args[0]
	vaultID := gc.ResolveVault(input)

	// Verify it exists
	dir := config.VaultDir(vaultID)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "error: vault '%s' not found\n", input)
		os.Exit(1)
	}

	// Verify identity and key exist
	if _, err := config.LoadIdentity(vaultID); err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\nBootstrap this machine first.\n", err)
		os.Exit(1)
	}
	keyPath := config.PrivateKeyPath(vaultID)
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "error: private key not found: %s\n", keyPath)
		os.Exit(1)
	}

	gc.DefaultVault = vaultID

	// Parse optional --alias
	alias := ""
	for i := 1; i < len(args); i++ {
		if args[i] == "--alias" && i+1 < len(args) {
			i++
			alias = args[i]
		}
	}
	if alias != "" {
		gc.SetAlias(alias, vaultID)
	}

	if err := config.SaveGlobalConfig(gc); err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(1)
	}

	if alias != "" {
		fmt.Printf("connected: %s (alias: %s)\n", vaultID, alias)
	} else {
		fmt.Printf("connected: %s\n", vaultID)
	}
}

func cmdRename(args []string) {
	if len(args) < 3 {
		printCommandHelp("rename")
		os.Exit(1)
	}

	kind := args[0]   // "vault" only — project rename has no local effect now that
	target := args[1] // canonical project names live on the server.
	newName := args[2]

	switch kind {
	case "vault":
		gc := config.LoadGlobalConfig()
		vaultID := gc.ResolveVault(target)
		if gc.VaultAliases != nil {
			for a, id := range gc.VaultAliases {
				if id == vaultID {
					delete(gc.VaultAliases, a)
				}
			}
		}
		gc.SetAlias(newName, vaultID)
		if err := config.SaveGlobalConfig(gc); err != nil {
			fmt.Fprintf(os.Stderr, "error: %s\n", err)
			os.Exit(1)
		}
		fmt.Printf("renamed vault %s → %s\n", vaultID, newName)

	default:
		fmt.Fprintf(os.Stderr, "error: unknown type '%s'. Use 'vault'.\n", kind)
		printCommandHelp("rename")
		os.Exit(1)
	}
}

// sikkerkey get <secret_id> [field] [-o format]
// cmdCertificate requests a certificate and puts it where ssh will find it.
//
// The keypair is generated per request and its private half never leaves this
// process except into the local ssh-agent, so SikkerKey signs a public key it is
// handed rather than issuing anyone a private key.
func cmdCertificate(args []string) {
	usage := "usage: sikkerkey certificate <secret_id> [--validity <duration>]"

	var secretID string
	var validitySeconds int64
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--validity" && i+1 < len(args):
			i++
			d, err := time.ParseDuration(args[i])
			if err != nil || d <= 0 {
				fmt.Fprintf(os.Stderr, "error: invalid duration '%s'. Use e.g. 15m or 2h\n", args[i])
				os.Exit(1)
			}
			validitySeconds = int64(d.Seconds())
		case strings.HasPrefix(args[i], "-"):
			fmt.Fprintf(os.Stderr, "error: unknown option '%s'\n%s\n", args[i], usage)
			os.Exit(1)
		case secretID == "":
			secretID = args[i]
		default:
			fmt.Fprintln(os.Stderr, usage)
			os.Exit(1)
		}
	}
	if secretID == "" {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(1)
	}

	profile := loadProfileFromIdentity()
	c := newClient(profile)

	// Generate a subject key for each certificate type up front and send both; the
	// server signs the one its authority calls for and names the type in the
	// response. This avoids a describe round trip and any query string, which a
	// signed route rejects.
	sshSubject, err := sshcert.NewSubject()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(1)
	}
	x509Subject, err := x509cert.NewSubject()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(1)
	}

	cert, err := c.GetCertificate(secretID, sshSubject.PublicKeyLine, x509Subject.PublicKey, validitySeconds)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(1)
	}

	switch cert.CertificateType {
	case "ssh":
		installSSHCertificate(sshSubject, cert, secretID)
	case "x509":
		installX509Certificate(x509Subject, cert, secretID)
	default:
		// Certificates are unrecallable once signed, so a type this build cannot
		// install must not be written somewhere and called done.
		fmt.Fprintf(os.Stderr, "error: this SikkerKey CLI cannot install '%s' certificates. Update the CLI.\n", cert.CertificateType)
		os.Exit(1)
	}
}

// installSSHCertificate loads a signed SSH certificate into the agent and prints
// the ssh command to use.
func installSSHCertificate(subject *sshcert.Subject, cert *client.CertificateResponse, secretID string) {
	installed, err := sshcert.Install(subject, cert.Certificate, "sikkerkey-"+secretID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(1)
	}

	username := cert.Fields["username"]
	host := cert.Fields["host"]
	remaining := time.Duration(cert.ValidBefore-time.Now().Unix()) * time.Second

	fmt.Printf("Loaded certificate for %s, valid %s\n", username, fmtRemaining(remaining))
	target := username + "@" + host
	if host == "" {
		target = username + "@<host>"
	}
	if installed.InAgent {
		fmt.Printf("ssh %s\n", target)
	} else {
		fmt.Printf("ssh -i %s %s\n", installed.KeyPath, target)
	}
}

// installX509Certificate writes a signed X.509 certificate, its key, and the
// issuing CA chain where a TLS client can load them.
func installX509Certificate(subject *x509cert.Subject, cert *client.CertificateResponse, secretID string) {
	installed, err := x509cert.Install(subject, cert.Certificate, cert.Fields["chain"], "sikkerkey-"+secretID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(1)
	}

	name := cert.Fields["commonName"]
	if name == "" {
		name = secretID
	}
	remaining := time.Duration(cert.ValidBefore-time.Now().Unix()) * time.Second

	fmt.Printf("Issued certificate for %s, valid %s\n", name, fmtRemaining(remaining))
	fmt.Printf("  cert:  %s\n", installed.CertPath)
	fmt.Printf("  key:   %s\n", installed.KeyPath)
	if installed.ChainPath != "" {
		fmt.Printf("  chain: %s\n", installed.ChainPath)
	}
}

// fmtRemaining renders a validity the way a person reads it, e.g. "1h0m".
func fmtRemaining(d time.Duration) string {
	if d <= 0 {
		return "0m"
	}
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	if h > 0 {
		return fmt.Sprintf("%dh%dm", h, m)
	}
	return fmt.Sprintf("%dm", m)
}

func cmdGet(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: sikkerkey get <secret_id> [field] [-o json|plain]")
		os.Exit(1)
	}

	outputFormat := "plain"
	offline := false
	var positional []string
	for i := 0; i < len(args); i++ {
		if (args[i] == "-o" || args[i] == "--output") && i+1 < len(args) {
			i++
			outputFormat = args[i]
		} else if args[i] == "--offline" {
			offline = true
		} else {
			positional = append(positional, args[i])
		}
	}

	if len(positional) < 1 {
		fmt.Fprintln(os.Stderr, "usage: sikkerkey get <secret_id> [field] [-o json|plain]")
		os.Exit(1)
	}

	secretID := positional[0]
	fieldName := ""
	if len(positional) >= 2 {
		fieldName = positional[1]
	}

	if outputFormat != "plain" && outputFormat != "json" {
		fmt.Fprintf(os.Stderr, "error: unknown output format '%s'. Use: plain, json\n", outputFormat)
		os.Exit(1)
	}

	profile := loadProfileFromIdentity()
	cacheOn := config.LoadGlobalConfig().CacheEnabled
	c, ch := newClientWithCache(profile, cacheOn || offline)
	value, _ := fetchSecretCached(c, ch, secretID, cacheOn, offline)

	// Try to parse as structured secret
	var fields map[string]string
	isStructured := json.Unmarshal([]byte(value), &fields) == nil && len(fields) > 0

	if fieldName != "" {
		if !isStructured {
			fmt.Fprintln(os.Stderr, "error: secret is not a structured JSON object")
			os.Exit(1)
		}
		fieldValue, ok := fields[fieldName]
		if !ok {
			fmt.Fprintf(os.Stderr, "error: field '%s' not found\n", fieldName)
			os.Exit(1)
		}
		if outputFormat == "json" {
			out := map[string]interface{}{"id": secretID, "field": fieldName, "value": fieldValue}
			data, _ := json.MarshalIndent(out, "", "  ")
			fmt.Println(string(data))
		} else {
			fmt.Println(fieldValue)
		}
		return
	}

	if outputFormat == "json" {
		out := map[string]interface{}{"id": secretID, "value": value}
		if isStructured {
			out["fields"] = fields
		}
		data, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(data))
	} else {
		fmt.Println(value)
	}
}

// sikkerkey run [--prefix PREFIX] -- <command> [args...]
func cmdAgent(args []string) {
	if len(args) < 1 {
		printCommandHelp("agent")
		os.Exit(1)
	}

	sub := args[0]
	remaining := args[1:]

	switch sub {
	case "start":
		var secretID string
		for i := 0; i < len(remaining); i++ {
			if remaining[i] == "--secret" && i+1 < len(remaining) {
				i++
				secretID = remaining[i]
			}
		}
		if secretID == "" {
			fmt.Fprintln(os.Stderr, "error: --secret is required")
			os.Exit(1)
		}

		profile := loadProfileFromIdentity()
		c := newClient(profile)

		// Try local config first (manually configured), fall back to server config (synchronized secret)
		cfg, err := agent.LoadConfig(secretID)
		if err != nil {
			// No local config — try fetching from SikkerKey
			if err := agent.RunFromServer(c, secretID); err != nil {
				fmt.Fprintf(os.Stderr, "error: %s\n", err)
				os.Exit(1)
			}
			return
		}

		if err := agent.Run(c, *cfg); err != nil {
			fmt.Fprintf(os.Stderr, "error: %s\n", err)
			os.Exit(1)
		}

	case "configure":
		var secretID, providerType, host, database, adminUser, adminPass, usernameField, passwordField string
		port := 0
		pollInterval := 10

		for i := 0; i < len(remaining); i++ {
			switch remaining[i] {
			case "--secret":
				if i+1 >= len(remaining) {
					fmt.Fprintln(os.Stderr, "error: --secret requires a value")
					os.Exit(1)
				}
				i++
				secretID = remaining[i]
			case "--provider":
				if i+1 >= len(remaining) {
					fmt.Fprintln(os.Stderr, "error: --provider requires a value")
					os.Exit(1)
				}
				i++
				providerType = remaining[i]
			case "--host":
				if i+1 >= len(remaining) {
					fmt.Fprintln(os.Stderr, "error: --host requires a value")
					os.Exit(1)
				}
				i++
				host = remaining[i]
			case "--port":
				if i+1 >= len(remaining) {
					fmt.Fprintln(os.Stderr, "error: --port requires a value")
					os.Exit(1)
				}
				i++
				p, err := strconv.Atoi(remaining[i])
				if err != nil {
					fmt.Fprintln(os.Stderr, "error: --port must be a number")
					os.Exit(1)
				}
				port = p
			case "--database":
				if i+1 >= len(remaining) {
					fmt.Fprintln(os.Stderr, "error: --database requires a value")
					os.Exit(1)
				}
				i++
				database = remaining[i]
			case "--admin-user":
				if i+1 >= len(remaining) {
					fmt.Fprintln(os.Stderr, "error: --admin-user requires a value")
					os.Exit(1)
				}
				i++
				adminUser = remaining[i]
			case "--admin-pass":
				if i+1 >= len(remaining) {
					fmt.Fprintln(os.Stderr, "error: --admin-pass requires a value")
					os.Exit(1)
				}
				i++
				adminPass = remaining[i]
			case "--username-field":
				if i+1 >= len(remaining) {
					fmt.Fprintln(os.Stderr, "error: --username-field requires a value")
					os.Exit(1)
				}
				i++
				usernameField = remaining[i]
			case "--password-field":
				if i+1 >= len(remaining) {
					fmt.Fprintln(os.Stderr, "error: --password-field requires a value")
					os.Exit(1)
				}
				i++
				passwordField = remaining[i]
			case "--poll-interval":
				if i+1 >= len(remaining) {
					fmt.Fprintln(os.Stderr, "error: --poll-interval requires a value")
					os.Exit(1)
				}
				i++
				p, err := strconv.Atoi(remaining[i])
				if err != nil {
					fmt.Fprintln(os.Stderr, "error: --poll-interval must be a number")
					os.Exit(1)
				}
				pollInterval = p
			}
		}

		if secretID == "" || providerType == "" || host == "" || adminUser == "" || adminPass == "" {
			fmt.Fprintln(os.Stderr, "error: --secret, --provider, --host, --admin-user, and --admin-pass are required")
			os.Exit(1)
		}

		// Validate provider exists
		if _, err := agent.GetProvider(providerType); err != nil {
			fmt.Fprintf(os.Stderr, "error: %s\n", err)
			os.Exit(1)
		}

		// Set default port if not specified
		if port == 0 {
			switch providerType {
			case "postgresql":
				port = 5432
			case "mysql":
				port = 3306
			case "mongodb":
				port = 27017
			case "redis":
				port = 6379
			case "mssql":
				port = 1433
			default:
				fmt.Fprintln(os.Stderr, "error: --port is required for this provider")
				os.Exit(1)
			}
		}

		cfg := agent.AgentConfig{
			SecretID:     secretID,
			ProviderType: providerType,
			PollInterval: pollInterval,
			Connection: agent.Config{
				Host:          host,
				Port:          port,
				Database:      database,
				AdminUser:     adminUser,
				AdminPass:     adminPass,
				UsernameField: usernameField,
				PasswordField: passwordField,
			},
		}

		if err := agent.SaveConfig(cfg); err != nil {
			fmt.Fprintf(os.Stderr, "error: %s\n", err)
			os.Exit(1)
		}

		fmt.Printf("Agent configured for %s via %s (%s:%d)\n", secretID, providerType, host, port)
		fmt.Printf("Run: sikkerkey agent start --secret %s\n", secretID)

	case "install":
		var secretID string
		installNow := false
		for i := 0; i < len(remaining); i++ {
			switch remaining[i] {
			case "--secret":
				if i+1 >= len(remaining) {
					fmt.Fprintln(os.Stderr, "error: --secret requires a value")
					os.Exit(1)
				}
				i++
				secretID = remaining[i]
			case "--now":
				installNow = true
			}
		}
		if secretID == "" {
			fmt.Fprintln(os.Stderr, "error: --secret is required")
			os.Exit(1)
		}

		// Config can be local (agent configure) or server-side (synchronized secret) — both are valid

		if err := agent.GenerateServiceConfig(secretID, installNow); err != nil {
			fmt.Fprintf(os.Stderr, "error: %s\n", err)
			os.Exit(1)
		}

	case "list":
		agents := agent.ListRunning()
		if len(agents) == 0 {
			fmt.Println("No agents running.")
			return
		}
		fmt.Printf("%-20s %-14s %-8s %-6s %s\n", "SECRET", "PROVIDER", "STATUS", "PID", "HOST")
		for _, a := range agents {
			status := "stopped"
			if a.Running {
				status = "running"
			}
			fmt.Printf("%-20s %-14s %-8s %-6d %s\n", a.SecretID, a.ProviderType, status, a.PID, a.Host)
		}

	case "stop":
		var secretID string
		for i := 0; i < len(remaining); i++ {
			if remaining[i] == "--secret" && i+1 < len(remaining) {
				i++
				secretID = remaining[i]
			}
		}
		if secretID == "" {
			fmt.Fprintln(os.Stderr, "error: --secret is required")
			os.Exit(1)
		}
		if err := agent.StopAgent(secretID); err != nil {
			fmt.Fprintf(os.Stderr, "error: %s\n", err)
			os.Exit(1)
		}

	case "remove":
		var secretID string
		for i := 0; i < len(remaining); i++ {
			if remaining[i] == "--secret" && i+1 < len(remaining) {
				i++
				secretID = remaining[i]
			}
		}
		if secretID == "" {
			fmt.Fprintln(os.Stderr, "error: --secret is required")
			os.Exit(1)
		}
		agent.RemoveConfig(secretID)
		fmt.Printf("Agent config removed for %s\n", secretID)

	case "test":
		var secretID string
		for i := 0; i < len(remaining); i++ {
			if remaining[i] == "--secret" && i+1 < len(remaining) {
				i++
				secretID = remaining[i]
			}
		}
		if secretID == "" {
			fmt.Fprintln(os.Stderr, "error: --secret is required")
			os.Exit(1)
		}

		cfg, err := agent.LoadConfig(secretID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %s\n", err)
			os.Exit(1)
		}

		provider, err := agent.GetProvider(cfg.ProviderType)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %s\n", err)
			os.Exit(1)
		}

		fmt.Printf("Testing %s connection to %s:%d...\n", provider.DisplayName(), cfg.Connection.Host, cfg.Connection.Port)
		if err := provider.TestConnection(cfg.Connection); err != nil {
			fmt.Fprintf(os.Stderr, "FAILED: %s\n", err)
			os.Exit(1)
		}
		fmt.Println("OK — connection successful.")

	default:
		fmt.Fprintf(os.Stderr, "unknown agent subcommand: %s\n", sub)
		printCommandHelp("agent")
		os.Exit(1)
	}
}

func cmdRun(args []string) {
	prefix := ""
	dryRun := false
	showValues := false
	allSecrets := false
	watch := false
	offline := false
	var secretIDs []string
	cmdStart := -1

	// Parse flags before --
	for i := 0; i < len(args); i++ {
		if args[i] == "--" {
			cmdStart = i + 1
			break
		}
		switch args[i] {
		case "--prefix":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "error: --prefix requires a value")
				os.Exit(1)
			}
			i++
			prefix = args[i]
		case "--project":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "error: --project requires a value")
				os.Exit(1)
			}
			i++
			projectFlag = args[i]
		case "--secret":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "error: --secret requires a value")
				os.Exit(1)
			}
			i++
			secretIDs = append(secretIDs, args[i])
		case "--all":
			allSecrets = true
		case "--watch":
			watch = true
		case "--offline":
			offline = true
		case "--dry-run":
			dryRun = true
		case "--show-values":
			showValues = true
		}
	}

	if !allSecrets && len(secretIDs) == 0 {
		fmt.Fprintln(os.Stderr, "error: specify secrets to inject with --secret <id> or use --all")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "examples:")
		fmt.Fprintln(os.Stderr, "  sikkerkey run --secret sk_db_pass --secret sk_api_key -- ./my-app")
		fmt.Fprintln(os.Stderr, "  sikkerkey run --all -- ./my-app")
		fmt.Fprintln(os.Stderr, "  sikkerkey run --all --project production -- ./my-app")
		os.Exit(1)
	}

	if !dryRun && (cmdStart < 0 || cmdStart >= len(args)) {
		fmt.Fprintln(os.Stderr, "usage: sikkerkey run [options] -- <command> [args...]")
		os.Exit(1)
	}

	if offline && watch {
		fmt.Fprintln(os.Stderr, "error: --offline can't be combined with --watch (watching for changes needs the server)")
		os.Exit(1)
	}

	profile := loadProfileFromIdentity()
	gc := config.LoadGlobalConfig()
	cacheOn := gc.CacheEnabled
	c, ch := newClientWithCache(profile, cacheOn || offline)

	// Resolve --project to a projectId once, up front. Empty string means "all
	// granted projects" for the export call below. Offline can't resolve project
	// names (that needs the server), so it ignores the scope and serves all cached.
	resolvedProjectID := ""
	if offline && projectFlag != "" {
		fmt.Fprintln(os.Stderr, "# offline: --project is ignored; injecting all cached secrets")
	} else if projectFlag != "" {
		id, err := resolveProjectByNameOrId(c, projectFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %s\n", err)
			os.Exit(1)
		}
		resolvedProjectID = id
	}

	// With --all and no explicit --project, fall back to the per-vault
	// application scope.
	activeApp := ""
	if resolvedProjectID == "" && !offline {
		activeApp = gc.CurrentApplication(profile.VaultID)
	}
	if allSecrets && activeApp != "" {
		fmt.Fprintf(os.Stderr, "# scoped to application %s\n", activeApp)
	}

	type envPair struct{ key, value string }

	// addEnv appends one secret's env var(s). structuredKnown=true honors the
	// fieldNames signal (export/--all path: only a marked-structured secret
	// expands); false falls back to parsing the value (--secret path, no metadata).
	addEnvTo := func(injected *[]envPair, rawName, value string, fieldNames *string, structuredKnown bool) {
		envName := toEnvName(rawName)
		var fields map[string]string
		isStruct := json.Unmarshal([]byte(value), &fields) == nil && len(fields) > 0
		if structuredKnown {
			isStruct = isStruct && fieldNames != nil
		}
		if isStruct {
			for k, v := range fields {
				*injected = append(*injected, envPair{prefix + envName + "_" + toEnvName(k), v})
			}
		} else {
			*injected = append(*injected, envPair{prefix + envName, value})
		}
	}

	fetchSecrets := func() ([]envPair, []string) {
		var injected []envPair
		var watchIDs []string

		if allSecrets {
			for _, s := range fetchAllCached(c, ch, resolvedProjectID, activeApp, cacheOn, offline) {
				watchIDs = append(watchIDs, s.ID)
				addEnvTo(&injected, s.Name, s.Value, s.FieldNames, true)
			}
		} else {
			for _, secretID := range secretIDs {
				watchIDs = append(watchIDs, secretID)
				value, _ := fetchSecretCached(c, ch, secretID, cacheOn, offline)
				// --secret keys env vars off the ID, not the name (see help).
				addEnvTo(&injected, secretID, value, nil, false)
			}
		}
		return injected, watchIDs
	}

	injected, watchIDs := fetchSecrets()

	// Dry run: print what would be injected and exit
	if dryRun {
		fmt.Fprintf(os.Stderr, "%d env var(s)\n\n", len(injected))
		for _, p := range injected {
			if showValues {
				fmt.Printf("%s=%s\n", p.key, p.value)
			} else {
				fmt.Printf("%s=****\n", p.key)
			}
		}
		return
	}

	cmdArgs := args[cmdStart:]

	startProcess := func(env []envPair) *exec.Cmd {
		envVars := os.Environ()
		for _, p := range env {
			envVars = append(envVars, p.key+"="+p.value)
		}
		cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
		cmd.Env = envVars
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Start(); err != nil {
			fmt.Fprintf(os.Stderr, "error starting command: %s\n", err)
			os.Exit(1)
		}
		return cmd
	}

	if !watch {
		// No watch: run once and exit with the child's exit code
		cmd := startProcess(injected)

		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			for sig := range sigCh {
				if cmd.Process != nil {
					cmd.Process.Signal(sig)
				}
			}
		}()

		if err := cmd.Wait(); err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				os.Exit(exitErr.ExitCode())
			}
			fmt.Fprintf(os.Stderr, "error: %s\n", err)
			os.Exit(1)
		}
		return
	}

	// Watch mode: run process, poll for changes, restart on change
	fmt.Fprintf(os.Stderr, "[watch] starting process, polling %d secret(s) every 15s\n", len(watchIDs))
	cmd := startProcess(injected)

	// Handle SIGINT/SIGTERM: kill child and exit
	stopping := false
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		stopping = true
		if cmd.Process != nil {
			cmd.Process.Signal(syscall.SIGTERM)
		}
	}()

	// Poll loop in background, signal restart via channel
	restartCh := make(chan struct{}, 1)
	go func() {
		for !stopping {
			time.Sleep(15 * time.Second)
			if stopping {
				return
			}
			changes, err := c.PollSecrets(watchIDs)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[watch] poll error: %s\n", err)
				continue
			}
			if len(changes) > 0 {
				for id, change := range changes {
					fmt.Fprintf(os.Stderr, "[watch] %s: %s\n", id, change.Status)
				}
				select {
				case restartCh <- struct{}{}:
				default:
				}
			}
		}
	}()

	// Main loop: wait for process exit or restart signal
	for {
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()

		select {
		case err := <-done:
			if stopping {
				// User sent SIGINT/SIGTERM, exit cleanly
				if exitErr, ok := err.(*exec.ExitError); ok {
					os.Exit(exitErr.ExitCode())
				}
				return
			}
			// Process exited on its own (crash, normal exit)
			if err != nil {
				if exitErr, ok := err.(*exec.ExitError); ok {
					fmt.Fprintf(os.Stderr, "[watch] process exited with code %d, waiting for changes to restart\n", exitErr.ExitCode())
				} else {
					fmt.Fprintf(os.Stderr, "[watch] process error: %s, waiting for changes to restart\n", err)
				}
				// Wait for a change before restarting
				<-restartCh
			} else {
				fmt.Fprintf(os.Stderr, "[watch] process exited cleanly, waiting for changes to restart\n")
				<-restartCh
			}
			// Re-fetch and restart
			fmt.Fprintf(os.Stderr, "[watch] secrets changed, restarting process\n")
			injected, watchIDs = fetchSecrets()
			cmd = startProcess(injected)

		case <-restartCh:
			// Secrets changed while process is running -- kill and restart
			fmt.Fprintf(os.Stderr, "[watch] secrets changed, restarting process\n")
			cmd.Process.Signal(syscall.SIGTERM)
			cmd.Wait()
			injected, watchIDs = fetchSecrets()
			cmd = startProcess(injected)
		}
	}
}

var nonAlphanumeric = regexp.MustCompile(`[^a-zA-Z0-9]+`)

// toEnvName converts a secret or field name to an environment variable name.
// "Database Credentials" -> "DATABASE_CREDENTIALS"
// "api-key" -> "API_KEY"
func toEnvName(name string) string {
	s := nonAlphanumeric.ReplaceAllString(name, "_")
	s = strings.Trim(s, "_")
	return strings.ToUpper(s)
}

// sikkerkey list secrets
// sikkerkey list <secrets|vaults|projects>
func cmdList(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: sikkerkey list <secrets|vaults|projects|applications>")
		os.Exit(1)
	}

	sub := args[0]

	switch sub {
	case "secrets":
		cmdListSecrets()
	case "vaults":
		cmdListVaults()
	case "projects":
		cmdListProjects()
	case "applications":
		cmdListApplications()
	default:
		fmt.Fprintf(os.Stderr, "unknown: sikkerkey list %s\n", sub)
		fmt.Fprintln(os.Stderr, "available: secrets, vaults, projects, applications")
		os.Exit(1)
	}
}

func cmdListSecrets() {
	vaultID := resolveConfiguredVault()
	if vaultID == "" {
		fmt.Fprintln(os.Stderr, "error: no vault connected. Run 'sikkerkey connect <vault_id>' first.")
		os.Exit(1)
	}

	identity, err := config.LoadIdentity(vaultID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(1)
	}
	keyPath := config.PrivateKeyPath(vaultID)
	signer, err := auth.NewSigner(keyPath, strings.TrimSpace(identity.MachineID))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading private key: %s\n", err)
		os.Exit(1)
	}

	c := client.New(strings.TrimSpace(identity.APIURL), signer)

	secrets, err := c.ListCliSecrets()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error listing secrets: %s\n", err)
		os.Exit(1)
	}

	// Application scope (per-vault, local). Each secret carries its
	// application, so the filter needs no extra round trip. Unset = every
	// granted secret, identical to the pre-application behaviour.
	if activeApp := config.LoadGlobalConfig().CurrentApplication(vaultID); activeApp != "" {
		var filtered []client.CliSecretListItem
		for _, s := range secrets {
			if s.ApplicationID == activeApp {
				filtered = append(filtered, s)
			}
		}
		secrets = filtered
	}

	if len(secrets) == 0 {
		fmt.Println("no secrets available")
		return
	}

	// Nested grouping: application -> project -> secrets, all derived from the
	// single secrets response. Secrets whose project has no application fall
	// under "Standalone" (printed last). First-appearance order keeps output
	// stable for a given response.
	appOrder := make([]string, 0)
	appName := make(map[string]string)
	projOrder := make(map[string][]string)
	byAppProj := make(map[string]map[string][]client.CliSecretListItem)
	for _, s := range secrets {
		key := s.ApplicationID // "" = standalone
		if _, ok := appName[key]; !ok {
			appName[key] = s.ApplicationName
			appOrder = append(appOrder, key)
			byAppProj[key] = make(map[string][]client.CliSecretListItem)
		}
		if _, ok := byAppProj[key][s.ProjectName]; !ok {
			projOrder[key] = append(projOrder[key], s.ProjectName)
		}
		byAppProj[key][s.ProjectName] = append(byAppProj[key][s.ProjectName], s)
	}

	// Named applications first, standalone ("") last.
	keys := make([]string, 0, len(appOrder))
	for _, k := range appOrder {
		if k != "" {
			keys = append(keys, k)
		}
	}
	for _, k := range appOrder {
		if k == "" {
			keys = append(keys, k)
		}
	}

	for i, key := range keys {
		if i > 0 {
			fmt.Println()
		}
		header := appName[key]
		if key == "" {
			header = "Standalone"
		} else if header == "" {
			header = key
		}
		fmt.Println(header)
		for _, proj := range projOrder[key] {
			fmt.Printf("  [%s]\n", proj)
			for _, s := range byAppProj[key][proj] {
				if tag := secretKindTag(s); tag != "" {
					fmt.Printf("    %s  %s  %s\n", s.ID, s.Name, tag)
				} else {
					fmt.Printf("    %s  %s\n", s.ID, s.Name)
				}
			}
		}
	}
}

// secretKindTag labels a secret in list output, or returns "" for a plain one.
//
// Driven by the server's type where it sends one. The fieldNames fallback below
// is for a service older than that field: it can only ever say "structured",
// which is why leased and certificate secrets used to be labelled that way.
func secretKindTag(s client.CliSecretListItem) string {
	switch s.Type {
	case "certificate":
		return "[certificate]"
	case "leased-secret":
		return "[leased]"
	case "structured":
		return "[structured]"
	case "managed":
		return "[managed]"
	case "canary":
		return "[canary]"
	case "secret":
		return ""
	}
	if s.FieldNames != nil && *s.FieldNames != "" && *s.FieldNames != "[]" {
		return "[structured]"
	}
	return ""
}

func cmdListVaults() {
	gc := config.LoadGlobalConfig()
	vaults := config.ListVaults()
	if len(vaults) == 0 {
		fmt.Println("no vaults found")
		return
	}
	aliasFor := make(map[string]string)
	for alias, id := range gc.VaultAliases {
		aliasFor[id] = alias
	}
	for _, v := range vaults {
		marker := "  "
		if v == gc.DefaultVault {
			marker = "* "
		}
		if alias, ok := aliasFor[v]; ok {
			fmt.Printf("%s%s (%s)\n", marker, v, alias)
		} else {
			fmt.Printf("%s%s\n", marker, v)
		}
	}
}

func cmdListProjects() {
	vaultID := resolveConfiguredVault()
	if vaultID == "" {
		fmt.Fprintln(os.Stderr, "error: no vault connected. Run 'sikkerkey connect <vault_id>' first.")
		os.Exit(1)
	}

	identity, err := config.LoadIdentity(vaultID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(1)
	}
	keyPath := config.PrivateKeyPath(vaultID)
	signer, err := auth.NewSigner(keyPath, strings.TrimSpace(identity.MachineID))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading private key: %s\n", err)
		os.Exit(1)
	}

	c := client.New(strings.TrimSpace(identity.APIURL), signer)
	projects, err := c.ListCliProjects()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error listing projects: %s\n", err)
		os.Exit(1)
	}

	// Application scope (per-vault, local). Unset = every granted project.
	if activeApp := config.LoadGlobalConfig().CurrentApplication(vaultID); activeApp != "" {
		var filtered []client.CliProject
		for _, p := range projects {
			if p.ApplicationID == activeApp {
				filtered = append(filtered, p)
			}
		}
		projects = filtered
	}

	if len(projects) == 0 {
		fmt.Println("no projects available")
		return
	}

	// Nested grouping: application -> projects. Projects with no application
	// fall under "Standalone" (printed last). First-appearance order keeps
	// output stable for a given response.
	appOrder := make([]string, 0)
	appName := make(map[string]string)
	byApp := make(map[string][]client.CliProject)
	for _, p := range projects {
		key := p.ApplicationID // "" = standalone
		if _, ok := appName[key]; !ok {
			appName[key] = p.ApplicationName
			appOrder = append(appOrder, key)
		}
		byApp[key] = append(byApp[key], p)
	}

	// Named applications first, standalone ("") last.
	keys := make([]string, 0, len(appOrder))
	for _, k := range appOrder {
		if k != "" {
			keys = append(keys, k)
		}
	}
	for _, k := range appOrder {
		if k == "" {
			keys = append(keys, k)
		}
	}

	for i, key := range keys {
		if i > 0 {
			fmt.Println()
		}
		header := appName[key]
		if key == "" {
			header = "Standalone"
		} else if header == "" {
			header = key
		}
		fmt.Println(header)
		for _, p := range byApp[key] {
			fmt.Printf("  %s (%s)\n", p.ProjectName, p.ProjectID)
		}
	}
}

// sikkerkey set <application> ...
func cmdSet(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: sikkerkey set application <id|none>")
		os.Exit(1)
	}
	switch args[0] {
	case "application":
		cmdSetApplication(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown: sikkerkey set %s\n", args[0])
		fmt.Fprintln(os.Stderr, "available: application")
		os.Exit(1)
	}
}

// sikkerkey set application <id|none>  (no arg shows the current scope)
func cmdSetApplication(args []string) {
	vaultID := resolveConfiguredVault()
	if vaultID == "" {
		fmt.Fprintln(os.Stderr, "error: no vault connected. Run 'sikkerkey connect <vault_id>' first.")
		os.Exit(1)
	}
	gc := config.LoadGlobalConfig()

	// No argument: report the current scope.
	if len(args) < 1 {
		if cur := gc.CurrentApplication(vaultID); cur != "" {
			fmt.Printf("application: %s\n", cur)
		} else {
			fmt.Println("application: none (global)")
		}
		return
	}

	if args[0] == "none" {
		gc.ClearCurrentApplication(vaultID)
		if err := config.SaveGlobalConfig(gc); err != nil {
			fmt.Fprintf(os.Stderr, "error: %s\n", err)
			os.Exit(1)
		}
		fmt.Println("application cleared — list commands are global again")
		return
	}

	target := args[0]

	// Validate against the applications this machine can actually see, and
	// capture the name for a friendly confirmation.
	identity, err := config.LoadIdentity(vaultID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(1)
	}
	keyPath := config.PrivateKeyPath(vaultID)
	signer, err := auth.NewSigner(keyPath, strings.TrimSpace(identity.MachineID))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading private key: %s\n", err)
		os.Exit(1)
	}
	c := client.New(strings.TrimSpace(identity.APIURL), signer)
	projects, err := c.ListCliProjects()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(1)
	}

	appName := ""
	found := false
	for _, p := range projects {
		if p.ApplicationID == target {
			found = true
			appName = p.ApplicationName
			break
		}
	}
	if !found {
		fmt.Fprintf(os.Stderr, "error: no application '%s' is accessible to this machine.\n", target)
		fmt.Fprintln(os.Stderr, "run 'sikkerkey list applications' to see available applications.")
		os.Exit(1)
	}

	gc.SetCurrentApplication(vaultID, target)
	if err := config.SaveGlobalConfig(gc); err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(1)
	}
	if appName != "" {
		fmt.Printf("application set: %s (%s)\n", appName, target)
	} else {
		fmt.Printf("application set: %s\n", target)
	}
	fmt.Println("'list secrets' and 'list projects' now scope to this application")
}

func cmdListApplications() {
	vaultID := resolveConfiguredVault()
	if vaultID == "" {
		fmt.Fprintln(os.Stderr, "error: no vault connected. Run 'sikkerkey connect <vault_id>' first.")
		os.Exit(1)
	}

	identity, err := config.LoadIdentity(vaultID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(1)
	}
	keyPath := config.PrivateKeyPath(vaultID)
	signer, err := auth.NewSigner(keyPath, strings.TrimSpace(identity.MachineID))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading private key: %s\n", err)
		os.Exit(1)
	}

	c := client.New(strings.TrimSpace(identity.APIURL), signer)
	projects, err := c.ListCliProjects()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error listing applications: %s\n", err)
		os.Exit(1)
	}

	// Distinct applications across the machine's accessible projects, with a
	// project count each. Standalone projects (no application) are skipped.
	type appInfo struct {
		name  string
		count int
	}
	apps := make(map[string]*appInfo)
	order := make([]string, 0)
	for _, p := range projects {
		if p.ApplicationID == "" {
			continue
		}
		if apps[p.ApplicationID] == nil {
			apps[p.ApplicationID] = &appInfo{name: p.ApplicationName}
			order = append(order, p.ApplicationID)
		}
		apps[p.ApplicationID].count++
	}

	if len(order) == 0 {
		fmt.Println("no applications available")
		return
	}

	active := config.LoadGlobalConfig().CurrentApplication(vaultID)
	for _, id := range order {
		a := apps[id]
		marker := "  "
		if id == active {
			marker = "* "
		}
		name := a.name
		if name == "" {
			name = id
		}
		plural := "s"
		if a.count == 1 {
			plural = ""
		}
		fmt.Printf("%s%s (%s)  %d project%s\n", marker, name, id, a.count, plural)
	}
}

// sikkerkey export [--format env|json|yaml|dotenv] [--project <name>]
func cmdExport(args []string) {
	format := "env"
	offline := false

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--format":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "error: --format requires a value")
				os.Exit(1)
			}
			i++
			format = args[i]
		case "--project":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "error: --project requires a value")
				os.Exit(1)
			}
			i++
			projectFlag = args[i]
		case "--offline":
			offline = true
		}
	}

	profile := loadProfileFromIdentity()
	gc := config.LoadGlobalConfig()
	cacheOn := gc.CacheEnabled
	c, ch := newClientWithCache(profile, cacheOn || offline)

	// Resolve --project to an id once. Empty string = all granted projects.
	// Offline can't resolve project names (that needs the server), so it ignores
	// the scope and exports everything cached.
	resolvedProjectID := ""
	if offline && projectFlag != "" {
		fmt.Fprintln(os.Stderr, "# offline: --project is ignored; exporting all cached secrets")
	} else if projectFlag != "" {
		id, err := resolveProjectByNameOrId(c, projectFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %s\n", err)
			os.Exit(1)
		}
		resolvedProjectID = id
	}

	// With no explicit --project, fall back to the per-vault application scope.
	// The note goes to stderr so it never pollutes the exported (piped) output.
	activeApp := ""
	if resolvedProjectID == "" && !offline {
		activeApp = gc.CurrentApplication(profile.VaultID)
		if activeApp != "" {
			fmt.Fprintf(os.Stderr, "# scoped to application %s\n", activeApp)
		}
	}

	type entry struct{ key, value string }
	var entries []entry

	for _, s := range fetchAllCached(c, ch, resolvedProjectID, activeApp, cacheOn, offline) {
		envName := toEnvName(s.Name)
		var fields map[string]string
		if s.FieldNames != nil && json.Unmarshal([]byte(s.Value), &fields) == nil && len(fields) > 0 {
			for k, v := range fields {
				entries = append(entries, entry{envName + "_" + toEnvName(k), v})
			}
		} else {
			entries = append(entries, entry{envName, s.Value})
		}
	}

	switch format {
	case "json":
		m := make(map[string]string)
		for _, e := range entries {
			m[e.key] = e.value
		}
		data, _ := json.MarshalIndent(m, "", "  ")
		fmt.Println(string(data))

	case "yaml":
		for _, e := range entries {
			// Simple YAML output, quote values that need it
			fmt.Printf("%s: \"%s\"\n", e.key, strings.ReplaceAll(e.value, "\"", "\\\""))
		}

	case "dotenv":
		for _, e := range entries {
			// Dotenv format: quote values
			fmt.Printf("%s=\"%s\"\n", e.key, strings.ReplaceAll(e.value, "\"", "\\\""))
		}

	default: // "env"
		for _, e := range entries {
			fmt.Printf("%s=%s\n", e.key, e.value)
		}
	}
}

// sikkerkey completion <shell>
func cmdCompletion(args []string) {
	if len(args) < 1 {
		printCommandHelp("completion")
		os.Exit(1)
	}

	commands := []string{
		"connect", "unlock", "rename", "project", "get", "certificate", "export", "run",
		"list", "delete", "agent", "whoami", "status", "cache",
		"clear", "completion", "version", "help",
	}

	switch args[0] {
	case "bash":
		fmt.Println("# sikkerkey bash completion")
		fmt.Println("# Add to ~/.bashrc: eval \"$(sikkerkey completion bash)\"")
		fmt.Printf("_sikkerkey() {\n")
		fmt.Printf("  local cur=${COMP_WORDS[COMP_CWORD]}\n")
		fmt.Printf("  if [ $COMP_CWORD -eq 1 ]; then\n")
		fmt.Printf("    COMPREPLY=($(compgen -W \"%s\" -- \"$cur\"))\n", strings.Join(commands, " "))
		fmt.Printf("  fi\n")
		fmt.Printf("}\n")
		fmt.Printf("complete -F _sikkerkey sikkerkey\n")

	case "zsh":
		fmt.Println("#compdef sikkerkey")
		fmt.Println("# Add to ~/.zshrc: eval \"$(sikkerkey completion zsh)\"")
		fmt.Printf("_sikkerkey() {\n")
		fmt.Printf("  local -a commands\n")
		fmt.Printf("  commands=(\n")
		for _, c := range commands {
			fmt.Printf("    '%s'\n", c)
		}
		fmt.Printf("  )\n")
		fmt.Printf("  _describe 'command' commands\n")
		fmt.Printf("}\n")
		fmt.Printf("compdef _sikkerkey sikkerkey\n")

	case "fish":
		fmt.Println("# sikkerkey fish completion")
		fmt.Println("# Save to ~/.config/fish/completions/sikkerkey.fish")
		for _, c := range commands {
			fmt.Printf("complete -c sikkerkey -n '__fish_use_subcommand' -a '%s'\n", c)
		}

	default:
		fmt.Fprintf(os.Stderr, "error: unsupported shell '%s'. Use bash, zsh, or fish.\n", args[0])
		os.Exit(1)
	}
}

// sikkerkey clear
// sikkerkey delete <vault|project> <id_or_alias>
func cmdDelete(args []string) {
	if len(args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: sikkerkey delete <vault|project> <id_or_alias>")
		os.Exit(1)
	}

	sub := args[0]
	target := args[1]

	switch sub {
	case "vault":
		cmdDeleteVault(target)
	default:
		fmt.Fprintf(os.Stderr, "unknown: sikkerkey delete %s\n", sub)
		fmt.Fprintln(os.Stderr, "available: vault")
		os.Exit(1)
	}
}

func cmdDeleteVault(target string) {
	gc := config.LoadGlobalConfig()
	vaultID := gc.ResolveVault(target)

	// Remove the entire vault directory (identity, keys, cli.json)
	vaultDir := config.VaultDir(vaultID)
	if _, err := os.Stat(vaultDir); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "error: vault '%s' not found\n", target)
		os.Exit(1)
	}

	if err := os.RemoveAll(vaultDir); err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(1)
	}

	// Clear default vault if it was this one
	if gc.DefaultVault == vaultID {
		gc.DefaultVault = ""
	}

	// Remove alias if one points to this vault
	for alias, id := range gc.VaultAliases {
		if id == vaultID {
			delete(gc.VaultAliases, alias)
			break
		}
	}

	config.SaveGlobalConfig(gc)
	fmt.Printf("deleted vault %s\n", vaultID)
}

// sikkerkey whoami
func cmdWhoami() {
	profile := loadProfileFromIdentity()

	identity, err := config.LoadIdentity(profile.VaultID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(1)
	}

	app := config.LoadGlobalConfig().CurrentApplication(profile.VaultID)
	if app == "" {
		app = "none (global)"
	}

	fmt.Printf("Machine ID:  %s\n", profile.MachineID)
	fmt.Printf("Machine:     %s\n", identity.MachineName)
	fmt.Printf("Vault:       %s\n", profile.VaultID)
	fmt.Printf("Application: %s\n", app)
	fmt.Printf("API:         %s\n", profile.APIBaseURL)
	fmt.Printf("Key:         %s\n", config.PrivateKeyPath(profile.VaultID))
}

// sikkerkey status
func cmdStatus() {
	profile := loadProfileFromIdentity()

	// Check private key readable
	keyPath := config.PrivateKeyPath(profile.VaultID)
	if _, err := os.Stat(keyPath); err != nil {
		fmt.Printf("private key:    MISSING (%s)\n", keyPath)
		os.Exit(1)
	}
	fmt.Printf("private key:    ok\n")

	// Check we can sign and authenticate
	c := newClient(profile)
	secrets, err := c.ListSecrets()
	if err != nil {
		fmt.Printf("authentication: FAILED (%s)\n", err)
		os.Exit(1)
	}
	fmt.Printf("authentication: ok\n")
	fmt.Printf("secrets:        %d accessible\n", len(secrets))
	fmt.Printf("vault:          %s\n", profile.VaultID)
	fmt.Printf("api:            %s\n", profile.APIBaseURL)
}

// resolveConfiguredVault returns the vault id to use for the current
// command, in priority order:
//  1. SIKKERKEY_VAULT env var (alias-resolvable)
//  2. global default vault from cli_global.json
//  3. single bootstrapped vault on disk
//
// Returns empty string when nothing is connected and no vault exists
// to fall back to. Exits when multiple vaults exist and none has been
// chosen as default.
func resolveConfiguredVault() string {
	gc := config.LoadGlobalConfig()
	vaultID := os.Getenv("SIKKERKEY_VAULT")
	if vaultID != "" {
		return gc.ResolveVault(vaultID)
	}
	if gc.DefaultVault != "" {
		return gc.DefaultVault
	}
	vaults := config.ListVaults()
	if len(vaults) == 0 {
		return ""
	}
	if len(vaults) == 1 {
		return vaults[0]
	}
	fmt.Fprintln(os.Stderr, "error: multiple bootstrapped vaults. Run 'sikkerkey connect <vault_id>' to select one:")
	for _, v := range vaults {
		fmt.Fprintf(os.Stderr, "  %s\n", v)
	}
	os.Exit(1)
	return ""
}

// projectFlag is set by commands that parse --project from their args.
var projectFlag string

// newClient creates an authenticated API client from a profile.
func newClient(profile *config.Profile) *client.Client {
	return client.New(profile.APIBaseURL, newSigner(profile))
}

// newSigner loads the machine's Ed25519 signer for the profile's vault.
func newSigner(profile *config.Profile) *auth.Signer {
	keyPath := config.PrivateKeyPath(profile.VaultID)
	signer, err := auth.NewSigner(keyPath, profile.MachineID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading private key: %s\n", err)
		os.Exit(1)
	}
	return signer
}

// newClientWithCache builds the API client plus, when wanted, a fallback-cache
// handle. The cache is constructed — and its key derived — ONLY when wanted is
// true (caching enabled or an --offline read). Otherwise it's nil and the read
// path touches no cache code, so a normal read costs nothing.
func newClientWithCache(profile *config.Profile, wantCache bool) (*client.Client, *cache.Cache) {
	signer := newSigner(profile)
	c := client.New(profile.APIBaseURL, signer)
	var ch *cache.Cache
	if wantCache {
		ch = cache.New(profile.VaultID, profile.MachineID, signer.Seed())
	}
	return c, ch
}

// secretItem is the common shape a read resolves to, from either the live
// server or the cache, so run/export build env vars the same way regardless.
type secretItem struct {
	ID         string
	Name       string
	Value      string
	FieldNames *string
}

// fetchSecretCached returns a single secret's value, honoring the cache flag and
// --offline. It exits on an unrecoverable error (as the callers already do).
//
//   - offline:            served straight from cache; error if not cached.
//   - online + reachable: fetched live; cached on success when caching is on.
//   - online + unreachable (transport/503) + caching on: falls back to cache.
//   - online + an authoritative error (403/404/...): propagates, never cache.
func fetchSecretCached(c *client.Client, ch *cache.Cache, secretID string, cacheOn, offline bool) (value string, fromCache bool) {
	if offline {
		res := mustLoadCached(ch, secretID)
		fmt.Fprintf(os.Stderr, "# offline: %s served from cache (cached %s)\n", secretID, cacheAgeNote(res.CachedAt))
		return res.Value, true
	}
	value, err := c.GetSecret(secretID)
	if err != nil {
		if cacheOn && ch != nil && client.IsUnavailable(err) {
			if res, cerr := ch.Load(secretID); cerr == nil && res != nil {
				fmt.Fprintf(os.Stderr, "# sikkerkey unreachable: %s served from cache (cached %s)\n", secretID, cacheAgeNote(res.CachedAt))
				return res.Value, true
			}
		}
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(1)
	}
	if cacheOn && ch != nil {
		if serr := ch.Store(secretID, "", value, nil); serr != nil {
			fmt.Fprintf(os.Stderr, "# warning: could not cache %s: %s\n", secretID, serr)
		}
	}
	return value, false
}

// fetchAllCached resolves the full secret set for run --all / export, honoring
// the cache flag and --offline. Exits on an unrecoverable error.
func fetchAllCached(c *client.Client, ch *cache.Cache, projectID, appID string, cacheOn, offline bool) []secretItem {
	if offline {
		return loadAllCached(ch)
	}
	secrets, err := c.ExportSecrets(projectID, appID)
	if err != nil {
		if cacheOn && ch != nil && client.IsUnavailable(err) {
			items := loadAllCached(ch)
			fmt.Fprintf(os.Stderr, "# sikkerkey unreachable: serving %d secret(s) from cache\n", len(items))
			return items
		}
		fmt.Fprintf(os.Stderr, "error exporting secrets: %s\n", err)
		os.Exit(1)
	}
	items := make([]secretItem, 0, len(secrets))
	for _, s := range secrets {
		items = append(items, secretItem{ID: s.ID, Name: s.Name, Value: s.Value, FieldNames: s.FieldNames})
		if cacheOn && ch != nil {
			if serr := ch.Store(s.ID, s.Name, s.Value, s.FieldNames); serr != nil {
				fmt.Fprintf(os.Stderr, "# warning: could not cache %s: %s\n", s.ID, serr)
			}
		}
	}
	return items
}

// mustLoadCached loads a required cached entry, or exits with a clear message.
func mustLoadCached(ch *cache.Cache, secretID string) *cache.Result {
	if ch == nil {
		fmt.Fprintln(os.Stderr, "error: --offline needs the cache, but none is available")
		os.Exit(1)
	}
	res, err := ch.Load(secretID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading cache: %s\n", err)
		os.Exit(1)
	}
	if res == nil {
		fmt.Fprintf(os.Stderr, "error: %s is not cached. Fetch it online once with caching enabled ('sikkerkey cache enable') first.\n", secretID)
		os.Exit(1)
	}
	return res
}

// loadAllCached returns every cached secret, or exits if the cache is empty.
func loadAllCached(ch *cache.Cache) []secretItem {
	if ch == nil {
		fmt.Fprintln(os.Stderr, "error: --offline needs the cache, but none is available")
		os.Exit(1)
	}
	results, err := ch.LoadAll()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading cache: %s\n", err)
		os.Exit(1)
	}
	if len(results) == 0 {
		fmt.Fprintln(os.Stderr, "error: nothing is cached. Fetch secrets online once with caching enabled ('sikkerkey cache enable') first.")
		os.Exit(1)
	}
	items := make([]secretItem, 0, len(results))
	for _, r := range results {
		items = append(items, secretItem{ID: r.SecretID, Name: r.Name, Value: r.Value, FieldNames: r.FieldNames})
	}
	return items
}

// cacheAgeNote renders a short human age like "3m ago" for stderr notices.
func cacheAgeNote(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours())/24)
	}
}

// cmdCache manages the on-disk fallback cache: enable | disable | status | clear.
func cmdCache(args []string) {
	if len(args) < 1 {
		printCommandHelp("cache")
		os.Exit(1)
	}
	switch args[0] {
	case "enable":
		setCacheEnabled(true)
		fmt.Println("Fallback cache enabled. Secrets you read are now cached (encrypted) and served if SikkerKey is unreachable.")
	case "disable":
		setCacheEnabled(false)
		fmt.Println("Fallback cache disabled. Reads no longer touch the cache. Cached files are kept — run 'sikkerkey cache clear' to remove them.")
	case "status":
		gc := config.LoadGlobalConfig()
		profile := loadProfileFromIdentity()
		n, err := cache.Count(profile.VaultID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %s\n", err)
			os.Exit(1)
		}
		state := "disabled"
		if gc.CacheEnabled {
			state = "enabled"
		}
		fmt.Printf("Fallback cache: %s\n", state)
		fmt.Printf("Cached secrets: %d\n", n)
		fmt.Printf("Location:       %s\n", config.CacheDir(profile.VaultID))
	case "clear":
		profile := loadProfileFromIdentity()
		n, _ := cache.Count(profile.VaultID)
		if err := cache.Clear(profile.VaultID); err != nil {
			fmt.Fprintf(os.Stderr, "error: %s\n", err)
			os.Exit(1)
		}
		fmt.Printf("Cleared %d cached secret(s) for %s.\n", n, profile.VaultID)
	default:
		fmt.Fprintf(os.Stderr, "unknown cache subcommand: %s\n\n", args[0])
		printCommandHelp("cache")
		os.Exit(1)
	}
}

func setCacheEnabled(on bool) {
	gc := config.LoadGlobalConfig()
	gc.CacheEnabled = on
	if err := config.SaveGlobalConfig(gc); err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(1)
	}
}

// loadProfileFromIdentity builds a Profile straight from identity.json
// for the configured vault. Replaces loadProfile() now that project
// context is no longer carried locally — the backend's /v1/cli/* routes
// return the project info live.
func loadProfileFromIdentity() *config.Profile {
	vaultID := resolveConfiguredVault()
	if vaultID == "" {
		fmt.Fprintln(os.Stderr, "error: no vault connected. Run 'sikkerkey connect <vault_id>' first.")
		os.Exit(1)
	}
	identity, err := config.LoadIdentity(vaultID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(1)
	}
	return &config.Profile{
		VaultID:    strings.TrimSpace(identity.VaultID),
		APIBaseURL: strings.TrimSpace(identity.APIURL),
		MachineID:  strings.TrimSpace(identity.MachineID),
	}
}

// resolveProjectByNameOrId hits /v1/cli/projects and returns the project
// id matching the input. Accepts either a name or an id; checks names
// first since they're what users typically pass.
func resolveProjectByNameOrId(c *client.Client, input string) (string, error) {
	projects, err := c.ListCliProjects()
	if err != nil {
		return "", fmt.Errorf("list projects: %w", err)
	}
	for _, p := range projects {
		if p.ProjectName == input {
			return p.ProjectID, nil
		}
	}
	for _, p := range projects {
		if p.ProjectID == input {
			return p.ProjectID, nil
		}
	}
	available := ""
	for _, p := range projects {
		available += fmt.Sprintf("  %s (%s)\n", p.ProjectName, p.ProjectID)
	}
	if available == "" {
		return "", fmt.Errorf("no projects available for this machine")
	}
	return "", fmt.Errorf("project %q not found. Available:\n%s", input, available)
}
