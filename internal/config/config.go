// Package config handles reading and writing the CLI's local configuration.
//
// Bootstrap writes identity.json and private.pem to ~/.sikkerkey/vaults/{vaultId}/.
// The "auth" command reads identity.json and writes cli.json alongside it.
// cli.json supports multiple named projects per vault.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// baseDir returns the SikkerKey config directory, respecting SIKKERKEY_HOME env var.
func baseDir() string {
	if env := os.Getenv("SIKKERKEY_HOME"); env != "" {
		return env
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join("/tmp", ".sikkerkey")
	}
	return filepath.Join(home, ".sikkerkey")
}

// Profile carries the per-vault auth context required to talk to the
// SikkerKey API: which vault the identity belongs to, the base URL for
// the API, and the machine id used in the signed-request header.
//
// Project context is no longer carried locally — the backend resolves
// grants directly from the machine identity, and project enumeration
// happens live via /v1/cli/projects when needed.
type Profile struct {
	VaultID    string
	APIBaseURL string
	MachineID  string
}

// Identity is the structure written by the bootstrap script.
type Identity struct {
	MachineID      string `json:"machineId"`
	MachineName    string `json:"machineName"`
	VaultID        string `json:"vaultId"`
	APIURL         string `json:"apiUrl"`
	PrivateKeyPath string `json:"privateKeyPath"`
}

func basePath() string     { return filepath.Join(baseDir(), "vaults") }
func globalConfigPath() string { return filepath.Join(baseDir(), "cli_global.json") }

type GlobalConfig struct {
	DefaultVault string            `json:"default_vault,omitempty"`
	VaultAliases map[string]string `json:"vault_aliases,omitempty"` // alias -> vault_id
	// CurrentApplications scopes `list` output to one application per vault
	// (vault_id -> application_id). Optional and per-vault: an unset vault, or
	// an older config without this field, behaves globally exactly as before.
	CurrentApplications map[string]string `json:"current_applications,omitempty"`
	// CacheEnabled turns on the on-disk fallback cache: successful reads are
	// written to an encrypted per-secret cache and served from it when the
	// server is unreachable. Off by default — nothing is cached or read back
	// until this is enabled, so a normal read touches no cache code at all.
	CacheEnabled bool `json:"cache_enabled,omitempty"`
}

// ResolveVault returns a vault ID from an alias or raw vault ID.
func (gc *GlobalConfig) ResolveVault(nameOrID string) string {
	if gc.VaultAliases != nil {
		if id, ok := gc.VaultAliases[nameOrID]; ok {
			return id
		}
	}
	return nameOrID
}

// SetAlias maps an alias to a vault ID.
func (gc *GlobalConfig) SetAlias(alias, vaultID string) {
	if gc.VaultAliases == nil {
		gc.VaultAliases = make(map[string]string)
	}
	gc.VaultAliases[alias] = vaultID
}

// CurrentApplication returns the application id scoping `list` output for the
// given vault, or "" when none is set (global).
func (gc *GlobalConfig) CurrentApplication(vaultID string) string {
	if gc.CurrentApplications == nil {
		return ""
	}
	return gc.CurrentApplications[vaultID]
}

// SetCurrentApplication scopes `list` output to an application for a vault.
func (gc *GlobalConfig) SetCurrentApplication(vaultID, appID string) {
	if gc.CurrentApplications == nil {
		gc.CurrentApplications = make(map[string]string)
	}
	gc.CurrentApplications[vaultID] = appID
}

// ClearCurrentApplication returns the vault to global (unscoped) `list` output.
func (gc *GlobalConfig) ClearCurrentApplication(vaultID string) {
	if gc.CurrentApplications != nil {
		delete(gc.CurrentApplications, vaultID)
	}
}

func LoadGlobalConfig() *GlobalConfig {
	data, err := os.ReadFile(globalConfigPath())
	if err != nil {
		return &GlobalConfig{}
	}
	var gc GlobalConfig
	if json.Unmarshal(data, &gc) != nil {
		return &GlobalConfig{}
	}
	return &gc
}

func SaveGlobalConfig(gc *GlobalConfig) error {
	data, err := json.MarshalIndent(gc, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal global config: %w", err)
	}
	p := globalConfigPath()
	os.MkdirAll(filepath.Dir(p), 0700)
	if err := os.WriteFile(p, data, 0600); err != nil {
		return fmt.Errorf("write %s: %w", p, err)
	}
	return nil
}

// ListVaults returns all vault IDs that have identity.json.
func ListVaults() []string {
	bp := basePath()
	entries, err := os.ReadDir(bp)
	if err != nil {
		return nil
	}
	var vaults []string
	for _, e := range entries {
		if e.IsDir() {
			if _, err := os.Stat(filepath.Join(bp, e.Name(), "identity.json")); err == nil {
				vaults = append(vaults, e.Name())
			}
		}
	}
	return vaults
}

// VaultDir returns the path to the vault's config directory.
func VaultDir(vaultID string) string {
	return filepath.Join(basePath(), vaultID)
}

// CacheDir returns the on-disk fallback-cache directory for a vault
// (~/.sikkerkey/vaults/{vaultId}/cache).
func CacheDir(vaultID string) string {
	return filepath.Join(VaultDir(vaultID), "cache")
}

// PrivateKeyPath returns the path to the machine's Ed25519 private key.
func PrivateKeyPath(vaultID string) string {
	return filepath.Join(VaultDir(vaultID), "private.pem")
}

// IdentityPath returns the path to the identity file written by bootstrap.
func IdentityPath(vaultID string) string {
	return filepath.Join(VaultDir(vaultID), "identity.json")
}

// LoadIdentity reads the identity.json written by bootstrap.
func LoadIdentity(vaultID string) (*Identity, error) {
	path := IdentityPath(vaultID)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var id Identity
	if err := json.Unmarshal(data, &id); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &id, nil
}
