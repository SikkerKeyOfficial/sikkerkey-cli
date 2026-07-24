// Package agent implements the SikkerKey sync agent.
// The agent watches for secret rotations and applies new values
// to external systems (databases, caches, etc.).
package agent

import "fmt"

// Provider applies a rotated secret value to an external system.
type Provider interface {
	// Type returns the provider identifier (e.g. "postgresql", "mysql").
	Type() string

	// DisplayName returns the human-readable name (e.g. "PostgreSQL").
	DisplayName() string

	// ApplyCredentials applies the new credentials to the external system.
	// fields contains the full structured secret (e.g. {"username": "app", "password": "new-value"}).
	// For single-value secrets, fields has a single "value" key.
	// config contains the provider-specific connection config.
	ApplyCredentials(config Config, fields map[string]string) error

	// TestConnection verifies the provider can connect with the given config.
	TestConnection(config Config) error

	// VerifyCredentials verifies the managed user can connect with the new password.
	// Uses the managed credentials (not admin) to confirm the apply worked.
	VerifyCredentials(config Config, username, password string) error
}

// Config holds the connection details for a provider.
type Config struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Database string `json:"database,omitempty"`
	AdminUser string `json:"adminUser"`
	AdminPass string `json:"adminPass"`
	// ProjectReference is a platform-specific routing suffix. When set, the
	// provider appends ".<ProjectReference>" to the database connection
	// username for both the admin connection and the managed-role verify
	// connection. SQL identifiers (ALTER ROLE, CREATE ROLE) still use the
	// plain role name. Populated for the Supabase variant; empty for
	// standard Postgres deployments.
	ProjectReference string `json:"projectReference,omitempty"`
	// UsernameField is the field name in the secret that contains the target username.
	// Default: "username"
	UsernameField string `json:"usernameField,omitempty"`
	// PasswordField is the field name in the secret that contains the password to sync.
	// Default: "password"
	PasswordField string `json:"passwordField,omitempty"`
}

func (c Config) GetUsernameField() string {
	if c.UsernameField != "" {
		return c.UsernameField
	}
	return "username"
}

func (c Config) GetPasswordField() string {
	if c.PasswordField != "" {
		return c.PasswordField
	}
	return "password"
}

// AdminConnectUser returns the admin username to use when opening a database
// connection. On providers with a project reference (e.g. Supabase through
// Supavisor), the suffix is appended for tenant routing; otherwise the raw
// AdminUser is returned.
func (c Config) AdminConnectUser() string {
	if c.ProjectReference != "" {
		return c.AdminUser + "." + c.ProjectReference
	}
	return c.AdminUser
}

// ManagedConnectUser returns the username to use when opening a verify
// connection as the managed role after a rotation. Same tenant-suffix logic
// as AdminConnectUser.
func (c Config) ManagedConnectUser(roleName string) string {
	if c.ProjectReference != "" {
		return roleName + "." + c.ProjectReference
	}
	return roleName
}

// Registry of all available providers.
var providers = map[string]Provider{}

// Register adds a provider to the registry.
func Register(p Provider) {
	providers[p.Type()] = p
}

// GetProvider returns a provider by type, or an error if not found.
func GetProvider(providerType string) (Provider, error) {
	p, ok := providers[providerType]
	if !ok {
		available := make([]string, 0, len(providers))
		for k := range providers {
			available = append(available, k)
		}
		return nil, fmt.Errorf("unknown provider '%s'. Available: %v", providerType, available)
	}
	return p, nil
}

// ListProviders returns all registered provider types.
func ListProviders() []string {
	result := make([]string, 0, len(providers))
	for _, p := range providers {
		result = append(result, p.Type())
	}
	return result
}
