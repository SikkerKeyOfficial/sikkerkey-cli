package providers

import (
	"database/sql"
	"fmt"
	"strings"

	"github.com/lib/pq"
	"github.com/SikkerKeyOfficial/sikkerkey-cli/internal/agent"
)

func init() {
	agent.Register(&PostgreSQLProvider{typeName: "postgresql", displayName: "PostgreSQL"})
	// Supabase variant routes through Supavisor, which requires a tenant
	// suffix on the DB connection username. Same driver and SQL path as
	// standard PostgreSQL; the Config.ProjectReference field is what triggers
	// the suffix when opening connections.
	agent.Register(&PostgreSQLProvider{typeName: "postgresql_supabase", displayName: "PostgreSQL (Supabase)"})
}

type PostgreSQLProvider struct {
	typeName    string
	displayName string
}

func (p *PostgreSQLProvider) Type() string        { return p.typeName }
func (p *PostgreSQLProvider) DisplayName() string  { return p.displayName }

func (p *PostgreSQLProvider) ApplyCredentials(config agent.Config, fields map[string]string) error {
	db, err := p.connect(config)
	if err != nil {
		return err
	}
	defer db.Close()

	username := fields[config.GetUsernameField()]
	password := fields[config.GetPasswordField()]

	if username == "" {
		return fmt.Errorf("field '%s' is empty or missing in the secret", config.GetUsernameField())
	}
	if password == "" {
		return fmt.Errorf("field '%s' is empty or missing in the secret", config.GetPasswordField())
	}

	// Check if the role exists
	var exists bool
	err = db.QueryRow("SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname = $1)", username).Scan(&exists)
	if err != nil {
		return fmt.Errorf("check role existence: %w", err)
	}

	safeName := sanitizeIdentifier(username)
	safePass := pq.QuoteLiteral(password)

	if !exists {
		_, err = db.Exec(fmt.Sprintf("CREATE ROLE %s WITH LOGIN PASSWORD %s", safeName, safePass))
		if err != nil {
			return fmt.Errorf("create role: %w", err)
		}
	} else {
		_, err = db.Exec(fmt.Sprintf("ALTER ROLE %s WITH PASSWORD %s", safeName, safePass))
		if err != nil {
			return fmt.Errorf("alter role password: %w", err)
		}
	}

	return nil
}

func (p *PostgreSQLProvider) TestConnection(config agent.Config) error {
	db, err := p.connect(config)
	if err != nil {
		return err
	}
	defer db.Close()

	// Verify we have permission to manage roles
	var canCreate bool
	err = db.QueryRow("SELECT rolcreaterole FROM pg_roles WHERE rolname = current_user").Scan(&canCreate)
	if err != nil {
		return fmt.Errorf("check permissions: %w", err)
	}

	// Also accept superuser
	if !canCreate {
		var isSuperuser bool
		db.QueryRow("SELECT rolsuper FROM pg_roles WHERE rolname = current_user").Scan(&isSuperuser)
		if !isSuperuser {
			return fmt.Errorf("admin user '%s' does not have CREATEROLE or SUPERUSER privilege", config.AdminUser)
		}
	}

	return nil
}

func (p *PostgreSQLProvider) VerifyCredentials(config agent.Config, username, password string) error {
	connectUser := config.ManagedConnectUser(username)
	dsn := fmt.Sprintf("host=%s port=%d user=%s password=%s sslmode=disable", config.Host, config.Port, connectUser, password)
	if config.Database != "" {
		dsn = fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable", config.Host, config.Port, connectUser, password, config.Database)
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return fmt.Errorf("verify open: %w", err)
	}
	defer db.Close()
	if err := db.Ping(); err != nil {
		return fmt.Errorf("verify connect: %w", err)
	}
	return nil
}

func (p *PostgreSQLProvider) connect(config agent.Config) (*sql.DB, error) {
	connectUser := config.AdminConnectUser()
	dsn := fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
		config.Host, config.Port, connectUser, config.AdminPass, config.Database,
	)
	if config.Database == "" {
		dsn = fmt.Sprintf(
			"host=%s port=%d user=%s password=%s sslmode=disable",
			config.Host, config.Port, connectUser, config.AdminPass,
		)
	}

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("open connection: %w", err)
	}

	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("connect to %s:%d: %w", config.Host, config.Port, err)
	}

	return db, nil
}

// sanitizeIdentifier prevents SQL injection in role names.
// PostgreSQL identifiers: letters, digits, underscores. Quote with double quotes.
func sanitizeIdentifier(name string) string {
	// Remove any double quotes and null bytes
	safe := strings.ReplaceAll(name, "\"", "")
	safe = strings.ReplaceAll(safe, "\x00", "")
	return fmt.Sprintf("\"%s\"", safe)
}
