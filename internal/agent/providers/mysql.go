package providers

import (
	"database/sql"
	"fmt"
	"strings"

	_ "github.com/go-sql-driver/mysql"
	"github.com/SikkerKeyOfficial/sikkerkey-cli/internal/agent"
)

func init() {
	agent.Register(&MySQLProvider{})
}

type MySQLProvider struct{}

func (p *MySQLProvider) Type() string       { return "mysql" }
func (p *MySQLProvider) DisplayName() string { return "MySQL" }

func (p *MySQLProvider) ApplyCredentials(config agent.Config, fields map[string]string) error {
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

	// Check if the user exists
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM mysql.user WHERE User = ? AND Host = '%'", username).Scan(&count)
	if err != nil {
		return fmt.Errorf("check user existence: %w", err)
	}

	safeName := quoteIdentifier(username)
	safePass := quoteString(password)

	if count == 0 {
		_, err = db.Exec(fmt.Sprintf("CREATE USER %s@'%%' IDENTIFIED BY %s", safeName, safePass))
		if err != nil {
			return fmt.Errorf("create user: %w", err)
		}
	} else {
		_, err = db.Exec(fmt.Sprintf("ALTER USER %s@'%%' IDENTIFIED BY %s", safeName, safePass))
		if err != nil {
			return fmt.Errorf("alter user password: %w", err)
		}
	}

	return nil
}

func (p *MySQLProvider) TestConnection(config agent.Config) error {
	db, err := p.connect(config)
	if err != nil {
		return err
	}
	defer db.Close()

	// Verify we have CREATE USER privilege
	var grantResult string
	rows, err := db.Query("SHOW GRANTS FOR CURRENT_USER()")
	if err != nil {
		return fmt.Errorf("check permissions: %w", err)
	}
	defer rows.Close()

	hasPrivilege := false
	for rows.Next() {
		if err := rows.Scan(&grantResult); err != nil {
			continue
		}
		upper := strings.ToUpper(grantResult)
		if strings.Contains(upper, "ALL PRIVILEGES") || strings.Contains(upper, "CREATE USER") {
			hasPrivilege = true
			break
		}
	}

	if !hasPrivilege {
		return fmt.Errorf("admin user '%s' does not have CREATE USER privilege", config.AdminUser)
	}

	return nil
}

func (p *MySQLProvider) VerifyCredentials(config agent.Config, username, password string) error {
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/", username, password, config.Host, config.Port)
	if config.Database != "" {
		dsn = fmt.Sprintf("%s:%s@tcp(%s:%d)/%s", username, password, config.Host, config.Port, config.Database)
	}
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return fmt.Errorf("verify open: %w", err)
	}
	defer db.Close()
	if err := db.Ping(); err != nil {
		return fmt.Errorf("verify connect: %w", err)
	}
	return nil
}

func (p *MySQLProvider) connect(config agent.Config) (*sql.DB, error) {
	// DSN format: user:password@tcp(host:port)/dbname
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/",
		config.AdminUser, config.AdminPass, config.Host, config.Port,
	)
	if config.Database != "" {
		dsn = fmt.Sprintf("%s:%s@tcp(%s:%d)/%s",
			config.AdminUser, config.AdminPass, config.Host, config.Port, config.Database,
		)
	}

	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, fmt.Errorf("open connection: %w", err)
	}

	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("connect to %s:%d: %w", config.Host, config.Port, err)
	}

	return db, nil
}

// quoteIdentifier quotes a MySQL identifier with backticks.
func quoteIdentifier(name string) string {
	safe := strings.ReplaceAll(name, "`", "")
	safe = strings.ReplaceAll(safe, "\x00", "")
	return fmt.Sprintf("`%s`", safe)
}

// quoteString quotes a MySQL string literal with single quotes.
func quoteString(value string) string {
	safe := strings.ReplaceAll(value, "\\", "\\\\")
	safe = strings.ReplaceAll(safe, "'", "\\'")
	safe = strings.ReplaceAll(safe, "\x00", "")
	return fmt.Sprintf("'%s'", safe)
}
