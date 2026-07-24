package providers

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/SikkerKeyOfficial/sikkerkey-cli/internal/agent"
)

func init() {
	agent.Register(&RedisProvider{})
}

type RedisProvider struct{}

func (p *RedisProvider) Type() string       { return "redis" }
func (p *RedisProvider) DisplayName() string { return "Redis" }

func (p *RedisProvider) ApplyCredentials(config agent.Config, fields map[string]string) error {
	rdb, err := p.connect(config)
	if err != nil {
		return err
	}
	defer rdb.Close()
	ctx := context.Background()

	username := fields[config.GetUsernameField()]
	password := fields[config.GetPasswordField()]

	if password == "" {
		return fmt.Errorf("field '%s' is empty or missing in the secret", config.GetPasswordField())
	}

	// If no username or username is "default", set the password on the default user
	if username == "" || username == "default" {
		// Redis 6+ ACL: update default user password
		if p.hasACL(rdb, ctx) {
			err = rdb.Do(ctx, "ACL", "SETUSER", "default", "on", ">"+password).Err()
			if err != nil {
				return fmt.Errorf("ACL SETUSER default: %w", err)
			}
		} else {
			// Legacy Redis (< 6): CONFIG SET requirepass
			err = rdb.ConfigSet(ctx, "requirepass", password).Err()
			if err != nil {
				return fmt.Errorf("CONFIG SET requirepass: %w", err)
			}
		}
		return nil
	}

	// Named user (Redis 6+ ACL only)
	if !p.hasACL(rdb, ctx) {
		return fmt.Errorf("named users require Redis 6+ with ACL support")
	}

	// Check if user exists
	users, err := rdb.Do(ctx, "ACL", "LIST").StringSlice()
	if err != nil {
		return fmt.Errorf("ACL LIST: %w", err)
	}

	exists := false
	for _, u := range users {
		if strings.HasPrefix(u, "user "+username+" ") {
			exists = true
			break
		}
	}

	if !exists {
		// Create user with login enabled and the password
		err = rdb.Do(ctx, "ACL", "SETUSER", username, "on", ">"+password, "~*", "+@all").Err()
		if err != nil {
			return fmt.Errorf("ACL SETUSER (create): %w", err)
		}
	} else {
		// Reset passwords and set the new one
		err = rdb.Do(ctx, "ACL", "SETUSER", username, "resetpass", ">"+password).Err()
		if err != nil {
			return fmt.Errorf("ACL SETUSER (update): %w", err)
		}
	}

	return nil
}

func (p *RedisProvider) TestConnection(config agent.Config) error {
	rdb, err := p.connect(config)
	if err != nil {
		return err
	}
	defer rdb.Close()
	ctx := context.Background()

	// Ping to verify auth works
	if err := rdb.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("ping failed: %w", err)
	}

	return nil
}

func (p *RedisProvider) VerifyCredentials(config agent.Config, username, password string) error {
	opts := &redis.Options{
		Addr:        fmt.Sprintf("%s:%d", config.Host, config.Port),
		Password:    password,
		DialTimeout: 5 * time.Second,
	}
	if username != "" && username != "default" {
		opts.Username = username
	}
	rdb := redis.NewClient(opts)
	defer rdb.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := rdb.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("verify connect: %w", err)
	}
	return nil
}

func (p *RedisProvider) connect(config agent.Config) (*redis.Client, error) {
	opts := &redis.Options{
		Addr:        fmt.Sprintf("%s:%d", config.Host, config.Port),
		DialTimeout: 5 * time.Second,
	}

	if config.AdminUser != "" && config.AdminUser != "default" {
		opts.Username = config.AdminUser
	}
	if config.AdminPass != "" {
		opts.Password = config.AdminPass
	}
	if config.Database != "" {
		// Redis databases are numeric (0-15)
		var db int
		fmt.Sscanf(config.Database, "%d", &db)
		opts.DB = db
	}

	rdb := redis.NewClient(opts)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := rdb.Ping(ctx).Err(); err != nil {
		rdb.Close()
		return nil, fmt.Errorf("connect to %s:%d: %w", config.Host, config.Port, err)
	}

	return rdb, nil
}

// hasACL checks if the Redis server supports ACL commands (Redis 6+).
func (p *RedisProvider) hasACL(rdb *redis.Client, ctx context.Context) bool {
	err := rdb.Do(ctx, "ACL", "WHOAMI").Err()
	return err == nil
}
