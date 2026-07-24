package providers

import (
	"context"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"github.com/SikkerKeyOfficial/sikkerkey-cli/internal/agent"
)

func init() {
	agent.Register(&MongoDBProvider{})
}

type MongoDBProvider struct{}

func (p *MongoDBProvider) Type() string       { return "mongodb" }
func (p *MongoDBProvider) DisplayName() string { return "MongoDB" }

func (p *MongoDBProvider) ApplyCredentials(config agent.Config, fields map[string]string) error {
	client, err := p.connect(config)
	if err != nil {
		return err
	}
	defer client.Disconnect(context.Background())

	username := fields[config.GetUsernameField()]
	password := fields[config.GetPasswordField()]

	if username == "" {
		return fmt.Errorf("field '%s' is empty or missing in the secret", config.GetUsernameField())
	}
	if password == "" {
		return fmt.Errorf("field '%s' is empty or missing in the secret", config.GetPasswordField())
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Users are managed in the target database (or "admin" if no database specified)
	dbName := config.Database
	if dbName == "" {
		dbName = "admin"
	}
	db := client.Database(dbName)

	// Check if user exists
	result := db.RunCommand(ctx, bson.D{{Key: "usersInfo", Value: bson.D{{Key: "user", Value: username}, {Key: "db", Value: dbName}}}})
	var usersInfo struct {
		Users []struct {
			User string `bson:"user"`
		} `bson:"users"`
	}
	if err := result.Decode(&usersInfo); err != nil {
		return fmt.Errorf("check user existence: %w", err)
	}

	if len(usersInfo.Users) == 0 {
		// Create user with readWrite role on the target database
		createCmd := bson.D{
			{Key: "createUser", Value: username},
			{Key: "pwd", Value: password},
			{Key: "roles", Value: bson.A{
				bson.D{{Key: "role", Value: "readWrite"}, {Key: "db", Value: dbName}},
			}},
		}
		if err := db.RunCommand(ctx, createCmd).Err(); err != nil {
			return fmt.Errorf("createUser: %w", err)
		}
	} else {
		// Update password
		updateCmd := bson.D{
			{Key: "updateUser", Value: username},
			{Key: "pwd", Value: password},
		}
		if err := db.RunCommand(ctx, updateCmd).Err(); err != nil {
			return fmt.Errorf("updateUser: %w", err)
		}
	}

	return nil
}

func (p *MongoDBProvider) TestConnection(config agent.Config) error {
	client, err := p.connect(config)
	if err != nil {
		return err
	}
	defer client.Disconnect(context.Background())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Ping to verify connection
	if err := client.Ping(ctx, nil); err != nil {
		return fmt.Errorf("ping failed: %w", err)
	}

	// Verify admin privileges by checking if we can list users
	dbName := config.Database
	if dbName == "" {
		dbName = "admin"
	}
	result := client.Database(dbName).RunCommand(ctx, bson.D{{Key: "usersInfo", Value: 1}})
	if err := result.Err(); err != nil {
		return fmt.Errorf("admin user '%s' cannot manage users: %w", config.AdminUser, err)
	}

	return nil
}

func (p *MongoDBProvider) VerifyCredentials(config agent.Config, username, password string) error {
	dbName := config.Database
	if dbName == "" {
		dbName = "admin"
	}
	uri := fmt.Sprintf("mongodb://%s:%s@%s:%d/%s?authSource=%s", username, password, config.Host, config.Port, dbName, dbName)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := mongo.Connect(options.Client().ApplyURI(uri))
	if err != nil {
		return fmt.Errorf("verify connect: %w", err)
	}
	defer client.Disconnect(context.Background())
	if err := client.Ping(ctx, nil); err != nil {
		return fmt.Errorf("verify ping: %w", err)
	}
	return nil
}

func (p *MongoDBProvider) connect(config agent.Config) (*mongo.Client, error) {
	// Build connection URI
	dbName := config.Database
	if dbName == "" {
		dbName = "admin"
	}

	uri := fmt.Sprintf("mongodb://%s:%s@%s:%d/%s?authSource=admin",
		config.AdminUser, config.AdminPass, config.Host, config.Port, dbName,
	)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := mongo.Connect(options.Client().ApplyURI(uri))
	if err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}

	if err := client.Ping(ctx, nil); err != nil {
		client.Disconnect(context.Background())
		return nil, fmt.Errorf("connect to %s:%d: %w", config.Host, config.Port, err)
	}

	return client, nil
}
