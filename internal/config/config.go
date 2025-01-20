// internal/config/config.go
package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/joho/godotenv"
	"github.com/kelseyhightower/envconfig"
)

// MasterKey represents a master key with an ID and the key bytes.
type MasterKey struct {
	ID  string
	Key []byte
}

// Config holds the configuration variables.
type Config struct {
	MongoURI                   string `envconfig:"MONGO_URI" required:"true"`
	MongoDBName                string `envconfig:"MONGO_DB_NAME" required:"true"`
	MongoUsersCollection       string `envconfig:"MONGO_USERS_COLLECTION" required:"true"`
	FirebaseServiceAccountPath string `envconfig:"FIREBASE_SERVICE_ACCOUNT_PATH" required:"true"`
	MasterKeys                 string `envconfig:"MASTER_KEYS" required:"true"` // Comma-separated: id:base64key
	TLSCertPath                string `envconfig:"TLS_CERT_PATH" required:"true"`
	TLSKeyPath                 string `envconfig:"TLS_KEY_PATH" required:"true"`
}

// LoadConfig loads configuration from a .env file and environment variables.
func LoadConfig() (*Config, error) {
	// Load .env file if it exists
	err := godotenv.Load()
	if err != nil {
		fmt.Println("No .env file found, relying on environment variables")
	}

	var cfg Config
	err = envconfig.Process("", &cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to process environment variables: %w", err)
	}
	return &cfg, nil
}

// ParseMasterKeys parses the MASTER_KEYS environment variable into a slice of MasterKey.
func (cfg *Config) ParseMasterKeys() ([]MasterKey, error) {
	var masterKeys []MasterKey
	keys := strings.Split(cfg.MasterKeys, ",")
	for _, key := range keys {
		parts := strings.SplitN(key, ":", 2)
		if len(parts) != 2 {
			return nil, errors.New("invalid MASTER_KEYS format; expected id:base64key")
		}
		id := parts[0]
		keyBytes, err := base64.StdEncoding.DecodeString(parts[1])
		if err != nil {
			return nil, fmt.Errorf("failed to decode base64 key for ID %s: %w", id, err)
		}
		if len(keyBytes) != 32 {
			return nil, fmt.Errorf("master key for ID %s must be 32 bytes for AES-256", id)
		}
		masterKeys = append(masterKeys, MasterKey{
			ID:  id,
			Key: keyBytes,
		})
	}
	return masterKeys, nil
}
