package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/joho/godotenv"
	"github.com/kelseyhightower/envconfig"
)

type MasterKey struct {
	ID  string
	Key []byte
}

type Config struct {
	MongoURI                   string `envconfig:"MONGO_URI" required:"true"`
	MongoDBName                string `envconfig:"MONGO_DB_NAME" required:"true"`
	MongoUsersCollection       string `envconfig:"MONGO_USERS_COLLECTION" required:"true"`
	FirebaseServiceAccountPath string `envconfig:"FIREBASE_SERVICE_ACCOUNT_PATH" required:"true"`
	MasterKeys                 string `envconfig:"MASTER_KEYS" required:"true"`
	TLSCertPath                string `envconfig:"TLS_CERT_PATH" required:"true"`
	TLSKeyPath                 string `envconfig:"TLS_KEY_PATH" required:"true"`
	MongoDEKCollection         string `envconfig:"MONGO_DEK_COLLECTION" required:"true"`
}

func LoadConfig() (*Config, error) {

	if err := godotenv.Load(); err != nil {
		fmt.Println("No .env file found, relying on environment variables...")
	}

	var cfg Config
	err := envconfig.Process("", &cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to process environment variables: %w", err)
	}
	return &cfg, nil
}

func (cfg *Config) ParseMasterKeys() ([]MasterKey, error) {
	parts := strings.Split(cfg.MasterKeys, ",")
	var masterKeys []MasterKey
	for _, p := range parts {
		kv := strings.SplitN(p, ":", 2)
		if len(kv) != 2 {
			return nil, errors.New("invalid MASTER_KEYS format; expected id:base64key")
		}
		id := kv[0]
		keyBytes, err := base64.StdEncoding.DecodeString(kv[1])
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
