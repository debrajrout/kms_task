package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"

	"my-kms/internal/config"
	"my-kms/internal/server"
	"my-kms/internal/storage"

	firebase "firebase.google.com/go"
	"google.golang.org/api/option"
)

func main() {
	log.Println("KMS server is starting...")

	// 1. Load configuration from environment variables
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// 2. Parse Master Keys
	configMasterKeys, err := cfg.ParseMasterKeys()
	if err != nil {
		log.Fatalf("Failed to parse master keys: %v", err)
	}

	// 3. Convert []config.MasterKey to []storage.MasterKey
	storageMasterKeys := make([]storage.MasterKey, len(configMasterKeys))
	for i, mk := range configMasterKeys {
		storageMasterKeys[i] = storage.MasterKey{
			ID:  mk.ID,
			Key: mk.Key,
		}
	}

	// 4. Initialize MasterKeyStore with master keys
	masterKeyStore, err := storage.NewMasterKeyStore(storageMasterKeys)
	if err != nil {
		log.Fatalf("Failed to initialize MasterKeyStore: %v", err)
	}
	defer func() {
		if err := masterKeyStore.Close(context.Background()); err != nil {
			log.Printf("Failed to close MasterKeyStore: %v", err)
		}
	}()

	// 5. Initialize MongoDB user store
	mongoUserStore, err := storage.NewMongoUserStore(cfg.MongoURI, cfg.MongoDBName, cfg.MongoUsersCollection)
	if err != nil {
		log.Fatalf("Failed to create MongoUserStore: %v", err)
	}
	defer func() {
		if err := mongoUserStore.Close(context.Background()); err != nil {
			log.Printf("Failed to close MongoUserStore: %v", err)
		}
	}()

	// 6. Initialize Firebase
	opt := option.WithCredentialsFile(cfg.FirebaseServiceAccountPath)
	app, err := firebase.NewApp(context.Background(), nil, opt)
	if err != nil {
		log.Fatalf("Failed to initialize Firebase App: %v", err)
	}

	firebaseAuth, err := app.Auth(context.Background())
	if err != nil {
		log.Fatalf("Failed to get Firebase Auth client: %v", err)
	}

	// 7. Create the KMS server with master key store, MongoDB user store, and Firebase Auth client
	kmsServer := server.NewServer(masterKeyStore, mongoUserStore, firebaseAuth)

	// 8. Setup HTTP routes with middleware
	router := kmsServer.Routes()

	// 9. Start HTTPS server with graceful shutdown
	addr := ":8443"                // Use port 443 in production
	tlsCertPath := cfg.TLSCertPath // e.g., "certs/server.crt"
	tlsKeyPath := cfg.TLSKeyPath   // e.g., "certs/server.key"

	httpServer := &http.Server{
		Addr:    addr,
		Handler: router,
	}

	// Run the server in a separate goroutine
	go func() {
		log.Printf("KMS server listening on %s", addr)
		if err := httpServer.ListenAndServeTLS(tlsCertPath, tlsKeyPath); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()

	// Graceful shutdown on interrupt signal
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)
	<-stop

	log.Println("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := httpServer.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	log.Println("Server gracefully stopped.")
}
