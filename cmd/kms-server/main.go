package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"

	firebase "firebase.google.com/go"
	"google.golang.org/api/option"

	"my-kms/internal/config"
	"my-kms/internal/server"
	"my-kms/internal/storage"
)

func main() {
	log.Println("KMS server is starting...")

	// 1. Load configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// 2. Parse master keys
	configMasterKeys, err := cfg.ParseMasterKeys()
	if err != nil {
		log.Fatalf("Failed to parse master keys: %v", err)
	}

	// Convert config.MasterKey to storage.MasterKey
	storageMasterKeys := make([]storage.MasterKey, len(configMasterKeys))
	for i, mk := range configMasterKeys {
		storageMasterKeys[i] = storage.MasterKey{
			ID:  mk.ID,
			Key: mk.Key,
		}
	}

	// 3. Initialize MasterKeyStore
	masterKeyStore, err := storage.NewMasterKeyStore(storageMasterKeys)
	if err != nil {
		log.Fatalf("Failed to initialize MasterKeyStore: %v", err)
	}
	defer masterKeyStore.Close(context.Background())

	// 4. Initialize MongoDB user store
	userStore, err := storage.NewMongoUserStore(cfg.MongoURI, cfg.MongoDBName, cfg.MongoUsersCollection)
	if err != nil {
		log.Fatalf("Failed to create MongoUserStore: %v", err)
	}
	defer userStore.Close(context.Background())

	// 5. Initialize MongoDB DEK store
	dekStore, err := storage.NewMongoDEKStore(cfg.MongoURI, cfg.MongoDBName, cfg.MongoDEKCollection)
	if err != nil {
		log.Fatalf("Failed to create MongoDEKStore: %v", err)
	}
	defer dekStore.Close(context.Background())

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

	// 7. Create the KMS server
	kmsServer := server.NewServer(masterKeyStore, userStore, dekStore, firebaseAuth)

	// 8. Setup routes
	router := kmsServer.Routes()

	// 9. Start HTTPS server with graceful shutdown
	addr := ":8443"
	httpServer := &http.Server{
		Addr:    addr,
		Handler: router,
	}

	go func() {
		log.Printf("KMS server listening on %s", addr)
		if err := httpServer.ListenAndServeTLS(cfg.TLSCertPath, cfg.TLSKeyPath); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()

	// Handle graceful shutdown
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
