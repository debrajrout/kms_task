package server

import (
	firebaseauth "firebase.google.com/go/auth"

	"my-kms/internal/storage"
)

// Server holds references to the MasterKeyStore, MongoUserStore, DEKStore, etc.
type Server struct {
	KeyStore       *storage.MasterKeyStore
	MongoUserStore *storage.MongoUserStore
	DEKStore       *storage.MongoDEKStore
	FirebaseAuth   *firebaseauth.Client
}

// NewServer creates a new Server with the given dependencies.
func NewServer(
	ks *storage.MasterKeyStore,
	mus *storage.MongoUserStore,
	dekStore *storage.MongoDEKStore,
	fa *firebaseauth.Client,
) *Server {
	return &Server{
		KeyStore:       ks,
		MongoUserStore: mus,
		DEKStore:       dekStore,
		FirebaseAuth:   fa,
	}
}
