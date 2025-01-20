// internal/server/router.go
package server

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"my-kms/internal/auth"
	"my-kms/internal/storage"

	firebaseauth "firebase.google.com/go/auth" // Aliased to prevent conflict
)

// Server holds references to the MasterKeyStore, MongoUserStore, Firebase Auth client, and other resources.
type Server struct {
	KeyStore       *storage.MasterKeyStore
	MongoUserStore *storage.MongoUserStore
	FirebaseAuth   *firebaseauth.Client
}

// NewServer creates a new Server with the given MasterKeyStore, MongoUserStore, and Firebase Auth client.
func NewServer(ks *storage.MasterKeyStore, mus *storage.MongoUserStore, fa *firebaseauth.Client) *Server {
	return &Server{
		KeyStore:       ks,
		MongoUserStore: mus,
		FirebaseAuth:   fa,
	}
}

// Routes sets up the HTTP endpoints.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()

	// We wrap each handler with firebaseAuthMiddleware to enforce authentication and RBAC
	mux.HandleFunc("/generate-data-key", s.RateLimitMiddleware(s.firebaseAuthMiddleware(s.GenerateDataKeyHandler)))
	mux.HandleFunc("/encrypt", s.RateLimitMiddleware(s.firebaseAuthMiddleware(s.EncryptHandler)))
	mux.HandleFunc("/decrypt", s.RateLimitMiddleware(s.firebaseAuthMiddleware(s.DecryptHandler)))
	mux.HandleFunc("/rotate-master-key", s.RateLimitMiddleware(s.firebaseAuthMiddleware(s.RotateMasterKeyHandler)))

	return mux
}

// firebaseAuthMiddleware authenticates the Firebase JWT token, retrieves user role from MongoDB, and sets Identity in context.
func (s *Server) firebaseAuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 1. Extract the Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Authorization header missing", http.StatusUnauthorized)
			return
		}

		// 2. Expect the header to be in the format "Bearer <token>"
		var token string
		_, err := fmt.Sscanf(authHeader, "Bearer %s", &token)
		if err != nil || token == "" {
			http.Error(w, "Invalid Authorization header format", http.StatusUnauthorized)
			return
		}

		// 3. Verify the ID token with Firebase
		ctx := context.Background()
		decodedToken, err := s.FirebaseAuth.VerifyIDToken(ctx, token)
		if err != nil {
			log.Printf("Failed to verify ID token: %v", err)
			http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
			return
		}

		// 4. Retrieve the user's role from MongoDB using firebaseUID
		firebaseUID := decodedToken.UID
		user, err := s.MongoUserStore.GetUserByFirebaseUID(ctx, firebaseUID)
		if err != nil {
			log.Printf("Failed to retrieve user from MongoDB: %v", err)
			http.Error(w, "User not found", http.StatusUnauthorized)
			return
		}

		// 5. Create an Identity object
		identity := auth.Identity{
			Name: firebaseUID, // Using Firebase UID as the name
			Role: auth.Role(user.Role),
		}

		// 6. Inject the Identity into the request context
		ctx = context.WithValue(r.Context(), "identity", identity)
		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
	}
}

// RateLimitMiddleware limits the rate of incoming requests
func (s *Server) RateLimitMiddleware(next http.HandlerFunc) http.HandlerFunc {
	// Implement rate limiting logic here or use a third-party library
	// For simplicity, this is a no-op
	return next
}
