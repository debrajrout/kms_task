package server

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"my-kms/internal/auth"
)

// Routes sets up the HTTP endpoints.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/generate-data-key", s.RateLimitMiddleware(s.firebaseAuthMiddleware(s.GenerateDataKeyHandler)))
	mux.HandleFunc("/encrypt", s.RateLimitMiddleware(s.firebaseAuthMiddleware(s.EncryptHandler)))
	mux.HandleFunc("/decrypt", s.RateLimitMiddleware(s.firebaseAuthMiddleware(s.DecryptHandler)))
	mux.HandleFunc("/rotate-master-key", s.RateLimitMiddleware(s.firebaseAuthMiddleware(s.RotateMasterKeyHandler)))

	// New endpoint to delete a DEK:
	mux.HandleFunc("/delete-data-key", s.RateLimitMiddleware(s.firebaseAuthMiddleware(s.DeleteDataKeyHandler)))

	return mux
}

// firebaseAuthMiddleware authenticates the Firebase JWT, retrieves role from MongoDB, sets identity in context.
func (s *Server) firebaseAuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 1. Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Authorization header missing", http.StatusUnauthorized)
			return
		}

		// 2. Parse token
		var token string
		_, err := fmt.Sscanf(authHeader, "Bearer %s", &token)
		if err != nil || token == "" {
			http.Error(w, "Invalid Authorization header format", http.StatusUnauthorized)
			return
		}

		// 3. Verify token
		ctx := context.Background()
		decodedToken, err := s.FirebaseAuth.VerifyIDToken(ctx, token)
		if err != nil {
			log.Printf("Failed to verify ID token: %v", err)
			http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
			return
		}

		// 4. Lookup user from MongoDB
		firebaseUID := decodedToken.UID
		user, err := s.MongoUserStore.GetUserByFirebaseUID(ctx, firebaseUID)
		if err != nil {
			log.Printf("Failed to retrieve user from MongoDB: %v", err)
			http.Error(w, "User not found", http.StatusUnauthorized)
			return
		}

		// 5. Create Identity
		identity := auth.Identity{
			Name: firebaseUID,
			Role: auth.Role(user.Role),
		}

		// 6. Inject identity into context
		ctx = context.WithValue(r.Context(), "identity", identity)
		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
	}
}

// RateLimitMiddleware is a no-op; implement real rate limiting if needed.
func (s *Server) RateLimitMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Potentially implement rate-limiting or call an external library here.
		next.ServeHTTP(w, r)
	}
}
